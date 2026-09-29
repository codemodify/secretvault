package svcms

import (
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// EnvelopedData is a parsed CMS EnvelopedData (RFC 5652, section 6) or
// AuthEnvelopedData (RFC 5083): encrypted content, and the recipients who
// can recover its key.
type EnvelopedData struct {
	Version int

	// Authenticated says whether this is AuthEnvelopedData, whose
	// content is encrypted with an AEAD (AES-GCM) and so cannot be
	// changed undetected. EnvelopedData with CBC has no integrity
	// protection at all: anyone can change the plaintext in ways that
	// survive decryption.
	Authenticated bool

	// Recipients are those the content key was encrypted to, in order.
	Recipients []*Recipient

	// ContentType is the type of the encrypted content: OIDData for a
	// MIME entity.
	ContentType asn1.ObjectIdentifier

	// ContentEncryption names the content cipher, such as "AES-256-GCM",
	// or holds its OID when this package does not know it.
	ContentEncryption string

	cipher    *contentCipher
	cipherErr error
	encrypted []byte
	aad       []byte // the authenticated attributes, as the AEAD's input
	mac       []byte
}

// ParseEnvelopedData reads a ContentInfo holding EnvelopedData or
// AuthEnvelopedData, in BER or DER.
func ParseEnvelopedData(data []byte, lim *Limits) (*EnvelopedData, error) {
	l := lim.withDefaults()
	oid, content, err := parseContentInfo(data, l)
	if err != nil {
		return nil, err
	}
	e := &EnvelopedData{}
	switch {
	case oid.Equal(OIDEnvelopedData):
	case oid.Equal(OIDAuthEnvelopedData):
		e.Authenticated = true
	default:
		return nil, fmt.Errorf("%w: %v is not enveloped data", ErrWrongType, oid)
	}
	var seq cryptobyte.String
	if content == nil || !content.ReadASN1(&seq, cbasn1.SEQUENCE) || !content.Empty() || !seq.ReadASN1Integer(&e.Version) {
		return nil, malformed("EnvelopedData")
	}
	if e.Version < 0 || e.Version > 4 {
		return nil, unsupported("EnvelopedData version %d", e.Version)
	}
	if tag := cbasn1.Tag(0).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) {
		// originatorInfo: certificates and CRLs for the recipients, which
		// decryption does not need.
		if !seq.SkipASN1(tag) {
			return nil, malformed("originatorInfo")
		}
	}
	var infos, eci cryptobyte.String
	var alg algorithm
	if !seq.ReadASN1(&infos, cbasn1.SET) || !seq.ReadASN1(&eci, cbasn1.SEQUENCE) ||
		!eci.ReadASN1ObjectIdentifier(&e.ContentType) || !readAlgorithm(&eci, &alg) {
		return nil, malformed("EncryptedContentInfo")
	}
	e.cipher, e.cipherErr = parseContentCipher(alg)
	if e.cipherErr == nil {
		e.ContentEncryption = e.cipher.name
		switch {
		case e.Authenticated && !e.cipher.gcm:
			e.cipherErr = unsupported("AuthEnvelopedData with %s, which is not an AEAD", e.cipher.name)
		case !e.Authenticated && e.cipher.gcm:
			e.cipherErr = unsupported("EnvelopedData with %s (RFC 5084 puts GCM in AuthEnvelopedData)", e.cipher.name)
		}
	} else {
		e.ContentEncryption = alg.oid.String()
	}
	if eci.Empty() {
		return nil, unsupported("encrypted content kept outside the message")
	}
	if !readImplicitOctets(&eci, 0, &e.encrypted) || !eci.Empty() {
		return nil, malformed("encryptedContent")
	}
	keyLen := 0
	if e.cipher != nil {
		keyLen = e.cipher.keyLen
	}
	if e.Recipients, err = parseRecipientInfos(infos, keyLen, l); err != nil {
		return nil, err
	}
	if e.Authenticated {
		if tag := cbasn1.Tag(1).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) {
			var attrs cryptobyte.String
			if !seq.ReadASN1Element(&attrs, tag) {
				return nil, malformed("authAttrs")
			}
			// The AEAD authenticates their DER with the SET OF tag
			// (RFC 5083, section 2.2).
			e.aad = append([]byte{0x31}, attrs[1:]...)
		}
		var mac cryptobyte.String
		if !seq.ReadASN1(&mac, cbasn1.OCTET_STRING) {
			return nil, malformed("AuthEnvelopedData mac")
		}
		e.mac = append([]byte{}, mac...)
		if tag := cbasn1.Tag(2).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) && !seq.SkipASN1(tag) {
			return nil, malformed("unauthAttrs")
		}
	} else if tag := cbasn1.Tag(1).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) && !seq.SkipASN1(tag) {
		return nil, malformed("unprotectedAttrs")
	}
	if !seq.Empty() {
		return nil, malformed("EnvelopedData has trailing data")
	}
	return e, nil
}

// Plaintext is decrypted content.
type Plaintext struct {
	Content     []byte
	ContentType asn1.ObjectIdentifier
	// Recipient is the recipient whose key decrypted it.
	Recipient *Recipient
	// Cipher names the content cipher; Authenticated says whether it was
	// an AEAD whose tag was checked.
	Cipher        string
	Authenticated bool
	// Warnings are things to tell the person, such as an obsolete cipher.
	Warnings []string
}

// Decrypt decrypts the content with the first recipient d has a key for.
// It fails with ErrNotRecipient if d holds no key for any recipient,
// ErrDecryption if the content does not decrypt (with the same error
// whatever the reason), or whatever d returns (a refusal to use the key,
// say).
func (e *EnvelopedData) Decrypt(d Decrypter) (*Plaintext, error) {
	if e.cipherErr != nil {
		return nil, e.cipherErr
	}
	var lastErr error
	for _, r := range e.Recipients {
		if r.Err != nil {
			continue
		}
		key, err := d.ContentKey(r)
		if err != nil {
			if !errors.Is(err, ErrNotRecipient) {
				lastErr = err
			}
			continue
		}
		plain, err := e.cipher.decrypt(key, e.encrypted, e.mac, e.aad)
		clear(key)
		if err != nil {
			lastErr = ErrDecryption
			continue
		}
		p := &Plaintext{Content: plain, ContentType: e.ContentType, Recipient: r, Cipher: e.cipher.name, Authenticated: e.Authenticated}
		if e.cipher.legacy {
			p.Warnings = append(p.Warnings, fmt.Sprintf("the message is encrypted with %s, which is obsolete: its confidentiality is suspect", e.cipher.name))
		}
		return p, nil
	}
	if lastErr != nil {
		return nil, lastErr
	}
	for _, r := range e.Recipients {
		if r.Err == nil {
			return nil, ErrNotRecipient
		}
	}
	// Every recipient uses something unsupported: say what.
	return nil, e.Recipients[0].Err
}
