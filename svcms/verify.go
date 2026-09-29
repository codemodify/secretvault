package svcms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// VerifyOptions say what signatures are checked against.
type VerifyOptions struct {
	// Content is the signed content of a detached signature. It is
	// ignored when the SignedData carries its own.
	Content []byte
	// Roots are the trusted roots; with none, every signer's certificate
	// is reported as untrusted (the operating system's roots are never
	// used implicitly).
	Roots []*x509.Certificate
	// Intermediates are certificates to find signers among and build
	// chains with, besides those the message carries.
	Intermediates []*x509.Certificate
	// Time is when certificates must be valid; zero means now.
	Time time.Time
	// Email, if set, is the address the signer's certificate must name:
	// the From address of the message.
	Email string
}

// SignerResult is the verdict on one signer.
type SignerResult struct {
	// Valid is true when the signature verifies over the content, passes
	// the policy, and its certificate is valid for signing (and names
	// Email, if one was asked for). Only then.
	Valid bool
	// Err says why the result is not valid: SignatureErr if set, else
	// CertificateErr. nil when Valid.
	Err error
	// SignatureErr is the cryptographic verdict: nil when the signature
	// verifies over the content and passes the policy. It wraps
	// ErrBadSignature, ErrUnknownSigner, ErrWeakAlgorithm,
	// ErrSignatureMalformed or ErrUnsupported.
	SignatureErr error
	// CertificateErr is the verdict on the signer's certificate, from
	// VerifyCertificate: one or more of ErrUntrustedRoot, ErrCertExpired,
	// ErrWrongUsage, ErrAddressMismatch and ErrCertInvalid, joined.
	CertificateErr error

	Signer *SignerInfo
	// Certificate is the signer's certificate, when it was found; Chains
	// are the chains built from it to a root.
	Certificate *x509.Certificate
	Chains      [][]*x509.Certificate

	Hash        crypto.Hash
	Algorithm   string // "RSA PKCS#1 v1.5", "RSA-PSS", "ECDSA" or "Ed25519"
	SigningTime time.Time
}

// Verify checks every signer's signature over the content, and each
// signer's certificate. It returns a result per signer; the error is only
// for signed data that cannot be verified at all (no signers, or detached
// with no content given). A nil error does not mean any signature is
// valid.
func (sd *SignedData) Verify(opts VerifyOptions) ([]SignerResult, error) {
	if len(sd.Signers) == 0 {
		return nil, ErrNoSignature
	}
	content := sd.Content
	if content == nil {
		if opts.Content == nil {
			return nil, fmt.Errorf("%w: the signature is detached and no content was given", ErrNoSignature)
		}
		content = opts.Content
	}
	t := opts.Time
	if t.IsZero() {
		t = time.Now()
	}
	pool := append(append([]*x509.Certificate{}, sd.Certificates...), opts.Intermediates...)
	digests := map[crypto.Hash][]byte{}
	var results []SignerResult
	for _, si := range sd.Signers {
		r := sd.verifySigner(si, content, pool, digests)
		if r.Certificate != nil {
			r.Chains, r.CertificateErr = VerifyCertificate(r.Certificate, CertOptions{
				Roots:         opts.Roots,
				Intermediates: pool,
				Time:          t,
				Email:         opts.Email,
				Usage:         UsageSigning,
			})
		}
		switch {
		case r.SignatureErr != nil:
			r.Err = r.SignatureErr
		case r.CertificateErr != nil:
			r.Err = r.CertificateErr
		default:
			r.Valid = true
		}
		results = append(results, r)
	}
	return results, nil
}

func (sd *SignedData) verifySigner(si *SignerInfo, content []byte, pool []*x509.Certificate, digests map[crypto.Hash][]byte) SignerResult {
	r := SignerResult{Signer: si, SigningTime: si.SigningTime}
	scheme, err := parseSignatureAlgorithm(si.sigAlg)
	if err != nil {
		r.SignatureErr = err
		return r
	}
	r.Algorithm = scheme.String()
	h, err := hashByOID(si.digestAlg.oid)
	if err != nil {
		r.SignatureErr = err
		return r
	}
	r.Hash = h
	if scheme.hash != 0 && scheme.hash != h {
		r.SignatureErr = fmt.Errorf("%w: the signature algorithm's hash (%v) is not the digest algorithm (%v)", ErrSignatureMalformed, scheme.hash, h)
		return r
	}
	var candidates []*x509.Certificate
	for _, c := range pool {
		if si.Matches(c) {
			candidates = append(candidates, c)
		}
	}
	if len(candidates) == 0 {
		r.SignatureErr = ErrUnknownSigner
		return r
	}
	var signed []byte
	if si.HasSignedAttributes {
		if si.attrErr != nil {
			r.SignatureErr = fmt.Errorf("%w: %w", ErrSignatureMalformed, si.attrErr)
			return r
		}
		digest, ok := digests[h]
		if !ok {
			hh := h.New()
			hh.Write(content)
			digest = hh.Sum(nil)
			digests[h] = digest
		}
		if err := checkSignedAttributes(si, sd.ContentType, digest); err != nil {
			r.SignatureErr = err
			return r
		}
		// The signature covers the DER of the attributes with the SET OF
		// tag in place of the [0] (RFC 5652, section 5.4).
		signed = append([]byte{0x31}, si.signedAttrs[1:]...)
	} else {
		if !sd.ContentType.Equal(OIDData) {
			r.SignatureErr = fmt.Errorf("%w: no signed attributes over content of type %v", ErrSignatureMalformed, sd.ContentType)
			return r
		}
		signed = content
	}
	var lastErr error
	for _, cert := range candidates {
		if err := verifyWith(cert, scheme, h, signed, si.Signature); err != nil {
			lastErr = err
			continue
		}
		r.Certificate = cert
		r.SignatureErr = weakKey(cert)
		if r.SignatureErr == nil {
			r.SignatureErr = checkSigningCertificate(si, cert)
		}
		if r.SignatureErr == nil {
			r.SignatureErr = hashPolicy(h, si.SigningTime)
		}
		return r
	}
	if errors.Is(lastErr, ErrUnsupported) {
		r.SignatureErr = lastErr
	} else {
		r.SignatureErr = ErrBadSignature
		if len(candidates) == 1 {
			r.Certificate = candidates[0] // named by the signer, but not its signature
		}
	}
	return r
}

// verifyWith checks a signature with a certificate's public key.
func verifyWith(cert *x509.Certificate, scheme sigScheme, h crypto.Hash, signed, sig []byte) error {
	digest := func() []byte {
		hh := h.New()
		hh.Write(signed)
		return hh.Sum(nil)
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		switch scheme.kind {
		case sigRSA:
			return rsa.VerifyPKCS1v15(pub, h, digest(), sig)
		case sigRSAPSS:
			return rsa.VerifyPSS(pub, h, digest(), sig, &rsa.PSSOptions{SaltLength: scheme.pssSalt, Hash: h})
		}
	case *ecdsa.PublicKey:
		if scheme.kind == sigECDSA {
			if !ecdsa.VerifyASN1(pub, digest(), sig) {
				return ErrBadSignature
			}
			return nil
		}
	case ed25519.PublicKey:
		if scheme.kind == sigEd25519 {
			if !ed25519.Verify(pub, signed, sig) {
				return ErrBadSignature
			}
			return nil
		}
	default:
		return unsupported("a %T key", cert.PublicKey)
	}
	return fmt.Errorf("%w: a %s signature by a %T key", ErrBadSignature, scheme, cert.PublicKey)
}

// weakKey refuses RSA keys under 2048 bits, as svpgp does.
func weakKey(cert *x509.Certificate) error {
	if pub, ok := cert.PublicKey.(*rsa.PublicKey); ok && pub.N.BitLen() < 2048 {
		return fmt.Errorf("%w: a %d-bit RSA key", ErrWeakAlgorithm, pub.N.BitLen())
	}
	return nil
}

// checkSignedAttributes checks the attributes RFC 5652 requires (section
// 11): content-type and message-digest, present once, matching the
// content; and CMS algorithm protection (RFC 6211) when present.
func checkSignedAttributes(si *SignerInfo, contentType asn1.ObjectIdentifier, digest []byte) error {
	ct, err := findAttribute(si.attrs, oidAttrContentType)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignatureMalformed, err)
	}
	if ct == nil {
		return fmt.Errorf("%w: no content-type attribute", ErrSignatureMalformed)
	}
	var oid asn1.ObjectIdentifier
	v := cryptobyte.String(ct.values[0])
	if !v.ReadASN1ObjectIdentifier(&oid) || !v.Empty() {
		return fmt.Errorf("%w: content-type attribute", ErrSignatureMalformed)
	}
	if !oid.Equal(contentType) {
		return fmt.Errorf("%w: the content-type attribute says %v, the content is %v", ErrBadSignature, oid, contentType)
	}
	md, err := findAttribute(si.attrs, oidAttrMessageDigest)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignatureMalformed, err)
	}
	if md == nil {
		return fmt.Errorf("%w: no message-digest attribute", ErrSignatureMalformed)
	}
	var got cryptobyte.String
	v = cryptobyte.String(md.values[0])
	if !v.ReadASN1(&got, cbasn1.OCTET_STRING) || !v.Empty() {
		return fmt.Errorf("%w: message-digest attribute", ErrSignatureMalformed)
	}
	if !bytes.Equal(got, digest) {
		return fmt.Errorf("%w: the content does not match its message digest", ErrBadSignature)
	}
	ap, err := findAttribute(si.attrs, oidAttrAlgProtection)
	if err != nil {
		return fmt.Errorf("%w: %w", ErrSignatureMalformed, err)
	}
	if ap != nil {
		var seq cryptobyte.String
		var d, s algorithm
		v = cryptobyte.String(ap.values[0])
		if !v.ReadASN1(&seq, cbasn1.SEQUENCE) || !v.Empty() || !readAlgorithm(&seq, &d) {
			return fmt.Errorf("%w: CMS algorithm protection attribute", ErrSignatureMalformed)
		}
		if !d.oid.Equal(si.digestAlg.oid) {
			return fmt.Errorf("%w: the algorithm protection attribute names another digest algorithm", ErrBadSignature)
		}
		// signatureAlgorithm [1] IMPLICIT AlgorithmIdentifier
		if tag := cbasn1.Tag(1).Constructed().ContextSpecific(); seq.PeekASN1Tag(tag) {
			var inner cryptobyte.String
			if !seq.ReadASN1(&inner, tag) || !inner.ReadASN1ObjectIdentifier(&s.oid) {
				return fmt.Errorf("%w: CMS algorithm protection attribute", ErrSignatureMalformed)
			}
			if !s.oid.Equal(si.sigAlg.oid) {
				return fmt.Errorf("%w: the algorithm protection attribute names another signature algorithm", ErrBadSignature)
			}
		}
	}
	return nil
}

// checkSigningCertificate checks the ESS signing-certificate attributes
// (RFC 2634 and RFC 5035), when present: the first certificate each names
// must be the one the signature verified with, so that another
// certificate for the same key cannot be put in its place.
func checkSigningCertificate(si *SignerInfo, cert *x509.Certificate) error {
	for _, v2 := range []bool{false, true} {
		oid := oidAttrSigningCertificate
		if v2 {
			oid = oidAttrSigningCertV2
		}
		a, err := findAttribute(si.attrs, oid)
		if err != nil {
			return fmt.Errorf("%w: %w", ErrSignatureMalformed, err)
		}
		if a == nil {
			continue
		}
		bad := fmt.Errorf("%w: signing-certificate attribute", ErrSignatureMalformed)
		v := cryptobyte.String(a.values[0])
		var seq, certs, id cryptobyte.String
		if !v.ReadASN1(&seq, cbasn1.SEQUENCE) || !v.Empty() || !seq.ReadASN1(&certs, cbasn1.SEQUENCE) ||
			!certs.ReadASN1(&id, cbasn1.SEQUENCE) {
			return bad
		}
		h := crypto.SHA1
		if v2 {
			h = crypto.SHA256
			if id.PeekASN1Tag(cbasn1.SEQUENCE) {
				var alg algorithm
				if !readAlgorithm(&id, &alg) {
					return bad
				}
				hh, err := hashByOID(alg.oid)
				if err != nil {
					return err
				}
				if hh == crypto.SHA1 {
					return fmt.Errorf("%w: SHA-1 in a signing-certificate-v2 attribute", ErrWeakAlgorithm)
				}
				h = hh
			}
		}
		var certHash cryptobyte.String
		if !id.ReadASN1(&certHash, cbasn1.OCTET_STRING) {
			return bad
		}
		hh := h.New()
		hh.Write(cert.Raw)
		if !bytes.Equal(certHash, hh.Sum(nil)) {
			return fmt.Errorf("%w: the signing-certificate attribute names another certificate", ErrBadSignature)
		}
		if !id.Empty() {
			// IssuerSerial ::= SEQUENCE { issuer GeneralNames, serialNumber }
			var is, names cryptobyte.String
			serial := new(big.Int)
			if !id.ReadASN1(&is, cbasn1.SEQUENCE) || !is.ReadASN1(&names, cbasn1.SEQUENCE) ||
				!is.ReadASN1Integer(serial) {
				return bad
			}
			if serial.Cmp(cert.SerialNumber) != 0 {
				return fmt.Errorf("%w: the signing-certificate attribute names another serial number", ErrBadSignature)
			}
			dirTag := cbasn1.Tag(4).Constructed().ContextSpecific()
			for !names.Empty() {
				var gn cryptobyte.String
				var tag cbasn1.Tag
				if !names.ReadAnyASN1(&gn, &tag) {
					return bad
				}
				if tag == dirTag {
					is := &IssuerAndSerial{Issuer: gn, Serial: cert.SerialNumber}
					if !is.matches(cert.RawIssuer, cert.SerialNumber) {
						return fmt.Errorf("%w: the signing-certificate attribute names another issuer", ErrBadSignature)
					}
				}
			}
		}
	}
	return nil
}
