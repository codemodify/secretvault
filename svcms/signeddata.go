package svcms

import (
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// SignedData is a parsed CMS SignedData (RFC 5652, section 5): content,
// attached or not, the certificates that came with it, and its signers.
type SignedData struct {
	Version int

	// ContentType is the type of the signed content (the
	// eContentType): OIDData for a MIME entity.
	ContentType asn1.ObjectIdentifier

	// Content is the signed content when it is attached (an opaque
	// signed message), nil when it is detached.
	Content []byte

	// Certificates are the certificates the message carries, in order.
	// Any that did not parse are left out and counted in
	// BadCertificates.
	Certificates    []*x509.Certificate
	BadCertificates int

	// Signers holds one entry per SignerInfo.
	Signers []*SignerInfo

	lim Limits
}

// SignerInfo is one signer's part of a SignedData.
type SignerInfo struct {
	Version int

	// The signer's certificate is named by issuer and serial number, or,
	// in version 3, by subject key identifier: one of these is set.
	IssuerAndSerial *IssuerAndSerial
	SubjectKeyID    []byte

	// SigningTime is the signing-time attribute; zero when there is none.
	// It is what the signer says, signed but not otherwise proven.
	SigningTime time.Time

	// HasSignedAttributes says whether the signature covers signed
	// attributes (and so the content by its digest) or the content
	// itself.
	HasSignedAttributes bool

	Signature []byte

	digestAlg   algorithm
	sigAlg      algorithm
	signedAttrs []byte // the [0] element, whole, as it appears
	attrs       []attribute
	attrErr     error // the signed attributes could not be read
}

// ParseSignedData reads a ContentInfo holding SignedData, in BER or DER.
// It checks structure only; Verify checks the signatures.
func ParseSignedData(data []byte, lim *Limits) (*SignedData, error) {
	l := lim.withDefaults()
	oid, content, err := parseContentInfo(data, l)
	if err != nil {
		return nil, err
	}
	if !oid.Equal(OIDSignedData) {
		return nil, fmt.Errorf("%w: %v is not signed data", ErrWrongType, oid)
	}
	if content == nil {
		return nil, malformed("SignedData without content")
	}
	sd := &SignedData{lim: l}
	var seq, digestAlgs, encap cryptobyte.String
	if !content.ReadASN1(&seq, cbasn1.SEQUENCE) || !content.Empty() ||
		!seq.ReadASN1Integer(&sd.Version) ||
		!seq.ReadASN1(&digestAlgs, cbasn1.SET) ||
		!seq.ReadASN1(&encap, cbasn1.SEQUENCE) {
		return nil, malformed("SignedData")
	}
	if sd.Version < 1 || sd.Version > 5 {
		return nil, unsupported("SignedData version %d", sd.Version)
	}
	if !encap.ReadASN1ObjectIdentifier(&sd.ContentType) {
		return nil, malformed("EncapsulatedContentInfo")
	}
	if !encap.Empty() {
		var explicit cryptobyte.String
		if !encap.ReadASN1(&explicit, cbasn1.Tag(0).Constructed().ContextSpecific()) || !encap.Empty() {
			return nil, malformed("EncapsulatedContentInfo content")
		}
		if explicit.PeekASN1Tag(cbasn1.OCTET_STRING) {
			var octets cryptobyte.String
			if !explicit.ReadASN1(&octets, cbasn1.OCTET_STRING) || !explicit.Empty() {
				return nil, malformed("eContent")
			}
			sd.Content = append([]byte{}, octets...)
		} else {
			// PKCS #7 version 1.5 put the content itself here, not in an
			// OCTET STRING (RFC 5652, section 5.2.1); its signature
			// covers the contents of the element.
			var inner cryptobyte.String
			var tag cbasn1.Tag
			if !explicit.ReadAnyASN1(&inner, &tag) || !explicit.Empty() {
				return nil, malformed("eContent")
			}
			sd.Content = append([]byte{}, inner...)
		}
	}
	certTag := cbasn1.Tag(0).Constructed().ContextSpecific()
	if seq.PeekASN1Tag(certTag) {
		var certs cryptobyte.String
		if !seq.ReadASN1(&certs, certTag) {
			return nil, malformed("certificates")
		}
		n := 0
		for !certs.Empty() {
			var c cryptobyte.String
			var tag cbasn1.Tag
			if !certs.ReadAnyASN1Element(&c, &tag) {
				return nil, malformed("certificates")
			}
			if n++; n > l.MaxCertificates {
				return nil, limit("more than %d certificates", l.MaxCertificates)
			}
			if tag != cbasn1.SEQUENCE {
				continue // an attribute certificate or other kind: not ours to use
			}
			cert, err := x509.ParseCertificate(c)
			if err != nil {
				sd.BadCertificates++
				continue
			}
			sd.Certificates = append(sd.Certificates, cert)
		}
	}
	crlTag := cbasn1.Tag(1).Constructed().ContextSpecific()
	if seq.PeekASN1Tag(crlTag) {
		// Revocation lists are not checked; nothing here reads them.
		if !seq.SkipASN1(crlTag) {
			return nil, malformed("crls")
		}
	}
	var infos cryptobyte.String
	if !seq.ReadASN1(&infos, cbasn1.SET) || !seq.Empty() {
		return nil, malformed("SignerInfos")
	}
	for !infos.Empty() {
		if len(sd.Signers) >= l.MaxSigners {
			return nil, limit("more than %d signers", l.MaxSigners)
		}
		si, err := parseSignerInfo(&infos, l)
		if err != nil {
			return nil, err
		}
		sd.Signers = append(sd.Signers, si)
	}
	return sd, nil
}

func parseSignerInfo(s *cryptobyte.String, lim Limits) (*SignerInfo, error) {
	var seq cryptobyte.String
	si := &SignerInfo{}
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Integer(&si.Version) {
		return nil, malformed("SignerInfo")
	}
	skiTag := cbasn1.Tag(0).ContextSpecific()
	switch {
	case seq.PeekASN1Tag(cbasn1.SEQUENCE):
		is, ok := readIssuerAndSerial(&seq)
		if !ok {
			return nil, malformed("SignerInfo issuer and serial number")
		}
		si.IssuerAndSerial = is
	case seq.PeekASN1Tag(skiTag):
		var ski cryptobyte.String
		if !seq.ReadASN1(&ski, skiTag) {
			return nil, malformed("SignerInfo subject key identifier")
		}
		si.SubjectKeyID = append([]byte{}, ski...)
	default:
		return nil, malformed("SignerInfo signer identifier")
	}
	if !readAlgorithm(&seq, &si.digestAlg) {
		return nil, malformed("SignerInfo digest algorithm")
	}
	attrTag := cbasn1.Tag(0).Constructed().ContextSpecific()
	if seq.PeekASN1Tag(attrTag) {
		var whole, body cryptobyte.String
		if !seq.ReadASN1Element(&whole, attrTag) {
			return nil, malformed("SignerInfo signed attributes")
		}
		si.signedAttrs = whole
		si.HasSignedAttributes = true
		outer := whole
		outer.ReadASN1(&body, attrTag)
		si.attrs, si.attrErr = readAttributes(body, lim)
		if si.attrErr == nil {
			if a, err := findAttribute(si.attrs, oidAttrSigningTime); err != nil {
				si.attrErr = err
			} else if a != nil {
				v := cryptobyte.String(a.values[0])
				if !readTime(&v, &si.SigningTime) || !v.Empty() {
					si.attrErr = malformed("signing-time attribute")
				}
			}
		}
	}
	var sig cryptobyte.String
	if !readAlgorithm(&seq, &si.sigAlg) || !seq.ReadASN1(&sig, cbasn1.OCTET_STRING) {
		return nil, malformed("SignerInfo signature")
	}
	si.Signature = append([]byte{}, sig...)
	unsignedTag := cbasn1.Tag(1).Constructed().ContextSpecific()
	if seq.PeekASN1Tag(unsignedTag) && !seq.SkipASN1(unsignedTag) {
		return nil, malformed("SignerInfo unsigned attributes")
	}
	if !seq.Empty() {
		return nil, malformed("SignerInfo has trailing data")
	}
	return si, nil
}

// DigestAlgorithm is the OID of the signer's digest algorithm.
func (si *SignerInfo) DigestAlgorithm() asn1.ObjectIdentifier { return si.digestAlg.oid }

// SignatureAlgorithm is the OID of the signer's signature algorithm.
func (si *SignerInfo) SignatureAlgorithm() asn1.ObjectIdentifier { return si.sigAlg.oid }

// Matches says whether cert is the certificate the signer names.
func (si *SignerInfo) Matches(cert *x509.Certificate) bool {
	if si.IssuerAndSerial != nil {
		return si.IssuerAndSerial.matches(cert.RawIssuer, cert.SerialNumber)
	}
	return len(si.SubjectKeyID) > 0 && string(si.SubjectKeyID) == string(cert.SubjectKeyId)
}
