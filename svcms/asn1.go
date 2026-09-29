package svcms

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"slices"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Object identifiers.
var (
	// Content types (RFC 5652, section 4; RFC 5083).
	OIDData              = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	OIDSignedData        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	OIDEnvelopedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 3}
	OIDEncryptedData     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 6}
	OIDAuthEnvelopedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 23}
	OIDCompressedData    = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 1, 9}

	// Attributes.
	oidAttrContentType        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime        = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttrSMIMECapabilities  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 15}
	oidAttrSigningCertificate = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidAttrSigningCertV2      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidAttrAlgProtection      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52}
	oidAttrFriendlyName       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 20}
	oidAttrLocalKeyID         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 21}
	oidEmailAddress           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

	// Digests.
	oidMD5    = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 5}
	oidSHA1   = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA224 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 4}
	oidSHA256 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512 = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}

	// Signatures and public keys.
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidMD5WithRSA      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 4}
	oidSHA1WithRSA     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 5}
	oidSHA224WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 14}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSAPSS          = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidRSAOAEP         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 7}
	oidPSpecified      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 9}
	oidECPublicKey     = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}
	oidECDSAWithSHA1   = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 1}
	oidECDSAWithSHA224 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 1}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidEd25519         = asn1.ObjectIdentifier{1, 3, 101, 112}
	oidCurveP256       = asn1.ObjectIdentifier{1, 2, 840, 10045, 3, 1, 7}
	oidCurveP384       = asn1.ObjectIdentifier{1, 3, 132, 0, 34}
	oidCurveP521       = asn1.ObjectIdentifier{1, 3, 132, 0, 35}

	// Key agreement (RFC 5753, section 7.1.4). For the NIST curves, whose
	// cofactor is 1, the cofactor schemes compute the same thing.
	oidECDHSHA1KDF           = asn1.ObjectIdentifier{1, 3, 133, 16, 840, 63, 0, 2}
	oidECDHSHA224KDF         = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 0}
	oidECDHSHA256KDF         = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 1}
	oidECDHSHA384KDF         = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 2}
	oidECDHSHA512KDF         = asn1.ObjectIdentifier{1, 3, 132, 1, 11, 3}
	oidECDHCofactorSHA1KDF   = asn1.ObjectIdentifier{1, 3, 133, 16, 840, 63, 0, 3}
	oidECDHCofactorSHA224KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 14, 0}
	oidECDHCofactorSHA256KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 14, 1}
	oidECDHCofactorSHA384KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 14, 2}
	oidECDHCofactorSHA512KDF = asn1.ObjectIdentifier{1, 3, 132, 1, 14, 3}

	// Key wrap and content encryption.
	oidAES128Wrap = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 5}
	oidAES192Wrap = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 25}
	oidAES256Wrap = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 45}
	oidAES128CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 2}
	oidAES192CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 22}
	oidAES256CBC  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 42}
	oidAES128GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 6}
	oidAES192GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 26}
	oidAES256GCM  = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 1, 46}
	oidDESEDE3CBC = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 7}
	oidRC2CBC     = asn1.ObjectIdentifier{1, 2, 840, 113549, 3, 2}
	oidDESCBC     = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 7}
)

// algorithm is a parsed AlgorithmIdentifier.
type algorithm struct {
	oid    asn1.ObjectIdentifier
	params []byte // the parameters element, whole; nil when absent
	raw    []byte // the whole AlgorithmIdentifier
}

// paramsEmpty says whether the parameters are absent or NULL, which most
// algorithms treat alike.
func (a algorithm) paramsEmpty() bool {
	return a.params == nil || bytes.Equal(a.params, []byte{0x05, 0x00})
}

func readAlgorithm(s *cryptobyte.String, out *algorithm) bool {
	var raw, inner cryptobyte.String
	if !s.ReadASN1Element(&raw, cbasn1.SEQUENCE) {
		return false
	}
	body := raw
	if !body.ReadASN1(&inner, cbasn1.SEQUENCE) || !inner.ReadASN1ObjectIdentifier(&out.oid) {
		return false
	}
	out.raw = raw
	out.params = nil
	if !inner.Empty() {
		var p cryptobyte.String
		var tag cbasn1.Tag
		if !inner.ReadAnyASN1Element(&p, &tag) || !inner.Empty() {
			return false
		}
		out.params = p
	}
	return true
}

// addAlgorithm writes an AlgorithmIdentifier; params may be nil for none.
func addAlgorithm(b *cryptobyte.Builder, oid asn1.ObjectIdentifier, params func(*cryptobyte.Builder)) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		if params != nil {
			params(b)
		}
	})
}

func addNull(b *cryptobyte.Builder) { b.AddBytes([]byte{0x05, 0x00}) }

// readImplicitOctets reads an [n] IMPLICIT OCTET STRING that may, in BER
// that has been through toDER, still be constructed: a context-specific
// tag hides the type, so its chunks could not be joined.
func readImplicitOctets(s *cryptobyte.String, n int, out *[]byte) bool {
	prim := cbasn1.Tag(n).ContextSpecific()
	if s.PeekASN1Tag(prim) {
		var v cryptobyte.String
		if !s.ReadASN1(&v, prim) {
			return false
		}
		*out = v
		return true
	}
	var cons cryptobyte.String
	if !s.ReadASN1(&cons, prim.Constructed()) {
		return false
	}
	var joined []byte
	for !cons.Empty() {
		var chunk cryptobyte.String
		if !cons.ReadASN1(&chunk, cbasn1.OCTET_STRING) {
			return false
		}
		joined = append(joined, chunk...)
	}
	if joined == nil {
		joined = []byte{}
	}
	*out = joined
	return true
}

// IssuerAndSerial names a certificate by its issuer and serial number, as
// CMS does to identify signers and recipients.
type IssuerAndSerial struct {
	Issuer []byte // the issuer's Name, DER, as it appears in the message
	Serial *big.Int
}

func readIssuerAndSerial(s *cryptobyte.String) (*IssuerAndSerial, bool) {
	var seq, name cryptobyte.String
	out := &IssuerAndSerial{Serial: new(big.Int)}
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1Element(&name, cbasn1.SEQUENCE) ||
		!seq.ReadASN1Integer(out.Serial) || !seq.Empty() {
		return nil, false
	}
	out.Issuer = name
	return out, true
}

func addIssuerAndSerial(b *cryptobyte.Builder, issuer []byte, serial *big.Int) {
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddBytes(issuer)
		b.AddASN1BigInt(serial)
	})
}

// IssuerName is the issuer as text, in the form of pkix.Name's String, or
// "" if it does not parse.
func (is *IssuerAndSerial) IssuerName() string { return nameString(is.Issuer) }

// Matches says whether the certificate whose raw issuer and serial are
// given is the one named.
func (is *IssuerAndSerial) matches(rawIssuer []byte, serial *big.Int) bool {
	if serial == nil || is.Serial.Cmp(serial) != 0 {
		return false
	}
	if bytes.Equal(is.Issuer, rawIssuer) {
		return true
	}
	// Some encoders re-encode names (a PrintableString as a UTF8String,
	// say). Compare what the names say.
	a, b := parseName(is.Issuer), parseName(rawIssuer)
	return a != nil && b != nil && namesEqual(a, b)
}

func parseName(der []byte) pkix.RDNSequence {
	var rdn pkix.RDNSequence
	if rest, err := asn1.Unmarshal(der, &rdn); err != nil || len(rest) != 0 {
		return nil
	}
	return rdn
}

func namesEqual(a, b pkix.RDNSequence) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if len(a[i]) != len(b[i]) {
			return false
		}
		for j := range a[i] {
			x, y := a[i][j], b[i][j]
			if !x.Type.Equal(y.Type) {
				return false
			}
			xs, ok1 := x.Value.(string)
			ys, ok2 := y.Value.(string)
			if !ok1 || !ok2 || xs != ys {
				return false
			}
		}
	}
	return true
}

func nameString(der []byte) string {
	rdn := parseName(der)
	if rdn == nil {
		return ""
	}
	var n pkix.Name
	n.FillFromRDNSequence(&rdn)
	return n.String()
}

// readTime reads a UTCTime or GeneralizedTime.
func readTime(s *cryptobyte.String, out *time.Time) bool {
	switch {
	case s.PeekASN1Tag(cbasn1.UTCTime):
		return s.ReadASN1UTCTime(out)
	case s.PeekASN1Tag(cbasn1.GeneralizedTime):
		return s.ReadASN1GeneralizedTime(out)
	}
	return false
}

// addTime writes a time as RFC 5280 wants it: UTCTime from 1950 through
// 2049, GeneralizedTime otherwise.
func addTime(b *cryptobyte.Builder, t time.Time) {
	t = t.UTC().Truncate(time.Second)
	if y := t.Year(); y >= 1950 && y < 2050 {
		b.AddASN1UTCTime(t)
	} else {
		b.AddASN1GeneralizedTime(t)
	}
}

// attribute is one Attribute: a type and its values, each a whole element.
type attribute struct {
	oid    asn1.ObjectIdentifier
	values [][]byte
}

// readAttributes reads the contents of a SET OF Attribute.
func readAttributes(s cryptobyte.String, lim Limits) ([]attribute, error) {
	var out []attribute
	for !s.Empty() {
		if len(out) >= lim.MaxAttributes {
			return nil, limit("more than %d attributes", lim.MaxAttributes)
		}
		var seq, set cryptobyte.String
		var a attribute
		if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1ObjectIdentifier(&a.oid) ||
			!seq.ReadASN1(&set, cbasn1.SET) || !seq.Empty() {
			return nil, malformed("attribute")
		}
		for !set.Empty() {
			if len(a.values) >= lim.MaxAttributes {
				return nil, limit("more than %d attribute values", lim.MaxAttributes)
			}
			var v cryptobyte.String
			var tag cbasn1.Tag
			if !set.ReadAnyASN1Element(&v, &tag) {
				return nil, malformed("attribute value")
			}
			a.values = append(a.values, v)
		}
		out = append(out, a)
	}
	return out, nil
}

// find returns the one attribute of a type, nil if there is none, and an
// error if there are several or it does not hold exactly one value.
func findAttribute(attrs []attribute, oid asn1.ObjectIdentifier) (*attribute, error) {
	var found *attribute
	for i := range attrs {
		if attrs[i].oid.Equal(oid) {
			if found != nil {
				return nil, malformed("attribute %v appears more than once", oid)
			}
			found = &attrs[i]
		}
	}
	if found != nil && len(found.values) != 1 {
		return nil, malformed("attribute %v has %d values", oid, len(found.values))
	}
	return found, nil
}

// derSet encodes elements as a DER SET OF: sorted by their encodings (X.690,
// section 11.6).
func derSet(elems [][]byte) []byte {
	sorted := slices.Clone(elems)
	slices.SortFunc(sorted, bytes.Compare)
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
		for _, e := range sorted {
			b.AddBytes(e)
		}
	})
	return b.BytesOrPanic()
}

func buildAttribute(oid asn1.ObjectIdentifier, value []byte) []byte {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1ObjectIdentifier(oid)
		b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddBytes(value) })
	})
	return b.BytesOrPanic()
}

// element builds one element with a builder function.
func element(f func(*cryptobyte.Builder)) []byte {
	var b cryptobyte.Builder
	f(&b)
	return b.BytesOrPanic()
}
