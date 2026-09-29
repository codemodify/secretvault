package svcms

import (
	"encoding/asn1"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// ContentType reads the type of a ContentInfo, BER or DER, without
// parsing the content: OIDSignedData, OIDEnvelopedData,
// OIDAuthEnvelopedData or another. It is how an S/MIME part with no
// smime-type parameter is told apart.
func ContentType(data []byte, lim *Limits) (asn1.ObjectIdentifier, error) {
	oid, _, err := parseContentInfo(data, lim.withDefaults())
	return oid, err
}

// parseContentInfo reads a ContentInfo (RFC 5652, section 3) and returns
// its type and the contents of its [0] EXPLICIT content, rewriting BER
// into DER first.
func parseContentInfo(data []byte, lim Limits) (asn1.ObjectIdentifier, cryptobyte.String, error) {
	der, err := toDER(data, lim)
	if err != nil {
		return nil, nil, err
	}
	s := cryptobyte.String(der)
	var seq, content cryptobyte.String
	var oid asn1.ObjectIdentifier
	if !s.ReadASN1(&seq, cbasn1.SEQUENCE) || !seq.ReadASN1ObjectIdentifier(&oid) {
		return nil, nil, malformed("ContentInfo")
	}
	if seq.Empty() {
		return oid, nil, nil
	}
	if !seq.ReadASN1(&content, cbasn1.Tag(0).Constructed().ContextSpecific()) || !seq.Empty() {
		return nil, nil, malformed("ContentInfo content")
	}
	return oid, content, nil
}

// buildContentInfo wraps content (a whole element) in a ContentInfo.
func buildContentInfo(oid asn1.ObjectIdentifier, content []byte) []byte {
	return element(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1ObjectIdentifier(oid)
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes(content)
			})
		})
	})
}
