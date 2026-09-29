package svcms

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// SignOptions choose how Sign signs.
type SignOptions struct {
	// Hash is the digest algorithm; zero means SHA-256, and for Ed25519
	// SHA-512, which RFC 8419 requires.
	Hash crypto.Hash
	// PSS signs with RSA-PSS (a salt as long as the hash, MGF1 with the
	// same hash) instead of RSA PKCS #1 v1.5.
	PSS bool
	// Time goes into the signing-time attribute; zero means now.
	Time time.Time
	// Attached puts the content inside the SignedData (an opaque signed
	// message) instead of leaving it detached.
	Attached bool
	// ContentType is the type of the content; nil means OIDData.
	ContentType asn1.ObjectIdentifier
}

// Sign makes a SignedData over content, signed by signer, whose certificate
// is chain[0]; the rest of the chain goes into the message too, so that
// receivers can build a path to their roots. The signer may keep its key
// elsewhere: it is only asked to sign a digest (or, for Ed25519, the
// signed attributes). The signed attributes are content-type,
// signing-time, message-digest, the S/MIME capabilities this package
// decrypts, and signing-certificate-v2. It returns the DER ContentInfo.
func Sign(content []byte, signer crypto.Signer, chain []*x509.Certificate, opts SignOptions) ([]byte, error) {
	if len(chain) == 0 {
		return nil, errors.New("svcms: no signer certificate")
	}
	cert := chain[0]
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if pub, ok := signer.Public().(equaler); !ok || !pub.Equal(cert.PublicKey) {
		return nil, errors.New("svcms: the signer's key is not the certificate's")
	}
	if err := weakKey(cert); err != nil {
		return nil, err
	}
	h := opts.Hash
	var sigAlg func(*cryptobyte.Builder)
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if h == 0 {
			h = crypto.SHA256
		}
		if opts.PSS {
			sigAlg = func(b *cryptobyte.Builder) {
				addAlgorithm(b, oidRSAPSS, func(b *cryptobyte.Builder) { addPSSParams(b, h) })
			}
		} else {
			oid := map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA256: oidSHA256WithRSA, crypto.SHA384: oidSHA384WithRSA, crypto.SHA512: oidSHA512WithRSA}[h]
			if oid == nil {
				return nil, unsupported("signing with %v", h)
			}
			sigAlg = func(b *cryptobyte.Builder) { addAlgorithm(b, oid, addNull) }
		}
	case *ecdsa.PublicKey:
		if h == 0 {
			h = map[int]crypto.Hash{256: crypto.SHA256, 384: crypto.SHA384, 521: crypto.SHA512}[pub.Curve.Params().BitSize]
		}
		oid := map[crypto.Hash]asn1.ObjectIdentifier{crypto.SHA256: oidECDSAWithSHA256, crypto.SHA384: oidECDSAWithSHA384, crypto.SHA512: oidECDSAWithSHA512}[h]
		if oid == nil {
			return nil, unsupported("signing with %v", h)
		}
		sigAlg = func(b *cryptobyte.Builder) { addAlgorithm(b, oid, nil) }
	case ed25519.PublicKey:
		if h != 0 && h != crypto.SHA512 {
			return nil, unsupported("Ed25519 with %v (RFC 8419 requires SHA-512)", h)
		}
		h = crypto.SHA512
		sigAlg = func(b *cryptobyte.Builder) { addAlgorithm(b, oidEd25519, nil) }
	default:
		return nil, unsupported("signing with a %T key", cert.PublicKey)
	}
	if hashOID(h) == nil || h == crypto.SHA1 {
		return nil, unsupported("signing with %v", h)
	}
	t := opts.Time
	if t.IsZero() {
		t = time.Now()
	}
	contentType := opts.ContentType
	if contentType == nil {
		contentType = OIDData
	}

	hh := h.New()
	hh.Write(content)
	digest := hh.Sum(nil)
	certHash := crypto.SHA256.New()
	certHash.Write(cert.Raw)

	attrs := [][]byte{
		buildAttribute(oidAttrContentType, element(func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(contentType) })),
		buildAttribute(oidAttrSigningTime, element(func(b *cryptobyte.Builder) { addTime(b, t) })),
		buildAttribute(oidAttrMessageDigest, element(func(b *cryptobyte.Builder) { b.AddASN1OctetString(digest) })),
		buildAttribute(oidAttrSMIMECapabilities, smimeCapabilities()),
		buildAttribute(oidAttrSigningCertV2, element(func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // SigningCertificateV2
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // certs
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // ESSCertIDv2, SHA-256 by default
						b.AddASN1OctetString(certHash.Sum(nil))
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // IssuerSerial
							b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) { // GeneralNames
								b.AddASN1(cbasn1.Tag(4).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
									b.AddBytes(cert.RawIssuer)
								})
							})
							b.AddASN1BigInt(cert.SerialNumber)
						})
					})
				})
			})
		})),
	}
	signedSet := derSet(attrs)

	var sig []byte
	var err error
	switch cert.PublicKey.(type) {
	case ed25519.PublicKey:
		sig, err = signer.Sign(rand.Reader, signedSet, crypto.Hash(0))
	default:
		hh := h.New()
		hh.Write(signedSet)
		var so crypto.SignerOpts = h
		if opts.PSS {
			so = &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash, Hash: h}
		}
		sig, err = signer.Sign(rand.Reader, hh.Sum(nil), so)
	}
	if err != nil {
		return nil, fmt.Errorf("svcms: signing: %w", err)
	}

	signerInfo := element(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(1)
			addIssuerAndSerial(b, cert.RawIssuer, cert.SerialNumber)
			addAlgorithm(b, hashOID(h), nil)
			// signedAttrs [0] IMPLICIT: the SET with its tag replaced.
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				s := cryptobyte.String(signedSet)
				var body cryptobyte.String
				s.ReadASN1(&body, cbasn1.SET)
				b.AddBytes(body)
			})
			sigAlg(b)
			b.AddASN1OctetString(sig)
		})
	})
	var certs [][]byte
	for _, c := range chain {
		certs = append(certs, c.Raw)
	}
	signedData := element(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(1)
			b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { addAlgorithm(b, hashOID(h), nil) })
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(contentType)
				if opts.Attached {
					b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
						b.AddASN1OctetString(content)
					})
				}
			})
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				s := cryptobyte.String(derSet(certs))
				var body cryptobyte.String
				s.ReadASN1(&body, cbasn1.SET)
				b.AddBytes(body)
			})
			b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) { b.AddBytes(signerInfo) })
		})
	})
	return buildContentInfo(OIDSignedData, signedData), nil
}

// smimeCapabilities lists, most preferred first, the content encryption
// this package reads (RFC 8551, section 2.5.2).
func smimeCapabilities() []byte {
	return element(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			for _, oid := range []asn1.ObjectIdentifier{oidAES256GCM, oidAES128GCM, oidAES256CBC, oidAES128CBC} {
				addAlgorithm(b, oid, nil)
			}
		})
	})
}
