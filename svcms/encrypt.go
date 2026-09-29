package svcms

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// EncryptOptions choose how Encrypt encrypts.
type EncryptOptions struct {
	// Legacy makes EnvelopedData with AES-256-CBC, for clients that do
	// not read AuthEnvelopedData. Such a message has no integrity
	// protection. The default is AuthEnvelopedData with AES-256-GCM.
	Legacy bool
	// ContentType is the type of the content; nil means OIDData.
	ContentType asn1.ObjectIdentifier
}

// Encrypt encrypts content to the recipients' certificates and returns the
// DER ContentInfo. An RSA key gets RSA-OAEP with SHA-256; a P-256, P-384 or
// P-521 key gets ephemeral-static ECDH with the X9.63 KDF (SHA-256,
// SHA-384 or SHA-512 by curve) and AES-256 key wrap. Recipients are named
// by issuer and serial number, which every client reads. A certificate
// whose key usage forbids the use is refused; whether to trust it is the
// caller's decision.
func Encrypt(content []byte, recipients []*x509.Certificate, opts EncryptOptions) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("svcms: no recipients")
	}
	contentType := opts.ContentType
	if contentType == nil {
		contentType = OIDData
	}
	cek := make([]byte, 32)
	rand.Read(cek)
	defer clear(cek)

	var infos [][]byte
	allV0 := true
	for _, cert := range recipients {
		if err := keyUsageAllows(cert, UsageEncryption); err != nil {
			return nil, fmt.Errorf("svcms: cannot encrypt to %s: %w", cert.Subject, err)
		}
		switch pub := cert.PublicKey.(type) {
		case *rsa.PublicKey:
			if pub.N.BitLen() < 2048 {
				return nil, fmt.Errorf("%w: cannot encrypt to %s: a %d-bit RSA key", ErrUnsupported, cert.Subject, pub.N.BitLen())
			}
			ri, err := buildKTRI(cert, pub, cek)
			if err != nil {
				return nil, err
			}
			infos = append(infos, ri)
		case *ecdsa.PublicKey:
			ek, err := pub.ECDH()
			if err != nil {
				return nil, fmt.Errorf("%w: cannot encrypt to %s: %v", ErrUnsupported, cert.Subject, err)
			}
			ri, err := buildKARI(cert, ek, cek)
			if err != nil {
				return nil, err
			}
			infos = append(infos, ri)
			allV0 = false
		default:
			return nil, fmt.Errorf("%w: cannot encrypt to %s: a %T key", ErrUnsupported, cert.Subject, cert.PublicKey)
		}
	}

	block, _ := aes.NewCipher(cek)
	var algID, ciphertext, tag []byte
	if opts.Legacy {
		iv := make([]byte, aes.BlockSize)
		rand.Read(iv)
		plain := pad(append([]byte{}, content...), aes.BlockSize)
		ciphertext = make([]byte, len(plain))
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plain)
		clear(plain)
		algID = element(func(b *cryptobyte.Builder) {
			addAlgorithm(b, oidAES256CBC, func(b *cryptobyte.Builder) { b.AddASN1OctetString(iv) })
		})
	} else {
		nonce := make([]byte, 12)
		rand.Read(nonce)
		g, _ := cipher.NewGCM(block)
		sealed := g.Seal(nil, nonce, content, nil)
		ciphertext, tag = sealed[:len(content)], sealed[len(content):]
		algID = element(func(b *cryptobyte.Builder) {
			addAlgorithm(b, oidAES256GCM, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					b.AddASN1OctetString(nonce)
					b.AddASN1Int64(int64(len(tag)))
				})
			})
		})
	}

	version := int64(0)
	if !allV0 && opts.Legacy {
		version = 2 // a recipient info other than version 0 (RFC 5652, section 6.1)
	}
	body := element(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(version)
			b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
				s := cryptobyte.String(derSet(infos))
				var inner cryptobyte.String
				s.ReadASN1(&inner, cbasn1.SET)
				b.AddBytes(inner)
			})
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1ObjectIdentifier(contentType)
				b.AddBytes(algID)
				b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(ciphertext) })
			})
			if !opts.Legacy {
				b.AddASN1OctetString(tag)
			}
		})
	})
	if opts.Legacy {
		return buildContentInfo(OIDEnvelopedData, body), nil
	}
	return buildContentInfo(OIDAuthEnvelopedData, body), nil
}

func buildKTRI(cert *x509.Certificate, pub *rsa.PublicKey, cek []byte) ([]byte, error) {
	ek, err := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, pub, cek, nil)
	if err != nil {
		return nil, fmt.Errorf("svcms: encrypting to %s: %w", cert.Subject, err)
	}
	return element(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
			b.AddASN1Int64(0)
			addIssuerAndSerial(b, cert.RawIssuer, cert.SerialNumber)
			addAlgorithm(b, oidRSAOAEP, func(b *cryptobyte.Builder) { addOAEPParams(b, crypto.SHA256) })
			b.AddASN1OctetString(ek)
		})
	}), nil
}

func buildKARI(cert *x509.Certificate, pub *ecdh.PublicKey, cek []byte) ([]byte, error) {
	curve := pub.Curve()
	var kdfOID asn1.ObjectIdentifier
	var h crypto.Hash
	switch curve {
	case ecdh.P256():
		kdfOID, h = oidECDHSHA256KDF, crypto.SHA256
	case ecdh.P384():
		kdfOID, h = oidECDHSHA384KDF, crypto.SHA384
	case ecdh.P521():
		kdfOID, h = oidECDHSHA512KDF, crypto.SHA512
	default:
		return nil, fmt.Errorf("%w: cannot encrypt to %s: its curve", ErrUnsupported, cert.Subject)
	}
	eph, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	z, err := eph.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("svcms: encrypting to %s: %w", cert.Subject, err)
	}
	wrapAlg := element(func(b *cryptobyte.Builder) { addAlgorithm(b, oidAES256Wrap, nil) })
	kek := x963KDF(h, z, sharedInfo(wrapAlg, nil, 32), 32)
	clear(z)
	wrapped, err := keyWrap(kek, cek)
	clear(kek)
	if err != nil {
		return nil, err
	}
	return element(func(b *cryptobyte.Builder) {
		b.AddASN1(cbasn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
			b.AddASN1Int64(3)
			b.AddASN1(cbasn1.Tag(0).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.Tag(1).Constructed().ContextSpecific(), func(b *cryptobyte.Builder) {
					addAlgorithm(b, oidECPublicKey, func(b *cryptobyte.Builder) { b.AddASN1ObjectIdentifier(curveOID(curve)) })
					b.AddASN1BitString(eph.PublicKey().Bytes())
				})
			})
			addAlgorithm(b, kdfOID, func(b *cryptobyte.Builder) { b.AddBytes(wrapAlg) })
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
					addIssuerAndSerial(b, cert.RawIssuer, cert.SerialNumber)
					b.AddASN1OctetString(wrapped)
				})
			})
		})
	}), nil
}
