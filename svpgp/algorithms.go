package svpgp

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha3"
	"crypto/sha512"
	"fmt"
	"hash"

	"golang.org/x/crypto/blowfish"
	"golang.org/x/crypto/cast5"
	"golang.org/x/crypto/twofish"
)

// PublicKeyAlgorithm is an OpenPGP public-key algorithm ID (RFC 9580,
// section 9.1).
type PublicKeyAlgorithm uint8

// Public-key algorithms.
const (
	RSA            PublicKeyAlgorithm = 1
	RSAEncryptOnly PublicKeyAlgorithm = 2
	RSASignOnly    PublicKeyAlgorithm = 3
	ElGamal        PublicKeyAlgorithm = 16
	DSA            PublicKeyAlgorithm = 17
	ECDH           PublicKeyAlgorithm = 18
	ECDSA          PublicKeyAlgorithm = 19
	EdDSALegacy    PublicKeyAlgorithm = 22
	X25519         PublicKeyAlgorithm = 25
	X448           PublicKeyAlgorithm = 26
	Ed25519        PublicKeyAlgorithm = 27
	Ed448          PublicKeyAlgorithm = 28
)

func (a PublicKeyAlgorithm) String() string {
	switch a {
	case RSA:
		return "RSA"
	case RSAEncryptOnly:
		return "RSA (encrypt only)"
	case RSASignOnly:
		return "RSA (sign only)"
	case ElGamal:
		return "ElGamal"
	case DSA:
		return "DSA"
	case ECDH:
		return "ECDH"
	case ECDSA:
		return "ECDSA"
	case EdDSALegacy:
		return "EdDSA (legacy)"
	case X25519:
		return "X25519"
	case X448:
		return "X448"
	case Ed25519:
		return "Ed25519"
	case Ed448:
		return "Ed448"
	}
	return fmt.Sprintf("public-key algorithm %d", uint8(a))
}

// canSign reports whether the algorithm makes signatures at all.
func (a PublicKeyAlgorithm) canSign() bool {
	switch a {
	case RSA, RSASignOnly, DSA, ECDSA, EdDSALegacy, Ed25519, Ed448:
		return true
	}
	return false
}

// canEncrypt reports whether the algorithm encrypts session keys at all.
func (a PublicKeyAlgorithm) canEncrypt() bool {
	switch a {
	case RSA, RSAEncryptOnly, ElGamal, ECDH, X25519, X448:
		return true
	}
	return false
}

// HashAlgorithm is an OpenPGP hash algorithm ID (RFC 9580, section 9.5).
type HashAlgorithm uint8

// Hash algorithms. MD5 and RIPEMD-160 are named so they can be reported;
// they are never used.
const (
	MD5       HashAlgorithm = 1
	SHA1      HashAlgorithm = 2
	RIPEMD160 HashAlgorithm = 3
	SHA256    HashAlgorithm = 8
	SHA384    HashAlgorithm = 9
	SHA512    HashAlgorithm = 10
	SHA224    HashAlgorithm = 11
	SHA3_256  HashAlgorithm = 12
	SHA3_512  HashAlgorithm = 14
)

// String is the algorithm's text name as the Hash armor header writes it.
func (h HashAlgorithm) String() string {
	switch h {
	case MD5:
		return "MD5"
	case SHA1:
		return "SHA1"
	case RIPEMD160:
		return "RIPEMD160"
	case SHA256:
		return "SHA256"
	case SHA384:
		return "SHA384"
	case SHA512:
		return "SHA512"
	case SHA224:
		return "SHA224"
	case SHA3_256:
		return "SHA3-256"
	case SHA3_512:
		return "SHA3-512"
	}
	return fmt.Sprintf("hash algorithm %d", uint8(h))
}

// hashByName maps the Hash armor header's names back to algorithms.
func hashByName(name string) (HashAlgorithm, bool) {
	for _, h := range []HashAlgorithm{MD5, SHA1, RIPEMD160, SHA256, SHA384, SHA512, SHA224, SHA3_256, SHA3_512} {
		if h.String() == name {
			return h, true
		}
	}
	return 0, false
}

// cryptoHash is the standard library's name for the algorithm, for the
// ones this package computes.
func (h HashAlgorithm) cryptoHash() (crypto.Hash, bool) {
	switch h {
	case SHA1:
		return crypto.SHA1, true
	case SHA256:
		return crypto.SHA256, true
	case SHA384:
		return crypto.SHA384, true
	case SHA512:
		return crypto.SHA512, true
	case SHA224:
		return crypto.SHA224, true
	case SHA3_256:
		return crypto.SHA3_256, true
	case SHA3_512:
		return crypto.SHA3_512, true
	}
	return 0, false
}

// Size is the digest size in bytes, or 0 for an algorithm this package
// does not compute.
func (h HashAlgorithm) Size() int {
	if c, ok := h.cryptoHash(); ok {
		return c.Size()
	}
	return 0
}

// newHash starts a hash. MD5, RIPEMD-160 and unknown algorithms are refused.
func (h HashAlgorithm) newHash() (hash.Hash, error) {
	switch h {
	case SHA1:
		return sha1.New(), nil
	case SHA256:
		return sha256.New(), nil
	case SHA384:
		return sha512.New384(), nil
	case SHA512:
		return sha512.New(), nil
	case SHA224:
		return sha256.New224(), nil
	case SHA3_256:
		return sha3.New256(), nil
	case SHA3_512:
		return sha3.New512(), nil
	case MD5, RIPEMD160:
		return nil, unsupported("the %v hash is not accepted", h)
	}
	return nil, unsupported("%v", h)
}

// saltSize is the salt a version 6 signature must carry with this hash
// (RFC 9580, table 23), or 0 where version 6 signatures may not use it.
func (h HashAlgorithm) saltSize() int {
	switch h {
	case SHA256, SHA224, SHA3_256:
		return 16
	case SHA384:
		return 24
	case SHA512, SHA3_512:
		return 32
	}
	return 0
}

// CipherAlgorithm is an OpenPGP symmetric cipher ID (RFC 9580, section
// 9.3).
type CipherAlgorithm uint8

// Symmetric ciphers. Only AES is used to encrypt; TripleDES, CAST5,
// Blowfish and Twofish are decrypted for old data. IDEA and Camellia are
// refused.
const (
	IDEA        CipherAlgorithm = 1
	TripleDES   CipherAlgorithm = 2
	CAST5       CipherAlgorithm = 3
	Blowfish    CipherAlgorithm = 4
	AES128      CipherAlgorithm = 7
	AES192      CipherAlgorithm = 8
	AES256      CipherAlgorithm = 9
	Twofish     CipherAlgorithm = 10
	Camellia128 CipherAlgorithm = 11
	Camellia192 CipherAlgorithm = 12
	Camellia256 CipherAlgorithm = 13
)

func (c CipherAlgorithm) String() string {
	switch c {
	case IDEA:
		return "IDEA"
	case TripleDES:
		return "TripleDES"
	case CAST5:
		return "CAST5"
	case Blowfish:
		return "Blowfish"
	case AES128:
		return "AES-128"
	case AES192:
		return "AES-192"
	case AES256:
		return "AES-256"
	case Twofish:
		return "Twofish"
	case Camellia128:
		return "Camellia-128"
	case Camellia192:
		return "Camellia-192"
	case Camellia256:
		return "Camellia-256"
	}
	return fmt.Sprintf("cipher %d", uint8(c))
}

// KeySize is the key size in bytes, or 0 for a cipher this package does
// not implement.
func (c CipherAlgorithm) KeySize() int {
	switch c {
	case TripleDES:
		return 24
	case CAST5, Blowfish, AES128:
		return 16
	case AES192:
		return 24
	case AES256, Twofish:
		return 32
	}
	return 0
}

// BlockSize is the block size in bytes, or 0 for a cipher this package does
// not implement.
func (c CipherAlgorithm) BlockSize() int {
	switch c {
	case TripleDES, CAST5, Blowfish:
		return 8
	case AES128, AES192, AES256, Twofish:
		return 16
	}
	return 0
}

// isAES reports whether the cipher is one of the AES variants, the only
// ciphers this package encrypts with and the only ones it accepts in AEAD
// modes.
func (c CipherAlgorithm) isAES() bool { return c == AES128 || c == AES192 || c == AES256 }

// legacy reports whether decrypting with the cipher deserves a warning
// that the message's confidentiality is suspect (RFC 9580, section 9.3).
func (c CipherAlgorithm) legacy() bool {
	return c == TripleDES || c == CAST5 || c == Blowfish
}

// newBlock makes the block cipher for a key.
func (c CipherAlgorithm) newBlock(key []byte) (cipher.Block, error) {
	if c.KeySize() == 0 {
		return nil, unsupported("the %v cipher", c)
	}
	if len(key) != c.KeySize() {
		return nil, malformed("%v key is %d bytes, want %d", c, len(key), c.KeySize())
	}
	switch c {
	case TripleDES:
		return des.NewTripleDESCipher(key)
	case CAST5:
		return cast5.NewCipher(key)
	case Blowfish:
		return blowfish.NewCipher(key)
	case AES128, AES192, AES256:
		return aes.NewCipher(key)
	case Twofish:
		return twofish.NewCipher(key)
	}
	return nil, unsupported("the %v cipher", c)
}

// AEADAlgorithm is an OpenPGP AEAD mode ID (RFC 9580, section 9.6).
type AEADAlgorithm uint8

// AEAD modes. OCB is the one every implementation must have.
const (
	EAX AEADAlgorithm = 1
	OCB AEADAlgorithm = 2
	GCM AEADAlgorithm = 3
)

func (a AEADAlgorithm) String() string {
	switch a {
	case EAX:
		return "EAX"
	case OCB:
		return "OCB"
	case GCM:
		return "GCM"
	}
	return fmt.Sprintf("AEAD mode %d", uint8(a))
}

// nonceSize is the nonce size the mode uses in OpenPGP, or 0 if unknown.
func (a AEADAlgorithm) nonceSize() int {
	switch a {
	case EAX:
		return 16
	case OCB:
		return 15
	case GCM:
		return 12
	}
	return 0
}

// aeadTagSize is the tag size of every OpenPGP AEAD mode.
const aeadTagSize = 16

// newAEAD makes the AEAD for a cipher and key. Only AES is accepted.
func (a AEADAlgorithm) newAEAD(c CipherAlgorithm, key []byte) (cipher.AEAD, error) {
	if !c.isAES() {
		return nil, unsupported("the %v cipher with AEAD", c)
	}
	block, err := c.newBlock(key)
	if err != nil {
		return nil, err
	}
	switch a {
	case EAX:
		return newEAX(block)
	case OCB:
		return newOCB(block, 15, aeadTagSize)
	case GCM:
		return cipher.NewGCM(block)
	}
	return nil, unsupported("%v", a)
}

// CompressionAlgorithm is an OpenPGP compression algorithm ID (RFC 9580,
// section 9.4).
type CompressionAlgorithm uint8

// Compression algorithms. BZip2 is read but never written.
const (
	Uncompressed CompressionAlgorithm = 0
	ZIP          CompressionAlgorithm = 1
	ZLIB         CompressionAlgorithm = 2
	BZip2        CompressionAlgorithm = 3
)

func (c CompressionAlgorithm) String() string {
	switch c {
	case Uncompressed:
		return "uncompressed"
	case ZIP:
		return "ZIP"
	case ZLIB:
		return "ZLIB"
	case BZip2:
		return "BZip2"
	}
	return fmt.Sprintf("compression %d", uint8(c))
}

// SignatureType is an OpenPGP signature type ID (RFC 9580, section 5.2.1).
type SignatureType uint8

// Signature types.
const (
	SigBinary              SignatureType = 0x00
	SigText                SignatureType = 0x01
	SigStandalone          SignatureType = 0x02
	SigGenericCert         SignatureType = 0x10
	SigPersonaCert         SignatureType = 0x11
	SigCasualCert          SignatureType = 0x12
	SigPositiveCert        SignatureType = 0x13
	SigSubkeyBinding       SignatureType = 0x18
	SigPrimaryKeyBinding   SignatureType = 0x19
	SigDirectKey           SignatureType = 0x1F
	SigKeyRevocation       SignatureType = 0x20
	SigSubkeyRevocation    SignatureType = 0x28
	SigCertRevocation      SignatureType = 0x30
	SigTimestamp           SignatureType = 0x40
	SigThirdPartyConfirmed SignatureType = 0x50
)

func (t SignatureType) String() string {
	switch t {
	case SigBinary:
		return "binary"
	case SigText:
		return "text"
	case SigStandalone:
		return "standalone"
	case SigGenericCert:
		return "generic certification"
	case SigPersonaCert:
		return "persona certification"
	case SigCasualCert:
		return "casual certification"
	case SigPositiveCert:
		return "positive certification"
	case SigSubkeyBinding:
		return "subkey binding"
	case SigPrimaryKeyBinding:
		return "primary key binding"
	case SigDirectKey:
		return "direct key"
	case SigKeyRevocation:
		return "key revocation"
	case SigSubkeyRevocation:
		return "subkey revocation"
	case SigCertRevocation:
		return "certification revocation"
	case SigTimestamp:
		return "timestamp"
	case SigThirdPartyConfirmed:
		return "third-party confirmation"
	}
	return fmt.Sprintf("signature type 0x%02x", uint8(t))
}

func (t SignatureType) isCertification() bool {
	return t >= SigGenericCert && t <= SigPositiveCert
}

// Key flags (RFC 9580, section 5.2.3.29), first octet.
const (
	flagCertify        = 0x01
	flagSign           = 0x02
	flagEncryptComms   = 0x04
	flagEncryptStorage = 0x08
	flagAuthenticate   = 0x20
)

// Features (RFC 9580, section 5.2.3.32), first octet.
const (
	featureSEIPDv1 = 0x01
	featureSEIPDv2 = 0x08
)
