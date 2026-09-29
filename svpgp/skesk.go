package svpgp

import (
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"slices"
)

// Symmetric-key encrypted session key packets (RFC 9580, section 5.3):
// version 4, before a v1 SEIPD packet, and version 6, before a v2 one.

type skesk struct {
	version int
	cipher  CipherAlgorithm // v4: also the session key's cipher when there is no ESK
	aead    AEADAlgorithm   // v6
	s2k     *s2k
	iv      []byte // v6: the AEAD nonce
	esk     []byte // the encrypted session key (v6: with its tag); may be empty in v4
}

func parseSKESK(body []byte) (*skesk, error) {
	p := newParser(body)
	k := &skesk{version: int(p.u8())}
	switch k.version {
	case 4:
		k.cipher = CipherAlgorithm(p.u8())
		if p.err != nil {
			return nil, p.err
		}
		spec, err := parseS2K(p)
		if err != nil {
			return nil, err
		}
		k.s2k = spec
		k.esk = p.rest()
		if len(k.esk) > 0 && !spec.salted() {
			return nil, malformed("v4 SKESK with an encrypted session key and an unsalted S2K")
		}
	case 6:
		n := int(p.u8())
		q := newParser(p.bytes(n))
		if p.err != nil {
			return nil, p.err
		}
		k.cipher = CipherAlgorithm(q.u8())
		k.aead = AEADAlgorithm(q.u8())
		s2kLen := int(q.u8())
		sp := newParser(q.bytes(s2kLen))
		if q.err != nil {
			return nil, q.err
		}
		spec, err := parseS2K(sp)
		if err != nil {
			return nil, err
		}
		sp.done()
		if sp.err != nil {
			return nil, sp.err
		}
		if spec.typ == s2kGNU {
			return nil, malformed("GnuPG S2K extension in an SKESK")
		}
		k.s2k = spec
		if k.aead.nonceSize() == 0 {
			return nil, unsupported("v6 SKESK with %v", k.aead)
		}
		k.iv = q.bytes(k.aead.nonceSize())
		q.done()
		if q.err != nil {
			return nil, q.err
		}
		k.esk = p.rest()
		if len(k.esk) <= aeadTagSize {
			return nil, malformed("v6 SKESK without an encrypted session key")
		}
	default:
		if p.err != nil {
			return nil, p.err
		}
		return nil, unsupported("version %d SKESK packets", k.version)
	}
	if p.err != nil {
		return nil, p.err
	}
	return k, nil
}

// decrypt recovers the session key with a passphrase. A version 6 packet
// authenticates it, so a wrong passphrase is ErrPassphrase; a version 4
// packet cannot tell, and a wrong passphrase only shows when the data
// fails to decrypt.
func (k *skesk) decrypt(passphrase []byte, v2Cipher CipherAlgorithm, lim Limits) (CipherAlgorithm, []byte, error) {
	if k.cipher.KeySize() == 0 {
		return 0, nil, unsupported("SKESK with %v", k.cipher)
	}
	derived, err := k.s2k.derive(passphrase, k.cipher.KeySize(), k.version == 6, lim)
	if err != nil {
		return 0, nil, err
	}
	if k.version == 4 {
		if len(k.esk) == 0 {
			return k.cipher, derived, nil
		}
		defer clear(derived)
		block, err := k.cipher.newBlock(derived)
		if err != nil {
			return 0, nil, err
		}
		plain := make([]byte, len(k.esk))
		newCFB(block, make([]byte, block.BlockSize()), true).XORKeyStream(plain, k.esk)
		defer clear(plain)
		alg := CipherAlgorithm(plain[0])
		if alg.KeySize() == 0 || len(plain)-1 != alg.KeySize() {
			return 0, nil, ErrPassphrase
		}
		return alg, slices.Clone(plain[1:]), nil
	}
	defer clear(derived)
	info := []byte{0xC0 | byte(ptSKESK), 6, byte(k.cipher), byte(k.aead)}
	kek, err := hkdf.Key(sha256.New, derived, nil, string(info), k.cipher.KeySize())
	if err != nil {
		return 0, nil, err
	}
	defer clear(kek)
	aead, err := k.aead.newAEAD(k.cipher, kek)
	if err != nil {
		return 0, nil, err
	}
	key, err := aead.Open(nil, k.iv, k.esk, info)
	if err != nil {
		return 0, nil, ErrPassphrase
	}
	if len(key) != v2Cipher.KeySize() {
		clear(key)
		return 0, nil, ErrPassphrase
	}
	return v2Cipher, key, nil
}

// newSKESK makes an SKESK packet body that encrypts the session key under
// a passphrase: version 4 (for v1 SEIPD) with iterated S2K and AES-256-CFB,
// or version 6 (for v2 SEIPD) with Argon2 and AES-256 in the given AEAD
// mode.
func newSKESK(version int, passphrase []byte, alg CipherAlgorithm, sessionKey []byte, aeadMode AEADAlgorithm) ([]byte, error) {
	const kekCipher = AES256
	if version == 4 {
		spec := newIteratedS2K()
		derived, err := spec.derive(passphrase, kekCipher.KeySize(), false, DefaultLimits)
		if err != nil {
			return nil, err
		}
		defer clear(derived)
		block, err := kekCipher.newBlock(derived)
		if err != nil {
			return nil, err
		}
		plain := append([]byte{byte(alg)}, sessionKey...)
		defer clear(plain)
		esk := make([]byte, len(plain))
		newCFB(block, make([]byte, block.BlockSize()), false).XORKeyStream(esk, plain)
		body := append([]byte{4, byte(kekCipher)}, spec.bytes()...)
		return append(body, esk...), nil
	}
	spec := newArgon2S2K()
	derived, err := spec.derive(passphrase, kekCipher.KeySize(), true, DefaultLimits)
	if err != nil {
		return nil, err
	}
	defer clear(derived)
	info := []byte{0xC0 | byte(ptSKESK), 6, byte(kekCipher), byte(aeadMode)}
	kek, err := hkdf.Key(sha256.New, derived, nil, string(info), kekCipher.KeySize())
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	aead, err := aeadMode.newAEAD(kekCipher, kek)
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aeadMode.nonceSize())
	rand.Read(iv)
	specBytes := spec.bytes()
	fields := []byte{byte(kekCipher), byte(aeadMode), byte(len(specBytes))}
	fields = append(append(fields, specBytes...), iv...)
	body := append([]byte{6, byte(len(fields))}, fields...)
	return aead.Seal(body, iv, sessionKey, info), nil
}
