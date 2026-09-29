package svpgp

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"
	"slices"
)

// Public-key encrypted session key packets (RFC 9580, section 5.1):
// version 3, before a v1 SEIPD packet, and version 6, before a v2 one.

type pkesk struct {
	version    int
	keyID      uint64 // version 3; zero for an anonymous recipient
	keyVersion int    // version 6; zero for an anonymous recipient
	fp         []byte // version 6
	alg        PublicKeyAlgorithm
	fields     []byte // the algorithm-specific fields
}

// errSessionKey is any failure to get a session key out of a PKESK. It is
// deliberately uninformative (RFC 9580, section 13.5).
var errSessionKey = errors.New("svpgp: session key decryption failed")

func parsePKESK(body []byte) (*pkesk, error) {
	p := newParser(body)
	k := &pkesk{version: int(p.u8())}
	switch k.version {
	case 3:
		if id := p.bytes(8); p.err == nil {
			k.keyID = binary.BigEndian.Uint64(id)
		}
	case 6:
		n := int(p.u8())
		if p.err == nil && n != 0 {
			k.keyVersion = int(p.u8())
			k.fp = p.bytes(n - 1)
			if p.err == nil && !(k.keyVersion == 4 && len(k.fp) == 20 || k.keyVersion == 6 && len(k.fp) == 32) {
				return nil, malformed("PKESK recipient of version %d with a %d-byte fingerprint", k.keyVersion, len(k.fp))
			}
		}
	default:
		if p.err != nil {
			return nil, p.err
		}
		return nil, unsupported("version %d PKESK packets", k.version)
	}
	k.alg = PublicKeyAlgorithm(p.u8())
	k.fields = p.rest()
	if p.err != nil {
		return nil, p.err
	}
	return k, nil
}

// anonymous reports whether the packet hides its recipient.
func (k *pkesk) anonymous() bool {
	if k.version == 3 {
		return k.keyID == 0
	}
	return k.fp == nil
}

// matches reports whether the packet names this (sub)key.
func (k *pkesk) matches(pk *publicKey) bool {
	if k.version == 3 {
		return k.keyID == pk.keyID
	}
	return k.keyVersion == pk.version && subtle.ConstantTimeCompare(k.fp, pk.fp) == 1
}

// decrypt recovers the session key with a secret key. For a version 3
// packet it also returns the cipher; for version 6 the cipher comes from
// the SEIPD packet and is passed in, to check the key size.
func (k *pkesk) decrypt(sk *secretKey, v2Cipher CipherAlgorithm) (CipherAlgorithm, []byte, error) {
	pk := sk.pub
	if k.alg != pk.alg && !(k.alg == RSA && pk.alg == RSAEncryptOnly || k.alg == RSAEncryptOnly && pk.alg == RSA) {
		return 0, nil, errSessionKey
	}
	sp, err := sk.parts()
	if err != nil {
		return 0, nil, err
	}
	defer sp.wipe()
	p := newParser(k.fields)
	strict := k.version == 6
	var plain []byte // what was encrypted: [cipher] key [checksum]
	switch pk.alg {
	case RSA, RSAEncryptOnly:
		c := p.mpi(strict)
		p.done()
		if p.err != nil || len(c) > pk.rsa.Size() {
			return 0, nil, errSessionKey
		}
		padded, _ := fixedOctets(c, pk.rsa.Size())
		plain, err = rsa.DecryptPKCS1v15(nil, sp.rsa, padded)
		if err != nil {
			return 0, nil, errSessionKey
		}
	case ElGamal:
		c1, c2 := p.mpi(strict), p.mpi(strict)
		p.done()
		if p.err != nil {
			return 0, nil, errSessionKey
		}
		if plain, err = elGamalDecrypt(pk.elg, sp.elgX, c1, c2); err != nil {
			return 0, nil, errSessionKey
		}
	case ECDH:
		point := p.mpi(strict)
		n := int(p.u8())
		wrapped := p.bytes(n)
		p.done()
		if p.err != nil || n == 0xFF {
			return 0, nil, errSessionKey
		}
		native := point
		if pk.curve == curveCurve25519Legacy {
			var ok bool
			if native, ok = prefixedOctets(point, 32); !ok || !canonicalX25519(native) {
				return 0, nil, errSessionKey
			}
		}
		eph, err := pk.curve.ecdh.NewPublicKey(native)
		if err != nil {
			return 0, nil, errSessionKey
		}
		shared, err := sp.ecdh.ECDH(eph)
		if err != nil {
			return 0, nil, errSessionKey
		}
		kek, err := ecdhKDF(pk, shared)
		clear(shared)
		if err != nil {
			return 0, nil, errSessionKey
		}
		padded, err := keyUnwrap(kek, wrapped)
		clear(kek)
		if err != nil {
			return 0, nil, errSessionKey
		}
		var ok bool
		if plain, ok = pkcs5Unpad(padded); !ok {
			clear(padded)
			return 0, nil, errSessionKey
		}
	case X25519:
		eph := p.bytes(32)
		n := int(p.u8())
		rest := p.bytes(n)
		p.done()
		if p.err != nil || !canonicalX25519(eph) {
			return 0, nil, errSessionKey
		}
		var alg CipherAlgorithm
		if k.version == 3 {
			if len(rest) < 1 {
				return 0, nil, errSessionKey
			}
			alg, rest = CipherAlgorithm(rest[0]), rest[1:]
			if !alg.isAES() {
				return 0, nil, errSessionKey
			}
		}
		ephKey, err := ecdh.X25519().NewPublicKey(eph)
		if err != nil {
			return 0, nil, errSessionKey
		}
		shared, err := sp.ecdh.ECDH(ephKey)
		if err != nil {
			return 0, nil, errSessionKey
		}
		kek, err := x25519KEK(eph, pk.point, shared)
		clear(shared)
		if err != nil {
			return 0, nil, errSessionKey
		}
		key, err := keyUnwrap(kek, rest)
		clear(kek)
		if err != nil {
			return 0, nil, errSessionKey
		}
		// No checksum: the key wrap authenticated it.
		want := alg
		if k.version == 6 {
			want = v2Cipher
		}
		if len(key) != want.KeySize() {
			clear(key)
			return 0, nil, errSessionKey
		}
		return want, key, nil
	default:
		return 0, nil, errSessionKey
	}
	defer clear(plain)
	return parseSessionKey(plain, k.version == 3, v2Cipher)
}

// canonicalX25519 reports whether an X25519 public key is in canonical
// form: below 2^255 - 19, and so with the top bit clear. X25519 would
// ignore the top bit (RFC 7748, section 5), which would let a ciphertext be
// changed without the change being noticed; no implementation makes such
// keys, so they are refused.
func canonicalX25519(u []byte) bool {
	if len(u) != 32 || u[31]&0x80 != 0 {
		return false
	}
	if u[31] != 0x7F || u[0] < 0xED {
		return true
	}
	for _, b := range u[1:31] {
		if b != 0xFF {
			return true
		}
	}
	return false
}

// parseSessionKey checks and splits [cipher] key checksum.
func parseSessionKey(plain []byte, withCipher bool, v2Cipher CipherAlgorithm) (CipherAlgorithm, []byte, error) {
	alg := v2Cipher
	if withCipher {
		if len(plain) < 1 {
			return 0, nil, errSessionKey
		}
		alg, plain = CipherAlgorithm(plain[0]), plain[1:]
	}
	if alg.KeySize() == 0 || len(plain) != alg.KeySize()+2 {
		return 0, nil, errSessionKey
	}
	key := plain[:len(plain)-2]
	if checksum16(key) != binary.BigEndian.Uint16(plain[len(key):]) {
		return 0, nil, errSessionKey
	}
	return alg, slices.Clone(key), nil
}

// elGamalDecrypt recovers the PKCS #1 v1.5 encoded message. The secret
// exponent is blinded with a random multiple of p-1, since math/big is not
// constant time.
func elGamalDecrypt(k *elGamalKey, x *big.Int, c1b, c2b []byte) ([]byte, error) {
	c1, c2 := new(big.Int).SetBytes(c1b), new(big.Int).SetBytes(c2b)
	one := big.NewInt(1)
	pm1 := new(big.Int).Sub(k.p, one)
	if c1.Cmp(one) <= 0 || c1.Cmp(pm1) >= 0 || c2.Sign() <= 0 || c2.Cmp(k.p) >= 0 {
		return nil, errSessionKey
	}
	r := make([]byte, 16)
	rand.Read(r)
	blinded := new(big.Int).Mul(new(big.Int).SetBytes(r), pm1)
	blinded.Add(blinded, x)
	s := new(big.Int).Exp(c1, blinded, k.p)
	clearBig(blinded)
	sInv := new(big.Int).ModInverse(s, k.p)
	if sInv == nil {
		return nil, errSessionKey
	}
	m := new(big.Int).Mul(c2, sInv)
	m.Mod(m, k.p)
	em, ok := fixedOctets(m.Bytes(), (k.p.BitLen()+7)/8)
	clearBig(m)
	clearBig(s)
	if !ok {
		return nil, errSessionKey
	}
	defer clear(em)
	return emePKCS1Decode(em)
}

// emePKCS1Decode undoes EME-PKCS1-v1_5 (RFC 9580, section 12.1.2) without
// branching on where the separator is.
func emePKCS1Decode(em []byte) ([]byte, error) {
	if len(em) < 11 {
		return nil, errSessionKey
	}
	good := subtle.ConstantTimeByteEq(em[0], 0) & subtle.ConstantTimeByteEq(em[1], 2)
	lookingForIndex, index := 1, 0
	for i := 2; i < len(em); i++ {
		zero := subtle.ConstantTimeByteEq(em[i], 0)
		index = subtle.ConstantTimeSelect(lookingForIndex&zero, i, index)
		lookingForIndex = subtle.ConstantTimeSelect(zero, 0, lookingForIndex)
	}
	good &= subtle.ConstantTimeLessOrEq(10, index) // at least 8 bytes of padding
	good &= 1 - lookingForIndex
	if good != 1 {
		return nil, errSessionKey
	}
	return slices.Clone(em[index+1:]), nil
}

// encryptSessionKey makes a PKESK packet body for one recipient (sub)key.
// For version 3 the cipher is encrypted with the key; for version 6 it is
// not.
func encryptSessionKey(version int, pk *publicKey, alg CipherAlgorithm, key []byte) ([]byte, error) {
	if pk.unusable != nil {
		return nil, pk.unusable
	}
	body := []byte{byte(version)}
	if version == 3 {
		body = appendU32(body, uint32(pk.keyID>>32))
		body = appendU32(body, uint32(pk.keyID))
	} else {
		body = append(body, byte(len(pk.fp)+1), byte(pk.version))
		body = append(body, pk.fp...)
	}
	body = append(body, byte(pk.alg))
	// [cipher] key checksum, for the algorithms that carry a checksum.
	plain := []byte{}
	if version == 3 {
		plain = append(plain, byte(alg))
	}
	plain = append(plain, key...)
	plain = binary.BigEndian.AppendUint16(plain, checksum16(key))
	defer clear(plain)
	switch pk.alg {
	case RSA, RSAEncryptOnly:
		c, err := rsa.EncryptPKCS1v15(rand.Reader, pk.rsa, plain)
		if err != nil {
			return nil, err
		}
		return appendMPI(body, c), nil
	case ECDH:
		eph, err := pk.curve.ecdh.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		shared, err := eph.ECDH(pk.ecdh)
		if err != nil {
			return nil, err
		}
		kek, err := ecdhKDF(pk, shared)
		clear(shared)
		if err != nil {
			return nil, err
		}
		padded := pkcs5Pad(slices.Clone(plain))
		wrapped, err := keyWrap(kek, padded)
		clear(kek)
		clear(padded)
		if err != nil {
			return nil, err
		}
		point := eph.PublicKey().Bytes()
		if pk.curve == curveCurve25519Legacy {
			point = append([]byte{0x40}, point...)
		}
		body = appendMPI(body, point)
		body = append(body, byte(len(wrapped)))
		return append(body, wrapped...), nil
	case X25519:
		if version == 3 && !alg.isAES() {
			return nil, unsupported("X25519 with %v", alg)
		}
		eph, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		shared, err := eph.ECDH(pk.ecdh)
		if err != nil {
			return nil, err
		}
		ephPub := eph.PublicKey().Bytes()
		kek, err := x25519KEK(ephPub, pk.point, shared)
		clear(shared)
		if err != nil {
			return nil, err
		}
		wrapped, err := keyWrap(kek, key)
		clear(kek)
		if err != nil {
			return nil, err
		}
		body = append(body, ephPub...)
		if version == 3 {
			body = append(body, byte(len(wrapped)+1), byte(alg))
		} else {
			body = append(body, byte(len(wrapped)))
		}
		return append(body, wrapped...), nil
	case ElGamal:
		return nil, unsupported("encrypting to ElGamal keys")
	}
	return nil, unsupported("encrypting to %v keys", pk.alg)
}
