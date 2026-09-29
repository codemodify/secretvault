package svcms

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/hmac"
	"crypto/pbkdf2"
	"encoding/asn1"
	"fmt"
	"unicode/utf16"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Password-based encryption for PKCS #12: PBES2 with PBKDF2 (RFC 8018),
// and, for reading only, PKCS #12's own schemes (RFC 7292, appendix B and
// C) and its MAC.

var (
	oidPBES2            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 13}
	oidPBKDF2           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 12}
	oidPBMAC1           = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 5, 14}
	oidHMACWithSHA1     = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 7}
	oidHMACWithSHA224   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 8}
	oidHMACWithSHA256   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 9}
	oidHMACWithSHA384   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 10}
	oidHMACWithSHA512   = asn1.ObjectIdentifier{1, 2, 840, 113549, 2, 11}
	oidPBEWithSHA128RC4 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 1}
	oidPBEWithSHA40RC4  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 2}
	oidPBEWithSHA3DES   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 3}
	oidPBEWithSHA2DES   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 4}
	oidPBEWithSHA128RC2 = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 5}
	oidPBEWithSHA40RC2  = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 12, 1, 6}
)

func hmacHash(oid asn1.ObjectIdentifier) (crypto.Hash, error) {
	switch {
	case oid.Equal(oidHMACWithSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidHMACWithSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidHMACWithSHA512):
		return crypto.SHA512, nil
	case oid.Equal(oidHMACWithSHA224):
		return crypto.SHA224, nil
	case oid.Equal(oidHMACWithSHA1):
		return crypto.SHA1, nil
	}
	return 0, unsupported("PRF %v", oid)
}

// bmpPassword is the password as PKCS #12's own KDF takes it: UTF-16,
// big-endian, with a terminating zero (RFC 7292, appendix B.1). An empty
// password is two zero bytes; some writers use no bytes at all instead,
// which callers try as well.
func bmpPassword(password []byte) []byte {
	units := utf16.Encode([]rune(string(password)))
	out := make([]byte, 0, 2*len(units)+2)
	for _, u := range units {
		out = append(out, byte(u>>8), byte(u))
	}
	clear(units)
	return append(out, 0, 0)
}

// pkcs12KDF is RFC 7292's key derivation (appendix B.2): id 1 makes
// cipher keys, 2 IVs, 3 MAC keys.
func pkcs12KDF(h crypto.Hash, id byte, password, salt []byte, iter, n int) []byte {
	u := h.Size()
	v := 64
	if h == crypto.SHA384 || h == crypto.SHA512 {
		v = 128
	}
	fill := func(b []byte) []byte {
		if len(b) == 0 {
			return nil
		}
		out := make([]byte, v*((len(b)+v-1)/v))
		for i := range out {
			out[i] = b[i%len(b)]
		}
		return out
	}
	d := make([]byte, v)
	for i := range d {
		d[i] = id
	}
	s, p := fill(salt), fill(password)
	I := append(s, p...)
	clear(p)
	defer clear(I)
	var out []byte
	for len(out) < n {
		hh := h.New()
		hh.Write(d)
		hh.Write(I)
		a := hh.Sum(nil)
		for i := 1; i < iter; i++ {
			hh.Reset()
			hh.Write(a)
			a = hh.Sum(a[:0])
		}
		out = append(out, a...)
		if len(out) >= n {
			clear(a)
			break
		}
		// I_j = (I_j + B + 1) mod 2^(8v), for each v-byte block of I,
		// where B is A repeated to v bytes.
		b := make([]byte, v)
		for i := range b {
			b[i] = a[i%u]
		}
		for j := 0; j < len(I); j += v {
			carry := 1
			for k := v - 1; k >= 0; k-- {
				sum := int(I[j+k]) + int(b[k]) + carry
				I[j+k] = byte(sum)
				carry = sum >> 8
			}
		}
		clear(a)
		clear(b)
	}
	clear(out[n:])
	return out[:n]
}

// pbePassword is a password in the forms the schemes take: its UTF-8
// bytes for PBES2, and for PKCS #12's own KDF its UTF-16 encodings to try
// (an empty password has two, which writers disagree about).
type pbePassword struct {
	raw []byte
	bmp [][]byte
}

func newPBEPassword(password []byte) *pbePassword {
	p := &pbePassword{raw: password, bmp: [][]byte{bmpPassword(password)}}
	if len(password) == 0 {
		p.bmp = append(p.bmp, []byte{})
	}
	return p
}

func (p *pbePassword) wipe() {
	for _, b := range p.bmp {
		clear(b)
	}
}

// pbeDecrypt decrypts data protected by a password-based encryption
// algorithm. A wrong password is ErrPassword. legacy is set to the
// algorithm's name when it is one of the old PKCS #12 schemes.
func pbeDecrypt(alg algorithm, password *pbePassword, data []byte, lim Limits) (plain []byte, legacy string, err error) {
	switch {
	case alg.oid.Equal(oidPBES2):
		block, iv, key, err := pbes2Key(alg.params, password.raw, lim)
		if err != nil {
			return nil, "", err
		}
		clear(key)
		plain, err = cbcDecrypt(block, iv, data)
		if err != nil {
			return nil, "", ErrPassword
		}
		return plain, "", nil
	case alg.oid.Equal(oidPBEWithSHA3DES), alg.oid.Equal(oidPBEWithSHA2DES),
		alg.oid.Equal(oidPBEWithSHA128RC2), alg.oid.Equal(oidPBEWithSHA40RC2):
		var iter int
		p := cryptobyte.String(alg.params)
		var seq, salt cryptobyte.String
		if !p.ReadASN1(&seq, cbasn1.SEQUENCE) || !p.Empty() || !seq.ReadASN1(&salt, cbasn1.OCTET_STRING) ||
			!seq.ReadASN1Integer(&iter) || !seq.Empty() {
			return nil, "", malformed("PKCS #12 PBE parameters")
		}
		if iter < 1 || iter > lim.MaxIterations {
			return nil, "", limit("%d iterations (the limit is %d)", iter, lim.MaxIterations)
		}
		keyLen := 24
		switch {
		case alg.oid.Equal(oidPBEWithSHA3DES):
			legacy = "pbeWithSHAAnd3-KeyTripleDES-CBC"
		case alg.oid.Equal(oidPBEWithSHA2DES):
			legacy, keyLen = "pbeWithSHAAnd2-KeyTripleDES-CBC", 16
		case alg.oid.Equal(oidPBEWithSHA128RC2):
			legacy, keyLen = "pbeWithSHAAnd128BitRC2-CBC", 16
		default:
			legacy, keyLen = "pbeWithSHAAnd40BitRC2-CBC", 5
		}
		for _, pw := range password.bmp {
			key := pkcs12KDF(crypto.SHA1, 1, pw, salt, iter, keyLen)
			iv := pkcs12KDF(crypto.SHA1, 2, pw, salt, iter, 8)
			var block cipher.Block
			switch {
			case alg.oid.Equal(oidPBEWithSHA3DES):
				block, _ = des.NewTripleDESCipher(key)
			case alg.oid.Equal(oidPBEWithSHA2DES):
				k := append(append([]byte{}, key...), key[:8]...)
				block, _ = des.NewTripleDESCipher(k)
				clear(k)
			default:
				block = newRC2(key, keyLen*8)
			}
			clear(key)
			if plain, err = cbcDecrypt(block, iv, data); err == nil {
				return plain, legacy, nil
			}
		}
		return nil, legacy, ErrPassword
	case alg.oid.Equal(oidPBEWithSHA128RC4), alg.oid.Equal(oidPBEWithSHA40RC4):
		return nil, "", unsupported("RC4 password-based encryption")
	}
	return nil, "", unsupported("password-based encryption %v", alg.oid)
}

func cbcDecrypt(block cipher.Block, iv, data []byte) ([]byte, error) {
	bs := block.BlockSize()
	if len(data) == 0 || len(data)%bs != 0 || len(iv) != bs {
		return nil, ErrPassword
	}
	plain := make([]byte, len(data))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, data)
	n, ok := unpad(plain, bs)
	if !ok {
		clear(plain)
		return nil, ErrPassword
	}
	return plain[:n], nil
}

// pbkdf2Params are PBKDF2-params (RFC 8018, appendix A.2).
type pbkdf2Params struct {
	salt   []byte
	iter   int
	keyLen int // 0 when absent
	prf    crypto.Hash
}

func parsePBKDF2(alg algorithm, lim Limits) (*pbkdf2Params, error) {
	if !alg.oid.Equal(oidPBKDF2) {
		return nil, unsupported("key derivation %v", alg.oid)
	}
	p := cryptobyte.String(alg.params)
	var seq, salt cryptobyte.String
	out := &pbkdf2Params{prf: crypto.SHA1}
	if !p.ReadASN1(&seq, cbasn1.SEQUENCE) || !p.Empty() {
		return nil, malformed("PBKDF2 parameters")
	}
	if !seq.ReadASN1(&salt, cbasn1.OCTET_STRING) {
		return nil, unsupported("PBKDF2 with a salt from elsewhere")
	}
	out.salt = salt
	if !seq.ReadASN1Integer(&out.iter) {
		return nil, malformed("PBKDF2 iteration count")
	}
	if out.iter < 1 || out.iter > lim.MaxIterations {
		return nil, limit("%d iterations (the limit is %d)", out.iter, lim.MaxIterations)
	}
	if seq.PeekASN1Tag(cbasn1.INTEGER) && (!seq.ReadASN1Integer(&out.keyLen) || out.keyLen < 1 || out.keyLen > 64) {
		return nil, malformed("PBKDF2 key length")
	}
	if !seq.Empty() {
		var prf algorithm
		if !readAlgorithm(&seq, &prf) || !seq.Empty() {
			return nil, malformed("PBKDF2 parameters")
		}
		h, err := hmacHash(prf.oid)
		if err != nil {
			return nil, err
		}
		out.prf = h
	}
	return out, nil
}

func (p *pbkdf2Params) derive(password []byte, n int) ([]byte, error) {
	// crypto/pbkdf2 takes the password as a string, which cannot be
	// wiped; svcrypto lives with the same.
	return pbkdf2.Key(p.prf.New, string(password), p.salt, p.iter, n)
}

// pbes2Key reads PBES2-params and derives the cipher and key they
// describe. The password goes into PBKDF2 as its UTF-8 bytes, as OpenSSL
// and Windows do.
func pbes2Key(params, password []byte, lim Limits) (cipher.Block, []byte, []byte, error) {
	p := cryptobyte.String(params)
	var seq cryptobyte.String
	var kdf, enc algorithm
	if !p.ReadASN1(&seq, cbasn1.SEQUENCE) || !p.Empty() || !readAlgorithm(&seq, &kdf) || !readAlgorithm(&seq, &enc) || !seq.Empty() {
		return nil, nil, nil, malformed("PBES2 parameters")
	}
	kp, err := parsePBKDF2(kdf, lim)
	if err != nil {
		return nil, nil, nil, err
	}
	c, err := parseContentCipher(enc)
	if err != nil {
		return nil, nil, nil, err
	}
	if c.gcm {
		return nil, nil, nil, unsupported("PBES2 with %s", c.name)
	}
	if kp.keyLen != 0 && kp.keyLen != c.keyLen {
		return nil, nil, nil, malformed("PBES2 key length %d for %s", kp.keyLen, c.name)
	}
	key, err := kp.derive(password, c.keyLen)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("svcms: PBKDF2: %w", err)
	}
	block, err := c.block(key)
	if err != nil {
		clear(key)
		return nil, nil, nil, err
	}
	return block, c.iv, key, nil
}

// pbes2Encrypt encrypts with PBES2: PBKDF2 with HMAC-SHA-256 and
// AES-256-CBC. It returns the AlgorithmIdentifier and the ciphertext.
func pbes2Encrypt(password, plain []byte, iter int, rnd func([]byte)) ([]byte, []byte, error) {
	salt := make([]byte, 16)
	iv := make([]byte, aes.BlockSize)
	rnd(salt)
	rnd(iv)
	kp := &pbkdf2Params{salt: salt, iter: iter, prf: crypto.SHA256}
	key, err := kp.derive(password, 32)
	if err != nil {
		return nil, nil, err
	}
	defer clear(key)
	block, _ := aes.NewCipher(key)
	padded := pad(append([]byte{}, plain...), aes.BlockSize)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	clear(padded)
	alg := element(func(b *cryptobyte.Builder) {
		addAlgorithm(b, oidPBES2, func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				addAlgorithm(b, oidPBKDF2, func(b *cryptobyte.Builder) {
					b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
						b.AddASN1OctetString(salt)
						b.AddASN1Int64(int64(iter))
						addAlgorithm(b, oidHMACWithSHA256, addNull)
					})
				})
				addAlgorithm(b, oidAES256CBC, func(b *cryptobyte.Builder) { b.AddASN1OctetString(iv) })
			})
		})
	})
	return alg, out, nil
}

// pkcs12MAC is an HMAC, as PKCS #12's MAC and PBMAC1 use it.
func pkcs12MAC(h crypto.Hash, key, data []byte) []byte {
	m := hmac.New(h.New, key)
	m.Write(data)
	return m.Sum(nil)
}
