package svpgp

import (
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// AES key wrap (RFC 3394), used by ECDH and X25519 to encrypt session keys.

var keyWrapIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

var errKeyWrap = errors.New("svpgp: key unwrap failed")

// keyWrap wraps plaintext, a multiple of 8 bytes and at least 16, under an
// AES key encryption key.
func keyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, errors.New("svpgp: key wrap input must be a multiple of 8 bytes, at least 16")
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(plaintext) / 8
	out := make([]byte, 8+len(plaintext))
	copy(out[8:], plaintext)
	a := keyWrapIV
	var b [16]byte
	for j := 0; j < 6; j++ {
		for i := 1; i <= n; i++ {
			copy(b[:8], a[:])
			copy(b[8:], out[8*i:8*i+8])
			block.Encrypt(b[:], b[:])
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(a[:], binary.BigEndian.Uint64(b[:8])^t)
			copy(out[8*i:], b[8:])
		}
	}
	copy(out[:8], a[:])
	clear(b[:])
	return out, nil
}

// keyUnwrap reverses keyWrap, checking the integrity value in constant
// time.
func keyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, errKeyWrap
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}
	n := len(ciphertext)/8 - 1
	out := make([]byte, 8*n)
	copy(out, ciphertext[8:])
	var a [8]byte
	copy(a[:], ciphertext[:8])
	var b [16]byte
	for j := 5; j >= 0; j-- {
		for i := n; i >= 1; i-- {
			t := uint64(n*j + i)
			binary.BigEndian.PutUint64(b[:8], binary.BigEndian.Uint64(a[:])^t)
			copy(b[8:], out[8*(i-1):8*i])
			block.Decrypt(b[:], b[:])
			copy(a[:], b[:8])
			copy(out[8*(i-1):], b[8:])
		}
	}
	clear(b[:])
	if subtle.ConstantTimeCompare(a[:], keyWrapIV[:]) != 1 {
		clear(out)
		return nil, errKeyWrap
	}
	return out, nil
}
