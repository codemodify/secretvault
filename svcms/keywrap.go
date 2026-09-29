package svcms

import (
	"crypto"
	"crypto/aes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
)

// AES key wrap (RFC 3394), which key agreement recipients use to wrap the
// content key, and the X9.63 key derivation (RFC 5753, section 7.2) that
// makes the wrapping key.

var keyWrapIV = [8]byte{0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6, 0xA6}

// keyWrap wraps plaintext, a multiple of 8 bytes and at least 16, under an
// AES key encryption key.
func keyWrap(kek, plaintext []byte) ([]byte, error) {
	if len(plaintext) < 16 || len(plaintext)%8 != 0 {
		return nil, errors.New("svcms: key wrap input must be a multiple of 8 bytes, at least 16")
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
// time. Every failure is ErrDecryption.
func keyUnwrap(kek, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 || len(ciphertext)%8 != 0 {
		return nil, ErrDecryption
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, ErrDecryption
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
		return nil, ErrDecryption
	}
	return out, nil
}

// x963KDF derives n bytes from the shared secret z and the shared info
// (ANSI X9.63, as SEC 1 section 3.6.1 gives it): Hash(z || counter ||
// sharedInfo) for counter = 1, 2, ..., concatenated.
func x963KDF(h crypto.Hash, z, sharedInfo []byte, n int) []byte {
	out := make([]byte, 0, n+h.Size())
	var counter [4]byte
	for i := uint32(1); len(out) < n; i++ {
		binary.BigEndian.PutUint32(counter[:], i)
		hh := h.New()
		hh.Write(z)
		hh.Write(counter[:])
		hh.Write(sharedInfo)
		out = hh.Sum(out)
	}
	clear(out[n:])
	return out[:n]
}
