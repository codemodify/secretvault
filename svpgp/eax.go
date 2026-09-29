package svpgp

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
)

// EAX mode (Bellare, Rogaway and Wagner, "The EAX Mode of Operation",
// FSE 2004) on a 128-bit block cipher, as a cipher.AEAD with 16-byte nonces
// and tags, as OpenPGP uses it. OMAC is OMAC1, which is CMAC.

type eax struct {
	block  cipher.Block
	k1, k2 [16]byte // CMAC subkeys
}

func newEAX(block cipher.Block) (cipher.AEAD, error) {
	if block.BlockSize() != 16 {
		return nil, errors.New("svpgp: EAX needs a 128-bit block cipher")
	}
	e := &eax{block: block}
	var l [16]byte
	block.Encrypt(l[:], l[:])
	e.k1 = double(l)
	e.k2 = double(e.k1)
	return e, nil
}

func (e *eax) NonceSize() int { return 16 }
func (e *eax) Overhead() int  { return 16 }

// omac is OMAC over [t]_128 || data: CMAC of the block holding t followed
// by the data.
func (e *eax) omac(t byte, data []byte) [16]byte {
	var x [16]byte
	x[15] = t
	if len(data) == 0 {
		xor16(&x, e.k1[:])
		e.block.Encrypt(x[:], x[:])
		return x
	}
	e.block.Encrypt(x[:], x[:])
	for len(data) > 16 {
		xor16(&x, data)
		e.block.Encrypt(x[:], x[:])
		data = data[16:]
	}
	if len(data) == 16 {
		xor16(&x, data)
		xor16(&x, e.k1[:])
	} else {
		var last [16]byte
		copy(last[:], data)
		last[len(data)] = 0x80
		xor16(&x, last[:])
		xor16(&x, e.k2[:])
	}
	e.block.Encrypt(x[:], x[:])
	return x
}

func (e *eax) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != 16 {
		panic("svpgp: EAX nonce has the wrong length")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+16)
	n := e.omac(0, nonce)
	h := e.omac(1, additionalData)
	cipher.NewCTR(e.block, n[:]).XORKeyStream(out[:len(plaintext)], plaintext)
	c := e.omac(2, out[:len(plaintext)])
	xor16(&c, n[:])
	xor16(&c, h[:])
	copy(out[len(plaintext):], c[:])
	return ret
}

func (e *eax) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != 16 {
		panic("svpgp: EAX nonce has the wrong length")
	}
	if len(ciphertext) < 16 {
		return nil, errOpen
	}
	ct, want := ciphertext[:len(ciphertext)-16], ciphertext[len(ciphertext)-16:]
	n := e.omac(0, nonce)
	h := e.omac(1, additionalData)
	c := e.omac(2, ct)
	xor16(&c, n[:])
	xor16(&c, h[:])
	if subtle.ConstantTimeCompare(c[:], want) != 1 {
		return nil, errOpen
	}
	ret, out := sliceForAppend(dst, len(ct))
	cipher.NewCTR(e.block, n[:]).XORKeyStream(out, ct)
	return ret, nil
}
