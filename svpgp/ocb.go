package svpgp

import (
	"crypto/cipher"
	"crypto/subtle"
	"errors"
	"math/bits"
)

// OCB mode (RFC 7253) on a 128-bit block cipher, as a cipher.AEAD. OpenPGP
// uses it with 15-byte nonces and 16-byte tags; other sizes exist for the
// RFC's test vectors.

var errOpen = errors.New("svpgp: message authentication failed")

type ocb struct {
	block     cipher.Block
	nonceSize int
	tagSize   int
	lStar     [16]byte
	lDollar   [16]byte
	l         [64][16]byte // L_i for i < 64, which covers any message length
}

func newOCB(block cipher.Block, nonceSize, tagSize int) (cipher.AEAD, error) {
	if block.BlockSize() != 16 {
		return nil, errors.New("svpgp: OCB needs a 128-bit block cipher")
	}
	if nonceSize < 1 || nonceSize > 15 {
		return nil, errors.New("svpgp: OCB nonce must be 1 to 15 bytes")
	}
	if tagSize < 8 || tagSize > 16 {
		return nil, errors.New("svpgp: OCB tag must be 8 to 16 bytes")
	}
	o := &ocb{block: block, nonceSize: nonceSize, tagSize: tagSize}
	block.Encrypt(o.lStar[:], o.lStar[:])
	o.lDollar = double(o.lStar)
	o.l[0] = double(o.lDollar)
	for i := 1; i < len(o.l); i++ {
		o.l[i] = double(o.l[i-1])
	}
	return o, nil
}

func (o *ocb) NonceSize() int { return o.nonceSize }
func (o *ocb) Overhead() int  { return o.tagSize }

// double multiplies by x in GF(2^128), without a branch on the secret
// top bit.
func double(s [16]byte) [16]byte {
	var d [16]byte
	carry := s[0] >> 7
	for i := 0; i < 15; i++ {
		d[i] = s[i]<<1 | s[i+1]>>7
	}
	d[15] = s[15]<<1 ^ (0x87 & (0 - carry))
	return d
}

func xor16(dst *[16]byte, a []byte) {
	subtle.XORBytes(dst[:], dst[:], a[:16])
}

// offset0 derives the initial offset from the nonce (RFC 7253, section
// 4.2).
func (o *ocb) offset0(nonce []byte) [16]byte {
	var n [16]byte
	n[0] = byte((o.tagSize*8)%128) << 1
	n[15-len(nonce)] |= 1
	copy(n[16-len(nonce):], nonce)
	bottom := int(n[15] & 0x3F)
	n[15] &^= 0x3F
	var ktop [16]byte
	o.block.Encrypt(ktop[:], n[:])
	var stretch [24]byte
	copy(stretch[:], ktop[:])
	for i := 0; i < 8; i++ {
		stretch[16+i] = ktop[i] ^ ktop[i+1]
	}
	byteShift, bitShift := bottom/8, uint(bottom%8)
	var off [16]byte
	for i := range off {
		off[i] = stretch[i+byteShift] << bitShift
		if bitShift != 0 {
			off[i] |= stretch[i+byteShift+1] >> (8 - bitShift)
		}
	}
	return off
}

// hash is OCB's HASH of the associated data (RFC 7253, section 4.1).
func (o *ocb) hash(a []byte) [16]byte {
	var sum, off, tmp [16]byte
	for i := 1; len(a) >= 16; i++ {
		xor16(&off, o.l[bits.TrailingZeros(uint(i))][:])
		copy(tmp[:], a[:16])
		xor16(&tmp, off[:])
		o.block.Encrypt(tmp[:], tmp[:])
		xor16(&sum, tmp[:])
		a = a[16:]
	}
	if len(a) > 0 {
		xor16(&off, o.lStar[:])
		tmp = [16]byte{}
		copy(tmp[:], a)
		tmp[len(a)] = 0x80
		xor16(&tmp, off[:])
		o.block.Encrypt(tmp[:], tmp[:])
		xor16(&sum, tmp[:])
	}
	return sum
}

func (o *ocb) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != o.nonceSize {
		panic("svpgp: OCB nonce has the wrong length")
	}
	ret, out := sliceForAppend(dst, len(plaintext)+o.tagSize)
	off := o.offset0(nonce)
	var checksum, tmp [16]byte
	p, c := plaintext, out
	for i := 1; len(p) >= 16; i++ {
		xor16(&off, o.l[bits.TrailingZeros(uint(i))][:])
		xor16(&checksum, p)
		copy(tmp[:], p[:16])
		xor16(&tmp, off[:])
		o.block.Encrypt(tmp[:], tmp[:])
		xor16(&tmp, off[:])
		copy(c, tmp[:])
		p, c = p[16:], c[16:]
	}
	if len(p) > 0 {
		xor16(&off, o.lStar[:])
		var pad [16]byte
		o.block.Encrypt(pad[:], off[:])
		tmp = [16]byte{}
		copy(tmp[:], p)
		tmp[len(p)] = 0x80
		xor16(&checksum, tmp[:])
		subtle.XORBytes(c[:len(p)], p, pad[:len(p)])
		c = c[len(p):]
	}
	tag := o.tag(checksum, off, additionalData)
	copy(c, tag[:o.tagSize])
	return ret
}

func (o *ocb) tag(checksum, off [16]byte, ad []byte) [16]byte {
	xor16(&checksum, off[:])
	xor16(&checksum, o.lDollar[:])
	o.block.Encrypt(checksum[:], checksum[:])
	h := o.hash(ad)
	xor16(&checksum, h[:])
	return checksum
}

func (o *ocb) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != o.nonceSize {
		panic("svpgp: OCB nonce has the wrong length")
	}
	if len(ciphertext) < o.tagSize {
		return nil, errOpen
	}
	var want [16]byte
	copy(want[:], ciphertext[len(ciphertext)-o.tagSize:])
	ct := ciphertext[:len(ciphertext)-o.tagSize]
	ret, out := sliceForAppend(dst, len(ct))
	off := o.offset0(nonce)
	var checksum, tmp [16]byte
	c, p := ct, out
	for i := 1; len(c) >= 16; i++ {
		xor16(&off, o.l[bits.TrailingZeros(uint(i))][:])
		copy(tmp[:], c[:16])
		xor16(&tmp, off[:])
		o.block.Decrypt(tmp[:], tmp[:])
		xor16(&tmp, off[:])
		xor16(&checksum, tmp[:])
		copy(p, tmp[:])
		c, p = c[16:], p[16:]
	}
	if len(c) > 0 {
		xor16(&off, o.lStar[:])
		var pad [16]byte
		o.block.Encrypt(pad[:], off[:])
		subtle.XORBytes(p[:len(c)], c, pad[:len(c)])
		tmp = [16]byte{}
		copy(tmp[:], p[:len(c)])
		tmp[len(c)] = 0x80
		xor16(&checksum, tmp[:])
	}
	got := o.tag(checksum, off, additionalData)
	if subtle.ConstantTimeCompare(got[:o.tagSize], want[:o.tagSize]) != 1 {
		clear(out)
		return nil, errOpen
	}
	return ret, nil
}

// sliceForAppend extends in by n bytes, reusing its capacity when it can,
// and returns the whole slice and the new part.
func sliceForAppend(in []byte, n int) (head, tail []byte) {
	if total := len(in) + n; cap(in) >= total {
		head = in[:total]
	} else {
		head = make([]byte, total)
		copy(head, in)
	}
	return head, head[len(in):]
}
