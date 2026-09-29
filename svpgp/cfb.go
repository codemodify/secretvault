package svpgp

import (
	"crypto/cipher"
	"crypto/subtle"
)

// cfb is full-block cipher feedback mode (NIST SP 800-38A, section 6.3,
// with the segment size equal to the block size), the mode OpenPGP uses
// for v1 SEIPD packets, v4 SKESK packets, CFB-protected secret keys and
// old SED packets. It is written out here because the standard library
// deprecates its own.
type cfb struct {
	b       cipher.Block
	reg     []byte // the feedback register: the last ciphertext block
	ks      []byte // keystream for the current block
	used    int    // keystream bytes used
	decrypt bool
}

func newCFB(b cipher.Block, iv []byte, decrypt bool) *cfb {
	bs := b.BlockSize()
	c := &cfb{b: b, reg: make([]byte, bs), ks: make([]byte, bs), used: bs, decrypt: decrypt}
	copy(c.reg, iv)
	return c
}

// XORKeyStream encrypts or decrypts src into dst, which may overlap
// exactly.
func (c *cfb) XORKeyStream(dst, src []byte) {
	bs := len(c.reg)
	for len(src) > 0 {
		if c.used == bs {
			c.b.Encrypt(c.ks, c.reg)
			c.used = 0
		}
		n := min(len(src), bs-c.used)
		if c.decrypt {
			// The ciphertext feeds back, so save it before dst may
			// overwrite it.
			copy(c.reg[c.used:], src[:n])
		}
		subtle.XORBytes(dst[:n], src[:n], c.ks[c.used:c.used+n])
		if !c.decrypt {
			copy(c.reg[c.used:], dst[:n])
		}
		c.used += n
		dst, src = dst[n:], src[n:]
	}
}
