package svcrypto

import (
	"errors"
	"fmt"
)

// Shamir secret sharing over GF(2^8), byte by byte, with the AES field
// polynomial x^8 + x^4 + x^3 + x + 1. A share is one byte of x coordinate
// (1..255) followed by one y byte per secret byte. Any threshold of the
// shares rebuild the secret; fewer reveal nothing about it.
//
// The field arithmetic is written without tables or data-dependent
// branches, so the time taken does not depend on the secret.

// ErrShares is a set of shares that cannot be combined: too few, of
// different lengths, or with a repeated x coordinate.
var ErrShares = errors.New("svcrypto: shares do not combine")

// SplitSecret cuts secret into n shares, any k of which rebuild it.
func SplitSecret(secret []byte, n, k int) ([][]byte, error) {
	if k < 2 || n < k || n > 255 {
		return nil, fmt.Errorf("svcrypto: cannot split into %d shares with threshold %d (need 2 <= k <= n <= 255)", n, k)
	}
	if len(secret) == 0 {
		return nil, errors.New("svcrypto: empty secret")
	}
	shares := make([][]byte, n)
	for i := range shares {
		shares[i] = make([]byte, 1+len(secret))
		shares[i][0] = byte(i + 1)
	}
	coeffs := make([]byte, k)
	defer clear(coeffs)
	for j, s := range secret {
		coeffs[0] = s
		rand := RandomBytes(k - 1)
		copy(coeffs[1:], rand)
		clear(rand)
		for i := range shares {
			shares[i][1+j] = evalPoly(coeffs, shares[i][0])
		}
	}
	return shares, nil
}

// CombineShares rebuilds a secret from at least threshold shares. Given
// fewer, it returns a wrong secret, not an error: the shares cannot know
// the threshold. Callers check the result, for example by opening
// something sealed with it.
func CombineShares(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 {
		return nil, ErrShares
	}
	size := len(shares[0])
	if size < 2 {
		return nil, ErrShares
	}
	seen := map[byte]bool{}
	for _, s := range shares {
		if len(s) != size || s[0] == 0 || seen[s[0]] {
			return nil, ErrShares
		}
		seen[s[0]] = true
	}
	secret := make([]byte, size-1)
	for j := range secret {
		// Lagrange interpolation at x = 0.
		var acc byte
		for i, si := range shares {
			num, den := byte(1), byte(1)
			for m, sm := range shares {
				if m == i {
					continue
				}
				num = gfMul(num, sm[0])
				den = gfMul(den, sm[0]^si[0])
			}
			acc ^= gfMul(si[1+j], gfMul(num, gfInv(den)))
		}
		secret[j] = acc
	}
	return secret, nil
}

// evalPoly evaluates the polynomial with the given coefficients (constant
// term first) at x, by Horner's rule.
func evalPoly(coeffs []byte, x byte) byte {
	var y byte
	for i := len(coeffs) - 1; i >= 0; i-- {
		y = gfMul(y, x) ^ coeffs[i]
	}
	return y
}

// gfMul multiplies in GF(2^8) in constant time.
func gfMul(a, b byte) byte {
	var p byte
	for range 8 {
		p ^= -(b & 1) & a
		hi := -(a >> 7)
		a = (a << 1) ^ (hi & 0x1b)
		b >>= 1
	}
	return p
}

// gfInv is the multiplicative inverse, a^254, in constant time. gfInv(0)
// is 0, which callers never ask for (x coordinates are distinct).
func gfInv(a byte) byte {
	r := byte(1)
	for range 7 { // a^(2+4+...+128) = a^254
		a = gfMul(a, a)
		r = gfMul(r, a)
	}
	return r
}
