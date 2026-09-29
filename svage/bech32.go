package svage

import (
	"bytes"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Bech32 as BIP 173 specifies it
// (https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki), with
// the one change age makes: no limit on the length of the data part, which
// a post-quantum recipient needs (1,216 bytes of key). A string is all
// lowercase or all uppercase, and the checksum is always computed over the
// lowercase form.
//
// Identities are secrets, so the byte-slice forms here make no copy of
// their data that they do not wipe.

const bech32Charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

// maxHRP is BIP 173's limit on the human-readable part.
const maxHRP = 83

var bech32Generator = [5]uint32{0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3}

// bech32Polymod continues the checksum chk over values; it starts at 1.
func bech32Polymod(chk uint32, values []byte) uint32 {
	for _, v := range values {
		top := chk >> 25
		chk = (chk&0x1ffffff)<<5 ^ uint32(v)
		for i, g := range bech32Generator {
			if top>>i&1 == 1 {
				chk ^= g
			}
		}
	}
	return chk
}

// bech32HRPExpand expands a lowercase human-readable part for the checksum.
func bech32HRPExpand(hrp string) []byte {
	out := make([]byte, 0, 2*len(hrp)+1)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]>>5)
	}
	out = append(out, 0)
	for i := 0; i < len(hrp); i++ {
		out = append(out, hrp[i]&31)
	}
	return out
}

// convertBits regroups bits: 8 to 5 when encoding (padding the last
// group), 5 to 8 when decoding (where padding must be short and zero).
func convertBits(data []byte, from, to uint, pad bool) ([]byte, error) {
	var acc uint32
	var bits uint
	maxv := uint32(1)<<to - 1
	out := make([]byte, 0, len(data)*int(from)/int(to)+1)
	fail := func(msg string) ([]byte, error) {
		clear(out)
		return nil, errors.New(msg)
	}
	for _, v := range data {
		if uint32(v)>>from != 0 {
			return fail("bech32: value out of range")
		}
		acc = acc<<from | uint32(v)
		bits += from
		for bits >= to {
			bits -= to
			out = append(out, byte(acc>>bits&maxv))
		}
	}
	switch {
	case pad:
		if bits > 0 {
			out = append(out, byte(acc<<(to-bits)&maxv))
		}
	case bits >= from:
		return fail("bech32: too much padding")
	case acc<<(to-bits)&maxv != 0:
		return fail("bech32: non-zero padding")
	}
	return out, nil
}

func checkHRP(hrp string) error {
	if len(hrp) < 1 || len(hrp) > maxHRP {
		return fmt.Errorf("bech32: human-readable part of %d characters", len(hrp))
	}
	for i := 0; i < len(hrp); i++ {
		if hrp[i] < 33 || hrp[i] > 126 {
			return fmt.Errorf("bech32: invalid character in human-readable part at %d", i)
		}
	}
	return nil
}

// bech32Append appends the encoding of data under hrp to dst. The result
// is uppercase when hrp is, lowercase otherwise; a mixed-case hrp is an
// error.
func bech32Append(dst []byte, hrp string, data []byte) ([]byte, error) {
	if err := checkHRP(hrp); err != nil {
		return nil, err
	}
	lower := strings.ToLower(hrp)
	upper := hrp == strings.ToUpper(hrp) && hrp != lower
	if !upper && hrp != lower {
		return nil, errors.New("bech32: mixed-case human-readable part")
	}
	values, err := convertBits(data, 8, 5, true)
	if err != nil {
		return nil, err
	}
	defer clear(values)
	chk := bech32Polymod(bech32Polymod(bech32Polymod(1, bech32HRPExpand(lower)), values), make([]byte, 6)) ^ 1
	start := len(dst)
	dst = slices.Grow(dst, len(lower)+1+len(values)+6)
	dst = append(dst, lower...)
	dst = append(dst, '1')
	for _, v := range values {
		dst = append(dst, bech32Charset[v])
	}
	for i := range 6 {
		dst = append(dst, bech32Charset[chk>>(5*(5-i))&31])
	}
	if upper {
		for i := start; i < len(dst); i++ {
			if c := dst[i]; c >= 'a' && c <= 'z' {
				dst[i] = c - 'a' + 'A'
			}
		}
	}
	return dst, nil
}

// bech32Encode is bech32Append for a string.
func bech32Encode(hrp string, data []byte) (string, error) {
	b, err := bech32Append(nil, hrp, data)
	return string(b), err
}

// bech32Decode decodes s, returning its human-readable part as written
// (so its case tells an identity from a recipient) and its data.
func bech32Decode(s string) (hrp string, data []byte, err error) {
	return bech32DecodeBytes([]byte(s))
}

// bech32DecodeBytes is bech32Decode for bytes. The data it returns is
// the only copy it makes of the data part.
func bech32DecodeBytes(b []byte) (hrp string, data []byte, err error) {
	hrp, values, err := bech32Values(b)
	if err != nil {
		return "", nil, err
	}
	defer clear(values)
	data, err = convertBits(values, 5, 8, false)
	if err != nil {
		return "", nil, err
	}
	return hrp, data, nil
}

// bech32Values checks b and returns its human-readable part and its data
// as 5-bit values, without the checksum.
func bech32Values(b []byte) (hrp string, values []byte, err error) {
	var hasLower, hasUpper bool
	for _, c := range b {
		hasLower = hasLower || c >= 'a' && c <= 'z'
		hasUpper = hasUpper || c >= 'A' && c <= 'Z'
	}
	if hasLower && hasUpper {
		return "", nil, errors.New("bech32: mixed case")
	}
	pos := bytes.LastIndexByte(b, '1')
	if pos < 1 || pos+7 > len(b) {
		return "", nil, errors.New("bech32: separator missing or misplaced")
	}
	hrp = string(b[:pos])
	if err := checkHRP(hrp); err != nil {
		return "", nil, err
	}
	values = make([]byte, 0, len(b)-pos-1)
	for i := pos + 1; i < len(b); i++ {
		d := strings.IndexByte(bech32Charset, lowerASCII(b[i]))
		if d < 0 {
			clear(values)
			return "", nil, fmt.Errorf("bech32: invalid character at %d", i)
		}
		values = append(values, byte(d))
	}
	if bech32Polymod(bech32Polymod(1, bech32HRPExpand(strings.ToLower(hrp))), values) != 1 {
		clear(values)
		return "", nil, errors.New("bech32: bad checksum")
	}
	return hrp, values[:len(values)-6], nil
}

func lowerASCII(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + 'a' - 'A'
	}
	return c
}
