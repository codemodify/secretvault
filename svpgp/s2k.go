package svpgp

import (
	"bytes"
	"crypto/rand"
	"math/bits"

	"golang.org/x/crypto/argon2"
)

// String-to-key specifiers (RFC 9580, section 3.7): how a passphrase becomes
// a key.

const (
	s2kSimple   = 0
	s2kSalted   = 1
	s2kIterated = 3
	s2kArgon2   = 4
	s2kGNU      = 101 // GnuPG's extension for secret keys that are not there
)

type s2k struct {
	typ   byte
	hash  HashAlgorithm // simple, salted, iterated
	salt  []byte        // 8 bytes, or 16 for Argon2
	count byte          // iterated: the coded octet count
	t     byte          // Argon2 passes
	p     byte          // Argon2 parallelism
	m     byte          // Argon2 memory exponent (2^m KiB)

	gnuMode   byte   // 1: no secret key (gnu-dummy); 2: on a smartcard
	gnuSerial []byte // the card's serial number, for mode 2
}

// parseS2K reads an S2K specifier.
func parseS2K(p *parser) (*s2k, error) {
	s := &s2k{typ: p.u8()}
	switch s.typ {
	case s2kSimple:
		s.hash = HashAlgorithm(p.u8())
	case s2kSalted:
		s.hash = HashAlgorithm(p.u8())
		s.salt = p.bytes(8)
	case s2kIterated:
		s.hash = HashAlgorithm(p.u8())
		s.salt = p.bytes(8)
		s.count = p.u8()
	case s2kArgon2:
		s.salt = p.bytes(16)
		s.t, s.p, s.m = p.u8(), p.u8(), p.u8()
	case s2kGNU:
		s.hash = HashAlgorithm(p.u8())
		if magic := p.bytes(3); p.err == nil && string(magic) != "GNU" {
			return nil, unsupported("S2K type 101 without the GNU marker")
		}
		s.gnuMode = p.u8()
		switch s.gnuMode {
		case 1:
		case 2:
			n := int(p.u8())
			if n > 16 {
				return nil, malformed("smartcard serial number of %d bytes", n)
			}
			s.gnuSerial = p.bytes(n)
		default:
			if p.err == nil {
				return nil, unsupported("GnuPG S2K extension mode %d", s.gnuMode)
			}
		}
	default:
		if p.err == nil {
			return nil, unsupported("S2K type %d", s.typ)
		}
	}
	if p.err != nil {
		return nil, p.err
	}
	return s, nil
}

func (s *s2k) bytes() []byte {
	out := []byte{s.typ}
	switch s.typ {
	case s2kSimple:
		out = append(out, byte(s.hash))
	case s2kSalted:
		out = append(append(out, byte(s.hash)), s.salt...)
	case s2kIterated:
		out = append(append(out, byte(s.hash)), s.salt...)
		out = append(out, s.count)
	case s2kArgon2:
		out = append(append(out, s.salt...), s.t, s.p, s.m)
	case s2kGNU:
		out = append(append(out, byte(s.hash)), 'G', 'N', 'U', s.gnuMode)
		if s.gnuMode == 2 {
			out = append(append(out, byte(len(s.gnuSerial))), s.gnuSerial...)
		}
	}
	return out
}

// salted reports whether the specifier mixes in a salt, which v4 SKESK
// packets with an encrypted session key need (RFC 9580, section 5.3.1).
func (s *s2k) salted() bool { return s.typ != s2kSimple && s.typ != s2kGNU }

// iteratedCount decodes the coded octet count of an iterated S2K.
func iteratedCount(c byte) int { return (16 + int(c&15)) << (int(c>>4) + 6) }

// derive turns a passphrase into keyLen bytes. v6 is set for version 6
// packets, where the weak hashes are refused outright (RFC 9580, section
// 9.5); in older packets SHA-1 is still accepted, as the format requires.
func (s *s2k) derive(passphrase []byte, keyLen int, v6 bool, lim Limits) ([]byte, error) {
	switch s.typ {
	case s2kSimple, s2kSalted, s2kIterated:
		if v6 && s.hash == SHA1 {
			return nil, unsupported("an S2K with SHA-1 in a version 6 packet")
		}
		h, err := s.hash.newHash()
		if err != nil {
			return nil, err
		}
		data := append(append([]byte{}, s.salt...), passphrase...)
		defer clear(data)
		count := len(data)
		if s.typ == s2kIterated {
			count = max(iteratedCount(s.count), len(data))
		}
		// A run of whole copies of data, so the stream can be fed in large
		// writes and cut off anywhere.
		var run []byte
		if len(data) > 0 {
			run = bytes.Repeat(data, max(1, 8192/len(data)))
			defer clear(run)
		}
		out := make([]byte, 0, keyLen+h.Size())
		for i := 0; len(out) < keyLen; i++ {
			h.Reset()
			h.Write(make([]byte, i))
			left := count
			for left >= len(run) && len(run) > 0 {
				h.Write(run)
				left -= len(run)
			}
			h.Write(run[:left])
			out = h.Sum(out)
		}
		clear(out[keyLen:])
		return out[:keyLen], nil
	case s2kArgon2:
		if s.t == 0 || s.p == 0 {
			return nil, malformed("Argon2 S2K with zero passes or parallelism")
		}
		if int(s.m) < 3+bits.Len(uint(s.p)-1) || s.m > 31 {
			return nil, malformed("Argon2 S2K memory exponent %d with parallelism %d", s.m, s.p)
		}
		if uint64(1)<<s.m > uint64(lim.MaxArgon2Memory) {
			return nil, limit("Argon2 S2K asks for %d KiB of memory (the limit is %d)", uint64(1)<<s.m, lim.MaxArgon2Memory)
		}
		if s.t > lim.MaxArgon2Passes {
			return nil, limit("Argon2 S2K asks for %d passes (the limit is %d)", s.t, lim.MaxArgon2Passes)
		}
		return argon2.IDKey(passphrase, s.salt, uint32(s.t), uint32(1)<<s.m, s.p, uint32(keyLen)), nil
	case s2kGNU:
		return nil, ErrKeyLocked
	}
	return nil, unsupported("S2K type %d", s.typ)
}

// newArgon2S2K makes a fresh Argon2 specifier: RFC 9106's second
// recommended option, three passes over 64 MiB with four lanes.
func newArgon2S2K() *s2k {
	salt := make([]byte, 16)
	rand.Read(salt)
	return &s2k{typ: s2kArgon2, salt: salt, t: 3, p: 4, m: 16}
}

// newIteratedS2K makes a fresh iterated and salted SHA-256 specifier with
// the largest octet count, for readers (GnuPG 2.4) that lack Argon2.
func newIteratedS2K() *s2k {
	salt := make([]byte, 8)
	rand.Read(salt)
	return &s2k{typ: s2kIterated, hash: SHA256, salt: salt, count: 0xFF}
}
