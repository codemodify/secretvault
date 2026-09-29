package svluks

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"

	"golang.org/x/crypto/argon2"
)

// KDF types, as keyslots name them.
const (
	KDFArgon2id = "argon2id"
	KDFArgon2i  = "argon2i"
	KDFPBKDF2   = "pbkdf2"
)

// KDF says how a keyslot turns a passphrase into the key that encrypts its
// area.
type KDF struct {
	Type       string // KDFArgon2id, KDFArgon2i or KDFPBKDF2
	Hash       string // PBKDF2's hash: "sha256" (when ""), "sha512" or "sha1"
	Iterations uint32 // PBKDF2's iteration count, or Argon2's time cost
	MemoryKiB  uint32 // Argon2 only
	Threads    uint32 // Argon2 only
}

var (
	// DefaultKDF is for passphrases people type: Argon2id, 4 passes over
	// 256 MiB with 4 lanes. cryptsetup would benchmark for 2 seconds up to
	// 1 GiB; a fixed cost gives the same result on every machine.
	DefaultKDF = KDF{Type: KDFArgon2id, Iterations: 4, MemoryKiB: 256 << 10, Threads: 4}

	// KeyKDF is for keys that are already random, such as the 256-bit
	// keys secretvault keeps in vault items: PBKDF2-SHA256 at cryptsetup's
	// minimum of 1000 iterations. Stretching a key nobody can guess adds
	// nothing.
	KeyKDF = KDF{Type: KDFPBKDF2, Hash: "sha256", Iterations: 1000}
)

// Bounds on what a header may ask for, so a planted header cannot turn an
// unlock attempt into minutes of work or an out-of-memory kill. They admit
// everything cryptsetup writes: at most 4 GiB of memory, and its
// benchmarked costs.
const (
	maxArgon2MemoryKiB  = 4 << 20  // 4 GiB, cryptsetup's own maximum
	maxArgon2Threads    = 64       // cryptsetup writes at most 4
	maxArgon2Time       = 1 << 12  // passes
	maxArgon2Work       = 64 << 20 // KiB times passes: 16 passes over 4 GiB
	maxPBKDF2Iterations = 50_000_000

	// A digest is benchmarked by cryptsetup at 125 ms, so a few million
	// iterations at most; it is run once for every keyslot tried.
	maxDigestIterations = 4_000_000

	// What this package writes, as cryptsetup's own limits.
	minPBKDF2Iterations = 1000
	minArgon2Time       = 4
	minArgon2MemoryKiB  = 32
	maxArgon2WriteLanes = 4
)

// check reports whether the KDF's costs are within bounds: those for
// reading, or (writing) the stricter ones cryptsetup keeps for new
// keyslots.
func (k KDF) check(writing bool) error {
	switch k.Type {
	case KDFPBKDF2:
		if _, err := hashNamed(k.hash()); err != nil {
			return err
		}
		if k.Iterations < 1 || k.Iterations > maxPBKDF2Iterations || writing && k.Iterations < minPBKDF2Iterations {
			return headerErr("pbkdf2 with %d iterations", k.Iterations)
		}
	case KDFArgon2i, KDFArgon2id:
		work := uint64(k.Iterations) * uint64(k.MemoryKiB)
		if k.Iterations < 1 || k.Iterations > maxArgon2Time ||
			k.Threads < 1 || k.Threads > maxArgon2Threads ||
			k.MemoryKiB < 8*k.Threads || k.MemoryKiB > maxArgon2MemoryKiB || work > maxArgon2Work {
			return headerErr("%s with t=%d m=%dKiB p=%d, beyond what secretvault will run", k.Type, k.Iterations, k.MemoryKiB, k.Threads)
		}
		if writing && (k.Iterations < minArgon2Time || k.MemoryKiB < minArgon2MemoryKiB || k.Threads > maxArgon2WriteLanes) {
			return fmt.Errorf("svluks: %s with t=%d m=%dKiB p=%d is below cryptsetup's minimum (t>=4, m>=32KiB, p<=4)", k.Type, k.Iterations, k.MemoryKiB, k.Threads)
		}
	default:
		return unsupported("key derivation %q", k.Type)
	}
	return nil
}

func (k KDF) hash() string {
	if k.Type == KDFPBKDF2 && k.Hash == "" {
		return "sha256"
	}
	return k.Hash
}

// String describes the KDF the way cryptsetup's luksDump does, briefly.
func (k KDF) String() string {
	if k.Type == KDFPBKDF2 {
		return fmt.Sprintf("pbkdf2-%s, %d iterations", k.hash(), k.Iterations)
	}
	return fmt.Sprintf("%s t=%d m=%dKiB p=%d", k.Type, k.Iterations, k.MemoryKiB, k.Threads)
}

func kdfFromJSON(j kdfJSON) KDF {
	if j.Type == KDFPBKDF2 {
		return KDF{Type: j.Type, Hash: j.Hash, Iterations: j.Iterations}
	}
	return KDF{Type: j.Type, Iterations: j.Time, MemoryKiB: j.Memory, Threads: j.CPUs}
}

func (k KDF) toJSON(salt []byte) kdfJSON {
	if k.Type == KDFPBKDF2 {
		return kdfJSON{Type: k.Type, Hash: k.hash(), Iterations: k.Iterations, Salt: salt}
	}
	return kdfJSON{Type: k.Type, Time: k.Iterations, Memory: k.MemoryKiB, CPUs: k.Threads, Salt: salt}
}

// derive runs the KDF. The caller zeroes the result.
func (k KDF) derive(passphrase, salt []byte, n int) ([]byte, error) {
	if err := k.check(false); err != nil {
		return nil, err
	}
	switch k.Type {
	case KDFArgon2id:
		return argon2.IDKey(passphrase, salt, k.Iterations, k.MemoryKiB, uint8(k.Threads), uint32(n)), nil
	case KDFArgon2i:
		return argon2.Key(passphrase, salt, k.Iterations, k.MemoryKiB, uint8(k.Threads), uint32(n)), nil
	}
	h, _ := hashNamed(k.hash())
	return pbkdf2(h, passphrase, salt, int(k.Iterations), n), nil
}

// hashNamed is a hash by its LUKS name.
func hashNamed(name string) (func() hash.Hash, error) {
	switch name {
	case "sha256":
		return sha256.New, nil
	case "sha512":
		return sha512.New, nil
	case "sha1":
		return sha1.New, nil
	}
	return nil, unsupported("hash %q", name)
}

// pbkdf2 is PBKDF2-HMAC (RFC 8018 section 5.2). It is here rather than
// crypto/pbkdf2 because that takes the password as a string, a copy that
// can never be wiped, and the password here is often the volume key.
func pbkdf2(h func() hash.Hash, password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(h, password)
	size := prf.Size()
	out := make([]byte, 0, (keyLen+size-1)/size*size)
	u := make([]byte, size)
	t := make([]byte, size)
	var ctr [4]byte
	for block := uint32(1); len(out) < keyLen; block++ {
		binary.BigEndian.PutUint32(ctr[:], block)
		prf.Reset()
		prf.Write(salt)
		prf.Write(ctr[:])
		u = prf.Sum(u[:0])
		copy(t, u)
		for range iter - 1 {
			prf.Reset()
			prf.Write(u)
			u = prf.Sum(u[:0])
			for i := range t {
				t[i] ^= u[i]
			}
		}
		out = append(out, t...)
	}
	clear(u)
	clear(t)
	clear(out[keyLen:cap(out)])
	return out[:keyLen]
}

// The anti-forensic splitter of LUKS1 (the LUKS1 specification, section
// 2.4), which LUKS2's luks1-type splitter is: a key becomes stripes blocks
// of its own size that must all be read back to recover it, so that
// destroying any small part of a keyslot's area destroys the key.

// afSize is the space a key's split material takes in a keyslot area,
// whole 512-byte sectors.
func afSize(keySize int) uint64 {
	n := uint64(keySize) * afStripes
	return (n + sectorBytes - 1) / sectorBytes * sectorBytes
}

// afSplit splits key into stripes blocks, padded to whole sectors. The
// caller zeroes the result.
func afSplit(key []byte, h func() hash.Hash, random func([]byte)) []byte {
	n := len(key)
	out := make([]byte, afSize(n))
	buf := make([]byte, n)
	for i := range afStripes - 1 {
		stripe := out[i*n : (i+1)*n]
		random(stripe)
		xorInto(buf, stripe)
		diffuse(buf, h)
	}
	last := out[(afStripes-1)*n : afStripes*n]
	for i := range last {
		last[i] = buf[i] ^ key[i]
	}
	clear(buf)
	return out
}

// afMerge recovers a keySize key from split material. The caller zeroes
// the result.
func afMerge(material []byte, keySize int, h func() hash.Hash) []byte {
	buf := make([]byte, keySize)
	for i := range afStripes - 1 {
		xorInto(buf, material[i*keySize:(i+1)*keySize])
		diffuse(buf, h)
	}
	xorInto(buf, material[(afStripes-1)*keySize:afStripes*keySize])
	return buf
}

func xorInto(dst, src []byte) {
	for i := range dst {
		dst[i] ^= src[i]
	}
}

// diffuse hashes buf in place, a digest-sized block at a time, each block
// prefixed with its index as a big-endian uint32; a short last block takes
// the start of its hash.
func diffuse(buf []byte, newHash func() hash.Hash) {
	h := newHash()
	size := h.Size()
	var idx [4]byte
	var sum []byte
	for i := 0; i*size < len(buf); i++ {
		block := buf[i*size : min((i+1)*size, len(buf))]
		binary.BigEndian.PutUint32(idx[:], uint32(i))
		h.Reset()
		h.Write(idx[:])
		h.Write(block)
		sum = h.Sum(sum[:0])
		copy(block, sum)
	}
	clear(sum)
}
