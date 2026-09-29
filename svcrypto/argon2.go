package svcrypto

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/bits"
	"sync"

	"golang.org/x/crypto/blake2b"
)

// Argon2d and Argon2i name the other two Argon2 variants. secretvault's own
// keys use Argon2id only (through KDFParams); these exist to read other
// programs' files, such as KeePass databases, which default to Argon2d.
// golang.org/x/crypto/argon2 has no Argon2d, and none of its variants take
// a secret key or associated data, so Argon2 below is written here from
// RFC 9106 on top of x/crypto's BLAKE2b.
const (
	Argon2d = "argon2d"
	Argon2i = "argon2i"
)

// Argon2Input is everything Argon2 takes (RFC 9106 section 3.1). Secret
// (K) and Data (X) are optional; Version is 0x13 when zero.
type Argon2Input struct {
	Password  []byte
	Salt      []byte
	Secret    []byte
	Data      []byte
	Time      uint32 // passes over memory
	MemoryKiB uint32
	Threads   uint32 // lanes
	KeyLen    uint32
	Version   uint32 // 0x10 or 0x13
}

// ErrArgon2 is an Argon2 input outside what RFC 9106 or our bounds allow.
var ErrArgon2 = errors.New("svcrypto: bad Argon2 parameters")

// Argon2 derives a key with the named variant: Argon2d, Argon2i or
// Argon2id. It checks against RFC 9106's test vectors and, for Argon2i and
// Argon2id without a secret, against x/crypto. Memory is bounded as for
// keyslots (4 GiB), so a planted file cannot exhaust the machine.
func Argon2(variant string, in Argon2Input) ([]byte, error) {
	var y uint32
	switch variant {
	case Argon2d:
		y = 0
	case Argon2i:
		y = 1
	case Argon2id:
		y = 2
	default:
		return nil, fmt.Errorf("%w: variant %q", ErrArgon2, variant)
	}
	v := in.Version
	if v == 0 {
		v = 0x13
	}
	switch {
	case v != 0x10 && v != 0x13:
		return nil, fmt.Errorf("%w: version 0x%x", ErrArgon2, v)
	case in.Time < 1:
		return nil, fmt.Errorf("%w: no passes", ErrArgon2)
	case in.Threads < 1 || in.Threads > 255:
		return nil, fmt.Errorf("%w: %d lanes", ErrArgon2, in.Threads)
	case in.MemoryKiB < 8*in.Threads || in.MemoryKiB > maxArgon2MemoryKiB:
		return nil, fmt.Errorf("%w: %d KiB for %d lanes", ErrArgon2, in.MemoryKiB, in.Threads)
	case in.KeyLen < 4:
		return nil, fmt.Errorf("%w: %d-byte key", ErrArgon2, in.KeyLen)
	case len(in.Salt) < 8:
		return nil, fmt.Errorf("%w: %d-byte salt", ErrArgon2, len(in.Salt))
	}

	a := &argon2State{y: y, version: v, lanes: in.Threads, passes: in.Time}
	a.laneLen = in.MemoryKiB / (4 * in.Threads) * 4
	a.segLen = a.laneLen / 4
	a.blocks = a.laneLen * in.Threads
	a.mem = make([]argon2Block, a.blocks)
	defer clear(a.mem)

	h0 := argon2H0(y, v, in)
	defer clear(h0[:])
	var buf [1024]byte
	for lane := uint32(0); lane < a.lanes; lane++ {
		for j := uint32(0); j < 2; j++ {
			seed := binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(append([]byte(nil), h0[:]...), j), lane)
			argon2Hprime(buf[:], seed)
			a.mem[lane*a.laneLen+j].load(buf[:])
			clear(seed)
		}
	}
	for pass := uint32(0); pass < a.passes; pass++ {
		for slice := uint32(0); slice < 4; slice++ {
			var wg sync.WaitGroup
			for lane := uint32(0); lane < a.lanes; lane++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					a.fillSegment(pass, lane, slice)
				}()
			}
			wg.Wait()
		}
	}
	final := a.mem[a.laneLen-1]
	for lane := uint32(1); lane < a.lanes; lane++ {
		last := &a.mem[lane*a.laneLen+a.laneLen-1]
		for i := range final {
			final[i] ^= last[i]
		}
	}
	final.store(buf[:])
	clear(final[:])
	out := make([]byte, in.KeyLen)
	argon2Hprime(out, buf[:])
	clear(buf[:])
	return out, nil
}

// argon2Block is one 1 KiB block of Argon2 memory, as 128 words.
type argon2Block [128]uint64

func (b *argon2Block) load(p []byte) {
	for i := range b {
		b[i] = binary.LittleEndian.Uint64(p[8*i:])
	}
}

func (b *argon2Block) store(p []byte) {
	for i := range b {
		binary.LittleEndian.PutUint64(p[8*i:], b[i])
	}
}

type argon2State struct {
	y, version    uint32
	lanes, passes uint32
	laneLen       uint32 // blocks per lane
	segLen        uint32 // blocks per segment (a quarter of a lane)
	blocks        uint32 // m'
	mem           []argon2Block
}

// argon2H0 is the initial 64-byte hash of every input (RFC 9106 section
// 3.2, step 1).
func argon2H0(y, v uint32, in Argon2Input) [64]byte {
	h, _ := blake2b.New512(nil)
	le := func(x uint32) { h.Write(binary.LittleEndian.AppendUint32(nil, x)) }
	le(in.Threads)
	le(in.KeyLen)
	le(in.MemoryKiB)
	le(in.Time)
	le(v)
	le(y)
	for _, s := range [][]byte{in.Password, in.Salt, in.Secret, in.Data} {
		le(uint32(len(s)))
		h.Write(s)
	}
	var out [64]byte
	h.Sum(out[:0])
	return out
}

// argon2Hprime is the variable-length hash H' (RFC 9106 section 3.3),
// filling out.
func argon2Hprime(out, in []byte) {
	t := binary.LittleEndian.AppendUint32(nil, uint32(len(out)))
	if len(out) <= 64 {
		h, _ := blake2b.New(len(out), nil)
		h.Write(t)
		h.Write(in)
		h.Sum(out[:0])
		return
	}
	h, _ := blake2b.New512(nil)
	h.Write(t)
	h.Write(in)
	var v [64]byte
	h.Sum(v[:0])
	n := copy(out, v[:32])
	for len(out)-n > 64 {
		v = blake2b.Sum512(v[:])
		n += copy(out[n:], v[:32])
	}
	last, _ := blake2b.New(len(out)-n, nil)
	last.Write(v[:])
	last.Sum(out[n:n])
	clear(v[:])
}

// fillSegment computes one lane's quarter of one pass (RFC 9106 section
// 3.2, steps 5-6, and section 3.4 for how reference blocks are chosen).
func (a *argon2State) fillSegment(pass, lane, slice uint32) {
	independent := a.y == 1 || (a.y == 2 && pass == 0 && slice < 2)
	var addr, input, zero argon2Block
	if independent {
		input[0], input[1], input[2] = uint64(pass), uint64(lane), uint64(slice)
		input[3], input[4], input[5] = uint64(a.blocks), uint64(a.passes), uint64(a.y)
	}
	next := func() {
		input[6]++
		argon2G(&zero, &input, &addr, false)
		argon2G(&zero, &addr, &addr, false)
	}
	start := uint32(0)
	if pass == 0 && slice == 0 {
		start = 2
		if independent {
			next()
		}
	}
	cur := lane*a.laneLen + slice*a.segLen + start
	prev := cur - 1
	if cur%a.laneLen == 0 {
		prev = cur + a.laneLen - 1
	}
	for i := start; i < a.segLen; i, cur, prev = i+1, cur+1, prev+1 {
		if cur%a.laneLen == 1 {
			prev = cur - 1
		}
		var rand uint64
		if independent {
			if i%128 == 0 {
				next()
			}
			rand = addr[i%128]
		} else {
			rand = a.mem[prev][0]
		}
		refLane := uint32(rand>>32) % a.lanes
		if pass == 0 && slice == 0 {
			refLane = lane
		}
		ref := a.refIndex(pass, slice, i, uint32(rand), refLane == lane)
		argon2G(&a.mem[prev], &a.mem[refLane*a.laneLen+ref], &a.mem[cur], a.version == 0x13 && pass > 0)
	}
	clear(addr[:])
	clear(input[:])
}

// refIndex maps a pseudo-random J1 onto the blocks that may be referenced
// from position i of this segment (RFC 9106 section 3.4.2).
func (a *argon2State) refIndex(pass, slice, i, j1 uint32, sameLane bool) uint32 {
	var area uint32
	switch {
	case pass == 0 && slice == 0:
		area = i - 1
	case pass == 0 && sameLane:
		area = slice*a.segLen + i - 1
	case pass == 0:
		area = slice * a.segLen
		if i == 0 {
			area--
		}
	case sameLane:
		area = a.laneLen - a.segLen + i - 1
	default:
		area = a.laneLen - a.segLen
		if i == 0 {
			area--
		}
	}
	x := uint64(j1) * uint64(j1) >> 32
	rel := uint64(area) - 1 - (uint64(area) * x >> 32)
	startPos := uint32(0)
	if pass != 0 && slice != 3 {
		startPos = (slice + 1) * a.segLen
	}
	return uint32((uint64(startPos) + rel) % uint64(a.laneLen))
}

// argon2G is the compression function G (RFC 9106 section 3.5): out =
// P(prev ^ ref) ^ prev ^ ref, also XORed with out's old value when xor is
// set (version 0x13, passes after the first). out may alias ref.
func argon2G(prev, ref, out *argon2Block, xor bool) {
	var r, t argon2Block
	for i := range r {
		r[i] = prev[i] ^ ref[i]
	}
	t = r
	if xor {
		for i := range t {
			t[i] ^= out[i]
		}
	}
	for i := 0; i < 128; i += 16 {
		blamka(&r[i], &r[i+1], &r[i+2], &r[i+3], &r[i+4], &r[i+5], &r[i+6], &r[i+7],
			&r[i+8], &r[i+9], &r[i+10], &r[i+11], &r[i+12], &r[i+13], &r[i+14], &r[i+15])
	}
	for i := 0; i < 16; i += 2 {
		blamka(&r[i], &r[i+1], &r[i+16], &r[i+17], &r[i+32], &r[i+33], &r[i+48], &r[i+49],
			&r[i+64], &r[i+65], &r[i+80], &r[i+81], &r[i+96], &r[i+97], &r[i+112], &r[i+113])
	}
	for i := range out {
		out[i] = t[i] ^ r[i]
	}
	clear(r[:])
	clear(t[:])
}

// blamka is the permutation P: one BLAKE2b round whose additions carry the
// extra 2*lo(a)*lo(b) term (RFC 9106 section 3.6).
func blamka(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15 *uint64) {
	gb(v0, v4, v8, v12)
	gb(v1, v5, v9, v13)
	gb(v2, v6, v10, v14)
	gb(v3, v7, v11, v15)
	gb(v0, v5, v10, v15)
	gb(v1, v6, v11, v12)
	gb(v2, v7, v8, v13)
	gb(v3, v4, v9, v14)
}

func gb(pa, pb, pc, pd *uint64) {
	a, b, c, d := *pa, *pb, *pc, *pd
	a += b + 2*uint64(uint32(a))*uint64(uint32(b))
	d = bits.RotateLeft64(d^a, -32)
	c += d + 2*uint64(uint32(c))*uint64(uint32(d))
	b = bits.RotateLeft64(b^c, -24)
	a += b + 2*uint64(uint32(a))*uint64(uint32(b))
	d = bits.RotateLeft64(d^a, -16)
	c += d + 2*uint64(uint32(c))*uint64(uint32(d))
	b = bits.RotateLeft64(b^c, -63)
	*pa, *pb, *pc, *pd = a, b, c, d
}
