package svluks

import (
	"bytes"
	stdpbkdf2 "crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	mrand "math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// cheap KDFs, at cryptsetup's minimum costs, keep the tests fast.
var (
	cheapArgon = KDF{Type: KDFArgon2id, Iterations: 4, MemoryKiB: 32, Threads: 1}
	cheapPBKDF = KDF{Type: KDFPBKDF2, Hash: "sha256", Iterations: 1000}
	pass       = []byte("correct horse battery staple")
)

// memDev is an image in memory.
type memDev struct {
	mu sync.Mutex
	b  []byte
}

func newMemDev(size int) *memDev { return &memDev{b: make([]byte, size)} }

func (m *memDev) ReadAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if off >= int64(len(m.b)) {
		return 0, io.EOF
	}
	n := copy(p, m.b[off:])
	if n < len(p) {
		return n, io.EOF
	}
	return n, nil
}

func (m *memDev) WriteAt(p []byte, off int64) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if off+int64(len(p)) > int64(len(m.b)) {
		return 0, errors.New("memDev: write past the end")
	}
	return copy(m.b[off:], p), nil
}

func (m *memDev) Size() int64 { return int64(len(m.b)) }

func (m *memDev) clone() *memDev { return &memDev{b: bytes.Clone(m.b)} }

// newImage formats a fresh in-memory image with size bytes of data.
func newImage(t *testing.T, data int, o Options) (*memDev, *Header, *Key) {
	t.Helper()
	if o.KDF.Type == "" {
		o.KDF = cheapPBKDF
	}
	dev := newMemDev(DataOffset + data)
	h, key, err := Format(dev, pass, o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(key.Destroy)
	return dev, h, key
}

func TestPBKDF2(t *testing.T) {
	// RFC 6070, and agreement with the standard library for every hash and
	// for lengths that are and are not whole blocks.
	got := pbkdf2(sha1.New, []byte("password"), []byte("salt"), 4096, 20)
	if hex.EncodeToString(got) != "4b007901b765489abead49d926f721d065a429c1" {
		t.Fatalf("RFC 6070: %x", got)
	}
	for _, h := range []func() hash.Hash{sha1.New, sha256.New, sha512.New} {
		for _, n := range []int{1, 20, 32, 33, 64, 100} {
			want, err := stdpbkdf2.Key(h, "a key", []byte("some salt"), 1000, n)
			if err != nil {
				t.Fatal(err)
			}
			if got := pbkdf2(h, []byte("a key"), []byte("some salt"), 1000, n); !bytes.Equal(got, want) {
				t.Fatalf("length %d: %x, want %x", n, got, want)
			}
		}
	}
}

func TestAFSplitMerge(t *testing.T) {
	for _, n := range []int{16, 32, 33, 64, 100} {
		key := make([]byte, n)
		rand.Read(key)
		m := afSplit(key, sha256.New, func(b []byte) { rand.Read(b) })
		if len(m)%sectorBytes != 0 || uint64(len(m)) != afSize(n) {
			t.Fatalf("%d-byte key: %d bytes of material", n, len(m))
		}
		if got := afMerge(m, n, sha256.New); !bytes.Equal(got, key) {
			t.Fatalf("%d-byte key did not come back", n)
		}
		m[len(m)/2] ^= 1
		if got := afMerge(m, n, sha256.New); bytes.Equal(got, key) {
			t.Fatalf("%d-byte key survived a flipped bit", n)
		}
	}
}

func TestFormatAndUnlock(t *testing.T) {
	for _, o := range []Options{
		{SectorSize: 512, KDF: cheapPBKDF, Label: "mine"},
		{SectorSize: 4096, KDF: cheapArgon, Subsystem: "secretvault"},
		{KDF: KDF{Type: KDFArgon2i, Iterations: 4, MemoryKiB: 64, Threads: 2}},
	} {
		dev, h, key := newImage(t, 1<<20, o)
		h2, err := Read(dev)
		if err != nil {
			t.Fatal(err)
		}
		if h2.UUID() != h.UUID() || h2.Label() != o.Label || h2.Subsystem() != o.Subsystem ||
			h2.DataOffset() != DataOffset || h2.Cipher() != "aes-xts-plain64" || h2.Seqid() != 2 {
			t.Fatalf("read back %+v", h2.bin)
		}
		if ss := h2.SectorSize(); ss != max(o.SectorSize, 512) && !(o.SectorSize == 0 && ss == 4096) {
			t.Fatalf("sector size %d", ss)
		}
		got, slot, err := h2.Unlock(dev, pass)
		if err != nil || slot != 0 || !bytes.Equal(got.Bytes(), key.Bytes()) || len(got.Bytes()) != VolumeKeySize {
			t.Fatalf("unlock: slot %d, %v", slot, err)
		}
		got.Destroy()
		if _, _, err := h2.Unlock(dev, []byte("wrong")); !errors.Is(err, ErrWrongKey) {
			t.Fatalf("a wrong passphrase: %v", err)
		}
		ks := h2.Keyslots()
		if len(ks) != 1 || ks[0].KDF.Type != o.KDF.Type || !ks[0].Bound || ks[0].KeySize != 64 {
			t.Fatalf("keyslots %+v", ks)
		}
	}
}

func TestFormatRefuses(t *testing.T) {
	for name, c := range map[string]struct {
		size int
		o    Options
	}{
		"too small":        {DataOffset, Options{KDF: cheapPBKDF}},
		"ragged size":      {DataOffset + 4096 + 512, Options{KDF: cheapPBKDF}},
		"sector size 1024": {DataOffset + 4096, Options{SectorSize: 1024, KDF: cheapPBKDF}},
		"long label":       {DataOffset + 4096, Options{Label: strings.Repeat("x", 48), KDF: cheapPBKDF}},
		"weak pbkdf2":      {DataOffset + 4096, Options{KDF: KDF{Type: KDFPBKDF2, Iterations: 10}}},
		"weak argon2":      {DataOffset + 4096, Options{KDF: KDF{Type: KDFArgon2id, Iterations: 1, MemoryKiB: 64, Threads: 1}}},
		"bad uuid":         {DataOffset + 4096, Options{UUID: "not-a-uuid", KDF: cheapPBKDF}},
		"unknown kdf":      {DataOffset + 4096, Options{KDF: KDF{Type: "scrypt"}}},
	} {
		if _, _, err := Format(newMemDev(c.size), pass, c.o); err == nil {
			t.Errorf("%s: formatted", name)
		}
	}
}

func TestKeyslots(t *testing.T) {
	dev, h, key := newImage(t, 1<<20, Options{})
	second := []byte("another passphrase")
	id, err := h.AddKeyslot(dev, key, second, cheapArgon)
	if err != nil || id != 1 {
		t.Fatalf("add: %d %v", id, err)
	}
	if _, err := h.AddKeyslot(dev, NewKey(make([]byte, 64)), second, cheapArgon); err == nil {
		t.Fatal("added a keyslot for a key that is not the volume key")
	}
	h, _ = Read(dev)
	if k, slot, err := h.Unlock(dev, second); err != nil || slot != 1 || !bytes.Equal(k.Bytes(), key.Bytes()) {
		t.Fatalf("unlock the new slot: %d %v", slot, err)
	}
	areaBefore := h.meta.keyslots[1].Area

	// Change: same number, new area, old area overwritten.
	third := []byte("a third passphrase")
	if err := h.ChangeKeyslot(dev, 1, key, third, cheapPBKDF); err != nil {
		t.Fatal(err)
	}
	h, _ = Read(dev)
	if _, err := h.UnlockSlot(dev, 1, second); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("the old passphrase still opens slot 1: %v", err)
	}
	if _, err := h.UnlockSlot(dev, 1, third); err != nil {
		t.Fatal(err)
	}
	if h.meta.keyslots[1].Area.Offset == areaBefore.Offset {
		t.Fatal("changed in place")
	}
	old := dev.b[areaBefore.Offset : areaBefore.Offset+areaBefore.Size]
	if bytes.Count(old, []byte{0}) == len(old) {
		t.Fatal("the old area was zeroed, not overwritten with noise")
	}

	// Remove: slot 0 goes, slot 1 is then the last and stays.
	if err := h.RemoveKeyslot(dev, 0); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveKeyslot(dev, 1); !errors.Is(err, ErrLastKeyslot) {
		t.Fatalf("removed the last keyslot: %v", err)
	}
	h, err = Read(dev)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := h.Unlock(dev, pass); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("slot 0 still opens: %v", err)
	}
	if len(h.Keyslots()) != 1 || h.meta.digests[0].Keyslots[0] != 1 {
		t.Fatalf("after removal: %+v, digest %v", h.Keyslots(), h.meta.digests[0].Keyslots)
	}
	// Numbers are reused, and areas too.
	if id, err := h.AddKeyslot(dev, key, pass, cheapPBKDF); err != nil || id != 0 {
		t.Fatalf("re-add: %d %v", id, err)
	}
}

// editJSON rewrites the metadata of both header copies through a generic
// map, with good checksums: how a hostile header is made.
func editJSON(t *testing.T, dev *memDev, edit func(m map[string]any)) {
	t.Helper()
	for i, magic := range [][]byte{magicPrimary, magicSecondary} {
		b, text, err := readCopy(dev, uint64(i)*defHdrSize, magic)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		d := json.NewDecoder(bytes.NewReader(text))
		d.UseNumber()
		if err := d.Decode(&m); err != nil {
			t.Fatal(err)
		}
		edit(m)
		out, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		buf, err := encodeCopy(b, magic, out)
		if err != nil {
			t.Fatal(err)
		}
		dev.WriteAt(buf, int64(b.hdrOffset))
	}
}

func obj(m map[string]any, path ...string) map[string]any {
	for _, p := range path {
		m = m[p].(map[string]any)
	}
	return m
}

func TestHostileHeaders(t *testing.T) {
	base, h, key := newImage(t, 1<<20, Options{KDF: cheapArgon})
	if _, err := h.AddKeyslot(base, key, []byte("second passphrase"), cheapPBKDF); err != nil {
		t.Fatal(err)
	}
	cases := map[string]struct {
		edit func(m map[string]any)
		want error
	}{
		"overlapping keyslot areas": {func(m map[string]any) {
			obj(m, "keyslots", "1", "area")["offset"] = "65536"
		}, ErrHeader},
		"area outside the keyslot area": {func(m map[string]any) {
			obj(m, "keyslots", "0", "area")["offset"] = "16777216"
		}, ErrHeader},
		"area inside the header": {func(m map[string]any) {
			obj(m, "keyslots", "0", "area")["offset"] = "4096"
		}, ErrHeader},
		"area too small for the key": {func(m map[string]any) {
			obj(m, "keyslots", "0", "area")["size"] = "4096"
		}, ErrHeader},
		"argon2 wants 64 GiB": {func(m map[string]any) {
			obj(m, "keyslots", "0", "kdf")["memory"] = 64 << 20
		}, ErrHeader},
		"argon2 wants a million passes": {func(m map[string]any) {
			obj(m, "keyslots", "0", "kdf")["time"] = 1 << 20
		}, ErrHeader},
		"argon2 wants 1000 lanes": {func(m map[string]any) {
			obj(m, "keyslots", "0", "kdf")["cpus"] = 1000
		}, ErrHeader},
		"pbkdf2 wants 4 billion iterations": {func(m map[string]any) {
			obj(m, "keyslots", "1", "kdf")["iterations"] = uint32(1<<32 - 1)
		}, ErrHeader},
		"digest wants 4 billion iterations": {func(m map[string]any) {
			obj(m, "digests", "0")["iterations"] = uint32(1<<32 - 1)
		}, ErrHeader},
		"digest wants 5 million iterations": {func(m map[string]any) {
			obj(m, "digests", "0")["iterations"] = 5_000_000
		}, ErrHeader},
		"a long SHA-1 digest at 2 million iterations": {func(m map[string]any) {
			d := obj(m, "digests", "0")
			d["hash"], d["digest"], d["iterations"] = "sha1", base64.StdEncoding.EncodeToString(make([]byte, 64)), 2_000_000
		}, ErrHeader},
		"an offset that wraps round to the header": {func(m map[string]any) {
			obj(m, "segments", "0")["offset"] = "18446744073692774400"
		}, ErrHeader},
		"a size past an exbibyte": {func(m map[string]any) {
			obj(m, "segments", "0")["size"] = "9223372036854775808"
		}, ErrHeader},
		"a negative key size": {func(m map[string]any) {
			obj(m, "keyslots", "0")["key_size"] = -64
		}, ErrHeader},
		"a key size as a string": {func(m map[string]any) {
			obj(m, "keyslots", "0")["key_size"] = "64"
		}, ErrHeader},
		"an offset as a number": {func(m map[string]any) {
			obj(m, "segments", "0")["offset"] = 16777216
		}, ErrHeader},
		"an offset past 2^64": {func(m map[string]any) {
			obj(m, "segments", "0")["offset"] = "99999999999999999999"
		}, ErrHeader},
		"data inside the header": {func(m map[string]any) {
			obj(m, "segments", "0")["offset"] = "1048576"
		}, ErrHeader},
		"overlapping segments": {func(m map[string]any) {
			s := obj(m, "segments", "0")
			m["segments"].(map[string]any)["1"] = map[string]any{"type": "crypt", "offset": "16777216", "size": "dynamic",
				"iv_tweak": "0", "encryption": s["encryption"], "sector_size": s["sector_size"]}
		}, ErrUnsupported},
		"odd sector size": {func(m map[string]any) {
			obj(m, "segments", "0")["sector_size"] = 1000
		}, ErrHeader},
		"integrity": {func(m map[string]any) {
			obj(m, "segments", "0")["integrity"] = map[string]any{"type": "hmac(sha256)"}
		}, ErrUnsupported},
		"reencryption": {func(m map[string]any) {
			obj(m, "segments", "0")["flags"] = []any{"in-reencryption"}
		}, ErrUnsupported},
		"no segment": {func(m map[string]any) {
			m["segments"] = map[string]any{}
		}, ErrHeader},
		"keyslot number with a leading zero": {func(m map[string]any) {
			ks := m["keyslots"].(map[string]any)
			ks["01"] = ks["1"]
			delete(ks, "1")
		}, ErrHeader},
		"keyslot 32": {func(m map[string]any) {
			ks := m["keyslots"].(map[string]any)
			ks["32"] = ks["1"]
			delete(ks, "1")
		}, ErrHeader},
		"digest names a missing keyslot": {func(m map[string]any) {
			obj(m, "digests", "0")["keyslots"] = []any{"0", "1", "7"}
		}, ErrHeader},
		"keyslot with no digest": {func(m map[string]any) {
			obj(m, "digests", "0")["keyslots"] = []any{"0"}
		}, ErrHeader},
		"token names a missing keyslot": {func(m map[string]any) {
			m["tokens"] = map[string]any{"0": map[string]any{"type": "x", "keyslots": []any{"9"}}}
		}, ErrHeader},
		"json size that disagrees": {func(m map[string]any) {
			obj(m, "config")["json_size"] = "4096"
		}, ErrHeader},
		"keyslot area not aligned": {func(m map[string]any) {
			obj(m, "config")["keyslots_size"] = "16744447"
		}, ErrHeader},
		"requirements": {func(m map[string]any) {
			obj(m, "config")["requirements"] = map[string]any{"mandatory": []any{"online-reencrypt-v2"}}
		}, nil}, // readable, but neither openable nor changeable (below)
		"no config": {func(m map[string]any) { delete(m, "config") }, ErrHeader},
		"stripes": {func(m map[string]any) {
			obj(m, "keyslots", "0", "af")["stripes"] = 1
		}, ErrHeader},
		"salt that is not base64": {func(m map[string]any) {
			obj(m, "keyslots", "0", "kdf")["salt"] = "!!!"
		}, ErrHeader},
	}
	for name, c := range cases {
		dev := base.clone()
		editJSON(t, dev, c.edit)
		h, err := Read(dev)
		if c.want == nil {
			if err != nil {
				t.Errorf("%s: %v", name, err)
				continue
			}
			if _, _, err := h.Unlock(dev, pass); !errors.Is(err, ErrUnsupported) {
				t.Errorf("%s: unlocked (%v)", name, err)
			}
			if _, err := h.AddKeyslot(dev, key, pass, cheapPBKDF); !errors.Is(err, ErrUnsupported) {
				t.Errorf("%s: changed (%v)", name, err)
			}
			continue
		}
		if !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestDamagedHeaders(t *testing.T) {
	dev, h, key := newImage(t, 1<<20, Options{})

	// A damaged primary: the secondary is used, and the next write repairs
	// the primary with a new salt.
	d := dev.clone()
	d.b[5000] ^= 1
	h2, err := Read(d)
	if err != nil || !h2.fresh[0] || h2.fresh[1] {
		t.Fatalf("damaged primary: %v %v", err, h2.fresh)
	}
	oldSalt := bytes.Clone(dev.b[offSalt : offSalt+saltLen])
	if _, err := h2.AddKeyslot(d, key, []byte("repair it"), cheapPBKDF); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readCopy(d, 0, magicPrimary); err != nil {
		t.Fatalf("not repaired: %v", err)
	}
	if bytes.Equal(d.b[offSalt:offSalt+saltLen], oldSalt) {
		t.Fatal("repaired without a new salt")
	}

	// A damaged secondary: the primary is used.
	d = dev.clone()
	d.b[defHdrSize+100] ^= 1
	if _, err := Read(d); err != nil {
		t.Fatal(err)
	}

	// The newer copy wins: a primary written after the secondary.
	d = dev.clone()
	if _, err := h.AddKeyslot(d, key, []byte("newer"), cheapPBKDF); err != nil {
		t.Fatal(err)
	}
	copy(d.b[defHdrSize:2*defHdrSize], dev.b[defHdrSize:2*defHdrSize])
	h3, err := Read(d)
	if err != nil || len(h3.Keyslots()) != 2 {
		t.Fatalf("newer primary: %v, %d keyslots", err, len(h3.Keyslots()))
	}

	// Both damaged, or none there: refused.
	d = dev.clone()
	d.b[5000] ^= 1
	d.b[defHdrSize+5000] ^= 1
	if _, err := Read(d); !errors.Is(err, ErrHeader) {
		t.Fatalf("both damaged: %v", err)
	}
	if _, err := Read(newMemDev(1 << 20)); !errors.Is(err, ErrNotLUKS) {
		t.Fatalf("zeros: %v", err)
	}
	if _, err := Read(bytes.NewReader([]byte("LUKS\xba\xbe"))); !errors.Is(err, ErrNotLUKS) {
		t.Fatalf("six bytes: %v", err)
	}

	// LUKS1 is named as such.
	d = newMemDev(8192)
	copy(d.b, "LUKS\xba\xbe\x00\x01")
	if _, err := Read(d); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "LUKS1") {
		t.Fatalf("LUKS1: %v", err)
	}
}

// A newer copy whose checksum holds but whose metadata does not parse is
// an error: falling back to the older copy would have the next write put
// the older state over it.
func TestANewerCopyThatFailsIsNotSkipped(t *testing.T) {
	dev, h, _ := newImage(t, 1<<20, Options{})
	s := h.meta.segments[0]
	raw, err := setMember(s.raw, "integrity", map[string]string{"type": "hmac(sha256)"})
	if err != nil {
		t.Fatal(err)
	}
	old := s.raw
	s.raw = raw
	text, _ := h.meta.marshal()
	s.raw = old
	b := h.bin
	b.seqid++
	b.salt = h.salts[0]
	buf, err := encodeCopy(&b, magicPrimary, text)
	if err != nil {
		t.Fatal(err)
	}
	dev.WriteAt(buf, 0)
	if _, err := Read(dev); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("read the older copy instead: %v", err)
	}
}

// failingDev fails every write after the first n.
type failingDev struct {
	*memDev
	n int
}

func (f *failingDev) WriteAt(p []byte, off int64) (int, error) {
	if f.n <= 0 {
		return 0, errors.New("the disk is gone")
	}
	f.n--
	return f.memDev.WriteAt(p, off)
}

// After a write fails half way, what is on disk is unknown: the Header
// refuses further changes until read again, and no sequence number is
// written twice.
func TestAFailedWriteBreaksTheHeader(t *testing.T) {
	dev, h, key := newImage(t, 1<<20, Options{})
	fd := &failingDev{memDev: dev, n: 2} // the keyslot area and the primary copy
	if _, err := h.AddKeyslot(fd, key, []byte("half written"), cheapPBKDF); err == nil {
		t.Fatal("a failed write succeeded")
	}
	fd.n = 100
	if _, err := h.AddKeyslot(fd, key, []byte("again"), cheapPBKDF); err == nil || !strings.Contains(err.Error(), "read it again") {
		t.Fatalf("changed a broken header: %v", err)
	}
	h2, err := Read(dev)
	if err != nil || h2.Seqid() != 3 || len(h2.Keyslots()) != 2 {
		t.Fatalf("read again: %v, seqid %d", err, h2.Seqid())
	}
	if _, err := h2.AddKeyslot(dev, key, []byte("and now"), cheapPBKDF); err != nil || h2.Seqid() != 4 {
		t.Fatalf("after reading again: %v, seqid %d", err, h2.Seqid())
	}
}

// Writes and reads bigger than a chunk, at ragged offsets.
func TestVolumeInChunks(t *testing.T) {
	for _, ss := range []int{512, 4096} {
		const size = 5 << 20
		dev, h, key := newImage(t, size, Options{SectorSize: ss})
		v, err := h.Volume(dev, key)
		if err != nil {
			t.Fatal(err)
		}
		model := make([]byte, size)
		rand.Read(model)
		if n, err := v.WriteAt(model, 0); n != size || err != nil {
			t.Fatal(n, err)
		}
		for _, c := range [][2]int{{1, 3<<20 + 5}, {ss - 1, 2<<20 + 2}, {1<<20 - 3, 1<<20 + 7}, {size - (2<<20 + 1), 2<<20 + 1}} {
			off, n := c[0], c[1]
			p := make([]byte, n)
			rand.Read(p)
			if w, err := v.WriteAt(p, int64(off)); w != n || err != nil {
				t.Fatal(w, err)
			}
			copy(model[off:], p)
			got := make([]byte, size)
			if r, err := v.ReadAt(got, 0); r != size || err != nil || !bytes.Equal(got, model) {
				t.Fatalf("%d-byte sectors, %d at %d: read %d, %v", ss, n, off, r, err)
			}
			roff := max(off-1, 0)
			got = got[:min(n+3, size-roff)]
			if _, err := v.ReadAt(got, int64(roff)); err != nil || !bytes.Equal(got, model[roff:roff+len(got)]) {
				t.Fatalf("%d-byte sectors: a ragged read at %d differs", ss, roff)
			}
		}
	}
}

func TestUnknownMembersSurvive(t *testing.T) {
	dev, _, key := newImage(t, 1<<20, Options{})
	editJSON(t, dev, func(m map[string]any) {
		m["tokens"] = map[string]any{"0": map[string]any{"type": "systemd-tpm2", "keyslots": []any{"0"}, "tpm2-pcrs": []any{7.0}}}
		obj(m, "config")["flags"] = []any{"allow-discards"}
		obj(m, "keyslots", "0")["priority"] = 2
		m["x-future"] = map[string]any{"kept": true}
	})
	h, err := Read(dev)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.AddKeyslot(dev, key, []byte("one more"), cheapPBKDF); err != nil {
		t.Fatal(err)
	}
	if err := h.ChangeKeyslot(dev, 0, key, []byte("changed one"), cheapPBKDF); err != nil {
		t.Fatal(err)
	}
	_, text, _ := readCopy(dev, 0, magicPrimary)
	for _, want := range []string{`"tpm2-pcrs":[7]`, `"allow-discards"`, `"x-future":{"kept":true}`, `"priority":2`} {
		if !bytes.Contains(text, []byte(want)) {
			t.Errorf("%s was lost: %s", want, text)
		}
	}
	// Removing the keyslot a token names takes it off the token's list.
	h, _ = Read(dev)
	if err := h.RemoveKeyslot(dev, 0); err != nil {
		t.Fatal(err)
	}
	_, text, _ = readCopy(dev, 0, magicPrimary)
	if !bytes.Contains(text, []byte(`"keyslots":[]`)) || !bytes.Contains(text, []byte(`"systemd-tpm2"`)) {
		t.Fatalf("token after removal: %s", text)
	}
}

func TestVolume(t *testing.T) {
	for _, ss := range []int{512, 4096} {
		t.Run(fmt.Sprint(ss), func(t *testing.T) {
			const size = 256 << 10
			dev, h, key := newImage(t, size, Options{SectorSize: ss})
			v, err := h.Volume(dev, key)
			if err != nil {
				t.Fatal(err)
			}
			if v.Size() != size || v.SectorSize() != ss {
				t.Fatalf("size %d, sectors %d", v.Size(), v.SectorSize())
			}
			// Random writes at ragged offsets, against a plain copy. (Data
			// never written decrypts to noise, so it all is first.)
			model := make([]byte, size)
			rand.Read(model)
			if n, err := v.WriteAt(model, 0); n != size || err != nil {
				t.Fatalf("write it all: %d %v", n, err)
			}
			r := mrand.New(mrand.NewPCG(1, uint64(ss)))
			for range 300 {
				off := r.IntN(size)
				n := min(r.IntN(3*ss), size-off)
				p := make([]byte, n)
				rand.Read(p)
				if w, err := v.WriteAt(p, int64(off)); err != nil || w != n {
					t.Fatalf("write %d at %d: %d %v", n, off, w, err)
				}
				copy(model[off:], p)
				roff := r.IntN(size)
				got := make([]byte, min(r.IntN(3*ss), size-roff))
				if _, err := v.ReadAt(got, int64(roff)); err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, model[roff:roff+len(got)]) {
					t.Fatalf("read %d at %d differs", len(got), roff)
				}
			}
			// The data on disk is not the plaintext.
			if bytes.Contains(dev.b[DataOffset:], model[1000:1100]) {
				t.Fatal("plaintext on disk")
			}
			// A fresh Volume reads the same, whole.
			v2, _ := h.Volume(dev, key)
			all := make([]byte, size+10)
			if n, err := v2.ReadAt(all, 0); n != size || err != io.EOF || !bytes.Equal(all[:n], model) {
				t.Fatalf("read all: %d %v", n, err)
			}
			// Ends.
			if _, err := v2.WriteAt([]byte("xx"), size-1); err == nil {
				t.Fatal("wrote past the end")
			}
			if n, err := v2.ReadAt(make([]byte, 4), size); n != 0 || err != io.EOF {
				t.Fatalf("read at the end: %d %v", n, err)
			}
			if _, err := h.Volume(dev, NewKey(make([]byte, 64))); err == nil {
				t.Fatal("opened with the wrong key")
			}
		})
	}
}

func TestBackupRestore(t *testing.T) {
	dev, h, key := newImage(t, 1<<20, Options{})
	var backup bytes.Buffer
	n, err := BackupHeader(dev, &backup)
	if err != nil || n != DataOffset {
		t.Fatalf("backup: %d %v", n, err)
	}
	// The header is changed (a keyslot removed), then restored.
	if _, err := h.AddKeyslot(dev, key, []byte("temporary"), cheapPBKDF); err != nil {
		t.Fatal(err)
	}
	if err := h.RemoveKeyslot(dev, 0); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mustRead(t, dev).Unlock(dev, pass); !errors.Is(err, ErrWrongKey) {
		t.Fatal("keyslot 0 was not removed")
	}
	if err := RestoreHeader(dev, bytes.NewReader(backup.Bytes())); err != nil {
		t.Fatal(err)
	}
	if _, _, err := mustRead(t, dev).Unlock(dev, pass); err != nil {
		t.Fatalf("after restore: %v", err)
	}
	// Another image's backup, and a short one, are refused.
	other, _, _ := newImage(t, 1<<20, Options{})
	var ob bytes.Buffer
	BackupHeader(other, &ob)
	if err := RestoreHeader(dev, bytes.NewReader(ob.Bytes())); err == nil || !strings.Contains(err.Error(), "another image") {
		t.Fatalf("another image's backup: %v", err)
	}
	if err := RestoreHeader(dev, bytes.NewReader(backup.Bytes()[:100000])); err == nil {
		t.Fatal("restored a short backup")
	}
}

func mustRead(t *testing.T, dev io.ReaderAt) *Header {
	t.Helper()
	h, err := Read(dev)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestOnAFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.img")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := f.Truncate(DataOffset + 1<<20); err != nil {
		t.Fatal(err)
	}
	h, key, err := Format(f, pass, Options{KDF: cheapPBKDF})
	if err != nil {
		t.Fatal(err)
	}
	defer key.Destroy()
	v, err := h.Volume(f, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.WriteAt([]byte("hello"), 12345); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 5)
	v.ReadAt(got, 12345)
	if string(got) != "hello" {
		t.Fatalf("read %q", got)
	}
}

// FuzzRead feeds Read damaged and hostile headers: it must refuse or
// accept them, never panic, and what it accepts must write back out.
func FuzzRead(f *testing.F) {
	for _, o := range []Options{{KDF: cheapPBKDF}, {SectorSize: 512, KDF: cheapArgon, Label: "x"}} {
		dev := newMemDev(DataOffset + 4096)
		if _, _, err := Format(dev, pass, o); err != nil {
			f.Fatal(err)
		}
		f.Add(dev.b[:2*defHdrSize])
		f.Add(dev.b[defHdrSize : 2*defHdrSize])
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := Read(bytes.NewReader(data))
		if err != nil {
			return
		}
		h.Keyslots()
		if _, err := h.meta.marshal(); err != nil {
			t.Fatalf("accepted a header it cannot write back: %v", err)
		}
	})
}

// FuzzMetadata feeds the JSON parser directly, with sound checksums around
// it taken for granted.
func FuzzMetadata(f *testing.F) {
	dev := newMemDev(DataOffset + 4096)
	h, key, err := Format(dev, pass, Options{KDF: cheapPBKDF})
	if err != nil {
		f.Fatal(err)
	}
	h.AddKeyslot(dev, key, []byte("a second one"), cheapArgon)
	_, text, _ := readCopy(dev, 0, magicPrimary)
	f.Add(text)
	f.Add([]byte(`{"keyslots":{},"tokens":{},"segments":{},"digests":{},"config":{"json_size":"12288","keyslots_size":"16744448"}}`))
	f.Fuzz(func(t *testing.T, text []byte) {
		m, err := parseMetadata(text, defHdrSize)
		if err != nil {
			return
		}
		out, err := m.marshal()
		if err != nil {
			t.Fatalf("accepted metadata it cannot write back: %v", err)
		}
		if _, err := parseMetadata(out, defHdrSize); err != nil {
			t.Fatalf("what it wrote back does not parse: %v\n%s", err, out)
		}
	})
}
