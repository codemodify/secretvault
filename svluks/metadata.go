package svluks

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// The JSON metadata (specification section 3): five objects, keyslots,
// tokens, segments, digests and config, the first four holding objects
// named by decimal numbers. Each object is kept as the text it was read
// as, and only the members this package changes are rewritten, so what it
// does not interpret (tokens, priorities, flags, unknown members) survives.

const (
	maxObjects   = 32 // keyslots, tokens, segments and digests each, as cryptsetup
	maxKeySize   = 512
	afStripes    = 4000
	areaAlign    = 4096
	minSalt      = 16
	maxSalt      = 64
	maxKeyslots  = 128 << 20 // the keyslot area, as cryptsetup allows at most
	cipherXTS    = "aes-xts-plain64"
	maxCipherLen = 64
	maxDataBytes = 1 << 60 // an exbibyte: data offsets and sizes past it are nonsense
)

// metadata is the parsed JSON area.
type metadata struct {
	keyslots map[int]*keyslot
	tokens   map[int]json.RawMessage
	segments map[int]*segment
	digests  map[int]*digest
	config   json.RawMessage
	extra    map[string]json.RawMessage // unknown top-level members

	jsonSize, keyslotsSize uint64
	requirements           []string
}

type keyslot struct {
	Type     string
	KeySize  int
	AF       afJSON
	Area     areaJSON
	KDF      kdfJSON
	Priority int
	raw      json.RawMessage
}

type segment struct {
	Type       string
	Offset     uint64
	Size       uint64 // 0 for "dynamic"
	IVTweak    uint64
	Encryption string
	SectorSize int
	raw        json.RawMessage
}

type digest struct {
	Type       string
	Keyslots   []int
	Segments   []int
	Hash       string
	Iterations uint32
	Salt       []byte
	Digest     []byte
	raw        json.RawMessage
}

// The members as they appear in JSON. Field order is the order written,
// which follows cryptsetup's.

type keyslotJSON struct {
	Type     string    `json:"type"`
	KeySize  uint32    `json:"key_size"`
	AF       *afJSON   `json:"af,omitempty"`
	Area     *areaJSON `json:"area"`
	KDF      *kdfJSON  `json:"kdf,omitempty"`
	Priority *uint32   `json:"priority,omitempty"`
}

type afJSON struct {
	Type    string `json:"type"`
	Stripes uint32 `json:"stripes"`
	Hash    string `json:"hash"`
}

type areaJSON struct {
	Type       string `json:"type"`
	Offset     u64    `json:"offset"`
	Size       u64    `json:"size"`
	Encryption string `json:"encryption,omitempty"`
	KeySize    uint32 `json:"key_size,omitempty"`
}

type kdfJSON struct {
	Type       string `json:"type"`
	Hash       string `json:"hash,omitempty"`
	Iterations uint32 `json:"iterations,omitempty"`
	Time       uint32 `json:"time,omitempty"`
	Memory     uint32 `json:"memory,omitempty"`
	CPUs       uint32 `json:"cpus,omitempty"`
	Salt       []byte `json:"salt"`
}

type segmentJSON struct {
	Type       string          `json:"type"`
	Offset     u64             `json:"offset"`
	Size       string          `json:"size"`
	IVTweak    u64             `json:"iv_tweak"`
	Encryption string          `json:"encryption"`
	SectorSize uint32          `json:"sector_size"`
	Integrity  json.RawMessage `json:"integrity,omitempty"`
	Flags      []string        `json:"flags,omitempty"`
}

type digestJSON struct {
	Type       string   `json:"type"`
	Keyslots   []string `json:"keyslots"`
	Segments   []string `json:"segments"`
	Hash       string   `json:"hash"`
	Iterations uint32   `json:"iterations"`
	Salt       []byte   `json:"salt"`
	Digest     []byte   `json:"digest"`
}

type configJSON struct {
	JSONSize     u64             `json:"json_size"`
	KeyslotsSize u64             `json:"keyslots_size"`
	Flags        []string        `json:"flags,omitempty"`
	Requirements json.RawMessage `json:"requirements,omitempty"`
}

// u64 is the specification's string-uint64: a 64-bit number written as a
// decimal string, since JSON numbers cannot hold one.
type u64 uint64

func (v *u64) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return fmt.Errorf("%s is not a number in a string", b)
	}
	n, err := parseU64(s)
	if err != nil {
		return err
	}
	*v = u64(n)
	return nil
}

func (v u64) MarshalJSON() ([]byte, error) {
	return []byte(`"` + strconv.FormatUint(uint64(v), 10) + `"`), nil
}

func parseU64(s string) (uint64, error) {
	if s == "" || len(s) > 20 || strings.Trim(s, "0123456789") != "" {
		return 0, fmt.Errorf("%q is not a decimal number", s)
	}
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("%q is out of range", s)
	}
	return n, nil
}

// parseID reads an object name: a decimal number below max, written
// without leading zeros.
func parseID(s string, max int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || n >= max || strconv.Itoa(n) != s {
		return 0, fmt.Errorf("%q is not an object number below %d", s, max)
	}
	return n, nil
}

// members splits a JSON object into its members, and says whether each
// named one is there.
func members(raw json.RawMessage, what string, required ...string) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil || obj == nil {
		return nil, headerErr("%s is not a JSON object", what)
	}
	for _, name := range required {
		if v, ok := obj[name]; !ok || string(v) == "null" {
			return nil, headerErr("%s has no %q", what, name)
		}
	}
	return obj, nil
}

// strict decodes raw into v, naming what on failure.
func strict(raw json.RawMessage, v any, what string) error {
	if err := json.Unmarshal(raw, v); err != nil {
		return headerErr("%s: %v", what, err)
	}
	return nil
}

// numbered reads one of the four objects of numbered objects.
func numbered(raw json.RawMessage, what string) (map[int]json.RawMessage, error) {
	obj, err := members(raw, what)
	if err != nil {
		return nil, err
	}
	if len(obj) > maxObjects {
		return nil, headerErr("%d %s, more than %d", len(obj), what, maxObjects)
	}
	out := make(map[int]json.RawMessage, len(obj))
	for name, v := range obj {
		id, err := parseID(name, maxObjects)
		if err != nil {
			return nil, headerErr("%s: %v", what, err)
		}
		out[id] = v
	}
	return out, nil
}

// parseMetadata parses and checks the JSON area of a header copy whose
// size is hdrSize.
func parseMetadata(text []byte, hdrSize uint64) (*metadata, error) {
	if !utf8.Valid(text) {
		return nil, headerErr("the metadata is not UTF-8")
	}
	top, err := members(text, "the metadata", "keyslots", "tokens", "segments", "digests", "config")
	if err != nil {
		return nil, err
	}
	m := &metadata{keyslots: map[int]*keyslot{}, segments: map[int]*segment{}, digests: map[int]*digest{},
		config: top["config"], extra: map[string]json.RawMessage{}}
	for name, v := range top {
		switch name {
		case "keyslots", "tokens", "segments", "digests", "config":
		default:
			m.extra[name] = v
		}
	}
	if err := m.parseConfig(hdrSize); err != nil {
		return nil, err
	}
	raws, err := numbered(top["keyslots"], "keyslots")
	if err != nil {
		return nil, err
	}
	for id, raw := range raws {
		ks, err := parseKeyslot(id, raw)
		if err != nil {
			return nil, err
		}
		m.keyslots[id] = ks
	}
	if raws, err = numbered(top["segments"], "segments"); err != nil {
		return nil, err
	}
	for id, raw := range raws {
		s, err := parseSegment(id, raw)
		if err != nil {
			return nil, err
		}
		m.segments[id] = s
	}
	if raws, err = numbered(top["digests"], "digests"); err != nil {
		return nil, err
	}
	for id, raw := range raws {
		d, err := parseDigest(id, raw)
		if err != nil {
			return nil, err
		}
		m.digests[id] = d
	}
	if m.tokens, err = numbered(top["tokens"], "tokens"); err != nil {
		return nil, err
	}
	if err := m.check(hdrSize); err != nil {
		return nil, err
	}
	return m, nil
}

func (m *metadata) parseConfig(hdrSize uint64) error {
	if _, err := members(m.config, "config", "json_size", "keyslots_size"); err != nil {
		return err
	}
	var c configJSON
	if err := strict(m.config, &c, "config"); err != nil {
		return err
	}
	m.jsonSize, m.keyslotsSize = uint64(c.JSONSize), uint64(c.KeyslotsSize)
	if m.jsonSize != hdrSize-binSize {
		return headerErr("config says the JSON area is %d bytes; the binary header says %d", m.jsonSize, hdrSize-binSize)
	}
	if m.keyslotsSize%areaAlign != 0 || m.keyslotsSize > maxKeyslots {
		return headerErr("a keyslot area of %d bytes", m.keyslotsSize)
	}
	// Requirements are features a reader must have to touch the device.
	// cryptsetup writes {"mandatory": [...]}; the specification says an
	// array. Either way, this package has none of them.
	if len(c.Requirements) > 0 && string(c.Requirements) != "null" {
		var list []string
		var obj struct {
			Mandatory []string `json:"mandatory"`
		}
		switch {
		case json.Unmarshal(c.Requirements, &list) == nil:
		case json.Unmarshal(c.Requirements, &obj) == nil:
			list = obj.Mandatory
		default:
			return headerErr("config.requirements is neither a list nor {\"mandatory\": [...]}")
		}
		m.requirements = list
	}
	return nil
}

func parseKeyslot(id int, raw json.RawMessage) (*keyslot, error) {
	what := fmt.Sprintf("keyslot %d", id)
	if _, err := members(raw, what, "type", "key_size", "area"); err != nil {
		return nil, err
	}
	var j keyslotJSON
	if err := strict(raw, &j, what); err != nil {
		return nil, err
	}
	ks := &keyslot{Type: j.Type, KeySize: int(j.KeySize), Area: *j.Area, Priority: 1, raw: raw}
	if j.Priority != nil {
		if *j.Priority > 2 {
			return nil, headerErr("%s has priority %d", what, *j.Priority)
		}
		ks.Priority = int(*j.Priority)
	}
	if ks.Area.Type == "" || ks.Area.Size == 0 {
		return nil, headerErr("%s has no area", what)
	}
	if ks.Type != "luks2" {
		return ks, nil // kept, and its area respected, but never opened
	}
	if j.AF == nil || j.KDF == nil {
		return nil, headerErr("%s has no af or kdf", what)
	}
	ks.AF, ks.KDF = *j.AF, *j.KDF
	if ks.KeySize < 1 || ks.KeySize > maxKeySize {
		return nil, headerErr("%s holds a %d-byte key", what, ks.KeySize)
	}
	if ks.AF.Type != "luks1" || ks.AF.Stripes != afStripes {
		return nil, headerErr("%s: anti-forensic splitter %q with %d stripes (only luks1 with 4000 exists)", what, ks.AF.Type, ks.AF.Stripes)
	}
	if ks.Area.Type != "raw" {
		return nil, headerErr("%s: area type %q", what, ks.Area.Type)
	}
	if need := afSize(ks.KeySize); uint64(ks.Area.Size) < need {
		return nil, headerErr("%s: a %d-byte area cannot hold %d bytes of key material", what, ks.Area.Size, need)
	}
	if ks.Area.KeySize < 1 || ks.Area.KeySize > 128 || !cipherName(ks.Area.Encryption) {
		return nil, headerErr("%s: area encryption %q with a %d-byte key", what, ks.Area.Encryption, ks.Area.KeySize)
	}
	// Costs beyond the bounds make the header hostile; a KDF or hash this
	// package lacks only makes the keyslot one it cannot open.
	if err := kdfFromJSON(ks.KDF).check(false); err != nil && !errors.Is(err, ErrUnsupported) {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if len(ks.KDF.Salt) < minSalt || len(ks.KDF.Salt) > maxSalt {
		return nil, headerErr("%s has a %d-byte salt", what, len(ks.KDF.Salt))
	}
	return ks, nil
}

func parseSegment(id int, raw json.RawMessage) (*segment, error) {
	what := fmt.Sprintf("segment %d", id)
	obj, err := members(raw, what, "type", "offset", "size")
	if err != nil {
		return nil, err
	}
	var j segmentJSON
	if err := strict(raw, &j, what); err != nil {
		return nil, err
	}
	s := &segment{Type: j.Type, Offset: uint64(j.Offset), raw: raw}
	if j.Size != "dynamic" {
		if s.Size, err = parseU64(j.Size); err != nil || s.Size == 0 {
			return nil, headerErr("%s has size %q", what, j.Size)
		}
	}
	// Offsets and sizes become int64 file positions: bounded here, so no
	// sum of them can wrap round to before the header.
	if s.Offset > maxDataBytes || s.Size > maxDataBytes {
		return nil, headerErr("%s at %d, %d bytes, is beyond any device", what, s.Offset, s.Size)
	}
	if s.Type != "crypt" {
		return s, nil
	}
	if _, err := members(raw, what, "iv_tweak", "encryption", "sector_size"); err != nil {
		return nil, err
	}
	s.IVTweak, s.Encryption, s.SectorSize = uint64(j.IVTweak), j.Encryption, int(j.SectorSize)
	switch s.SectorSize {
	case 512, 1024, 2048, 4096:
	default:
		return nil, headerErr("%s has %d-byte sectors", what, s.SectorSize)
	}
	if !cipherName(s.Encryption) {
		return nil, headerErr("%s: encryption %q", what, s.Encryption)
	}
	if s.Offset%uint64(s.SectorSize) != 0 || s.Size%uint64(s.SectorSize) != 0 {
		return nil, headerErr("%s is not aligned to its %d-byte sectors", what, s.SectorSize)
	}
	if _, ok := obj["integrity"]; ok && string(obj["integrity"]) != "null" {
		return nil, unsupported("%s is integrity-protected (dm-integrity), which secretvault does not do", what)
	}
	for _, f := range j.Flags {
		if f == "in-reencryption" || strings.HasPrefix(f, "backup-") {
			return nil, unsupported("%s is being re-encrypted; finish that with cryptsetup first", what)
		}
	}
	return s, nil
}

func parseDigest(id int, raw json.RawMessage) (*digest, error) {
	what := fmt.Sprintf("digest %d", id)
	if _, err := members(raw, what, "type", "keyslots", "segments"); err != nil {
		return nil, err
	}
	var j digestJSON
	if err := strict(raw, &j, what); err != nil {
		return nil, err
	}
	d := &digest{Type: j.Type, Hash: j.Hash, Iterations: j.Iterations, Salt: j.Salt, Digest: j.Digest, raw: raw}
	for _, s := range j.Keyslots {
		n, err := parseID(s, maxObjects)
		if err != nil || slices.Contains(d.Keyslots, n) {
			return nil, headerErr("%s names keyslot %q", what, s)
		}
		d.Keyslots = append(d.Keyslots, n)
	}
	for _, s := range j.Segments {
		n, err := parseID(s, maxObjects)
		if err != nil || slices.Contains(d.Segments, n) {
			return nil, headerErr("%s names segment %q", what, s)
		}
		d.Segments = append(d.Segments, n)
	}
	if d.Type != "pbkdf2" {
		return nil, unsupported("%s is of type %q", what, d.Type)
	}
	h, err := hashNamed(d.Hash)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", what, err)
	}
	if len(d.Salt) < minSalt || len(d.Salt) > maxSalt || len(d.Digest) < 16 || len(d.Digest) > 64 {
		return nil, headerErr("%s: a %d-byte salt and a %d-byte digest", what, len(d.Salt), len(d.Digest))
	}
	// The work is the iterations times the hash blocks the digest takes.
	blocks := uint64((len(d.Digest) + h().Size() - 1) / h().Size())
	if d.Iterations < 1 || uint64(d.Iterations)*blocks > maxDigestIterations {
		return nil, headerErr("%s: %d iterations for a %d-byte digest", what, d.Iterations, len(d.Digest))
	}
	return d, nil
}

// cipherName accepts a dm-crypt cipher specification's text, whether or
// not this package implements it.
func cipherName(s string) bool {
	if s == "" || len(s) > maxCipherLen {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-_:()", c)) {
			return false
		}
	}
	return true
}

// metaEnd is where the header copies and the keyslot area end.
func (m *metadata) metaEnd(hdrSize uint64) uint64 { return 2*hdrSize + m.keyslotsSize }

// check enforces what the objects mean together: every keyslot area inside
// the keyslot area and apart from the others, one data segment after it,
// and digests, keyslots and tokens that name each other.
func (m *metadata) check(hdrSize uint64) error {
	start, end := 2*hdrSize, m.metaEnd(hdrSize)
	type span struct {
		id       int
		off, len uint64
	}
	var spans []span
	for id, ks := range m.keyslots {
		off, n := uint64(ks.Area.Offset), uint64(ks.Area.Size)
		if off < start || n > end || off > end-n {
			return headerErr("keyslot %d's area [%d, +%d) is outside the keyslot area [%d, %d)", id, off, n, start, end)
		}
		spans = append(spans, span{id, off, n})
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].off < spans[j].off })
	for i := 1; i < len(spans); i++ {
		if spans[i-1].off+spans[i-1].len > spans[i].off {
			return headerErr("the areas of keyslots %d and %d overlap", spans[i-1].id, spans[i].id)
		}
	}

	if len(m.segments) == 0 {
		return headerErr("no data segment")
	}
	if len(m.segments) > 1 {
		return unsupported("%d data segments (a re-encryption in progress?)", len(m.segments))
	}
	for id, s := range m.segments {
		if s.Type != "crypt" {
			return unsupported("segment %d is of type %q", id, s.Type)
		}
		if s.Offset < end {
			return headerErr("segment %d starts at %d, inside the header (which ends at %d); detached headers are not supported", id, s.Offset, end)
		}
	}

	inDigest := map[int]int{}
	segDigest := map[int]bool{}
	for id, d := range m.digests {
		for _, k := range d.Keyslots {
			if _, ok := m.keyslots[k]; !ok {
				return headerErr("digest %d names keyslot %d, which does not exist", id, k)
			}
			if _, dup := inDigest[k]; dup {
				return headerErr("keyslot %d has two digests", k)
			}
			inDigest[k] = id
		}
		for _, s := range d.Segments {
			if _, ok := m.segments[s]; !ok {
				return headerErr("digest %d names segment %d, which does not exist", id, s)
			}
			if segDigest[s] {
				return headerErr("segment %d has two digests", s)
			}
			segDigest[s] = true
		}
	}
	for id, ks := range m.keyslots {
		if _, ok := inDigest[id]; !ok && ks.Type == "luks2" {
			return headerErr("keyslot %d has no digest", id)
		}
	}
	for id, raw := range m.tokens {
		what := fmt.Sprintf("token %d", id)
		if _, err := members(raw, what, "type", "keyslots"); err != nil {
			return err
		}
		var t struct {
			Type     string   `json:"type"`
			Keyslots []string `json:"keyslots"`
		}
		if err := strict(raw, &t, what); err != nil {
			return err
		}
		for _, s := range t.Keyslots {
			k, err := parseID(s, maxObjects)
			if err != nil {
				return headerErr("%s: %v", what, err)
			}
			if _, ok := m.keyslots[k]; !ok {
				return headerErr("%s names keyslot %d, which does not exist", what, k)
			}
		}
	}
	return nil
}

// dataSegment is the one data segment, and its digest.
func (m *metadata) dataSegment() (int, *segment, *digest) {
	for id, s := range m.segments {
		for _, d := range m.digests {
			if slices.Contains(d.Segments, id) {
				return id, s, d
			}
		}
		return id, s, nil
	}
	return -1, nil, nil
}

// digestOf is the digest a keyslot is checked with.
func (m *metadata) digestOf(slot int) *digest {
	for _, d := range m.digests {
		if slices.Contains(d.Keyslots, slot) {
			return d
		}
	}
	return nil
}

// encodeJSON is json.Marshal without HTML escaping (cryptsetup would read
// < fine; this keeps what was read byte for byte where it can).
func encodeJSON(v any) (json.RawMessage, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n")), nil
}

// setMember rewrites one member of an object's text, keeping the rest.
func setMember(raw json.RawMessage, name string, v any) (json.RawMessage, error) {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, err
	}
	b, err := encodeJSON(v)
	if err != nil {
		return nil, err
	}
	obj[name] = b
	return encodeJSON(obj)
}

func idStrings(ids []int) []string {
	out := []string{}
	for _, id := range ids {
		out = append(out, strconv.Itoa(id))
	}
	return out
}

// marshal writes the metadata as JSON text: the five objects in
// cryptsetup's order, then anything else that was there.
func (m *metadata) marshal() ([]byte, error) {
	var b bytes.Buffer
	b.WriteString(`{"keyslots":`)
	writeNumbered(&b, func(yield func(int, json.RawMessage)) {
		for id, ks := range m.keyslots {
			yield(id, ks.raw)
		}
	})
	b.WriteString(`,"tokens":`)
	writeNumbered(&b, func(yield func(int, json.RawMessage)) {
		for id, raw := range m.tokens {
			yield(id, raw)
		}
	})
	b.WriteString(`,"segments":`)
	writeNumbered(&b, func(yield func(int, json.RawMessage)) {
		for id, s := range m.segments {
			yield(id, s.raw)
		}
	})
	b.WriteString(`,"digests":`)
	writeNumbered(&b, func(yield func(int, json.RawMessage)) {
		for id, d := range m.digests {
			yield(id, d.raw)
		}
	})
	b.WriteString(`,"config":`)
	b.Write(m.config)
	names := make([]string, 0, len(m.extra))
	for name := range m.extra {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		k, _ := encodeJSON(name)
		b.WriteByte(',')
		b.Write(k)
		b.WriteByte(':')
		b.Write(m.extra[name])
	}
	b.WriteByte('}')
	// Compact whatever was read with whitespace, and prove the result
	// parses before it goes near a disk.
	var out bytes.Buffer
	if err := json.Compact(&out, b.Bytes()); err != nil {
		return nil, fmt.Errorf("svluks: writing the metadata: %w", err)
	}
	return out.Bytes(), nil
}

// writeNumbered writes {"0": ..., "1": ...} in numeric order.
func writeNumbered(b *bytes.Buffer, each func(yield func(int, json.RawMessage))) {
	type entry struct {
		id  int
		raw json.RawMessage
	}
	var all []entry
	each(func(id int, raw json.RawMessage) { all = append(all, entry{id, raw}) })
	sort.Slice(all, func(i, j int) bool { return all[i].id < all[j].id })
	b.WriteByte('{')
	for i, e := range all {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(b, "%q:", strconv.Itoa(e.id))
		b.Write(e.raw)
	}
	b.WriteByte('}')
}
