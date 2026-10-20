package svimport

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/twofish"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svrpc"
)

// ExportKDBX writes items as a KDBX 4.0 file that KeePass and KeePassXC
// open with the passphrase: AES-256-CBC, Argon2id at svcrypto's default
// cost, gzip, and ChaCha20 for protected values. Folders become groups,
// an item's last name segment its title; username, password, url and
// notes fill KeePass's standard fields, an "otp" field KeePassXC's otp
// string, and every other field a custom string, protected when it is
// concealed. What KDBX has no place for (the kind, the label, attributes,
// field types and order) is kept in the entry's CustomData, so a round
// trip through ExportKDBX and Import gives the same items back.
func ExportKDBX(items []svrpc.Item, w io.Writer, passphrase []byte) error {
	if len(passphrase) == 0 {
		return errors.New("svimport: a KDBX export needs a passphrase")
	}
	a := svcrypto.DefaultArgon2
	return writeKDBX(items, w, passphrase, nil, kdbxParams{
		major: 4, cipher: kdbxAES, kdf: kdfArgon2id,
		time: a.Time, memKiB: a.MemoryKiB, threads: uint32(a.Threads), gzip: true, stream: streamChaCha20,
	})
}

// kdbxParams choose how writeKDBX writes. ExportKDBX uses one choice; the
// tests use the others, so the reader is exercised on every combination.
type kdbxParams struct {
	major                 uint16 // 3 or 4
	cipher                string
	kdf                   string // KDBX 4 only; 3.1 uses AES-KDF
	rounds                uint64 // AES-KDF
	time, memKiB, threads uint32 // Argon2
	gzip                  bool
	stream                uint32
}

func writeKDBX(items []svrpc.Item, w io.Writer, pass, keyfile []byte, p kdbxParams) error {
	composite, err := kdbxCompositeKey(pass, keyfile)
	if err != nil {
		return err
	}
	defer clear(composite)
	h := &kdbxHeader{major: p.major, minor: 0, cipher: p.cipher, gzip: p.gzip, masterSeed: random(32)}
	if p.major == 3 {
		h.minor = 1
	}
	if p.cipher == kdbxChaCha20 {
		h.iv = random(12)
	} else {
		h.iv = random(16)
	}
	var hdr bytes.Buffer
	hdr.Write(kdbxSignature)
	hdr.Write(binary.LittleEndian.AppendUint32(nil, uint32(h.major)<<16|uint32(h.minor)))
	field := func(id byte, v []byte) {
		hdr.WriteByte(id)
		if p.major >= 4 {
			hdr.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(v))))
		} else {
			hdr.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(v))))
		}
		hdr.Write(v)
	}
	compression := uint32(0)
	if p.gzip {
		compression = 1
	}
	field(hCipher, []byte(p.cipher))
	field(hCompression, binary.LittleEndian.AppendUint32(nil, compression))
	field(hMasterSeed, h.masterSeed)
	var streamKey []byte
	if p.major == 3 {
		h.transformSeed, h.rounds, h.streamStart, h.streamID = random(32), p.rounds, random(32), p.stream
		streamKey = random(32)
		field(hTransformSeed, h.transformSeed)
		field(hTransformRounds, binary.LittleEndian.AppendUint64(nil, p.rounds))
		field(hIV, h.iv)
		field(hStreamKey, streamKey)
		field(hStreamStart, h.streamStart)
		field(hStreamID, binary.LittleEndian.AppendUint32(nil, p.stream))
	} else {
		streamKey = random(64)
		field(hIV, h.iv)
		vd := kdbxKDFParams(p)
		if h.kdf, err = parseVariantDict(vd); err != nil {
			return err
		}
		field(hKDF, vd)
	}
	defer clear(streamKey)
	field(hEnd, []byte("\r\n\r\n"))
	h.raw = hdr.Bytes()

	transformed, err := h.transformKey(composite)
	if err != nil {
		return err
	}
	defer clear(transformed)
	stream, err := newInnerStream(p.stream, streamKey)
	if err != nil {
		return err
	}
	var headerHash []byte
	if p.major == 3 {
		sum := sha256.Sum256(h.raw)
		headerHash = sum[:]
	}
	doc := kdbxXML(items, stream, p.major, headerHash)
	defer clear(doc)

	key := h.cipherKey(transformed)
	defer clear(key)
	out := bytes.NewBuffer(append([]byte(nil), h.raw...))
	if p.major == 3 {
		body := doc
		if p.gzip {
			body = gzipBytes(doc)
			defer clear(body)
		}
		plain := append(append([]byte(nil), h.streamStart...), hashedBlocks(body)...)
		defer clear(plain)
		ct, err := h.encrypt(key, plain)
		if err != nil {
			return err
		}
		out.Write(ct)
	} else {
		var inner bytes.Buffer
		innerField := func(t byte, v []byte) {
			inner.WriteByte(t)
			inner.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(v))))
			inner.Write(v)
		}
		innerField(1, binary.LittleEndian.AppendUint32(nil, p.stream))
		innerField(2, streamKey)
		innerField(0, nil)
		inner.Write(doc)
		plain := inner.Bytes()
		defer clear(plain)
		if p.gzip {
			plain = gzipBytes(plain)
			defer clear(plain)
		}
		ct, err := h.encrypt(key, plain)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(h.raw)
		out.Write(sum[:])
		hmacKey := kdbxHMACKey(h.masterSeed, transformed)
		defer clear(hmacKey)
		out.Write(kdbxBlockMAC(hmacKey, ^uint64(0), h.raw, false))
		out.Write(hmacBlocks(ct, hmacKey))
	}
	_, err = w.Write(out.Bytes())
	return err
}

// kdbxKDFParams writes the KDF's variant dictionary.
func kdbxKDFParams(p kdbxParams) []byte {
	b := binary.LittleEndian.AppendUint16(nil, 0x0100)
	put := func(typ byte, k string, v []byte) {
		b = append(b, typ)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(k)))
		b = append(b, k...)
		b = binary.LittleEndian.AppendUint32(b, uint32(len(v)))
		b = append(b, v...)
	}
	put(vdBytes, "$UUID", []byte(p.kdf))
	if p.kdf == kdfAES3 || p.kdf == kdfAES4 {
		put(vdUint64, "R", binary.LittleEndian.AppendUint64(nil, p.rounds))
		put(vdBytes, "S", random(32))
	} else {
		put(vdBytes, "S", random(32))
		put(vdUint32, "P", binary.LittleEndian.AppendUint32(nil, p.threads))
		put(vdUint64, "M", binary.LittleEndian.AppendUint64(nil, uint64(p.memKiB)*1024))
		put(vdUint64, "I", binary.LittleEndian.AppendUint64(nil, uint64(p.time)))
		put(vdUint32, "V", binary.LittleEndian.AppendUint32(nil, 0x13))
	}
	return append(b, 0)
}

// encrypt applies the outer cipher.
func (h *kdbxHeader) encrypt(key, plain []byte) ([]byte, error) {
	if h.cipher == kdbxChaCha20 {
		c, err := chacha20.NewUnauthenticatedCipher(key, h.iv)
		if err != nil {
			return nil, err
		}
		out := make([]byte, len(plain))
		c.XORKeyStream(out, plain)
		return out, nil
	}
	var blk cipher.Block
	var err error
	if h.cipher == kdbxTwofish {
		blk, err = twofish.NewCipher(key)
	} else {
		blk, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, err
	}
	n := blk.BlockSize() - len(plain)%blk.BlockSize()
	out := append(append([]byte(nil), plain...), bytes.Repeat([]byte{byte(n)}, n)...)
	cipher.NewCBCEncrypter(blk, h.iv).CryptBlocks(out, out)
	return out, nil
}

const kdbxBlockSize = 1 << 20

func hmacBlocks(ct, hmacKey []byte) []byte {
	var out []byte
	for i := uint64(0); ; i++ {
		n := min(len(ct), kdbxBlockSize)
		blk := ct[:n]
		out = append(out, kdbxBlockMAC(hmacKey, i, blk, true)...)
		out = binary.LittleEndian.AppendUint32(out, uint32(n))
		out = append(out, blk...)
		ct = ct[n:]
		if n == 0 {
			return out
		}
	}
}

func hashedBlocks(b []byte) []byte {
	var out []byte
	for i := uint32(0); ; i++ {
		n := min(len(b), kdbxBlockSize)
		out = binary.LittleEndian.AppendUint32(out, i)
		if n == 0 {
			out = append(out, make([]byte, 32)...)
		} else {
			sum := sha256.Sum256(b[:n])
			out = append(out, sum[:]...)
		}
		out = binary.LittleEndian.AppendUint32(out, uint32(n))
		out = append(out, b[:n]...)
		b = b[n:]
		if n == 0 {
			return out
		}
	}
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	z := gzip.NewWriter(&buf)
	z.Write(b)
	z.Close()
	return buf.Bytes()
}

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

// kdbxGroup is a folder being written.
type kdbxGroup struct {
	name    string
	groups  []*kdbxGroup
	entries []*svrpc.Item
}

func (g *kdbxGroup) sub(name string) *kdbxGroup {
	for _, s := range g.groups {
		if s.name == name {
			return s
		}
	}
	s := &kdbxGroup{name: name}
	g.groups = append(g.groups, s)
	return s
}

// kdbxXML writes the document, protecting values with the inner stream in
// the order they are written.
func kdbxXML(items []svrpc.Item, stream innerStream, major uint16, headerHash []byte) []byte {
	root := &kdbxGroup{name: "Root"}
	for i := range items {
		g := root
		if dir, _, ok := cutLast(items[i].Name, "/"); ok {
			for _, s := range strings.Split(dir, "/") {
				g = g.sub(s)
			}
		}
		g.entries = append(g.entries, &items[i])
	}
	x := &xmlOut{stream: stream, now: kdbxTime(time.Now(), major)}
	x.buf.WriteString(`<?xml version="1.0" encoding="utf-8" standalone="yes"?>` + "\n")
	x.open("KeePassFile")
	x.open("Meta")
	x.leaf("Generator", "secretvault")
	if headerHash != nil {
		x.leaf("HeaderHash", base64.StdEncoding.EncodeToString(headerHash))
	}
	x.leaf("DatabaseName", "secretvault export")
	x.leaf("RecycleBinEnabled", "False")
	x.close("Meta")
	x.open("Root")
	x.group(root)
	x.close("Root")
	x.close("KeePassFile")
	return x.buf.Bytes()
}

type xmlOut struct {
	buf    bytes.Buffer
	stream innerStream
	depth  int
	now    string
}

func (x *xmlOut) indent() { x.buf.WriteString(strings.Repeat("\t", x.depth)) }

func (x *xmlOut) open(name string) {
	x.indent()
	x.buf.WriteString("<" + name + ">\n")
	x.depth++
}

func (x *xmlOut) close(name string) {
	x.depth--
	x.indent()
	x.buf.WriteString("</" + name + ">\n")
}

func (x *xmlOut) leaf(name, text string) {
	x.indent()
	x.buf.WriteString("<" + name + ">")
	xml.EscapeText(&x.buf, []byte(text))
	x.buf.WriteString("</" + name + ">\n")
}

// str writes a String element. Values that are not valid XML text are
// always protected: protected values are base64, and carry any bytes.
func (x *xmlOut) str(key string, v []byte, protect bool) {
	x.open("String")
	x.leaf("Key", key)
	x.indent()
	if protect || !xmlSafe(v) {
		ct := make([]byte, len(v))
		x.stream.XORKeyStream(ct, v)
		x.buf.WriteString(`<Value Protected="True">` + base64.StdEncoding.EncodeToString(ct) + "</Value>\n")
	} else {
		x.buf.WriteString("<Value>")
		xml.EscapeText(&x.buf, v)
		x.buf.WriteString("</Value>\n")
	}
	x.close("String")
}

func (x *xmlOut) times() {
	x.open("Times")
	for _, t := range []string{"CreationTime", "LastModificationTime", "LastAccessTime", "ExpiryTime"} {
		x.leaf(t, x.now)
	}
	x.leaf("Expires", "False")
	x.leaf("UsageCount", "0")
	x.leaf("LocationChanged", x.now)
	x.close("Times")
}

func (x *xmlOut) group(g *kdbxGroup) {
	x.open("Group")
	x.leaf("UUID", base64.StdEncoding.EncodeToString(random(16)))
	x.leaf("Name", g.name)
	x.times()
	x.leaf("IsExpanded", "True")
	for _, it := range g.entries {
		x.entry(it)
	}
	for _, s := range g.groups {
		x.group(s)
	}
	x.close("Group")
}

// kdbxStandardKey is the KeePass string a field fills, if any.
var kdbxStandardKey = map[string]string{fUsername: "UserName", fPassword: "Password", fURL: "URL", fNotes: "Notes"}

func (x *xmlOut) entry(it *svrpc.Item) {
	_, title, _ := cutLast(it.Name, "/")
	x.open("Entry")
	x.leaf("UUID", base64.StdEncoding.EncodeToString(random(16)))
	if len(it.Tags) > 0 {
		x.leaf("Tags", strings.Join(it.Tags, ";"))
	}
	x.times()
	meta := kdbxMeta{Name: it.Name, Kind: it.Kind, Attrs: it.Attrs}
	if it.Label != title {
		meta.Label = it.Label
	}
	std := map[string][]byte{}
	keys := make([]string, len(it.Fields))
	for i, f := range it.Fields {
		mf := kdbxMetaField{Name: f.Name, Type: f.Type}
		if k, ok := kdbxStandardKey[f.Name]; ok {
			std[k] = f.Value
		} else {
			// A custom string may not take a standard string's key.
			keys[i] = f.Name
			if f.Name == "Title" || f.Name == "UserName" || f.Name == "Password" || f.Name == "URL" || f.Name == "Notes" {
				keys[i] = f.Name + " (field)"
				mf.Key = keys[i]
			}
		}
		meta.Fields = append(meta.Fields, mf)
	}
	x.str("Title", []byte(title), false)
	for _, k := range []string{"UserName", "Password", "URL", "Notes"} {
		x.str(k, std[k], k == "Password")
	}
	for i, f := range it.Fields {
		if keys[i] == "" {
			continue
		}
		protect := f.Type == svcore.FieldConcealed || f.Type == svcore.FieldKey || f.Type == svcore.FieldOTP || f.Type == svcore.FieldBinary
		x.str(keys[i], f.Value, protect)
	}
	blob, _ := json.Marshal(meta)
	x.open("CustomData")
	x.open("Item")
	x.leaf("Key", kdbxMetaKey)
	x.leaf("Value", string(blob))
	x.close("Item")
	x.close("CustomData")
	x.close("Entry")
}

// xmlSafe reports text XML 1.0 can hold as it is.
func xmlSafe(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r < 0x20 && r != '\t' && r != '\n' && r != '\r' || r == 0xfffe || r == 0xffff {
			return false
		}
	}
	return true
}

// kdbxTime writes a time: KDBX 4 as base64 of little-endian seconds since
// 0001-01-01, KDBX 3.1 as xs:dateTime.
func kdbxTime(t time.Time, major uint16) string {
	if major < 4 {
		return t.UTC().Format(time.RFC3339)
	}
	const epoch = 62135596800 // seconds from 0001-01-01 to 1970-01-01
	return base64.StdEncoding.EncodeToString(binary.LittleEndian.AppendUint64(nil, uint64(t.Unix()+epoch)))
}
