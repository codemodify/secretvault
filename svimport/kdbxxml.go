package svimport

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// The XML inside a KDBX file: KeePassFile → Meta (the recycle bin's
// group) and Root → Group → Entry and Group, recursively. An entry is a
// list of String key/value pairs (Title, UserName, Password, URL, Notes
// and custom ones, Protected="True" for concealed ones), Binary
// references (attachments), Tags, CustomData and a History of older
// versions. Groups become folders below the root group; the recycle bin is
// skipped.
//
// OTP keys are read from KeePassXC's "otp" string (an otpauth URI, or
// KeeOTP's key=...), its older "TOTP Seed" and "TOTP Settings" pair, and
// KeePass 2.47's own TimeOtp-* and HmacOtp-* strings. Keepass2Android's
// extra URLs (KP2A_URL, KP2A_URL_1...) become url2, url3...

// xnode is one element of the parsed document. Protected values are held
// decrypted, as bytes.
type xnode struct {
	name      string
	protected bool
	attrs     []xml.Attr
	text      []byte
	kids      []*xnode
}

func (n *xnode) child(name string) *xnode {
	if n == nil {
		return nil
	}
	for _, k := range n.kids {
		if k.name == name {
			return k
		}
	}
	return nil
}

func (n *xnode) children() []*xnode {
	if n == nil {
		return nil
	}
	return n.kids
}

func (n *xnode) value(name string) string {
	if c := n.child(name); c != nil {
		return strings.TrimSpace(string(c.text))
	}
	return ""
}

func (n *xnode) attr(name string) string {
	for _, a := range n.attrs {
		if a.Name.Local == name {
			return a.Value
		}
	}
	return ""
}

func (n *xnode) wipe() {
	clear(n.text)
	for _, k := range n.kids {
		k.wipe()
	}
}

// parseKDBXXML parses the document, decrypting protected values with the
// inner stream as they come, in document order.
func parseKDBXXML(data []byte, stream innerStream) (*xnode, error) {
	dec := xml.NewDecoder(bytes.NewReader(data))
	var root *xnode
	var stack []*xnode
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			if root != nil {
				root.wipe()
			}
			// Not err itself: its message can quote the document.
			line := 0
			var se *xml.SyntaxError
			if errors.As(err, &se) {
				line = se.Line
			}
			return nil, fmt.Errorf("%w: the KDBX XML is malformed (line %d)", ErrFormat, line)
		}
		switch t := tok.(type) {
		case xml.StartElement:
			n := &xnode{name: t.Name.Local, attrs: t.Attr}
			if len(stack) == 0 {
				if root != nil {
					return nil, fmt.Errorf("%w: KDBX XML has two roots", ErrFormat)
				}
				root = n
			} else {
				p := stack[len(stack)-1]
				p.kids = append(p.kids, n)
			}
			stack = append(stack, n)
		case xml.CharData:
			if len(stack) > 0 {
				n := stack[len(stack)-1]
				n.text = append(n.text, t...)
			}
		case xml.EndElement:
			n := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if strings.EqualFold(n.attr("Protected"), "True") {
				ct, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(n.text)))
				if err != nil {
					root.wipe()
					return nil, fmt.Errorf("%w: a protected KDBX value is not base64", ErrFormat)
				}
				stream.XORKeyStream(ct, ct)
				n.text, n.protected = ct, true
			}
		}
	}
	if root == nil || root.name != "KeePassFile" {
		return nil, fmt.Errorf("%w: not a KeePass XML document", ErrFormat)
	}
	return root, nil
}

// kdbxRead turns the document into items.
func kdbxRead(b *builder, h *kdbxHeader, data []byte, stream innerStream) error {
	doc, err := parseKDBXXML(data, stream)
	if err != nil {
		return err
	}
	defer doc.wipe()
	meta := doc.child("Meta")
	if hh := meta.value("HeaderHash"); h.major == 3 && hh != "" {
		sum := sha256.Sum256(h.raw)
		if hh != base64.StdEncoding.EncodeToString(sum[:]) {
			return fmt.Errorf("%w: the KDBX header does not match its hash: the file is damaged", ErrFormat)
		}
	}
	top := doc.child("Root").child("Group")
	if top == nil {
		return fmt.Errorf("%w: the KDBX file has no root group", ErrFormat)
	}
	recycle := meta.value("RecycleBinUUID")
	if recycle == "AAAAAAAAAAAAAAAAAAAAAA==" {
		recycle = ""
	}
	pool := h.binaries
	if h.major < 4 {
		if pool, err = kdbx3Binaries(meta); err != nil {
			return err
		}
	}
	defer func() {
		for _, bin := range pool {
			clear(bin)
		}
	}()
	var walk func(g *xnode, path []string)
	walk = func(g *xnode, path []string) {
		for _, k := range g.kids {
			switch k.name {
			case "Entry":
				b.add(kdbxDraft(k, path, pool))
			case "Group":
				if recycle != "" && k.value("UUID") == recycle {
					b.trashed += countEntries(k)
					continue
				}
				walk(k, append(append([]string(nil), path...), k.value("Name")))
			}
		}
	}
	walk(top, nil)
	return nil
}

// kdbx3Binaries reads KDBX 3.1's attachments, kept in Meta/Binaries: each
// with an ID, base64, gzipped when Compressed="True", and encrypted with
// the inner stream when Protected="True" (decoded already by then).
func kdbx3Binaries(meta *xnode) ([][]byte, error) {
	var pool [][]byte
	for _, bn := range meta.child("Binaries").children() {
		if bn.name != "Binary" {
			continue
		}
		id, err := strconv.Atoi(bn.attr("ID"))
		if err != nil || id < 0 || id > 1<<16 {
			return nil, fmt.Errorf("%w: a KDBX attachment has no usable ID", ErrFormat)
		}
		data := bn.text
		if !bn.protected {
			if data, err = base64.StdEncoding.DecodeString(strings.TrimSpace(string(bn.text))); err != nil {
				return nil, fmt.Errorf("%w: a KDBX attachment is not base64", ErrFormat)
			}
		} else {
			data = append([]byte(nil), data...)
		}
		if strings.EqualFold(bn.attr("Compressed"), "True") {
			z, err := gunzip(data)
			clear(data)
			if err != nil {
				return nil, err
			}
			data = z
		}
		for len(pool) <= id {
			pool = append(pool, nil)
		}
		pool[id] = data
	}
	return pool, nil
}

func countEntries(g *xnode) int {
	n := 0
	for _, k := range g.kids {
		switch k.name {
		case "Entry":
			n++
		case "Group":
			n += countEntries(k)
		}
	}
	return n
}

// kdbxString is one String of an entry.
type kdbxString struct {
	key       string
	value     []byte
	protected bool
}

// kdbxMeta is what ExportKDBX keeps about an item that KDBX has no place
// for, in the entry's CustomData under "secretvault".
type kdbxMeta struct {
	Kind   string            `json:"kind,omitempty"`
	Label  string            `json:"label,omitempty"`
	Attrs  map[string]string `json:"attrs,omitempty"`
	Fields []kdbxMetaField   `json:"fields,omitempty"`
}

// kdbxMetaField is one field: its name and type, and the key of the
// string holding it when that is not the name.
type kdbxMetaField struct {
	Name string `json:"n"`
	Type string `json:"t"`
	Key  string `json:"k,omitempty"`
}

const kdbxMetaKey = "secretvault"

// kdbxStandard maps KeePass's standard strings to field names.
var kdbxStandard = map[string]struct{ name, typ string }{
	"UserName": {fUsername, svcore.FieldText},
	"Password": {fPassword, svcore.FieldConcealed},
	"URL":      {fURL, svcore.FieldURL},
	"Notes":    {fNotes, svcore.FieldText},
}

func kdbxDraft(e *xnode, path []string, pool [][]byte) *draft {
	var strs []kdbxString
	find := func(key string) (kdbxString, bool) {
		for _, s := range strs {
			if s.key == key {
				return s, true
			}
		}
		return kdbxString{}, false
	}
	d := &draft{folder: path}
	for _, k := range e.kids {
		switch k.name {
		case "String":
			v := k.child("Value")
			s := kdbxString{key: k.value("Key")}
			if v != nil {
				s.value, s.protected = v.text, v.protected
			}
			strs = append(strs, s)
		case "Binary":
			ref, err := strconv.Atoi(k.child("Value").attr("Ref"))
			name := k.value("Key")
			if err != nil || ref < 0 || ref >= len(pool) || pool[ref] == nil || name == "" {
				d.attachments++
				continue
			}
			d.files = append(d.files, File{Name: name, Data: append([]byte(nil), pool[ref]...)})
		case "History":
			d.history = d.history || len(k.kids) > 0
		case "Tags":
			d.tags = strings.FieldsFunc(string(k.text), func(r rune) bool { return r == ';' || r == ',' })
		}
	}
	var meta *kdbxMeta
	for _, it := range e.child("CustomData").children() {
		if it.value("Key") == kdbxMetaKey {
			var m kdbxMeta
			if json.Unmarshal([]byte(it.value("Value")), &m) == nil {
				meta = &m
			}
		}
	}
	title, _ := find("Title")
	user, _ := find("UserName")
	d.title = string(title.value)
	for _, key := range []string{"UserName", "Password", "URL"} {
		if s, ok := find(key); ok {
			std := kdbxStandard[key]
			if key == "URL" {
				d.url(string(s.value))
			} else {
				d.setBytes(std.name, std.typ, bytes.Clone(s.value))
			}
		}
	}
	for _, s := range strs {
		if strings.HasPrefix(s.key, "KP2A_URL") {
			d.url(string(s.value))
		}
	}
	kdbxOTP(d, strs, d.title, string(user.value))
	if s, ok := find("Notes"); ok {
		d.setBytes(fNotes, svcore.FieldText, bytes.Clone(s.value))
	}
	for _, s := range strs {
		switch {
		case s.key == "Title" || kdbxStandard[s.key].name != "" || strings.HasPrefix(s.key, "KP2A_URL") || kdbxOTPKeys[s.key]:
		case strings.HasPrefix(s.key, "KPEX_PASSKEY_"):
			d.passkeys = 1
		case s.protected:
			d.setBytes(s.key, svcore.FieldConcealed, bytes.Clone(s.value))
		default:
			d.setBytes(s.key, svcore.FieldText, bytes.Clone(s.value))
		}
	}
	if meta != nil {
		kdbxApplyMeta(d, meta)
	}
	return d
}

// kdbxApplyMeta restores what ExportKDBX kept: kind, label, attributes,
// and each field's type and place.
func kdbxApplyMeta(d *draft, m *kdbxMeta) {
	d.kind, d.label, d.attrs = m.Kind, m.Label, m.Attrs
	if len(m.Fields) == 0 {
		return
	}
	var ordered []int
	placed := map[int]bool{}
	for _, mf := range m.Fields {
		key := mf.Key
		if key == "" {
			key = mf.Name
		}
		for i, f := range d.fields {
			if f.Name == key && !placed[i] {
				d.fields[i].Name, d.fields[i].Type = mf.Name, mf.Type
				ordered = append(ordered, i)
				placed[i] = true
				break
			}
		}
	}
	out := make([]svrpc.Field, 0, len(d.fields))
	for _, i := range ordered {
		out = append(out, d.fields[i])
	}
	for i, f := range d.fields {
		if !placed[i] {
			out = append(out, f)
		}
	}
	d.fields = out
}

// kdbxOTPKeys are the strings OTP keys are read from.
var kdbxOTPKeys = map[string]bool{
	"otp": true, "TOTP Seed": true, "TOTP Settings": true,
	"TimeOtp-Secret": true, "TimeOtp-Secret-Hex": true, "TimeOtp-Secret-Base32": true, "TimeOtp-Secret-Base64": true,
	"TimeOtp-Length": true, "TimeOtp-Period": true, "TimeOtp-Algorithm": true,
	"HmacOtp-Secret": true, "HmacOtp-Secret-Hex": true, "HmacOtp-Secret-Base32": true, "HmacOtp-Secret-Base64": true,
	"HmacOtp-Counter": true,
}

// kdbxOTP reads an entry's OTP key, in whichever of the ways KeePass
// programs store it.
func kdbxOTP(d *draft, strs []kdbxString, title, user string) {
	get := func(key string) string {
		for _, s := range strs {
			if s.key == key {
				return strings.TrimSpace(string(s.value))
			}
		}
		return ""
	}
	if v := get("otp"); v != "" {
		d.otp(v, title, user)
		return
	}
	if seed := get("TOTP Seed"); seed != "" {
		q := "key=" + seed
		if step, digits, ok := strings.Cut(get("TOTP Settings"), ";"); ok {
			if digits == "S" {
				d.otp("steam://"+seed, title, user)
				return
			}
			q += "&step=" + step + "&size=" + digits
		}
		d.otp(q, title, user)
		return
	}
	for _, kind := range []string{"TimeOtp", "HmacOtp"} {
		secret := kdbxOTPSecret(get, kind)
		if secret == "" {
			continue
		}
		q := "key=" + secret
		if kind == "HmacOtp" {
			q += "&type=hotp&counter=" + get("HmacOtp-Counter")
		} else {
			if v := get("TimeOtp-Length"); v != "" {
				q += "&size=" + v
			}
			if v := get("TimeOtp-Period"); v != "" {
				q += "&step=" + v
			}
			if v := get("TimeOtp-Algorithm"); v != "" {
				q += "&otpHashMode=" + v
			}
		}
		d.otp(q, title, user)
		return
	}
}

// kdbxOTPSecret reads KeePass's TimeOtp-Secret* or HmacOtp-Secret*, in
// whichever encoding is present, as base32.
func kdbxOTPSecret(get func(string) string, kind string) string {
	if v := get(kind + "-Secret-Base32"); v != "" {
		return strings.ReplaceAll(v, " ", "")
	}
	var raw []byte
	if v := get(kind + "-Secret"); v != "" {
		raw = []byte(v)
	} else if v := get(kind + "-Secret-Hex"); v != "" {
		raw, _ = hex.DecodeString(strings.Join(strings.Fields(v), ""))
	} else if v := get(kind + "-Secret-Base64"); v != "" {
		raw, _ = base64.StdEncoding.DecodeString(v)
	}
	if len(raw) == 0 {
		return ""
	}
	defer clear(raw)
	return base32NoPad(raw)
}
