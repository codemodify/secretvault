package svimport

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// Building items: every reader fills drafts, and the builder turns them
// into items with valid, unique names, collecting what was left behind.

// Field names used across formats. Custom fields keep the name the source
// gave them.
const (
	fUsername   = "username"
	fPassword   = "password"
	fURL        = "url"
	fOTP        = "otp"
	fNotes      = "notes"
	fEmail      = "email"
	fCardholder = "cardholder"
	fNumber     = "number"
	fExpiry     = "expiry" // MM/YYYY
	fCVV        = "cvv"
	fPIN        = "pin"
	fBrand      = "brand"
	fPrivateKey = "private_key"
	fPublicKey  = "public_key"
	fPassphrase = "passphrase"
)

// Item kinds, as svcore.Kinds names them.
const (
	kLogin    = "login"
	kPassword = "password"
	kNote     = "note"
	kCard     = "card"
	kIdentity = "identity"
	kSSHKey   = "ssh-key"
	kAPIKey   = "api-key"
	kOTP      = "otp"
	kGeneric  = "generic"
)

// maxName leaves room under svcore's 1024-byte limit for a " (N)" suffix.
const maxName = 1000

// A draft is one item as a reader found it.
type draft struct {
	kind   string   // "" to infer: login, note or generic
	folder []string // path segments, not yet cleaned
	title  string
	label  string // overrides title as the item's label (KDBX round trips)
	tags   []string
	attrs  map[string]string
	fields []svrpc.Field
	urls   int

	// Attached files, brought across.
	files []File

	// What could not be brought across, for warnings.
	attachments int
	passkeys    int
	history     bool
	lost        []string // described without secrets
}

// set adds a field unless its value is blank; the name is made unique.
func (d *draft) set(name, typ, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	d.setBytes(name, typ, []byte(value))
}

// setBytes adds a field unless its value is empty.
func (d *draft) setBytes(name, typ string, v []byte) {
	if len(v) == 0 {
		return
	}
	d.fields = append(d.fields, svrpc.Field{Name: d.freeName(name), Type: typ, Value: v})
}

// has reports whether the draft has a field of that name.
func (d *draft) has(name string) bool {
	for _, f := range d.fields {
		if f.Name == name {
			return true
		}
	}
	return false
}

// freeName is name, or name with " (2)", " (3)"... if it is taken.
func (d *draft) freeName(name string) string {
	name = strings.TrimSpace(strings.ToValidUTF8(name, "?"))
	if name == "" {
		name = "field"
	}
	base := name
	for n := 2; d.has(name); n++ {
		name = fmt.Sprintf("%s (%d)", base, n)
	}
	return name
}

// url adds a URL: the first is "url", then "url2", "url3"...
func (d *draft) url(u string) {
	u = strings.TrimSpace(u)
	if u == "" {
		return
	}
	for _, f := range d.fields {
		if f.Type == svcore.FieldURL && string(f.Value) == u {
			return
		}
	}
	d.urls++
	name := fURL
	if d.urls > 1 {
		name = fmt.Sprintf("url%d", d.urls)
	}
	d.set(name, svcore.FieldURL, u)
}

// otp adds an OTP key, stored as an otpauth URI. A key that cannot be read
// is kept as a concealed field, and said so.
func (d *draft) otp(value, issuer, account string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	uri, err := otpURI(value, issuer, account)
	if err != nil {
		d.set(fOTP, svcore.FieldConcealed, value)
		d.lost = append(d.lost, "an OTP key in a form secretvault does not know, kept as a concealed field")
		return
	}
	d.set(fOTP, svcore.FieldOTP, uri)
}

// notes adds the notes field.
func (d *draft) notes(s string) { d.set(fNotes, svcore.FieldText, s) }

// inferKind is the kind of a draft whose reader did not say.
func (d *draft) inferKind() string {
	login, notes := false, false
	for _, f := range d.fields {
		switch f.Name {
		case fUsername, fPassword, fURL, fOTP:
			login = true
		case fNotes:
			notes = true
		}
	}
	switch {
	case login:
		return kLogin
	case notes && len(d.fields) == 1:
		return kNote
	}
	return kGeneric
}

// builder collects items and warnings for one import.
type builder struct {
	prefix  []string
	items   []svrpc.Item
	used    map[string]bool
	warns   []string
	history []string // items whose older versions were left behind
	trashed int
	files   map[string][]File
	crypted bool // the file was encrypted (Result.Encrypted)
}

func newBuilder(prefix string) (*builder, error) {
	p, err := checkPrefix(prefix)
	if err != nil {
		return nil, err
	}
	return &builder{prefix: p, used: map[string]bool{}}, nil
}

// warn records something that could not be brought across. It never
// carries a secret.
func (b *builder) warn(format string, args ...any) {
	b.warns = append(b.warns, fmt.Sprintf(format, args...))
}

// add turns a draft into an item.
func (b *builder) add(d *draft) {
	kind := d.kind
	if kind == "" {
		kind = d.inferKind()
	}
	label := d.label
	if label == "" {
		label = strings.TrimSpace(d.title)
	}
	it := svrpc.Item{
		Kind:   kind,
		Name:   b.name(d.folder, d.title),
		Label:  strings.ToValidUTF8(label, "?"),
		Attrs:  d.attrs,
		Tags:   cleanTags(d.tags),
		Fields: d.fields,
	}
	b.items = append(b.items, it)
	if len(d.files) > 0 {
		if b.files == nil {
			b.files = map[string][]File{}
		}
		b.files[it.Name] = d.files
	}
	if d.attachments > 0 {
		b.warn("%s: %s not imported (the export does not hold their contents)", it.Name, plural(d.attachments, "attachment"))
	}
	if d.passkeys > 0 {
		b.warn("%s: %s not imported (passkeys cannot be moved between managers yet)", it.Name, plural(d.passkeys, "passkey"))
	}
	for _, l := range d.lost {
		b.warn("%s: %s", it.Name, l)
	}
	if d.history {
		b.history = append(b.history, it.Name)
	}
}

// result finishes the import.
func (b *builder) result() *Result {
	warns := b.warns
	if n := len(b.history); n > 0 {
		shown := b.history[:min(n, 10)]
		more := ""
		if n > len(shown) {
			more = fmt.Sprintf(" and %d more", n-len(shown))
		}
		warns = append(warns, fmt.Sprintf("older versions (history) not imported, only the current one, of %s: %s%s",
			plural(n, "item"), strings.Join(shown, ", "), more))
	}
	if b.trashed > 0 {
		warns = append(warns, fmt.Sprintf("%s in the trash or recycle bin skipped", plural(b.trashed, "item")))
	}
	return &Result{Items: b.items, Files: b.files, Warnings: warns, Encrypted: b.crypted}
}

// name makes a valid, unused item name from a folder path and a title.
func (b *builder) name(folder []string, title string) string {
	segs := append([]string(nil), b.prefix...)
	fixed := len(segs)
	for _, f := range folder {
		if s := segment(f); s != "" {
			segs = append(segs, s)
		}
	}
	t := segment(title)
	if t == "" {
		t = "untitled"
	}
	for len(segs) > fixed && len(strings.Join(segs, "/"))+1+len(t) > maxName {
		segs = segs[:len(segs)-1]
	}
	if room := maxName - len(strings.Join(segs, "/")) - 1; len(t) > room {
		t = strings.TrimSpace(truncate(t, max(room, 1)))
		if t == "" {
			t = "untitled"
		}
	}
	base := strings.Join(append(segs, t), "/")
	name := base
	for n := 2; b.used[name]; n++ {
		name = fmt.Sprintf("%s (%d)", base, n)
	}
	b.used[name] = true
	return name
}

// segment makes one path segment from a folder or title: no control
// characters, no '/', not "." or "..", valid UTF-8, trimmed.
func segment(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		switch {
		case r == '/':
			return '-'
		case unicode.IsControl(r):
			return ' '
		}
		return r
	}, s)
	s = strings.TrimSpace(truncate(s, 255))
	if s == "." || s == ".." {
		s = strings.Repeat("_", len(s))
	}
	return s
}

// truncate cuts s to at most n bytes without splitting a character.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

// splitPath splits a folder written as a path ("Work/Servers").
func splitPath(p string) []string {
	var out []string
	for _, s := range strings.Split(p, "/") {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func cleanTags(tags []string) []string {
	var out []string
	seen := map[string]bool{}
	for _, t := range tags {
		t = strings.TrimSpace(strings.ToValidUTF8(t, "?"))
		if t != "" && !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out
}

func plural(n int, what string) string {
	if n == 1 {
		return "1 " + what
	}
	return fmt.Sprintf("%d %ss", n, what)
}
