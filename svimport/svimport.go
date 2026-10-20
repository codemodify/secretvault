package svimport

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svrpc"
)

// Format names a file format that Import reads.
type Format string

// The formats Import reads.
const (
	FormatKDBX                Format = "kdbx"                 // KeePass 2.x, KDBX 3.1 and 4.x
	FormatBitwarden           Format = "bitwarden"            // Bitwarden JSON, plain or password-protected
	Format1PUX                Format = "1pux"                 // 1Password Unencrypted Export
	FormatProtonPass          Format = "protonpass"           // Proton Pass export, zip or JSON
	FormatCSV                 Format = "csv"                  // browser and password-manager CSV
	FormatAegis               Format = "aegis"                // Aegis Authenticator vault, plain or encrypted
	FormatGoogleAuthenticator Format = "google-authenticator" // otpauth-migration:// export URIs
	FormatCXF                 Format = "cxf"                  // FIDO Credential Exchange Format 1.0
)

// Formats lists every format Import reads, for help texts.
var Formats = []Format{FormatKDBX, FormatBitwarden, Format1PUX, FormatProtonPass, FormatCSV,
	FormatAegis, FormatGoogleAuthenticator, FormatCXF}

// Options change how Import reads a file.
type Options struct {
	// Passphrase opens encrypted inputs: KDBX, password-protected
	// Bitwarden exports, encrypted Aegis vaults.
	Passphrase []byte

	// Keyfile is a KeePass key file's contents, for KDBX files that use
	// one.
	Keyfile []byte
}

// Result is what Import brought across.
type Result struct {
	Items []svrpc.Item

	// Files are the items' attached files, by item name, to attach once
	// the items are stored (file.attach).
	Files map[string][]File

	// Warnings say what could not be brought across (attachments,
	// passkeys, history, trashed items, keys of unknown kinds), naming the
	// item but never holding a secret.
	Warnings []string

	// Encrypted says the file was encrypted: it took a passphrase or a
	// key file to read. An export that was not holds every secret in the
	// clear, and is best deleted once it is imported.
	Encrypted bool
}

// File is an attached file brought across with its item.
type File struct {
	Name string
	Type string // a media type, when the export says
	Data []byte
}

// Wipe zeroes every field value of every item, and every file.
func (r *Result) Wipe() {
	for i := range r.Items {
		for j := range r.Items[i].Fields {
			clear(r.Items[i].Fields[j].Value)
		}
	}
	for _, files := range r.Files {
		for _, f := range files {
			clear(f.Data)
		}
	}
}

var (
	// ErrFormat is input that is not in the format named, or is damaged.
	ErrFormat = errors.New("svimport: not a readable file of this format")

	// ErrPassphrase says the file is encrypted and Options gave no
	// passphrase (or key file): ask for one and call Import again.
	ErrPassphrase = errors.New("svimport: the file is encrypted; its passphrase is needed")

	// ErrWrongKey is a passphrase or key file that does not open the file.
	ErrWrongKey = errors.New("svimport: the passphrase or key file does not open this file")

	// ErrUnsupported is a file or a variant of a format that cannot be read.
	ErrUnsupported = errors.New("svimport: not supported")

	// ErrOpenPGP is a file encrypted with OpenPGP: an encrypted Proton Pass
	// export, or a pass or gopass entry.
	ErrOpenPGP = errors.New("svimport: the file is encrypted with OpenPGP, which secretvault reads from milestone M5 on; " +
		"export it unencrypted instead (Proton Pass: export without a passphrase)")
)

// maxInput bounds what one import reads, decompressed.
const maxInput = 512 << 20

// Import reads a file of format f into items. On ErrPassphrase, ask for
// the file's passphrase and call again.
func Import(f Format, data []byte, opts Options) (*Result, error) {
	if isOpenPGP(data) {
		return nil, ErrOpenPGP
	}
	b := newBuilder()
	var err error
	switch f {
	case FormatKDBX:
		err = readKDBX(b, data, opts)
	case FormatBitwarden:
		err = readBitwarden(b, data, opts)
	case Format1PUX:
		err = read1PUX(b, data)
	case FormatProtonPass:
		err = readProtonPass(b, data)
	case FormatCSV:
		err = readCSV(b, data)
	case FormatAegis:
		err = readAegis(b, data, opts)
	case FormatGoogleAuthenticator:
		err = readGoogleAuthenticator(b, data)
	case FormatCXF:
		err = readCXF(b, data)
	default:
		err = fmt.Errorf("%w: format %q (known: %s)", ErrUnsupported, f, formatList())
	}
	res := b.result()
	if err != nil {
		res.Wipe()
		return nil, err
	}
	return res, nil
}

func formatList() string {
	s := make([]string, len(Formats))
	for i, f := range Formats {
		s[i] = string(f)
	}
	return strings.Join(s, ", ")
}

var (
	kdbxSignature = []byte{0x03, 0xd9, 0xa2, 0x9a, 0x67, 0xfb, 0x4b, 0xb5}
	zipSignature  = []byte("PK\x03\x04")
	utf8BOM       = []byte("\xef\xbb\xbf")
)

// Detect guesses a file's format from its name and first bytes (the whole
// file is best: JSON formats are told apart by their top-level keys). An
// OpenPGP-encrypted file is reported as FormatProtonPass, whose encrypted
// export it most likely is; Import then says OpenPGP is not read yet.
func Detect(name string, head []byte) (Format, bool) {
	ext := strings.ToLower(filepath.Ext(name))
	h := bytes.TrimSpace(bytes.TrimPrefix(head, utf8BOM))
	switch {
	case bytes.HasPrefix(head, kdbxSignature) || ext == ".kdbx":
		return FormatKDBX, true
	case isOpenPGP(head):
		return FormatProtonPass, true
	case bytes.HasPrefix(head, zipSignature):
		switch {
		case bytes.Contains(head, []byte("export.data")), bytes.Contains(head, []byte("export.attributes")), ext == ".1pux":
			return Format1PUX, true
		case bytes.Contains(head, []byte("Proton Pass")), bytes.Contains(head, []byte("data.json")):
			return FormatProtonPass, true
		}
		return "", false
	case ext == ".1pux":
		return Format1PUX, true
	case bytes.HasPrefix(bytes.ToLower(h), []byte("otpauth-migration:")):
		return FormatGoogleAuthenticator, true
	case bytes.HasPrefix(h, []byte("{")):
		return detectJSON(h)
	case ext == ".csv" || looksLikeCSV(h):
		return FormatCSV, true
	}
	return "", false
}

// detectJSON tells the JSON formats apart by their top-level keys, or, when
// the head is cut short, by the keys it can see.
func detectJSON(h []byte) (Format, bool) {
	has := func(k string) bool { return bytes.Contains(h, []byte(`"`+k+`"`)) }
	var top map[string]json.RawMessage
	if json.Unmarshal(h, &top) == nil {
		has = func(k string) bool { _, ok := top[k]; return ok }
	}
	switch {
	case has("exporterRpId") || has("exporterDisplayName"):
		return FormatCXF, true
	case has("userId") && has("vaults"):
		return FormatProtonPass, true
	case has("accounts"):
		return Format1PUX, true
	case has("header") && has("db"):
		return FormatAegis, true
	case has("items") || has("folders") || has("passwordProtected") || has("encKeyValidation_DO_NOT_EDIT"):
		return FormatBitwarden, true
	case has("vaults"):
		return FormatProtonPass, true
	}
	return "", false
}

// looksLikeCSV reports a first line that names a password column.
func looksLikeCSV(h []byte) bool {
	line, _, _ := bytes.Cut(h, []byte("\n"))
	l := strings.ToLower(string(line))
	return strings.Contains(l, ",") && strings.Contains(l, "password")
}

// isOpenPGP reports an OpenPGP message: ASCII armour, or a binary packet
// that starts an encrypted message (a public-key or symmetric-key
// encrypted session key, in either packet framing) and is not text.
func isOpenPGP(b []byte) bool {
	t := bytes.TrimSpace(b)
	if bytes.HasPrefix(t, []byte("-----BEGIN PGP MESSAGE-----")) {
		return true
	}
	if len(b) < 2 || utf8.Valid(b) {
		return false
	}
	switch c := b[0]; {
	case c >= 0x84 && c <= 0x87, c >= 0x8c && c <= 0x8f: // old framing, tags 1 and 3
		return true
	case c == 0xc1 || c == 0xc3: // new framing, tags 1 and 3
		return true
	}
	return false
}

// jstr is a JSON string that also takes numbers and booleans (as their
// literal text) and null, since exports write some values either way: a
// card's expiry month, a port. Objects and arrays read as "".
type jstr string

func (s *jstr) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	switch {
	case len(b) == 0:
		*s = ""
	case b[0] == '"':
		var v string
		if err := json.Unmarshal(b, &v); err != nil {
			return err
		}
		*s = jstr(v)
	case b[0] == '{' || b[0] == '[' || bytes.Equal(b, []byte("null")):
		*s = ""
	default:
		*s = jstr(b)
	}
	return nil
}

// jsonError reports JSON that does not parse without quoting any of it:
// encoding/json's messages can carry a value from the file.
func jsonError(what string, err error) error {
	var syntax *json.SyntaxError
	var typ *json.UnmarshalTypeError
	switch {
	case errors.As(err, &syntax):
		return fmt.Errorf("%w: %s is not valid JSON (at byte %d)", ErrFormat, what, syntax.Offset)
	case errors.As(err, &typ):
		return fmt.Errorf("%w: %s: %s is not a %s", ErrFormat, what, typ.Field, typ.Type)
	}
	return fmt.Errorf("%w: %s is not valid JSON", ErrFormat, what)
}
