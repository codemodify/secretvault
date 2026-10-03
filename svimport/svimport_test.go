package svimport

import (
	"archive/zip"
	"bytes"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// Helpers shared by the format tests.

var testPassphrase = []byte("correct horse battery staple")

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// mustImport imports and checks what every import must hold: valid,
// unique names and well-formed fields, and warnings free of secrets.
func mustImport(t *testing.T, f Format, data []byte, opts Options) *Result {
	t.Helper()
	res, err := Import(f, data, opts)
	if err != nil {
		t.Fatalf("import %s: %v", f, err)
	}
	checkResult(t, res)
	return res
}

func checkResult(t *testing.T, res *Result) {
	t.Helper()
	names := map[string]bool{}
	for _, it := range res.Items {
		if err := svcore.CheckName(it.Name); err != nil {
			t.Errorf("invalid name: %v", err)
		}
		if names[it.Name] {
			t.Errorf("name %q used twice", it.Name)
		}
		names[it.Name] = true
		if it.Kind == "" {
			t.Errorf("%s has no kind", it.Name)
		}
		seen := map[string]bool{}
		for _, f := range it.Fields {
			if f.Name == "" || seen[f.Name] || f.Type == "" || len(f.Value) == 0 {
				t.Errorf("%s: bad field %q (type %q, %d bytes)", it.Name, f.Name, f.Type, len(f.Value))
			}
			seen[f.Name] = true
			if f.Type == svcore.FieldConcealed || f.Type == svcore.FieldKey || f.Type == svcore.FieldOTP {
				for _, w := range res.Warnings {
					if len(f.Value) >= 4 && strings.Contains(w, string(f.Value)) {
						t.Errorf("a warning holds the secret of %s/%s: %q", it.Name, f.Name, w)
					}
				}
			}
		}
	}
}

func item(t *testing.T, res *Result, name string) svrpc.Item {
	t.Helper()
	for _, it := range res.Items {
		if it.Name == name {
			return it
		}
	}
	var have []string
	for _, it := range res.Items {
		have = append(have, it.Name)
	}
	t.Fatalf("no item %q; have %q", name, have)
	return svrpc.Item{}
}

func noItem(t *testing.T, res *Result, name string) {
	t.Helper()
	for _, it := range res.Items {
		if it.Name == name {
			t.Errorf("item %q should not have been imported", name)
		}
	}
}

// has checks one field's type and value.
func has(t *testing.T, it svrpc.Item, name, typ, value string) {
	t.Helper()
	for _, f := range it.Fields {
		if f.Name == name {
			if f.Type != typ || string(f.Value) != value {
				t.Errorf("%s: field %s = %s %q, want %s %q", it.Name, name, f.Type, f.Value, typ, value)
			}
			return
		}
	}
	var have []string
	for _, f := range it.Fields {
		have = append(have, f.Name)
	}
	t.Errorf("%s: no field %q; have %q", it.Name, name, have)
}

func hasNot(t *testing.T, it svrpc.Item, name string) {
	t.Helper()
	for _, f := range it.Fields {
		if f.Name == name {
			t.Errorf("%s: unexpected field %q", it.Name, name)
		}
	}
}

func warned(t *testing.T, res *Result, parts ...string) {
	t.Helper()
	for _, w := range res.Warnings {
		ok := true
		for _, p := range parts {
			ok = ok && strings.Contains(w, p)
		}
		if ok {
			return
		}
	}
	t.Errorf("no warning with %q among %q", parts, res.Warnings)
}

// zipOf builds a zip archive in memory.
func zipOf(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, data := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		w.Write(data)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestNamesAreMadeValidAndUnique(t *testing.T) {
	b, err := newBuilder("imported/keepass/")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		folder []string
		title  string
		want   string
	}{
		{[]string{"Work", "Servers"}, "db1", "imported/keepass/Work/Servers/db1"},
		{[]string{"Work", "Servers"}, "db1", "imported/keepass/Work/Servers/db1 (2)"},
		{[]string{"Work", "Servers"}, "db1", "imported/keepass/Work/Servers/db1 (3)"},
		{nil, "https://example.com/login", "imported/keepass/https:--example.com-login"},
		{[]string{"", " . ", ".."}, "..", "imported/keepass/_/__/__"},
		{nil, "", "imported/keepass/untitled"},
		{nil, "tab\there\x00and\u0085more", "imported/keepass/tab here and more"},
		{[]string{"bad\xffutf8"}, "x", "imported/keepass/bad?utf8/x"},
	} {
		if got := b.name(c.folder, c.title); got != c.want {
			t.Errorf("name(%q, %q) = %q, want %q", c.folder, c.title, got, c.want)
		}
	}
	long := b.name([]string{strings.Repeat("f", 300), strings.Repeat("g", 300), strings.Repeat("h", 300)}, strings.Repeat("é", 400))
	if err := svcore.CheckName(long); err != nil || len(long) > maxName {
		t.Errorf("a long name is %d bytes: %v", len(long), err)
	}
	for _, p := range []string{"a/../b", "x/\x01", strings.Repeat("p", 600)} {
		if _, err := newBuilder(p); !errors.Is(err, svcore.ErrName) {
			t.Errorf("prefix %q accepted: %v", p, err)
		}
	}
}

func TestFormatsAreDetectedFromNameAndContent(t *testing.T) {
	zip1 := zipOf(t, map[string][]byte{"export.attributes": []byte("{}"), "export.data": []byte("{}")})
	zipProton := zipOf(t, map[string][]byte{"Proton Pass/data.json": []byte("{}")})
	for _, c := range []struct {
		name string
		head []byte
		want Format
	}{
		{"db.kdbx", readFixture(t, "kdbx31-aes-aeskdf-salsa20.kdbx"), FormatKDBX},
		{"x.bin", readFixture(t, "kdbx41-aes-argon2id.kdbx"), FormatKDBX},
		{"export.json", readFixture(t, "bitwarden.json"), FormatBitwarden},
		{"export.json", readFixture(t, "bitwarden-encrypted-pbkdf2.json"), FormatBitwarden},
		{"a.1pux", zip1, Format1PUX},
		{"export.zip", zip1, Format1PUX},
		{"export.data", readFixture(t, "1pux-export.data"), Format1PUX},
		{"Proton Pass_export.zip", zipProton, FormatProtonPass},
		{"data.json", readFixture(t, "protonpass-data.json"), FormatProtonPass},
		{"Proton Pass_export.pgp", []byte("-----BEGIN PGP MESSAGE-----\n\nwy4ECQMI...\n"), FormatProtonPass},
		{"aegis-backup.json", readFixture(t, "aegis-encrypted.json"), FormatAegis},
		{"aegis.json", readFixture(t, "aegis-plain.json"), FormatAegis},
		{"cxf.json", readFixture(t, "cxf.json"), FormatCXF},
		{"qr.txt", []byte("otpauth-migration://offline?data=CjEKCkhlbGxvId6tvu8SGEV4YW1wbGU6YWxpY2VAZ29vZ2xlLmNvbRoHRXhhbXBsZTAC\n"), FormatGoogleAuthenticator},
		{"passwords.csv", []byte("anything"), FormatCSV},
		{"Chrome Passwords.txt", []byte("\xef\xbb\xbfname,url,username,password,note\n"), FormatCSV},
		// A head cut short still shows its keys.
		{"x.json", readFixture(t, "cxf.json")[:120], FormatCXF},
	} {
		got, ok := Detect(c.name, c.head)
		if !ok || got != c.want {
			t.Errorf("Detect(%q) = %q, %v; want %q", c.name, got, ok, c.want)
		}
	}
	if f, ok := Detect("photos.zip", zipOf(t, map[string][]byte{"cat.jpg": []byte("meow")})); ok {
		t.Errorf("an unknown zip was taken for %q", f)
	}
	if f, ok := Detect("notes.txt", []byte("dear diary")); ok {
		t.Errorf("plain text was taken for %q", f)
	}
}

func TestOpenPGPFilesAreRefusedUntilM5(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("-----BEGIN PGP MESSAGE-----\n\njA0ECQMC...\n-----END PGP MESSAGE-----\n"),
		{0x8c, 0x0d, 0x04, 0x09, 0x03, 0x02, 0xff, 0xfe}, // a binary symmetric-key session packet
		{0xc3, 0x0d, 0x04, 0x09, 0x03, 0x02, 0xff, 0xfe},
	} {
		for _, f := range []Format{FormatProtonPass, FormatBitwarden} {
			if _, err := Import(f, data, Options{}); !errors.Is(err, ErrOpenPGP) || !strings.Contains(err.Error(), "M5") {
				t.Errorf("%s: %v", f, err)
			}
		}
	}
	// A CSV that merely starts with a non-ASCII letter is not OpenPGP.
	if isOpenPGP([]byte("Éclair,https://x,ada,pw\n")) {
		t.Error("UTF-8 text taken for OpenPGP")
	}
}

func TestUnknownFormatsAreRefused(t *testing.T) {
	if _, err := Import("pass", []byte("x"), Options{}); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestOTPKeysAreStoredAsOtpauthURIs(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{"JBSWY3DPEHPK3PXP", "otpauth://totp/Site:ada?issuer=Site&secret=JBSWY3DPEHPK3PXP"},
		{"jbsw y3dp ehpk 3pxp", "otpauth://totp/Site:ada?issuer=Site&secret=JBSWY3DPEHPK3PXP"},
		{"otpauth://totp/X:y?secret=JBSWY3DPEHPK3PXP&digits=8", "otpauth://totp/X:y?digits=8&issuer=X&secret=JBSWY3DPEHPK3PXP"},
		{"steam://STEAMSTEAMSTEAM2", "otpauth://totp/Steam:ada?encoder=steam&issuer=Steam&secret=STEAMSTEAMSTEAM2"},
		{"key=JBSWY3DPEHPK3PXP&size=8&step=60&otpHashMode=Sha512", "otpauth://totp/Site:ada?algorithm=SHA512&digits=8&issuer=Site&period=60&secret=JBSWY3DPEHPK3PXP"},
	} {
		got, err := otpURI(c.in, "Site", "ada")
		if err != nil || got != c.want {
			t.Errorf("otpURI(%q) = %q, %v; want %q", c.in, got, err, c.want)
		}
	}
	for _, bad := range []string{"not base32 at all!", "otpauth://totp/x?secret=", "otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&algorithm=MD5"} {
		if _, err := otpURI(bad, "", ""); err == nil {
			t.Errorf("otpURI(%q) accepted", bad)
		}
	}
	// A key that cannot be read is kept, concealed, and said so.
	d := &draft{title: "x"}
	d.otp("garbage!", "x", "")
	if len(d.fields) != 1 || d.fields[0].Type != svcore.FieldConcealed || len(d.lost) != 1 {
		t.Fatalf("an unreadable key: %+v %q", d.fields, d.lost)
	}
}

// Result.Encrypted says whether the file took a key to read: one that did
// not held its secrets in the clear, whatever it was given.
func TestAResultSaysWhetherItsFileWasEncrypted(t *testing.T) {
	for _, c := range []struct {
		f    Format
		file string
		opts Options
		want bool
	}{
		{FormatAegis, "aegis-encrypted.json", Options{Passphrase: testPassphrase}, true},
		{FormatAegis, "aegis-plain.json", Options{Passphrase: testPassphrase}, false},
		{FormatBitwarden, "bitwarden-encrypted-pbkdf2.json", Options{Passphrase: testPassphrase}, true},
		{FormatBitwarden, "bitwarden.json", Options{Passphrase: testPassphrase}, false},
		{FormatKDBX, "kdbx31-aes-aeskdf-salsa20.kdbx", Options{Passphrase: testPassphrase}, true},
		{FormatCXF, "cxf.json", Options{}, false},
		{Format1PUX, "1pux-export.data", Options{}, false},
	} {
		res := mustImport(t, c.f, readFixture(t, c.file), c.opts)
		if res.Encrypted != c.want {
			t.Errorf("%s: Encrypted = %v", c.file, res.Encrypted)
		}
	}
	res := mustImport(t, FormatCSV, []byte("url,username,password\nhttps://x.example,ada,pw\n"), Options{})
	if res.Encrypted {
		t.Error("a CSV file is said to be encrypted")
	}
}
