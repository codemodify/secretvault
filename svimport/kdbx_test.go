package svimport

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svrpc"
)

// The fixtures read here were made by testdata/make_fixtures.py with
// Python's cryptography package and the reference argon2 tool, not by this
// package's writer.

func TestAKeePass31FileImportsWithItsFolders(t *testing.T) {
	data := readFixture(t, "kdbx31-aes-aeskdf-salsa20.kdbx")
	res := mustImport(t, FormatKDBX, data, Options{Passphrase: testPassphrase, Prefix: "keepass"})
	if len(res.Items) != 5 {
		t.Errorf("%d items, want 5", len(res.Items))
	}
	bank := item(t, res, "keepass/Bank")
	if bank.Kind != "login" || bank.Label != "Bank" || !reflect.DeepEqual(bank.Tags, []string{"finance", "important"}) {
		t.Errorf("bank: %s %q %q", bank.Kind, bank.Label, bank.Tags)
	}
	has(t, bank, "username", svcore.FieldText, "ada")
	has(t, bank, "password", svcore.FieldConcealed, "b4nk-p4ss & <more>")
	has(t, bank, "url", svcore.FieldURL, "https://bank.example/login")
	has(t, bank, "notes", svcore.FieldText, "PIN is in the safe\nsecond line")
	has(t, bank, "Recovery code", svcore.FieldConcealed, "RC-123-456")
	has(t, bank, "Security question", svcore.FieldText, "first pet")
	if note := item(t, res, "keepass/Wifi note"); note.Kind != "note" || len(note.Fields) != 1 {
		t.Errorf("a notes-only entry: %+v", note)
	}
	has(t, item(t, res, "keepass/Work/VPN"), "otp", svcore.FieldOTP,
		"otpauth://totp/VPN:a.lovelace?issuer=VPN&secret=JBSWY3DPEHPK3PXP")
	db1 := item(t, res, "keepass/Work/Servers/db1")
	has(t, db1, "otp", svcore.FieldOTP, "otpauth://totp/db1:root?digits=8&issuer=db1&period=60&secret=GEZDGNBVGY3TQOJQ")
	hasNot(t, db1, "TOTP Seed")
	has(t, item(t, res, "keepass/Steam"), "otp", svcore.FieldOTP,
		"otpauth://totp/Steam:gaben?encoder=steam&issuer=Steam&secret=STEAMSTEAMSTEAM2")
	noItem(t, res, "keepass/Recycle Bin/Deleted thing")
	warned(t, res, "keepass/Work/Servers/db1", "attachment")
	warned(t, res, "history", "keepass/Bank")
	warned(t, res, "1 item in the trash")
}

func TestAKeePass4FileWithAKeyFileImports(t *testing.T) {
	data := readFixture(t, "kdbx4-chacha20-argon2d.kdbx")
	res := mustImport(t, FormatKDBX, data, Options{Passphrase: testPassphrase, Keyfile: readFixture(t, "kdbx4-chacha20-argon2d.keyx")})
	mail := item(t, res, "Mail & Chat/Mailbox")
	if !reflect.DeepEqual(mail.Tags, []string{"mail", "personal"}) {
		t.Errorf("tags %q", mail.Tags)
	}
	has(t, mail, "password", svcore.FieldConcealed, "m4il-p4ss")
	has(t, mail, "url", svcore.FieldURL, "https://mail.example.org")
	has(t, mail, "url2", svcore.FieldURL, "https://webmail.example.org")
	has(t, mail, "otp", svcore.FieldOTP,
		"otpauth://totp/Mailbox:ada@example.org?algorithm=SHA256&digits=8&issuer=Mailbox&secret=JBSWY3DPEHPK3PXP")
	has(t, mail, "PIN", svcore.FieldConcealed, "4321")
	for _, n := range []string{"KP2A_URL", "TimeOtp-Secret-Base32", "TimeOtp-Length"} {
		hasNot(t, mail, n)
	}
	warned(t, res, "Mail & Chat/Mailbox", "attachment")
	pk := item(t, res, "Passkey site")
	if len(pk.Fields) != 1 {
		t.Errorf("the passkey's strings were imported: %+v", pk.Fields)
	}
	warned(t, res, "Passkey site", "passkey")
}

func TestAKeePass41FileOpensWithAKeyFileAlone(t *testing.T) {
	res := mustImport(t, FormatKDBX, readFixture(t, "kdbx41-aes-argon2id.kdbx"), Options{Keyfile: readFixture(t, "kdbx41-aes-argon2id.key")})
	tok := item(t, res, "API token")
	has(t, tok, "password", svcore.FieldConcealed, "tok_live_0123456789")
	has(t, tok, "notes", svcore.FieldText, "rotate yearly")
}

func TestWrongOrMissingKeysAreReported(t *testing.T) {
	v3 := readFixture(t, "kdbx31-aes-aeskdf-salsa20.kdbx")
	v4 := readFixture(t, "kdbx4-chacha20-argon2d.kdbx")
	kf := readFixture(t, "kdbx4-chacha20-argon2d.keyx")
	for name, c := range map[string]struct {
		data []byte
		opts Options
		want error
	}{
		"3.1, no key":           {v3, Options{}, ErrPassphrase},
		"3.1, wrong passphrase": {v3, Options{Passphrase: []byte("wrong")}, ErrWrongKey},
		"4, no key file":        {v4, Options{Passphrase: testPassphrase}, ErrWrongKey},
		"4, key file alone":     {v4, Options{Keyfile: kf}, ErrWrongKey},
		"4, wrong passphrase":   {v4, Options{Passphrase: []byte("wrong"), Keyfile: kf}, ErrWrongKey},
	} {
		if _, err := Import(FormatKDBX, c.data, c.opts); !errors.Is(err, c.want) {
			t.Errorf("%s: %v, want %v", name, err, c.want)
		}
	}
}

func TestDamagedKeePassFilesAreRefused(t *testing.T) {
	v4 := readFixture(t, "kdbx4-chacha20-argon2d.kdbx")
	kf := readFixture(t, "kdbx4-chacha20-argon2d.keyx")
	h, err := parseKDBXHeader(v4)
	if err != nil {
		t.Fatal(err)
	}
	for name, at := range map[string]int{
		"a header byte":      len(h.raw) - 6,
		"the header's hash":  len(h.raw) + 3,
		"a ciphertext byte":  len(h.raw) + 64 + 36 + 10,
		"a block's own HMAC": len(h.raw) + 64 + 1,
	} {
		bad := bytes.Clone(v4)
		bad[at] ^= 1
		_, err := Import(FormatKDBX, bad, Options{Passphrase: testPassphrase, Keyfile: kf})
		if err == nil || errors.Is(err, ErrWrongKey) && name != "a header byte" {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, cut := range []int{10, len(h.raw) + 40, len(v4) - 20} {
		if _, err := Import(FormatKDBX, v4[:cut], Options{Passphrase: testPassphrase, Keyfile: kf}); !errors.Is(err, ErrFormat) {
			t.Errorf("cut at %d: %v", cut, err)
		}
	}
	kdb := append([]byte{0x03, 0xd9, 0xa2, 0x9a, 0x66, 0xfb, 0x4b, 0xb5}, make([]byte, 100)...)
	if _, err := Import(FormatKDBX, kdb, Options{Passphrase: testPassphrase}); !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "KeePass 1") {
		t.Errorf("a KeePass 1 file: %v", err)
	}
}

func TestKeyFilesAreReadInEveryKeePassForm(t *testing.T) {
	key := bytes.Repeat([]byte{0xab}, 32)
	sum := sha256.Sum256(key)
	v2 := `<?xml version="1.0" encoding="utf-8"?><KeyFile><Meta><Version>2.0</Version></Meta><Key>` +
		`<Data Hash="` + strings.ToUpper(hex.EncodeToString(sum[:4])) + `">ABABABAB ABABABAB ABABABAB ABABABAB` + "\n" +
		`ABABABAB ABABABAB ABABABAB ABABABAB</Data></Key></KeyFile>`
	v1 := `<?xml version="1.0" encoding="utf-8"?><KeyFile><Meta><Version>1.00</Version></Meta><Key><Data>` +
		`q6urq6urq6urq6urq6urq6urq6urq6urq6urq6urq6s=</Data></Key></KeyFile>`
	other := []byte("any file at all can be a key file")
	otherSum := sha256.Sum256(other)
	for name, c := range map[string]struct {
		file []byte
		want []byte
	}{
		"XML 2.0":  {[]byte(v2), key},
		"XML 1.0":  {[]byte(v1), key},
		"32 bytes": {key, key},
		"64 hex":   {[]byte(strings.Repeat("ab", 32)), key},
		"other":    {other, otherSum[:]},
	} {
		got, err := keyfileKey(c.file)
		if err != nil || !bytes.Equal(got, c.want) {
			t.Errorf("%s: %x, %v", name, got, err)
		}
	}
	bad := strings.Replace(v2, `Hash="`, `Hash="00`, 1)
	if _, err := keyfileKey([]byte(bad)); !errors.Is(err, ErrFormat) {
		t.Errorf("a key file with a wrong checksum: %v", err)
	}
}

// sampleItems are items of every kind, with the awkward cases: nested
// folders, a label unlike the name, a binary field, a value that XML
// cannot hold, attributes and tags.
func sampleItems() []svrpc.Item {
	return []svrpc.Item{
		{Kind: "login", Name: "web/github.com", Label: "GitHub", Tags: []string{"dev", "web"}, Attrs: map[string]string{"service": "github"},
			Fields: []svrpc.Field{
				{Name: "username", Type: svcore.FieldText, Value: []byte("ada")},
				{Name: "password", Type: svcore.FieldConcealed, Value: []byte("gh <p4ss> & \"more\"")},
				{Name: "url", Type: svcore.FieldURL, Value: []byte("https://github.com")},
				{Name: "url2", Type: svcore.FieldURL, Value: []byte("https://gist.github.com")},
				{Name: "otp", Type: svcore.FieldOTP, Value: []byte("otpauth://totp/GitHub:ada?issuer=GitHub&secret=JBSWY3DPEHPK3PXP")},
				{Name: "notes", Type: svcore.FieldText, Value: []byte("line one\r\nline two\n")},
				{Name: "recovery", Type: svcore.FieldConcealed, Value: []byte("r1 r2 r3")},
				{Name: "email", Type: svcore.FieldEmail, Value: []byte("ada@example.org")},
			}},
		{Kind: "note", Name: "notes/door", Label: "door", Fields: []svrpc.Field{{Name: "notes", Type: svcore.FieldText, Value: []byte("4711#")}}},
		{Kind: "card", Name: "money/visa", Label: "visa", Fields: []svrpc.Field{
			{Name: "cardholder", Type: svcore.FieldText, Value: []byte("Ada Lovelace")},
			{Name: "number", Type: svcore.FieldConcealed, Value: []byte("4111111111111111")},
			{Name: "expiry", Type: svcore.FieldText, Value: []byte("07/2031")},
			{Name: "cvv", Type: svcore.FieldConcealed, Value: []byte("123")},
			{Name: "brand", Type: svcore.FieldText, Value: []byte("Visa")},
		}},
		{Kind: "ssh-key", Name: "keys/deploy", Label: "deploy", Fields: []svrpc.Field{
			{Name: "private_key", Type: svcore.FieldKey, Value: []byte(testOpenSSHKey)},
			{Name: "public_key", Type: svcore.FieldText, Value: []byte(testSSHPublicKey)},
			{Name: "comment", Type: svcore.FieldText, Value: []byte("ada@build")},
		}},
		{Kind: "otp", Name: "otp/Bank (ada)", Label: "Bank (ada)", Fields: []svrpc.Field{
			{Name: "otp", Type: svcore.FieldOTP, Value: []byte("otpauth://hotp/Bank:ada?counter=7&issuer=Bank&secret=GEZDGNBVGY3TQOJQ")},
		}},
		{Kind: "kv", Name: "odd/raw", Label: "raw", Fields: []svrpc.Field{
			{Name: "blob", Type: svcore.FieldBinary, Value: []byte{0, 1, 2, 0xff, 0xfe}},
			{Name: "control", Type: svcore.FieldText, Value: []byte("bell\x07here")},
			{Name: "Title", Type: svcore.FieldText, Value: []byte("a field named like a KeePass one")},
		}},
		{Kind: "password", Name: "top-level", Label: "top-level", Fields: []svrpc.Field{
			{Name: "password", Type: svcore.FieldConcealed, Value: []byte("pw")},
		}},
	}
}

const testOpenSSHKey = `-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACDDJ20gBHBKmgDvl8Fo0kMPXw6nLeNOEbalxuPKPl0y4AAAAIiFNTG7hTUx
uwAAAAtzc2gtZWQyNTUxOQAAACDDJ20gBHBKmgDvl8Fo0kMPXw6nLeNOEbalxuPKPl0y4A
AAAEBdwuVaEivhwJSvCV1wM3j/gARHg+rNXHNfqVvJcBACZMMnbSAEcEqaAO+XwWjSQw9f
Dqct404RtqXG48o+XTLgAAAAAAECAwQF
-----END OPENSSH PRIVATE KEY-----
`

// testSSHPublicKey is testOpenSSHKey's public half, as ssh-keygen -y gives it.
const testSSHPublicKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMMnbSAEcEqaAO+XwWjSQw9fDqct404RtqXG48o+XTLg"

// sameItems compares imported items with what was exported, by name.
func sameItems(t *testing.T, got []svrpc.Item, want []svrpc.Item, prefix string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%d items came back, want %d", len(got), len(want))
	}
	byName := map[string]svrpc.Item{}
	for _, it := range got {
		byName[it.Name] = it
	}
	for _, w := range want {
		g, ok := byName[prefix+w.Name]
		if !ok {
			t.Errorf("%s did not come back", w.Name)
			continue
		}
		g.Name = w.Name
		if !reflect.DeepEqual(g, w) {
			t.Errorf("%s came back different:\n got %+v\nwant %+v", w.Name, g, w)
		}
	}
}

func TestKeePassFilesRoundTripThroughEveryCipherAndKDF(t *testing.T) {
	for _, p := range []kdbxParams{
		{major: 3, cipher: kdbxAES, rounds: 100, gzip: true, stream: streamSalsa20},
		{major: 3, cipher: kdbxTwofish, rounds: 100, gzip: false, stream: streamSalsa20},
		{major: 3, cipher: kdbxChaCha20, rounds: 100, gzip: true, stream: streamChaCha20},
		{major: 4, cipher: kdbxAES, kdf: kdfArgon2id, time: 1, memKiB: 64, threads: 2, gzip: true, stream: streamChaCha20},
		{major: 4, cipher: kdbxChaCha20, kdf: kdfArgon2d, time: 2, memKiB: 32, threads: 1, gzip: false, stream: streamChaCha20},
		{major: 4, cipher: kdbxTwofish, kdf: kdfAES3, rounds: 100, gzip: true, stream: streamSalsa20},
		{major: 4, cipher: kdbxAES, kdf: kdfAES4, rounds: 100, gzip: false, stream: streamNone},
	} {
		for _, key := range []struct{ pass, keyfile []byte }{
			{testPassphrase, nil},
			{testPassphrase, []byte("a key file")},
			{nil, []byte(strings.Repeat("cd", 32))},
		} {
			var buf bytes.Buffer
			if err := writeKDBX(sampleItems(), &buf, key.pass, key.keyfile, p); err != nil {
				t.Fatal(err)
			}
			res, err := Import(FormatKDBX, buf.Bytes(), Options{Passphrase: key.pass, Keyfile: key.keyfile, Prefix: "back"})
			if err != nil {
				t.Fatalf("%+v: %v", p, err)
			}
			checkResult(t, res)
			sameItems(t, res.Items, sampleItems(), "back/")
			if len(res.Warnings) != 0 {
				t.Errorf("%+v: warnings %q", p, res.Warnings)
			}
		}
	}
}

func TestExportKDBXWritesKDBX4WithArgon2idAndAES(t *testing.T) {
	saved := svcrypto.DefaultArgon2
	svcrypto.DefaultArgon2 = svcrypto.KDFParams{Alg: svcrypto.Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	defer func() { svcrypto.DefaultArgon2 = saved }()
	var buf bytes.Buffer
	if err := ExportKDBX(sampleItems(), &buf, testPassphrase); err != nil {
		t.Fatal(err)
	}
	h, err := parseKDBXHeader(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if h.major != 4 || h.cipher != kdbxAES || string(h.kdf.bytes("$UUID")) != kdfArgon2id || !h.gzip {
		t.Errorf("header: version %d.%d, cipher %x, kdf %x", h.major, h.minor, h.cipher, h.kdf.bytes("$UUID"))
	}
	if m, _ := h.kdf.uint("M"); m != 64*1024 {
		t.Errorf("argon2 memory %d bytes", m)
	}
	// Protected values really are encrypted in the file: no password in the clear.
	if bytes.Contains(buf.Bytes(), []byte("gh <p4ss>")) {
		t.Error("a secret is in the file in the clear")
	}
	res := mustImport(t, FormatKDBX, buf.Bytes(), Options{Passphrase: testPassphrase})
	sameItems(t, res.Items, sampleItems(), "")
	if err := ExportKDBX(sampleItems(), &buf, nil); err == nil {
		t.Error("an export without a passphrase was written")
	}
}

func TestHostileKDFParametersAreRefused(t *testing.T) {
	for _, p := range []kdbxParams{
		{major: 3, cipher: kdbxAES, rounds: 1 << 40, stream: streamSalsa20},
	} {
		var buf bytes.Buffer
		if err := writeKDBX(nil, &buf, testPassphrase, nil, p); !errors.Is(err, ErrUnsupported) {
			t.Errorf("writing with %+v: %v", p, err)
		}
	}
	// A KDBX 4 file asking Argon2 for 8 TiB.
	var buf bytes.Buffer
	if err := writeKDBX(nil, &buf, testPassphrase, nil, kdbxParams{major: 4, cipher: kdbxAES, kdf: kdfArgon2d, time: 1, memKiB: 64, threads: 1, stream: streamChaCha20}); err != nil {
		t.Fatal(err)
	}
	data := buf.Bytes()
	i := bytes.Index(data, []byte("M\x08\x00\x00\x00"))
	if i < 0 {
		t.Fatal("no M parameter")
	}
	binary.LittleEndian.PutUint64(data[i+5:], 8<<40)
	if _, err := Import(FormatKDBX, data, Options{Passphrase: testPassphrase}); !errors.Is(err, ErrUnsupported) {
		t.Errorf("8 TiB of Argon2: %v", err)
	}
}
