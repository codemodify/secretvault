package svimport

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
)

func TestACXFDocumentImportsWithCollectionsAsFolders(t *testing.T) {
	res := mustImport(t, FormatCXF, readFixture(t, "cxf.json"), Options{})
	login := item(t, res, "Work/Example Login")
	if login.Kind != "login" || !reflect.DeepEqual(login.Tags, []string{"demo", "web"}) {
		t.Errorf("login: %s %q", login.Kind, login.Tags)
	}
	has(t, login, "username", svcore.FieldText, "ada")
	has(t, login, "password", svcore.FieldConcealed, "ex4mple-p4ss")
	has(t, login, "otp", svcore.FieldOTP, "otpauth://totp/Example:ada?algorithm=SHA256&issuer=Example&secret=JBSWY3DPEHPK3PXP")
	has(t, login, "url", svcore.FieldURL, "https://login.example.com")
	has(t, login, "url2", svcore.FieldURL, "https://example.com")
	has(t, login, "favourite colour", svcore.FieldConcealed, "blue")
	has(t, login, "recovery email", svcore.FieldEmail, "backup@example.org")
	has(t, login, "Security", svcore.FieldText, "42") // an unlabelled field takes its section's label
	has(t, login, "notes", svcore.FieldText, "created for the demo")
	// Its passkey is an item of its own.
	pk := item(t, res, "Work/Example Login passkey")
	if pk.Kind != "passkey" {
		t.Errorf("the passkey's kind %q", pk.Kind)
	}
	has(t, pk, "rp_id", svcore.FieldText, "example.com")
	has(t, pk, "username", svcore.FieldText, "ada")

	card := item(t, res, "Corporate card")
	if card.Kind != "card" {
		t.Errorf("card kind %q", card.Kind)
	}
	has(t, card, "number", svcore.FieldConcealed, "4111111111111111")
	has(t, card, "expiry", svcore.FieldText, "04/2028")
	has(t, card, "pin", svcore.FieldConcealed, "9876")

	key := item(t, res, "Work/Servers/build server key")
	if key.Kind != "ssh-key" {
		t.Errorf("ssh kind %q", key.Kind)
	}
	has(t, key, "private_key", svcore.FieldKey,
		"-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEIF3C5VoSK+HAlK8JXXAzeP+ABEeD6s1cc1+pW8lwEAJk\n-----END PRIVATE KEY-----\n")
	// The public key derived here matches what ssh-keygen -y derives.
	has(t, key, "public_key", svcore.FieldText, testSSHPublicKey)
	has(t, key, "comment", svcore.FieldText, "ada@build")
	has(t, key, "source", svcore.FieldText, "https://git.example/settings/keys")

	api := item(t, res, "Work/Servers/Deploy API")
	if api.Kind != "api-key" {
		t.Errorf("api kind %q", api.Kind)
	}
	has(t, api, "key", svcore.FieldConcealed, "sk_live_abc")
	has(t, api, "url", svcore.FieldURL, "https://api.example")

	wifi := item(t, res, "Home/Home network")
	has(t, wifi, "password", svcore.FieldConcealed, "w1f1")
	has(t, wifi, "security", svcore.FieldText, "wpa3-personal")

	me := item(t, res, "Me")
	if me.Kind != "identity" {
		t.Errorf("identity kind %q", me.Kind)
	}
	has(t, me, "last_name", svcore.FieldText, "van der Lovelace")
	has(t, me, "address", svcore.FieldText, "12 St James's Square\nFlat 2")
	has(t, me, "passport_number", svcore.FieldConcealed, "P1234567")
	has(t, me, "passport_expires", svcore.FieldText, "2030-01-31")

	otp := item(t, res, "Authenticator only")
	if otp.Kind != "otp" {
		t.Errorf("an item holding only a TOTP key became %q", otp.Kind)
	}
	has(t, otp, "otp", svcore.FieldOTP, "otpauth://totp/Bank:?digits=8&issuer=Bank&period=60&secret=GEZDGNBVGY3TQOJQ")

	warned(t, res, "Future", "quantum-token")
	warned(t, res, "Future", "attachment")
}

func TestANewerCXFMajorVersionIsRefused(t *testing.T) {
	_, err := Import(FormatCXF, []byte(`{"version":{"major":2,"minor":0},"accounts":[]}`), Options{})
	if !errors.Is(err, ErrUnsupported) {
		t.Fatalf("got %v", err)
	}
}

func TestCXFExportsRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	if err := ExportCXF(sampleItems(), &buf); err != nil {
		t.Fatal(err)
	}
	// The document follows the spec's shape: required arrays present, a
	// credential per kind of data.
	var doc map[string]any
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	acct := doc["accounts"].([]any)[0].(map[string]any)
	if _, ok := acct["collections"].([]any); !ok {
		t.Error("the account has no collections array")
	}
	types := map[string]bool{}
	for _, it := range acct["items"].([]any) {
		for _, c := range it.(map[string]any)["credentials"].([]any) {
			types[c.(map[string]any)["type"].(string)] = true
		}
	}
	for _, want := range []string{"basic-auth", "totp", "note", "credit-card", "ssh-key", "custom-fields"} {
		if !types[want] {
			t.Errorf("no %s credential in the export", want)
		}
	}
	if !strings.Contains(buf.String(), `"privateKey": "MC4CAQAwBQYDK2VwBCIEIF3C5VoSK-HAlK8JXXAzeP-ABEeD6s1cc1-pW8lwEAJk"`) {
		t.Error("the OpenSSH key was not written as PKCS#8, as the fixture made by openssl has it")
	}

	res := mustImport(t, FormatCXF, buf.Bytes(), Options{Prefix: "back"})
	if len(res.Warnings) != 0 {
		t.Errorf("warnings: %q", res.Warnings)
	}
	back := map[string]map[string]string{}
	for _, it := range res.Items {
		fields := map[string]string{}
		for _, f := range it.Fields {
			fields[f.Name] = f.Type + " " + string(f.Value)
		}
		back[strings.TrimPrefix(it.Name, "back/")] = fields
		want := sampleItems()
		for _, w := range want {
			if "back/"+w.Name == it.Name && (it.Kind != w.Kind || !reflect.DeepEqual(it.Tags, w.Tags) || !reflect.DeepEqual(it.Attrs, w.Attrs)) {
				t.Errorf("%s: kind %q tags %q attrs %v; want %q %q %v", w.Name, it.Kind, it.Tags, it.Attrs, w.Kind, w.Tags, w.Attrs)
			}
		}
	}
	// Every field comes back with its value; types may be coarser
	// (a key file in PKCS#8 PEM, custom fields as text or concealed).
	for _, w := range sampleItems() {
		got, ok := back[w.Name]
		if !ok {
			t.Errorf("%s did not come back", w.Name)
			continue
		}
		for _, f := range w.Fields {
			g, ok := got[f.Name]
			switch {
			case !ok:
				t.Errorf("%s: field %s did not come back (have %v)", w.Name, f.Name, got)
			case f.Name == "private_key":
				if !strings.HasPrefix(g, "key -----BEGIN PRIVATE KEY-----") {
					t.Errorf("%s: private key came back as %q", w.Name, g)
				}
			case !strings.HasSuffix(g, " "+string(f.Value)):
				t.Errorf("%s: field %s = %q, want value %q", w.Name, f.Name, g, f.Value)
			}
		}
	}
	if got := back["otp/Bank (ada)"]["otp"]; !strings.HasPrefix(got, "otp otpauth://hotp/") {
		t.Errorf("an HOTP key, which CXF's totp cannot hold, came back as %q", got)
	}
	if got := back["web/github.com"]["otp"]; !strings.HasPrefix(got, "otp otpauth://totp/") {
		t.Errorf("a TOTP key came back as %q", got)
	}
	if got := back["odd/raw"]["blob"]; got != "binary "+string([]byte{0, 1, 2, 0xff, 0xfe}) {
		t.Errorf("a binary field came back as %q", got)
	}
}
