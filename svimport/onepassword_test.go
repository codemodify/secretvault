package svimport

import (
	"errors"
	"reflect"
	"testing"

	"github.com/codemodify/secretvault/svcore"
)

func onePUX(t *testing.T) []byte {
	return zipOf(t, map[string][]byte{
		"export.attributes": []byte(`{"version":3,"description":"1Password Unencrypted Export","createdAt":1585333569}`),
		"export.data":       readFixture(t, "1pux-export.data"),
		"files/o2xjvw2q5j2yx6rtpxfjdqopom___passport.png": []byte("png"),
	})
}

func TestA1PUXExportImportsWithVaultsAsFolders(t *testing.T) {
	res := mustImport(t, Format1PUX, onePUX(t), Options{Prefix: "1password"})
	db := item(t, res, "1password/Personal/Dropbox")
	if db.Kind != "login" || !reflect.DeepEqual(db.Tags, []string{"cloud", "storage"}) {
		t.Errorf("dropbox: %s %q", db.Kind, db.Tags)
	}
	has(t, db, "username", svcore.FieldText, "ada@example.org")
	has(t, db, "password", svcore.FieldConcealed, "most-secure-password-ever!")
	has(t, db, "url", svcore.FieldURL, "https://www.dropbox.com/")
	has(t, db, "url2", svcore.FieldURL, "https://api.dropbox.com/")
	has(t, db, "PIN", svcore.FieldConcealed, "12345")
	has(t, db, "otp", svcore.FieldOTP, "otpauth://totp/Dropbox:ada?issuer=Dropbox&secret=JBSWY3DPEHPK3PXP")
	has(t, db, "recovery", svcore.FieldEmail, "backup@example.org")
	has(t, db, "since", svcore.FieldText, "2021-02-26")
	has(t, db, "notes", svcore.FieldText, "This is a note. *bold*! _italic_!")
	hasNot(t, db, "remember")
	hasNot(t, db, "empty")
	warned(t, res, "history", "1password/Personal/Dropbox")

	visa := item(t, res, "1password/Personal/Visa")
	if visa.Kind != "card" {
		t.Errorf("card kind %q", visa.Kind)
	}
	has(t, visa, "cardholder", svcore.FieldText, "Ada Lovelace")
	has(t, visa, "number", svcore.FieldConcealed, "4111111111111111")
	has(t, visa, "cvv", svcore.FieldConcealed, "321")
	has(t, visa, "expiry", svcore.FieldText, "12/2026")
	has(t, visa, "brand", svcore.FieldText, "visa")

	ada := item(t, res, "1password/Personal/Ada")
	has(t, ada, "first_name", svcore.FieldText, "Ada")
	has(t, ada, "birth_date", svcore.FieldText, "2001-09-09")
	has(t, ada, "address", svcore.FieldText, "12 St James's Square")
	has(t, ada, "country", svcore.FieldText, "GB")
	has(t, ada, "email", svcore.FieldEmail, "ada@example.org")

	router := item(t, res, "1password/Personal/Router admin")
	if router.Kind != "password" {
		t.Errorf("a Password item became %q", router.Kind)
	}
	has(t, router, "password", svcore.FieldConcealed, "just-a-password")

	warned(t, res, "1password/Personal/Passport scan", "attachment")
	warned(t, res, "1 file")
	noItem(t, res, "1password/Personal/Deleted login")
	warned(t, res, "1 item in the trash")

	key := item(t, res, "1password/Work/deploy")
	if key.Kind != "ssh-key" || !reflect.DeepEqual(key.Tags, []string{"archived"}) {
		t.Errorf("ssh key: %s %q", key.Kind, key.Tags)
	}
	has(t, key, "public_key", svcore.FieldText, testSSHPublicKey)
	has(t, key, "key_type", svcore.FieldText, "ed25519")
	api := item(t, res, "1password/Work/CI token")
	if api.Kind != "api-key" {
		t.Errorf("an API credential became %q", api.Kind)
	}
	has(t, api, "credential", svcore.FieldConcealed, "tok_123")
}

func TestA1PUXExportDataFileAloneImports(t *testing.T) {
	res := mustImport(t, Format1PUX, readFixture(t, "1pux-export.data"), Options{})
	item(t, res, "Personal/Dropbox")
}

func TestA1PUXWithoutExportDataIsRefused(t *testing.T) {
	_, err := Import(Format1PUX, zipOf(t, map[string][]byte{"other.txt": []byte("x")}), Options{})
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("got %v", err)
	}
}
