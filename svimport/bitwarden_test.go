package svimport

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
)

func TestABitwardenExportImportsEveryItemType(t *testing.T) {
	res := mustImport(t, FormatBitwarden, readFixture(t, "bitwarden.json"), Options{})
	gh := item(t, res, "Personal/GitHub")
	if gh.Kind != "login" {
		t.Errorf("kind %q", gh.Kind)
	}
	has(t, gh, "username", svcore.FieldText, "ada")
	has(t, gh, "password", svcore.FieldConcealed, "gh-p4ss")
	has(t, gh, "url", svcore.FieldURL, "https://github.com/login")
	has(t, gh, "url2", svcore.FieldURL, "https://gist.github.com")
	has(t, gh, "otp", svcore.FieldOTP, "otpauth://totp/GitHub:ada?issuer=GitHub&secret=JBSWY3DPEHPK3PXP")
	has(t, gh, "notes", svcore.FieldText, "personal account")
	has(t, gh, "recovery email", svcore.FieldText, "ada@example.org")
	has(t, gh, "API token", svcore.FieldConcealed, "ghp_0123456789")
	has(t, gh, "2FA on", svcore.FieldText, "true")
	hasNot(t, gh, "user alias") // a linked field has no value of its own
	warned(t, res, "Personal/GitHub", "passkey")
	warned(t, res, "history", "Personal/GitHub")
	// The same name twice in one folder.
	has(t, item(t, res, "Personal/GitHub (2)"), "username", svcore.FieldText, "ada-work")

	has(t, item(t, res, "Work/Servers/db1"), "otp", svcore.FieldOTP,
		"otpauth://totp/Steam:root?encoder=steam&issuer=Steam&secret=STEAMSTEAMSTEAM2")
	if n := item(t, res, "Wifi"); n.Kind != "note" {
		t.Errorf("secure note kind %q", n.Kind)
	}
	has(t, item(t, res, "Wifi"), "notes", svcore.FieldText, "SSID home\npassword on the router")

	visa := item(t, res, "Visa")
	if visa.Kind != "card" {
		t.Errorf("card kind %q", visa.Kind)
	}
	has(t, visa, "cardholder", svcore.FieldText, "Ada Lovelace")
	has(t, visa, "number", svcore.FieldConcealed, "4111111111111111")
	has(t, visa, "expiry", svcore.FieldText, "01/2029")
	has(t, visa, "cvv", svcore.FieldConcealed, "321")
	has(t, visa, "brand", svcore.FieldText, "Visa")

	me := item(t, res, "Me")
	if me.Kind != "identity" {
		t.Errorf("identity kind %q", me.Kind)
	}
	has(t, me, "first_name", svcore.FieldText, "Ada")
	has(t, me, "last_name", svcore.FieldText, "Lovelace")
	has(t, me, "address", svcore.FieldText, "12 St James's Square\nFlat 2")
	has(t, me, "email", svcore.FieldEmail, "ada@example.org")
	has(t, me, "ssn", svcore.FieldConcealed, "123-45-6789")
	has(t, me, "passport_number", svcore.FieldConcealed, "P1234567")
	hasNot(t, me, "license_number")

	key := item(t, res, "deploy key")
	if key.Kind != "ssh-key" {
		t.Errorf("ssh key kind %q", key.Kind)
	}
	has(t, key, "private_key", svcore.FieldKey, testOpenSSHKey)
	has(t, key, "public_key", svcore.FieldText, testSSHPublicKey)

	noItem(t, res, "Old site")
	warned(t, res, "1 item in the trash")
	future := item(t, res, "From the future")
	if future.Kind != "generic" {
		t.Errorf("an unknown type became %q", future.Kind)
	}
	has(t, future, "code", svcore.FieldConcealed, "1234")
	warned(t, res, "From the future", "type 42")
}

func TestAnOrganisationExportUsesCollectionsAsFolders(t *testing.T) {
	data := `{"encrypted":false,"collections":[{"id":"c1","organizationId":"o","name":"Shared/Ops"}],
		"items":[{"type":1,"name":"pager","collectionIds":["c1"],"login":{"username":"ops","password":"p"}}]}`
	res := mustImport(t, FormatBitwarden, []byte(data), Options{Prefix: "bw"})
	has(t, item(t, res, "bw/Shared/Ops/pager"), "username", svcore.FieldText, "ops")
}

func TestPasswordProtectedBitwardenExportsOpen(t *testing.T) {
	for _, file := range []string{"bitwarden-encrypted-pbkdf2.json", "bitwarden-encrypted-argon2id.json"} {
		data := readFixture(t, file)
		if _, err := Import(FormatBitwarden, data, Options{}); !errors.Is(err, ErrPassphrase) {
			t.Errorf("%s without a password: %v", file, err)
		}
		if _, err := Import(FormatBitwarden, data, Options{Passphrase: []byte("wrong")}); !errors.Is(err, ErrWrongKey) {
			t.Errorf("%s with a wrong password: %v", file, err)
		}
		res := mustImport(t, FormatBitwarden, data, Options{Passphrase: testPassphrase})
		db := item(t, res, "Work/Servers/db.example")
		has(t, db, "password", svcore.FieldConcealed, "pg-secret")
		has(t, db, "root pw", svcore.FieldConcealed, "hunter22")
		has(t, db, "otp", svcore.FieldOTP, "otpauth://totp/db.example:dba?issuer=db.example&secret=JBSWY3DPEHPK3PXP")
		has(t, item(t, res, "Visa"), "expiry", svcore.FieldText, "07/2031")
		if !reflect.DeepEqual(len(res.Items), 2) {
			t.Errorf("%s: %d items", file, len(res.Items))
		}
	}
}

func TestNumbersWhereStringsBelongAreTaken(t *testing.T) {
	data := `{"items":[{"type":3,"name":"card","card":{"number":4111111111111111,"expMonth":7,"expYear":2031,"code":null}}]}`
	res := mustImport(t, FormatBitwarden, []byte(data), Options{})
	has(t, item(t, res, "card"), "number", svcore.FieldConcealed, "4111111111111111")
	has(t, item(t, res, "card"), "expiry", svcore.FieldText, "07/2031")
}

func TestJSONErrorsDoNotQuoteTheFile(t *testing.T) {
	for _, data := range []string{
		`{"items":[{"type":"one","name":"s3cr3t-value"}]}`,
		`{"items":[{"name":"s3cr3t-value" "x"}]}`,
	} {
		_, err := Import(FormatBitwarden, []byte(data), Options{})
		if !errors.Is(err, ErrFormat) || strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "one") {
			t.Errorf("got %v", err)
		}
	}
}

func TestAnAccountRestrictedBitwardenExportIsExplained(t *testing.T) {
	data := `{"encrypted":true,"encKeyValidation_DO_NOT_EDIT":"2.a|b|c","folders":[],"items":[]}`
	_, err := Import(FormatBitwarden, []byte(data), Options{Passphrase: testPassphrase})
	if !errors.Is(err, ErrUnsupported) || !strings.Contains(err.Error(), "password protected") {
		t.Fatalf("got %v", err)
	}
}
