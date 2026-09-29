package svimport

import (
	"errors"
	"testing"

	"github.com/codemodify/secretvault/svcore"
)

func TestAProtonPassExportImportsEveryItemType(t *testing.T) {
	data := zipOf(t, map[string][]byte{
		"Proton Pass/data.json":         readFixture(t, "protonpass-data.json"),
		"Proton Pass/files/receipt.pdf": []byte("%PDF"),
	})
	res := mustImport(t, FormatProtonPass, data, Options{})
	if res.Items[0].Name != "Personal/Proton" {
		t.Errorf("vaults are not read in name order: first is %s", res.Items[0].Name)
	}
	p := item(t, res, "Personal/Proton")
	if p.Kind != "login" {
		t.Errorf("kind %q", p.Kind)
	}
	has(t, p, "username", svcore.FieldText, "ada")
	has(t, p, "email", svcore.FieldEmail, "ada@proton.me")
	has(t, p, "password", svcore.FieldConcealed, "pr0t0n")
	has(t, p, "url", svcore.FieldURL, "https://account.proton.me")
	has(t, p, "url2", svcore.FieldURL, "https://mail.proton.me")
	has(t, p, "otp", svcore.FieldOTP, "otpauth://totp/Proton:ada?issuer=Proton&secret=JBSWY3DPEHPK3PXP")
	has(t, p, "second factor", svcore.FieldOTP, "otpauth://totp/Other:ada?issuer=Other&secret=GEZDGNBVGY3TQOJQ")
	has(t, p, "recovery phrase", svcore.FieldConcealed, "alpha beta gamma")
	has(t, p, "plan", svcore.FieldText, "unlimited")
	has(t, p, "renewal", svcore.FieldText, "1700000000")
	has(t, p, "notes", svcore.FieldText, "my account")
	warned(t, res, "Personal/Proton", "passkey")

	if n := item(t, res, "Personal/Door code"); n.Kind != "note" {
		t.Errorf("note kind %q", n.Kind)
	}
	card := item(t, res, "Personal/Mastercard")
	has(t, card, "number", svcore.FieldConcealed, "5555555555554444")
	has(t, card, "cvv", svcore.FieldConcealed, "999")
	has(t, card, "expiry", svcore.FieldText, "03/2027")
	has(t, card, "pin", svcore.FieldConcealed, "0000")
	me := item(t, res, "Personal/Me")
	has(t, me, "full_name", svcore.FieldText, "Ada Lovelace")
	has(t, me, "ssn", svcore.FieldConcealed, "AB123456C")
	has(t, me, "postal_code", svcore.FieldText, "SW1Y 4JH")
	has(t, me, "xHandle", svcore.FieldText, "@ada")
	has(t, me, "favourite engine", svcore.FieldText, "analytical")
	has(t, me, "locker", svcore.FieldConcealed, "L-12")
	has(t, item(t, res, "Personal/Shop alias"), "username", svcore.FieldText, "shop.xyz@passmail.net")
	wifi := item(t, res, "Personal/Home wifi")
	has(t, wifi, "ssid", svcore.FieldText, "home")
	has(t, wifi, "password", svcore.FieldConcealed, "w1f1-p4ss")
	custom := item(t, res, "Personal/Bank account")
	has(t, custom, "IBAN", svcore.FieldText, "GB00 0000")
	has(t, custom, "PIN", svcore.FieldConcealed, "2468")
	key := item(t, res, "Work/deploy")
	if key.Kind != "ssh-key" {
		t.Errorf("ssh key kind %q", key.Kind)
	}
	has(t, key, "public_key", svcore.FieldText, testSSHPublicKey)
	has(t, key, "host", svcore.FieldText, "git.example")
	noItem(t, res, "Personal/Trashed")
	warned(t, res, "1 item in the trash")
	warned(t, res, "1 attached file")
}

func TestAProtonPassDataJSONAloneImports(t *testing.T) {
	res := mustImport(t, FormatProtonPass, readFixture(t, "protonpass-data.json"), Options{})
	item(t, res, "Work/deploy")
}

func TestAnEncryptedProtonPassExportWaitsForOpenPGP(t *testing.T) {
	for _, data := range [][]byte{
		[]byte("-----BEGIN PGP MESSAGE-----\n\nwy4ECQMIxyz\n-----END PGP MESSAGE-----\n"),
		zipOf(t, map[string][]byte{"Proton Pass/data.json": []byte(`{"version":"1","userId":"u","encrypted":true,"vaults":{}}`)}),
	} {
		if _, err := Import(FormatProtonPass, data, Options{}); !errors.Is(err, ErrOpenPGP) {
			t.Errorf("got %v", err)
		}
	}
}
