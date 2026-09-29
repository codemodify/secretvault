package svimport

import (
	"errors"
	"testing"

	"github.com/codemodify/secretvault/svcore"
)

func TestAnEncryptedAegisVaultOpensWithItsPassword(t *testing.T) {
	data := readFixture(t, "aegis-encrypted.json")
	if _, err := Import(FormatAegis, data, Options{}); !errors.Is(err, ErrPassphrase) {
		t.Errorf("without a password: %v", err)
	}
	if _, err := Import(FormatAegis, data, Options{Passphrase: []byte("wrong")}); !errors.Is(err, ErrWrongKey) {
		t.Errorf("with a wrong password: %v", err)
	}
	res := mustImport(t, FormatAegis, data, Options{Passphrase: testPassphrase, Prefix: "otp"})
	gh := item(t, res, "otp/Work/GitHub (ada@example.org)")
	if gh.Kind != "otp" || gh.Label != "GitHub (ada@example.org)" {
		t.Errorf("kind %q label %q", gh.Kind, gh.Label)
	}
	has(t, gh, "otp", svcore.FieldOTP,
		"otpauth://totp/GitHub:ada@example.org?algorithm=SHA256&digits=8&issuer=GitHub&period=60&secret=JBSWY3DPEHPK3PXP")
	has(t, gh, "notes", svcore.FieldText, "work account")
	has(t, item(t, res, "otp/Bank (ada)"), "otp", svcore.FieldOTP,
		"otpauth://hotp/Bank:ada?counter=7&issuer=Bank&secret=GEZDGNBVGY3TQOJQ")
	has(t, item(t, res, "otp/Steam (gaben)"), "otp", svcore.FieldOTP,
		"otpauth://totp/Steam:gaben?encoder=steam&issuer=Steam&secret=STEAMSTEAMSTEAM2")
	warned(t, res, "Old VPN (legacy)", "MOTP")
	if len(res.Items) != 3 {
		t.Errorf("%d items", len(res.Items))
	}
}

func TestAPlainAegisVaultImports(t *testing.T) {
	res := mustImport(t, FormatAegis, readFixture(t, "aegis-plain.json"), Options{})
	bob := item(t, res, "Personal/Google (Bob)")
	has(t, bob, "otp", svcore.FieldOTP, "otpauth://totp/Google:Bob?issuer=Google&secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	has(t, bob, "notes", svcore.FieldText, "Main account")
	warned(t, res, "Yandex (bob)", "YANDEX")
	warned(t, res, "Broken", "could not be read")
	if len(res.Items) != 1 {
		t.Errorf("%d items", len(res.Items))
	}
}
