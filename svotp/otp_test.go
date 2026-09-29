package svotp

import (
	"strings"
	"testing"
	"time"
)

func TestHOTPMatchesRFC4226(t *testing.T) {
	k := &Key{Type: "hotp", Secret: []byte("12345678901234567890"), Algorithm: "SHA1", Digits: 6}
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got := k.HOTP(uint64(i)); got != w {
			t.Errorf("HOTP(%d) = %s, want %s", i, got, w)
		}
	}
}

func TestTOTPMatchesRFC6238(t *testing.T) {
	seeds := map[string]string{
		"SHA1":   "12345678901234567890",
		"SHA256": "12345678901234567890123456789012",
		"SHA512": "1234567890123456789012345678901234567890123456789012345678901234",
	}
	vectors := []struct {
		t    int64
		want map[string]string
	}{
		{59, map[string]string{"SHA1": "94287082", "SHA256": "46119246", "SHA512": "90693936"}},
		{1111111109, map[string]string{"SHA1": "07081804", "SHA256": "68084774", "SHA512": "25091201"}},
		{1111111111, map[string]string{"SHA1": "14050471", "SHA256": "67062674", "SHA512": "99943326"}},
		{1234567890, map[string]string{"SHA1": "89005924", "SHA256": "91819424", "SHA512": "93441116"}},
		{2000000000, map[string]string{"SHA1": "69279037", "SHA256": "90698825", "SHA512": "38618901"}},
		{20000000000, map[string]string{"SHA1": "65353130", "SHA256": "77737706", "SHA512": "47863826"}},
	}
	for _, v := range vectors {
		for alg, want := range v.want {
			k := &Key{Type: "totp", Secret: []byte(seeds[alg]), Algorithm: alg, Digits: 8, Period: 30}
			if got, _ := k.Code(time.Unix(v.t, 0)); got != want {
				t.Errorf("%s at %d = %s, want %s", alg, v.t, got, want)
			}
		}
	}
}

func TestURIsRoundTripAndForgiveSloppySecrets(t *testing.T) {
	uri := "otpauth://totp/Example:alice@example.com?secret=JBSW Y3DP-EHPK 3PXP&issuer=Example&period=60&digits=8&algorithm=sha256"
	k, err := Parse(uri)
	if err != nil {
		t.Fatal(err)
	}
	if k.Issuer != "Example" || k.Account != "alice@example.com" || k.Period != 60 || k.Digits != 8 || k.Algorithm != "SHA256" || string(k.Secret) != "Hello!\xde\xad\xbe\xef" {
		t.Fatalf("parsed %+v", k)
	}
	again, err := Parse(k.URI())
	if err != nil || again.URI() != k.URI() {
		t.Fatalf("round trip: %v\n%s\n%s", err, k.URI(), again.URI())
	}
	_, left := k.Code(time.Unix(61, 0))
	if left != 59*time.Second {
		t.Fatalf("remaining = %v", left)
	}
}

func TestSteamCodesUseSteamsAlphabet(t *testing.T) {
	k, err := Parse("otpauth://totp/Steam:gamer?secret=JBSWY3DPEHPK3PXP&issuer=Steam")
	if err != nil {
		t.Fatal(err)
	}
	code, _ := k.Code(time.Unix(1700000000, 0))
	if len(code) != 5 || strings.Trim(code, steamAlphabet) != "" {
		t.Fatalf("steam code %q", code)
	}
	if !strings.Contains(k.URI(), "encoder=steam") {
		t.Fatalf("URI lost the Steam encoder: %s", k.URI())
	}
}

func TestBadKeysAreRefused(t *testing.T) {
	for _, bad := range []string{
		"https://example.com",
		"otpauth://sms/x?secret=JBSWY3DP",
		"otpauth://totp/x",
		"otpauth://totp/x?secret=not*base32",
		"otpauth://totp/x?secret=JBSWY3DP&algorithm=MD5",
		"otpauth://totp/x?secret=JBSWY3DP&digits=3",
		"otpauth://totp/x?secret=JBSWY3DP&period=0",
	} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestAFieldHoldsAURIOrABareSeed(t *testing.T) {
	uri, err := ParseField([]byte(" otpauth://totp/x?secret=JBSWY3DPEHPK3PXP&digits=8\n"))
	if err != nil || uri.Digits != 8 {
		t.Fatalf("a URI field: %+v, %v", uri, err)
	}
	seed, err := ParseField([]byte("jbsw y3dp ehpk 3pxp"))
	if err != nil || seed.Type != "totp" || seed.Digits != 6 || seed.Period != 30 || seed.Algorithm != "SHA1" {
		t.Fatalf("a bare seed: %+v, %v", seed, err)
	}
	if _, err := ParseField([]byte("no key here!")); err == nil {
		t.Fatal("a field without a key parsed")
	}
}
