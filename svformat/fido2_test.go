package svformat

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func fido2Slot() *Slot {
	return &Slot{Format: SlotFormat, Vault: ID{1}, ID: ID{2}, Epoch: 1, Type: SlotFIDO2, Label: "key", Grants: []string{GrantContent},
		FIDO2: &FIDO2{RPID: FIDO2RPID, Credential: []byte{0xc1, 0xc2}, Salt: bytes.Repeat([]byte{0x5a}, 32), UV: true,
			AAGUID: bytes.Repeat([]byte{0xaa}, 16)},
		Wrapped: []byte{1}}
}

// A fido2 slot's AAD carries its credential, byte for byte as format.md
// lays it out, after the fields every slot has.
func TestAFIDO2SlotsCredentialIsInItsAAD(t *testing.T) {
	s := fido2Slot()
	want := "secretvault sv1 slot" +
		"\x01\x00\x10\x01" + strings.Repeat("\x00", 15) +
		"\x02\x00\x10\x02" + strings.Repeat("\x00", 15) +
		"\x03\x00\x04\x00\x00\x00\x01" +
		"\x04\x00\x05fido2" +
		"\x05\x00\x03key" +
		"\x06\x00\x07content" +
		"\x07\x00\x0csecretvault:" +
		"\x08\x00\x02\xc1\xc2" +
		"\x09\x00\x20" + strings.Repeat("\x5a", 32) +
		"\x0a\x00\x01\x01" +
		"\x0b\x00\x10" + strings.Repeat("\xaa", 16)
	if got := string(s.AAD()); got != want {
		t.Fatalf("AAD\n%q\nwant\n%q", got, want)
	}
	for name, change := range map[string]func(f *FIDO2){
		"rp":         func(f *FIDO2) { f.RPID = "other:" },
		"credential": func(f *FIDO2) { f.Credential = []byte{0xc1, 0xc3} },
		"salt":       func(f *FIDO2) { f.Salt = bytes.Repeat([]byte{0x5b}, 32) },
		"uv":         func(f *FIDO2) { f.UV = false },
		"aaguid":     func(f *FIDO2) { f.AAGUID = bytes.Repeat([]byte{0xab}, 16) },
	} {
		s2 := fido2Slot()
		change(s2.FIDO2)
		if bytes.Equal(s2.AAD(), s.AAD()) {
			t.Errorf("the %s is not in the AAD", name)
		}
	}
	// Other slots' AAD is as it always was.
	p := &Slot{Vault: ID{1}, ID: ID{2}, Epoch: 1, Type: SlotPassphrase, Label: "key", Grants: []string{GrantContent}}
	if !strings.HasSuffix(string(p.AAD()), "\x06\x00\x07content") {
		t.Fatal("a passphrase slot's AAD grew")
	}
}

func TestFIDO2SlotsAreChecked(t *testing.T) {
	good, err := json.Marshal(fido2Slot())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseSlot(good)
	if err != nil || !bytes.Equal(s.AAD(), fido2Slot().AAD()) {
		t.Fatalf("a good slot: %v", err)
	}
	for name, change := range map[string]func(s *Slot){
		"no credential":        func(s *Slot) { s.FIDO2 = nil },
		"no rp":                func(s *Slot) { s.FIDO2.RPID = "" },
		"an empty credential":  func(s *Slot) { s.FIDO2.Credential = nil },
		"a huge credential":    func(s *Slot) { s.FIDO2.Credential = make([]byte, 1024) },
		"a short salt":         func(s *Slot) { s.FIDO2.Salt = s.FIDO2.Salt[:31] },
		"a short aaguid":       func(s *Slot) { s.FIDO2.AAGUID = s.FIDO2.AAGUID[:15] },
		"another type with it": func(s *Slot) { s.Type = SlotKeyfile },
	} {
		bad := fido2Slot()
		change(bad)
		b, _ := json.Marshal(bad)
		if _, err := ParseSlot(b); !errors.Is(err, ErrSlot) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestFIDO2SaltIsWebAuthnsPRFTransform(t *testing.T) {
	salt := bytes.Repeat([]byte{7}, 32)
	want := sha256.Sum256(append([]byte("WebAuthn PRF\x00"), salt...))
	if got := FIDO2Salt(salt); !bytes.Equal(got, want[:]) {
		t.Fatalf("FIDO2Salt = %x", got)
	}
}
