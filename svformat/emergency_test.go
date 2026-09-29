package svformat

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func emergencySlot() *Slot {
	return &Slot{Format: SlotFormat, Vault: ID{1}, ID: ID{2}, Epoch: 1, Type: SlotEmergency, Label: "emergency", Grants: []string{GrantContent},
		Recipient: []byte{0xee}, Emergency: &Emergency{Grant: ID{0x0c}}, Wrapped: []byte{1}}
}

// An emergency slot's AAD carries its grant, byte for byte as format.md
// lays it out, after the fields every slot has.
func TestAnEmergencySlotsGrantIsInItsAAD(t *testing.T) {
	s := emergencySlot()
	want := "secretvault sv1 slot" +
		"\x01\x00\x10\x01" + strings.Repeat("\x00", 15) +
		"\x02\x00\x10\x02" + strings.Repeat("\x00", 15) +
		"\x03\x00\x04\x00\x00\x00\x01" +
		"\x04\x00\x09emergency" +
		"\x05\x00\x09emergency" +
		"\x06\x00\x07content" +
		"\x0c\x00\x10\x0c" + strings.Repeat("\x00", 15)
	if got := string(s.AAD()); got != want {
		t.Fatalf("AAD\n%q\nwant\n%q", got, want)
	}
	other := emergencySlot()
	other.Emergency.Grant = ID{0x0d}
	if bytes.Equal(other.AAD(), s.AAD()) {
		t.Fatal("the grant is not in the AAD")
	}
}

func TestEmergencySlotsAreChecked(t *testing.T) {
	good, err := json.Marshal(emergencySlot())
	if err != nil {
		t.Fatal(err)
	}
	s, err := ParseSlot(good)
	if err != nil || !bytes.Equal(s.AAD(), emergencySlot().AAD()) {
		t.Fatalf("a good slot: %v", err)
	}
	for name, change := range map[string]func(s *Slot){
		"no grant":             func(s *Slot) { s.Emergency = nil },
		"a zero grant":         func(s *Slot) { s.Emergency.Grant = ID{} },
		"no recipient":         func(s *Slot) { s.Recipient = nil },
		"another type with it": func(s *Slot) { s.Type = SlotRecipient },
	} {
		bad := emergencySlot()
		change(bad)
		b, _ := json.Marshal(bad)
		if _, err := ParseSlot(b); !errors.Is(err, ErrSlot) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestEmergencyInfosBindTheirGrant(t *testing.T) {
	a, b := ID{1}, ID{2}
	if bytes.Equal(EmergencyReleaseInfo(a, b), EmergencyReleaseInfo(b, a)) ||
		bytes.Equal(EmergencyChallengeInfo(a, b), EmergencyChallengeInfo(b, a)) ||
		bytes.Equal(EmergencyReleaseInfo(a, b), EmergencyChallengeInfo(a, b)) {
		t.Fatal("release and challenge infos are not distinct")
	}
	want := "secretvault sv1 emergency challenge\x01" + strings.Repeat("\x00", 15) + "\x02" + strings.Repeat("\x00", 15)
	if got := string(EmergencyChallengeInfo(a, b)); got != want {
		t.Fatalf("challenge info %q", got)
	}
}
