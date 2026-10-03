package svops

import (
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// The managers' words about vaults say what happens in plain words: no
// internal names, epochs or raw decisions lead a sentence.
func TestVaultWordsArePlain(t *testing.T) {
	title, summary, details, ok := VerifyReport("work", svrpc.VerifyResult{Live: 3, Objects: 9, Revisions: 4})
	if !ok || title != "Vault work is sound" || !strings.HasPrefix(summary, "Every file of vault work") || strings.Contains(summary, "objects") {
		t.Errorf("a sound vault: %q %q %v", title, summary, ok)
	}
	if len(details) != 1 || !strings.Contains(details[0], "9 objects") {
		t.Errorf("the details: %q", details)
	}
	_, summary, details, ok = VerifyReport("work", svrpc.VerifyResult{Problems: []string{"x: bad tag"}, Duplicates: map[string][]string{"a": {"1", "2"}}})
	if ok || !strings.Contains(summary, "some files are damaged") || !strings.Contains(summary, "more than one item") ||
		!strings.Contains(strings.Join(details, "\n"), "problem: x: bad tag") {
		t.Errorf("a vault that needs attention: %q %q", summary, details)
	}

	res := svrpc.RotateResult{Epoch: 7, Slots: []svrpc.SlotInfo{{ID: "s1", Type: svformat.SlotPassphrase}},
		Dropped: []svrpc.SlotInfo{{ID: "s2", Type: svformat.SlotFIDO2, Label: "desk"}}}
	if s := RotateDone("work", res, 0); strings.Contains(s, "epoch") || !strings.Contains(s, "1 keyslot no longer opens it") {
		t.Errorf("RotateDone: %q", s)
	}
	if d := strings.Join(RotateDetails(res), "\n"); !strings.Contains(d, "Key epoch: 7") || !strings.Contains(d, "desk (security key)") {
		t.Errorf("RotateDetails: %q", d)
	}
	if s := RotateDone("work", svrpc.RotateResult{}, 1); !strings.Contains(s, "The one cut off can no longer open it.") {
		t.Errorf("RotateDone, cutting off: %q", s)
	}
	if s := RotateIntro(1); !strings.Contains(s, "except the one being cut off") {
		t.Errorf("RotateIntro: %q", s)
	}

	s := svrpc.SlotInfo{Type: svformat.SlotKeyfile, Label: "usb"}
	if got := RemoveSlotText("work", s); !strings.HasPrefix(got, `The keyfile "usb" will no longer open vault work.`) {
		t.Errorf("RemoveSlotText: %q", got)
	}
	if got := SlotPhrase(svrpc.SlotInfo{Type: svformat.SlotRecipient}); got != "the key of a person or device" {
		t.Errorf("SlotPhrase: %q", got)
	}
	for _, k := range SlotKinds {
		if a := SlotAddAction(k.Type); a == "Add it" || a == "Add" {
			t.Errorf("%s: the button %q does not say what it adds", k.Type, a)
		}
	}

	g := svrpc.Grant{Program: "git (/usr/bin/git)", Item: "web/github.com", Ops: []string{"read", "list"}, Decision: "allow-until-lock"}
	if got := GrantDecided(g); got != "git (/usr/bin/git) may read and list item web/github.com until the vault locks." {
		t.Errorf("GrantDecided: %q", got)
	}
	g = svrpc.Grant{Program: "curl", Ops: []string{"read", "write"}, Decision: "deny-always"}
	if got := GrantDecided(g); got != "curl may never read or write the whole vault." {
		t.Errorf("GrantDecided: %q", got)
	}
	if DecisionText("allow-always") != "always allowed" {
		t.Error("DecisionText")
	}

	for _, c := range []struct {
		q    svrpc.PromptAsk
		want string
	}{
		{svrpc.PromptAsk{Kind: svrpc.PromptPassphrase, Title: "Unlock vault work"}, "Unlock"},
		{svrpc.PromptAsk{Kind: svrpc.PromptPassphrase, Title: "Allow secretvault-gui"}, "Allow"},
		{svrpc.PromptAsk{Kind: svrpc.PromptNewPassphrase}, "Set the passphrase"},
		{svrpc.PromptAsk{Kind: svrpc.PromptPIN, Title: "Security key PIN"}, "Continue"},
	} {
		if got := PromptAction(c.q); got != c.want {
			t.Errorf("PromptAction(%+v) = %q, want %q", c.q, got, c.want)
		}
	}
}
