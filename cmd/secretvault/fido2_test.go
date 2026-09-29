package main

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/fidotest"
)

// slowTouch is a person who touches the key after a moment, so it says it
// waits for the touch, and the CLI says to touch it.
func slowTouch(ctx context.Context) error {
	select {
	case <-time.After(40 * time.Millisecond):
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func TestASecurityKeyFromTheCommandLine(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.ok("v", h.with("set", "x")...)
	key := h.plug(fidotest.Options{Name: "YubiKey 5", PIN: "123456", Touch: slowTouch, Keepalive: 10 * time.Millisecond})

	// secretvault slot add fido2: the PIN is typed here, and the touches
	// asked for here.
	h.answers = []string{"123456"}
	out, errs, code := h.run("", h.with("slot", "add", "fido2")...)
	if code != 0 {
		t.Fatalf("slot add fido2: %d\n%s", code, errs)
	}
	if !strings.Contains(out, "Added fido2 slot") || !strings.Contains(out, "YubiKey 5 opens the vault with: PIN and touch") {
		t.Fatalf("slot add said:\n%s", out)
	}
	for _, want := range []string{"Enter the PIN of your security key (YubiKey 5)", "8 more wrong PINs",
		"Touch your security key to add it to the vault (1 of 2). (YubiKey 5)", "Touch your security key again to finish (2 of 2)."} {
		if !strings.Contains(errs, want) {
			t.Errorf("the terminal was not told %q:\n%s", want, errs)
		}
	}
	if list := h.ok("", "slot", "list"); !strings.Contains(list, "fido2") || !strings.Contains(list, "YubiKey 5") || !strings.Contains(list, "PIN and touch") {
		t.Fatalf("slot list:\n%s", list)
	}

	// secretvault unlock --fido2, and a wrong PIN on the way.
	h.ok("", "lock")
	h.answers = []string{"000000", "123456"}
	_, errs, code = h.run("", "unlock", "--fido2")
	if code != 0 || !strings.Contains(errs, "! Wrong PIN. 7 tries left") {
		t.Fatalf("unlock --fido2: %d\n%s", code, errs)
	}
	if key.Retries() != 8 {
		t.Fatalf("the right PIN left %d tries", key.Retries())
	}

	// Any command takes --fido2, and a plain unlock tries the key first.
	h.ok("", "lock")
	h.answers = []string{"123456"}
	if got := h.ok("", "get", "x", "--fido2"); got != "v\n" {
		t.Fatalf("get --fido2 = %q", got)
	}
	h.ok("", "lock")
	h.answers = []string{"123456"}
	h.ok("", "unlock")
	if len(h.answers) != 0 {
		t.Fatal("unlock did not ask for the key's PIN")
	}
}

func TestSlotAddFIDO2Flags(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.plug(fidotest.Options{Name: "Solo", PIN: "1234"})
	for args, want := range map[string]string{
		"fido2 --uv --no-uv": "contradict",
		"keyfile f --no-uv":  "are for fido2 slots",
		"fido2 extra":        "takes no argument",
	} {
		if _, errs, code := h.run("", h.with(append([]string{"slot", "add"}, strings.Fields(args)...)...)...); code == 0 || !strings.Contains(errs, want) {
			t.Errorf("slot add %s: %d %q", args, code, errs)
		}
	}
	// --no-uv: no PIN, now or later.
	out := h.ok("", h.with("slot", "add", "fido2", "--no-uv", "--label", "desk key")...)
	if !strings.Contains(out, "desk key opens the vault with: touch,") {
		t.Fatalf("--no-uv: %s", out)
	}
	h.ok("", "lock")
	h.ok("", "unlock", "--fido2") // nothing is typed

	// A rotation says the key has to be added again.
	out = h.ok("", h.with("vault", "rotate", "--new-passphrase-file", h.passFile)...)
	if !strings.Contains(out, "No longer opening it") || !strings.Contains(out, "desk key (fido2)") {
		t.Fatalf("rotate said:\n%s", out)
	}
}

func TestFIDO2ListShowsWhatEachKeyCanDo(t *testing.T) {
	h := newHarness(t)
	if out := h.ok("", "fido2"); !strings.Contains(out, "No security key is plugged in.") {
		t.Fatalf("none: %s", out)
	}
	h.plug(fidotest.Options{Name: "YubiKey 5", PIN: "1234"})
	h.plug(fidotest.Options{Name: "Old key", CTAP20: true, NoHMAC: true})
	out := h.ok("", "fido2", "list")
	for _, want := range []string{"YubiKey 5\n", "FIDO_2_0, FIDO_2_1", "PIN:         set, 8 tries left", "hmac-secret: yes",
		"Old key\n", "PIN:         not set", "hmac-secret: no", "problem:     the security key does not support hmac-secret"} {
		if !strings.Contains(out, want) {
			t.Errorf("fido2 list lacks %q:\n%s", want, out)
		}
	}
}
