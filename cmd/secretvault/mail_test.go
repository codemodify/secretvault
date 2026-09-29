package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svmail"
)

func TestMailInspectSaysWhoSignedAndWhetherYouKnowThem(t *testing.T) {
	h := newHarness(t)
	h.init()
	alice := newPGP(t, 6, "Alice Example <alice@example.org>")
	h.ok("", h.with("contact", "add", h.publicKeyFile("alice.asc", alice))...)
	h.ok("", h.with("contact", "verify", "Alice Example", "--fingerprint", fpHex(alice), "--in-person")...)

	msg := "From: Alice Example <alice@example.org>\r\nTo: me@example.org\r\nSubject: the plan\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nMeet at noon.\r\n"
	signed, err := svmail.SignPGPMIME([]byte(msg), alice, &svmail.ComposeOptions{ProtectHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	out := h.ok("", h.with("mail", "inspect", h.write("signed.eml", string(signed)))...)
	for _, want := range []string{"Signed: full", "signature: valid", "Alice Example's key, which you verified in person", "Meet at noon."} {
		if !strings.Contains(out, want) {
			t.Fatalf("inspect said:\n%s\nwithout %q", out, want)
		}
	}
	changed := bytes.Replace(signed, []byte("noon"), []byte("one."), 1)
	out = h.ok("", h.with("mail", "inspect", h.write("changed.eml", string(changed)))...)
	if !strings.Contains(out, "invalid") || strings.Contains(out, "signature: valid") {
		t.Fatalf("a changed message:\n%s", out)
	}
	if out := h.ok("", h.with("mail", "inspect", "--json", h.write("again.eml", string(signed)))...); !strings.Contains(out, `"verdicts"`) {
		t.Fatalf("--json:\n%s", out)
	}
}
