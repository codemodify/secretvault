package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/internal/webauthntest"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svrpc"
)

// Passkeys through the extension's host to a real daemon: made and kept
// in the vault, signed with in the daemon, each step decided by the
// broker, and checked by a relying party written apart
// (internal/webauthntest).

func clientData(typ, origin string, challenge []byte) string {
	cd := `{"type":"` + typ + `","challenge":"` + svext.B64.EncodeToString(challenge) + `","origin":"` + origin + `","crossOrigin":false}`
	return cd
}

func b64(s string) string { return svext.B64.EncodeToString([]byte(s)) }

func unb64(t *testing.T, v any) []byte {
	t.Helper()
	s, _ := v.(string)
	b, err := svext.UnB64(s)
	if err != nil {
		t.Fatalf("not base64url: %v", v)
	}
	return b
}

func TestPasskeysAreMadeKeptAndSignedWithInTheDaemon(t *testing.T) {
	h, _ := browserHarness(t)
	x := startOwnExtension(t, h)
	rp := &webauthntest.RP{ID: "example.com", Origin: "https://login.example.com"}

	// Saving a passkey is a write, asked about.
	ch := webauthntest.Challenge()
	cd := clientData("webauthn.create", rp.Origin, ch)
	asked := h.desk.count()
	h.desk.answer(svrpc.ChoiceOnce, "")
	r := x.ask("passkey-create", map[string]any{"origin": rp.Origin, "rpId": rp.ID, "rpName": "Example", "user": b64("u-1"),
		"userName": "ada@example.com", "userDisplayName": "Ada", "algorithms": []int{-257, -7}, "clientData": b64(cd)})
	if r["ok"] != true {
		t.Fatalf("create: %v", r)
	}
	if q := h.desk.questions()[asked]; !strings.Contains(q, `wants to save a new passkey "passkeys/example.com" for example.com (account "ada@example.com"), for https://login.example.com, through the secretvault extension.`) {
		t.Fatalf("the save prompt: %q", q)
	}
	cred, err := rp.VerifyRegistration([]byte(cd), unb64(t, r["attestationObject"]), ch, false)
	if err != nil {
		t.Fatal(err)
	}
	if cred.Alg != -7 || cred.Flags&webauthntest.UV != 0 {
		t.Errorf("the credential: %+v", cred)
	}
	if b, _ := json.Marshal(r); bytes.Contains(b, []byte("private")) {
		t.Fatalf("the answer names a private key: %s", b)
	}

	// It is an item of kind passkey, with no secret where people look.
	out := h.ok("", h.with("ls")...)
	if !strings.Contains(out, "passkeys/example.com") {
		t.Fatalf("ls: %s", out)
	}
	if _, errs, code := h.run("", h.with("get", "passkeys/example.com")...); code == 0 || !strings.Contains(errs, "is a passkey") {
		t.Fatalf("get printed a passkey's key: %d %s", code, errs)
	}
	if out := h.ok("", h.with("get", "passkeys/example.com", "--field", "rp_id")...); out != "example.com\n" {
		t.Fatalf("get --field rp_id: %q", out)
	}
	// Renamed and deleted like any item (below, after it is used).

	// Listing is listing the vault.
	h.desk.answer(svrpc.ChoiceAlways, "")
	l := x.ask("passkeys", map[string]any{"origin": rp.Origin, "rpId": rp.ID})
	list, _ := l["passkeys"].([]any)
	if len(list) != 1 || list[0].(map[string]any)["userName"] != "ada@example.com" || list[0].(map[string]any)["title"] != "Example" {
		t.Fatalf("passkeys: %v", l)
	}
	login := list[0].(map[string]any)["id"].(string)
	// Not for another RP, nor for a credential the page does not allow.
	if l := x.ask("passkeys", map[string]any{"origin": "https://other.example", "rpId": "other.example"}); len(l["passkeys"].([]any)) != 0 {
		t.Errorf("another RP's passkeys: %v", l)
	}
	if l := x.ask("passkeys", map[string]any{"origin": rp.Origin, "rpId": rp.ID, "allow": []string{b64("other")}}); len(l["passkeys"].([]any)) != 0 {
		t.Errorf("a credential not allowed: %v", l)
	}

	// Signing is the broker's sign on the item: asked, then remembered.
	sign := func(uv string) map[string]any {
		ch = webauthntest.Challenge()
		cd = clientData("webauthn.get", rp.Origin, ch)
		m := map[string]any{"origin": rp.Origin, "rpId": rp.ID, "login": login, "clientData": b64(cd)}
		if uv != "" {
			m["uv"] = uv
		}
		return x.ask("passkey-get", m)
	}
	asked = h.desk.count()
	h.desk.answer(svrpc.ChoiceDeny, "")
	if r := sign(""); refused(r) != svext.CodeDenied {
		t.Fatalf("a refused sign: %v", r)
	}
	if q := h.desk.questions()[asked]; !strings.Contains(q, `wants to sign in to example.com as "ada@example.com" with the passkey "passkeys/example.com", for https://login.example.com`) {
		t.Fatalf("the sign prompt: %q", q)
	}
	h.desk.answer(svrpc.ChoiceAlways, "")
	r = sign("")
	if r["ok"] != true {
		t.Fatalf("sign: %v", r)
	}
	if err := rp.VerifyAssertion(cred, []byte(cd), unb64(t, r["authenticatorData"]), unb64(t, r["signature"]), ch, false); err != nil {
		t.Fatal(err)
	}
	if string(unb64(t, r["userHandle"])) != "u-1" || !bytes.Equal(unb64(t, r["credentialId"]), cred.ID) {
		t.Errorf("the assertion: %v", r)
	}
	asked = h.desk.count()
	if r := sign(""); r["ok"] != true || h.desk.count() != asked {
		t.Fatalf("remembered: %v, %d prompts", r, h.desk.count()-asked)
	}
	// Its UV flag is not set: nobody was verified.
	if ad := unb64(t, r["authenticatorData"]); ad[32]&svext.FlagUV != 0 {
		t.Error("UV without verification")
	}

	// A page that requires user verification gets the passphrase prompt,
	// every time, whatever was remembered; UV is set then only.
	asked = h.desk.count()
	h.desk.answer(svrpc.ChoiceAlways, "correct horse battery staple")
	r = sign(svext.UVRequired)
	if r["ok"] != true || h.desk.count() != asked+1 || !strings.HasPrefix(h.desk.questions()[asked], "passphrase: ") {
		t.Fatalf("uv required: %v, %v", r, h.desk.questions()[asked:])
	}
	if err := rp.VerifyAssertion(cred, []byte(cd), unb64(t, r["authenticatorData"]), unb64(t, r["signature"]), ch, true); err != nil {
		t.Fatal(err)
	}
	h.desk.answer(svrpc.ChoiceAlways, "wrong")
	if r := sign(svext.UVRequired); r["ok"] == true {
		t.Fatalf("a wrong passphrase verified: %v", r)
	}
	h.desk.answer(svrpc.ChoiceAlways, "")
	if r := sign(svext.UVRequired); refused(r) != svext.CodeDenied {
		t.Fatalf("a cancelled verification: %v", r)
	}

	// Not for another rpId, nor a login of another kind, nor an item the
	// page did not allow; none asked about.
	h.ok("hunter2", h.with("set", "web/example", "--kind", "login", "--field", "url=https://example.com")...)
	asked = h.desk.count()
	for _, m := range []map[string]any{
		{"origin": "https://other.example", "rpId": "other.example", "login": login, "clientData": b64(clientData("webauthn.get", "https://other.example", ch))},
		{"origin": rp.Origin, "rpId": rp.ID, "login": login, "allow": []string{b64("other")}, "clientData": b64(clientData("webauthn.get", rp.Origin, ch))},
		{"origin": rp.Origin, "rpId": rp.ID, "login": strings.Repeat("0", 32), "clientData": b64(clientData("webauthn.get", rp.Origin, ch))},
	} {
		if r := x.ask("passkey-get", m); refused(r) != svext.CodeNotFound {
			t.Errorf("%v: %v", m, r)
		}
	}
	if h.desk.count() != asked {
		t.Error("a request for no passkey was asked about")
	}

	// excludeCredentials: the vault holds it, so it is refused, unasked.
	cd = clientData("webauthn.create", rp.Origin, ch)
	if r := x.ask("passkey-create", map[string]any{"origin": rp.Origin, "rpId": rp.ID, "user": b64("u-1"), "userName": "ada",
		"exclude": []string{svext.B64.EncodeToString(cred.ID)}, "clientData": b64(cd)}); refused(r) != svext.CodeExcluded {
		t.Errorf("excluded: %v", r)
	}
	// Algorithms secretvault cannot make: unsupported, for the browser to do.
	if r := x.ask("passkey-create", map[string]any{"origin": rp.Origin, "rpId": rp.ID, "user": b64("u-2"), "userName": "bob",
		"algorithms": []int{-257}, "clientData": b64(cd)}); refused(r) != svext.CodeUnsupported {
		t.Errorf("RS256 only: %v", r)
	}
	// Ed25519, when the RP prefers it.
	h.desk.answer(svrpc.ChoiceOnce, "")
	r = x.ask("passkey-create", map[string]any{"origin": rp.Origin, "rpId": rp.ID, "user": b64("u-2"), "userName": "bob",
		"algorithms": []int{-8, -7}, "clientData": b64(cd)})
	if c, err := rp.VerifyRegistration([]byte(cd), unb64(t, r["attestationObject"]), ch, false); err != nil || c.Alg != -8 {
		t.Fatalf("Ed25519: %v %v", r, err)
	}

	// Renamed, it is still the site's passkey; deleted, it is gone.
	h.ok("", h.with("mv", "passkeys/example.com", "passkeys/work")...)
	h.desk.answer(svrpc.ChoiceAlways, "")
	if r := sign(""); r["ok"] != true {
		t.Fatalf("sign after a rename: %v", r)
	}
	h.ok("", h.with("rm", "passkeys/work")...)
	if r := sign(""); refused(r) != svext.CodeNotFound {
		t.Fatalf("sign after a delete: %v", r)
	}

	// Locked: refused as locked, and no key is used.
	h.ok("", "lock")
	if r := sign(""); refused(r) != svext.CodeLocked {
		t.Errorf("locked: %v", r)
	}
	if r := x.ask("passkeys", map[string]any{"origin": rp.Origin, "rpId": rp.ID}); refused(r) != svext.CodeLocked {
		t.Errorf("locked: %v", r)
	}
}
