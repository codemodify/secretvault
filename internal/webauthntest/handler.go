package webauthntest

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// Handler is a relying party's site, as small as it can be: a page with a
// Register and a Sign in button, which call navigator.credentials.create
// and get, and endpoints that hand out challenges and check what comes
// back. Each result is shown on the page (document.body.dataset.result),
// and kept (Results).
type Handler struct {
	RP *RP
	// RequireUV makes the RP ask for user verification, and refuse what
	// is not verified.
	RequireUV bool

	mu        sync.Mutex
	challenge []byte
	creds     []*Credential
	results   []string
}

// Credentials are the credentials registered so far.
func (h *Handler) Credentials() []*Credential {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*Credential(nil), h.creds...)
}

// Results are what the RP said to each registration and sign-in.
func (h *Handler) Results() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.results...)
}

func (h *Handler) said(s string) string {
	h.mu.Lock()
	h.results = append(h.results, s)
	h.mu.Unlock()
	return s
}

const page = `<!doctype html><title>Test RP</title>
<style>body { font: 16px sans-serif; margin: 40px } button { font-size: 16px; padding: 8px 16px; margin: 8px }</style>
<h1>Test RP</h1>
<button id="register">Register</button> <button id="signin">Sign in</button>
<script>
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const show = (s) => { document.body.dataset.result = s; };
document.getElementById("register").onclick = async () => {
  try {
    const o = await (await fetch("begin")).json();
    const c = await navigator.credentials.create({ publicKey: {
      challenge: unb64(o.challenge), rp: { name: "Test RP" },
      user: { id: unb64(o.user), name: "ada@example.com", displayName: "Ada" },
      pubKeyCredParams: [{ type: "public-key", alg: -7 }, { type: "public-key", alg: -8 }],
      authenticatorSelection: { residentKey: "required", userVerification: o.uv },
      extensions: { credProps: true } } });
    const r = await fetch("register", { method: "POST", body: JSON.stringify({
      kind: c instanceof PublicKeyCredential && c.response instanceof AuthenticatorAttestationResponse ? "PublicKeyCredential" : "other",
      id: c.id, rawId: b64(c.rawId), clientDataJSON: b64(c.response.clientDataJSON),
      attestationObject: b64(c.response.attestationObject), publicKeyAlgorithm: c.response.getPublicKeyAlgorithm(),
      rk: (c.getClientExtensionResults().credProps || {}).rk === true }) });
    show(await r.text());
  } catch (e) { show("error: " + e.name + ": " + e.message); }
};
document.getElementById("signin").onclick = async () => {
  try {
    const o = await (await fetch("begin")).json();
    const c = await navigator.credentials.get({ publicKey: { challenge: unb64(o.challenge), rpId: o.rpId, userVerification: o.uv } });
    const r = await fetch("signin", { method: "POST", body: JSON.stringify({
      kind: c instanceof PublicKeyCredential && c.response instanceof AuthenticatorAssertionResponse ? "PublicKeyCredential" : "other",
      id: c.id, rawId: b64(c.rawId), clientDataJSON: b64(c.response.clientDataJSON), authenticatorData: b64(c.response.authenticatorData),
      signature: b64(c.response.signature), userHandle: c.response.userHandle ? b64(c.response.userHandle) : "" }) });
    show(await r.text());
  } catch (e) { show("error: " + e.name + ": " + e.message); }
};
</script>`

// conditionalPage signs in from autofill: it asks for a passkey with
// mediation "conditional" as it loads, and the person picks one where
// the user name field offers them.
const conditionalPage = `<!doctype html><title>Test RP: sign in</title>
<style>body { font: 16px sans-serif; margin: 40px } input { display: block; width: 260px; height: 28px; margin: 6px 0 16px }</style>
<form id="f" action="#" onsubmit="return false">
<label for="u">Email</label><input id="u" name="username" autocomplete="username webauthn">
<button>Next</button>
</form>
<script>
const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const unb64 = (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));
const show = (s) => { document.body.dataset.result = s; };
(async () => {
  try {
    if (!(await PublicKeyCredential.isConditionalMediationAvailable())) return show("no conditional mediation");
    const o = await (await fetch("begin")).json();
    const c = await navigator.credentials.get({ mediation: "conditional", publicKey: { challenge: unb64(o.challenge), rpId: o.rpId, userVerification: o.uv } });
    const r = await fetch("signin", { method: "POST", body: JSON.stringify({
      kind: c instanceof PublicKeyCredential ? "PublicKeyCredential" : "other",
      id: c.id, rawId: b64(c.rawId), clientDataJSON: b64(c.response.clientDataJSON), authenticatorData: b64(c.response.authenticatorData),
      signature: b64(c.response.signature), userHandle: c.response.userHandle ? b64(c.response.userHandle) : "" }) });
    show(await r.text());
  } catch (e) { show("error: " + e.name + ": " + e.message); }
})();
</script>`

// sandboxedPage asks to sign in from a document with an opaque origin.
const sandboxedPage = `<!doctype html><title>Sandboxed</title>
<style>body { font: 16px sans-serif; margin: 40px } button { font-size: 16px; padding: 8px 16px }</style>
<button id="signin">Sign in</button>
<script>
document.getElementById("signin").onclick = () => {
  navigator.credentials.get({ publicKey: { challenge: new Uint8Array(32), rpId: "localhost" } })
    .then(() => { document.body.dataset.result = "got a credential"; }, (e) => { document.body.dataset.result = "error: " + e.name; });
};
</script>`

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/", "/rp":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, page)
	case "/conditional":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, conditionalPage)
	case "/sandboxed":
		// The RP's own URL, but a sandboxed document: its origin is
		// opaque, and WebAuthn is not for it.
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "sandbox allow-scripts")
		io.WriteString(w, sandboxedPage)
	case "/begin":
		h.mu.Lock()
		h.challenge = Challenge()
		ch := h.challenge
		h.mu.Unlock()
		uv := "preferred"
		if h.RequireUV {
			uv = "required"
		}
		json.NewEncoder(w).Encode(map[string]string{"challenge": b64.EncodeToString(ch), "user": b64.EncodeToString([]byte("user-ada")),
			"rpId": h.RP.ID, "uv": uv})
	case "/register", "/signin":
		var m map[string]any
		if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&m); err != nil {
			io.WriteString(w, h.said("bad request"))
			return
		}
		io.WriteString(w, h.said(h.check(r.URL.Path, m)))
	default:
		http.NotFound(w, r)
	}
}

func (h *Handler) check(path string, m map[string]any) string {
	get := func(k string) []byte {
		s, _ := m[k].(string)
		b, _ := b64.DecodeString(s)
		return b
	}
	h.mu.Lock()
	ch := h.challenge
	h.challenge = nil
	h.mu.Unlock()
	if ch == nil {
		return "no challenge"
	}
	if m["kind"] != "PublicKeyCredential" {
		return "not a PublicKeyCredential"
	}
	if path == "/register" {
		c, err := h.RP.VerifyRegistration(get("clientDataJSON"), get("attestationObject"), ch, h.RequireUV)
		if err != nil {
			return "refused: " + err.Error()
		}
		if s, _ := m["id"].(string); s != b64.EncodeToString(c.ID) || string(get("rawId")) != string(c.ID) {
			return "refused: the id is not the attested credential's"
		}
		h.mu.Lock()
		h.creds = append(h.creds, c)
		h.mu.Unlock()
		return fmt.Sprintf("registered %s alg %v aaguid %x", b64.EncodeToString(c.ID), c.Alg, c.AAGUID)
	}
	id := get("rawId")
	for _, c := range h.Credentials() {
		if string(c.ID) == string(id) {
			if err := h.RP.VerifyAssertion(c, get("clientDataJSON"), get("authenticatorData"), get("signature"), ch, h.RequireUV); err != nil {
				return "refused: " + err.Error()
			}
			return fmt.Sprintf("signed in %s as %s", b64.EncodeToString(c.ID), get("userHandle"))
		}
	}
	return "refused: an unknown credential"
}
