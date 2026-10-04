package svext

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/cbor"
	"github.com/codemodify/secretvault/internal/webauthntest"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

type vectors struct {
	RPID []struct {
		Origin string `json:"origin"`
		RPID   string `json:"rpId"`
		OK     bool   `json:"ok"`
		Why    string `json:"why"`
	} `json:"rpId"`
	ClientData []struct {
		Type      string `json:"type"`
		Challenge string `json:"challenge"`
		Origin    string `json:"origin"`
		TopOrigin string `json:"topOrigin"`
		JSON      string `json:"json"`
	} `json:"clientData"`
}

func readVectors(t *testing.T) vectors {
	t.Helper()
	b, err := os.ReadFile("../browser/test/webauthn-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// Which rpId an origin may use: the same cases as the extension's
// (browser/test/webauthn.test.mjs), Public Suffix List edge cases and all.
func TestAnRPIDMustFitTheOriginByWebAuthnsRules(t *testing.T) {
	l := Suffixes()
	for _, c := range readVectors(t).RPID {
		o, err := ParseOrigin(c.Origin)
		if err != nil {
			t.Fatalf("%s: %v", c.Origin, err)
		}
		if err := CheckRPID(l, c.RPID, o); (err == nil) != c.OK {
			t.Errorf("%s with rpId %q: %v, want ok=%v (%s)", c.Origin, c.RPID, err, c.OK, c.Why)
		}
	}
}

// What the extension builds as clientDataJSON is what the daemon takes;
// anything that disagrees with the request is refused.
func TestClientDataIsCheckedAgainstTheRequest(t *testing.T) {
	for _, c := range readVectors(t).ClientData {
		o, _ := ParseOrigin(c.Origin)
		h, err := CheckClientData([]byte(c.JSON), c.Type, o)
		if err != nil {
			t.Errorf("%s: %v", c.JSON, err)
		}
		if h != sha256.Sum256([]byte(c.JSON)) {
			t.Error("the hash is not SHA-256 of the bytes")
		}
	}
	o, _ := ParseOrigin("https://example.com")
	good := `{"type":"webauthn.get","challenge":"AAECAwQFBgcICQoLDA0ODw","origin":"https://example.com","crossOrigin":false}`
	for _, bad := range []string{
		strings.Replace(good, "webauthn.get", "webauthn.create", 1),
		strings.Replace(good, "https://example.com", "https://evil.com", 1),
		strings.Replace(good, "https://example.com", "https://example.com/", 1),
		strings.Replace(good, "AAECAwQFBgcICQoLDA0ODw", "AAECAwQFBgcICQoLDA0O", 1), // 15 bytes
		strings.Replace(good, "AAECAwQFBgcICQoLDA0ODw", "AAEC+wQFBgcICQoLDA0ODw", 1),
		strings.Replace(good, `"crossOrigin":false`, `"crossOrigin":true`, 1),
		strings.Replace(good, `"crossOrigin":false`, `"crossOrigin":true,"topOrigin":"https://example.com/x"`, 1),
		strings.Replace(good, `"crossOrigin":false`, `"crossOrigin":false,"topOrigin":"https://other.example"`, 1),
		"[]", "", strings.Repeat(" ", MaxClientData+1),
		strings.Replace(good, `"type"`, `"Type":"webauthn.create","type"`, 1), // another case, read alike by Go
		strings.Replace(good, `{`, `{"type":"webauthn.create",`, 1),           // a member twice
		strings.Replace(good, `}`, `,"extra":1}`, 1),
		strings.Replace(good, `,`, `, `, 1),
	} {
		if _, err := CheckClientData([]byte(bad), ClientGet, o); err == nil {
			t.Errorf("taken: %s", bad)
		}
	}
}

// authenticatorData's layout (WebAuthn §6.1), byte for byte: SHA-256 of
// "example.com" is the spec's own example rpIdHash.
func TestAuthenticatorDataIsLaidOutAsTheSpecSays(t *testing.T) {
	got := AuthenticatorData("example.com", FlagUP|FlagBE|FlagBS, 0, nil)
	want := unhex(t, "a379a6f6eeafb9a55e378c118034e2751e682fab9f2d30ab13d2125586ce1947 19 00000000")
	if !bytes.Equal(got, want) {
		t.Errorf("assertion authData\n got %x\nwant %x", got, want)
	}
	got = AuthenticatorData("example.com", FlagUP|FlagUV, 0x01020304, nil)
	if got[32] != 0x05 || !bytes.Equal(got[33:], []byte{1, 2, 3, 4}) {
		t.Errorf("flags and count: %x", got[32:])
	}
	cose := []byte{0xa0}
	att := AttestedCredentialData([]byte{0xaa, 0xbb, 0xcc}, cose)
	want = append(append(append([]byte{}, AAGUID[:]...), 0x00, 0x03, 0xaa, 0xbb, 0xcc), 0xa0)
	if !bytes.Equal(att, want) {
		t.Errorf("attested credential data %x", att)
	}
	got = AuthenticatorData("example.com", FlagUP, 0, att)
	if got[32] != FlagUP|FlagAT || !bytes.Equal(got[37:], att) {
		t.Errorf("with attested data: %x", got)
	}
	if hex.EncodeToString(AAGUID[:]) != "147e5391634b49198f0ad0c353e3a97f" {
		t.Error("the AAGUID changed: it must not")
	}
}

// The attestation object of format "none" (§8.7), in CTAP2 canonical
// CBOR: fmt, attStmt, authData, by the length of their keys.
func TestTheAttestationObjectIsNoneInCanonicalCBOR(t *testing.T) {
	ad := []byte{1, 2, 3}
	want := unhex(t, "a3 63666d74 646e6f6e65 6761747453746d74 a0 6861757468446174 61 43 010203")
	if got := AttestationObject(ad); !bytes.Equal(got, want) {
		t.Errorf("\n got %x\nwant %x", got, want)
	}
}

// COSE keys as WebAuthn's examples write them, and RFC 8032's first test
// key, whose Ed25519 signature over an assertion is checked against one
// OpenSSL made (openssl pkeyutl -sign -rawin).
func TestKeysAreCOSEAndSignaturesAreTheSpecsKnownAnswers(t *testing.T) {
	seed := unhex(t, "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	der, err := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	kp, err := PublicOf(der)
	if err != nil {
		t.Fatal(err)
	}
	pub := "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
	if want := unhex(t, "a4 01 01 03 27 20 06 21 5820"+pub); kp.Alg != AlgEdDSA || !bytes.Equal(kp.COSE, want) {
		t.Errorf("Ed25519 COSE key\n got %x\nwant %x", kp.COSE, want)
	}
	cd := `{"type":"webauthn.get","challenge":"AAECAwQFBgcICQoLDA0ODw","origin":"https://example.com","crossOrigin":false}`
	ad := AuthenticatorData("example.com", passkeyTestFlags, 0, nil)
	sig, err := SignAssertion(der, ad, sha256.Sum256([]byte(cd)))
	if err != nil {
		t.Fatal(err)
	}
	want := "ec69b261d5a1aeebf515a3debb23b3333b57bb382678dea5c555c88091b4cd3181ec45d4835ce1eb02d4e15843102e1eedebc390d5b373191a4af6c6a4754a0c"
	if hex.EncodeToString(sig) != want {
		t.Errorf("Ed25519 assertion signature\n got %x\nwant %s", sig, want)
	}

	// ES256: EC2 on P-256, x and y of 32 bytes each.
	es, err := NewKeyPair(AlgES256)
	if err != nil {
		t.Fatal(err)
	}
	if len(es.COSE) != 77 || !bytes.HasPrefix(es.COSE, unhex(t, "a5 01 02 03 26 20 01 21 5820")) || !bytes.Equal(es.COSE[42:45], unhex(t, "22 5820")) {
		t.Errorf("ES256 COSE key %x", es.COSE)
	}
	k, _ := x509.ParsePKIXPublicKey(es.SPKI)
	ep, ok := k.(*ecdsa.PublicKey)
	if !ok || !bytes.Equal(ep.X.FillBytes(make([]byte, 32)), es.COSE[10:42]) {
		t.Error("the SPKI and the COSE key are not the same key")
	}
	if _, err := NewKeyPair(-257); err == nil {
		t.Error("an RSA passkey was made")
	}
}

const passkeyTestFlags = FlagUP | FlagBE | FlagBS

func TestTheAlgorithmIsTheRPsFirstThatSecretvaultMakes(t *testing.T) {
	for _, c := range []struct {
		rp   []int
		want int
		ok   bool
	}{
		{nil, AlgES256, true},
		{[]int{-257, -7}, AlgES256, true},
		{[]int{-8, -7}, AlgEdDSA, true},
		{[]int{-7, -8}, AlgES256, true},
		{[]int{-257, -35}, 0, false},
	} {
		if a, ok := ChooseAlgorithm(c.rp); a != c.want || ok != c.ok {
			t.Errorf("%v: %d %v", c.rp, a, ok)
		}
	}
}

// --- The fake backend's passkeys: a real authenticator, in memory. ---

func (b *backend) Passkeys(_ context.Context, vault string, o Origin, rpID string, allow [][]byte) ([]PasskeyEntry, error) {
	b.asked = append(b.asked, "passkeys "+rpID)
	var out []PasskeyEntry
	for i, r := range b.keys {
		if r.RPID == rpID && (len(allow) == 0 || containsID(allow, r.CredentialID)) {
			out = append(out, PasskeyEntry{ID: loginID(i), Title: rpID, UserName: r.UserName})
		}
	}
	return out, nil
}

func containsID(list [][]byte, id []byte) bool {
	for _, x := range list {
		if bytes.Equal(x, id) {
			return true
		}
	}
	return false
}

func loginID(i int) string { return strings.Repeat("0", 31) + string(rune('a'+i)) }

func (b *backend) CreatePasskey(_ context.Context, vault string, o Origin, c PasskeyCreate) (PasskeyCreated, error) {
	b.asked = append(b.asked, "create "+c.RPID)
	for _, r := range b.keys {
		if r.RPID == c.RPID && containsID(c.Exclude, r.CredentialID) {
			return PasskeyCreated{}, Errorf(CodeExcluded, "excluded")
		}
	}
	alg, ok := ChooseAlgorithm(c.Algorithms)
	if !ok {
		return PasskeyCreated{}, Errorf(CodeUnsupported, "no algorithm")
	}
	kp, err := NewKeyPair(alg)
	if err != nil {
		return PasskeyCreated{}, err
	}
	r := &PasskeyRecord{RPID: c.RPID, UserName: c.UserName, CredentialID: NewCredentialID(), UserHandle: c.UserHandle, Alg: alg, PrivateKey: kp.Private, Created: time.Now()}
	b.keys = append(b.keys, r)
	ad := AuthenticatorData(c.RPID, passkeyTestFlags, 0, AttestedCredentialData(r.CredentialID, kp.COSE))
	return PasskeyCreated{Login: loginID(len(b.keys) - 1), CredentialID: r.CredentialID, AuthenticatorData: ad, AttestationObject: AttestationObject(ad), PublicKey: kp.SPKI, Algorithm: alg}, nil
}

func (b *backend) GetPasskey(_ context.Context, vault string, o Origin, g PasskeyGet) (PasskeyAssertion, error) {
	b.asked = append(b.asked, "get "+g.RPID)
	for i, r := range b.keys {
		if loginID(i) == g.Login && r.RPID == g.RPID {
			ad := AuthenticatorData(g.RPID, passkeyTestFlags, 0, nil)
			sig, err := SignAssertion(r.PrivateKey, ad, g.ClientDataHash)
			return PasskeyAssertion{CredentialID: r.CredentialID, AuthenticatorData: ad, Signature: sig, UserHandle: r.UserHandle}, err
		}
	}
	return PasskeyAssertion{}, Errorf(CodeNotFound, "no such passkey")
}

// A registration and an assertion through the protocol, checked by an
// RP written apart from this package (internal/webauthntest).
func TestAPasskeyMadeAndUsedThroughTheProtocolVerifiesAtAnRP(t *testing.T) {
	for _, algs := range [][]int{{-7}, {-8}} {
		b := &backend{}
		s := NewSession(b)
		rp := &webauthntest.RP{ID: "example.com", Origin: "https://login.example.com"}
		ch := webauthntest.Challenge()
		cd := `{"type":"webauthn.create","challenge":"` + B64.EncodeToString(ch) + `","origin":"https://login.example.com","crossOrigin":false}`
		r := ask(t, s, map[string]any{"op": "passkey-create", "origin": rp.Origin, "rpId": rp.ID, "user": B64.EncodeToString([]byte("user-1")),
			"userName": "ada@example.com", "algorithms": algs, "clientData": B64.EncodeToString([]byte(cd))})
		if r["ok"] != true {
			t.Fatalf("create: %v", r)
		}
		att, _ := UnB64(r["attestationObject"].(string))
		cred, err := rp.VerifyRegistration([]byte(cd), att, ch, false)
		if err != nil {
			t.Fatal(err)
		}
		if cred.Alg != int64(algs[0]) || !bytes.Equal(cred.AAGUID, AAGUID[:]) || cred.Flags&webauthntest.BE == 0 || cred.Flags&webauthntest.BS == 0 || cred.Flags&webauthntest.UV != 0 {
			t.Errorf("the credential: %+v", cred)
		}
		if id, _ := UnB64(r["credentialId"].(string)); !bytes.Equal(id, cred.ID) {
			t.Error("credentialId is not the attested one")
		}
		// Through the passkey list, then signing.
		l := ask(t, s, map[string]any{"op": "passkeys", "origin": rp.Origin, "rpId": rp.ID, "allow": []string{B64.EncodeToString(cred.ID)}})
		list, _ := l["passkeys"].([]any)
		if len(list) != 1 {
			t.Fatalf("passkeys: %v", l)
		}
		login := list[0].(map[string]any)["id"].(string)
		ch = webauthntest.Challenge()
		cd = `{"type":"webauthn.get","challenge":"` + B64.EncodeToString(ch) + `","origin":"https://login.example.com","crossOrigin":false}`
		g := ask(t, s, map[string]any{"op": "passkey-get", "origin": rp.Origin, "rpId": rp.ID, "login": login, "clientData": B64.EncodeToString([]byte(cd))})
		if g["ok"] != true {
			t.Fatalf("get: %v", g)
		}
		ad, _ := UnB64(g["authenticatorData"].(string))
		sig, _ := UnB64(g["signature"].(string))
		if err := rp.VerifyAssertion(cred, []byte(cd), ad, sig, ch, false); err != nil {
			t.Error(err)
		}
		if uh, _ := UnB64(g["userHandle"].(string)); string(uh) != "user-1" {
			t.Errorf("userHandle %q", uh)
		}
		// The signature is over what was asked: another challenge fails.
		if err := rp.VerifyAssertion(cred, []byte(cd), ad, sig, webauthntest.Challenge(), false); err == nil {
			t.Error("verified with another challenge")
		}
		// Excluded: the vault already holds it.
		cd = `{"type":"webauthn.create","challenge":"` + B64.EncodeToString(ch) + `","origin":"https://login.example.com","crossOrigin":false}`
		x := ask(t, s, map[string]any{"op": "passkey-create", "origin": rp.Origin, "rpId": rp.ID, "user": "dXNlcg", "userName": "ada",
			"exclude": []string{B64.EncodeToString(cred.ID)}, "clientData": B64.EncodeToString([]byte(cd))})
		if refusedWith(x) != CodeExcluded {
			t.Errorf("an excluded credential: %v", x)
		}
	}
}

func refusedWith(r map[string]any) string {
	if r["ok"] == true {
		return ""
	}
	s, _ := r["error"].(string)
	return s
}

// The session refuses before the backend hears of it: an rpId that does
// not fit, an insecure page, clientData that disagrees, malformed members.
func TestPasskeyRequestsAreCheckedBeforeTheBackendSeesThem(t *testing.T) {
	b := &backend{}
	s := NewSession(b)
	cd := func(typ, origin string) string {
		return B64.EncodeToString([]byte(`{"type":"` + typ + `","challenge":"AAECAwQFBgcICQoLDA0ODw","origin":"` + origin + `","crossOrigin":false}`))
	}
	good := map[string]any{"op": "passkey-get", "origin": "https://example.com", "rpId": "example.com", "login": loginID(0), "clientData": cd("webauthn.get", "https://example.com")}
	with := func(k string, v any) map[string]any {
		m := map[string]any{}
		for a, b := range good {
			m[a] = b
		}
		if v == nil {
			delete(m, k)
		} else {
			m[k] = v
		}
		return m
	}
	for _, m := range []map[string]any{
		with("rpId", "github.io"),
		with("rpId", "evil.com"),
		with("rpId", "Example.com"),
		with("origin", "http://example.com"),
		with("clientData", cd("webauthn.create", "https://example.com")),
		with("clientData", cd("webauthn.get", "https://evil.com")),
		with("clientData", "not base64!"),
		with("clientData", nil),
		with("uv", "always"),
		with("allow", "AAAA"),
		with("allow", []any{1}),
		with("allow", make([]string, MaxCredentialIDs+1)),
		with("algorithms", []int{-7}),
	} {
		if r := ask(t, s, m); r["ok"] == true {
			t.Errorf("taken: %v", m)
		}
	}
	if len(b.asked) != 0 {
		t.Errorf("the backend was asked: %v", b.asked)
	}
	cr := map[string]any{"op": "passkey-create", "origin": "https://example.com", "rpId": "example.com", "user": B64.EncodeToString(make([]byte, 65)),
		"userName": "a", "clientData": cd("webauthn.create", "https://example.com")}
	if r := ask(t, s, cr); r["ok"] == true {
		t.Error("a user handle of 65 bytes was taken")
	}
	// The CBOR reader agrees with the encoder.
	if v, err := cbor.UnmarshalCanonical(AttestationObject([]byte{1})); err != nil || v.(cbor.Map)["fmt"] != "none" {
		t.Errorf("%v %v", v, err)
	}
}
