package svdeliver

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

const aud = "https://secrets.example.com"

func verifyWith(t *testing.T, f *fakeIssuer, c *clock, raw string) (map[string]any, error) {
	t.Helper()
	iss := f.issuer("test", aud)
	keys, err := newRemoteKeys(iss, c.now)
	if err != nil {
		t.Fatal(err)
	}
	return verifyJWT(context.Background(), raw, iss, keys, c.now())
}

func TestIDTokensVerifyWithEachAlgorithm(t *testing.T) {
	c := newClock()
	for _, alg := range []string{AlgRS256, AlgES256, AlgEdDSA} {
		t.Run(alg, func(t *testing.T) {
			k := newTestKey(t, alg, "key-"+alg)
			f := newFakeIssuer(t, newTestKey(t, AlgEdDSA, "other"), k)
			raw := f.token(t, k, aud, c.now(), map[string]any{"sub": "repo:acme/app:ref:refs/heads/main", "repository": "acme/app"})
			claims, err := verifyWith(t, f, c, raw)
			if err != nil {
				t.Fatal(err)
			}
			if claims["repository"] != "acme/app" {
				t.Fatalf("claims %v", claims)
			}
		})
	}
}

func TestIDTokensAreRefused(t *testing.T) {
	c := newClock()
	now := c.now()
	rsaK := newTestKey(t, AlgRS256, "rsa")
	ecK := newTestKey(t, AlgES256, "ec")
	edK := newTestKey(t, AlgEdDSA, "ed")
	f := newFakeIssuer(t, rsaK, ecK, edK)
	base := func() map[string]any {
		return map[string]any{"iss": f.URL, "aud": aud, "sub": "x", "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	}
	with := func(changes map[string]any) map[string]any {
		m := base()
		for k, v := range changes {
			if v == nil {
				delete(m, k)
			} else {
				m[k] = v
			}
		}
		return m
	}
	hdr := func(alg, kid string) map[string]any { return map[string]any{"alg": alg, "kid": kid} }

	// HS256 with the RSA public key as the HMAC secret: the classic
	// confusion, if the verifier trusted the header's algorithm.
	pubDER, _ := x509.MarshalPKIXPublicKey(&rsaK.priv.(*rsa.PrivateKey).PublicKey)
	hs := func() string {
		hb, _ := json.Marshal(hdr("HS256", "rsa"))
		cb, _ := json.Marshal(base())
		signed := b64url.EncodeToString(hb) + "." + b64url.EncodeToString(cb)
		m := hmac.New(sha256.New, pubDER)
		m.Write([]byte(signed))
		return signed + "." + b64url.EncodeToString(m.Sum(nil))
	}()
	none := func() string {
		hb, _ := json.Marshal(hdr("none", ""))
		cb, _ := json.Marshal(base())
		return b64url.EncodeToString(hb) + "." + b64url.EncodeToString(cb) + "."
	}()
	noneSigned := func() string {
		hb, _ := json.Marshal(hdr("none", ""))
		cb, _ := json.Marshal(base())
		return b64url.EncodeToString(hb) + "." + b64url.EncodeToString(cb) + "." + b64url.EncodeToString([]byte("x"))
	}()
	good := signJWT(t, hdr(AlgRS256, "rsa"), base(), rsaK, AlgRS256)
	parts := strings.Split(good, ".")
	tamperedClaims := func() string {
		cb, _ := json.Marshal(with(map[string]any{"sub": "someone else"}))
		return parts[0] + "." + b64url.EncodeToString(cb) + "." + parts[2]
	}()
	tamperedSig := func() string {
		sig, _ := b64url.DecodeString(parts[2])
		sig[10] ^= 1
		return parts[0] + "." + parts[1] + "." + b64url.EncodeToString(sig)
	}()
	padded := parts[0] + "." + base64.URLEncoding.EncodeToString(mustDecode(parts[1])) + "." + parts[2]

	cases := []struct {
		name, token, want string
	}{
		{"wrong issuer", signJWT(t, hdr(AlgRS256, "rsa"), with(map[string]any{"iss": "https://evil.example.com"}), rsaK, AlgRS256), "issued by"},
		{"wrong audience", signJWT(t, hdr(AlgRS256, "rsa"), with(map[string]any{"aud": "https://other.example.com"}), rsaK, AlgRS256), "audience"},
		{"no audience", signJWT(t, hdr(AlgRS256, "rsa"), with(map[string]any{"aud": nil}), rsaK, AlgRS256), "no audience"},
		{"expired", signJWT(t, hdr(AlgRS256, "rsa"), with(map[string]any{"exp": now.Add(-2 * time.Minute).Unix()}), rsaK, AlgRS256), "expired"},
		{"no expiry", signJWT(t, hdr(AlgRS256, "rsa"), with(map[string]any{"exp": nil}), rsaK, AlgRS256), "no expiry"},
		{"exp not a number", signJWT(t, hdr(AlgRS256, "rsa"), with(map[string]any{"exp": "tomorrow"}), rsaK, AlgRS256), "not a time"},
		{"not yet valid", signJWT(t, hdr(AlgRS256, "rsa"), with(map[string]any{"nbf": now.Add(5 * time.Minute).Unix()}), rsaK, AlgRS256), "not valid until"},
		{"issued in the future", signJWT(t, hdr(AlgRS256, "rsa"), with(map[string]any{"iat": now.Add(5 * time.Minute).Unix()}), rsaK, AlgRS256), "future"},
		{"alg none, unsigned", none, "not signed"},
		{"alg none, signed", noneSigned, `algorithm "none" is not accepted`},
		{"HS256 with the public key", hs, `algorithm "HS256" is not accepted`},
		{"RS256 header on the EC key", signJWT(t, hdr(AlgRS256, "ec"), base(), rsaK, AlgRS256), "does not publish"},
		{"ES256 header on the RSA key", signJWT(t, hdr(AlgES256, "rsa"), base(), ecK, AlgES256), "does not publish"},
		{"EdDSA header on the RSA key", signJWT(t, hdr(AlgEdDSA, "rsa"), base(), edK, AlgEdDSA), "does not publish"},
		{"ES256 signed by another key", signJWT(t, hdr(AlgES256, "ec"), base(), newTestKey(t, AlgES256, "ec"), AlgES256), "signature does not verify"},
		{"unknown kid", signJWT(t, hdr(AlgRS256, "nobody"), base(), rsaK, AlgRS256), "does not publish"},
		{"tampered claims", tamperedClaims, "signature does not verify"},
		{"tampered signature", tamperedSig, "signature does not verify"},
		{"crit header", signJWT(t, map[string]any{"alg": AlgRS256, "kid": "rsa", "crit": []string{"exp"}}, base(), rsaK, AlgRS256), "critical"},
		{"padded base64", padded, "base64url"},
		{"two parts", parts[0] + "." + parts[1], "three parts"},
		{"too large", signJWT(t, hdr(AlgRS256, "rsa"), with(map[string]any{"pad": strings.Repeat("a", maxJWT)}), rsaK, AlgRS256), "longer than"},
		{"issuer twice", signRaw(t, []byte(`{"alg":"RS256","kid":"rsa"}`),
			[]byte(`{"iss":"https://evil.example.com","iss":"`+f.URL+`","aud":"`+aud+`","exp":`+jsonNum(now.Add(time.Minute).Unix())+`}`), rsaK, AlgRS256), "twice"},
		{"alg twice", signRaw(t, []byte(`{"alg":"none","alg":"RS256","kid":"rsa"}`), mustJSON(base()), rsaK, AlgRS256), "twice"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := verifyWith(t, f, c, tc.token)
			var te *TokenError
			if !errors.As(err, &te) {
				t.Fatalf("accepted, or refused for the wrong reason: %v", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("refused with %q, want it to say %q", err, tc.want)
			}
		})
	}
	// Leeway: a token a few seconds past its expiry still counts.
	late := signJWT(t, hdr(AlgRS256, "rsa"), with(map[string]any{"exp": now.Add(-10 * time.Second).Unix()}), rsaK, AlgRS256)
	if _, err := verifyWith(t, f, c, late); err != nil {
		t.Errorf("a token 10s past expiry was refused despite the leeway: %v", err)
	}
}

func TestAKeyVerifiesOnlyItsOwnAlgorithm(t *testing.T) {
	keys := map[string]testKey{}
	for _, alg := range []string{AlgRS256, AlgES256, AlgEdDSA} {
		keys[alg] = newTestKey(t, alg, alg)
	}
	jwks, _ := json.Marshal(map[string]any{"keys": []any{keys[AlgRS256].jwk(), keys[AlgES256].jwk(), keys[AlgEdDSA].jwk()}})
	set, err := parseJWKS(jwks)
	if err != nil || len(set.keys) != 3 {
		t.Fatalf("%d keys, %v", len(set.keys), err)
	}
	for _, pk := range set.keys {
		for _, alg := range []string{AlgRS256, AlgES256, AlgEdDSA, "HS256", "none"} {
			raw := signJWT(t, map[string]any{"alg": pk.alg}, map[string]any{"x": 1}, keys[pk.alg], pk.alg)
			parts := strings.Split(raw, ".")
			got := pk.verify(alg, []byte(parts[0]+"."+parts[1]), mustDecode(parts[2]))
			if got != (alg == pk.alg) {
				t.Errorf("the %s key's verify(%s) = %v", pk.alg, alg, got)
			}
		}
	}
}

func mustDecode(s string) []byte {
	b, err := b64url.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func jsonNum(n int64) string { return string(mustJSON(n)) }

func TestKeysLabelledForAnotherAlgorithmAreNotUsed(t *testing.T) {
	c := newClock()
	k := newTestKey(t, AlgRS256, "rsa")
	f := newFakeIssuer(t)
	j := k.jwk()
	j["alg"] = "PS256"
	jwks, _ := json.Marshal(map[string]any{"keys": []any{j, newTestKey(t, AlgEdDSA, "ed").jwk()}})
	iss := &Issuer{Name: "k8s", URL: f.URL, Audiences: []string{aud}, JWKS: jwks}
	set, err := parseJWKS(iss.JWKS)
	if err != nil {
		t.Fatal(err)
	}
	raw := f.token(t, k, aud, c.now(), nil)
	if _, err := verifyJWT(context.Background(), raw, iss, set, c.now()); err == nil || !strings.Contains(err.Error(), "does not publish") {
		t.Fatalf("an RS256 token verified with a key labelled PS256: %v", err)
	}
}

func TestUnknownKeysAreFetchedAgainButNotTooOften(t *testing.T) {
	c := newClock()
	old := newTestKey(t, AlgES256, "old")
	f := newFakeIssuer(t, old)
	iss := f.issuer("test", aud)
	keys, err := newRemoteKeys(iss, c.now)
	if err != nil {
		t.Fatal(err)
	}
	verify := func(raw string) error {
		_, err := verifyJWT(context.Background(), raw, iss, keys, c.now())
		return err
	}
	if err := verify(f.token(t, old, aud, c.now(), nil)); err != nil {
		t.Fatal(err)
	}
	if n := f.fetchCount(); n != 1 {
		t.Fatalf("%d fetches for the first token", n)
	}
	// Made-up key IDs do not make us fetch again and again.
	for i := range 5 {
		k := newTestKey(t, AlgES256, "made-up")
		if err := verify(f.token(t, k, aud, c.now(), nil)); err == nil {
			t.Fatalf("token %d with an unknown key verified", i)
		}
	}
	if n := f.fetchCount(); n != 1 {
		t.Fatalf("%d fetches after tokens with unknown keys; want no more than the first", n)
	}
	// The issuer rotates its key: after a while, a token with the new key
	// makes us fetch again, and verifies.
	fresh := newTestKey(t, AlgEdDSA, "new")
	f.addKey(fresh)
	c.add(jwksMinRefresh + time.Second)
	if err := verify(f.token(t, fresh, aud, c.now(), nil)); err != nil {
		t.Fatalf("a token with the issuer's new key: %v", err)
	}
	if n := f.fetchCount(); n != 2 {
		t.Fatalf("%d fetches; want one more for the new key", n)
	}
	// Cached keys are used, and fetched again once they are old.
	if err := verify(f.token(t, old, aud, c.now(), nil)); err != nil || f.fetchCount() != 2 {
		t.Fatalf("cached key: %v, %d fetches", err, f.fetchCount())
	}
	c.add(jwksMaxAge + time.Second)
	if err := verify(f.token(t, old, aud, c.now(), nil)); err != nil || f.fetchCount() != 3 {
		t.Fatalf("after an hour: %v, %d fetches", err, f.fetchCount())
	}
}

func TestDiscoveryIsChecked(t *testing.T) {
	c := newClock()
	k := newTestKey(t, AlgRS256, "rsa")

	f := newFakeIssuer(t, k)
	f.discIssuer = "https://token.actions.githubusercontent.com"
	_, err := verifyWith(t, f, c, f.token(t, k, aud, c.now(), nil))
	if err == nil || !strings.Contains(err.Error(), "names the issuer") {
		t.Errorf("a discovery document for another issuer was believed: %v", err)
	}

	g := newFakeIssuer(t, k)
	g.jwksURI = "http://" + strings.TrimPrefix(g.URL, "https://") + "/keys"
	_, err = verifyWith(t, g, c, g.token(t, k, aud, c.now(), nil))
	if err == nil || !strings.Contains(err.Error(), "not an HTTPS URL") {
		t.Errorf("a jwks_uri over plain HTTP was used: %v", err)
	}

	// Without the issuer's CA, its certificate is not trusted.
	h := newFakeIssuer(t, k)
	iss := h.issuer("test", aud)
	iss.CA = ""
	keys, _ := newRemoteKeys(iss, c.now)
	if _, err := verifyJWT(context.Background(), h.token(t, k, aud, c.now(), nil), iss, keys, c.now()); err == nil || !strings.Contains(err.Error(), "could not be fetched") {
		t.Errorf("an issuer with an untrusted certificate was used: %v", err)
	}
}

func TestJWKSParsingRefusesWeakAndBrokenKeys(t *testing.T) {
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"rsa 1024":       `{"keys":[{"kty":"RSA","kid":"a","n":"` + b64url.EncodeToString(weak.N.Bytes()) + `","e":"AQAB"}]}`,
		"ec off curve":   `{"keys":[{"kty":"EC","crv":"P-256","x":"` + b64url.EncodeToString(make([]byte, 32)) + `","y":"` + b64url.EncodeToString(make([]byte, 32)) + `"}]}`,
		"ec P-384":       `{"keys":[{"kty":"EC","crv":"P-384","x":"AA","y":"AA"}]}`,
		"encryption key": `{"keys":[` + string(mustJSON(withMember(newTestKey(t, AlgEdDSA, "e").jwk(), "use", "enc"))) + `]}`,
		"hmac key":       `{"keys":[{"kty":"oct","k":"c2VjcmV0"}]}`,
		"not json":       `keys`,
	}
	for name, doc := range cases {
		if _, err := parseJWKS([]byte(doc)); err == nil {
			t.Errorf("%s: the key set was accepted", name)
		}
	}
}

func withMember(m map[string]any, k string, v any) map[string]any {
	m[k] = v
	return m
}
