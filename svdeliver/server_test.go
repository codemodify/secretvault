package svdeliver

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// fixture is a delivery server on localhost, initialised, with one
// vault of the owner's shared with it and added, still sealed.
type fixture struct {
	t        *testing.T
	root     string
	dir      string // the delivery directory
	creds    string // $CREDENTIALS_DIRECTORY
	res      *InitResult
	clock    *clock
	srv      *Server
	http     *httptest.Server
	vault    *svcore.Vault // the owner's handle on it
	vaultDir string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	root := t.TempDir()
	f := &fixture{t: t, root: root, dir: filepath.Join(root, "deliver"), creds: filepath.Join(root, "creds"), clock: newClock()}
	res, err := Init(f.dir, InitOptions{Shares: 3, Threshold: 2, Credential: true, Now: f.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	f.res = res
	// No rate limit: the test clock stands still.
	if err := os.WriteFile(filepath.Join(f.dir, ConfigFile), []byte(`{"rate": -1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	os.MkdirAll(f.creds, 0o700)

	// The owner's vault, shared with the server's identity.
	f.vaultDir = filepath.Join(root, "vault")
	store, err := svstore.OpenDir(f.vaultDir)
	if err != nil {
		t.Fatal(err)
	}
	v, _, err := svcore.Create(store, svcrypto.Modern, svcore.NewSlot{Type: svformat.SlotKeyfile, Keyfile: svcrypto.RandomBytes(32)}, svcore.Options{Now: f.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	f.vault = v
	f.put("prod/db/password", "login", "username", "app", "password", "hunter2")
	f.put("prod/api/key", "api-key", "secret", "sk_live_123")
	f.put("staging/db/password", "password", "password", "staging-pw")
	if _, err := v.Put(svcore.Item{Kind: "key", Name: "prod/tls/key", Fields: []svcore.Field{{Name: "der", Type: svcore.FieldBinary, Value: []byte{0xff, 0, 0x80}}}}); err != nil {
		t.Fatal(err)
	}
	f.share(v, "sv1-modern")

	f.start()
	return f
}

// start (re)starts the server on the delivery directory.
func (f *fixture) start() {
	f.t.Helper()
	if f.http != nil {
		f.http.Close()
		f.srv.Close()
	}
	srv, err := New(Config{Dir: f.dir, SyncRoot: filepath.Join(f.root, "sync"), CredentialsDir: f.creds, Now: f.clock.now, Log: func(s string) { f.t.Log(s) }})
	if err != nil {
		f.t.Fatal(err)
	}
	f.srv = srv
	hs := httptest.NewUnstartedServer(srv)
	hs.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	hs.StartTLS()
	f.http = hs
	f.t.Cleanup(func() {
		hs.Close()
		srv.Close()
	})
}

func (f *fixture) put(name, kind string, kv ...string) {
	f.t.Helper()
	it := svcore.Item{Kind: kind, Name: name}
	for i := 0; i < len(kv); i += 2 {
		typ := svcore.FieldText
		if kv[i] == "password" || kv[i] == "secret" {
			typ = svcore.FieldConcealed
		}
		it.Fields = append(it.Fields, svcore.Field{Name: kv[i], Type: typ, Value: []byte(kv[i+1])})
	}
	if _, err := f.vault.Put(it); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) share(v *svcore.Vault, suite string) {
	f.t.Helper()
	_, pub, err := svformat.ParseRecipient(f.res.Recipients[suite])
	if err != nil {
		f.t.Fatal(err)
	}
	if _, err := v.AddSlot(svcore.NewSlot{Type: svformat.SlotRecipient, Label: "delivery server", Recipient: pub}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *fixture) fingerprint() string { return certFingerprint(f.http.Certificate()) }

func (f *fixture) client(token string) *Client {
	f.t.Helper()
	c, err := NewClient(ClientOptions{URL: f.http.URL, Fingerprint: f.fingerprint(), Token: token})
	if err != nil {
		f.t.Fatal(err)
	}
	return c
}

func (f *fixture) admin() *Client { return f.client(f.res.AdminToken) }

// unsealed unseals with the first two shares, adds the vault as "main",
// and returns the admin client.
func (f *fixture) unsealed() *Client {
	f.t.Helper()
	c := f.admin()
	ctx := context.Background()
	for _, s := range f.res.Shares[:2] {
		if _, err := c.Unseal(ctx, s); err != nil {
			f.t.Fatal(err)
		}
	}
	if f.srv.Sealed() {
		f.t.Fatal("still sealed after two shares")
	}
	if _, err := c.AddVault(ctx, VaultRequest{Name: "main", Path: f.vaultDir}); err != nil {
		f.t.Fatal(err)
	}
	return c
}

// get makes a raw request, as curl would, and returns the status and body.
func (f *fixture) get(path, token string, header ...string) (int, string) {
	f.t.Helper()
	return f.do(f.http.Client(), http.MethodGet, path, token, "", header...)
}

func (f *fixture) do(client *http.Client, method, path, token, body string, header ...string) (int, string) {
	f.t.Helper()
	req, err := http.NewRequest(method, f.http.URL+path, strings.NewReader(body))
	if err != nil {
		f.t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for i := 0; i+1 < len(header); i += 2 {
		req.Header.Set(header[i], header[i+1])
	}
	resp, err := client.Do(req)
	if err != nil {
		f.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func (f *fixture) token(admin *Client, name string, req TokenRequest) string {
	f.t.Helper()
	req.Name = name
	nt, err := admin.CreateToken(context.Background(), req)
	if err != nil {
		f.t.Fatal(err)
	}
	return nt.Token
}

func (f *fixture) role(admin *Client, r Role) {
	f.t.Helper()
	if _, err := admin.SetRole(context.Background(), r); err != nil {
		f.t.Fatalf("role %s: %v", r.Name, err)
	}
}

func apiStatus(err error) int {
	var e *APIError
	if errors.As(err, &e) {
		return e.Status
	}
	return 0
}

func TestUnsealingTakesTheThresholdOfShares(t *testing.T) {
	f := newFixture(t)
	c := f.admin()
	ctx := context.Background()
	st, err := c.Status(ctx)
	if err != nil || !st.Sealed || st.Threshold != 2 || st.Shares != 3 || !st.AutoUnseal {
		t.Fatalf("status %+v, %v", st, err)
	}
	// Sealed, nothing is served, and the admin API is closed too.
	if code, _ := f.get("/v1/deliver/secret/main/prod/db/password", "svdt_x"); code != http.StatusServiceUnavailable {
		t.Errorf("a sealed server answered %d to a secret request", code)
	}
	if _, err := c.Tokens(ctx); apiStatus(err) != http.StatusServiceUnavailable {
		t.Errorf("a sealed server's admin API answered %v", err)
	}
	st, err = c.Unseal(ctx, f.res.Shares[2])
	if err != nil || !st.Sealed || st.Progress != 1 {
		t.Fatalf("after one share: %+v, %v", st, err)
	}
	if _, err := c.Unseal(ctx, f.res.Shares[2]); err == nil || !strings.Contains(err.Error(), "given already") {
		t.Fatalf("the same share twice: %v", err)
	}
	typo := []byte(f.res.Shares[0])
	typo[8] ^= 1
	if _, err := c.Unseal(ctx, string(typo)); err == nil || !strings.Contains(err.Error(), "check for a typo") {
		t.Fatalf("a mistyped share: %v", err)
	}
	st, err = c.Unseal(ctx, f.res.Shares[0])
	if err != nil || st.Sealed || st.Progress != 0 {
		t.Fatalf("after two shares: %+v, %v", st, err)
	}
	// Sealing again forgets everything.
	if _, err := c.Seal(ctx); err != nil {
		t.Fatal(err)
	}
	if !f.srv.Sealed() {
		t.Fatal("seal did not seal")
	}
}

func TestSharesFromElsewhereDoNotUnseal(t *testing.T) {
	f := newFixture(t)
	other, err := Init(filepath.Join(f.root, "other"), InitOptions{Shares: 3, Threshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	c := f.admin()
	ctx := context.Background()
	if _, err := c.Unseal(ctx, f.res.Shares[0]); err != nil {
		t.Fatal(err)
	}
	_, err = c.Unseal(ctx, other.Shares[1])
	if err == nil || !strings.Contains(err.Error(), "do not fit together") {
		t.Fatalf("shares of two servers combined: %v", err)
	}
	if st, _ := c.Status(ctx); !st.Sealed || st.Progress != 0 {
		t.Fatalf("after a failed combination: %+v; want sealed, and the shares forgotten", st)
	}
	// A share of a split with another threshold is refused on sight.
	third, _ := Init(filepath.Join(f.root, "third"), InitOptions{Shares: 5, Threshold: 3})
	if _, err := c.Unseal(ctx, third.Shares[0]); err == nil || !strings.Contains(err.Error(), "needs 3 shares") {
		t.Fatalf("a share of a 3-of-5 split given to a 2-of-3 server: %v", err)
	}
}

func TestSharesGivenAreForgottenAfterTheTimeout(t *testing.T) {
	f := newFixture(t)
	c := f.admin()
	ctx := context.Background()
	if _, err := c.Unseal(ctx, f.res.Shares[0]); err != nil {
		t.Fatal(err)
	}
	f.clock.add(11 * time.Minute)
	if st, _ := c.Status(ctx); st.Progress != 0 {
		t.Fatalf("progress %d after the timeout", st.Progress)
	}
	st, err := c.Unseal(ctx, f.res.Shares[1])
	if err != nil || !st.Sealed || st.Progress != 1 {
		t.Fatalf("a share after the timeout: %+v, %v; want it counted alone", st, err)
	}
	if st, err := c.UnsealReset(ctx); err != nil || st.Progress != 0 {
		t.Fatalf("reset: %+v, %v", st, err)
	}
}

func TestATokenReadsWhatItsRoleAllowsAndNothingElse(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	tok := f.token(admin, "app", TokenRequest{CIDRs: []string{"127.0.0.0/8", "::1/128"}})
	f.role(admin, Role{Name: "app", Token: "app", Rules: []Rule{{Vault: "main", Items: "prod/db/*", Capabilities: []string{CapRead}}}})

	code, body := f.get("/v1/deliver/secret/main/prod/db/password", tok)
	var s Secret
	if code != http.StatusOK || json.Unmarshal([]byte(body), &s) != nil {
		t.Fatalf("%d %s", code, body)
	}
	if s.Fields["password"] != "hunter2" || s.Fields["username"] != "app" || s.SecretField != "password" || s.Kind != "login" || s.Version == "" {
		t.Fatalf("secret %+v", s)
	}
	code, body = f.get("/v1/deliver/secret/main/prod/db/password?field=username", tok)
	if code != http.StatusOK || !strings.Contains(body, `"value":"app"`) {
		t.Fatalf("one field: %d %s", code, body)
	}
	code, body = f.get("/v1/deliver/secret/main/prod/db/password?field=password&raw=true", tok)
	if code != http.StatusOK || body != "hunter2" {
		t.Fatalf("a raw field: %d %q", code, body)
	}
	if code, body := f.get("/v1/deliver/secret/main/prod/db/password?field=nope", tok); code != http.StatusNotFound || !strings.Contains(body, "no field") {
		t.Fatalf("a missing field: %d %s", code, body)
	}
	// Allowed, but not there: said plainly.
	if code, body := f.get("/v1/deliver/secret/main/prod/db/nothere", tok); code != http.StatusNotFound || !strings.Contains(body, `"no such secret"`) {
		t.Fatalf("a missing secret the role covers: %d %s", code, body)
	}
	// Not allowed: the same answer whether the item exists or not, and
	// whether the vault does.
	c1, b1 := f.get("/v1/deliver/secret/main/prod/api/key", tok)
	c2, b2 := f.get("/v1/deliver/secret/main/prod/api/nothere", tok)
	c3, b3 := f.get("/v1/deliver/secret/nosuchvault/prod/db/password", tok)
	if c1 != http.StatusNotFound || c1 != c2 || c2 != c3 || b1 != b2 || b2 != b3 {
		t.Fatalf("not allowed vs not there differ:\n%d %s\n%d %s\n%d %s", c1, b1, c2, b2, c3, b3)
	}
	if !strings.Contains(b1, msgNoSecret) {
		t.Fatalf("not allowed: %s", b1)
	}
	// Binary values come in base64.
	f.role(admin, Role{Name: "app", Token: "app", Rules: []Rule{{Vault: "main", Items: "prod/*", Capabilities: []string{CapRead}}}})
	code, body = f.get("/v1/deliver/secret/main/prod/tls/key", tok)
	if code != http.StatusOK || !strings.Contains(body, `"fields_base64":{"der":"/wCA"}`) {
		t.Fatalf("a binary field: %d %s", code, body)
	}
	// The Go client does the same.
	v, err := f.client(tok).Value(context.Background(), "main", "prod/api/key", "")
	if err != nil || string(v) != "sk_live_123" {
		t.Fatalf("client Value: %q %v", v, err)
	}
	// No credentials, a made-up token, or the admin token: refused.
	for _, bad := range []string{"", "svdt_madeup", "hunter2", f.res.AdminToken} {
		if code, _ := f.get("/v1/deliver/secret/main/prod/db/password", bad); code != http.StatusUnauthorized {
			t.Errorf("token %.10q: %d", bad, code)
		}
	}
}

func TestTokensExpireAreRevokedAndKeepToTheirNetworks(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	ctx := context.Background()
	rules := []Rule{{Vault: "main", Items: "*", Capabilities: []string{CapRead}}}
	short := f.token(admin, "short", TokenRequest{TTL: "10m"})
	far := f.token(admin, "far", TokenRequest{CIDRs: []string{"10.0.0.0/8"}})
	gone := f.token(admin, "gone", TokenRequest{})
	for _, n := range []string{"short", "far", "gone"} {
		f.role(admin, Role{Name: n, Token: n, Rules: rules})
	}
	const path = "/v1/deliver/secret/main/prod/api/key"
	if code, _ := f.get(path, short); code != http.StatusOK {
		t.Fatalf("a fresh token: %d", code)
	}
	if code, body := f.get(path, far); code != http.StatusUnauthorized || !strings.Contains(body, "may not be used from") {
		t.Fatalf("a token used outside its network: %d %s", code, body)
	}
	if err := admin.RevokeToken(ctx, "gone"); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.get(path, gone); code != http.StatusUnauthorized {
		t.Fatalf("a revoked token: %d", code)
	}
	f.clock.add(11 * time.Minute)
	if code, body := f.get(path, short); code != http.StatusUnauthorized || !strings.Contains(body, "expired") {
		t.Fatalf("an expired token: %d %s", code, body)
	}
	list, err := admin.Tokens(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("tokens %+v %v", list, err)
	}
	if _, err := admin.CreateToken(ctx, TokenRequest{Name: "far"}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a second token of one name: %v", err)
	}
}

func TestListingShowsOnlyWhatMayBeListed(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	tok := f.token(admin, "lister", TokenRequest{})
	f.role(admin, Role{Name: "lister", Token: "lister", Rules: []Rule{{Vault: "main", Items: "prod/*", Capabilities: []string{CapList}}}})
	code, body := f.get("/v1/deliver/list/main/prod/", tok)
	var l List
	if code != http.StatusOK || json.Unmarshal([]byte(body), &l) != nil {
		t.Fatalf("%d %s", code, body)
	}
	if strings.Join(l.Items, ",") != "prod/api/key,prod/db/password,prod/tls/key" {
		t.Fatalf("listed %v", l.Items)
	}
	code, body = f.get("/v1/deliver/list/main", tok)
	if code != http.StatusOK || strings.Contains(body, "staging") {
		t.Fatalf("the whole vault: %d %s", code, body)
	}
	// Listing is not reading.
	if code, _ := f.get("/v1/deliver/secret/main/prod/api/key", tok); code != http.StatusNotFound {
		t.Fatalf("a list-only role read a secret: %d", code)
	}
	c1, b1 := f.get("/v1/deliver/list/other/", tok)
	if c1 != http.StatusNotFound || !strings.Contains(b1, "not allowed") {
		t.Fatalf("another vault: %d %s", c1, b1)
	}
}

func TestPipelinesLogInWithIDTokens(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	ctx := context.Background()
	key := newTestKey(t, AlgRS256, "gh-1")
	gh := newFakeIssuer(t, key)
	if _, err := admin.SetIssuer(ctx, *gh.issuer("github", aud)); err != nil {
		t.Fatal(err)
	}
	f.role(admin, Role{Name: "deploy", TTL: "20m",
		OIDC:  &OIDCMatch{Issuer: "github", Claims: map[string]string{"repository": "acme/app", "ref": "refs/heads/main", "environment": "prod"}},
		Rules: []Rule{{Vault: "main", Items: "prod/*", Capabilities: []string{CapRead}}},
	})
	claims := map[string]any{"sub": "repo:acme/app:environment:prod", "repository": "acme/app", "ref": "refs/heads/main", "environment": "prod"}
	jwt := gh.token(t, key, aud, f.clock.now(), claims)

	c := f.client("")
	sess, err := c.LoginOIDC(ctx, "deploy", jwt)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Role != "deploy" || !strings.HasPrefix(sess.Token, sessionPrefix) || sess.Identity != "oidc:github:repo:acme/app:environment:prod" {
		t.Fatalf("session %+v", sess)
	}
	c.SetToken(sess.Token)
	if v, err := c.Value(ctx, "main", "prod/db/password", "password"); err != nil || string(v) != "hunter2" {
		t.Fatalf("with the session: %q %v", v, err)
	}
	// An ID token as the bearer token, with the role beside it: a login
	// and a request in one, for clients that cannot do two steps.
	code, body := f.get("/v1/deliver/secret/main/prod/api/key?field=secret&raw=1", jwt, RoleHeader, "deploy")
	if code != http.StatusOK || body != "sk_live_123" {
		t.Fatalf("one-shot: %d %s", code, body)
	}
	// Another branch's token: the same answer as for no such role.
	wrong := gh.token(t, key, aud, f.clock.now(), map[string]any{"sub": "repo:acme/app:ref:refs/heads/dev", "repository": "acme/app", "ref": "refs/heads/dev", "environment": "prod"})
	_, err1 := c.LoginOIDC(ctx, "deploy", wrong)
	_, err2 := c.LoginOIDC(ctx, "nosuchrole", jwt)
	if apiStatus(err1) != http.StatusForbidden || apiStatus(err2) != http.StatusForbidden ||
		strings.ReplaceAll(err1.Error(), "deploy", "X") != strings.ReplaceAll(err2.Error(), "nosuchrole", "X") {
		t.Fatalf("claims that do not match: %v; no such role: %v", err1, err2)
	}
	// The audit log says who it was, and which claim did not match.
	log, err := admin.Audit(ctx, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range log.Entries {
		if e.Op == "login" && e.Outcome == OutcomeDenied && e.Identity == "oidc:github:repo:acme/app:ref:refs/heads/dev" &&
			strings.Contains(e.Reason, `ref="refs/heads/dev" (wants "refs/heads/main")`) && e.Role == "deploy" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no audit entry for the refused login: %+v", log.Entries)
	}
	// Another repository's token for our audience.
	evil := gh.token(t, key, aud, f.clock.now(), map[string]any{"repository": "evil/app", "ref": "refs/heads/main", "environment": "prod"})
	if _, err := c.LoginOIDC(ctx, "deploy", evil); apiStatus(err) != http.StatusForbidden {
		t.Fatalf("another repository's token: %v", err)
	}
	// A token for another audience, or expired, is refused as such.
	if _, err := c.LoginOIDC(ctx, "deploy", gh.token(t, key, "https://other.example.com", f.clock.now(), claims)); apiStatus(err) != http.StatusUnauthorized || !strings.Contains(err.Error(), "audience") {
		t.Fatalf("another audience: %v", err)
	}
	// The session lasts the role's TTL.
	f.clock.add(21 * time.Minute)
	if _, err := c.Value(ctx, "main", "prod/db/password", ""); apiStatus(err) != http.StatusUnauthorized {
		t.Fatalf("an expired session: %v", err)
	}
	if _, err := c.LoginOIDC(ctx, "deploy", jwt); apiStatus(err) != http.StatusUnauthorized || !strings.Contains(err.Error(), "expired") {
		t.Fatalf("an expired ID token: %v", err)
	}
	// Sealing ends every session.
	c.SetToken("")
	sess, err = c.LoginOIDC(ctx, "deploy", gh.token(t, key, aud, f.clock.now(), claims))
	if err != nil {
		t.Fatal(err)
	}
	admin.Seal(ctx)
	for _, s := range f.res.Shares[:2] {
		admin.Unseal(ctx, s)
	}
	c.SetToken(sess.Token)
	if _, err := c.Value(ctx, "main", "prod/db/password", ""); apiStatus(err) != http.StatusUnauthorized {
		t.Fatalf("a session from before the seal: %v", err)
	}
}

func TestKubernetesServiceAccountsWithAConfiguredKeySet(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	ctx := context.Background()
	key := newTestKey(t, AlgES256, "k8s-1")
	jwks, _ := json.Marshal(map[string]any{"keys": []any{key.jwk()}})
	const issuer = "https://kubernetes.default.svc.cluster.local"
	if _, err := admin.SetIssuer(ctx, Issuer{Name: "cluster", URL: issuer, Audiences: []string{"secretvault"}, JWKS: jwks}); err != nil {
		t.Fatal(err)
	}
	f.role(admin, Role{Name: "payments",
		OIDC:  &OIDCMatch{Issuer: "cluster", Claims: map[string]string{"kubernetes.io/namespace": "payments", "kubernetes.io/serviceaccount/name": "api"}},
		Rules: []Rule{{Vault: "main", Items: "prod/db/*", Capabilities: []string{CapRead}}},
	})
	now := f.clock.now()
	sa := func(ns, name string) string {
		return signJWT(t, map[string]any{"alg": AlgES256, "kid": "k8s-1"}, map[string]any{
			"iss": issuer, "aud": []string{"secretvault"}, "sub": "system:serviceaccount:" + ns + ":" + name,
			"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(),
			"kubernetes.io": map[string]any{"namespace": ns, "serviceaccount": map[string]any{"name": name, "uid": "u"}},
		}, key, AlgES256)
	}
	c := f.client("")
	sess, err := c.LoginOIDC(ctx, "payments", sa("payments", "api"))
	if err != nil {
		t.Fatal(err)
	}
	c.SetToken(sess.Token)
	if v, err := c.Value(ctx, "main", "prod/db/password", ""); err != nil || string(v) != "hunter2" {
		t.Fatalf("%q %v", v, err)
	}
	if _, err := c.LoginOIDC(ctx, "payments", sa("web", "api")); apiStatus(err) != http.StatusForbidden {
		t.Fatalf("another namespace's service account: %v", err)
	}
	// An issuer in use cannot be removed.
	if err := admin.RemoveIssuer(ctx, "cluster"); apiStatus(err) != http.StatusConflict {
		t.Fatalf("removing an issuer in use: %v", err)
	}
}

// testCA makes a CA and certificates it signs.
type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T) *testCA {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test client CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

// issue makes a client certificate; a nil CA makes it self-signed.
func (ca *testCA) issue(t *testing.T, cn string, uri string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	u, _ := url.Parse(uri)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn, Organization: []string{"Acme"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		URIs: []*url.URL{u},
	}
	parent, signer := tmpl, any(key)
	if ca != nil {
		parent, signer = ca.cert, ca.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, &key.PublicKey, signer)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func (f *fixture) certClient(cert tls.Certificate) *http.Client {
	t := f.http.Client().Transport.(*http.Transport).Clone()
	t.TLSClientConfig.Certificates = []tls.Certificate{cert}
	return &http.Client{Transport: t}
}

func TestClientCertificates(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	ctx := context.Background()
	ca := newTestCA(t)
	if _, err := admin.SetClientCA(ctx, ca.pem); err != nil {
		t.Fatal(err)
	}
	rules := []Rule{{Vault: "main", Items: "prod/api/*", Capabilities: []string{CapRead}}}
	f.role(admin, Role{Name: "spiffe", Cert: &CertMatch{SAN: "spiffe://acme/app/*", Subject: "CN=app*,O=Acme"}, Rules: rules})

	good := ca.issue(t, "app-1", "spiffe://acme/app/web")
	const path = "/v1/deliver/secret/main/prod/api/key?field=secret&raw=1"
	if code, body := f.do(f.certClient(good), http.MethodGet, path, "", ""); code != http.StatusOK || body != "sk_live_123" {
		t.Fatalf("a certificate from the CA: %d %s", code, body)
	}
	// The same names on a certificate the CA did not sign.
	forged := (*testCA)(nil).issue(t, "app-1", "spiffe://acme/app/web")
	if code, _ := f.do(f.certClient(forged), http.MethodGet, path, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("a self-signed certificate with the right names: %d", code)
	}
	// Signed by the CA, but for another workload.
	other := ca.issue(t, "app-2", "spiffe://acme/db/primary")
	if code, _ := f.do(f.certClient(other), http.MethodGet, path, "", ""); code != http.StatusUnauthorized {
		t.Fatalf("another workload's certificate: %d", code)
	}
	// A pinned certificate needs no CA.
	leaf, _ := x509.ParseCertificate(forged.Certificate[0])
	f.role(admin, Role{Name: "pinned", Cert: &CertMatch{Fingerprint: strings.ToUpper(certFingerprint(leaf))}, Rules: rules})
	if code, body := f.do(f.certClient(forged), http.MethodGet, path, "", ""); code != http.StatusOK || body != "sk_live_123" {
		t.Fatalf("a pinned certificate: %d %s", code, body)
	}
}

func TestTheAuditLogHasEveryRequestAndNoSecret(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	ctx := context.Background()
	tok := f.token(admin, "app", TokenRequest{})
	f.role(admin, Role{Name: "app", Token: "app", Rules: []Rule{{Vault: "main", Items: "prod/db/*", Capabilities: []string{CapRead}}}})
	f.get("/v1/deliver/secret/main/prod/db/password", tok)
	f.get("/v1/deliver/secret/main/prod/api/key", tok)
	f.get("/v1/deliver/secret/main/prod/db/password", "svdt_nope")

	log, err := admin.Audit(ctx, 0, 0)
	if err != nil || !log.Intact {
		t.Fatalf("%+v %v", log, err)
	}
	var ops []string
	for _, e := range log.Entries {
		ops = append(ops, e.Op+":"+e.Outcome)
		if e.IP != "127.0.0.1" {
			t.Errorf("entry %d has IP %q", e.Seq, e.IP)
		}
	}
	want := "unseal:allowed,unseal:allowed,vault.add:allowed,token.create:allowed,role.set:allowed,read:allowed,read:denied,read:denied"
	if got := strings.Join(ops, ","); got != want {
		t.Fatalf("audit ops\n got %s\nwant %s", got, want)
	}
	read := log.Entries[5]
	if read.Identity != "token:app" || read.Role != "app" || read.Vault != "main" || read.Item != "prod/db/password" || read.Status != 200 {
		t.Fatalf("the read's entry: %+v", read)
	}
	if denied := log.Entries[6]; denied.Reason != "no rule allows reading it" || denied.Role != "app" {
		t.Fatalf("the refusal's entry: %+v", denied)
	}
	// Neither the log file nor its entries hold a secret, a token or a
	// share.
	raw, _ := os.ReadFile(filepath.Join(f.dir, AuditFile))
	entries, _ := json.Marshal(log.Entries)
	for _, secret := range []string{"hunter2", tok, f.res.AdminToken, f.res.Shares[0], "prod/db/password"} {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("the audit file holds %.12q in the clear", secret)
		}
		if secret != "prod/db/password" && bytes.Contains(entries, []byte(secret)) {
			t.Errorf("an audit entry holds %.12q", secret)
		}
	}
	// Removing a line breaks the chain.
	lines := bytes.SplitAfter(raw, []byte("\n"))
	cut := append(append([]byte{}, bytes.Join(lines[:3], nil)...), bytes.Join(lines[4:], nil)...)
	if err := os.WriteFile(filepath.Join(f.dir, AuditFile), cut, 0o600); err != nil {
		t.Fatal(err)
	}
	f.start()
	admin = f.admin()
	for _, s := range f.res.Shares[:2] {
		admin.Unseal(ctx, s)
	}
	log, err = admin.Audit(ctx, 0, 0)
	if err != nil || log.Intact || !strings.Contains(log.Problem, "chain breaks at line 4") {
		t.Fatalf("a log with a line cut out: intact %v, %q, %v", log.Intact, log.Problem, err)
	}
}

func TestTheOnDiskStateRevealsAndGrantsNothing(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	f.token(admin, "deploy-bot", TokenRequest{})
	f.role(admin, Role{Name: "secret-role-name", Token: "deploy-bot", Rules: []Rule{{Vault: "main", Items: "prod/db/*", Capabilities: []string{CapRead}}}})
	for _, name := range []string{PolicyFile, SealFile, ConfigFile, AuditFile} {
		b, err := os.ReadFile(filepath.Join(f.dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range []string{"secret-role-name", "deploy-bot", "prod/db", f.vaultDir, "SV-IDENTITY"} {
			if bytes.Contains(b, []byte(s)) {
				t.Errorf("%s holds %q in the clear", name, s)
			}
		}
	}
	// A policy altered on disk does not open.
	p := filepath.Join(f.dir, PolicyFile)
	b, _ := os.ReadFile(p)
	b[len(b)/2] ^= 1
	os.WriteFile(p, b, 0o600)
	f.start()
	c := f.admin()
	ctx := context.Background()
	c.Unseal(ctx, f.res.Shares[0])
	if _, err := c.Unseal(ctx, f.res.Shares[1]); err == nil || !strings.Contains(err.Error(), "altered") || !f.srv.Sealed() {
		t.Fatalf("unsealing with an altered policy: %v (sealed %v)", err, f.srv.Sealed())
	}
}

func TestRekeyReplacesTheSharesAndTheCredential(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	ctx := context.Background()
	st, err := admin.RekeyStart(ctx, RekeyRequest{Shares: 4, Threshold: 3, Credential: "new"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.RekeyStart(ctx, RekeyRequest{Shares: 4, Threshold: 3}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a second rekey at once: %v", err)
	}
	operator := f.client("") // operators need no token
	if _, err := operator.RekeyShare(ctx, "wrong-nonce", f.res.Shares[0]); apiStatus(err) != http.StatusNotFound {
		t.Fatalf("a share for another rekey: %v", err)
	}
	res, err := operator.RekeyShare(ctx, st.Nonce, f.res.Shares[0])
	if err != nil || res.Done || res.Progress != 1 {
		t.Fatalf("first share: %+v %v", res, err)
	}
	res, err = operator.RekeyShare(ctx, st.Nonce, f.res.Shares[2])
	if err != nil || !res.Done || len(res.Shares) != 4 || !strings.HasPrefix(res.Credential, "SVUK1-") {
		t.Fatalf("second share: %+v %v", res, err)
	}
	if !strings.HasPrefix(res.Shares[0], "SVUS1-") {
		t.Fatalf("new share %q", res.Shares[0])
	}
	if s, _ := admin.Status(ctx); s.Sealed || s.Threshold != 3 || s.Shares != 4 {
		t.Fatalf("status after the rekey: %+v", s)
	}
	// The old shares no longer unseal; the new ones do.
	admin.Seal(ctx)
	admin.Unseal(ctx, f.res.Shares[0])
	if _, err := admin.Unseal(ctx, f.res.Shares[1]); err == nil {
		t.Fatal("an old share was taken after the rekey")
	}
	for _, s := range res.Shares[1:4] {
		if _, err := admin.Unseal(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if f.srv.Sealed() {
		t.Fatal("the new shares do not unseal")
	}
	// The vaults and policy survived: the root key did not change.
	tok := f.token(admin, "after", TokenRequest{})
	f.role(admin, Role{Name: "after", Token: "after", Rules: []Rule{{Vault: "main", Items: "*", Capabilities: []string{CapRead}}}})
	if code, _ := f.get("/v1/deliver/secret/main/prod/db/password", tok); code != http.StatusOK {
		t.Fatalf("reading after the rekey: %d", code)
	}
	// The old credential no longer unseals; the new one does.
	os.WriteFile(filepath.Join(f.creds, DefaultCredential), []byte(f.res.Credential+"\n"), 0o600)
	f.start()
	if !f.srv.Sealed() {
		t.Fatal("the old credential unsealed the server after a rekey")
	}
	os.WriteFile(filepath.Join(f.creds, DefaultCredential), []byte(res.Credential+"\n"), 0o600)
	f.start()
	if f.srv.Sealed() {
		t.Fatal("the new credential does not unseal the server")
	}
}

func TestASystemdCredentialUnsealsAtStart(t *testing.T) {
	f := newFixture(t)
	if err := os.WriteFile(filepath.Join(f.creds, DefaultCredential), []byte(f.res.Credential), 0o600); err != nil {
		t.Fatal(err)
	}
	f.start()
	if f.srv.Sealed() {
		t.Fatal("the credential did not unseal the server")
	}
	// A share, or garbage, in the credential file does not.
	os.WriteFile(filepath.Join(f.creds, DefaultCredential), []byte(f.res.Shares[0]), 0o600)
	f.start()
	if !f.srv.Sealed() {
		t.Fatal("a share in the credential file unsealed the server")
	}
}

func TestAVaultNotYetSharedOpensOnceItIs(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	ctx := context.Background()
	// A second vault, of the other suite, not shared with the server.
	dir := filepath.Join(f.root, "nist")
	store, _ := svstore.OpenDir(dir)
	v, _, err := svcore.Create(store, svcrypto.NIST, svcore.NewSlot{Type: svformat.SlotKeyfile, Keyfile: svcrypto.RandomBytes(32)}, svcore.Options{Now: f.clock.now})
	if err != nil {
		t.Fatal(err)
	}
	v.Put(svcore.Item{Kind: "password", Name: "x", Fields: []svcore.Field{{Name: "password", Type: svcore.FieldConcealed, Value: []byte("nist-pw")}}})
	info, err := admin.AddVault(ctx, VaultRequest{Name: "nist", Path: dir})
	if err != nil {
		t.Fatal(err)
	}
	if info.Open || !strings.Contains(info.Problem, "not been shared") || info.Recipient != f.res.Recipients["sv1-nist"] || info.Suite != "sv1-nist" {
		t.Fatalf("an unshared vault: %+v", info)
	}
	tok := f.token(admin, "n", TokenRequest{})
	f.role(admin, Role{Name: "n", Token: "n", Rules: []Rule{{Vault: "nist", Items: "*", Capabilities: []string{CapRead}}}})
	if code, body := f.get("/v1/deliver/secret/nist/x", tok); code != http.StatusServiceUnavailable || !strings.Contains(body, "not been shared") {
		t.Fatalf("reading an unshared vault: %d %s", code, body)
	}
	f.share(v, "sv1-nist")
	f.clock.add(reopenEvery)
	if code, body := f.get("/v1/deliver/secret/nist/x?field=password&raw", tok); code != http.StatusOK || body != "nist-pw" {
		t.Fatalf("after sharing: %d %s", code, body)
	}
	// What the owner writes shows up.
	v.Put(svcore.Item{Kind: "password", Name: "x", Fields: []svcore.Field{{Name: "password", Type: svcore.FieldConcealed, Value: []byte("rotated-pw")}}})
	f.clock.add(time.Second)
	if code, body := f.get("/v1/deliver/secret/nist/x?field=password&raw", tok); code != http.StatusOK || body != "rotated-pw" {
		t.Fatalf("after the owner changed it: %d %s", code, body)
	}
	// A vault key rotation that keeps the server keeps it reading.
	if _, err := v.Rotate(nil, true, nil); err != nil {
		t.Fatal(err)
	}
	v.Put(svcore.Item{Kind: "password", Name: "y", Fields: []svcore.Field{{Name: "password", Type: svcore.FieldConcealed, Value: []byte("after-rotation")}}})
	f.clock.add(time.Second)
	if code, body := f.get("/v1/deliver/secret/nist/y?field=password&raw", tok); code != http.StatusOK || body != "after-rotation" {
		t.Fatalf("after a rotation: %d %s", code, body)
	}
	// Another vault moved into the folder is refused.
	if err := admin.RemoveVault(ctx, "nist"); err != nil {
		t.Fatal(err)
	}
	if code, _ := f.get("/v1/deliver/secret/nist/y", tok); code != http.StatusNotFound {
		t.Fatalf("a removed vault: %d", code)
	}
}

func TestDeliveryVaultsAreOnlyRead(t *testing.T) {
	v, err := openVaultReadOnly(newFixture(t).vaultDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := v.Unlock(svcore.Keyfile(make([]byte, 32))); !errors.Is(err, svcore.ErrWrongKey) {
		t.Fatalf("unlock %v", err)
	}
	var ro readOnly
	for _, err := range []error{ro.Create("x", nil), ro.Write("x", nil), ro.Remove("x")} {
		if !errors.Is(err, errReadOnly) {
			t.Errorf("a write went through: %v", err)
		}
	}
}

func TestTheAdminTokenIsItsOwnCredential(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	ctx := context.Background()
	tok := f.token(admin, "app", TokenRequest{})
	if _, err := f.client(tok).Tokens(ctx); apiStatus(err) != http.StatusUnauthorized {
		t.Fatalf("a delivery token on the admin API: %v", err)
	}
	nt, err := admin.RotateAdminToken(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := admin.Tokens(ctx); apiStatus(err) != http.StatusUnauthorized {
		t.Fatalf("the old admin token after a rotation: %v", err)
	}
	if _, err := f.client(nt.Token).Tokens(ctx); err != nil {
		t.Fatalf("the new admin token: %v", err)
	}
	id, err := f.client(nt.Token).Identity(ctx)
	if err != nil || id.Recipients["sv1-modern"] != f.res.Recipients["sv1-modern"] {
		t.Fatalf("identity %+v %v", id, err)
	}
}

func TestVaultsCanBeAddedByTheirSyncName(t *testing.T) {
	f := newFixture(t)
	admin := f.unsealed()
	ctx := context.Background()
	// The sync hub keeps a vault's files under vaults/<name>/files.
	hub := filepath.Join(f.root, "sync", "vaults", "team-vault", "files")
	if err := os.MkdirAll(filepath.Dir(hub), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.CopyFS(hub, os.DirFS(f.vaultDir)); err != nil {
		t.Fatal(err)
	}
	info, err := admin.AddVault(ctx, VaultRequest{Name: "team", Sync: "team-vault"})
	if err != nil || !info.Open || info.Path != hub {
		t.Fatalf("%+v %v", info, err)
	}
	if _, err := admin.AddVault(ctx, VaultRequest{Name: "rel", Path: "relative/dir"}); apiStatus(err) != http.StatusBadRequest {
		t.Fatalf("a relative path: %v", err)
	}
	if _, err := admin.AddVault(ctx, VaultRequest{Name: "team", Sync: "team-vault"}); apiStatus(err) != http.StatusConflict {
		t.Fatalf("a second vault of one name: %v", err)
	}
}
