package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svdeliver"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svstore"
)

// ciWorld is a delivery server with a vault, an OIDC issuer on
// localhost, and GitHub Actions' token endpoint, faked.
type ciWorld struct {
	t      *testing.T
	dir    string
	server *httptest.Server
	fp     string
	admin  *svdeliver.Client

	issuer *httptest.Server
	key    ed25519.PrivateKey

	mu        sync.Mutex
	audiences []string // what GitHub was asked for
}

// clearCIEnv makes sure this test's own environment (say, a real CI job
// running the tests) plays no part.
func clearCIEnv(t *testing.T) {
	for _, k := range []string{"ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "KUBERNETES_SERVICE_HOST",
		"SECRETVAULT_ID_TOKEN", "SECRETVAULT_ID_TOKEN_FILE", "SECRETVAULT_TOKEN", "SECRETVAULT_TOKEN_FILE", "SECRETVAULT_SERVER",
		"SECRETVAULT_SERVER_FINGERPRINT", "SECRETVAULT_SERVER_CA", "SECRETVAULT_ROLE", "SECRETVAULT_AUDIENCE", "GITHUB_ENV", "CI_JOB_TOKEN"} {
		t.Setenv(k, "")
	}
	old := svops.K8sTokenPath
	svops.K8sTokenPath = filepath.Join(t.TempDir(), "no-token")
	t.Cleanup(func() { svops.K8sTokenPath = old })
}

func newCIWorld(t *testing.T) *ciWorld {
	t.Helper()
	clearCIEnv(t)
	w := &ciWorld{t: t, dir: t.TempDir()}
	_, w.key, _ = ed25519.GenerateKey(rand.Reader)

	// The issuer: discovery and its key set.
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(rw http.ResponseWriter, r *http.Request) {
		json.NewEncoder(rw).Encode(map[string]string{"issuer": w.issuer.URL, "jwks_uri": w.issuer.URL + "/keys"})
	})
	mux.HandleFunc("GET /keys", func(rw http.ResponseWriter, r *http.Request) {
		json.NewEncoder(rw).Encode(map[string]any{"keys": []any{map[string]string{
			"kty": "OKP", "crv": "Ed25519", "kid": "k1", "x": base64.RawURLEncoding.EncodeToString(w.key.Public().(ed25519.PublicKey)),
		}}})
	})
	w.issuer = httptest.NewTLSServer(mux)
	t.Cleanup(w.issuer.Close)

	// The delivery server, unsealed, with a vault shared with it.
	deliverDir := filepath.Join(w.dir, "deliver")
	res, err := svdeliver.Init(deliverDir, svdeliver.InitOptions{Shares: 2, Threshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(deliverDir, svdeliver.ConfigFile), []byte(`{"rate": -1}`), 0o600)
	vaultDir := filepath.Join(w.dir, "vault")
	store, _ := svstore.OpenDir(vaultDir)
	v, _, err := svcore.Create(store, svcrypto.Modern, svcore.NewSlot{Type: svformat.SlotKeyfile, Keyfile: svcrypto.RandomBytes(32)}, svcore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v.Put(svcore.Item{Kind: "login", Name: "prod/db", Fields: []svcore.Field{
		{Name: "username", Type: svcore.FieldText, Value: []byte("app")},
		{Name: "password", Type: svcore.FieldConcealed, Value: []byte("it's hunter2")},
	}})
	v.Put(svcore.Item{Kind: "api-key", Name: "prod/api", Fields: []svcore.Field{{Name: "secret", Type: svcore.FieldConcealed, Value: []byte("sk_live\nline2")}}})
	_, pub, _ := svformat.ParseRecipient(res.Recipients["sv1-modern"])
	v.AddSlot(svcore.NewSlot{Type: svformat.SlotRecipient, Recipient: pub})

	srv, err := svdeliver.New(svdeliver.Config{Dir: deliverDir, CredentialsDir: filepath.Join(w.dir, "no-creds")})
	if err != nil {
		t.Fatal(err)
	}
	w.server = httptest.NewUnstartedServer(srv)
	w.server.TLS = &tls.Config{ClientAuth: tls.RequestClientCert}
	w.server.StartTLS()
	t.Cleanup(func() { w.server.Close(); srv.Close() })
	sum := sha256.Sum256(w.server.Certificate().Raw)
	w.fp = hex.EncodeToString(sum[:])
	w.admin, _ = svdeliver.NewClient(svdeliver.ClientOptions{URL: w.server.URL, Fingerprint: w.fp, Token: res.AdminToken})
	ctx := context.Background()
	for _, s := range res.Shares {
		if _, err := w.admin.Unseal(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := w.admin.AddVault(ctx, svdeliver.VaultRequest{Name: "main", Path: vaultDir}); err != nil {
		t.Fatal(err)
	}
	caPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: w.issuer.Certificate().Raw}))
	if _, err := w.admin.SetIssuer(ctx, svdeliver.Issuer{Name: "ci", URL: w.issuer.URL, Audiences: []string{w.server.URL, "gitlab-aud"}, CA: caPEM}); err != nil {
		t.Fatal(err)
	}
	rules := []svdeliver.Rule{{Vault: "main", Items: "prod/*", Capabilities: []string{svdeliver.CapRead}}}
	for _, r := range []svdeliver.Role{
		{Name: "gh-deploy", OIDC: &svdeliver.OIDCMatch{Issuer: "ci", Claims: map[string]string{"repository": "acme/app", "ref": "refs/heads/main"}}, Rules: rules},
		{Name: "gl-deploy", OIDC: &svdeliver.OIDCMatch{Issuer: "ci", Claims: map[string]string{"project_path": "acme/app", "ref_type": "branch"}}, Rules: rules},
		{Name: "k8s-api", OIDC: &svdeliver.OIDCMatch{Issuer: "ci", Claims: map[string]string{"sub": "system:serviceaccount:payments:api"}}, Rules: rules},
	} {
		if _, err := w.admin.SetRole(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	return w
}

// jwt signs claims as the issuer, for an audience.
func (w *ciWorld) jwt(aud string, claims map[string]any) string {
	now := time.Now()
	c := map[string]any{"iss": w.issuer.URL, "aud": aud, "iat": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	for k, v := range claims {
		c[k] = v
	}
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "k1", "typ": "JWT"})
	b, _ := json.Marshal(c)
	signed := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(b)
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(w.key, []byte(signed)))
}

// github fakes GitHub Actions' ID token endpoint for the job.
func (w *ciWorld) github() {
	gh := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "bearer job-request-token" {
			http.Error(rw, "no", http.StatusUnauthorized)
			return
		}
		aud := r.URL.Query().Get("audience")
		w.mu.Lock()
		w.audiences = append(w.audiences, aud)
		w.mu.Unlock()
		json.NewEncoder(rw).Encode(map[string]any{"count": 1, "value": w.jwt(aud, map[string]any{
			"sub": "repo:acme/app:ref:refs/heads/main", "repository": "acme/app", "ref": "refs/heads/main",
		})})
	}))
	w.t.Cleanup(gh.Close)
	w.t.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", gh.URL+"/token?api-version=2.0")
	w.t.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "job-request-token")
}

// ci runs 'secretvault ci ...' against the world's server.
func (w *ciWorld) ci(args ...string) (string, string, int) {
	var out, errb bytes.Buffer
	c := &cli{stdin: strings.NewReader(""), stdout: &out, stderr: &errb}
	// The server's flags go straight after the subcommand: ci run's own
	// arguments end at "--".
	full := append([]string{"ci", args[0], "--server", w.server.URL, "--fingerprint", w.fp}, args[1:]...)
	code := c.run(full)
	return out.String(), errb.String(), code
}

func TestCIFetchInGitHubActions(t *testing.T) {
	w := newCIWorld(t)
	w.github()
	out, errs, code := w.ci("fetch", "sv://main/prod/db#password", "--role", "gh-deploy")
	if code != 0 || out != "it's hunter2\n" {
		t.Fatalf("exit %d, %q, %s", code, out, errs)
	}
	if len(w.audiences) != 1 || w.audiences[0] != w.server.URL {
		t.Fatalf("GitHub was asked for audiences %v; want the server's URL", w.audiences)
	}
	// Exports for eval, quoted for the shell.
	out, _, code = w.ci("fetch", "DB_PASSWORD=sv://main/prod/db#password", "DB_USER=sv://main/prod/db#username", "--role", "gh-deploy")
	if code != 0 || out != "export DB_PASSWORD='it'\\''s hunter2'\nexport DB_USER='app'\n" {
		t.Fatalf("exports: %d %q", code, out)
	}
	// Into $GITHUB_ENV for later steps, masked in the log.
	envFile := filepath.Join(w.dir, "github_env")
	os.WriteFile(envFile, nil, 0o600)
	t.Setenv("GITHUB_ENV", envFile)
	out, errs, code = w.ci("fetch", "API_KEY=sv://main/prod/api", "--role", "gh-deploy", "--github-env")
	if code != 0 || out != "::add-mask::sk_live\n::add-mask::line2\n" {
		t.Fatalf("--github-env: %d %q %s", code, out, errs)
	}
	b, _ := os.ReadFile(envFile)
	lines := strings.Split(string(b), "\n")
	if len(lines) != 5 || !strings.HasPrefix(lines[0], "API_KEY<<SECRETVAULT_") || lines[1] != "sk_live" || lines[2] != "line2" || lines[3] != strings.TrimPrefix(lines[0], "API_KEY<<") {
		t.Fatalf("$GITHUB_ENV holds %q", b)
	}
	// A role whose claims the job's token does not meet.
	if _, errs, code := w.ci("fetch", "sv://main/prod/db", "--role", "gl-deploy"); code != 1 || !strings.Contains(errs, "does not satisfy role") {
		t.Fatalf("the wrong role: %d %s", code, errs)
	}
}

func TestCIFetchInGitLabAndKubernetes(t *testing.T) {
	w := newCIWorld(t)
	// GitLab puts the token in the variable its id_tokens: names.
	t.Setenv("SECRETVAULT_ID_TOKEN", w.jwt("gitlab-aud", map[string]any{"sub": "project_path:acme/app:ref_type:branch:ref:main", "project_path": "acme/app", "ref_type": "branch", "ref": "main"}))
	if out, errs, code := w.ci("fetch", "sv://main/prod/db", "--role", "gl-deploy"); code != 0 || out != "it's hunter2\n" {
		t.Fatalf("GitLab: %d %q %s", code, out, errs)
	}
	t.Setenv("MY_TOKEN", w.jwt("gitlab-aud", map[string]any{"project_path": "acme/app", "ref_type": "branch"}))
	t.Setenv("SECRETVAULT_ID_TOKEN", "")
	if out, errs, code := w.ci("fetch", "sv://main/prod/db", "--role", "gl-deploy", "--id-token-env", "MY_TOKEN"); code != 0 || out != "it's hunter2\n" {
		t.Fatalf("GitLab, another variable: %d %q %s", code, out, errs)
	}
	t.Setenv("MY_TOKEN", "")

	// Nothing to go on.
	if _, errs, code := w.ci("fetch", "sv://main/prod/db", "--role", "k8s-api"); code != 1 || !strings.Contains(errs, "found no ID token") {
		t.Fatalf("no ID token anywhere: %d %s", code, errs)
	}

	// A pod's service-account token.
	tokenFile := filepath.Join(w.dir, "sa-token")
	os.WriteFile(tokenFile, []byte(w.jwt(w.server.URL, map[string]any{"sub": "system:serviceaccount:payments:api"})+"\n"), 0o600)
	svops.K8sTokenPath = tokenFile
	t.Setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
	if out, errs, code := w.ci("fetch", "sv://main/prod/db#username", "--role", "k8s-api"); code != 0 || out != "app\n" {
		t.Fatalf("Kubernetes: %d %q %s", code, out, errs)
	}
	// Or named outright.
	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	if out, errs, code := w.ci("fetch", "sv://main/prod/db#username", "--role", "k8s-api", "--id-token-file", tokenFile); code != 0 || out != "app\n" {
		t.Fatalf("--id-token-file: %d %q %s", code, out, errs)
	}
}

func TestCIRunAndTokens(t *testing.T) {
	w := newCIWorld(t)
	ctx := context.Background()
	nt, err := w.admin.CreateToken(ctx, svdeliver.TokenRequest{Name: "svc"})
	if err != nil {
		t.Fatal(err)
	}
	w.admin.SetRole(ctx, svdeliver.Role{Name: "svc", Token: "svc", Rules: []svdeliver.Rule{{Vault: "main", Items: "prod/db", Capabilities: []string{svdeliver.CapRead}}}})
	tokenFile := filepath.Join(w.dir, "token")
	os.WriteFile(tokenFile, []byte(nt.Token+"\n"), 0o600)

	env := filepath.Join(w.dir, "app.env")
	os.WriteFile(env, []byte("DB_PASSWORD=sv://main/prod/db#password\nPLAIN=kept\n"), 0o600)
	out, errs, code := w.ci("run", "--token-file", tokenFile, "--env-file", env, "--", "sh", "-c", `printf "%s|%s" "$DB_PASSWORD" "$PLAIN"`)
	if code != 0 || out != "it's hunter2|kept" {
		t.Fatalf("ci run: %d %q %s", code, out, errs)
	}
	// What the token may not read reads as absent.
	if _, errs, code := w.ci("fetch", "sv://main/prod/api", "--token-file", tokenFile); code != 1 || !strings.Contains(errs, "no such secret, or not allowed") {
		t.Fatalf("beyond the token's role: %d %s", code, errs)
	}
	if _, _, code := w.ci("run", "--token-file", tokenFile, "--", "sh", "-c", "exit 3"); code != 3 {
		t.Fatalf("the child's exit status: %d", code)
	}
	if _, errs, code := w.ci("fetch", "sv://-/prod/db", "--token-file", tokenFile); code != 1 || !strings.Contains(errs, "no default one") {
		t.Fatalf("the default vault: %d %s", code, errs)
	}
	if _, errs, code := w.ci("fetch", "sv://main/prod/db"); code != 1 || !strings.Contains(errs, "--role ROLE") {
		t.Fatalf("no way to log in: %d %s", code, errs)
	}
}
