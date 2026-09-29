package svcsi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svdeliver"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

const clusterIssuer = "https://kubernetes.default.svc.cluster.local"

// world is a delivery server that trusts a cluster's service-account
// tokens, and the provider on a unix socket.
type world struct {
	t      *testing.T
	server *httptest.Server
	fp     string
	admin  *svdeliver.Client
	key    ed25519.PrivateKey
	socket string
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{t: t}
	_, w.key, _ = ed25519.GenerateKey(rand.Reader)
	dir := t.TempDir()

	deliverDir := filepath.Join(dir, "deliver")
	res, err := svdeliver.Init(deliverDir, svdeliver.InitOptions{Shares: 2, Threshold: 2})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(deliverDir, svdeliver.ConfigFile), []byte(`{"rate": -1}`), 0o600)
	vaultDir := filepath.Join(dir, "vault")
	store, _ := svstore.OpenDir(vaultDir)
	v, _, err := svcore.Create(store, svcrypto.Modern, svcore.NewSlot{Type: svformat.SlotKeyfile, Keyfile: svcrypto.RandomBytes(32)}, svcore.Options{})
	if err != nil {
		t.Fatal(err)
	}
	v.Put(svcore.Item{Kind: "login", Name: "payments/db", Fields: []svcore.Field{
		{Name: "username", Type: svcore.FieldText, Value: []byte("pay")},
		{Name: "password", Type: svcore.FieldConcealed, Value: []byte("db-pw")},
	}})
	v.Put(svcore.Item{Kind: "key", Name: "payments/tls", Fields: []svcore.Field{{Name: "key", Type: svcore.FieldKey, Value: []byte{0, 1, 2, 0xff}}}})
	v.Put(svcore.Item{Kind: "password", Name: "billing/db", Fields: []svcore.Field{{Name: "password", Type: svcore.FieldConcealed, Value: []byte("not yours")}}})
	_, pub, _ := svformat.ParseRecipient(res.Recipients["sv1-modern"])
	v.AddSlot(svcore.NewSlot{Type: svformat.SlotRecipient, Recipient: pub})

	srv, err := svdeliver.New(svdeliver.Config{Dir: deliverDir, CredentialsDir: filepath.Join(dir, "no-creds")})
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
	w.admin.AddVault(ctx, svdeliver.VaultRequest{Name: "main", Path: vaultDir})
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]string{
		"kty": "OKP", "crv": "Ed25519", "kid": "sa", "x": base64.RawURLEncoding.EncodeToString(w.key.Public().(ed25519.PublicKey)),
	}}})
	if _, err := w.admin.SetIssuer(ctx, svdeliver.Issuer{Name: "cluster", URL: clusterIssuer, Audiences: []string{"secretvault"}, JWKS: jwks}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.admin.SetRole(ctx, svdeliver.Role{Name: "payments",
		OIDC:  &svdeliver.OIDCMatch{Issuer: "cluster", Claims: map[string]string{"kubernetes.io/namespace": "payments", "kubernetes.io/serviceaccount/name": "api"}},
		Rules: []svdeliver.Rule{{Vault: "main", Items: "payments/*", Capabilities: []string{svdeliver.CapRead}}},
	}); err != nil {
		t.Fatal(err)
	}

	// The provider, on a socket in a short directory (sockets allow about
	// a hundred bytes of path).
	sockDir, err := os.MkdirTemp("", "svcsi")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(sockDir) })
	w.socket = filepath.Join(sockDir, ProviderName+".sock")
	pctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	p := &Provider{Log: func(s string) { t.Log(s) }}
	go func() { done <- p.Serve(pctx, w.socket) }()
	t.Cleanup(func() { cancel(); <-done })
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(w.socket); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	return w
}

// saToken is a projected service-account token, as the kubelet makes it.
func (w *world) saToken(ns, name string) string {
	now := time.Now()
	h, _ := json.Marshal(map[string]string{"alg": "EdDSA", "kid": "sa"})
	c, _ := json.Marshal(map[string]any{
		"iss": clusterIssuer, "aud": []string{"secretvault"}, "sub": "system:serviceaccount:" + ns + ":" + name,
		"iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(time.Hour).Unix(),
		"kubernetes.io": map[string]any{"namespace": ns, "serviceaccount": map[string]any{"name": name, "uid": "u"}, "pod": map[string]any{"name": "p"}},
	})
	signed := base64.RawURLEncoding.EncodeToString(h) + "." + base64.RawURLEncoding.EncodeToString(c)
	return signed + "." + base64.RawURLEncoding.EncodeToString(ed25519.Sign(w.key, []byte(signed)))
}

// attributes are what the driver sends: the SecretProviderClass's
// parameters and the pod's, with its tokens.
func (w *world) attributes(objects, token string) string {
	tokens, _ := json.Marshal(map[string]any{"secretvault": map[string]string{"token": token, "expirationTimestamp": time.Now().Add(time.Hour).Format(time.RFC3339)}})
	a := map[string]string{
		"server": w.server.URL, "fingerprint": w.fp, "role": "payments", "audience": "secretvault", "objects": objects,
		"csi.storage.k8s.io/pod.name": "api-7d9", "csi.storage.k8s.io/pod.namespace": "payments",
		"csi.storage.k8s.io/serviceAccount.name": "api", tokensAttribute: string(tokens),
	}
	b, _ := json.Marshal(a)
	return string(b)
}

// call makes a unary gRPC call over the socket, as the driver's gRPC
// client would: HTTP/2 with prior knowledge.
func (w *world) call(method string, req []byte) ([]byte, int, string) {
	w.t.Helper()
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: &p, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", w.socket)
	}}
	defer tr.CloseIdleConnections()
	body := binary.BigEndian.AppendUint32([]byte{0}, uint32(len(req)))
	body = append(body, req...)
	hr, _ := http.NewRequest(http.MethodPost, "http://localhost/v1alpha1.CSIDriverProvider/"+method, bytes.NewReader(body))
	hr.Header.Set("Content-Type", "application/grpc")
	hr.Header.Set("TE", "trailers")
	resp, err := (&http.Client{Transport: tr}).Do(hr)
	if err != nil {
		w.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	if resp.ProtoMajor != 2 || resp.StatusCode != http.StatusOK {
		w.t.Fatalf("%s: %s %s", method, resp.Proto, resp.Status)
	}
	code, err := strconv.Atoi(resp.Trailer.Get("Grpc-Status"))
	if err != nil {
		w.t.Fatalf("%s: no grpc-status trailer (%v)", method, resp.Trailer)
	}
	msg, _ := url.PathUnescape(resp.Trailer.Get("Grpc-Message"))
	if code != codeOK {
		return nil, code, msg
	}
	if len(b) < 5 || int(binary.BigEndian.Uint32(b[1:5])) != len(b)-5 {
		w.t.Fatalf("%s: the response is not one message: %x", method, b)
	}
	return b[5:], code, msg
}

func (w *world) mount(req *MountRequest) (*MountResponse, int, string) {
	w.t.Helper()
	b, code, msg := w.call("Mount", req.Marshal())
	if code != codeOK {
		return nil, code, msg
	}
	var resp MountResponse
	if err := resp.Unmarshal(b); err != nil {
		w.t.Fatal(err)
	}
	return &resp, code, msg
}

func TestAPodMountsItsSecrets(t *testing.T) {
	w := newWorld(t)
	b, code, _ := w.call("Version", (&VersionRequest{Version: "v1alpha1"}).Marshal())
	var v VersionResponse
	if code != codeOK || v.Unmarshal(b) != nil || v.RuntimeName != ProviderName || v.Version != "v1alpha1" {
		t.Fatalf("Version: %d %+v", code, v)
	}

	objects := "# the pod's files\ndb/password = sv://main/payments/db#password\ndb/user=sv://main/payments/db#username\ntls.key=sv://main/payments/tls\n"
	resp, code, msg := w.mount(&MountRequest{Attributes: w.attributes(objects, w.saToken("payments", "api")), TargetPath: "/var/lib/kubelet/pods/x/volumes/v", Permission: "420"})
	if code != codeOK {
		t.Fatalf("Mount: %d %s", code, msg)
	}
	got := map[string]string{}
	for _, f := range resp.Files {
		if f.Mode != 0o644 {
			t.Errorf("%s has mode %o", f.Path, f.Mode)
		}
		got[f.Path] = string(f.Contents)
	}
	if got["db/password"] != "db-pw" || got["db/user"] != "pay" || got["tls.key"] != "\x00\x01\x02\xff" || len(got) != 3 {
		t.Fatalf("files %q", got)
	}
	if len(resp.ObjectVersion) != 3 || resp.ObjectVersion[0].ID != "db/password" || resp.ObjectVersion[0].Version == "" {
		t.Fatalf("object versions %+v", resp.ObjectVersion)
	}
}

func TestMountsAreRefused(t *testing.T) {
	w := newWorld(t)
	good := "db=sv://main/payments/db"
	ctx := context.Background()
	nt, _ := w.admin.CreateToken(ctx, svdeliver.TokenRequest{Name: "billing"})
	cases := []struct {
		name, attrs, secrets, perm string
		code                       int
		says                       string
	}{
		{"another namespace's pod", w.attributes(good, w.saToken("billing", "api")), "", "420", codePermissionDenied, "does not satisfy role"},
		{"a secret beyond the role", w.attributes("db=sv://main/billing/db", w.saToken("payments", "api")), "", "420", codeNotFound, "no such secret, or not allowed"},
		{"a path out of the volume", w.attributes("../etc/passwd=sv://main/payments/db", w.saToken("payments", "api")), "", "420", codeInvalidArgument, "not a path inside"},
		{"an absolute path", w.attributes("/etc/passwd=sv://main/payments/db", w.saToken("payments", "api")), "", "420", codeInvalidArgument, "not a path inside"},
		{"a path twice", w.attributes(good+"\n"+good, w.saToken("payments", "api")), "", "420", codeInvalidArgument, "twice"},
		{"no objects", w.attributes("", w.saToken("payments", "api")), "", "420", codeInvalidArgument, "names no file"},
		{"not a reference", w.attributes("db=main/payments/db", w.saToken("payments", "api")), "", "420", codeInvalidArgument, "not PATH=sv://"},
		{"a bad mode", w.attributes(good, w.saToken("payments", "api")), "", "\"rw\"", codeInvalidArgument, "not a file mode"},
		{"a forged token", w.attributes(good, w.saToken("payments", "api")[:40]+"x.y.z"), "", "420", codeUnauthenticated, "not accepted"},
		{"a token that exists but has no role", w.attributes(good, ""), `{"token":"` + nt.Token + `"}`, "420", codeNotFound, "not allowed"},
	}
	for _, c := range cases {
		_, code, msg := w.mount(&MountRequest{Attributes: c.attrs, Secrets: c.secrets, Permission: c.perm})
		if code != c.code || !strings.Contains(msg, c.says) {
			t.Errorf("%s: code %d %q; want %d saying %q", c.name, code, msg, c.code, c.says)
		}
	}
	// A token in the nodePublishSecretRef instead of a role.
	w.admin.SetRole(ctx, svdeliver.Role{Name: "billing", Token: "billing", Rules: []svdeliver.Rule{{Vault: "main", Items: "billing/*", Capabilities: []string{svdeliver.CapRead}}}})
	resp, code, msg := w.mount(&MountRequest{Attributes: w.attributes("pw=sv://main/billing/db", ""), Secrets: `{"token":"` + nt.Token + `"}`, Permission: "288"})
	if code != codeOK || len(resp.Files) != 1 || string(resp.Files[0].Contents) != "not yours" || resp.Files[0].Mode != 0o440 {
		t.Fatalf("with a token: %d %s %+v", code, msg, resp)
	}
}

func TestTheSocketSpeaksGRPCOnly(t *testing.T) {
	w := newWorld(t)
	if _, code, msg := w.call("Unmount", nil); code != codeUnimplemented || !strings.Contains(msg, "no method") {
		t.Fatalf("an unknown method: %d %s", code, msg)
	}
	var p http.Protocols
	p.SetUnencryptedHTTP2(true)
	tr := &http.Transport{Protocols: &p, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", w.socket)
	}}
	defer tr.CloseIdleConnections()
	resp, err := (&http.Client{Transport: tr}).Get("http://localhost/v1alpha1.CSIDriverProvider/Version")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnsupportedMediaType {
		t.Fatalf("a plain GET: %s", resp.Status)
	}
	if st, err := os.Stat(w.socket); err != nil || st.Mode().Perm() != 0o660 {
		t.Fatalf("the socket: %v %v", st.Mode(), err)
	}
}

func TestPercentEncoding(t *testing.T) {
	if got := percentEncode("100% sure: ünïcode\n"); got != "100%25 sure: %C3%BCn%C3%AFcode%0A" {
		t.Fatalf("%q", got)
	}
}
