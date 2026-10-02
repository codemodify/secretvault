package svops

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svdeliver"
	"github.com/codemodify/secretvault/svrpc"
)

// Secrets for CI jobs, pods and services, from a delivery server
// (secretvault-server with -delivery-dir), without a daemon or a vault on
// the machine: 'secretvault ci fetch' and 'ci run'. A client proves who it
// is with the first of:
//
//   - a token (TokenFile, or $SECRETVAULT_TOKEN);
//   - a client certificate (CertFile and KeyFile);
//   - with a Role, an ID token, which it finds in IDTokenFile, in the
//     variable IDTokenEnv names (default SECRETVAULT_ID_TOKEN, which
//     GitLab CI fills from id_tokens:), by asking GitHub Actions for one
//     ($ACTIONS_ID_TOKEN_REQUEST_URL, with the permission id-token: write),
//     or in a Kubernetes pod's service-account token file. It logs in to
//     the role with it, and the pipeline stores no secret at all.
//
// The server's certificate is trusted by Fingerprint, CA, or the system.

// K8sTokenPath is where Kubernetes mounts a pod's service-account token
// (tests point it elsewhere).
var K8sTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// DeliveryOptions say which delivery server, and how to prove who this is.
type DeliveryOptions struct {
	Server, Fingerprint, CA      string
	Role, Audience               string
	TokenFile, CertFile, KeyFile string
	IDTokenFile, IDTokenEnv      string // IDTokenEnv: SECRETVAULT_ID_TOKEN, unless a job names another
}

// DeliveryRef reads a reference to a delivery server's item. The server
// has no default vault, so it must be named.
func DeliveryRef(s string) (svrpc.Ref, error) {
	r, err := svrpc.ParseRef(s)
	if err != nil {
		return r, err
	}
	if r.Vault == "" {
		return r, fmt.Errorf("%q names no vault: a delivery server has no default one", s)
	}
	return r, nil
}

// DeliveryClient connects to the server and proves who this is.
func DeliveryClient(ctx context.Context, o DeliveryOptions) (*svdeliver.Client, error) {
	if o.Server == "" {
		return nil, errors.New("name the delivery server: --server URL (or $SECRETVAULT_SERVER)")
	}
	co := svdeliver.ClientOptions{URL: o.Server, Fingerprint: o.Fingerprint}
	if o.CA != "" {
		b, err := os.ReadFile(o.CA)
		if err != nil {
			return nil, err
		}
		co.CA = b
	}
	token := os.Getenv("SECRETVAULT_TOKEN")
	if o.TokenFile != "" {
		b, err := ReadSecretFile(o.TokenFile)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(string(b))
	}
	if (o.CertFile == "") != (o.KeyFile == "") {
		return nil, errors.New("--cert and --key go together")
	}
	switch {
	case token != "":
		co.Token = token
		return svdeliver.NewClient(co)
	case o.CertFile != "":
		cert, err := tls.LoadX509KeyPair(o.CertFile, o.KeyFile)
		if err != nil {
			return nil, err
		}
		co.Certificate = &cert
		return svdeliver.NewClient(co)
	case o.Role == "":
		return nil, errors.New("say how to prove who this is: --role ROLE (with this job's ID token), --token-file F, or --cert and --key")
	}
	cl, err := svdeliver.NewClient(co)
	if err != nil {
		return nil, err
	}
	jwt, source, err := IDToken(ctx, o)
	if err != nil {
		return nil, err
	}
	sess, err := cl.LoginOIDC(ctx, o.Role, jwt)
	if err != nil {
		return nil, fmt.Errorf("logging in to role %s with the ID token from %s: %w", o.Role, source, err)
	}
	cl.SetToken(sess.Token)
	return cl, nil
}

// IDToken finds this job's ID token, and says where it came from.
func IDToken(ctx context.Context, o DeliveryOptions) (string, string, error) {
	if o.IDTokenFile != "" {
		b, err := os.ReadFile(o.IDTokenFile)
		return strings.TrimSpace(string(b)), o.IDTokenFile, err
	}
	env := o.IDTokenEnv
	if v := strings.TrimSpace(os.Getenv(env)); v != "" {
		return v, "$" + env, nil
	}
	if u, t := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"); u != "" && t != "" {
		aud := o.Audience
		if aud == "" {
			aud = strings.TrimSuffix(o.Server, "/")
		}
		jwt, err := GithubIDToken(ctx, u, t, aud)
		return jwt, "GitHub Actions", err
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		if b, err := os.ReadFile(K8sTokenPath); err == nil {
			return strings.TrimSpace(string(b)), K8sTokenPath, nil
		}
	}
	return "", "", fmt.Errorf("found no ID token: not in --id-token-file, nor in $%s (GitLab: add it under id_tokens:), "+
		"nor from GitHub Actions (give the job 'permissions: id-token: write'), nor a Kubernetes service-account token", env)
}

// GithubIDToken asks GitHub Actions for the job's ID token, for an
// audience.
func GithubIDToken(ctx context.Context, requestURL, bearer, audience string) (string, error) {
	u, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("$ACTIONS_ID_TOKEN_REQUEST_URL is not a URL")
	}
	q := u.Query()
	q.Set("audience", audience)
	u.RawQuery = q.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return "", fmt.Errorf("asking GitHub Actions for an ID token: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("GitHub Actions gave no ID token (%s); does the job have 'permissions: id-token: write'?", resp.Status)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.Unmarshal(b, &out); err != nil || out.Value == "" {
		return "", errors.New("GitHub Actions answered with no ID token")
	}
	return out.Value, nil
}

// ValidEnvName reports whether s can name an environment variable.
func ValidEnvName(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		if !(r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || i > 0 && r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// ShellQuote quotes s for a POSIX shell.
func ShellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
