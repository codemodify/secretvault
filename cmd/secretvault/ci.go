package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svdeliver"
)

// Secrets for CI jobs, pods and services, from a delivery server
// (secretvault-server with -delivery-dir), without a daemon or a vault
// on the machine:
//
//	secretvault ci fetch sv://VAULT/ITEM[#FIELD]...     print the values
//	secretvault ci fetch NAME=sv://VAULT/ITEM[#FIELD]... print them as shell exports
//	secretvault ci run [--env-file F] [--env K=V] -- CMD ...
//
// It proves who it is with the first of:
//
//   - a token (--token-file, or $SECRETVAULT_TOKEN);
//   - a client certificate (--cert and --key);
//   - with --role, an ID token, which it finds in --id-token-file, in the
//     variable --id-token-env names (default SECRETVAULT_ID_TOKEN, which
//     GitLab CI fills from id_tokens:), by asking GitHub Actions for one
//     ($ACTIONS_ID_TOKEN_REQUEST_URL, with the permission id-token: write),
//     or in a Kubernetes pod's service-account token file. It logs in to
//     the role with it, and the pipeline stores no secret at all.
//
// The server is --server ($SECRETVAULT_SERVER), its certificate trusted by
// --fingerprint ($SECRETVAULT_SERVER_FINGERPRINT), --ca, or the system.

// k8sTokenPath is where Kubernetes mounts a pod's service-account token.
var k8sTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"

// ciFlags are the flags every ci command takes.
type ciFlags struct {
	server, fingerprint, ca      string
	role, audience               string
	tokenFile, certFile, keyFile string
	idTokenFile, idTokenEnv      string
	timeout                      time.Duration
	githubEnv                    bool
	envFiles, envs               multi
}

func (c *cli) ciFlagSet(name string, f *ciFlags) *flag.FlagSet {
	fs := c.flags(name)
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	fs.StringVar(&f.server, "server", env("SECRETVAULT_SERVER", ""), "the delivery server's `URL`")
	fs.StringVar(&f.fingerprint, "fingerprint", env("SECRETVAULT_SERVER_FINGERPRINT", ""), "trust the server's certificate by its SHA-256 `FP` (a self-signed one)")
	fs.StringVar(&f.ca, "ca", env("SECRETVAULT_SERVER_CA", ""), "trust the server's certificate if it chains to the CA in `FILE`")
	fs.StringVar(&f.role, "role", env("SECRETVAULT_ROLE", ""), "log in to `ROLE` with this job's ID token")
	fs.StringVar(&f.audience, "audience", env("SECRETVAULT_AUDIENCE", ""), "the `AUD` to ask GitHub Actions to put in the ID token (default: the server's URL)")
	fs.StringVar(&f.tokenFile, "token-file", env("SECRETVAULT_TOKEN_FILE", ""), "use the token in `FILE` instead of an ID token")
	fs.StringVar(&f.certFile, "cert", "", "present the client certificate in `FILE` (PEM)")
	fs.StringVar(&f.keyFile, "key", "", "the client certificate's private key, in `FILE` (PEM)")
	fs.StringVar(&f.idTokenFile, "id-token-file", env("SECRETVAULT_ID_TOKEN_FILE", ""), "read the ID token from `FILE` (a projected service-account token, say)")
	fs.StringVar(&f.idTokenEnv, "id-token-env", "SECRETVAULT_ID_TOKEN", "the environment `VARIABLE` holding the ID token (GitLab's id_tokens:)")
	fs.DurationVar(&f.timeout, "timeout", time.Minute, "give up after this long")
	return fs
}

func (c *cli) cmdCI(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: secretvault ci fetch REF... | ci run [--env-file F] -- CMD ...  (with --server URL and --role ROLE or --token-file F)")
		return errUsage
	}
	switch args[0] {
	case "fetch":
		return c.ciFetch(args[1:])
	case "run":
		return c.ciRun(args[1:])
	}
	fmt.Fprintf(c.stderr, "unknown ci command %q (fetch, run)\n", args[0])
	return errUsage
}

// deliveryRef is a reference to a delivery server's item. The server has
// no default vault, so it must be named.
func deliveryRef(s string) (ref, error) {
	r, err := parseRef(s)
	if err != nil {
		return r, err
	}
	if r.vault == "" {
		return r, fmt.Errorf("%q names no vault: a delivery server has no default one", s)
	}
	return r, nil
}

func (c *cli) ciFetch(args []string) error {
	var f ciFlags
	fs := c.ciFlagSet("ci fetch", &f)
	fs.BoolVar(&f.githubEnv, "github-env", false, "for NAME=REF: add NAME to the job's later steps ($GITHUB_ENV), masked in its logs")
	pos, err := parse(fs, args, 1, -1, "sv://VAULT/ITEM[#FIELD]... | NAME=sv://...  --server URL (--role ROLE | --token-file F)")
	if err != nil {
		return err
	}
	type want struct {
		name string
		ref  ref
	}
	var wants []want
	for _, p := range pos {
		name, rest, named := strings.Cut(p, "=")
		if !named || strings.HasPrefix(p, "sv://") {
			name, rest = "", p
		} else if !validEnvName(name) {
			return fmt.Errorf("%q is not a variable name", name)
		}
		r, err := deliveryRef(rest)
		if err != nil {
			return err
		}
		if f.githubEnv && name == "" {
			return fmt.Errorf("--github-env takes NAME=%s", rest)
		}
		wants = append(wants, want{name, r})
	}
	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()
	cl, err := c.deliveryClient(ctx, &f)
	if err != nil {
		return err
	}
	var ghEnv *os.File
	if f.githubEnv {
		path := os.Getenv("GITHUB_ENV")
		if path == "" {
			return errors.New("--github-env is for GitHub Actions: $GITHUB_ENV is not set")
		}
		if ghEnv, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0); err != nil {
			return err
		}
		defer ghEnv.Close()
	}
	for _, w := range wants {
		v, err := cl.Value(ctx, w.ref.vault, w.ref.item, w.ref.field)
		if err != nil {
			return fmt.Errorf("sv://%s/%s: %w", w.ref.vault, w.ref.item, err)
		}
		switch {
		case ghEnv != nil:
			// Masked first, so the value never shows in the job's log.
			for line := range strings.SplitSeq(string(v), "\n") {
				if strings.TrimSpace(line) != "" {
					fmt.Fprintf(c.stdout, "::add-mask::%s\n", line)
				}
			}
			delim := "SECRETVAULT_" + strings.ToUpper(fmt.Sprintf("%x", svcrypto.RandomBytes(12)))
			if _, err := fmt.Fprintf(ghEnv, "%s<<%s\n%s\n%s\n", w.name, delim, v, delim); err != nil {
				return err
			}
		case w.name != "":
			fmt.Fprintf(c.stdout, "export %s=%s\n", w.name, shellQuote(string(v)))
		default:
			c.stdout.Write(v)
			fmt.Fprintln(c.stdout)
		}
		clear(v)
	}
	return nil
}

func (c *cli) ciRun(args []string) error {
	var f ciFlags
	fs := c.ciFlagSet("ci run", &f)
	fs.Var(&f.envFiles, "env-file", "also load KEY=VALUE lines from `FILE` (repeatable)")
	fs.Var(&f.envs, "env", "set `KEY=VALUE` (repeatable)")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	cmdline := fs.Args()
	if len(cmdline) == 0 {
		fmt.Fprintln(c.stderr, "usage: secretvault ci run [--env-file F] [--env K=V] --server URL (--role ROLE | --token-file F) -- COMMAND [ARGS...]")
		return errUsage
	}
	env := map[string]string{}
	var order []string
	set := func(k, v string) {
		if _, ok := env[k]; !ok {
			order = append(order, k)
		}
		env[k] = v
	}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			set(k, v)
		}
	}
	for _, file := range f.envFiles {
		pairs, err := readEnvFile(file)
		if err != nil {
			return err
		}
		for _, p := range pairs {
			set(p[0], p[1])
		}
	}
	for _, kv := range f.envs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("--env %q is not KEY=VALUE", kv)
		}
		set(k, v)
	}
	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()
	var cl *svdeliver.Client
	for _, k := range order {
		if !strings.HasPrefix(env[k], "sv://") {
			continue
		}
		r, err := deliveryRef(env[k])
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		if cl == nil {
			if cl, err = c.deliveryClient(ctx, &f); err != nil {
				return err
			}
		}
		v, err := cl.Value(ctx, r.vault, r.item, r.field)
		if err != nil {
			return fmt.Errorf("%s: sv://%s/%s: %w", k, r.vault, r.item, err)
		}
		env[k] = string(v)
		clear(v)
	}
	var list []string
	for _, k := range order {
		list = append(list, k+"="+env[k])
	}
	path, err := exec.LookPath(cmdline[0])
	if err != nil {
		return err
	}
	cmd := exec.Command(path, cmdline[1:]...)
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = list, c.stdin, c.stdout, c.stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitCode(ee.ExitCode())
		}
		return err
	}
	return nil
}

// deliveryClient connects to the server and proves who this is.
func (c *cli) deliveryClient(ctx context.Context, f *ciFlags) (*svdeliver.Client, error) {
	if f.server == "" {
		return nil, errors.New("name the delivery server: --server URL (or $SECRETVAULT_SERVER)")
	}
	o := svdeliver.ClientOptions{URL: f.server, Fingerprint: f.fingerprint}
	if f.ca != "" {
		b, err := os.ReadFile(f.ca)
		if err != nil {
			return nil, err
		}
		o.CA = b
	}
	token := os.Getenv("SECRETVAULT_TOKEN")
	if f.tokenFile != "" {
		b, err := readSecretFile(f.tokenFile)
		if err != nil {
			return nil, err
		}
		token = strings.TrimSpace(string(b))
	}
	if (f.certFile == "") != (f.keyFile == "") {
		return nil, errors.New("--cert and --key go together")
	}
	switch {
	case token != "":
		o.Token = token
		return svdeliver.NewClient(o)
	case f.certFile != "":
		cert, err := tls.LoadX509KeyPair(f.certFile, f.keyFile)
		if err != nil {
			return nil, err
		}
		o.Certificate = &cert
		return svdeliver.NewClient(o)
	case f.role == "":
		return nil, errors.New("say how to prove who this is: --role ROLE (with this job's ID token), --token-file F, or --cert and --key")
	}
	cl, err := svdeliver.NewClient(o)
	if err != nil {
		return nil, err
	}
	jwt, source, err := c.idToken(ctx, f)
	if err != nil {
		return nil, err
	}
	sess, err := cl.LoginOIDC(ctx, f.role, jwt)
	if err != nil {
		return nil, fmt.Errorf("logging in to role %s with the ID token from %s: %w", f.role, source, err)
	}
	cl.SetToken(sess.Token)
	return cl, nil
}

// idToken finds this job's ID token, and says where it came from.
func (c *cli) idToken(ctx context.Context, f *ciFlags) (string, string, error) {
	if f.idTokenFile != "" {
		b, err := os.ReadFile(f.idTokenFile)
		return strings.TrimSpace(string(b)), f.idTokenFile, err
	}
	if v := strings.TrimSpace(os.Getenv(f.idTokenEnv)); v != "" {
		return v, "$" + f.idTokenEnv, nil
	}
	if u, t := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN"); u != "" && t != "" {
		aud := f.audience
		if aud == "" {
			aud = serverOrigin(f.server)
		}
		jwt, err := githubIDToken(ctx, u, t, aud)
		return jwt, "GitHub Actions", err
	}
	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		if b, err := os.ReadFile(k8sTokenPath); err == nil {
			return strings.TrimSpace(string(b)), k8sTokenPath, nil
		}
	}
	return "", "", fmt.Errorf("found no ID token: not in --id-token-file, nor in $%s (GitLab: add it under id_tokens:), "+
		"nor from GitHub Actions (give the job 'permissions: id-token: write'), nor a Kubernetes service-account token", f.idTokenEnv)
}

// githubIDToken asks GitHub Actions for the job's ID token, for an
// audience.
func githubIDToken(ctx context.Context, requestURL, bearer, audience string) (string, error) {
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

// serverOrigin is the audience asked for by default: the server's URL
// without a trailing slash.
func serverOrigin(server string) string { return strings.TrimSuffix(server, "/") }

func validEnvName(s string) bool {
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

// shellQuote quotes s for a POSIX shell.
func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }
