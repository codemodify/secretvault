package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svdeliver"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Secrets for CI jobs, pods and services, from a delivery server
// (secretvault-server with -delivery-dir), without a daemon or a vault
// on the machine:
//
//	secretvault ci fetch sv://VAULT/ITEM[#FIELD]...     print the values
//	secretvault ci fetch NAME=sv://VAULT/ITEM[#FIELD]... print them as shell exports
//	secretvault ci run [--env-file F] [--env K=V] -- CMD ...
//
// How it proves who it is (a token, a client certificate, or with --role
// the job's ID token) is svops' (ci.go). The server is --server
// ($SECRETVAULT_SERVER), its certificate trusted by --fingerprint
// ($SECRETVAULT_SERVER_FINGERPRINT), --ca, or the system.

// ciFlags are the flags every ci command takes.
type ciFlags struct {
	svops.DeliveryOptions
	timeout        time.Duration
	githubEnv      bool
	envFiles, envs multi
}

func (c *cli) ciFlagSet(name string, f *ciFlags) *flag.FlagSet {
	fs := c.flags(name)
	env := func(k, def string) string {
		if v := os.Getenv(k); v != "" {
			return v
		}
		return def
	}
	fs.StringVar(&f.Server, "server", env("SECRETVAULT_SERVER", ""), "the delivery server's `URL`")
	fs.StringVar(&f.Fingerprint, "fingerprint", env("SECRETVAULT_SERVER_FINGERPRINT", ""), "trust the server's certificate by its SHA-256 `FP` (a self-signed one)")
	fs.StringVar(&f.CA, "ca", env("SECRETVAULT_SERVER_CA", ""), "trust the server's certificate if it chains to the CA in `FILE`")
	fs.StringVar(&f.Role, "role", env("SECRETVAULT_ROLE", ""), "log in to `ROLE` with this job's ID token")
	fs.StringVar(&f.Audience, "audience", env("SECRETVAULT_AUDIENCE", ""), "the `AUD` to ask GitHub Actions to put in the ID token (default: the server's URL)")
	fs.StringVar(&f.TokenFile, "token-file", env("SECRETVAULT_TOKEN_FILE", ""), "use the token in `FILE` instead of an ID token")
	fs.StringVar(&f.CertFile, "cert", "", "present the client certificate in `FILE` (PEM)")
	fs.StringVar(&f.KeyFile, "key", "", "the client certificate's private key, in `FILE` (PEM)")
	fs.StringVar(&f.IDTokenFile, "id-token-file", env("SECRETVAULT_ID_TOKEN_FILE", ""), "read the ID token from `FILE` (a projected service-account token, say)")
	fs.StringVar(&f.IDTokenEnv, "id-token-env", "SECRETVAULT_ID_TOKEN", "the environment `VARIABLE` holding the ID token (GitLab's id_tokens:)")
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
		ref  svrpc.Ref
	}
	var wants []want
	for _, p := range pos {
		name, rest, named := strings.Cut(p, "=")
		if !named || strings.HasPrefix(p, "sv://") {
			name, rest = "", p
		} else if !svops.ValidEnvName(name) {
			return fmt.Errorf("%q is not a variable name", name)
		}
		r, err := svops.DeliveryRef(rest)
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
	cl, err := svops.DeliveryClient(ctx, f.DeliveryOptions)
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
		v, err := cl.Value(ctx, w.ref.Vault, w.ref.Item, w.ref.Field)
		if err != nil {
			return fmt.Errorf("sv://%s/%s: %w", w.ref.Vault, w.ref.Item, err)
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
			fmt.Fprintf(c.stdout, "export %s=%s\n", w.name, svops.ShellQuote(string(v)))
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
	env := svops.NewEnviron(os.Environ())
	if err := env.LoadFiles(f.envFiles); err != nil {
		return err
	}
	if err := env.SetPairs(f.envs); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), f.timeout)
	defer cancel()
	var cl *svdeliver.Client
	connect := func() (err error) {
		cl, err = svops.DeliveryClient(ctx, f.DeliveryOptions)
		return err
	}
	fetch := func(r svrpc.Ref) ([]byte, error) {
		v, err := cl.Value(ctx, r.Vault, r.Item, r.Field)
		if err != nil {
			return nil, fmt.Errorf("sv://%s/%s: %w", r.Vault, r.Item, err)
		}
		return v, nil
	}
	if err := env.Resolve(svops.DeliveryRef, connect, fetch); err != nil {
		return err
	}
	return c.runCommand(cmdline, env.List())
}
