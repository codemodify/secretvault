package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"golang.org/x/term"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svdeliver"
	"github.com/codemodify/secretvault/svterm"
)

// The delivery side's commands. init works on the delivery directory
// itself, on the server's machine; every other command talks to the
// running server:
//
//	secretvault-server init --delivery-dir DIR [--shares 5] [--threshold 3] [--credential-file F]
//	secretvault-server status
//	secretvault-server unseal [--share-file F] [--reset]            one operator's share
//	secretvault-server seal
//	secretvault-server rekey --shares N --threshold K [--credential keep|new|remove]
//	secretvault-server rekey [--share-file F] [--cancel]            an operator's current share
//	secretvault-server token create NAME [--ttl D] [--cidr C]... | revoke NAME | ls
//	secretvault-server role set NAME ... | rm NAME | ls
//	secretvault-server deliver add-vault NAME (PATH | --sync NAME) | rm-vault NAME | ls
//	secretvault-server issuer set NAME --url URL --audience A [--jwks-file F] [--ca-file F] | rm NAME | ls
//	secretvault-server client-ca set FILE | clear | show
//	secretvault-server admin-token rotate [--out F]
//	secretvault-server audit [--limit N] [--after SEQ] [--json]
//
// They reach the server at --server (default $SECRETVAULT_SERVER, else
// https://localhost:8443), trusting its certificate by --fingerprint
// ($SECRETVAULT_SERVER_FINGERPRINT) or --ca, and prove they are the
// admin with the admin token in --admin-token-file
// ($SECRETVAULT_ADMIN_TOKEN_FILE). Unsealing and giving a share towards a
// rekey need no admin token: the share is the credential.

// app is everything a command talks to, so tests can drive run.
type app struct {
	stdin          io.Reader
	stdout, stderr io.Writer

	// ask asks for a secret on the terminal, without echo; nil when there
	// is no terminal (a share is then read from stdin).
	ask func(prompt string) ([]byte, error)

	getenv func(string) string

	// client, when set, replaces connecting (tests).
	client func(o svdeliver.ClientOptions) (*svdeliver.Client, error)
}

func newApp() *app {
	a := &app{stdin: os.Stdin, stdout: os.Stdout, stderr: os.Stderr, getenv: os.Getenv, client: svdeliver.NewClient}
	if term.IsTerminal(int(os.Stdin.Fd())) {
		a.ask = svterm.Secret
	}
	return a
}

var errUsage = errors.New("usage")

type subcommand struct {
	name, summary string
	run           func(a *app, args []string) error
}

var subcommands []subcommand

func init() {
	subcommands = []subcommand{
		{"init", "make a delivery server: its unseal key and shares, identity and admin token", (*app).cmdInit},
		{"status", "show whether the server is sealed", (*app).cmdStatus},
		{"unseal", "give one unseal share", (*app).cmdUnseal},
		{"seal", "seal the server again (admin)", (*app).cmdSeal},
		{"rekey", "make new unseal shares: start (admin), give a current share, or cancel", (*app).cmdRekey},
		{"token", "tokens for services: create, revoke, ls (admin)", (*app).cmdToken},
		{"role", "who may read what: set, rm, ls (admin)", (*app).cmdRole},
		{"deliver", "delivery vaults: add-vault, rm-vault, ls (admin)", (*app).cmdDeliver},
		{"issuer", "OIDC issuers whose ID tokens roles take: set, rm, ls (admin)", (*app).cmdIssuer},
		{"client-ca", "the CA client certificates chain to: set, clear, show (admin)", (*app).cmdClientCA},
		{"admin-token", "replace the admin token: rotate (admin)", (*app).cmdAdminToken},
		{"audit", "read the audit log (admin)", (*app).cmdAudit},
		{"version", "print the version", func(a *app, _ []string) error {
			fmt.Fprintln(a.stdout, "secretvault-server", secretvault.Version)
			return nil
		}},
	}
}

func (a *app) run(args []string) int {
	if len(args) == 0 || args[0] == "help" || args[0] == "-h" || args[0] == "--help" {
		a.usage()
		return 2
	}
	for _, c := range subcommands {
		if c.name != args[0] {
			continue
		}
		err := c.run(a, args[1:])
		switch {
		case err == nil:
			return 0
		case errors.Is(err, errUsage), errors.Is(err, flag.ErrHelp):
			return 2
		default:
			fmt.Fprintln(a.stderr, "secretvault-server:", err)
			return 1
		}
	}
	fmt.Fprintf(a.stderr, "secretvault-server: unknown command %q\n", args[0])
	a.usage()
	return 2
}

func (a *app) usage() {
	fmt.Fprintln(a.stderr, "usage: secretvault-server [flags]            serve (secretvault-server -h for the flags)")
	fmt.Fprintln(a.stderr, "       secretvault-server COMMAND [flags]    run the delivery side:")
	fmt.Fprintln(a.stderr)
	for _, c := range subcommands {
		fmt.Fprintf(a.stderr, "  %-12s %s\n", c.name, c.summary)
	}
}

func (a *app) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet("secretvault-server "+name, flag.ContinueOnError)
	fs.SetOutput(a.stderr)
	return fs
}

// parse parses flags that may come before, between or after positional
// arguments, and checks how many of those there are.
func parse(fs *flag.FlagSet, args []string, minArgs, maxArgs int, usage string) ([]string, error) {
	var pos []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, errUsage
		}
		args = fs.Args()
		if len(args) == 0 {
			break
		}
		pos = append(pos, args[0])
		args = args[1:]
	}
	if len(pos) < minArgs || (maxArgs >= 0 && len(pos) > maxArgs) {
		fmt.Fprintf(fs.Output(), "usage: %s %s\n", fs.Name(), usage)
		fs.PrintDefaults()
		return nil, errUsage
	}
	return pos, nil
}

type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

// conn are the flags that reach the server.
type conn struct {
	server, fingerprint, ca, tokenFile string
}

func (a *app) connFlags(fs *flag.FlagSet, admin bool) *conn {
	c := &conn{}
	server := a.getenv("SECRETVAULT_SERVER")
	if server == "" {
		server = "https://localhost:8443"
	}
	fs.StringVar(&c.server, "server", server, "the server's `URL`")
	fs.StringVar(&c.fingerprint, "fingerprint", a.getenv("SECRETVAULT_SERVER_FINGERPRINT"), "trust the server's certificate by its SHA-256 `FP` (a self-signed one)")
	fs.StringVar(&c.ca, "ca", "", "trust the server's certificate if it chains to the CA in `FILE`")
	if admin {
		fs.StringVar(&c.tokenFile, "admin-token-file", a.getenv("SECRETVAULT_ADMIN_TOKEN_FILE"), "the admin token, from `FILE`")
	}
	return c
}

func (a *app) connect(c *conn, admin bool) (*svdeliver.Client, error) {
	o := svdeliver.ClientOptions{URL: c.server, Fingerprint: c.fingerprint}
	if c.ca != "" {
		b, err := os.ReadFile(c.ca)
		if err != nil {
			return nil, err
		}
		o.CA = b
	}
	if admin {
		if c.tokenFile == "" {
			return nil, errors.New("this needs the admin token: pass --admin-token-file (or set SECRETVAULT_ADMIN_TOKEN_FILE)")
		}
		b, err := os.ReadFile(c.tokenFile)
		if err != nil {
			return nil, err
		}
		o.Token = strings.TrimSpace(string(b))
	}
	return a.client(o)
}

func ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 2*time.Minute)
}

// Initialising.

func (a *app) cmdInit(args []string) error {
	fs := a.flags("init")
	dir := fs.String("delivery-dir", "", "the delivery `DIR` to make (serve with -delivery-dir DIR)")
	shares := fs.Int("shares", 5, "how many unseal shares to make")
	threshold := fs.Int("threshold", 3, "how many shares unseal the server")
	credFile := fs.String("credential-file", "", "also make a key for unattended start, written to `FILE` (for systemd-creds)")
	tokenFile := fs.String("admin-token-file", "", "write the admin token to `FILE` (default: print it)")
	suiteName := fs.String("suite", "modern", "the cipher suite of the server's own seals: modern or nist")
	if _, err := parse(fs, args, 0, 0, "--delivery-dir DIR [--shares N --threshold K] [--credential-file F] [--admin-token-file F]"); err != nil {
		return err
	}
	if *dir == "" {
		fmt.Fprintln(a.stderr, "usage: secretvault-server init --delivery-dir DIR [flags]")
		return errUsage
	}
	suite, err := svcrypto.ParseSuite(*suiteName)
	if err != nil {
		return err
	}
	// Refuse before making anything if a file to write is there already.
	for _, f := range []string{*credFile, *tokenFile} {
		if f == "" {
			continue
		}
		if _, err := os.Stat(f); err == nil {
			return fmt.Errorf("%s exists already; it is not overwritten", f)
		}
	}
	abs, err := filepath.Abs(*dir)
	if err != nil {
		return err
	}
	res, err := svdeliver.Init(abs, svdeliver.InitOptions{Shares: *shares, Threshold: *threshold, Credential: *credFile != "", Suite: suite})
	if err != nil {
		return err
	}
	out := a.stdout
	fmt.Fprintf(out, "Made a delivery server in %s. It starts sealed.\n\n", abs)
	fmt.Fprintf(out, "The unseal key, as %d shares; any %d of them unseal the server, fewer reveal nothing.\n", len(res.Shares), res.Threshold)
	fmt.Fprintln(out, "Give each to a different operator. They are shown only now.")
	for i, s := range res.Shares {
		fmt.Fprintf(out, "\n  Share %d of %d:\n    %s\n", i+1, len(res.Shares), s)
	}
	fmt.Fprintln(out)
	if *tokenFile != "" {
		if err := writeNew(*tokenFile, []byte(res.AdminToken+"\n")); err != nil {
			return fmt.Errorf("the admin token could not be written (%v); it is: %s", err, res.AdminToken)
		}
		fmt.Fprintf(out, "The admin token is in %s. Commands take it with --admin-token-file.\n\n", *tokenFile)
	} else {
		fmt.Fprintf(out, "The admin token (shown only now; commands take it from a file, --admin-token-file):\n    %s\n\n", res.AdminToken)
	}
	if *credFile != "" {
		if err := writeNew(*credFile, []byte(res.Credential+"\n")); err != nil {
			return err
		}
		fmt.Fprintf(out, "The key for unattended start is in %s. Seal it to this machine, then delete it:\n", *credFile)
		fmt.Fprintf(out, "    systemd-creds encrypt --with-key=tpm2 --name=%s %s /etc/credstore.encrypted/%s\n", svdeliver.DefaultCredential, *credFile, svdeliver.DefaultCredential)
		fmt.Fprintf(out, "    shred -u %s\n", *credFile)
		fmt.Fprintf(out, "and give the service LoadCredentialEncrypted=%s.\n\n", svdeliver.DefaultCredential)
	}
	fmt.Fprintln(out, "The server's recipients: a vault's owner shares the vault with the one for its suite")
	fmt.Fprintln(out, "(secretvault share RECIPIENT), and 'secretvault-server deliver add-vault' says which.")
	for _, s := range slices.Sorted(maps.Keys(res.Recipients)) {
		fmt.Fprintf(out, "    %s  %s\n", s, res.Recipients[s])
	}
	fmt.Fprintf(out, "\nServe it with: secretvault-server -delivery-dir %s [your TLS flags]\n", abs)
	fmt.Fprintf(out, "Settings (session lifetime, unseal timeout, rate limit) are in %s.\n", filepath.Join(abs, svdeliver.ConfigFile))
	return nil
}

// writeNew creates a file that must not exist yet, mode 0600.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// The seal.

func (a *app) printStatus(st svdeliver.Status) {
	switch {
	case st.Sealed && st.Progress > 0:
		fmt.Fprintf(a.stdout, "Sealed: %d of %d shares given (forgotten at %s).\n", st.Progress, st.Threshold, st.ProgressExpires.Local().Format(time.Kitchen))
	case st.Sealed:
		fmt.Fprintf(a.stdout, "Sealed: %d of the %d shares unseal it.\n", st.Threshold, st.Shares)
	default:
		fmt.Fprintf(a.stdout, "Unsealed. %d of the %d shares unseal it.\n", st.Threshold, st.Shares)
	}
	if st.AutoUnseal {
		fmt.Fprintln(a.stdout, "It can unseal itself at start from its systemd credential.")
	}
	if r := st.Rekey; r != nil {
		fmt.Fprintf(a.stdout, "A rekey to %d of %d shares is in progress: %d of %d current shares given (nonce %s).\n", r.NewThreshold, r.NewShares, r.Progress, r.Threshold, r.Nonce)
	}
}

func (a *app) cmdStatus(args []string) error {
	fs := a.flags("status")
	c := a.connFlags(fs, false)
	asJSON := fs.Bool("json", false, "print JSON")
	if _, err := parse(fs, args, 0, 0, "[--server URL]"); err != nil {
		return err
	}
	cl, err := a.connect(c, false)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	st, err := cl.Status(cx)
	if err != nil {
		return err
	}
	if *asJSON {
		return a.printJSON(st)
	}
	a.printStatus(st)
	return nil
}

// readShare reads one share: from a file, from the terminal (without
// echo), or from a line of stdin.
func (a *app) readShare(file, prompt string) (string, error) {
	var b []byte
	var err error
	switch {
	case file != "":
		b, err = os.ReadFile(file)
	case a.ask != nil:
		b, err = a.ask(prompt)
	default:
		var line string
		line, err = bufio.NewReader(a.stdin).ReadString('\n')
		if errors.Is(err, io.EOF) && line != "" {
			err = nil
		}
		b = []byte(line)
	}
	if err != nil {
		return "", err
	}
	s := strings.TrimSpace(string(b))
	clear(b)
	if s == "" {
		return "", errors.New("no share was given")
	}
	return s, nil
}

func (a *app) cmdUnseal(args []string) error {
	fs := a.flags("unseal")
	c := a.connFlags(fs, false)
	file := fs.String("share-file", "", "read the share from `FILE` (default: the terminal, or stdin)")
	reset := fs.Bool("reset", false, "forget the shares given so far instead")
	if _, err := parse(fs, args, 0, 0, "[--share-file F | --reset] [--server URL]"); err != nil {
		return err
	}
	cl, err := a.connect(c, false)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	var st svdeliver.Status
	if *reset {
		st, err = cl.UnsealReset(cx)
	} else {
		st, err = cl.Status(cx)
		if err == nil && !st.Sealed {
			fmt.Fprintln(a.stdout, "The server is not sealed.")
			return nil
		}
		var share string
		if share, err = a.readShare(*file, "Unseal share: "); err != nil {
			return err
		}
		st, err = cl.Unseal(cx, share)
	}
	if err != nil {
		return err
	}
	a.printStatus(st)
	return nil
}

func (a *app) cmdSeal(args []string) error {
	fs := a.flags("seal")
	c := a.connFlags(fs, true)
	if _, err := parse(fs, args, 0, 0, "[--server URL] --admin-token-file F"); err != nil {
		return err
	}
	cl, err := a.connect(c, true)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	st, err := cl.Seal(cx)
	if err != nil {
		return err
	}
	a.printStatus(st)
	return nil
}

// cmdRekey starts a rekey (with --shares, as the admin), gives this
// operator's current share to the one in progress, or cancels it. The
// share that completes it gets the new shares, to hand out.
func (a *app) cmdRekey(args []string) error {
	fs := a.flags("rekey")
	c := a.connFlags(fs, true)
	shares := fs.Int("shares", 0, "start a rekey to this many new shares (admin)")
	threshold := fs.Int("threshold", 0, "how many of the new shares unseal the server")
	cred := fs.String("credential", "keep", "the key for unattended start: keep, new or remove")
	credFile := fs.String("credential-file", "", "when this share completes the rekey, write a new credential key to `FILE`")
	file := fs.String("share-file", "", "read this operator's current share from `FILE`")
	cancelIt := fs.Bool("cancel", false, "cancel the rekey in progress (admin)")
	if _, err := parse(fs, args, 0, 0, "[--shares N --threshold K [--credential keep|new|remove]] [--share-file F] [--cancel]"); err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	if *cancelIt || *shares > 0 {
		cl, err := a.connect(c, true)
		if err != nil {
			return err
		}
		if *cancelIt {
			if err := cl.RekeyCancel(cx); err != nil {
				return err
			}
			fmt.Fprintln(a.stdout, "The rekey was cancelled; the current shares still unseal the server.")
			return nil
		}
		rs, err := cl.RekeyStart(cx, svdeliver.RekeyRequest{Shares: *shares, Threshold: *threshold, Credential: *cred})
		if err != nil {
			return err
		}
		fmt.Fprintf(a.stdout, "A rekey to %d of %d shares has started. %d operators now give their current shares\n", rs.NewThreshold, rs.NewShares, rs.Threshold)
		fmt.Fprintln(a.stdout, "with 'secretvault-server rekey'; the last of them gets the new shares.")
		return nil
	}
	cl, err := a.connect(c, false)
	if err != nil {
		return err
	}
	st, err := cl.Status(cx)
	if err != nil {
		return err
	}
	if st.Rekey == nil {
		return errors.New("no rekey is in progress: the admin starts one with --shares N --threshold K")
	}
	if *credFile != "" {
		if _, err := os.Stat(*credFile); err == nil {
			return fmt.Errorf("%s exists already; it is not overwritten", *credFile)
		}
	}
	share, err := a.readShare(*file, "Current unseal share: ")
	if err != nil {
		return err
	}
	res, err := cl.RekeyShare(cx, st.Rekey.Nonce, share)
	if err != nil {
		return err
	}
	if !res.Done {
		fmt.Fprintf(a.stdout, "Share taken: %d of %d given.\n", res.Progress, res.Threshold)
		return nil
	}
	fmt.Fprintf(a.stdout, "The unseal key was replaced. The old shares no longer unseal the server.\n\n")
	fmt.Fprintf(a.stdout, "The new shares; any %d of them unseal it. Give each to a different operator. They are shown only now.\n", res.NewThreshold)
	for i, s := range res.Shares {
		fmt.Fprintf(a.stdout, "\n  Share %d of %d:\n    %s\n", i+1, len(res.Shares), s)
	}
	fmt.Fprintln(a.stdout)
	switch {
	case res.Credential != "" && *credFile != "":
		if err := writeNew(*credFile, []byte(res.Credential+"\n")); err != nil {
			return fmt.Errorf("the new credential key could not be written (%v); it is: %s", err, res.Credential)
		}
		fmt.Fprintf(a.stdout, "The new key for unattended start is in %s: seal it with systemd-creds, then delete it.\n", *credFile)
	case res.Credential != "":
		fmt.Fprintf(a.stdout, "The new key for unattended start (seal it with systemd-creds):\n    %s\n", res.Credential)
	case res.RekeyStatus.Credential == "remove":
		fmt.Fprintln(a.stdout, "The server can no longer unseal itself at start.")
	}
	return nil
}

// Tokens.

func (a *app) cmdToken(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "usage: secretvault-server token create|revoke|ls")
		return errUsage
	}
	fs := a.flags("token " + args[0])
	c := a.connFlags(fs, true)
	switch args[0] {
	case "create":
		ttl := fs.String("ttl", "", "how long it lasts, like 720h (default: until revoked)")
		var cidrs multi
		fs.Var(&cidrs, "cidr", "only from this `CIDR` (repeatable)")
		pos, err := parse(fs, args[1:], 1, 1, "NAME [--ttl D] [--cidr C]...")
		if err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
			t, err := cl.CreateToken(cx, svdeliver.TokenRequest{Name: pos[0], TTL: *ttl, CIDRs: cidrs})
			if err != nil {
				return err
			}
			fmt.Fprintln(a.stdout, t.Token)
			fmt.Fprintf(a.stderr, "Token %s made; it is shown only now. Give it a role: secretvault-server role set NAME --token %s --allow VAULT:ITEMS\n", t.Name, t.Name)
			return nil
		})
	case "revoke":
		pos, err := parse(fs, args[1:], 1, 1, "NAME")
		if err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error { return cl.RevokeToken(cx, pos[0]) })
	case "ls":
		asJSON := fs.Bool("json", false, "print JSON")
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
			list, err := cl.Tokens(cx)
			if err != nil || *asJSON {
				return a.printJSONErr(list, err)
			}
			tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tCREATED\tEXPIRES\tFROM")
			for _, t := range list {
				exp, from := "never", "anywhere"
				if !t.Expires.IsZero() {
					exp = t.Expires.Local().Format(time.DateTime)
				}
				if len(t.CIDRs) > 0 {
					from = strings.Join(t.CIDRs, ",")
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", t.Name, t.Created.Local().Format(time.DateTime), exp, from)
			}
			return tw.Flush()
		})
	}
	fmt.Fprintf(a.stderr, "unknown token command %q (create, revoke, ls)\n", args[0])
	return errUsage
}

// admin connects with the admin token and runs f.
func (a *app) admin(c *conn, f func(context.Context, *svdeliver.Client) error) error {
	cl, err := a.connect(c, true)
	if err != nil {
		return err
	}
	cx, cancel := ctx()
	defer cancel()
	return f(cx, cl)
}

func (a *app) printJSON(v any) error {
	e := json.NewEncoder(a.stdout)
	e.SetIndent("", "  ")
	return e.Encode(v)
}

func (a *app) printJSONErr(v any, err error) error {
	if err != nil {
		return err
	}
	return a.printJSON(v)
}

// Roles.

// parseAllow reads a rule as VAULT:ITEMS[:CAPS], CAPS being read, list or
// read,list (default read).
func parseAllow(s string) (svdeliver.Rule, error) {
	vault, rest, ok := strings.Cut(s, ":")
	if !ok || vault == "" || rest == "" {
		return svdeliver.Rule{}, fmt.Errorf("--allow %q is not VAULT:ITEMS[:read,list]", s)
	}
	caps := []string{svdeliver.CapRead}
	if i := strings.LastIndex(rest, ":"); i >= 0 {
		list := strings.Split(rest[i+1:], ",")
		if !slices.ContainsFunc(list, func(c string) bool { return c != svdeliver.CapRead && c != svdeliver.CapList }) {
			rest, caps = rest[:i], list
		}
	}
	return svdeliver.Rule{Vault: vault, Items: rest, Capabilities: caps}, nil
}

func (a *app) cmdRole(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "usage: secretvault-server role set|rm|ls")
		return errUsage
	}
	fs := a.flags("role " + args[0])
	c := a.connFlags(fs, true)
	switch args[0] {
	case "set":
		file := fs.String("file", "", "the role as JSON, from `FILE` (instead of the flags below)")
		token := fs.String("token", "", "for the token of this `NAME`")
		oidc := fs.String("oidc", "", "for ID tokens from this `ISSUER` (see 'issuer set')")
		var claims, allow multi
		fs.Var(&claims, "claim", "with --oidc: the claim must match, as `NAME=GLOB` (repeatable)")
		subject := fs.String("cert-subject", "", "for client certificates whose subject matches `GLOB` (CN=app,O=Acme)")
		san := fs.String("cert-san", "", "for client certificates with a SAN matching `GLOB`")
		fp := fs.String("cert-fingerprint", "", "for the client certificate with this SHA-256 `FP`")
		ttl := fs.String("ttl", "", "with --oidc: how long its sessions last, like 30m")
		fs.Var(&allow, "allow", "allow `VAULT:ITEMS[:read,list]` (repeatable; default capability read)")
		pos, err := parse(fs, args[1:], 1, 1, "NAME (--token T | --oidc ISSUER --claim K=GLOB... | --cert-...) --allow VAULT:ITEMS[:CAPS]...  or  NAME --file ROLE.json")
		if err != nil {
			return err
		}
		r := svdeliver.Role{Name: pos[0], Token: *token, TTL: *ttl}
		if *file != "" {
			b, err := os.ReadFile(*file)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(b, &r); err != nil {
				return fmt.Errorf("%s: %v", *file, err)
			}
			if r.Name == "" {
				r.Name = pos[0]
			}
		} else {
			if *oidc != "" {
				r.OIDC = &svdeliver.OIDCMatch{Issuer: *oidc, Claims: map[string]string{}}
				for _, kv := range claims {
					k, v, ok := strings.Cut(kv, "=")
					if !ok || k == "" {
						return fmt.Errorf("--claim %q is not NAME=GLOB", kv)
					}
					r.OIDC.Claims[k] = v
				}
			} else if len(claims) > 0 {
				return errors.New("--claim is for --oidc roles")
			}
			if *subject != "" || *san != "" || *fp != "" {
				r.Cert = &svdeliver.CertMatch{Subject: *subject, SAN: *san, Fingerprint: *fp}
			}
			for _, s := range allow {
				rule, err := parseAllow(s)
				if err != nil {
					return err
				}
				r.Rules = append(r.Rules, rule)
			}
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
			if _, err := cl.SetRole(cx, r); err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "Role %s set.\n", r.Name)
			return nil
		})
	case "rm":
		pos, err := parse(fs, args[1:], 1, 1, "NAME")
		if err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error { return cl.RemoveRole(cx, pos[0]) })
	case "ls":
		asJSON := fs.Bool("json", false, "print JSON")
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
			roles, err := cl.Roles(cx)
			if err != nil || *asJSON {
				return a.printJSONErr(roles, err)
			}
			for _, r := range roles {
				fmt.Fprintf(a.stdout, "%s  for %s\n", r.Name, describeIdentity(r))
				for _, rule := range r.Rules {
					fmt.Fprintf(a.stdout, "    %s %s:%s\n", strings.Join(rule.Capabilities, ","), rule.Vault, rule.Items)
				}
			}
			return nil
		})
	}
	fmt.Fprintf(a.stderr, "unknown role command %q (set, rm, ls)\n", args[0])
	return errUsage
}

func describeIdentity(r svdeliver.Role) string {
	switch {
	case r.Token != "":
		return "token " + r.Token
	case r.OIDC != nil:
		var cs []string
		for _, k := range slices.Sorted(maps.Keys(r.OIDC.Claims)) {
			cs = append(cs, k+"="+r.OIDC.Claims[k])
		}
		return "ID tokens from " + r.OIDC.Issuer + " with " + strings.Join(cs, " ")
	case r.Cert != nil:
		var parts []string
		if r.Cert.Subject != "" {
			parts = append(parts, "subject "+r.Cert.Subject)
		}
		if r.Cert.SAN != "" {
			parts = append(parts, "SAN "+r.Cert.SAN)
		}
		if r.Cert.Fingerprint != "" {
			parts = append(parts, "fingerprint "+r.Cert.Fingerprint)
		}
		return "client certificates with " + strings.Join(parts, ", ")
	}
	return "nobody"
}

// Vaults.

func (a *app) cmdDeliver(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "usage: secretvault-server deliver add-vault|rm-vault|ls")
		return errUsage
	}
	fs := a.flags("deliver " + args[0])
	c := a.connFlags(fs, true)
	switch args[0] {
	case "add-vault":
		sync := fs.String("sync", "", "the vault synced to this server under this `NAME`, instead of a PATH")
		pos, err := parse(fs, args[1:], 1, 2, "NAME (PATH | --sync NAME)")
		if err != nil {
			return err
		}
		req := svdeliver.VaultRequest{Name: pos[0], Sync: *sync}
		if len(pos) == 2 {
			req.Path = pos[1]
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
			info, err := cl.AddVault(cx, req)
			if err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "Delivery vault %s is %s (vault %s).\n", info.Name, info.Path, info.ID)
			if info.Open {
				fmt.Fprintln(a.stdout, "It is shared with the server already, and open.")
				return nil
			}
			fmt.Fprintf(a.stdout, "It is not open yet: %s\n\n", info.Problem)
			if info.Recipient != "" {
				fmt.Fprintln(a.stdout, "On a device that opens it, share it with the server:")
				fmt.Fprintf(a.stdout, "    secretvault share %s --label delivery-server\n", info.Recipient)
			}
			return nil
		})
	case "rm-vault":
		pos, err := parse(fs, args[1:], 1, 1, "NAME")
		if err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error { return cl.RemoveVault(cx, pos[0]) })
	case "ls":
		asJSON := fs.Bool("json", false, "print JSON")
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
			list, err := cl.Vaults(cx)
			if err != nil || *asJSON {
				return a.printJSONErr(list, err)
			}
			tw := tabwriter.NewWriter(a.stdout, 0, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "NAME\tSTATE\tPATH")
			for _, v := range list {
				state := "open"
				if !v.Open {
					state = "not open: " + v.Problem
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\n", v.Name, state, v.Path)
			}
			return tw.Flush()
		})
	}
	fmt.Fprintf(a.stderr, "unknown deliver command %q (add-vault, rm-vault, ls)\n", args[0])
	return errUsage
}

// Issuers, the client CA, the admin token and the audit log.

func (a *app) cmdIssuer(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "usage: secretvault-server issuer set|rm|ls")
		return errUsage
	}
	fs := a.flags("issuer " + args[0])
	c := a.connFlags(fs, true)
	switch args[0] {
	case "set":
		u := fs.String("url", "", "the issuer as its tokens' iss has it, like https://token.actions.githubusercontent.com")
		var auds multi
		fs.Var(&auds, "audience", "this server's `NAME` in the issuer's tokens (their aud; repeatable)")
		jwks := fs.String("jwks-file", "", "the issuer's keys, from `FILE`, instead of discovery (kubectl get --raw /openid/v1/jwks)")
		caFile := fs.String("ca-file", "", "the CA the issuer's HTTPS certificate chains to, from `FILE`")
		pos, err := parse(fs, args[1:], 1, 1, "NAME --url URL --audience AUD [--jwks-file F] [--ca-file F]")
		if err != nil {
			return err
		}
		iss := svdeliver.Issuer{Name: pos[0], URL: *u, Audiences: auds}
		if *jwks != "" {
			b, err := os.ReadFile(*jwks)
			if err != nil {
				return err
			}
			iss.JWKS = json.RawMessage(b)
		}
		if *caFile != "" {
			b, err := os.ReadFile(*caFile)
			if err != nil {
				return err
			}
			iss.CA = string(b)
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
			if _, err := cl.SetIssuer(cx, iss); err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "Issuer %s set.\n", iss.Name)
			return nil
		})
	case "rm":
		pos, err := parse(fs, args[1:], 1, 1, "NAME")
		if err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error { return cl.RemoveIssuer(cx, pos[0]) })
	case "ls":
		asJSON := fs.Bool("json", false, "print JSON")
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
			list, err := cl.Issuers(cx)
			if err != nil || *asJSON {
				return a.printJSONErr(list, err)
			}
			for _, iss := range list {
				keys := "discovery"
				if len(iss.JWKS) > 0 {
					keys = "a configured key set"
				}
				fmt.Fprintf(a.stdout, "%s  %s  audience %s  (keys: %s)\n", iss.Name, iss.URL, strings.Join(iss.Audiences, ","), keys)
			}
			return nil
		})
	}
	fmt.Fprintf(a.stderr, "unknown issuer command %q (set, rm, ls)\n", args[0])
	return errUsage
}

func (a *app) cmdClientCA(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(a.stderr, "usage: secretvault-server client-ca set FILE | clear | show")
		return errUsage
	}
	fs := a.flags("client-ca " + args[0])
	c := a.connFlags(fs, true)
	switch args[0] {
	case "set":
		pos, err := parse(fs, args[1:], 1, 1, "FILE")
		if err != nil {
			return err
		}
		b, err := os.ReadFile(pos[0])
		if err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
			ca, err := cl.SetClientCA(cx, string(b))
			if err != nil {
				return err
			}
			fmt.Fprintf(a.stdout, "Client certificates chaining to %s are now believed.\n", strings.Join(ca.Subjects, "; "))
			return nil
		})
	case "clear":
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error { return cl.ClearClientCA(cx) })
	case "show":
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
			ca, err := cl.ClientCA(cx)
			if err != nil {
				return err
			}
			if ca.PEM == "" {
				fmt.Fprintln(a.stdout, "There is no client CA: only pinned certificates are recognised.")
				return nil
			}
			fmt.Fprint(a.stdout, ca.PEM)
			return nil
		})
	}
	fmt.Fprintf(a.stderr, "unknown client-ca command %q (set, clear, show)\n", args[0])
	return errUsage
}

func (a *app) cmdAdminToken(args []string) error {
	if len(args) == 0 || args[0] != "rotate" {
		fmt.Fprintln(a.stderr, "usage: secretvault-server admin-token rotate [--out FILE]")
		return errUsage
	}
	fs := a.flags("admin-token rotate")
	c := a.connFlags(fs, true)
	out := fs.String("out", "", "write the new token to `FILE` (default: print it)")
	if _, err := parse(fs, args[1:], 0, 0, "[--out FILE]"); err != nil {
		return err
	}
	if *out != "" {
		if _, err := os.Stat(*out); err == nil {
			return fmt.Errorf("%s exists already; it is not overwritten", *out)
		}
	}
	return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
		t, err := cl.RotateAdminToken(cx)
		if err != nil {
			return err
		}
		if *out == "" {
			fmt.Fprintln(a.stdout, t.Token)
			return nil
		}
		if err := writeNew(*out, []byte(t.Token+"\n")); err != nil {
			return fmt.Errorf("the new admin token could not be written (%v); it is: %s", err, t.Token)
		}
		fmt.Fprintf(a.stdout, "The new admin token is in %s; the old one no longer works.\n", *out)
		return nil
	})
}

func (a *app) cmdAudit(args []string) error {
	fs := a.flags("audit")
	c := a.connFlags(fs, true)
	limit := fs.Int("limit", 50, "show the newest `N` entries (or N after --after)")
	after := fs.Uint64("after", 0, "show entries after this sequence number")
	asJSON := fs.Bool("json", false, "print JSON lines, one per entry")
	if _, err := parse(fs, args, 0, 0, "[--limit N] [--after SEQ] [--json]"); err != nil {
		return err
	}
	return a.admin(c, func(cx context.Context, cl *svdeliver.Client) error {
		log, err := cl.Audit(cx, *after, *limit)
		if err != nil {
			return err
		}
		for _, e := range log.Entries {
			if *asJSON {
				b, _ := json.Marshal(e)
				fmt.Fprintln(a.stdout, string(b))
				continue
			}
			what := e.Op
			if e.Vault != "" {
				what += " " + e.Vault + "/" + e.Item
				if e.Field != "" {
					what += "#" + e.Field
				}
			}
			if e.Target != "" {
				what += " " + e.Target
			}
			who := e.Identity
			if who == "" {
				who = "(unknown)"
			}
			if e.Role != "" {
				who += " (" + e.Role + ")"
			}
			line := fmt.Sprintf("%6d %s %-15s %-8s %s %s", e.Seq, e.Time.Local().Format(time.DateTime), e.IP, e.Outcome, what, who)
			if e.Reason != "" && e.Outcome != svdeliver.OutcomeAllowed {
				line += ": " + e.Reason
			}
			fmt.Fprintln(a.stdout, line)
		}
		if !log.Intact {
			return errors.New(log.Problem)
		}
		return nil
	})
}
