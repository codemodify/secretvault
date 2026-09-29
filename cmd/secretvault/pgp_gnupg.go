package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svgpgagent"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

// `secretvault pgp gpg-setup`: a GnuPG home whose gpg signs and decrypts
// with the OpenPGP keys in a vault, through secretvaultd's gpg-agent
// face, the keys never leaving the daemon.
//
// gpg keeps public keys and asks its agent for everything secret, the
// agent it finds at S.gpg-agent in its socket directory (gpgconf
// --list-dirs agent-socket). gpg-setup, in the home given (by default
// DATA/gnupg, made if need be):
//
//   - has the daemon link that socket to its own, and S.gpg-agent.ssh to
//     its SSH agent; the daemon links them again each time it starts;
//   - imports the vault's public keys into gpg's keyring (version 4 keys:
//     GnuPG 2.4 reads no version 6), trusted as gpg trusts the keys it
//     makes itself, since they are yours;
//   - names this program as gpg's agent-program in gpg.conf, so that a gpg
//     that finds no agent (the daemon not running yet) starts secretvault,
//     which starts the daemon and links the socket again, rather than
//     GnuPG's own gpg-agent.
//
// No secret key is written into the home: gpg asks the agent whether it
// has each key (HAVEKEY, KEYINFO), and needs no stub for it. A home is
// only ever the one given or the default one: ~/.gnupg is touched only
// when named, and --dry-run says first what would change. --remove undoes
// the links and the gpg.conf line, and leaves the public keys.

// gpgAgentProgramFlag is what gpg passes secretvault as its agent-program:
// gpg runs PROGRAM --homedir HOME --use-standard-socket FLAG --daemon.
const gpgAgentProgramFlag = "--secretvault-gpg-agent"

// agentProgramComment marks the gpg.conf line gpg-setup writes.
const agentProgramComment = "# secretvault pgp gpg-setup: when gpg finds no agent, it starts secretvault, which starts secretvaultd."

func (c *cli) pgpGnuPGSetup(args []string) error {
	fs := c.flags("pgp gpg-setup")
	homeFlag := fs.String("gnupghome", "", "the GnuPG home to point at secretvault (default: secretvault's data directory/gnupg)")
	dryRun := fs.Bool("dry-run", false, "say what would change, and change nothing")
	remove := fs.Bool("remove", false, "stop pointing the home at secretvault (its public keys stay)")
	gpgFlag := fs.String("gpg", "", "the gpg program (default: gpg on PATH)")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "[--gnupghome DIR] [--dry-run] [--remove] [--gpg PATH]"); err != nil {
		return err
	}
	if runtime.GOOS == "windows" {
		return errors.New("gpg on Windows reaches its agent through a TCP socket emulation, which secretvaultd does not serve yet")
	}
	home := *homeFlag
	if home == "" {
		data, err := svcore.Home()
		if err != nil {
			return err
		}
		home = filepath.Join(data, "gnupg")
	}
	home, err := filepath.Abs(home)
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if *remove {
		return c.gnupgRemove(ctx, home, *dryRun)
	}
	gpg, gpgconf, err := gnupgPrograms(*gpgFlag)
	if err != nil {
		return err
	}

	keys, skipped, err := c.gnupgKeys(ctx)
	if err != nil {
		return err
	}
	st, err := cl.Status(ctx)
	if err != nil {
		return err
	}
	if st.GPGAgent == "" {
		return errors.New("secretvaultd serves no gpg-agent socket (is no_gpg_agent set in its config.json?)")
	}
	sock, err := gnupgDir(gpgconf, home, "agent-socket")
	if err != nil {
		return err
	}
	sshSock, _ := gnupgDir(gpgconf, home, "agent-ssh-socket")
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if resolved, err := filepath.EvalSymlinks(exe); err == nil {
		exe = resolved
	}
	agentProgram := "agent-program " + exe + "|" + gpgAgentProgramFlag
	_, homeErr := os.Stat(home)
	unreachable := unreachableKeys(home, keys)

	if *dryRun {
		fmt.Fprintf(c.stdout, "Pointing the GnuPG home %s at secretvault would:\n", home)
		if homeErr != nil {
			fmt.Fprintf(c.stdout, "- make the directory %s (0700)\n", home)
		}
		fmt.Fprintf(c.stdout, "- link %s (where gpg looks for its agent) to %s\n", sock, st.GPGAgent)
		if sshSock != "" && st.SSHAgent != "" {
			fmt.Fprintf(c.stdout, "- link %s (its SSH agent) to %s\n", sshSock, st.SSHAgent)
		}
		for _, k := range keys {
			fmt.Fprintf(c.stdout, "- import the public key %s  %s (%s), trusted as your own\n", groupFP(k.Fingerprint), firstUID(k), k.Item)
		}
		fmt.Fprintf(c.stdout, "- add to %s: %s\n", filepath.Join(home, "gpg.conf"), agentProgram)
		c.gnupgNotes(skipped, unreachable, home)
		fmt.Fprintln(c.stdout, "Nothing was changed.")
		return nil
	}

	if homeErr != nil {
		if err := os.MkdirAll(home, 0o700); err != nil {
			return err
		}
	}
	res, err := cl.LinkGnuPG(ctx, svrpc.GnuPGLinkParams{Home: home, Socket: sock, SSHSocket: sshSock})
	if err != nil {
		return err
	}
	var pubs, trust bytes.Buffer
	for _, k := range keys {
		pubs.WriteString(k.PublicKey)
		fmt.Fprintf(&trust, "%s:6:\n", k.Fingerprint)
	}
	if len(keys) > 0 {
		if out, err := runGnuPG(gpg, home, pubs.Bytes(), "--import"); err != nil {
			return fmt.Errorf("gpg --import: %v\n%s", err, out)
		}
		if out, err := runGnuPG(gpg, home, trust.Bytes(), "--import-ownertrust"); err != nil {
			return fmt.Errorf("gpg --import-ownertrust: %v\n%s", err, out)
		}
	}
	if note, err := addAgentProgram(filepath.Join(home, "gpg.conf"), agentProgram); err != nil {
		return err
	} else if note != "" {
		fmt.Fprintln(c.stderr, "warning:", note)
	}

	fmt.Fprintf(c.stdout, "The GnuPG home %s signs and decrypts with secretvault's keys:\n", home)
	for _, k := range keys {
		fmt.Fprintf(c.stdout, "  %s  %s\n", groupFP(k.Fingerprint), firstUID(k))
	}
	fmt.Fprintf(c.stdout, "Its agent is secretvaultd: %s -> %s\n", sock, res.Agent)
	if res.SSHAgent != "" {
		fmt.Fprintf(c.stdout, "and so is its SSH agent: %s -> %s\n", sshSock, res.SSHAgent)
	}
	c.gnupgNotes(skipped, unreachable, home)
	fmt.Fprintf(c.stdout, "Use it with: export GNUPGHOME=%s\n", home)
	fmt.Fprintln(c.stdout, "Each program's first signature or decryption with a key is asked about.")
	return nil
}

// gnupgNotes says what gpg will not get.
func (c *cli) gnupgNotes(skipped []string, unreachable int, home string) {
	for _, s := range skipped {
		fmt.Fprintf(c.stdout, "Left out: %s\n", s)
	}
	if unreachable > 0 {
		fmt.Fprintf(c.stdout, "Note: %d secret keys in %s are GnuPG's own, which gpg cannot use while secretvault is its agent;\n"+
			"take them into the vault first ('gpg --export-secret-keys KEY | secretvault pgp import -').\n",
			unreachable, filepath.Join(home, "private-keys-v1.d"))
	}
}

// gnupgKeys are the public keys of the vault's OpenPGP keys that gpg can
// use, and what was left out and why.
func (c *cli) gnupgKeys(ctx context.Context) ([]svrpc.PGPKey, []string, error) {
	cl, err := c.daemon()
	if err != nil {
		return nil, nil, err
	}
	entries, err := cl.List(ctx, c.vault, "")
	if err != nil {
		return nil, nil, err
	}
	var keys []svrpc.PGPKey
	var skipped []string
	for _, e := range entries {
		if e.Item.Kind != svrpc.PGPItemKind || e.Item.Attrs[svrpc.PGPFingerprint] == "" {
			continue
		}
		k, err := cl.PGPPublicKey(ctx, c.vault, e.Item.Name)
		if err != nil {
			return nil, nil, err
		}
		if k.Version != 4 {
			skipped = append(skipped, fmt.Sprintf("%s, a version %d key, which GnuPG 2.4 does not read", k.Item, k.Version))
			continue
		}
		keys = append(keys, k)
	}
	if len(keys) == 0 {
		return nil, skipped, errors.New("the vault holds no OpenPGP key gpg can use: make one with 'secretvault pgp new --v4', or 'secretvault pgp import' one")
	}
	return keys, skipped, nil
}

// unreachableKeys counts the secret keys GnuPG's own agent holds in a
// home that are not among keys.
func unreachableKeys(home string, keys []svrpc.PGPKey) int {
	files, _ := filepath.Glob(filepath.Join(home, "private-keys-v1.d", "*.key"))
	if len(files) == 0 {
		return 0
	}
	var ours []string
	for _, k := range keys {
		pub, err := svpgp.ReadKey(strings.NewReader(k.PublicKey))
		if err != nil {
			continue
		}
		for _, p := range pub.Parts() {
			if grip, err := svgpgagent.Keygrip(p.Algorithm, p.Public); err == nil {
				ours = append(ours, strings.ToUpper(hex.EncodeToString(grip)))
			}
		}
	}
	n := 0
	for _, f := range files {
		if !slices.Contains(ours, strings.ToUpper(strings.TrimSuffix(filepath.Base(f), ".key"))) {
			n++
		}
	}
	return n
}

func (c *cli) gnupgRemove(ctx context.Context, home string, dryRun bool) error {
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	conf := filepath.Join(home, "gpg.conf")
	if dryRun {
		st, err := cl.Status(ctx)
		if err != nil {
			return err
		}
		if !slices.Contains(st.GnuPGHomes, home) {
			fmt.Fprintf(c.stdout, "%s is not pointed at secretvault.\n", home)
			return nil
		}
		fmt.Fprintf(c.stdout, "Removing would take away the links to secretvaultd in %s's socket directory, and secretvault's agent-program line from %s; the public keys stay.\nNothing was changed.\n", home, conf)
		return nil
	}
	if _, err := cl.LinkGnuPG(ctx, svrpc.GnuPGLinkParams{Home: home, Remove: true}); err != nil {
		return err
	}
	if err := removeAgentProgram(conf); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "The GnuPG home %s is no longer pointed at secretvault; the public keys stay in its keyring.\n", home)
	return nil
}

// gpgAgentStart is secretvault run by gpg as its agent-program, when it
// finds no agent: it has the daemon (which it starts if need be) link the
// home's agent socket again, and exits, as gpg expects of an agent that
// daemonizes. gpg then connects.
func (c *cli) gpgAgentStart(args []string) int {
	var home string
	for i, a := range args {
		if a == "--homedir" && i+1 < len(args) {
			home = args[i+1]
		} else if h, ok := strings.CutPrefix(a, "--homedir="); ok {
			home = h
		}
	}
	if home == "" {
		fmt.Fprintln(c.stderr, "secretvault: started as gpg's agent without --homedir")
		return 2
	}
	_, gpgconf, err := gnupgPrograms("")
	if err != nil {
		fmt.Fprintln(c.stderr, "secretvault:", err)
		return 1
	}
	sock, err := gnupgDir(gpgconf, home, "agent-socket")
	if err != nil {
		fmt.Fprintln(c.stderr, "secretvault:", err)
		return 1
	}
	sshSock, _ := gnupgDir(gpgconf, home, "agent-ssh-socket")
	cl, err := c.daemon()
	if err != nil {
		fmt.Fprintln(c.stderr, "secretvault:", describe(err))
		return 1
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if _, err := cl.LinkGnuPG(ctx, svrpc.GnuPGLinkParams{Home: home, Socket: sock, SSHSocket: sshSock, Relink: true}); err != nil {
		fmt.Fprintln(c.stderr, "secretvault:", describe(err))
		return 1
	}
	return 0
}

// gnupgPrograms finds gpg (named, or on PATH) and the gpgconf beside it.
func gnupgPrograms(gpg string) (string, string, error) {
	if gpg == "" {
		p, err := exec.LookPath("gpg")
		if err != nil {
			return "", "", errors.New("GnuPG's gpg is not on PATH (name it with --gpg)")
		}
		gpg = p
	}
	gpgconf := filepath.Join(filepath.Dir(gpg), "gpgconf")
	if _, err := os.Stat(gpgconf); err != nil {
		p, err := exec.LookPath("gpgconf")
		if err != nil {
			return "", "", errors.New("GnuPG's gpgconf is neither beside gpg nor on PATH")
		}
		gpgconf = p
	}
	return gpg, gpgconf, nil
}

// gnupgEnv is this environment with GNUPGHOME set to home.
func gnupgEnv(home string) []string {
	env := slices.DeleteFunc(os.Environ(), func(e string) bool { return strings.HasPrefix(e, "GNUPGHOME=") })
	return append(env, "GNUPGHOME="+home)
}

// gnupgDir is a directory or socket gpgconf --list-dirs names for home.
func gnupgDir(gpgconf, home, name string) (string, error) {
	cmd := exec.Command(gpgconf, "--homedir", home, "--list-dirs", name)
	cmd.Env = gnupgEnv(home)
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("gpgconf --list-dirs %s: %v", name, err)
	}
	p := strings.TrimSpace(string(out))
	if !filepath.IsAbs(p) {
		return "", fmt.Errorf("gpgconf --list-dirs %s gave %q", name, p)
	}
	return p, nil
}

// runGnuPG runs gpg in batch mode on home.
func runGnuPG(gpg, home string, stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(gpg, append([]string{"--homedir", home, "--batch", "--no-tty"}, args...)...)
	cmd.Env = gnupgEnv(home)
	cmd.Stdin = bytes.NewReader(stdin)
	return cmd.CombinedOutput()
}

// addAgentProgram puts line into gpg.conf, marked as secretvault's,
// unless it is there already. Another agent-program is left as it is, and
// said so.
func addAgentProgram(conf, line string) (string, error) {
	b, err := os.ReadFile(conf)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	lines := strings.Split(strings.TrimRight(string(b), "\n"), "\n")
	for i, l := range lines {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "agent-program") {
			continue
		}
		if l == line {
			return "", nil
		}
		if i > 0 && lines[i-1] == agentProgramComment {
			// An older line of ours (secretvault moved): replace it.
			lines[i] = line
			return "", writeConf(conf, strings.Join(lines, "\n")+"\n")
		}
		return fmt.Sprintf("%s names its own agent-program (%s): left as it is, so a gpg that finds no agent starts that one", conf, l), nil
	}
	text := string(b)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return "", writeConf(conf, text+agentProgramComment+"\n"+line+"\n")
}

// removeAgentProgram takes secretvault's agent-program line (and its
// comment) out of gpg.conf.
func removeAgentProgram(conf string) error {
	b, err := os.ReadFile(conf)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	lines := strings.Split(string(b), "\n")
	var out []string
	for i := 0; i < len(lines); i++ {
		if lines[i] == agentProgramComment && i+1 < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i+1]), "agent-program") {
			i++
			continue
		}
		out = append(out, lines[i])
	}
	if len(out) == len(lines) {
		return nil
	}
	return writeConf(conf, strings.Join(out, "\n"))
}

// writeConf replaces a file, keeping its mode (0600 for a new one).
func writeConf(path, text string) error {
	mode := os.FileMode(0o600)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.WriteString(text)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

func firstUID(k svrpc.PGPKey) string {
	if len(k.UserIDs) > 0 {
		return k.UserIDs[0]
	}
	return ""
}
