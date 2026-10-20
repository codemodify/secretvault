package svops

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

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svgpgagent"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

// A GnuPG home whose gpg signs and decrypts with the OpenPGP keys in a
// vault, through secretvaultd's gpg-agent face, the keys never leaving
// the daemon ('secretvault pgp gpg-setup').
//
// gpg keeps public keys and asks its agent for everything secret, the
// agent it finds at S.gpg-agent in its socket directory (gpgconf
// --list-dirs agent-socket). Setting a home up (PlanGnuPGSetup, then
// ApplyGnuPGSetup), in the home given (by default DATA/gnupg, made if need
// be):
//
//   - has the daemon link that socket to its own, and S.gpg-agent.ssh to
//     its SSH agent; the daemon links them again each time it starts;
//   - imports the vault's public keys into gpg's keyring (version 4 keys:
//     GnuPG 2.4 reads no version 6), trusted as gpg trusts the keys it
//     makes itself, since they are yours;
//   - names the secretvault CLI as gpg's agent-program in gpg.conf, so
//     that a gpg that finds no agent (the daemon not running yet) starts
//     secretvault, which starts the daemon and links the socket again
//     (RelinkGnuPG), rather than GnuPG's own gpg-agent.
//
// No secret key is written into the home: gpg asks the agent whether it
// has each key (HAVEKEY, KEYINFO), and needs no stub for it. A home is
// only ever the one given or the default one: ~/.gnupg is touched only
// when named, and a dry run says first what would change. RemoveGnuPG
// undoes the links and the gpg.conf line, and leaves the public keys.

// GPGAgentProgramFlag is what gpg passes secretvault as its
// agent-program: gpg runs PROGRAM --homedir HOME --use-standard-socket
// FLAG --daemon.
const GPGAgentProgramFlag = "--secretvault-gpg-agent"

// agentProgramComment marks the gpg.conf line the setup writes.
const agentProgramComment = "# secretvault pgp gpg-setup: when gpg finds no agent, it starts secretvault, which starts secretvaultd."

// GnuPGHere says, with an error, why gpg cannot be pointed at the daemon
// here.
func GnuPGHere() error {
	if runtime.GOOS == "windows" {
		return errors.New("gpg on Windows reaches its agent through a TCP socket emulation, which secretvaultd does not serve yet")
	}
	return nil
}

// GnuPGHome is the home to set up, absolute: home, or secretvault's own
// (DATA/gnupg) when it is "".
func GnuPGHome(home string) (string, error) {
	if home == "" {
		data, err := svcore.DataDir()
		if err != nil {
			return "", err
		}
		home = filepath.Join(data, "gnupg")
	}
	return filepath.Abs(home)
}

// GnuPGOptions say which home to set up, with what.
type GnuPGOptions struct {
	Vault  string // whose OpenPGP keys
	Home   string // the GnuPG home, from GnuPGHome
	GPG    string // the gpg program ("" for gpg on PATH)
	CLI    string // the secretvault CLI, named as gpg's agent-program: the CLI's own path (os.Executable), or the managers' CLIProgram()
	DryRun bool   // only to show it: leave nothing behind (gpgconf makes the socket directory it names)
}

// GnuPGPlan is what setting a home up does.
type GnuPGPlan struct {
	Home         string
	HomeExists   bool   // else it is made, 0700
	Socket       string // where gpg looks for its agent, to link to Agent
	SSHSocket    string // its SSH agent's socket, to link to SSHAgent ("" when gpgconf names none)
	Agent        string // the daemon's gpg-agent socket
	SSHAgent     string // the daemon's SSH agent socket ("" when it serves none)
	Keys         []svrpc.PGPKey
	Skipped      []string // keys left out, and why
	AgentProgram string   // the gpg.conf line
	Unreachable  int      // secret keys of GnuPG's own in the home, which gpg cannot use then
	OwnHome      bool     // the home is the person's own GnuPG home ($GNUPGHOME, ~/.gnupg)
	gpg          string
}

// PlanGnuPGSetup works out what setting a GnuPG home up would do. It
// changes nothing, but for the socket directory gpgconf makes, which a
// dry run removes again.
func PlanGnuPGSetup(ctx context.Context, cl *secretvault.Client, o GnuPGOptions) (*GnuPGPlan, error) {
	gpg, gpgconf, err := GnuPGPrograms(o.GPG)
	if err != nil {
		return nil, err
	}
	keys, skipped, err := GnuPGKeys(ctx, cl, o.Vault)
	if err != nil {
		return nil, err
	}
	st, err := cl.Status(ctx)
	if err != nil {
		return nil, err
	}
	if st.GPGAgent == "" {
		return nil, errors.New("secretvaultd serves no gpg-agent socket (is no_gpg_agent set in its config.json?)")
	}
	sock, err := GnuPGDir(gpgconf, o.Home, "agent-socket")
	if err != nil {
		return nil, err
	}
	sshSock, _ := GnuPGDir(gpgconf, o.Home, "agent-ssh-socket")
	exe, err := StableExecutable(o.CLI)
	if err != nil {
		return nil, err
	}
	_, homeErr := os.Stat(o.Home)
	p := &GnuPGPlan{
		Home: o.Home, HomeExists: homeErr == nil, Socket: sock, SSHSocket: sshSock,
		Agent: st.GPGAgent, SSHAgent: st.SSHAgent, Keys: keys, Skipped: skipped,
		AgentProgram: "agent-program " + exe + "|" + GPGAgentProgramFlag,
		Unreachable:  unreachableKeys(o.Home, keys),
		OwnHome:      sameDir(o.Home, defaultGnuPGHome()),
		gpg:          gpg,
	}
	if o.DryRun {
		ForgetSocketDir(sock)
	}
	return p, nil
}

// Discard drops a plan that will not be carried out: the socket directory
// gpgconf made for it goes, if it is empty.
func (p *GnuPGPlan) Discard() { ForgetSocketDir(p.Socket) }

// ApplyGnuPGSetup carries a plan out. note, when not "", says what was
// left as it was (another agent-program in gpg.conf).
func ApplyGnuPGSetup(ctx context.Context, cl *secretvault.Client, p *GnuPGPlan) (res svrpc.GnuPGLinkResult, note string, err error) {
	if !p.HomeExists {
		if err := os.MkdirAll(p.Home, 0o700); err != nil {
			return res, "", err
		}
	}
	res, err = cl.LinkGnuPG(ctx, svrpc.GnuPGLinkParams{Home: p.Home, Socket: p.Socket, SSHSocket: p.SSHSocket})
	if err != nil {
		return res, "", err
	}
	var pubs, trust bytes.Buffer
	for _, k := range p.Keys {
		pubs.WriteString(k.PublicKey)
		fmt.Fprintf(&trust, "%s:6:\n", k.Fingerprint)
	}
	if len(p.Keys) > 0 {
		if out, err := runGnuPG(p.gpg, p.Home, pubs.Bytes(), "--import"); err != nil {
			return res, "", fmt.Errorf("gpg --import: %v\n%s", err, out)
		}
		if out, err := runGnuPG(p.gpg, p.Home, trust.Bytes(), "--import-ownertrust"); err != nil {
			return res, "", fmt.Errorf("gpg --import-ownertrust: %v\n%s", err, out)
		}
	}
	note, err = addAgentProgram(filepath.Join(p.Home, "gpg.conf"), p.AgentProgram)
	return res, note, err
}

// GnuPGPointed reports whether the daemon has a home pointed at it.
func GnuPGPointed(ctx context.Context, cl *secretvault.Client, home string) (bool, error) {
	st, err := cl.Status(ctx)
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(st.GnuPGHomes, func(h string) bool { return sameDir(h, home) }), nil
}

// RemoveGnuPG stops pointing a home at the daemon: the links go, and
// secretvault's agent-program line in gpg.conf; the public keys stay.
func RemoveGnuPG(ctx context.Context, cl *secretvault.Client, home string) error {
	if _, err := cl.LinkGnuPG(ctx, svrpc.GnuPGLinkParams{Home: home, Remove: true}); err != nil {
		return err
	}
	return removeAgentProgram(filepath.Join(home, "gpg.conf"))
}

// RelinkGnuPG is secretvault started by gpg as its agent-program, when it
// finds no agent: the daemon (which connecting starts if need be) links
// the home's agent socket again. gpg then connects.
func RelinkGnuPG(ctx context.Context, connect func() (*secretvault.Client, error), home string) error {
	_, gpgconf, err := GnuPGPrograms("")
	if err != nil {
		return err
	}
	sock, err := GnuPGDir(gpgconf, home, "agent-socket")
	if err != nil {
		return err
	}
	sshSock, _ := GnuPGDir(gpgconf, home, "agent-ssh-socket")
	cl, err := connect()
	if err != nil {
		return err
	}
	_, err = cl.LinkGnuPG(ctx, svrpc.GnuPGLinkParams{Home: home, Socket: sock, SSHSocket: sshSock, Relink: true})
	return err
}

// ErrNoGnuPGKey is a vault with no OpenPGP key gpg can use. Its text is
// the CLI's; a manager says it in its own words.
var ErrNoGnuPGKey = errors.New("the vault holds no OpenPGP key gpg can use: make one with 'secretvault pgp new --v4', or 'secretvault pgp import' one")

// GnuPGKeys are the public keys of the vault's OpenPGP keys that gpg can
// use, and what was left out and why.
func GnuPGKeys(ctx context.Context, cl *secretvault.Client, vault string) ([]svrpc.PGPKey, []string, error) {
	entries, err := cl.List(ctx, vault, "")
	if err != nil {
		return nil, nil, err
	}
	var keys []svrpc.PGPKey
	var skipped []string
	for _, e := range entries {
		if e.Item.Kind != svrpc.PGPItemKind || e.Item.Attrs[svrpc.PGPFingerprint] == "" {
			continue
		}
		k, err := cl.PGPPublicKey(ctx, vault, e.Item.Name)
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
		return nil, skipped, ErrNoGnuPGKey
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

// StableExecutable is a program's path as gpg.conf should name it: as
// found on PATH when that is the program (/usr/bin/secretvault, a
// profile's bin), which outlives an upgrade that moves the file itself
// (a Homebrew Cellar, the Nix store), else exe itself.
func StableExecutable(exe string) (string, error) {
	if exe == "" {
		return "", ErrNoCLI
	}
	if p, err := exec.LookPath("secretvault"); err == nil && filepath.IsAbs(p) {
		if a, err1 := os.Stat(p); err1 == nil {
			if b, err2 := os.Stat(exe); err2 == nil && os.SameFile(a, b) {
				return p, nil
			}
		}
	}
	return exe, nil
}

// defaultGnuPGHome is the home gpg uses when none is named: $GNUPGHOME,
// else ~/.gnupg.
func defaultGnuPGHome() string {
	if h := os.Getenv("GNUPGHOME"); h != "" {
		return h
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, ".gnupg")
}

// sameDir reports whether two paths are the same directory.
func sameDir(a, b string) bool {
	if filepath.Clean(a) == filepath.Clean(b) {
		return true
	}
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(fa, fb)
}

// ForgetSocketDir removes the per-home socket directory (d.HASH) holding
// sock, if it is empty.
func ForgetSocketDir(sock string) {
	if dir := filepath.Dir(sock); strings.HasPrefix(filepath.Base(dir), "d.") {
		os.Remove(dir) // only ever removes an empty directory
	}
}

// GnuPGPrograms finds gpg (named, or on PATH) and the gpgconf beside it.
func GnuPGPrograms(gpg string) (string, string, error) {
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

// GnuPGDir is a directory or socket gpgconf --list-dirs names for home.
func GnuPGDir(gpgconf, home, name string) (string, error) {
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

// writeConf replaces a file, keeping its mode (0600 for a new one); a
// link is followed, and the file it leads to replaced.
func writeConf(path, text string) error {
	if target, err := filepath.EvalSymlinks(path); err == nil {
		path = target
	}
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

// FirstUserID is a key's first user ID ("" when it has none).
func FirstUserID(k svrpc.PGPKey) string {
	if len(k.UserIDs) > 0 {
		return k.UserIDs[0]
	}
	return ""
}
