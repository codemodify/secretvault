// Command secretvault is the command-line face of secretvault.
//
// It is a client of secretvaultd, which it starts if it is not running.
// The daemon holds the keys; the CLI asks it for things, and when the
// daemon needs to know it is you, the CLI asks for the vault's passphrase
// on this terminal (once per terminal, until the vault locks), as sudo
// does.
//
// Usage:
//
//	secretvault [--vault NAME] <command> [flags] [args]
//
//	init                       create a vault
//	unlock [VAULT]             unlock a vault
//	lock [VAULT] [--all]       lock a vault, or all of them
//	status                     show the daemon and its vaults
//	vault list|add|forget|default
//	vault signatures [required|optional]   whether only signed revisions count
//	set NAME                   store or update an item (secret from stdin or a prompt)
//	get NAME                   print an item's secret, a field, or the whole item
//	ls [PREFIX]                list items
//	mv FROM TO                 rename an item
//	rm NAME                    delete an item
//	history NAME               list an item's revisions, and who signed each
//	device ls|label|rm|vouch   the devices registered in a vault, whose keys sign what they write
//	import FORMAT FILE         import another password manager's export
//	export cxf|kdbx FILE       export items to a CXF or KeePass file
//	gen                        print a random password
//	slot list|add|rm           manage the ways a vault can be unlocked
//	fido2 list                 list the security keys plugged in
//	passwd                     change the passphrase
//	share RECIPIENT|FILE       give a person's identity a keyslot
//	unshare SLOT-ID            cut them off: remove the keyslot and rotate the key
//	emergency grant|ls|deny|revoke   let a person open a vault after a wait you can refuse
//	emergency accept|request|open    the other side: ask for such access, and open the vault after the wait
//	vault rotate               rotate the vault key
//	grant list|allow|deny|revoke  decide what programs may do
//	audit                      show who accessed what
//	keyring status|import|takeover|restore   be the desktop's keyring (Linux)
//	browser install|uninstall|status|ls|rm   fill logins in browsers through KeePassXC-Browser
//	read sv://VAULT/ITEM[#FIELD]            print one value ("-" is the default vault)
//	run [--env-file F] -- CMD               run CMD with sv:// references in its environment resolved
//	inject [-i IN] [-o OUT]                 fill {{ sv://... }} references in a template
//	ci fetch|run --server URL --role ROLE   secrets from a delivery server, with the job's ID token
//	age keygen|recipient|identity|encrypt|decrypt   age files with vault-held keys
//	container create|open|close|ls|header-backup|passwd   encrypted containers (LUKS2 images)
//	identity new|pub           make or show a recipient identity
//	contact ls|show|add|import|rm|verify|lookup|qr|vault   people, their keys, and how you verified them
//	trust check|seen           the verdict on a message's signer; record a key seen in mail
//	pgp ls|new|import|export|pub|sign|decrypt|verify|gpg-setup   your OpenPGP keys, used inside the daemon (and by gpg)
//	verify                     re-authenticate every file of the vault
//	host init|allow|deny|ls|status|audit    set up the host daemon (as root)
//	version                    print the version
//
// Installed as git-credential-secretvault or docker-credential-secretvault
// (symlinks to this program), it is git's or docker's credential helper;
// as age-plugin-secretvault, the age plugin for identities kept in vaults;
// as secretvault-browser (or when a browser starts it by its manifest),
// the native-messaging host KeePassXC-Browser talks to. gpg starts it as
// its agent-program in a GnuPG home 'pgp gpg-setup' pointed at the
// daemon, to start the daemon and link the agent socket again.
//
// Commands that use a vault also take --passphrase-file FILE, --keyfile
// FILE, --identity FILE, --recovery, --shares or --fido2, to unlock (and
// prove it is you) without being asked for the passphrase.
//
// A FIDO2 security key becomes a keyslot with 'slot add fido2' (its PIN
// is then asked for with each touch if it has one; --no-uv makes a touch
// enough). While such a key is plugged in, unlocking asks for it first,
// and for the passphrase only if it is not used.
//
// --host (or SECRETVAULT_HOST=1) talks to the host daemon (secretvaultd
// --host) instead of your own: as root on its admin socket, where any
// command works; as anyone else on its services socket, where read, run
// and inject get what the host's policy lists for them.
//
// import reads KeePass (KDBX 3.1 and 4), Bitwarden JSON, 1Password (1PUX),
// Proton Pass, browser and password-manager CSV, Aegis, Google
// Authenticator and CXF exports; FORMAT auto guesses which. An encrypted
// export's own passphrase is asked for on the terminal, or read with
// --source-passphrase-file (a KeePass key file with --source-keyfile).
// Items that already exist are skipped unless --overwrite is given, and
// --dry-run only lists the names that would be created. pass and gopass
// stores need OpenPGP, which arrives with milestone M5. export writes a
// new file, mode 0600, never over an existing one: KDBX asks for the
// file's passphrase; CXF is not encrypted, and says so.
//
// Environment: SECRETVAULT_VAULT names the vault to use, SECRETVAULT_SOCK
// the daemon's socket; SECRETVAULT_HOST=1 is --host, and
// SECRETVAULT_HOST_DATA and SECRETVAULT_HOST_RUNTIME move the host
// daemon's data and sockets.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svterm"
)

// EnvVault names the vault to use when --vault is not given.
const EnvVault = "SECRETVAULT_VAULT"

// minPassphrase is the shortest passphrase accepted for a new keyslot.
const minPassphrase = 8

// cli is everything a command talks to, so tests can drive run.
type cli struct {
	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	stdinIsTTY bool

	// ask and askNew prompt on the terminal; tests replace them. canAsk
	// says whether there is a terminal to ask on at all.
	ask    func(prompt string) ([]byte, error)
	askNew func(prompt string, min int) ([]byte, error)
	canAsk bool

	// connect reaches the daemon (tests point it at their own).
	connect func(secretvault.Options) (*secretvault.Client, error)

	// clip, when set, replaces copying to the real clipboard (tests).
	clip func(secret []byte, ttl time.Duration) (string, error)

	// clientName is the name the daemon's logs give this connection
	// ("secretvault" when empty).
	clientName string

	// host talks to the host daemon (--host): on its admin socket as
	// root, else on its services socket. hostAdmin picks the admin socket
	// whoever runs this (the host commands, which only root may use).
	host, hostAdmin bool

	// root reports whether this runs as root (os.Geteuid() == 0 when nil;
	// tests stand in).
	root func() bool

	// systemdCreds runs systemd-creds with stdin, for 'host init --seal'
	// (tests stand in, so nothing touches the system).
	systemdCreds func(stdin []byte, args ...string) ([]byte, error)

	vault  string
	client *secretvault.Client
}

func main() {
	_ = svcrypto.NoCoreDumps()
	c := &cli{
		stdin:      os.Stdin,
		stdout:     os.Stdout,
		stderr:     os.Stderr,
		stdinIsTTY: term.IsTerminal(int(os.Stdin.Fd())),
		ask:        svterm.Secret,
		askNew:     svterm.NewSecret,
		connect:    secretvault.Connect,
	}
	if len(os.Args) > 1 && os.Args[1] == clipCommand {
		os.Exit(clipHelper(os.Args[2:]))
	}
	if t, err := svterm.OpenTerminal(""); err == nil {
		t.Close()
		c.canAsk = true
	}
	args := os.Args[1:]
	if h := helperName(os.Args[0]); h != "" {
		args = append([]string{h}, args...)
	} else if _, ok := browserOrigin(args); ok {
		args = append([]string{"browser-host"}, args...)
	}
	code := c.run(args)
	if c.client != nil {
		c.client.Close()
	}
	os.Exit(code)
}

type command struct {
	name    string
	summary string
	run     func(c *cli, args []string) error
}

var commands []command

func init() {
	commands = []command{
		{"init", "create a vault", (*cli).cmdInit},
		{"unlock", "unlock a vault", (*cli).cmdUnlock},
		{"lock", "lock a vault, or all of them (--all)", (*cli).cmdLock},
		{"status", "show the daemon and its vaults", (*cli).cmdStatus},
		{"vault", "list, add, forget or choose the default vault", (*cli).cmdVault},
		{"sync", "keep a vault in step with a sync server: setup, join, invite, status, now, devices, off", (*cli).cmdSync},
		{"set", "store or update an item", (*cli).cmdSet},
		{"get", "print an item's secret, a field, or the whole item", (*cli).cmdGet},
		{"ls", "list items", (*cli).cmdList},
		{"mv", "rename an item", (*cli).cmdMove},
		{"rm", "delete an item", (*cli).cmdRemove},
		{"history", "list an item's revisions, and who signed each", (*cli).cmdHistory},
		{"restore", "make an earlier revision, or a deleted item, current again", (*cli).cmdRestore},
		{"resolve", "settle an item changed on two devices at once: show its versions, keep one", (*cli).cmdResolve},
		{"device", "the devices registered in a vault, whose keys sign what they write: ls, label, rm, vouch", (*cli).cmdDevice},
		{"attach", "attach a file to an item", (*cli).cmdAttach},
		{"file", "an item's attached files: ls, get, rm", (*cli).cmdFile},
		{"import", "import another password manager's export", (*cli).cmdImport},
		{"export", "export items to a CXF or KeePass (KDBX) file", (*cli).cmdExport},
		{"gen", "print a random password", (*cli).cmdGen},
		{"slot", "manage keyslots: list, add, rm", (*cli).cmdSlot},
		{"fido2", "list the security keys plugged in, and what each can do", (*cli).cmdFIDO2},
		{"passwd", "change the passphrase", (*cli).cmdPasswd},
		{"share", "give a person's identity a keyslot", (*cli).cmdShare},
		{"unshare", "cut a person off: remove their keyslot and rotate the key", (*cli).cmdUnshare},
		{"emergency", "emergency access, after a wait you can refuse: grant, ls, deny, revoke; accept, request, open", (*cli).cmdEmergency},
		{"grant", "decide what programs may do: list, allow, deny, revoke", (*cli).cmdGrant},
		{"audit", "show who accessed what", (*cli).cmdAudit},
		{"keyring", "be the desktop's keyring: status, import, takeover, restore", (*cli).cmdKeyring},
		{"browser", "fill logins in browsers through KeePassXC-Browser: install, uninstall, status, ls, rm", (*cli).cmdBrowser},
		{"browser-host", "the browsers' native-messaging host (run as secretvault-browser)", (*cli).cmdBrowserHost},
		{"read", "print one value: sv://VAULT/ITEM[#FIELD]", (*cli).cmdRead},
		{"run", "run a command with sv:// references in its environment resolved", (*cli).cmdRun},
		{"inject", "fill {{ sv://... }} references in a template", (*cli).cmdInject},
		{"ci", "secrets from a delivery server, for CI jobs, pods and services: fetch, run", (*cli).cmdCI},
		{"git-credential", "git's credential helper (get, store, erase)", (*cli).cmdGitCredential},
		{"docker-credential", "docker's credential helper (get, store, erase, list)", (*cli).cmdDockerCredential},
		{"mail", "inspect a message (its signers, against your contacts; --decrypt), or compose one signed and encrypted", (*cli).cmdMail},
		{"smime", "your S/MIME keys: import a .p12, ls", (*cli).cmdSMIME},
		{"age", "age files with vault-held keys: keygen, recipient, identity, encrypt, decrypt", (*cli).cmdAge},
		{"container", "encrypted containers: create, open, close, ls, header-backup, passwd", (*cli).cmdContainer},
		{"age-plugin", "age's plugin protocol (run as age-plugin-secretvault)", (*cli).cmdAgePlugin},
		{"identity", "make (new) or show (pub) a recipient identity", (*cli).cmdIdentity},
		{"contact", "people and their keys: ls, show, add, import, rm, verify, lookup, qr, vault", (*cli).cmdContact},
		{"trust", "who signed a message, as far as you know: check, seen", (*cli).cmdTrust},
		{"pgp", "your OpenPGP keys: ls, new, import, export, pub, sign, decrypt, verify", (*cli).cmdPGP},
		{"verify", "re-authenticate every file of the vault", (*cli).cmdVerify},
		{"host", "set up the host daemon, as root: init, allow, deny, ls, status, audit", (*cli).cmdHost},
		{"version", "print the version", (*cli).cmdVersion},
	}
}

// errUsage is a usage error whose message has already been printed.
var errUsage = errors.New("usage")

func (c *cli) run(args []string) int {
	if slices.Contains(args, gpgAgentProgramFlag) && slices.Contains(args, "--daemon") {
		return c.gpgAgentStart(args) // gpg starting its agent (pgp_gnupg.go)
	}
	global := flag.NewFlagSet("secretvault", flag.ContinueOnError)
	global.SetOutput(c.stderr)
	global.StringVar(&c.vault, "vault", os.Getenv(EnvVault), "the vault to use (default: the default vault)")
	global.BoolVar(&c.host, "host", c.host || envTrue(svrpc.EnvHost), "talk to the host daemon (secretvaultd --host), not your own")
	global.Usage = func() { c.usage() }
	if err := global.Parse(args); err != nil {
		return 2
	}
	rest := global.Args()
	if len(rest) == 0 {
		c.usage()
		return 2
	}
	if rest[0] == "help" || rest[0] == "-h" || rest[0] == "--help" {
		c.usage()
		return 0
	}
	for _, cmd := range commands {
		if cmd.name == rest[0] {
			err := cmd.run(c, rest[1:])
			var ec exitCode
			switch {
			case err == nil:
				return 0
			case errors.As(err, &ec):
				return int(ec)
			case errors.Is(err, errUsage), errors.Is(err, flag.ErrHelp):
				return 2
			default:
				fmt.Fprintln(c.stderr, "secretvault:", describe(err))
				return 1
			}
		}
	}
	fmt.Fprintf(c.stderr, "secretvault: unknown command %q\n", rest[0])
	c.usage()
	return 2
}

// describe turns an error into something to tell a person.
func describe(err error) string {
	var e *svrpc.Error
	if errors.As(err, &e) {
		switch e.Code {
		case svrpc.CodeCanceled:
			return "canceled"
		case svrpc.CodeWrongKey:
			return "that key does not open this vault"
		}
		return e.Message
	}
	if errors.Is(err, secretvault.ErrNoDaemon) {
		return err.Error() + " (is secretvaultd installed beside secretvault?)"
	}
	return err.Error()
}

func (c *cli) usage() {
	fmt.Fprintln(c.stderr, "usage: secretvault [--vault NAME] [--host] <command> [flags] [args]")
	fmt.Fprintln(c.stderr)
	for _, cmd := range commands {
		fmt.Fprintf(c.stderr, "  %-10s %s\n", cmd.name, cmd.summary)
	}
	fmt.Fprintln(c.stderr)
	fmt.Fprintln(c.stderr, "Run 'secretvault <command> -h' for a command's flags.")
}

// parse parses flags that may appear before, between or after positional
// arguments, and checks the positional count.
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
		fmt.Fprintf(fs.Output(), "usage: secretvault %s %s\n", fs.Name(), usage)
		fs.PrintDefaults()
		return nil, errUsage
	}
	return pos, nil
}

func (c *cli) flags(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(c.stderr)
	// --vault is global, and works after the command too, where people
	// tend to type it. So does --host.
	fs.StringVar(&c.vault, "vault", c.vault, "the vault to use (default: the default vault)")
	fs.BoolVar(&c.host, "host", c.host, "talk to the host daemon (secretvaultd --host), not your own")
	return fs
}

// envTrue reports whether an environment variable is set to yes.
func envTrue(name string) bool {
	switch strings.ToLower(os.Getenv(name)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// multi is a repeatable string flag.
type multi []string

func (m *multi) String() string     { return strings.Join(*m, ",") }
func (m *multi) Set(s string) error { *m = append(*m, s); return nil }

// keyValues splits k=v arguments.
func keyValues(what string, list []string) (map[string]string, error) {
	out := map[string]string{}
	for _, kv := range list {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, fmt.Errorf("%s %q is not key=value", what, kv)
		}
		out[k] = v
	}
	return out, nil
}
