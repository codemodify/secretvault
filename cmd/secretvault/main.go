// Command secretvault is the command-line face of secretvault.
//
// In this milestone (M0) it opens vault folders directly: every command
// that needs secrets unlocks the vault itself, asking for the passphrase on
// the terminal. That is transitional. From M1 the CLI is purely a client of
// secretvaultd (starting it if needed), so every access goes through one
// place that asks for consent and keeps the audit trail.
//
// Usage:
//
//	secretvault [--vault DIR] <command> [flags] [args]
//
//	init                       create a vault
//	set NAME                   store or update an item (secret from stdin or a prompt)
//	get NAME                   print an item's secret, a field, or the whole item
//	ls [PREFIX]                list items
//	mv FROM TO                 rename an item
//	rm NAME                    delete an item
//	history NAME               list an item's revisions
//	gen                        print a random password
//	slot list|add|rm           manage the ways a vault can be unlocked
//	passwd                     change the passphrase
//	identity new|pub           make or show a recipient identity
//	verify                     re-authenticate every file of the vault
//	version                    print the version
//
// Unlocking: by default the passphrase is asked for on the terminal. Any
// command that opens a vault also takes --passphrase-file FILE,
// --keyfile FILE, --identity FILE or --recovery.
//
// Environment: SECRETVAULT_VAULT names the vault directory,
// SECRETVAULT_HOME the data directory (default vaults live in
// SECRETVAULT_HOME/vaults/default).
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svprompt"
)

// EnvVault names the vault directory to use.
const EnvVault = "SECRETVAULT_VAULT"

// minPassphrase is the shortest passphrase accepted for a new keyslot.
const minPassphrase = 8

// cli is everything a command talks to, so tests can drive run.
type cli struct {
	stdin      io.Reader
	stdout     io.Writer
	stderr     io.Writer
	stdinIsTTY bool

	// ask and askNew prompt on the terminal; tests replace them.
	ask    func(prompt string) ([]byte, error)
	askNew func(prompt string, min int) ([]byte, error)

	vaultDir string
}

func main() {
	_ = svcrypto.HardenProcess()
	c := &cli{
		stdin:      os.Stdin,
		stdout:     os.Stdout,
		stderr:     os.Stderr,
		stdinIsTTY: term.IsTerminal(int(os.Stdin.Fd())),
		ask:        svprompt.Secret,
		askNew:     svprompt.NewSecret,
	}
	os.Exit(c.run(os.Args[1:]))
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
		{"set", "store or update an item", (*cli).cmdSet},
		{"get", "print an item's secret, a field, or the whole item", (*cli).cmdGet},
		{"ls", "list items", (*cli).cmdList},
		{"mv", "rename an item", (*cli).cmdMove},
		{"rm", "delete an item", (*cli).cmdRemove},
		{"history", "list an item's revisions", (*cli).cmdHistory},
		{"gen", "print a random password", (*cli).cmdGen},
		{"slot", "manage keyslots: list, add, rm", (*cli).cmdSlot},
		{"passwd", "change the passphrase", (*cli).cmdPasswd},
		{"identity", "make (new) or show (pub) a recipient identity", (*cli).cmdIdentity},
		{"verify", "re-authenticate every file of the vault", (*cli).cmdVerify},
		{"version", "print the version", (*cli).cmdVersion},
	}
}

// errUsage is a usage error whose message has already been printed.
var errUsage = errors.New("usage")

func (c *cli) run(args []string) int {
	global := flag.NewFlagSet("secretvault", flag.ContinueOnError)
	global.SetOutput(c.stderr)
	global.StringVar(&c.vaultDir, "vault", "", "vault directory (default $"+EnvVault+", else the default vault)")
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
			switch {
			case err == nil:
				return 0
			case errors.Is(err, errUsage), errors.Is(err, flag.ErrHelp):
				return 2
			default:
				fmt.Fprintln(c.stderr, "secretvault:", err)
				return 1
			}
		}
	}
	fmt.Fprintf(c.stderr, "secretvault: unknown command %q\n", rest[0])
	c.usage()
	return 2
}

func (c *cli) usage() {
	fmt.Fprintln(c.stderr, "usage: secretvault [--vault DIR] <command> [flags] [args]")
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
	return fs
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
