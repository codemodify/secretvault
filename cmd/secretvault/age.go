package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/codemodify/secretvault/svage"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// age files with vault-held keys:
//
//	secretvault age keygen [--pq] --name ITEM    a new identity, stored as ITEM
//	secretvault age recipient ITEM               its public key (age1... or age1pq1...)
//	secretvault age identity ITEM                the AGE-PLUGIN-SECRETVAULT-1... line for age and SOPS
//	secretvault age encrypt [-r R]... [-R F]... [-p] [-a] [-o OUT] [IN]
//	secretvault age decrypt [-i sv://VAULT/ITEM | -i FILE]... [-o OUT] [IN]
//
// How identities are kept in items, made, found and used is svops'
// (age.go); age, rage and SOPS reach them through age-plugin-secretvault
// (age_plugin.go).

func (c *cli) cmdAge(args []string) error {
	usage := func() error {
		fmt.Fprintln(c.stderr, "usage: secretvault age keygen|recipient|identity|encrypt|decrypt [flags] [args]")
		fmt.Fprintln(c.stderr)
		fmt.Fprintln(c.stderr, "  keygen [--pq] --name ITEM [-o FILE]   make an identity and store it as ITEM")
		fmt.Fprintln(c.stderr, "  recipient ITEM                        print ITEM's recipient (its public key)")
		fmt.Fprintln(c.stderr, "  identity ITEM                         print ITEM's plugin identity, for age and SOPS")
		fmt.Fprintln(c.stderr, "  encrypt [-r R]... [-R FILE]... [-p] [-a] [-o OUT] [IN]")
		fmt.Fprintln(c.stderr, "  decrypt [-i sv://VAULT/ITEM | -i FILE]... [-o OUT] [IN]")
		fmt.Fprintln(c.stderr)
		fmt.Fprintln(c.stderr, "ITEM is an item name (in --vault) or sv://VAULT/ITEM.")
		return errUsage
	}
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "keygen":
		return c.ageKeygen(args[1:])
	case "recipient":
		return c.ageShow(args[1:], false)
	case "identity":
		return c.ageShow(args[1:], true)
	case "encrypt":
		return c.ageEncrypt(args[1:])
	case "decrypt":
		return c.ageDecrypt(args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	}
	fmt.Fprintf(c.stderr, "secretvault age: unknown subcommand %q\n", args[0])
	return usage()
}

func (c *cli) ageKeygen(args []string) error {
	fs := c.flags("age keygen")
	pq := fs.Bool("pq", false, "make a post-quantum identity (ML-KEM-768 + X25519, age v1.3 or later)")
	name := fs.String("name", "", "store the identity as the item `ITEM` (required)")
	out := fs.String("o", "", "also write the plugin identity to `FILE` (created 0600), instead of printing it")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "--name ITEM [--pq] [-o FILE]"); err != nil {
		return err
	}
	if *name == "" {
		fmt.Fprintln(c.stderr, "usage: secretvault age keygen --name ITEM [--pq] [-o FILE]")
		return errUsage
	}
	r, err := svops.AgeItemRef(c.vault, *name)
	if err != nil {
		return err
	}
	n, err := svops.GenerateAgeIdentity(*pq)
	if err != nil {
		return err
	}
	defer n.Wipe()
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	k, err := svops.StoreAgeIdentity(ctx, cl, r, n)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "Stored a new %s age identity as %s (revision %s).\n", k.Kind, r.Item, svops.Short(k.Entry.Rev))
	if *out != "" {
		if err := svops.WriteNew(*out, k.File); err != nil {
			return err
		}
		fmt.Fprintln(c.stdout, k.Recipient)
		return nil
	}
	_, err = c.stdout.Write(k.File)
	return err
}

func (c *cli) ageShow(args []string, asPlugin bool) error {
	cmd := "recipient"
	if asPlugin {
		cmd = "identity"
	}
	fs := c.flags("age " + cmd)
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "ITEM")
	if err != nil {
		return err
	}
	r, err := svops.AgeItemRef(c.vault, pos[0])
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	rcpt, err := svops.AgeItemRecipient(ctx, cl, r)
	if err != nil {
		return err
	}
	if !asPlugin {
		fmt.Fprintln(c.stdout, rcpt)
		return nil
	}
	vault, err := svops.VaultName(ctx, cl, r.Vault)
	if err != nil {
		return err
	}
	s, err := svops.AgePluginIdentity(vault, r.Item)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.stdout, s)
	return nil
}

// vaultIdentity is an age identity kept in a vault item, fetched through
// the daemon (presenting the keys u names; none in the plugin) the first
// time a stanza it could open turns up.
func (c *cli) vaultIdentity(u *unlockFlags, r svrpc.Ref) svage.Identity {
	return &svops.VaultIdentity{Ref: r, Fetch: func(r svrpc.Ref) (svage.Identity, error) {
		cl, err := c.open(u)
		if err != nil {
			return nil, err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		id, err := svops.LoadAgeIdentity(ctx, cl, r)
		if err != nil {
			return nil, fmt.Errorf("sv://%s/%s: %s", r.Vault, r.Item, describe(err))
		}
		return id, nil
	}}
}

// askPassphrase asks for a file's passphrase, when it turns out to be
// encrypted to one.
func (c *cli) askPassphrase() ([]byte, error) {
	if !c.canAsk {
		return nil, errors.New("the file is encrypted to a passphrase, and there is no terminal to ask for it on")
	}
	return c.ask("Passphrase: ")
}

// pluginUI lets other plugins (a YubiKey's, say) talk to the person on
// this terminal.
func (c *cli) pluginUI() *svage.PluginUI {
	return &svage.PluginUI{
		DisplayMessage: func(name, msg string) error {
			fmt.Fprintf(c.stderr, "age-plugin-%s: %s\n", name, msg)
			return nil
		},
		RequestValue: func(name, prompt string, _ bool) ([]byte, error) {
			if !c.canAsk {
				return nil, errors.New("no terminal")
			}
			return c.ask(fmt.Sprintf("age-plugin-%s: %s ", name, strings.TrimSpace(prompt)))
		},
		Confirm: func(name, prompt, yes, no string) (bool, error) {
			if !c.canAsk {
				return false, errors.New("no terminal")
			}
			choices := yes
			if no != "" {
				choices += "/" + no
			}
			a, err := c.ask(fmt.Sprintf("age-plugin-%s: %s [%s] ", name, strings.TrimSpace(prompt), choices))
			if err != nil {
				return false, err
			}
			ans := strings.TrimSpace(string(a))
			return strings.EqualFold(ans, yes) || (ans != "" && strings.EqualFold(ans[:1], yes[:min(1, len(yes))])), nil
		},
	}
}

// ageRecipient reads a -r argument: any recipient age knows, or
// sv://VAULT/ITEM for the recipient of an identity kept in a vault.
func (c *cli) ageRecipient(ctx context.Context, u *unlockFlags, arg string) (svage.Recipient, error) {
	return svops.AgeRecipient(arg, func(r svrpc.Ref) (string, error) {
		cl, err := c.open(u)
		if err != nil {
			return "", err
		}
		return svops.AgeItemRecipient(ctx, cl, r)
	}, c.pluginUI())
}

func (c *cli) ageEncrypt(args []string) error {
	fs := c.flags("age encrypt")
	var rcpts, files multi
	fs.Var(&rcpts, "r", "encrypt to `RECIPIENT`: age1..., age1pq1..., an SSH public key, a plugin's, or sv://VAULT/ITEM (repeatable)")
	fs.Var(&files, "R", "encrypt to the recipients listed in `FILE`, one per line (repeatable)")
	pass := fs.Bool("p", false, "encrypt to a passphrase, asked for twice on the terminal")
	armor := fs.Bool("a", false, "write ASCII armor instead of binary")
	outPath := fs.String("o", "", "write to `FILE` (default: stdout)")
	mixed := fs.Bool("allow-mixed-pq", false, "let post-quantum and classical recipients share the file (it is then only as safe as X25519)")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[-r RECIPIENT]... [-R FILE]... [-p] [-a] [-o OUT] [IN]")
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	var recipients []svage.Recipient
	for _, a := range rcpts {
		r, err := c.ageRecipient(ctx, &u, a)
		if err != nil {
			return fmt.Errorf("-r %.40s: %w", a, err)
		}
		recipients = append(recipients, r)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		err = svops.EachKeyLine(b, func(n int, line []byte) error {
			r, err := c.ageRecipient(ctx, &u, string(line))
			if err != nil {
				return fmt.Errorf("%s:%d: %w", f, n, err)
			}
			recipients = append(recipients, r)
			return nil
		})
		if err != nil {
			return err
		}
	}
	if *pass {
		if len(recipients) > 0 {
			return errors.New("a passphrase must be a file's only recipient: -p cannot be used with -r or -R")
		}
		if !c.canAsk {
			return errors.New("no terminal to ask for the passphrase on")
		}
		p, err := c.askNew("Passphrase: ", 1)
		if err != nil {
			return err
		}
		sr, err := svage.NewScryptRecipient(p)
		clear(p)
		if err != nil {
			return err
		}
		defer sr.Wipe()
		recipients = append(recipients, sr)
	}
	if len(recipients) == 0 {
		fmt.Fprintln(c.stderr, "secretvault age encrypt: no recipients; use -r, -R or -p")
		return errUsage
	}
	in, closeIn, err := c.input(pos)
	if err != nil {
		return err
	}
	defer closeIn()
	out, err := c.output(*outPath, 0o644)
	if err != nil {
		return err
	}
	defer out.abort()
	if !*armor && out.terminal() {
		return errors.New("refusing to write binary ciphertext to a terminal; use -a or -o")
	}
	if err := svops.AgeEncrypt(out.w, in, recipients, *armor, *mixed); err != nil {
		return err
	}
	return out.commit()
}

// ageIdentities reads a -i argument: sv://VAULT/ITEM[#FIELD], or a file
// of identities (age's, plugins', ours) or an SSH private key.
func (c *cli) ageIdentities(u *unlockFlags, arg string) ([]svage.Identity, error) {
	return svops.AgeIdentities(arg, svops.AgeIdentityOptions{
		Vault: func(r svrpc.Ref) svage.Identity { return c.vaultIdentity(u, r) },
		UI:    c.pluginUI(),
		SSHPassphrase: func(path string) ([]byte, error) {
			if !c.canAsk {
				return nil, errors.New("no terminal to ask for it on")
			}
			return c.ask("Passphrase for " + path + ": ")
		},
	})
}

func (c *cli) ageDecrypt(args []string) error {
	fs := c.flags("age decrypt")
	var idArgs multi
	fs.Var(&idArgs, "i", "decrypt with `IDENTITY`: sv://VAULT/ITEM, or a file of identities or an SSH private key (repeatable)")
	outPath := fs.String("o", "", "write to `FILE`, created 0600 (default: stdout)")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[-i sv://VAULT/ITEM | -i FILE]... [-o OUT] [IN]")
	if err != nil {
		return err
	}
	var ids []svage.Identity
	for _, a := range idArgs {
		more, err := c.ageIdentities(&u, a)
		if err != nil {
			return err
		}
		ids = append(ids, more...)
	}
	if len(ids) == 0 {
		ids = append(ids, svops.PassphraseIdentity{Ask: c.askPassphrase})
	}
	in, closeIn, err := c.input(pos)
	if err != nil {
		return err
	}
	defer closeIn()
	r, err := svops.AgeDecrypt(in, ids)
	if err != nil {
		return err
	}
	out, err := c.output(*outPath, 0o600)
	if err != nil {
		return err
	}
	defer out.abort()
	if _, err := io.Copy(out.w, r); err != nil {
		return err
	}
	return out.commit()
}

// input opens the file named in pos, or stdin.
func (c *cli) input(pos []string) (io.Reader, func(), error) {
	if len(pos) == 0 || pos[0] == "-" {
		return c.stdin, func() {}, nil
	}
	f, err := os.Open(pos[0])
	if err != nil {
		return nil, nil, err
	}
	return f, func() { f.Close() }, nil
}

// outFile is where a command's result goes: stdout, or a file that
// appears only when the whole result is written (svops.AtomicFile), so a
// failed decryption leaves neither part of the plaintext nor a clobbered
// file.
type outFile struct {
	w io.Writer
	c *cli
	f *svops.AtomicFile // nil for stdout
}

func (c *cli) output(path string, mode os.FileMode) (*outFile, error) {
	if path == "" || path == "-" {
		return &outFile{w: c.stdout, c: c}, nil
	}
	f, err := svops.CreateAtomic(path, mode)
	if err != nil {
		return nil, err
	}
	return &outFile{w: f, c: c, f: f}, nil
}

// terminal reports whether the output is stdout on a terminal.
func (o *outFile) terminal() bool {
	f, ok := o.c.stdout.(*os.File)
	return o.f == nil && ok && term.IsTerminal(int(f.Fd()))
}

func (o *outFile) commit() error {
	if o.f == nil {
		return nil
	}
	return o.f.Commit()
}

func (o *outFile) abort() {
	if o.f != nil {
		o.f.Abort()
	}
}
