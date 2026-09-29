package main

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/term"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svage"
	"github.com/codemodify/secretvault/svcore"
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
// An age identity lives in an item of kind "key": the field age_identity
// (type "key") holds the AGE-SECRET-KEY-1... or AGE-SECRET-KEY-PQ-1...
// text, and the attribute and field age_recipient its public half. The
// recipient is a plain age recipient, so anyone can encrypt to it without
// secretvault. Decrypting takes the identity from the daemon, which asks
// the person first as it does for any other item; age, rage and SOPS get
// there through age-plugin-secretvault (age_plugin.go), whose identity
// string names the item.

const (
	ageIdentityField = "age_identity"
	ageRecipientName = "age_recipient" // the field and the attribute
	agePluginName    = "secretvault"
)

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

// ageItem reads an ITEM argument: a name in --vault, or sv://VAULT/ITEM.
func (c *cli) ageItem(arg string) (ref, error) {
	if strings.HasPrefix(arg, "sv://") {
		return parseRef(arg)
	}
	if err := svcore.CheckName(arg); err != nil {
		return ref{}, err
	}
	return ref{vault: c.vault, item: arg}, nil
}

// vaultName is the name of vault ("" for the default one).
func vaultName(ctx context.Context, cl *secretvault.Client, vault string) (string, error) {
	if vault != "" {
		return vault, nil
	}
	vs, err := cl.Vaults(ctx)
	if err != nil {
		return "", err
	}
	for _, v := range vs {
		if v.Default {
			return v.Name, nil
		}
	}
	return "", errors.New("there is no default vault; create one with 'secretvault init'")
}

// pluginIdentity is the AGE-PLUGIN-SECRETVAULT-1... string naming an item.
func pluginIdentity(vault, item string) (string, error) {
	return svage.EncodePluginIdentity(agePluginName, []byte(vault+"/"+item))
}

// itemOfPluginIdentity reads what pluginIdentity wrote: "VAULT/ITEM",
// with "-" (or nothing) for the default vault.
func itemOfPluginIdentity(data []byte) (ref, error) {
	vault, item, ok := strings.Cut(string(data), "/")
	if !ok {
		return ref{}, errors.New("the identity does not name a vault item")
	}
	if err := svcore.CheckName(item); err != nil {
		return ref{}, err
	}
	if vault == "-" {
		vault = ""
	}
	return ref{vault: vault, item: item}, nil
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
	r, err := c.ageItem(*name)
	if err != nil {
		return err
	}
	var idText []byte
	var rcpt string
	if *pq {
		id, err := svage.GenerateHybridIdentity()
		if err != nil {
			return err
		}
		idText, err = id.AppendText(nil)
		if err != nil {
			return err
		}
		rcpt = id.Recipient().String()
	} else {
		id, err := svage.GenerateX25519Identity()
		if err != nil {
			return err
		}
		idText, _ = id.AppendText(nil)
		rcpt = id.Recipient().String()
	}
	defer clear(idText)

	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	// Never replace a key: files encrypted to it would be lost.
	if found, _, err := findItem(ctx, cl, r.vault, r.item); err != nil {
		return err
	} else if found {
		return fmt.Errorf("%s already exists; pick another name (an age identity is never replaced)", r.item)
	}
	it := svrpc.Item{
		Kind: "key", Name: r.item, Label: "age identity",
		Attrs: map[string]string{ageRecipientName: rcpt},
		Fields: []svrpc.Field{
			{Name: ageIdentityField, Type: svcore.FieldKey, Value: idText},
			{Name: ageRecipientName, Type: svcore.FieldText, Value: []byte(rcpt)},
		},
	}
	e, err := cl.Put(ctx, r.vault, it)
	if err != nil {
		return err
	}
	vault, err := vaultName(ctx, cl, r.vault)
	if err != nil {
		return err
	}
	plugin, err := pluginIdentity(vault, r.item)
	if err != nil {
		return err
	}
	kind := "X25519"
	if *pq {
		kind = "post-quantum"
	}
	file := fmt.Sprintf("# secretvault age identity (%s): item %q in vault %q\n# created: %s\n# recipient: %s\n%s\n",
		kind, r.item, vault, e.Time.UTC().Format(time.RFC3339), rcpt, plugin)
	fmt.Fprintf(c.stderr, "Stored a new %s age identity as %s (revision %s).\n", kind, r.item, short(e.Rev))
	if *out != "" {
		if err := writeNew(*out, []byte(file)); err != nil {
			return err
		}
		fmt.Fprintln(c.stdout, rcpt)
		return nil
	}
	_, err = io.WriteString(c.stdout, file)
	return err
}

// findItem looks an item up by listing (which shows attributes, never
// secrets).
func findItem(ctx context.Context, cl *secretvault.Client, vault, item string) (bool, svrpc.Item, error) {
	entries, err := cl.List(ctx, vault, item)
	if err != nil {
		return false, svrpc.Item{}, err
	}
	for _, e := range entries {
		if e.Item.Name == item {
			return true, e.Item, nil
		}
	}
	return false, svrpc.Item{}, nil
}

// itemRecipient is the age recipient of the identity in an item: from its
// attribute when it has one, else worked out from the identity.
func (c *cli) itemRecipient(ctx context.Context, cl *secretvault.Client, r ref) (string, error) {
	found, it, err := findItem(ctx, cl, r.vault, r.item)
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("%s: %w", r.item, svrpc.ErrNotFound)
	}
	if rc := it.Attrs[ageRecipientName]; rc != "" && r.field == "" {
		return rc, nil
	}
	id, err := loadIdentity(ctx, cl, r)
	if err != nil {
		return "", err
	}
	switch id := id.(type) {
	case *svage.X25519Identity:
		return id.Recipient().String(), nil
	case *svage.HybridIdentity:
		return id.Recipient().String(), nil
	}
	return "", fmt.Errorf("%s does not hold an age identity", r.item)
}

// loadIdentity reads the age identity in an item (its age_identity
// field, or r.field), wiping the item once it is parsed.
func loadIdentity(ctx context.Context, cl *secretvault.Client, r ref) (svage.Identity, error) {
	e, err := cl.Get(ctx, r.vault, r.item)
	if err != nil {
		return nil, err
	}
	defer wipe(&e.Item)
	name := r.field
	if name == "" {
		name = ageIdentityField
	}
	f, ok := field(&e.Item, name)
	if !ok {
		return nil, fmt.Errorf("%s has no field %q (make one with 'secretvault age keygen')", r.item, name)
	}
	id, err := svage.ParseIdentityBytes(f.Value)
	if err != nil {
		return nil, fmt.Errorf("%s: field %q: %w", r.item, name, err)
	}
	return id, nil
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
	r, err := c.ageItem(pos[0])
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	rcpt, err := c.itemRecipient(ctx, cl, r)
	if err != nil {
		return err
	}
	if !asPlugin {
		fmt.Fprintln(c.stdout, rcpt)
		return nil
	}
	vault, err := vaultName(ctx, cl, r.vault)
	if err != nil {
		return err
	}
	s, err := pluginIdentity(vault, r.item)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.stdout, s)
	return nil
}

// vaultIdentity is an age identity kept in a vault item. It is fetched
// through the daemon, which asks the person as it always does, the first
// time a stanza it could open turns up, and kept for the rest of the run.
type vaultIdentity struct {
	c  *cli
	u  *unlockFlags // nil in the plugin, which presents no keys
	r  ref
	id svage.Identity
}

func (v *vaultIdentity) Unwrap(stanzas []*svage.Stanza) ([]byte, error) {
	if v.id == nil {
		native := false
		for _, s := range stanzas {
			native = native || s.Type == "X25519" || s.Type == "mlkem768x25519"
		}
		if !native {
			// Not worth asking anyone about.
			return nil, fmt.Errorf("%w: the file has no X25519 or post-quantum stanza", svage.ErrIncorrectIdentity)
		}
		cl, err := v.c.open(v.u)
		if err != nil {
			return nil, err
		}
		ctx, cancel := v.c.ctx()
		defer cancel()
		if v.id, err = loadIdentity(ctx, cl, v.r); err != nil {
			return nil, fmt.Errorf("sv://%s/%s: %s", v.r.vault, v.r.item, describe(err))
		}
	}
	return v.id.Unwrap(stanzas)
}

// askedPassphrase is the identity used when none is given: a passphrase,
// asked for on the terminal if the file turns out to be encrypted to one.
type askedPassphrase struct{ c *cli }

func (a askedPassphrase) Unwrap(stanzas []*svage.Stanza) ([]byte, error) {
	if len(stanzas) != 1 || stanzas[0].Type != "scrypt" {
		return nil, fmt.Errorf("%w: the file is not encrypted to a passphrase; give an identity with -i", svage.ErrIncorrectIdentity)
	}
	if !a.c.canAsk {
		return nil, errors.New("the file is encrypted to a passphrase, and there is no terminal to ask for it on")
	}
	p, err := a.c.ask("Passphrase: ")
	if err != nil {
		return nil, err
	}
	defer clear(p)
	id, err := svage.NewScryptIdentity(p)
	if err != nil {
		return nil, err
	}
	defer id.Wipe()
	return id.Unwrap(stanzas)
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
	arg = strings.TrimSpace(arg)
	if strings.HasPrefix(arg, "sv://") {
		r, err := parseRef(arg)
		if err != nil {
			return nil, err
		}
		cl, err := c.open(u)
		if err != nil {
			return nil, err
		}
		rc, err := c.itemRecipient(ctx, cl, r)
		if err != nil {
			return nil, err
		}
		arg = rc
	}
	if strings.HasPrefix(arg, "AGE-") {
		return nil, errors.New("that is an identity (a secret key), not a recipient")
	}
	r, err := svage.ParseRecipient(arg)
	if err != nil {
		return nil, err
	}
	if _, ok := r.(*svage.PluginRecipient); ok {
		// Another plugin's: let it talk to the person here.
		pr, err := svage.NewPluginRecipient(arg, c.pluginUI())
		if err != nil {
			return nil, err
		}
		return pr, nil
	}
	return r, nil
}

// eachKeyLine calls f for each line of a key file that is not blank or a
// "#" comment, numbering lines from 1.
func eachKeyLine(b []byte, f func(n int, line []byte) error) error {
	for n, line := range bytes.Split(b, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if err := f(n+1, line); err != nil {
			return err
		}
	}
	return nil
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
		err = eachKeyLine(b, func(n int, line []byte) error {
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
	dst, aw := out.w, io.WriteCloser(nil)
	if *armor {
		aw = svage.NewArmorWriter(dst)
		dst = aw
	}
	w, err := svage.Options{AllowMixedPostQuantum: *mixed}.Encrypt(dst, recipients...)
	if err != nil {
		return err
	}
	if _, err := io.Copy(w, in); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	if aw != nil {
		if err := aw.Close(); err != nil {
			return err
		}
	}
	return out.commit()
}

// ageIdentities reads a -i argument: sv://VAULT/ITEM[#FIELD], or a file
// of identities (age's, plugins', ours) or an SSH private key.
func (c *cli) ageIdentities(u *unlockFlags, arg string) ([]svage.Identity, error) {
	if strings.HasPrefix(arg, "sv://") {
		r, err := parseRef(arg)
		if err != nil {
			return nil, err
		}
		return []svage.Identity{&vaultIdentity{c: c, u: u, r: r}}, nil
	}
	b, err := os.ReadFile(arg)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	if bytes.Contains(b, []byte("PRIVATE KEY-----")) {
		id, err := svage.ParseSSHIdentity(b, func() ([]byte, error) {
			if !c.canAsk {
				return nil, errors.New("no terminal to ask for it on")
			}
			return c.ask("Passphrase for " + arg + ": ")
		})
		if err != nil {
			return nil, fmt.Errorf("%s: %w", arg, err)
		}
		return []svage.Identity{id}, nil
	}
	var ids []svage.Identity
	err = eachKeyLine(b, func(n int, line []byte) error {
		var id svage.Identity
		var err error
		switch {
		case bytes.HasPrefix(line, []byte("AGE-PLUGIN-")):
			var name string
			var data []byte
			if name, data, err = svage.ParsePluginIdentity(string(line)); err != nil {
				break
			}
			if name == agePluginName {
				// Ours: straight to the daemon, no plugin process.
				var r ref
				if r, err = itemOfPluginIdentity(data); err == nil {
					id = &vaultIdentity{c: c, u: u, r: r}
				}
			} else {
				id, err = svage.NewPluginIdentity(string(line), c.pluginUI())
			}
		default:
			id, err = svage.ParseIdentityBytes(line)
		}
		if err != nil {
			return fmt.Errorf("%s:%d: %w", arg, n, err)
		}
		ids = append(ids, id)
		return nil
	})
	if err == nil && len(ids) == 0 {
		err = fmt.Errorf("%s holds no identities", arg)
	}
	return ids, err
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
		ids = append(ids, askedPassphrase{c})
	}
	in, closeIn, err := c.input(pos)
	if err != nil {
		return err
	}
	defer closeIn()
	br := bufio.NewReader(in)
	var src io.Reader = br
	if peek, _ := br.Peek(2048); svage.IsArmored(peek) {
		src = svage.NewArmorReader(br)
	}
	r, err := svage.Decrypt(src, ids...)
	var nm *svage.NoIdentityMatchError
	if errors.As(err, &nm) {
		msg := "no identity given can open this file"
		if len(nm.Errors) == 1 {
			// With one identity, say what it said ("wrong passphrase", say).
			prefix := svage.ErrIncorrectIdentity.Error() + ": "
			if why, ok := strings.CutPrefix(nm.Errors[0].Error(), prefix); ok {
				msg = why
			}
		}
		return fmt.Errorf("%s (it is encrypted to: %s)", msg, strings.Join(nm.StanzaTypes, ", "))
	}
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
// appears only when the whole result is written (so a failed decryption
// leaves neither part of the plaintext nor a clobbered file).
type outFile struct {
	w      io.Writer
	c      *cli
	f      *os.File
	path   string
	closed bool
}

func (c *cli) output(path string, mode os.FileMode) (*outFile, error) {
	if path == "" || path == "-" {
		return &outFile{w: c.stdout, c: c, closed: true}, nil
	}
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return &outFile{w: f, c: c, f: f, path: path}, nil
}

// terminal reports whether the output is stdout on a terminal.
func (o *outFile) terminal() bool {
	f, ok := o.c.stdout.(*os.File)
	return o.f == nil && ok && term.IsTerminal(int(f.Fd()))
}

func (o *outFile) commit() error {
	if o.closed {
		return nil
	}
	o.closed = true
	if err := o.f.Close(); err != nil {
		os.Remove(o.f.Name())
		return err
	}
	if err := os.Rename(o.f.Name(), o.path); err != nil {
		os.Remove(o.f.Name())
		return err
	}
	return nil
}

func (o *outFile) abort() {
	if !o.closed {
		o.closed = true
		o.f.Close()
		os.Remove(o.f.Name())
	}
}
