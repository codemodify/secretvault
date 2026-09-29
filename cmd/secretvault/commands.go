package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svprompt"
	"github.com/codemodify/secretvault/svstore"
)

// dir is the vault directory this invocation works on.
func (c *cli) dir() (string, error) {
	if c.vaultDir != "" {
		return c.vaultDir, nil
	}
	if d := os.Getenv(EnvVault); d != "" {
		return d, nil
	}
	return svcore.VaultDir("default")
}

func (c *cli) options() svcore.Options {
	var opts svcore.Options
	if home, err := svcore.Home(); err == nil {
		opts.Device, _ = svcore.Device(home)
	}
	return opts
}

// unlockFlags choose the key a command unlocks with.
type unlockFlags struct {
	passFile string
	keyfile  string
	identity string
	recovery bool
}

func (u *unlockFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&u.passFile, "passphrase-file", "", "read the passphrase from `FILE` instead of asking")
	fs.StringVar(&u.keyfile, "keyfile", "", "unlock with the keyfile at `PATH`")
	fs.StringVar(&u.identity, "identity", "", "unlock with the identity in `FILE`")
	fs.BoolVar(&u.recovery, "recovery", false, "unlock with a recovery key (asked for on the terminal)")
}

// openStore returns the backend of an existing vault.
func (c *cli) openStore() (string, svstore.Backend, error) {
	dir, err := c.dir()
	if err != nil {
		return "", nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, svformat.DescriptorName)); errors.Is(err, fs.ErrNotExist) {
		return dir, nil, fmt.Errorf("there is no vault at %s (create one with 'secretvault init')", dir)
	}
	store, err := svstore.OpenDir(dir)
	return dir, store, err
}

// open opens and unlocks the vault. The caller locks it when done.
func (c *cli) open(u *unlockFlags) (*svcore.Vault, error) {
	dir, store, err := c.openStore()
	if err != nil {
		return nil, err
	}
	v, err := svcore.Open(store, c.options())
	if err != nil {
		return nil, err
	}
	key, wipe, err := c.key(u, dir)
	if errors.Is(err, svprompt.ErrNoTerminal) {
		return nil, errors.New("no terminal to ask for the passphrase on; use --passphrase-file, --keyfile, --identity or --recovery")
	}
	if err != nil {
		return nil, err
	}
	defer wipe()
	if err := v.Unlock(key); err != nil {
		if errors.Is(err, svcore.ErrWrongKey) {
			return nil, errors.New("that key does not open this vault")
		}
		return nil, err
	}
	return v, nil
}

func (c *cli) key(u *unlockFlags, dir string) (svcore.Key, func(), error) {
	switch {
	case u.keyfile != "":
		b, err := os.ReadFile(u.keyfile)
		return svcore.Keyfile(b), func() { clear(b) }, err
	case u.identity != "":
		id, err := readIdentity(u.identity)
		return svcore.IdentityKey(id), func() {}, err
	case u.recovery:
		text, err := c.ask("Recovery key: ")
		if err != nil {
			return nil, nil, err
		}
		defer clear(text)
		rk, err := svformat.ParseRecoveryKey(string(text))
		return svcore.RecoveryKey(rk), func() { clear(rk) }, err
	case u.passFile != "":
		p, err := readSecretFile(u.passFile)
		return svcore.Passphrase(p), func() { clear(p) }, err
	default:
		p, err := c.ask("Passphrase for " + dir + ": ")
		return svcore.Passphrase(p), func() { clear(p) }, err
	}
}

// readSecretFile reads a secret from a file, without its final newline.
func readSecretFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return trimNewline(b), nil
}

func trimNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

func readIdentity(path string) (*svcrypto.Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		suite, priv, err := svformat.ParseIdentity(line)
		if err != nil {
			return nil, err
		}
		defer clear(priv)
		return suite.ParseIdentity(priv)
	}
	return nil, fmt.Errorf("%s holds no identity", path)
}

// newPassphrase gets a new passphrase from a file or the terminal.
func (c *cli) newPassphrase(file string) ([]byte, error) {
	if file != "" {
		p, err := readSecretFile(file)
		if err == nil && len(p) < minPassphrase {
			return nil, fmt.Errorf("the passphrase is too short: use at least %d characters", minPassphrase)
		}
		return p, err
	}
	return c.askNew("New passphrase: ", minPassphrase)
}

func (c *cli) cmdInit(args []string) error {
	fs := c.flags("init")
	suiteName := fs.String("suite", "modern", "cipher suite: modern or nist")
	recovery := fs.Bool("recovery", false, "also make a recovery key, and print it once")
	passFile := fs.String("passphrase-file", "", "read the new passphrase from `FILE` instead of asking")
	if _, err := parse(fs, args, 0, 0, "[--suite modern|nist] [--recovery]"); err != nil {
		return err
	}
	suite, err := svcrypto.ParseSuite(*suiteName)
	if err != nil {
		return err
	}
	dir, err := c.dir()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(dir, svformat.DescriptorName)); err == nil {
		return fmt.Errorf("a vault already exists at %s", dir)
	}
	pass, err := c.newPassphrase(*passFile)
	if err != nil {
		return err
	}
	defer clear(pass)
	store, err := svstore.OpenDir(dir)
	if err != nil {
		return err
	}
	v, _, err := svcore.Create(store, suite, svcore.NewSlot{Type: svformat.SlotPassphrase, Label: "passphrase", Passphrase: pass}, c.options())
	if err != nil {
		return err
	}
	defer v.Lock()
	fmt.Fprintf(c.stdout, "Created vault %s (%s) at %s\n", v.ID(), suite, dir)
	if *recovery {
		info, err := v.AddSlot(svcore.NewSlot{Type: svformat.SlotRecovery, Label: "recovery key"})
		if err != nil {
			return err
		}
		c.printRecoveryKey(info.RecoveryKey)
	}
	return nil
}

func (c *cli) printRecoveryKey(rk string) {
	fmt.Fprintln(c.stdout)
	fmt.Fprintln(c.stdout, "Recovery key (write it down and keep it somewhere safe; it is shown only now):")
	fmt.Fprintln(c.stdout)
	fmt.Fprintln(c.stdout, "    "+rk)
	fmt.Fprintln(c.stdout)
	fmt.Fprintln(c.stdout, "It opens the vault on its own, like the passphrase: 'secretvault --recovery ...'.")
}

func (c *cli) cmdSet(args []string) error {
	fs := c.flags("set")
	kind := fs.String("kind", "password", "item kind: "+strings.Join(svcore.Kinds, ", "))
	label := fs.String("label", "", "a title for people")
	var attrs, tags, fields multi
	fs.Var(&attrs, "attr", "lookup attribute `key=value` (repeatable)")
	fs.Var(&tags, "tag", "a tag (repeatable)")
	fs.Var(&fields, "field", "a plain field `name=value` (repeatable)")
	secretField := fs.String("secret-field", "password", "the field the secret goes in")
	generate := fs.Int("generate", 0, "generate a secret of `N` characters and print it, instead of reading one")
	noSecret := fs.Bool("no-secret", false, "change only the other parts; leave the secret as it is")
	replace := fs.Bool("replace", false, "replace the whole item instead of updating the parts given")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "NAME [flags]   (the secret comes from stdin, or is asked for)")
	if err != nil {
		return err
	}
	name := pos[0]
	if err := svcore.CheckName(name); err != nil {
		return err
	}
	attrMap, err := keyValues("--attr", attrs)
	if err != nil {
		return err
	}
	fieldMap, err := keyValues("--field", fields)
	if err != nil {
		return err
	}
	set := map[string]bool{}
	fs.Visit(func(f *flag.Flag) { set[f.Name] = true })

	v, err := c.open(&u)
	if err != nil {
		return err
	}
	defer v.Lock()

	it := svcore.Item{Kind: *kind, Name: name}
	if e, err := v.Get(name); err == nil && !*replace {
		it = e.Item
		if set["kind"] {
			it.Kind = *kind
		}
	} else if err != nil && !errors.Is(err, svcore.ErrNotFound) {
		return err
	}
	if set["label"] {
		it.Label = *label
	}
	if len(attrMap) > 0 && it.Attrs == nil {
		it.Attrs = map[string]string{}
	}
	for k, val := range attrMap {
		it.Attrs[k] = val
	}
	for _, t := range tags {
		if !slices.Contains(it.Tags, t) {
			it.Tags = append(it.Tags, t)
		}
	}
	for _, k := range sortedKeys(fieldMap) {
		it.SetField(svcore.Field{Name: k, Type: svcore.FieldText, Value: []byte(fieldMap[k])})
	}

	var generated []byte
	if !*noSecret {
		var secret []byte
		switch {
		case *generate > 0:
			if secret, err = svcrypto.Password(*generate); err != nil {
				return err
			}
			generated = bytes.Clone(secret) // the item's copy is wiped below
		case !c.stdinIsTTY:
			b, err := io.ReadAll(c.stdin)
			if err != nil {
				return err
			}
			secret = trimNewline(b)
			if len(secret) == 0 {
				return errors.New("stdin held no secret (use --no-secret to change only the other parts)")
			}
		default:
			if secret, err = c.askNew("Secret for "+name+": ", 1); err != nil {
				return err
			}
		}
		it.SetField(svcore.Field{Name: *secretField, Type: svcore.FieldConcealed, Value: secret})
	}
	e, err := v.Put(it)
	it.Wipe()
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "Stored %s (revision %s)\n", name, e.Rev.Short())
	if generated != nil {
		fmt.Fprintf(c.stdout, "%s\n", generated)
		clear(generated)
	}
	return nil
}

// jsonItem is how --json prints an item.
type jsonItem struct {
	ID        string            `json:"id"`
	Rev       string            `json:"rev"`
	Time      time.Time         `json:"time"`
	Kind      string            `json:"kind"`
	Name      string            `json:"name"`
	Label     string            `json:"label,omitempty"`
	Attrs     map[string]string `json:"attrs,omitempty"`
	Tags      []string          `json:"tags,omitempty"`
	Fields    []jsonField       `json:"fields,omitempty"`
	Conflicts []string          `json:"conflicts,omitempty"`
}

type jsonField struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value,omitempty"`
	Base64 string `json:"value_base64,omitempty"`
}

func toJSON(e svcore.Entry) jsonItem {
	j := jsonItem{ID: e.ID.String(), Rev: e.Rev.String(), Time: e.Time, Kind: e.Item.Kind, Name: e.Item.Name,
		Label: e.Item.Label, Attrs: e.Item.Attrs, Tags: e.Item.Tags}
	for _, f := range e.Item.Fields {
		jf := jsonField{Name: f.Name, Type: f.Type}
		if utf8.Valid(f.Value) && f.Type != svcore.FieldBinary && f.Type != svcore.FieldKey {
			jf.Value = string(f.Value)
		} else {
			jf.Base64 = base64.StdEncoding.EncodeToString(f.Value)
		}
		j.Fields = append(j.Fields, jf)
	}
	for _, r := range e.Conflicts {
		j.Conflicts = append(j.Conflicts, r.String())
	}
	return j
}

func (c *cli) warnConflicts(e svcore.Entry) {
	if len(e.Conflicts) > 0 {
		fmt.Fprintf(c.stderr, "warning: %s has %d conflicting revision(s); showing the newest (see 'secretvault history %s')\n",
			e.Item.Name, len(e.Conflicts), e.Item.Name)
	}
}

func (c *cli) cmdGet(args []string) error {
	fs := c.flags("get")
	field := fs.String("field", "", "print this field instead of the secret")
	asJSON := fs.Bool("json", false, "print the whole item as JSON")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "NAME [--field NAME | --json]")
	if err != nil {
		return err
	}
	v, err := c.open(&u)
	if err != nil {
		return err
	}
	defer v.Lock()
	e, err := v.Get(pos[0])
	if err != nil {
		return err
	}
	defer e.Item.Wipe()
	c.warnConflicts(e)
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(toJSON(e))
	}
	var f svcore.Field
	var ok bool
	if *field != "" {
		if f, ok = e.Item.Field(*field); !ok {
			return fmt.Errorf("%s has no field %q", pos[0], *field)
		}
	} else if f, ok = e.Item.Secret(); !ok {
		return fmt.Errorf("%s has no secret field; use --field or --json", pos[0])
	}
	c.stdout.Write(f.Value)
	if !bytes.HasSuffix(f.Value, []byte("\n")) {
		fmt.Fprintln(c.stdout)
	}
	return nil
}

func (c *cli) cmdList(args []string) error {
	fs := c.flags("ls")
	long := fs.Bool("l", false, "long listing: kind, last change, revision")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[-l] [PREFIX]")
	if err != nil {
		return err
	}
	prefix := ""
	if len(pos) == 1 {
		prefix = pos[0]
	}
	v, err := c.open(&u)
	if err != nil {
		return err
	}
	defer v.Lock()
	entries, err := v.List(prefix)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	for _, e := range entries {
		mark := ""
		if len(e.Conflicts) > 0 {
			mark = "  (conflict)"
		}
		if *long {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s%s\n", e.Item.Name, e.Item.Kind, e.Time.Local().Format("2006-01-02 15:04"), e.Rev.Short(), mark)
		} else {
			fmt.Fprintf(tw, "%s%s\n", e.Item.Name, mark)
		}
		e.Item.Wipe()
	}
	return tw.Flush()
}

func (c *cli) cmdMove(args []string) error {
	fs := c.flags("mv")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 2, 2, "FROM TO")
	if err != nil {
		return err
	}
	v, err := c.open(&u)
	if err != nil {
		return err
	}
	defer v.Lock()
	_, err = v.Rename(pos[0], pos[1])
	return err
}

func (c *cli) cmdRemove(args []string) error {
	fs := c.flags("rm")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "NAME")
	if err != nil {
		return err
	}
	v, err := c.open(&u)
	if err != nil {
		return err
	}
	defer v.Lock()
	return v.Delete(pos[0])
}

func (c *cli) cmdHistory(args []string) error {
	fs := c.flags("history")
	show := fs.Bool("show", false, "also print each revision's secret")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "NAME [--show]")
	if err != nil {
		return err
	}
	v, err := c.open(&u)
	if err != nil {
		return err
	}
	defer v.Lock()
	cur, err := v.Get(pos[0])
	if err != nil {
		return err
	}
	cur.Item.Wipe()
	heads := map[svformat.RevID]bool{cur.Rev: true}
	for _, r := range cur.Conflicts {
		heads[r] = true
	}
	hist, err := v.History(pos[0])
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	for _, e := range hist {
		note := ""
		switch {
		case e.Rev == cur.Rev:
			note = "current"
		case heads[e.Rev]:
			note = "conflict"
		}
		if e.Deleted {
			note = strings.TrimSpace(note + " deleted")
		}
		device := "-"
		if !e.Device.IsZero() {
			device = e.Device.String()[:8]
		}
		line := fmt.Sprintf("%s\t%s\t%s\t%s", e.Time.Local().Format("2006-01-02 15:04:05"), e.Rev.Short(), device, note)
		if *show {
			if f, ok := e.Item.Secret(); ok {
				line += "\t" + string(f.Value)
			}
		}
		fmt.Fprintln(tw, line)
		e.Item.Wipe()
	}
	return tw.Flush()
}

func (c *cli) cmdGen(args []string) error {
	fs := c.flags("gen")
	n := fs.Int("length", 24, "number of characters")
	noSymbols := fs.Bool("no-symbols", false, "letters and digits only")
	if _, err := parse(fs, args, 0, 0, "[--length N] [--no-symbols]"); err != nil {
		return err
	}
	classes := []string{svcrypto.Lower, svcrypto.Upper, svcrypto.Digits, svcrypto.Symbols}
	if *noSymbols {
		classes = classes[:3]
	}
	p, err := svcrypto.Password(*n, classes...)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "%s\n", p)
	clear(p)
	return nil
}

func (c *cli) cmdSlot(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: secretvault slot list | add passphrase|recovery|keyfile|recipient | rm ID")
		return errUsage
	}
	switch args[0] {
	case "list", "ls":
		return c.slotList(args[1:])
	case "add":
		return c.slotAdd(args[1:])
	case "rm", "remove":
		return c.slotRemove(args[1:])
	}
	fmt.Fprintf(c.stderr, "secretvault slot: unknown subcommand %q\n", args[0])
	return errUsage
}

func (c *cli) slotList(args []string) error {
	fs := c.flags("slot list")
	if _, err := parse(fs, args, 0, 0, ""); err != nil {
		return err
	}
	_, store, err := c.openStore()
	if err != nil {
		return err
	}
	v, err := svcore.Open(store, svcore.Options{})
	if err != nil {
		return err
	}
	slots, err := v.Slots()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTYPE\tLABEL\tCREATED\tDETAIL")
	for _, s := range slots {
		detail := ""
		switch {
		case s.KDF != nil && s.KDF.Alg == svcrypto.Argon2id:
			mem := fmt.Sprintf("%dKiB", s.KDF.MemoryKiB)
			if s.KDF.MemoryKiB%1024 == 0 {
				mem = fmt.Sprintf("%dMiB", s.KDF.MemoryKiB/1024)
			}
			detail = fmt.Sprintf("argon2id t=%d m=%s p=%d", s.KDF.Time, mem, s.KDF.Threads)
		case s.KDF != nil:
			detail = fmt.Sprintf("%s i=%d", s.KDF.Alg, s.KDF.Iterations)
		case s.Recipient != nil:
			r := svformat.EncodeRecipient(v.Suite(), s.Recipient)
			detail = r[:40] + "..."
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", s.ID, s.Type, s.Label, s.Created.Local().Format("2006-01-02 15:04"), detail)
	}
	return tw.Flush()
}

func (c *cli) slotAdd(args []string) error {
	fs := c.flags("slot add")
	label := fs.String("label", "", "a name for the slot")
	newPassFile := fs.String("new-passphrase-file", "", "passphrase slots: read the new passphrase from `FILE`")
	create := fs.Bool("create", false, "keyfile slots: create the keyfile (64 random bytes, mode 0600)")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 2, "passphrase | recovery | keyfile PATH | recipient RECIPIENT|FILE  [flags]")
	if err != nil {
		return err
	}
	ns := svcore.NewSlot{Type: pos[0], Label: *label}
	var cleanup func()
	switch pos[0] {
	case svformat.SlotPassphrase, svformat.SlotRecovery:
		if len(pos) != 1 {
			return fmt.Errorf("slot add %s takes no argument", pos[0])
		}
	case svformat.SlotKeyfile, svformat.SlotRecipient:
		if len(pos) != 2 {
			return fmt.Errorf("slot add %s needs an argument", pos[0])
		}
	default:
		return fmt.Errorf("unknown slot type %q (passphrase, recovery, keyfile, recipient)", pos[0])
	}

	v, err := c.open(&u)
	if err != nil {
		return err
	}
	defer v.Lock()

	switch pos[0] {
	case svformat.SlotPassphrase:
		p, err := c.newPassphrase(*newPassFile)
		if err != nil {
			return err
		}
		ns.Passphrase, cleanup = p, func() { clear(p) }
	case svformat.SlotKeyfile:
		if *create {
			if err := writeNew(pos[1], svcrypto.RandomBytes(64)); err != nil {
				return err
			}
		}
		b, err := os.ReadFile(pos[1])
		if err != nil {
			return err
		}
		ns.Keyfile, cleanup = b, func() { clear(b) }
	case svformat.SlotRecipient:
		suite, pub, err := recipientArg(pos[1])
		if err != nil {
			return err
		}
		if suite != v.Suite() {
			return fmt.Errorf("that recipient is for %v; this vault uses %v", suite, v.Suite())
		}
		ns.Recipient = pub
	}
	if cleanup != nil {
		defer cleanup()
	}
	info, err := v.AddSlot(ns)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Added %s slot %s\n", info.Type, info.ID)
	if info.RecoveryKey != "" {
		c.printRecoveryKey(info.RecoveryKey)
	}
	return nil
}

// recipientArg reads a recipient given as text, as a file holding one, or
// as an identity file (whose public half is the recipient).
func recipientArg(arg string) (svcrypto.Suite, []byte, error) {
	if suite, pub, err := svformat.ParseRecipient(arg); err == nil {
		return suite, pub, nil
	}
	b, err := os.ReadFile(arg)
	if err != nil {
		return 0, nil, fmt.Errorf("%q is neither a recipient nor a readable file", arg)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if suite, pub, err := svformat.ParseRecipient(line); err == nil {
			return suite, pub, nil
		}
	}
	clear(b)
	id, err := readIdentity(arg)
	if err != nil {
		return 0, nil, fmt.Errorf("%s holds no recipient or identity", arg)
	}
	return id.Suite(), id.Recipient(), nil
}

func (c *cli) slotRemove(args []string) error {
	fs := c.flags("slot rm")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "ID")
	if err != nil {
		return err
	}
	id, err := svformat.ParseID(pos[0])
	if err != nil {
		return err
	}
	v, err := c.open(&u)
	if err != nil {
		return err
	}
	defer v.Lock()
	if err := v.RemoveSlot(id); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Removed slot %s\n", id)
	return nil
}

func (c *cli) cmdPasswd(args []string) error {
	fs := c.flags("passwd")
	newPassFile := fs.String("new-passphrase-file", "", "read the new passphrase from `FILE` instead of asking")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "[--new-passphrase-file FILE]"); err != nil {
		return err
	}
	v, err := c.open(&u)
	if err != nil {
		return err
	}
	defer v.Lock()
	p, err := c.newPassphrase(*newPassFile)
	if err != nil {
		return err
	}
	defer clear(p)
	old := v.UnlockedBy()
	info, err := v.AddSlot(svcore.NewSlot{Type: svformat.SlotPassphrase, Label: "passphrase", Passphrase: p})
	if err != nil {
		return err
	}
	// Retire the passphrase slot that was used, if a passphrase was used.
	slots, err := v.Slots()
	if err != nil {
		return err
	}
	for _, s := range slots {
		if s.ID == old && s.Type == svformat.SlotPassphrase {
			if err := v.RemoveSlot(old); err != nil {
				return err
			}
		}
	}
	fmt.Fprintf(c.stdout, "Passphrase changed (slot %s)\n", info.ID)
	return nil
}

func (c *cli) cmdIdentity(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, "usage: secretvault identity new --out FILE [--suite modern|nist] | pub FILE")
		return errUsage
	}
	switch args[0] {
	case "new":
		fs := c.flags("identity new")
		out := fs.String("out", "", "write the identity to `FILE` (created with mode 0600)")
		suiteName := fs.String("suite", "modern", "cipher suite: modern or nist")
		if _, err := parse(fs, args[1:], 0, 0, "--out FILE [--suite modern|nist]"); err != nil {
			return err
		}
		if *out == "" {
			return errors.New("identity new needs --out FILE")
		}
		suite, err := svcrypto.ParseSuite(*suiteName)
		if err != nil {
			return err
		}
		id, err := suite.NewIdentity()
		if err != nil {
			return err
		}
		priv, err := id.Bytes()
		if err != nil {
			return err
		}
		defer clear(priv)
		rcpt := svformat.EncodeRecipient(suite, id.Recipient())
		body := fmt.Sprintf("# secretvault identity, created %s\n# recipient: %s\n%s\n",
			time.Now().UTC().Format(time.RFC3339), rcpt, svformat.EncodeIdentity(suite, priv))
		if err := writeNew(*out, []byte(body)); err != nil {
			return err
		}
		fmt.Fprintln(c.stdout, rcpt)
		return nil
	case "pub":
		fs := c.flags("identity pub")
		pos, err := parse(fs, args[1:], 1, 1, "FILE")
		if err != nil {
			return err
		}
		id, err := readIdentity(pos[0])
		if err != nil {
			return err
		}
		fmt.Fprintln(c.stdout, svformat.EncodeRecipient(id.Suite(), id.Recipient()))
		return nil
	}
	fmt.Fprintf(c.stderr, "secretvault identity: unknown subcommand %q\n", args[0])
	return errUsage
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

func (c *cli) cmdVerify(args []string) error {
	fs := c.flags("verify")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, ""); err != nil {
		return err
	}
	v, err := c.open(&u)
	if err != nil {
		return err
	}
	defer v.Lock()
	rep, err := v.Verify()
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "%d items (%d objects, %d revisions) authenticated\n", rep.Live, rep.Objects, rep.Revisions)
	for _, p := range rep.Problems {
		fmt.Fprintf(c.stdout, "problem: %s: %v\n", p.Name, p.Err)
	}
	for _, e := range rep.Conflicts {
		fmt.Fprintf(c.stdout, "conflict: %s has %d competing revisions\n", e.Item.Name, 1+len(e.Conflicts))
		e.Item.Wipe()
	}
	for _, name := range sortedKeys(rep.Duplicates) {
		fmt.Fprintf(c.stdout, "duplicate: %d items are named %s\n", len(rep.Duplicates[name]), name)
	}
	if !rep.OK() {
		return errors.New("the vault needs attention")
	}
	return nil
}

func (c *cli) cmdVersion(args []string) error {
	if _, err := parse(c.flags("version"), args, 0, 0, ""); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "secretvault %s\n", secretvault.Version)
	return nil
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
