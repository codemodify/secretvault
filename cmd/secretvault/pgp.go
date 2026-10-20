package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Your own OpenPGP keys, kept in vault items of kind "key":
//
//	secretvault pgp ls
//	secretvault pgp new --name NAME --email ADDRESS [--email ADDRESS]... [--v4] [--item ITEM] [--expires DAYS]
//	secretvault pgp import FILE [--item ITEM] [--key-passphrase-file F]
//	secretvault pgp export [KEY] [--secret [--unprotected] [--new-passphrase-file F]] [-o FILE]
//	secretvault pgp pub [KEY]
//	secretvault pgp sign [--key KEY] [--inline|--clear] [-a] [--text] [-o OUT] [IN]
//	secretvault pgp decrypt [--key KEY] [--verify] [--from ADDRESS] [-o OUT] [IN]
//	secretvault pgp verify [--signature FILE] [--from ADDRESS] [IN]
//	secretvault pgp gpg-setup [--gnupghome DIR] [--dry-run] [--remove] [--gpg PATH]
//
// KEY is the item's name, the key's fingerprint or key ID, or one of its
// addresses; it may be left out when the vault holds one key. new makes
// the key inside the daemon (version 6 by default, which GnuPG 2.4 does
// not read; --v4 for one it does). sign and decrypt happen in the daemon
// too: the secret key never reaches this program. export --secret does
// take it out, protected with a new passphrase unless --unprotected.
// gpg-setup points a GnuPG home at the daemon's gpg-agent face, so that
// gpg itself signs and decrypts with the vault's keys (pgp_gnupg.go).

func (c *cli) cmdPGP(args []string) error {
	usage := func() error {
		fmt.Fprintln(c.stderr, "usage: secretvault pgp ls|new|import|export|pub|sign|decrypt|verify|gpg-setup [flags] [args]")
		fmt.Fprintln(c.stderr)
		fmt.Fprintln(c.stderr, "  ls                                    list your OpenPGP keys")
		fmt.Fprintln(c.stderr, "  new --name N --email E [--v4]         make a key (version 6, or 4 for GnuPG 2.4)")
		fmt.Fprintln(c.stderr, "  import FILE [--item ITEM]             take a secret key into the vault")
		fmt.Fprintln(c.stderr, "  export [KEY] [--secret] [-o FILE]     write the public key, or the secret key")
		fmt.Fprintln(c.stderr, "  pub [KEY]                             print the public key")
		fmt.Fprintln(c.stderr, "  sign [--key KEY] [--inline|--clear] [-a] [-o OUT] [IN]")
		fmt.Fprintln(c.stderr, "  decrypt [--key KEY] [--verify --from ADDRESS] [-o OUT] [IN]")
		fmt.Fprintln(c.stderr, "  verify [--signature FILE] [--from ADDRESS] [IN]   check a signature against your contacts")
		fmt.Fprintln(c.stderr, "  gpg-setup [--gnupghome DIR] [--dry-run] [--remove]  let gpg itself use the vault's keys")
		fmt.Fprintln(c.stderr)
		fmt.Fprintln(c.stderr, "KEY is an item name, a fingerprint or key ID, or an address; optional with one key.")
		return errUsage
	}
	if len(args) == 0 {
		return usage()
	}
	switch args[0] {
	case "ls", "list":
		return c.pgpList(args[1:])
	case "new":
		return c.pgpNew(args[1:])
	case "import":
		return c.pgpImport(args[1:])
	case "export":
		return c.pgpExport(args[1:], false)
	case "pub":
		return c.pgpExport(args[1:], true)
	case "sign":
		return c.pgpSign(args[1:])
	case "decrypt":
		return c.pgpDecrypt(args[1:])
	case "verify":
		return c.pgpVerify(args[1:])
	case "gpg-setup":
		return c.pgpGnuPGSetup(args[1:])
	case "-h", "--help", "help":
		usage()
		return nil
	}
	fmt.Fprintf(c.stderr, "secretvault pgp: unknown subcommand %q\n", args[0])
	return usage()
}

func (c *cli) pgpList(args []string) error {
	fs := c.flags("pgp ls")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, ""); err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	entries, err := cl.List(ctx, c.vault, "")
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	keys := svops.PGPKeyEntries(entries)
	for _, e := range keys {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", e.Item.Name, svops.GroupFingerprint(e.Item.Attrs[svrpc.PGPFingerprint]), e.Item.Attrs[svrpc.PGPUserID])
	}
	if len(keys) == 0 {
		fmt.Fprintln(c.stdout, "No OpenPGP keys; make one with 'secretvault pgp new'.")
		return nil
	}
	return tw.Flush()
}

func (c *cli) pgpNew(args []string) error {
	fs := c.flags("pgp new")
	name := fs.String("name", "", "your name, for the user ID")
	var emails multi
	fs.Var(&emails, "email", "your address (repeatable: a user ID each)")
	v4 := fs.Bool("v4", false, "make a version 4 key, which GnuPG 2.4 and older software read (default: version 6)")
	item := fs.String("item", "", "store it as `ITEM` (default: named for its address)")
	days := fs.Int("expires", 0, "expire after `DAYS` days (default: never)")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "--name NAME --email ADDRESS [--email ADDRESS]... [--v4] [--item ITEM] [--expires DAYS]"); err != nil {
		return err
	}
	if *name == "" && len(emails) == 0 {
		fmt.Fprintln(c.stderr, "usage: secretvault pgp new --name NAME --email ADDRESS [--email ADDRESS]... [--v4] [--item ITEM] [--expires DAYS]")
		return errUsage
	}
	p := svrpc.PGPGenerateParams{Vault: c.vault, Item: *item, Name: *name, Emails: emails, Version: 6, LifetimeDays: *days}
	if *v4 {
		p.Version = 4
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	k, err := cl.GeneratePGP(ctx, p)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Made a version %d OpenPGP key, stored as %s:\n", k.Version, k.Item)
	fmt.Fprintf(c.stdout, "  %s\n", svops.GroupFingerprint(k.Fingerprint))
	for _, uid := range k.UserIDs {
		fmt.Fprintf(c.stdout, "  %s\n", uid)
	}
	fmt.Fprintf(c.stdout, "Give people its public key ('secretvault pgp pub %s'), or show it with 'secretvault contact qr'.\n", k.Item)
	return nil
}

func (c *cli) pgpImport(args []string) error {
	fs := c.flags("pgp import")
	item := fs.String("item", "", "store it as `ITEM` (default: named for its address)")
	passFile := fs.String("key-passphrase-file", "", "the key's own passphrase, from `FILE` (default: asked, if it has one)")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "FILE [--item ITEM] [--key-passphrase-file F]")
	if err != nil {
		return err
	}
	data, err := c.readArg(pos[0])
	if err != nil {
		return err
	}
	defer clear(data)
	it, fp, err := svops.PGPImportItem(data, pos[0], *item, func() ([]byte, error) {
		switch {
		case *passFile != "":
			return svops.ReadSecretFile(*passFile)
		case c.canAsk:
			return c.ask("Passphrase of the key: ")
		}
		return nil, errors.New("the key is protected: give its passphrase with --key-passphrase-file")
	})
	if err != nil {
		return err
	}
	defer svops.Wipe(&it)
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if err := svops.StorePGPKey(ctx, cl, c.vault, &it, *item != ""); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Imported %s as %s.\n", svops.GroupFingerprint(fp), it.Name)
	return nil
}

// pgpExport writes a key's public key (pub, or export), or with --secret
// its secret key.
func (c *cli) pgpExport(args []string, pub bool) error {
	name := "pgp export"
	if pub {
		name = "pgp pub"
	}
	fs := c.flags(name)
	out := fs.String("o", "", "write to `FILE` (created 0600; default: stdout)")
	secret, unprotected, newPassFile := new(bool), new(bool), new(string)
	if !pub {
		secret = fs.Bool("secret", false, "export the secret key")
		unprotected = fs.Bool("unprotected", false, "with --secret: as it is in the vault, without protecting it with a new passphrase")
		newPassFile = fs.String("new-passphrase-file", "", "with --secret: protect it with the passphrase in `FILE` (default: asked)")
	}
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[KEY] [-o FILE]")
	if err != nil {
		return err
	}
	ref := ""
	if len(pos) == 1 {
		ref = pos[0]
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	k, err := cl.PGPPublicKey(ctx, c.vault, ref)
	if err != nil {
		return err
	}
	data := []byte(k.PublicKey)
	if *secret {
		e, err := cl.Get(ctx, c.vault, k.Item)
		if err != nil {
			return err
		}
		defer svops.Wipe(&e.Item)
		f, ok := svops.Field(&e.Item, svrpc.PGPSecretField)
		if !ok {
			return fmt.Errorf("%s has no secret key", k.Item)
		}
		data = f.Value
		if !*unprotected {
			if data, err = c.protectKey(&e.Item, *newPassFile); err != nil {
				return err
			}
			defer clear(data)
		} else if _, protected := svops.Field(&e.Item, svrpc.PGPPassField); protected {
			fmt.Fprintf(c.stderr, "The key is protected by the passphrase in its item's %q field.\n", svrpc.PGPPassField)
		}
	}
	o, err := c.output(*out, 0o600)
	if err != nil {
		return err
	}
	defer o.abort()
	if _, err := o.w.Write(data); err != nil {
		return err
	}
	return o.commit()
}

// protectKey returns an item's secret key protected with a new
// passphrase.
func (c *cli) protectKey(it *svrpc.Item, passFile string) ([]byte, error) {
	return svops.ProtectPGPKey(it, func() ([]byte, error) { return c.newPassphrase(passFile) })
}

func (c *cli) pgpSign(args []string) error {
	fs := c.flags("pgp sign")
	key := fs.String("key", "", "sign with `KEY` (default: your only key)")
	inline := fs.Bool("inline", false, "write the message with its signature (default: the signature only)")
	cleartext := fs.Bool("clear", false, "write the message as readable text with its signature (cleartext)")
	armor := fs.Bool("a", false, "armor the output")
	text := fs.Bool("text", false, "a text signature, which ignores line endings")
	out := fs.String("o", "", "write to `FILE` (default: stdout)")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[--key KEY] [--inline|--clear] [-a] [--text] [-o OUT] [IN]")
	if err != nil {
		return err
	}
	mode := svrpc.SignDetached
	switch {
	case *inline && *cleartext:
		return errors.New("--inline or --clear, not both")
	case *inline:
		mode = svrpc.SignInline
	case *cleartext:
		mode = svrpc.SignCleartext
	}
	in, done, err := c.input(pos)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(in)
	done()
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	res, err := cl.SignPGP(ctx, svrpc.PGPSignParams{Vault: c.vault, Key: *key, Data: data, Mode: mode, Armor: *armor, Text: *text})
	if err != nil {
		return err
	}
	o, err := c.output(*out, 0o644)
	if err != nil {
		return err
	}
	defer o.abort()
	if !*armor && mode != svrpc.SignCleartext && o.terminal() {
		return errors.New("the signature is binary: use -a, or -o FILE")
	}
	if _, err := o.w.Write(res.Signature); err != nil {
		return err
	}
	return o.commit()
}

func (c *cli) pgpDecrypt(args []string) error {
	fs := c.flags("pgp decrypt")
	key := fs.String("key", "", "decrypt with `KEY` (default: the key the message is for)")
	verify := fs.Bool("verify", false, "check the signatures inside against your contacts")
	from := fs.String("from", "", "with --verify: the address the message claims to be from")
	out := fs.String("o", "", "write to `FILE` (created 0600; default: stdout)")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[--key KEY] [--verify [--from ADDRESS]] [-o OUT] [IN]")
	if err != nil {
		return err
	}
	in, done, err := c.input(pos)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(in)
	done()
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	res, err := cl.DecryptPGP(ctx, svrpc.PGPDecryptParams{Vault: c.vault, Key: *key, Data: data, Verify: *verify || *from != "", From: *from})
	if err != nil {
		return err
	}
	defer clear(res.Body)
	for _, w := range res.Warnings {
		fmt.Fprintln(c.stderr, "warning:", w)
	}
	c.printSignatures(res.Signatures)
	o, err := c.output(*out, 0o600)
	if err != nil {
		return err
	}
	defer o.abort()
	if _, err := o.w.Write(res.Body); err != nil {
		return err
	}
	return o.commit()
}

// printSignatures tells what each signature is, on stderr.
func (c *cli) printSignatures(sigs []svrpc.PGPSignature) {
	for _, l := range svops.SignatureLines(sigs) {
		fmt.Fprintln(c.stderr, l)
	}
}

func (c *cli) pgpVerify(args []string) error {
	fs := c.flags("pgp verify")
	sigFile := fs.String("signature", "", "the detached signature, from `FILE` (default: IN is a signed message)")
	from := fs.String("from", "", "the address the message claims to be from")
	out := fs.String("o", "", "write a signed message's text to `FILE`")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[--signature FILE] [--from ADDRESS] [-o OUT] [IN]")
	if err != nil {
		return err
	}
	in, done, err := c.input(pos)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(in)
	done()
	if err != nil {
		return err
	}
	p := svrpc.PGPVerifyParams{Vault: c.vault, Data: data, From: *from}
	if *sigFile != "" {
		if p.Signature, err = os.ReadFile(*sigFile); err != nil {
			return err
		}
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	res, err := cl.VerifyPGP(ctx, p)
	if err != nil {
		return err
	}
	c.printSignatures(res.Signatures)
	if *out != "" && res.Body != nil {
		o, err := c.output(*out, 0o644)
		if err != nil {
			return err
		}
		defer o.abort()
		if _, err := o.w.Write(res.Body); err != nil {
			return err
		}
		if err := o.commit(); err != nil {
			return err
		}
	}
	valid := false
	for _, s := range res.Signatures {
		if s.Valid && s.Verdict != nil && s.Verdict.Trusted {
			return nil
		}
		valid = valid || s.Valid
	}
	if valid {
		return exitCode(3)
	}
	return errors.New("no valid signature")
}
