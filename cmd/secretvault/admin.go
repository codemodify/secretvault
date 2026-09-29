package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

func (c *cli) cmdSlot(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	switch args[0] {
	case "list", "ls":
		return c.slotList(args[1:])
	case "add":
		return c.slotAdd(args[1:])
	case "rm", "remove":
		return c.slotRemove(args[1:])
	}
	fmt.Fprintf(c.stderr, "secretvault slot: unknown subcommand %q (list, add, rm)\n", args[0])
	return errUsage
}

func (c *cli) slotList(args []string) error {
	if _, err := parse(c.flags("slot list"), args, 0, 0, ""); err != nil {
		return err
	}
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	slots, err := cl.Slots(ctx, c.vault)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tTYPE\tLABEL\tCREATED\tDETAIL")
	for _, s := range slots {
		detail := s.Detail
		if s.Recipient != "" {
			detail = s.Recipient[:min(40, len(s.Recipient))] + "..."
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
	shares := fs.Int("split", 0, "recovery slots: print the key as `N` shares instead, to give to N people or places")
	threshold := fs.Int("threshold", 0, "recovery slots: how many of the shares it takes (default: a majority)")
	withPIN := fs.Bool("uv", false, "fido2 slots: the key's PIN is asked for with every touch (the default when the key has a PIN)")
	withoutPIN := fs.Bool("no-uv", false, "fido2 slots: a touch alone opens the vault, even if the key has a PIN")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 2, "passphrase | recovery [--split N --threshold K] | keyfile PATH | recipient RECIPIENT|FILE | fido2 [--uv|--no-uv]  [flags]")
	if err != nil {
		return err
	}
	if *shares != 0 || *threshold != 0 {
		if pos[0] != svformat.SlotRecovery {
			return errors.New("--split and --threshold are for recovery slots")
		}
		if *threshold == 0 {
			*threshold = *shares/2 + 1
		}
		if *shares < 2 || *shares > 255 || *threshold < 2 || *threshold > *shares {
			return fmt.Errorf("%d of %d shares: use 2 to 255 shares, and a threshold from 2 up to the number of shares", *threshold, *shares)
		}
		if *label == "" {
			*label = fmt.Sprintf("recovery key, %d of %d shares", *threshold, *shares)
		}
	}
	p := svrpc.SlotAddParams{Vault: c.vault, Type: pos[0], Label: *label}
	switch pos[0] {
	case svformat.SlotPassphrase, svformat.SlotRecovery, svformat.SlotFIDO2:
		if len(pos) != 1 {
			return fmt.Errorf("slot add %s takes no argument", pos[0])
		}
	case svformat.SlotKeyfile, svformat.SlotRecipient:
		if len(pos) != 2 {
			return fmt.Errorf("slot add %s needs an argument", pos[0])
		}
	default:
		return fmt.Errorf("unknown slot type %q (passphrase, recovery, keyfile, recipient, fido2)", pos[0])
	}
	if (*withPIN || *withoutPIN) && pos[0] != svformat.SlotFIDO2 {
		return errors.New("--uv and --no-uv are for fido2 slots")
	}
	switch {
	case *withPIN && *withoutPIN:
		return errors.New("--uv and --no-uv contradict each other")
	case *withPIN:
		p.UV = withPIN
	case *withoutPIN:
		no := false
		p.UV = &no
	}
	switch pos[0] {
	case svformat.SlotPassphrase:
		if p.Secret, err = c.newPassphrase(*newPassFile); err != nil {
			return err
		}
	case svformat.SlotKeyfile:
		if *create {
			if err := writeNew(pos[1], svcrypto.RandomBytes(64)); err != nil {
				return err
			}
		}
		if p.Secret, err = os.ReadFile(pos[1]); err != nil {
			return err
		}
	case svformat.SlotRecipient:
		r, err := recipientArg(pos[1])
		if err != nil {
			return err
		}
		p.Secret = []byte(r)
	}
	defer clear(p.Secret)
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	info, err := cl.AddSlot(ctx, p)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Added %s slot %s\n", info.Type, info.ID)
	if info.Type == svformat.SlotFIDO2 {
		fmt.Fprintf(c.stdout, "%s opens the vault with: %s. Try it with 'secretvault lock' and 'secretvault unlock --fido2'.\n", info.Label, info.Detail)
	}
	switch {
	case info.RecoveryKey != "" && *shares > 0:
		return c.printRecoveryShares(info.RecoveryKey, *shares, *threshold)
	case info.RecoveryKey != "":
		c.printRecoveryKey(info.RecoveryKey)
	}
	return nil
}

// printRecoveryShares splits a new recovery key into shares and prints
// them instead of it: the whole key is never shown.
func (c *cli) printRecoveryShares(text string, n, k int) error {
	rk, err := svformat.ParseRecoveryKey(text)
	if err != nil {
		return err
	}
	shares, err := svcrypto.SplitSecret(rk, n, k)
	clear(rk)
	if err != nil {
		return err
	}
	fmt.Fprintln(c.stdout)
	fmt.Fprintf(c.stdout, "The recovery key, as %d shares; any %d of them open the vault, fewer reveal nothing.\n", n, k)
	fmt.Fprintln(c.stdout, "Give each to a different person or place. They are shown only now.")
	for i, s := range shares {
		fmt.Fprintln(c.stdout)
		fmt.Fprintf(c.stdout, "  Share %d of %d:\n", i+1, n)
		fmt.Fprintln(c.stdout, "    "+svformat.EncodeRecoveryShare(s, k))
		clear(s)
	}
	fmt.Fprintln(c.stdout)
	fmt.Fprintf(c.stdout, "To open the vault with them: 'secretvault unlock --shares', then type any %d.\n", k)
	return nil
}

// cmdFIDO2 lists the security keys the daemon can see, and what each can
// do: the first thing to look at when a key does not work.
func (c *cli) cmdFIDO2(args []string) error {
	if len(args) > 0 && args[0] != "list" && args[0] != "ls" {
		fmt.Fprintf(c.stderr, "secretvault fido2: unknown subcommand %q (list)\n", args[0])
		return errUsage
	}
	if len(args) > 0 {
		args = args[1:]
	}
	if _, err := parse(c.flags("fido2 list"), args, 0, 0, ""); err != nil {
		return err
	}
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	keys, err := cl.SecurityKeys(ctx)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		fmt.Fprintln(c.stdout, "No security key is plugged in.")
		return nil
	}
	for i, k := range keys {
		if i > 0 {
			fmt.Fprintln(c.stdout)
		}
		fmt.Fprintf(c.stdout, "%s\n", k.Name)
		if k.Path != "" {
			fmt.Fprintf(c.stdout, "  device:      %s\n", k.Path)
		}
		if len(k.Versions) > 0 {
			fmt.Fprintf(c.stdout, "  speaks:      %s\n", strings.Join(k.Versions, ", "))
			fmt.Fprintf(c.stdout, "  model:       %s\n", k.AAGUID)
			pin := "cannot have one"
			switch k.PIN {
			case "set":
				pin = fmt.Sprintf("set, %d tries left", k.Retries)
			case "not set":
				pin = "not set"
			}
			fmt.Fprintf(c.stdout, "  PIN:         %s\n", pin)
			yes := map[bool]string{true: "yes", false: "no"}[k.HMACSecret]
			fmt.Fprintf(c.stdout, "  hmac-secret: %s\n", yes)
		}
		if k.Problem != "" {
			fmt.Fprintf(c.stdout, "  problem:     %s\n", k.Problem)
		}
	}
	return nil
}

func (c *cli) slotRemove(args []string) error {
	fs := c.flags("slot rm")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "ID")
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if err := cl.RemoveSlot(ctx, c.vault, pos[0]); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Removed slot %s\n", pos[0])
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
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	// Prove it is you (and unlock) before asking for the new passphrase.
	ctx, cancel := c.ctx()
	defer cancel()
	if !u.given() {
		if _, err := cl.Unlock(ctx, c.vault, nil); err != nil {
			return err
		}
	}
	p, err := c.newPassphrase(*newPassFile)
	if err != nil {
		return err
	}
	defer clear(p)
	info, err := cl.Passwd(ctx, c.vault, p)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Passphrase changed (slot %s)\n", info.ID)
	return nil
}

func (c *cli) cmdGrant(args []string) error {
	if len(args) == 0 {
		args = []string{"list"}
	}
	fs := c.flags("grant " + args[0])
	var u unlockFlags
	u.register(fs)
	switch args[0] {
	case "list", "ls":
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		grants, err := cl.Grants(ctx, c.vault)
		if err != nil {
			return err
		}
		if len(grants) == 0 {
			fmt.Fprintln(c.stdout, "No program has a remembered decision about this vault.")
			return nil
		}
		tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "ID\tDECISION\tPROGRAM\tITEM\tOPS\tSINCE")
		for _, g := range grants {
			item := g.Item
			if item == "" {
				item = "(whole vault)"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n", g.ID, g.Decision, g.Program, item, strings.Join(g.Ops, ","), g.Created.Local().Format("2006-01-02 15:04"))
		}
		return tw.Flush()
	case "allow", "deny":
		itemName := fs.String("item", "", "only this item (default: the whole vault)")
		contacts := fs.Bool("contacts", false, "the vault's contacts, instead of an item (ops read, write)")
		ops := fs.String("ops", "read", "operations, comma-separated: read, list, write, delete, manage, sign, decrypt")
		untilLock := fs.Bool("until-lock", false, "only until the vault next locks (default: always)")
		pos, err := parse(fs, args[1:], 1, 1, "PROGRAM [--item NAME | --contacts] [--ops read,list] [--until-lock]   (PROGRAM: a path, flatpak:APP or snap:NAME)")
		if err != nil {
			return err
		}
		decision := "allow-always"
		switch {
		case args[0] == "deny":
			decision = "deny-always"
		case *untilLock:
			decision = "allow-until-lock"
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		g, err := cl.Grant(ctx, svrpc.GrantAddParams{Vault: c.vault, Program: pos[0], Item: *itemName, Contacts: *contacts, Ops: strings.Split(*ops, ","), Decision: decision})
		if err != nil {
			return err
		}
		what := "the whole vault"
		if g.Item != "" {
			what = fmt.Sprintf("%q", g.Item)
		}
		fmt.Fprintf(c.stdout, "%s: %s may %s %s\n", g.Decision, g.Program, strings.Join(g.Ops, ","), what)
		return nil
	case "revoke", "rm":
		pos, err := parse(fs, args[1:], 1, 1, "ID")
		if err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		return cl.Revoke(ctx, c.vault, pos[0])
	}
	fmt.Fprintf(c.stderr, "secretvault grant: unknown subcommand %q (list, allow, deny, revoke)\n", args[0])
	return errUsage
}

func (c *cli) cmdAudit(args []string) error {
	fs := c.flags("audit")
	limit := fs.Int("limit", 50, "show the newest `N` entries (0 for all)")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "[--limit N]"); err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	entries, err := cl.Audit(ctx, c.vault, *limit)
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	for _, e := range entries {
		if e.Outcome == "log-damaged" {
			fmt.Fprintln(tw, "!! "+e.Reason)
			continue
		}
		fmt.Fprintf(tw, "%s\t%s\t%s %s\t%s\t%s\n", e.Time.Local().Format("2006-01-02 15:04:05"), e.Outcome, e.Op, e.Item, e.Program, e.Reason)
	}
	return tw.Flush()
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
		pos, err := parse(c.flags("identity pub"), args[1:], 1, 1, "FILE")
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

func (c *cli) cmdVerify(args []string) error {
	fs := c.flags("verify")
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
	rep, err := cl.Verify(ctx, c.vault)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "%d items (%d objects, %d revisions) authenticated\n", rep.Live, rep.Objects, rep.Revisions)
	for _, p := range rep.Problems {
		fmt.Fprintf(c.stdout, "problem: %s\n", p)
	}
	for _, conflict := range rep.Conflicts {
		fmt.Fprintf(c.stdout, "conflict: %s\n", conflict)
	}
	for _, name := range sortedKeys(rep.Duplicates) {
		fmt.Fprintf(c.stdout, "duplicate: %d items are named %s\n", len(rep.Duplicates[name]), name)
	}
	if len(rep.Problems)+len(rep.Conflicts)+len(rep.Duplicates) > 0 {
		return errors.New("the vault needs attention")
	}
	return nil
}
