package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"
	"text/tabwriter"
	"time"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

func (c *cli) cmdSet(args []string) error {
	fs := c.flags("set")
	kind := fs.String("kind", "password", "item kind: "+strings.Join(svcore.Kinds, ", "))
	label := fs.String("label", "", "a title for people")
	var attrs, tags, fields multi
	fs.Var(&attrs, "attr", "lookup attribute `key=value` (repeatable)")
	fs.Var(&tags, "tag", "a tag (repeatable)")
	fs.Var(&fields, "field", "a plain field `name=value` (repeatable)")
	secretName := fs.String("secret-field", "password", "the field the secret goes in")
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

	// Read the secret before talking to the daemon, so a prompt for it
	// and a prompt from the daemon never interleave.
	var secret, generated []byte
	if !*noSecret {
		switch {
		case *generate > 0:
			if secret, err = svcrypto.Password(*generate); err != nil {
				return err
			}
			generated = bytes.Clone(secret)
		case !c.stdinIsTTY:
			b, err := io.ReadAll(c.stdin)
			if err != nil {
				return err
			}
			secret = svops.TrimNewline(b)
			if len(secret) == 0 {
				return errors.New("stdin held no secret (use --no-secret to change only the other parts)")
			}
		case c.canAsk:
			if secret, err = c.askNew("Secret for "+name+": ", 1); err != nil {
				return err
			}
		default:
			return errors.New("no secret on stdin and no terminal to ask on")
		}
	}
	defer clear(generated)

	cl, err := c.open(&u)
	if err != nil {
		clear(secret)
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	it := svrpc.Item{Kind: *kind, Name: name}
	if !*replace {
		if e, err := cl.Get(ctx, c.vault, name); err == nil {
			it = e.Item
			if set["kind"] {
				it.Kind = *kind
			}
		} else if !errors.Is(err, svrpc.ErrNotFound) {
			clear(secret)
			return err
		}
	}
	defer svops.Wipe(&it)
	if set["label"] {
		it.Label = *label
	}
	if len(attrMap) > 0 && it.Attrs == nil {
		it.Attrs = map[string]string{}
	}
	for k, v := range attrMap {
		it.Attrs[k] = v
	}
	for _, t := range tags {
		if !slices.Contains(it.Tags, t) {
			it.Tags = append(it.Tags, t)
		}
	}
	for _, k := range sortedKeys(fieldMap) {
		svops.SetField(&it, svrpc.Field{Name: k, Type: svcore.FieldText, Value: []byte(fieldMap[k])})
	}
	if secret != nil {
		svops.SetField(&it, svrpc.Field{Name: *secretName, Type: svcore.FieldConcealed, Value: secret})
	}
	e, err := cl.Put(ctx, c.vault, it)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "Stored %s (revision %s)\n", name, svops.Short(e.Rev))
	if generated != nil {
		fmt.Fprintf(c.stdout, "%s\n", generated)
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
	Files     []svrpc.FileInfo  `json:"files,omitempty"`
	Conflicts []string          `json:"conflicts,omitempty"`
	Signature *svrpc.Signature  `json:"signature,omitempty"`
}

type jsonField struct {
	Name   string `json:"name"`
	Type   string `json:"type"`
	Value  string `json:"value,omitempty"`
	Base64 string `json:"value_base64,omitempty"`
}

func toJSON(e svrpc.Entry) jsonItem {
	j := jsonItem{ID: e.ID, Rev: e.Rev, Time: e.Time, Kind: e.Item.Kind, Name: e.Item.Name,
		Label: e.Item.Label, Attrs: e.Item.Attrs, Tags: e.Item.Tags, Files: e.Item.Files, Conflicts: e.Conflicts}
	if e.Signature.Status != "" {
		j.Signature = &e.Signature
	}
	for _, f := range e.Item.Fields {
		jf := jsonField{Name: f.Name, Type: f.Type}
		if utf8.Valid(f.Value) && f.Type != svcore.FieldBinary && f.Type != svcore.FieldKey {
			jf.Value = string(f.Value)
		} else {
			jf.Base64 = base64.StdEncoding.EncodeToString(f.Value)
		}
		j.Fields = append(j.Fields, jf)
	}
	return j
}

func (c *cli) warnConflicts(e svrpc.Entry) {
	if len(e.Conflicts) > 0 {
		fmt.Fprintf(c.stderr, "warning: %s has %d conflicting revision(s); showing the newest (see 'secretvault history %s')\n",
			e.Item.Name, len(e.Conflicts), e.Item.Name)
	}
	if e.Signature.Status == svrpc.SigBad {
		fmt.Fprintf(c.stderr, "warning: the current revision of %s has a bad signature: someone who can open the vault changed it, posing as another device (see 'secretvault history %s')\n",
			e.Item.Name, e.Item.Name)
	}
}

func (c *cli) cmdGet(args []string) error {
	fs := c.flags("get")
	fieldName := fs.String("field", "", "print this field instead of the secret")
	asJSON := fs.Bool("json", false, "print the whole item as JSON")
	toClip := fs.Bool("clip", false, "copy to the clipboard instead of printing, cleared after --clip-seconds")
	clipSecs := fs.Int("clip-seconds", 30, "how long a --clip copy stays")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "NAME [--field NAME | --json]")
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	e, err := cl.Get(ctx, c.vault, pos[0])
	if err != nil {
		return err
	}
	defer svops.Wipe(&e.Item)
	c.warnConflicts(e)
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(toJSON(e))
	}
	var f svrpc.Field
	var ok bool
	if *fieldName != "" {
		if f, ok = svops.Field(&e.Item, *fieldName); !ok {
			return fmt.Errorf("%s has no field %q", pos[0], *fieldName)
		}
	} else if svops.IsPasskey(&e.Item) {
		return fmt.Errorf("%s is a passkey: its key signs you in inside secretvault, for the browser extension, and is not printed; --field rp_id and --field username give its site and account", pos[0])
	} else if f, ok = svops.SecretField(&e.Item); !ok {
		return fmt.Errorf("%s has no secret field; use --field or --json", pos[0])
	}
	if *toClip {
		backend, err := c.copySecret(f.Value, time.Duration(*clipSecs)*time.Second)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stderr, "Copied %s to the clipboard (%s); it clears in %ds.\n", pos[0], backend, *clipSecs)
		return nil
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
	deleted := fs.Bool("deleted", false, "list deleted items instead ('secretvault restore NAME' brings one back)")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 0, 1, "[-l] [--deleted] [PREFIX]")
	if err != nil {
		return err
	}
	prefix := ""
	if len(pos) == 1 {
		prefix = pos[0]
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if *deleted {
		del, err := cl.Deleted(ctx, c.vault, prefix)
		if err != nil {
			return err
		}
		tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
		for _, d := range del {
			fmt.Fprintf(tw, "%s\t%s\tdeleted %s\n", d.Name, d.Kind, d.Deleted.Local().Format("2006-01-02 15:04"))
		}
		return tw.Flush()
	}
	entries, err := cl.List(ctx, c.vault, prefix)
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
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s%s\n", e.Item.Name, e.Item.Kind, e.Time.Local().Format("2006-01-02 15:04"), svops.Short(e.Rev), mark)
		} else {
			fmt.Fprintf(tw, "%s%s\n", e.Item.Name, mark)
		}
	}
	return tw.Flush()
}

// cmdMove renames an item (mv FROM TO), or with --to moves items to
// another vault (cmdTransfer).
func (c *cli) cmdMove(args []string) error {
	if slices.ContainsFunc(args, func(a string) bool {
		return a == "--to" || a == "-to" || strings.HasPrefix(a, "--to=") || strings.HasPrefix(a, "-to=")
	}) {
		return c.cmdTransfer("mv", args, false)
	}
	fs := c.flags("mv")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 2, 2, "FROM TO, or --to VAULT NAME... | --to VAULT --all")
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	_, err = cl.Rename(ctx, c.vault, pos[0], pos[1])
	return err
}

// cmdCopy copies items to another vault.
func (c *cli) cmdCopy(args []string) error { return c.cmdTransfer("cp", args, true) }

// cmdTransfer moves (or copies) items to another vault, inside the
// daemon:
//
//	secretvault [--vault FROM] mv --to VAULT NAME... | --all
//	secretvault [--vault FROM] cp --to VAULT NAME... | --all
//
// --dry-run says what would go, and who else reads VAULT. Into a vault
// others read too (people's keys, emergency access, other devices, a
// sync server), the items go only with --yes: that shows them to every
// one of them.
func (c *cli) cmdTransfer(name string, args []string, copy bool) error {
	fs := c.flags(name)
	var u unlockFlags
	u.register(fs)
	to := fs.String("to", "", "the vault the items go to")
	all := fs.Bool("all", false, "every item of the vault, in place of names")
	dryRun := fs.Bool("dry-run", false, "say what would go, and who else reads the vault it goes to; change nothing")
	yes := fs.Bool("yes", false, "go ahead even when others read the vault the items go to")
	pos, err := parse(fs, args, 0, -1, "--to VAULT NAME... | --to VAULT --all [--dry-run] [--yes]")
	if err != nil {
		return err
	}
	if *to == "" || *all == (len(pos) > 0) {
		fmt.Fprintf(c.stderr, "usage: secretvault %s --to VAULT NAME... | --to VAULT --all [--dry-run] [--yes]\n", name)
		return errUsage
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	p := svrpc.MoveParams{Vault: c.vault, To: *to, Names: pos}
	if *all {
		p.Prefix = svrpc.PrefixOf("")
	}
	do := cl.MoveItems
	if copy {
		do = cl.CopyItems
	}

	// What would go, and who else reads the vault: shown with --dry-run,
	// and the reason for --yes. Without a terminal there is no plan: the
	// daemon asks the person on the desktop, naming both.
	plan := p
	plan.Plan = true
	pl, err := do(ctx, plan)
	switch {
	case errors.Is(err, svrpc.ErrDenied) && !c.canAsk:
		if *dryRun {
			return fmt.Errorf("--dry-run needs a terminal to ask on: %w", err)
		}
	case err != nil:
		return err
	case *dryRun:
		pp := svops.MovePlain(pl, copy)
		fmt.Fprintln(c.stdout, pp.Text())
		fmt.Fprintln(c.stdout)
		for _, n := range pp.Details {
			fmt.Fprintln(c.stdout, "  "+n)
		}
		return nil
	case pl.Readers.Anyone() && !*yes:
		return fmt.Errorf("%s Run it again with --yes to %s them there (--dry-run lists them)",
			svops.ReadersText(pl.To, pl.Readers), map[bool]string{false: "move", true: "copy"}[copy])
	default:
		// What goes is what the plan found, not whatever is in the vault
		// a moment later.
		p.Names, p.Prefix = pl.Items, nil
	}

	res, err := do(ctx, p)
	if err != nil {
		if len(res.Done)+len(res.Both)+len(res.NotDone) > 0 {
			fmt.Fprintln(c.stderr, svops.MovedText(res, copy))
		}
		return err
	}
	fmt.Fprintln(c.stdout, svops.MovedText(res, copy))
	return nil
}

func (c *cli) cmdRemove(args []string) error {
	fs := c.flags("rm")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "NAME")
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	return cl.Delete(ctx, c.vault, pos[0])
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
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	cur, err := cl.Get(ctx, c.vault, pos[0])
	if err != nil {
		return err
	}
	svops.Wipe(&cur.Item)
	heads := map[string]bool{cur.Rev: true}
	for _, r := range cur.Conflicts {
		heads[r] = true
	}
	hist, err := cl.History(ctx, c.vault, pos[0])
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
		if e.Ignored {
			note = strings.TrimSpace(note + " ignored: the vault requires signatures")
		}
		line := fmt.Sprintf("%s\t%s\t%s\t%s", e.Time.Local().Format("2006-01-02 15:04:05"), svops.Short(e.Rev), svops.Author(e), note)
		if *show {
			if f, ok := svops.SecretField(&e.Item); ok {
				line += "\t" + string(f.Value)
			}
		}
		fmt.Fprintln(tw, line)
		svops.Wipe(&e.Item)
	}
	return tw.Flush()
}

func (c *cli) cmdGen(args []string) error {
	fs := c.flags("gen")
	n := fs.Int("length", 24, "number of characters")
	noSymbols := fs.Bool("no-symbols", false, "letters and digits only")
	toClip := fs.Bool("clip", false, "copy to the clipboard instead of printing (cleared after 30s)")
	if _, err := parse(fs, args, 0, 0, "[--length N] [--no-symbols] [--clip]"); err != nil {
		return err
	}
	p, err := svops.GeneratePassword(*n, !*noSymbols)
	if err != nil {
		return err
	}
	defer clear(p)
	if *toClip {
		backend, err := c.copySecret(p, 30*time.Second)
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stderr, "Copied a new password to the clipboard (%s); it clears in 30s.\n", backend)
		return nil
	}
	fmt.Fprintf(c.stdout, "%s\n", p)
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

// cmdRestore is `secretvault restore NAME [REV]`: an earlier revision (see
// history), or a deleted item's last contents, made current again.
func (c *cli) cmdRestore(args []string) error {
	fs := c.flags("restore")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 2, "NAME [REV]   (REV from 'secretvault history NAME'; none brings back a deleted item)")
	if err != nil {
		return err
	}
	rev := ""
	if len(pos) == 2 {
		rev = pos[1]
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	e, err := cl.Restore(ctx, svrpc.RestoreParams{Vault: c.vault, Name: pos[0], Rev: rev})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Restored %s (revision %s)\n", e.Item.Name, svops.Short(e.Rev))
	return nil
}

// cmdResolve is `secretvault resolve NAME [--keep REV]`: an item changed
// on two devices at once shows its versions, and keeps the one chosen.
func (c *cli) cmdResolve(args []string) error {
	fs := c.flags("resolve")
	keep := fs.String("keep", "", "keep this version (a revision from the list), on every device")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "NAME [--keep REV]")
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if *keep != "" {
		e, err := cl.Restore(ctx, svrpc.RestoreParams{Vault: c.vault, Name: pos[0], Rev: *keep})
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Kept that version of %s; the conflict is settled (revision %s).\n", e.Item.Name, svops.Short(e.Rev))
		return nil
	}
	con, err := svops.Conflicts(ctx, cl, c.vault, pos[0])
	if err != nil {
		return err
	}
	if len(con.Current.Conflicts) == 0 {
		fmt.Fprintf(c.stdout, "%s has no conflict.\n", pos[0])
		return nil
	}
	fmt.Fprintf(c.stdout, "%s was changed on two devices at once. Its versions:\n\n", pos[0])
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	for _, e := range con.Versions {
		note := ""
		if e.Rev == con.Current.Rev {
			note = "(shown now)"
		}
		device := "-"
		if e.Device != "" {
			device = e.Device[:8]
		}
		var fields []string
		for _, f := range e.Item.Fields {
			fields = append(fields, f.Name)
		}
		fmt.Fprintf(tw, "  %s\t%s\tdevice %s\tfields %s\t%s\n", svops.Short(e.Rev), e.Time.Local().Format("2006-01-02 15:04:05"), device, strings.Join(fields, ","), note)
		svops.Wipe(&e.Item)
	}
	tw.Flush()
	fmt.Fprintf(c.stdout, "\nSee each with 'secretvault history %s --show'; keep one with 'secretvault resolve %s --keep REV'.\n", pos[0], pos[0])
	return nil
}
