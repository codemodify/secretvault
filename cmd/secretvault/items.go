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
	"github.com/codemodify/secretvault/svrpc"
)

func wipe(it *svrpc.Item) {
	for i := range it.Fields {
		clear(it.Fields[i].Value)
	}
}

func field(it *svrpc.Item, name string) (svrpc.Field, bool) {
	for _, f := range it.Fields {
		if f.Name == name {
			return f, true
		}
	}
	return svrpc.Field{}, false
}

// secretField is the item's primary secret, as svcore.Item.Secret picks it.
func secretField(it *svrpc.Item) (svrpc.Field, bool) {
	for _, n := range []string{"password", "secret"} {
		if f, ok := field(it, n); ok {
			return f, true
		}
	}
	for _, f := range it.Fields {
		if f.Type == svcore.FieldConcealed || f.Type == svcore.FieldKey {
			return f, true
		}
	}
	return svrpc.Field{}, false
}

func setField(it *svrpc.Item, f svrpc.Field) {
	for i := range it.Fields {
		if it.Fields[i].Name == f.Name {
			clear(it.Fields[i].Value)
			it.Fields[i] = f
			return
		}
	}
	it.Fields = append(it.Fields, f)
}

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
			secret = trimNewline(b)
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
	defer wipe(&it)
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
		setField(&it, svrpc.Field{Name: k, Type: svcore.FieldText, Value: []byte(fieldMap[k])})
	}
	if secret != nil {
		setField(&it, svrpc.Field{Name: *secretName, Type: svcore.FieldConcealed, Value: secret})
	}
	e, err := cl.Put(ctx, c.vault, it)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "Stored %s (revision %s)\n", name, short(e.Rev))
	if generated != nil {
		fmt.Fprintf(c.stdout, "%s\n", generated)
	}
	return nil
}

func short(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
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
	defer wipe(&e.Item)
	c.warnConflicts(e)
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(toJSON(e))
	}
	var f svrpc.Field
	var ok bool
	if *fieldName != "" {
		if f, ok = field(&e.Item, *fieldName); !ok {
			return fmt.Errorf("%s has no field %q", pos[0], *fieldName)
		}
	} else if f, ok = secretField(&e.Item); !ok {
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
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
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
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s%s\n", e.Item.Name, e.Item.Kind, e.Time.Local().Format("2006-01-02 15:04"), short(e.Rev), mark)
		} else {
			fmt.Fprintf(tw, "%s%s\n", e.Item.Name, mark)
		}
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
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	_, err = cl.Rename(ctx, c.vault, pos[0], pos[1])
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
	wipe(&cur.Item)
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
		device := "-"
		if len(e.Device) >= 8 {
			device = e.Device[:8]
		}
		line := fmt.Sprintf("%s\t%s\t%s\t%s", e.Time.Local().Format("2006-01-02 15:04:05"), short(e.Rev), device, note)
		if *show {
			if f, ok := secretField(&e.Item); ok {
				line += "\t" + string(f.Value)
			}
		}
		fmt.Fprintln(tw, line)
		wipe(&e.Item)
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
	classes := []string{svcrypto.Lower, svcrypto.Upper, svcrypto.Digits, svcrypto.Symbols}
	if *noSymbols {
		classes = classes[:3]
	}
	p, err := svcrypto.Password(*n, classes...)
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
