package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/codemodify/secretvault/svimport"
	"github.com/codemodify/secretvault/svrpc"
)

// Moving secrets in from other password managers, and out to KeePass and
// CXF files. The work is svimport's; here are the files, the prompts and
// the daemon.

// maxImportFile bounds the file an import reads into memory.
const maxImportFile = 256 << 20

func formatNames() string {
	var s []string
	for _, f := range svimport.Formats {
		s = append(s, string(f))
	}
	return strings.Join(s, ", ")
}

func (c *cli) cmdImport(args []string) error {
	fs := c.flags("import")
	prefix := fs.String("prefix", "", "put every item under `FOLDER`, like imported/keepass")
	dryRun := fs.Bool("dry-run", false, "list the names that would be created, and store nothing")
	overwrite := fs.Bool("overwrite", false, "replace items that already exist (default: skip them)")
	srcPass := fs.String("source-passphrase-file", "", "read the export's own passphrase from `FILE` instead of asking")
	srcKey := fs.String("source-keyfile", "", "the KeePass key file (`FILE`) that opens a KDBX export")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 2, 2, "FORMAT FILE [flags]\n\nFORMAT is auto (guess from the file), or one of: "+formatNames())
	if err != nil {
		return err
	}
	format, path := pos[0], pos[1]
	switch format {
	case "pass", "gopass":
		return errors.New("pass and gopass stores are encrypted with OpenPGP, which secretvault reads from milestone M5 on")
	}
	data, err := readImportFile(path)
	if err != nil {
		return err
	}
	defer clear(data)
	f := svimport.Format(format)
	if format == "auto" {
		var ok bool
		if f, ok = svimport.Detect(filepath.Base(path), data); !ok {
			return fmt.Errorf("cannot tell what kind of export %s is; name its format: %s", path, formatNames())
		}
		fmt.Fprintf(c.stderr, "Reading %s as %s.\n", path, f)
	}

	opts := svimport.Options{Prefix: *prefix}
	if *srcPass != "" {
		if opts.Passphrase, err = readSecretFile(*srcPass); err != nil {
			return err
		}
	}
	if *srcKey != "" {
		if opts.Keyfile, err = os.ReadFile(*srcKey); err != nil {
			return err
		}
	}
	defer func() { clear(opts.Passphrase); clear(opts.Keyfile) }()
	res, err := c.readExport(f, data, path, &opts, *srcPass != "")
	if err != nil {
		return err
	}
	defer res.Wipe()

	if *dryRun {
		for _, it := range res.Items {
			fmt.Fprintln(c.stdout, it.Name)
		}
		c.printWarnings(res.Warnings)
		fmt.Fprintf(c.stderr, "Dry run: %d items would be imported; nothing was stored.\n", len(res.Items))
		return nil
	}

	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	existing, err := cl.List(ctx, c.vault, *prefix)
	cancel()
	if err != nil {
		return err
	}
	exists := map[string]bool{}
	for _, e := range existing {
		exists[e.Item.Name] = true
	}
	warnings := res.Warnings
	imported, skipped := 0, 0
	for _, it := range res.Items {
		if exists[it.Name] && !*overwrite {
			skipped++
			warnings = append(warnings, it.Name+": already exists, skipped (--overwrite replaces it)")
			continue
		}
		ctx, cancel := c.ctx()
		_, err := cl.Put(ctx, c.vault, it)
		cancel()
		if err != nil {
			c.printWarnings(warnings)
			return fmt.Errorf("storing %s: %s (%d items were stored before it)", it.Name, describe(err), imported)
		}
		imported++
	}
	c.printWarnings(warnings)
	fmt.Fprintf(c.stdout, "Imported %d items, skipped %d, with %d warnings.\n", imported, skipped, len(warnings))
	return nil
}

// readExport imports, asking on the terminal for the export's passphrase
// when it needs one that was not given, up to three times.
func (c *cli) readExport(f svimport.Format, data []byte, path string, opts *svimport.Options, fromFile bool) (*svimport.Result, error) {
	for tries := 0; ; tries++ {
		res, err := svimport.Import(f, data, *opts)
		switch {
		case err == nil:
			return res, nil
		case fromFile || tries >= 3 || !(errors.Is(err, svimport.ErrPassphrase) || errors.Is(err, svimport.ErrWrongKey)):
			return nil, err
		case !c.canAsk:
			return nil, fmt.Errorf("%s is encrypted and there is no terminal to ask on; use --source-passphrase-file", path)
		case errors.Is(err, svimport.ErrWrongKey) && len(opts.Passphrase) > 0:
			fmt.Fprintf(c.stderr, "! That passphrase does not open %s.\n", filepath.Base(path))
		}
		clear(opts.Passphrase)
		p, err := c.ask("Passphrase for " + filepath.Base(path) + ": ")
		if err != nil || len(p) == 0 {
			return nil, errors.New("canceled")
		}
		opts.Passphrase = p
	}
}

func (c *cli) printWarnings(ws []string) {
	for _, w := range ws {
		fmt.Fprintln(c.stderr, "warning:", w)
	}
}

func readImportFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxImportFile+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxImportFile {
		clear(b)
		return nil, fmt.Errorf("%s is larger than %d MiB", path, maxImportFile>>20)
	}
	return b, nil
}

func (c *cli) cmdExport(args []string) error {
	fs := c.flags("export")
	prefix := fs.String("prefix", "", "export only the items whose names start with `PREFIX`")
	newPass := fs.String("new-passphrase-file", "", "kdbx: read the file's passphrase from `FILE` instead of asking")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 2, 2, "cxf|kdbx FILE [--prefix PREFIX]")
	if err != nil {
		return err
	}
	format, path := pos[0], pos[1]
	if format != "cxf" && format != "kdbx" {
		return fmt.Errorf("cannot export to %q: the formats are cxf and kdbx", format)
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists; export writes only new files", path)
	}
	// Ask for the new file's passphrase before talking to the daemon, so
	// its prompts and ours never interleave.
	var pass []byte
	if format == "kdbx" {
		if pass, err = c.newPassphrase(*newPass); err != nil {
			return err
		}
		defer clear(pass)
	}

	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	entries, err := cl.List(ctx, c.vault, *prefix)
	cancel()
	if err != nil {
		return err
	}
	items := make([]svrpc.Item, 0, len(entries))
	defer func() {
		for i := range items {
			wipe(&items[i])
		}
	}()
	for _, e := range entries {
		ctx, cancel := c.ctx()
		full, err := cl.Get(ctx, c.vault, e.Item.Name)
		cancel()
		if err != nil {
			return fmt.Errorf("reading %s: %s", e.Item.Name, describe(err))
		}
		c.warnConflicts(full)
		items = append(items, full.Item)
	}

	var buf bytes.Buffer
	defer func() { clear(buf.Bytes()) }()
	switch format {
	case "cxf":
		fmt.Fprintf(c.stderr, "warning: %s is not encrypted: anyone who can read it has every secret in it. "+
			"Import it where it is going, then delete it.\n", path)
		err = svimport.ExportCXF(items, &buf)
	case "kdbx":
		err = svimport.ExportKDBX(items, &buf, pass)
	}
	if err != nil {
		return err
	}
	if err := writeNew(path, buf.Bytes()); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Exported %d items to %s.\n", len(items), path)
	return nil
}
