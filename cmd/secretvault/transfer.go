package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"text/tabwriter"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svimport"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Moving secrets in from other password managers, and out to KeePass and
// CXF files. The work is svimport's and svops' (transfer.go); here are
// the flags, the prompts and the printing.

// importUsage is import's usage, after "secretvault import".
const importUsage = `SOURCE|FORMAT FILE [flags]
       secretvault import SOURCE     how to make SOURCE's export
       secretvault import sources    the programs to import from

SOURCE is where the passwords are now: `

func (c *cli) cmdImport(args []string) error {
	if len(args) > 0 && args[0] == "sources" {
		return c.importSources(args[1:])
	}
	fs := c.flags("import")
	dryRun := fs.Bool("dry-run", false, "list the names that would be created, and store nothing")
	overwrite := fs.Bool("overwrite", false, "replace items that already exist (default: skip them)")
	srcPass := fs.String("source-passphrase-file", "", "read the export's own passphrase from `FILE` instead of asking")
	srcKey := fs.String("source-keyfile", "", "the KeePass key file (`FILE`) that opens a KDBX export")
	var u unlockFlags
	u.register(fs)
	usage := importUsage + svops.SourceNames() + " (secretvault import sources lists them).\n" +
		"FORMAT is auto (guess from the file), or one of: " + svops.FormatNames()
	pos, err := parse(fs, args, 1, 2, usage)
	if err != nil {
		return err
	}
	if len(pos) == 1 {
		src, ok := svops.FindImportSource(pos[0])
		if !ok {
			fmt.Fprintf(fs.Output(), "usage: secretvault import %s\n", usage)
			fs.PrintDefaults()
			return errUsage
		}
		c.printSourceSteps(src)
		return nil
	}
	format, path := pos[0], pos[1]
	if format == "pass" || format == "gopass" {
		_, _, err := svops.ImportFormat(format, path, nil)
		return err
	}
	data, err := svops.ReadImportFile(path)
	if err != nil {
		return err
	}
	defer clear(data)
	f, guessed, err := svops.ImportFormat(format, path, data)
	if err != nil {
		return err
	}
	if guessed {
		fmt.Fprintf(c.stderr, "Reading %s as %s.\n", path, f)
	}

	opts := svimport.Options{}
	if *srcPass != "" {
		if opts.Passphrase, err = svops.ReadSecretFile(*srcPass); err != nil {
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
	rep, err := svops.StoreImport(c.ctx, cl, res, svops.ImportOptions{Vault: c.vault, Overwrite: *overwrite, Describe: describe})
	if rep != nil {
		c.printWarnings(rep.Warnings)
	}
	if err != nil {
		return err
	}
	withFiles := ""
	if rep.Files > 0 {
		withFiles = fmt.Sprintf(" (%d files)", rep.Files)
	}
	fmt.Fprintf(c.stdout, "Imported %d items%s, skipped %d, with %d warnings.\n", rep.Imported, withFiles, rep.Skipped, len(rep.Warnings))
	if !res.Encrypted {
		fmt.Fprintf(c.stdout, "%s is not encrypted, and what it holds is in the vault now: delete it (%s).\n", path, deleteCommand(path))
	}
	return nil
}

// deleteCommand is how to delete the file at path in the system's shell:
// an ordinary delete, which is all RemoveExport does too.
func deleteCommand(path string) string {
	if runtime.GOOS == "windows" {
		return `del "` + path + `"`
	}
	return "rm -- " + svops.ShellQuote(path)
}

// importSources is 'secretvault import sources': the programs to import
// from (svops.ImportSources), and the names import takes for them.
func (c *cli) importSources(args []string) error {
	fs := c.flags("import sources")
	if _, err := parse(fs, args, 0, 0, ""); err != nil {
		return err
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "SOURCE\tFORMAT\tPROGRAM\tALSO")
	for _, s := range svops.ImportSources {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", s.Name, s.Format, s.Label, strings.Join(s.Aliases, ", "))
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	fmt.Fprintln(c.stderr, "'secretvault import SOURCE' says how to make its export; 'secretvault import SOURCE FILE' imports it.")
	return nil
}

// printSourceSteps is 'secretvault import SOURCE': how to make that
// program's export, and the command that imports it.
func (c *cli) printSourceSteps(s svops.ImportSource) {
	fmt.Fprintf(c.stdout, "To import from %s:\n\n", s.Label)
	for _, st := range s.NumberedSteps() {
		fmt.Fprintln(c.stdout, wrapText(st, 76, "  ", "     "))
	}
	if note := s.UnencryptedNote(); note != "" {
		fmt.Fprintln(c.stdout)
		fmt.Fprintln(c.stdout, wrapText(note, 76, "  ", "  "))
	}
	fmt.Fprintf(c.stdout, "\nThen import it:\n\n  secretvault import %s FILE\n\n", s.Name)
	var then string
	switch {
	case s.Keyfile:
		then = fmt.Sprintf("It asks for the %s; --source-keyfile FILE gives the key file, if you use one. ", strings.ToLower(s.Passphrase))
	case s.Passphrase != "":
		then = fmt.Sprintf("It asks for the %s if the file is encrypted. ", strings.ToLower(s.Passphrase))
	}
	fmt.Fprintln(c.stdout, wrapText(then+"--dry-run shows the names it would make, and stores nothing.", 76, "", ""))
}

// wrapText breaks text into lines of at most width runes, the first
// indented by first and the rest by rest.
func wrapText(text string, width int, first, rest string) string {
	var b strings.Builder
	line, indent := 0, first
	for i, w := range strings.Fields(text) {
		n := utf8.RuneCountInString(w)
		switch {
		case i == 0:
			b.WriteString(indent)
			line = utf8.RuneCountInString(indent)
		case line+1+n > width:
			b.WriteString("\n" + rest)
			line = utf8.RuneCountInString(rest)
		default:
			b.WriteByte(' ')
			line++
		}
		b.WriteString(w)
		line += n
	}
	return b.String()
}

// readExport imports, asking on the terminal for the export's passphrase
// when it needs one that was not given, up to three times.
func (c *cli) readExport(f svimport.Format, data []byte, path string, opts *svimport.Options, fromFile bool) (*svimport.Result, error) {
	for tries := 0; ; tries++ {
		res, err := svimport.Import(f, data, *opts)
		switch {
		case err == nil:
			return res, nil
		case fromFile || tries >= 3 || !svops.NeedsPassphrase(err):
			return nil, err
		case !c.canAsk:
			return nil, fmt.Errorf("%s is encrypted and there is no terminal to ask on; use --source-passphrase-file", path)
		case svops.WrongPassphrase(err) && len(opts.Passphrase) > 0:
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

func (c *cli) cmdExport(args []string) error {
	fs := c.flags("export")
	newPass := fs.String("new-passphrase-file", "", "kdbx: read the file's passphrase from `FILE` instead of asking")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 2, 2, "cxf|kdbx FILE")
	if err != nil {
		return err
	}
	format, path := pos[0], pos[1]
	if err := svops.CheckExport(format, path); err != nil {
		return err
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
	items, err := svops.ReadForExport(c.ctx, cl, svops.ExportOptions{Vault: c.vault, Describe: describe,
		Each: func(e svrpc.Entry) { c.warnConflicts(e) }})
	if err != nil {
		return err
	}
	defer func() {
		for i := range items {
			svops.Wipe(&items[i])
		}
	}()
	if format == "cxf" {
		fmt.Fprintf(c.stderr, "warning: %s is not encrypted: anyone who can read it has every secret in it. "+
			"Import it where it is going, then delete it.\n", path)
	}
	out, err := svops.EncodeExport(format, items, pass)
	if err != nil {
		return err
	}
	defer clear(out)
	if err := svops.WriteNew(path, out); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Exported %d items to %s.\n", len(items), path)
	return nil
}
