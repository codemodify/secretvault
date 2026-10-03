package svops

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"mime"
	"os"
	"path/filepath"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svimport"
	"github.com/codemodify/secretvault/svrpc"
)

// Moving secrets in from other password managers, and out to KeePass and
// CXF files. Reading and writing the formats is svimport's; here are the
// files, and storing what was read through the daemon.

// MaxImportFile bounds the file an import reads into memory.
const MaxImportFile = 256 << 20

// ExportFormats are the formats an export writes.
var ExportFormats = []string{"cxf", "kdbx"}

// FormatNames lists the formats an import reads, for people.
func FormatNames() string {
	var s []string
	for _, f := range svimport.Formats {
		s = append(s, string(f))
	}
	return strings.Join(s, ", ")
}

// ReadImportFile reads an export, of at most MaxImportFile bytes. The
// caller clears it.
func ReadImportFile(path string) ([]byte, error) { return ReadFileLimit(path, MaxImportFile) }

// ImportFormat is the format to read an export in: format itself, the
// format of the source it names (firefox: csv), or, for "auto", the one
// svimport recognises; guessed says it was guessed.
func ImportFormat(format, path string, data []byte) (f svimport.Format, guessed bool, err error) {
	if s, ok := FindImportSource(format); ok {
		return s.Format, false, nil
	}
	switch format {
	case "pass", "gopass":
		return "", false, errors.New("pass and gopass stores are encrypted with OpenPGP, which secretvault reads from milestone M5 on")
	case "auto":
		f, ok := svimport.Detect(filepath.Base(path), data)
		if !ok {
			return "", false, fmt.Errorf("cannot tell what kind of export %s is; name its format: %s", path, FormatNames())
		}
		return f, true, nil
	}
	return svimport.Format(format), false, nil
}

// NeedsPassphrase reports whether an import failed for want of the
// export's own passphrase (or for the wrong one), which a person can be
// asked for before trying again.
func NeedsPassphrase(err error) bool {
	return errors.Is(err, svimport.ErrPassphrase) || errors.Is(err, svimport.ErrWrongKey)
}

// WrongPassphrase reports whether the passphrase given did not open it.
func WrongPassphrase(err error) bool { return errors.Is(err, svimport.ErrWrongKey) }

// ImportOptions say how an import's items are stored.
type ImportOptions struct {
	Vault     string
	Prefix    string // the folder they were read under (svimport.Options.Prefix): what is listed to find those that exist
	Overwrite bool   // replace items that exist (else they are skipped)
	// Describe says an error in words, in the warnings (err.Error() when
	// nil).
	Describe func(error) string
	// Skipped says, in the warnings, that an item which exists was
	// skipped: in the CLI's words (which name --overwrite) when nil.
	Skipped func(name string) string
}

// ImportReport says what an import stored.
type ImportReport struct {
	Imported, Skipped, Files int
	Warnings                 []string // svimport's, then the store's
}

// StoreError is an item the daemon would not store: the import stops
// there, after Stored items. Err is the daemon's error (it is not
// unwrapped, so that the message says the whole of it: look at Err).
type StoreError struct {
	Name     string
	Stored   int
	Err      error
	describe func(error) string
}

func (e *StoreError) Error() string {
	what := e.Err.Error()
	if e.describe != nil {
		what = e.describe(e.Err)
	}
	return fmt.Sprintf("storing %s: %s (%d items were stored before it)", e.Name, what, e.Stored)
}

// StoreImport stores what svimport read in a vault, with the items'
// files, skipping the items that exist unless o.Overwrite. newCtx makes
// the context of each request, so that a long import is bounded request
// by request (each may wait for a person). On a StoreError, the report
// says what was done before it.
func StoreImport(newCtx func() (context.Context, context.CancelFunc), cl *secretvault.Client, res *svimport.Result, o ImportOptions) (*ImportReport, error) {
	describe := o.Describe
	if describe == nil {
		describe = func(err error) string { return err.Error() }
	}
	ctx, cancel := newCtx()
	existing, err := cl.List(ctx, o.Vault, o.Prefix)
	cancel()
	if err != nil {
		return nil, err
	}
	exists := map[string]bool{}
	for _, e := range existing {
		exists[e.Item.Name] = true
	}
	rep := &ImportReport{Warnings: res.Warnings}
	for _, it := range res.Items {
		if exists[it.Name] && !o.Overwrite {
			rep.Skipped++
			if o.Skipped != nil {
				rep.Warnings = append(rep.Warnings, o.Skipped(it.Name))
			} else {
				rep.Warnings = append(rep.Warnings, it.Name+": already exists, skipped (--overwrite replaces it)")
			}
			continue
		}
		ctx, cancel := newCtx()
		_, err := cl.Put(ctx, o.Vault, it)
		cancel()
		if err != nil {
			return rep, &StoreError{Name: it.Name, Stored: rep.Imported, Err: err, describe: describe}
		}
		rep.Imported++
		for _, f := range res.Files[it.Name] {
			if len(f.Data) > svrpc.MaxFileData {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s: file %s not imported (larger than %d MiB)", it.Name, f.Name, svrpc.MaxFileData>>20))
				continue
			}
			typ := f.Type
			if typ == "" {
				typ = mime.TypeByExtension(filepath.Ext(f.Name))
			}
			ctx, cancel := newCtx()
			_, err := cl.Attach(ctx, svrpc.FileAttachParams{Vault: o.Vault, Item: it.Name, Name: f.Name, Type: typ, Data: f.Data})
			cancel()
			if err != nil {
				rep.Warnings = append(rep.Warnings, fmt.Sprintf("%s: file %s not imported: %s", it.Name, f.Name, describe(err)))
				continue
			}
			rep.Files++
		}
	}
	return rep, nil
}

// CheckExport checks an export can be written: a format it knows, and a
// file that does not exist yet.
func CheckExport(format, path string) error {
	if format != "cxf" && format != "kdbx" {
		return fmt.Errorf("cannot export to %q: the formats are cxf and kdbx", format)
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("%s already exists; export writes only new files", path)
	}
	return nil
}

// ExportOptions say what an export reads.
type ExportOptions struct {
	Vault    string
	Prefix   string // only the items under it
	Describe func(error) string
	// Each is told of every item read, as it is: an interface warns of
	// its conflicts there.
	Each func(svrpc.Entry)
}

// ReadForExport reads every item (under the prefix) whole, for an export,
// a request per item, each in a context newCtx makes. The caller wipes
// the items.
func ReadForExport(newCtx func() (context.Context, context.CancelFunc), cl *secretvault.Client, o ExportOptions) ([]svrpc.Item, error) {
	describe := o.Describe
	if describe == nil {
		describe = func(err error) string { return err.Error() }
	}
	ctx, cancel := newCtx()
	entries, err := cl.List(ctx, o.Vault, o.Prefix)
	cancel()
	if err != nil {
		return nil, err
	}
	items := make([]svrpc.Item, 0, len(entries))
	for _, e := range entries {
		ctx, cancel := newCtx()
		full, err := cl.Get(ctx, o.Vault, e.Item.Name)
		cancel()
		if err != nil {
			for i := range items {
				Wipe(&items[i])
			}
			return nil, fmt.Errorf("reading %s: %s", e.Item.Name, describe(err))
		}
		if o.Each != nil {
			o.Each(full)
		}
		items = append(items, full.Item)
	}
	return items, nil
}

// EncodeExport writes items in an export format: cxf (not encrypted), or
// kdbx under pass. The caller clears the result.
func EncodeExport(format string, items []svrpc.Item, pass []byte) ([]byte, error) {
	var buf bytes.Buffer
	var err error
	switch format {
	case "cxf":
		err = svimport.ExportCXF(items, &buf)
	case "kdbx":
		err = svimport.ExportKDBX(items, &buf, pass)
	default:
		err = fmt.Errorf("cannot export to %q: the formats are cxf and kdbx", format)
	}
	if err != nil {
		clear(buf.Bytes())
		return nil, err
	}
	return buf.Bytes(), nil
}
