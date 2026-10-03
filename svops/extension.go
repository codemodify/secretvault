package svops

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"time"

	"github.com/codemodify/secretvault/browser"
)

// secretvault's own browser extension, packaged from the copy every
// program carries (package browser): a .zip with manifest.json at its
// root, which Firefox loads as a temporary add-on and addons.mozilla.org
// takes to sign; or its files in a folder, which Chromium's "Load
// unpacked" takes. Nothing here signs or uploads anything
// (docs/browser.md says how the person does).

// ExtensionVersion is the extension's version, from its manifest.
func ExtensionVersion() string {
	b, err := fs.ReadFile(browser.Extension(), "manifest.json")
	if err != nil {
		return ""
	}
	var m struct {
		Version string `json:"version"`
	}
	json.Unmarshal(b, &m)
	return m.Version
}

// ExtensionFileName is the package's usual name.
func ExtensionFileName() string { return "secretvault-extension-" + ExtensionVersion() + ".zip" }

// packTime is every packaged file's time, so that the same extension
// makes the same package.
var packTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func extensionFiles() ([]string, error) {
	var files []string
	err := fs.WalkDir(browser.Extension(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	sort.Slice(files, func(i, j int) bool {
		// The manifest first, as stores like to find it.
		if (files[i] == "manifest.json") != (files[j] == "manifest.json") {
			return files[i] == "manifest.json"
		}
		return files[i] < files[j]
	})
	return files, err
}

// PackExtension writes the extension as a zip.
func PackExtension(w io.Writer) error {
	files, err := extensionFiles()
	if err != nil {
		return err
	}
	z := zip.NewWriter(w)
	for _, p := range files {
		data, err := fs.ReadFile(browser.Extension(), p)
		if err != nil {
			return err
		}
		h := &zip.FileHeader{Name: p, Method: zip.Deflate, Modified: packTime}
		h.SetMode(0o644)
		f, err := z.CreateHeader(h)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			return err
		}
	}
	return z.Close()
}

// ErrExtensionExists is a package or folder already there, which writing
// the extension does not replace unless told to.
var ErrExtensionExists = errors.New("it is there already")

// WriteExtension writes the extension's zip to path, replacing a file
// there only when replace is set.
func WriteExtension(path string, replace bool) error {
	var buf bytes.Buffer
	if err := PackExtension(&buf); err != nil {
		return err
	}
	if !replace {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s: %w", path, ErrExtensionExists)
		}
	}
	return WriteReplacing(path, buf.Bytes(), 0o644)
}

// WriteExtensionDir writes the extension's files into dir, which must be
// missing or empty.
func WriteExtensionDir(dir string) error {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s: %w, and is not empty", dir, ErrExtensionExists)
	}
	files, err := extensionFiles()
	if err != nil {
		return err
	}
	for _, p := range files {
		data, err := fs.ReadFile(browser.Extension(), p)
		if err != nil {
			return err
		}
		out := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(out, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// ExtensionFileCount is how many files the extension has, to say so.
func ExtensionFileCount() int {
	files, _ := extensionFiles()
	return len(files)
}
