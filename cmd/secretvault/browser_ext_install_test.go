package main

import (
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svops"
)

// Writing secretvault's own extension out, to load in a browser.

func TestTheExtensionIsWrittenOutToLoad(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	file := filepath.Join(dir, "sv.zip")
	out := h.ok("", "browser", "extension", "--out", file)
	if !strings.Contains(out, "about:debugging") || !strings.Contains(out, "Load Temporary Add-on") {
		t.Errorf("it said:\n%s", out)
	}
	z, err := zip.OpenReader(file)
	if err != nil {
		t.Fatal(err)
	}
	defer z.Close()
	names := map[string]bool{}
	for _, f := range z.File {
		names[f.Name] = true
	}
	if z.File[0].Name != "manifest.json" || !names["background.js"] || !names["content.js"] || !names["data/public_suffix_list.dat"] || len(names) != svops.ExtensionFileCount() {
		t.Errorf("the package holds %v", names)
	}
	// Twice, the same bytes; a file there is replaced only with --force.
	first, _ := os.ReadFile(file)
	if _, errs, code := h.run("", "browser", "extension", "--out", file); code != 1 || !strings.Contains(errs, "--force") {
		t.Errorf("over a file: %d %s", code, errs)
	}
	h.ok("", "browser", "extension", "--out", file, "--force")
	if again, _ := os.ReadFile(file); !bytes.Equal(first, again) {
		t.Error("the package changed between two writes")
	}
	// A folder, for Chromium.
	unpacked := filepath.Join(dir, "unpacked")
	if out := h.ok("", "browser", "extension", "--dir", unpacked); !strings.Contains(out, "Load unpacked") {
		t.Errorf("it said:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(unpacked, "lib", "origin.js")); err != nil {
		t.Fatal(err)
	}
	if _, errs, code := h.run("", "browser", "extension", "--dir", unpacked); code != 1 || !strings.Contains(errs, "not empty") {
		t.Errorf("into a full folder: %d %s", code, errs)
	}
}
