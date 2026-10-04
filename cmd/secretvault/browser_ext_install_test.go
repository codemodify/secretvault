package main

import (
	"archive/zip"
	"bytes"
	"io"
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
	// Each family gets its own manifest.
	chromium, _ := os.ReadFile(filepath.Join(unpacked, "manifest.json"))
	if !strings.Contains(string(chromium), `"key"`) || strings.Contains(string(chromium), "browser_specific_settings") {
		t.Errorf("the Chromium folder's manifest:\n%s", chromium)
	}
	f, _ := z.Open("manifest.json")
	firefox, _ := io.ReadAll(f)
	f.Close()
	if strings.Contains(string(firefox), `"key"`) || !strings.Contains(string(firefox), "browser_specific_settings") {
		t.Errorf("the Firefox zip's manifest:\n%s", firefox)
	}
	// A zip for the Chrome Web Store, and a folder for Firefox.
	store := filepath.Join(dir, "store.zip")
	if out := h.ok("", "browser", "extension", "--target", "chromium", "--out", store); !strings.Contains(out, "Chrome Web Store") {
		t.Errorf("it said:\n%s", out)
	}
	if sz, err := zip.OpenReader(store); err != nil {
		t.Error(err)
	} else {
		f, _ := sz.Open("manifest.json")
		m, _ := io.ReadAll(f)
		f.Close()
		sz.Close()
		if strings.Contains(string(m), `"key"`) || !strings.Contains(string(m), `"service_worker"`) {
			t.Errorf("the Chrome Web Store's manifest:\n%s", m)
		}
	}
	if out := h.ok("", "browser", "extension", "--target", "firefox", "--dir", filepath.Join(dir, "ff")); !strings.Contains(out, "manifest.json in that folder") {
		t.Errorf("it said:\n%s", out)
	}
	if _, errs, code := h.run("", "browser", "extension", "--target", "safari"); code == 0 || !strings.Contains(errs, "firefox or chromium") {
		t.Errorf("an unknown target: %d %s", code, errs)
	}
}
