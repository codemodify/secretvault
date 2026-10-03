package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svops"
)

// Installing secretvault's own extension's host beside the legacy link,
// and writing the extension out: in a home of the test's own.

func TestTheExtensionsHostIsInstalledBesideTheLegacyLink(t *testing.T) {
	h := newHarness(t)
	home := browserHome(t)
	plantKeePassXC(t, firefoxManifest(home))
	os.MkdirAll(filepath.Join(home, ".config", "chromium"), 0o700)
	h.ok("", "browser", "install", "--keepassxc")

	out := h.ok("", "browser", "install", "--dry-run")
	if !strings.Contains(out, "for the secretvault extension:") || !strings.Contains(out, "firefox: write "+firefoxExtManifest(home)) ||
		strings.Contains(out, "KeePassXC writes its manifests back") {
		t.Errorf("the dry run:\n%s", out)
	}
	out = h.ok("", "browser", "install")
	if !strings.Contains(out, "'secretvault browser extension'") {
		t.Errorf("install said:\n%s", out)
	}
	exe, _ := svops.Executable()
	host, _ := svops.BrowserHostProgram(exe)
	ff := readJSON(t, firefoxExtManifest(home))
	if ff.Name != svext.HostName || ff.Path != host || len(ff.AllowedExtensions) != 1 || ff.AllowedExtensions[0] != svext.FirefoxID || ff.AllowedOrigins != nil {
		t.Fatalf("the Firefox manifest: %+v", ff)
	}
	cr := readJSON(t, chromiumExtManifest(home))
	if cr.Name != svext.HostName || len(cr.AllowedOrigins) != 1 || cr.AllowedOrigins[0] != svext.ChromeOrigin || cr.AllowedExtensions != nil {
		t.Fatalf("the Chromium manifest: %+v", cr)
	}
	// The legacy link is untouched, and both show, the extension first.
	if m := readJSON(t, firefoxManifest(home)); m.Name != "org.keepassxc.keepassxc_browser" || m.Path != host {
		t.Fatalf("the legacy link: %+v", m)
	}
	status := h.ok("", "browser", "status")
	ext, legacy := strings.Index(status, "secretvault's own extension ("+svext.HostName+")"), strings.Index(status, "KeePassXC-Browser, the legacy link")
	if ext < 0 || legacy < ext || !strings.Contains(status[legacy:], "KeePassXC (/usr/bin/keepassxc-proxy) kept, to put back") ||
		!strings.Contains(status[ext:legacy], "firefox   secretvault ("+host+")") {
		t.Errorf("status:\n%s", status)
	}

	// The legacy link alone is undone, and KeePassXC's manifest is back.
	out = h.ok("", "browser", "uninstall", "--keepassxc")
	if !strings.Contains(out, "put back the manifest naming KeePassXC") || strings.Contains(out, svext.HostName) {
		t.Errorf("uninstall --keepassxc said:\n%s", out)
	}
	if b, _ := os.ReadFile(firefoxManifest(home)); string(b) != keepassxcManifest {
		t.Fatal("KeePassXC's manifest did not come back")
	}
	if _, err := os.Stat(firefoxExtManifest(home)); err != nil {
		t.Fatal("undoing the legacy link took the extension's host")
	}
	if _, errs, code := h.run("", "browser", "uninstall", "--keepassxc"); code != 1 || !strings.Contains(errs, "KeePassXC-Browser (legacy) is not installed") {
		t.Errorf("the legacy link undone twice: %d %s", code, errs)
	}
	h.ok("", "browser", "uninstall", "--extension")
	for _, gone := range []string{firefoxExtManifest(home), chromiumExtManifest(home), filepath.Join(home, "sv", "browser-install.json")} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("%s is left behind", gone)
		}
	}
	if _, errs, code := h.run("", "browser", "uninstall", "--keepassxc", "--extension"); code != 1 || !strings.Contains(errs, "one, or neither") {
		t.Errorf("both flags: %d %s", code, errs)
	}
}

// An install made before there were two hosts (its record names none)
// is the legacy link, and is undone as one.
func TestAnOlderRecordIsTheLegacyLink(t *testing.T) {
	h := newHarness(t)
	home := browserHome(t)
	plantKeePassXC(t, firefoxManifest(home))
	h.ok("", "browser", "install", "--keepassxc")
	rec := filepath.Join(home, "sv", "browser-install.json")
	b, _ := os.ReadFile(rec)
	var r map[string]any
	json.Unmarshal(b, &r)
	hosts, _ := r["hosts"].([]any)
	if len(hosts) != 1 || hosts[0].(map[string]any)["host_name"] != "org.keepassxc.keepassxc_browser" {
		t.Fatalf("the record:\n%s", b)
	}
	delete(hosts[0].(map[string]any), "host_name")
	old, _ := json.Marshal(r)
	os.WriteFile(rec, old, 0o600)
	if status := h.ok("", "browser", "status"); !strings.Contains(status, "KeePassXC (/usr/bin/keepassxc-proxy) kept, to put back") {
		t.Errorf("status of an older record:\n%s", status)
	}
	h.ok("", "browser", "uninstall", "--keepassxc")
	if b, _ := os.ReadFile(firefoxManifest(home)); string(b) != keepassxcManifest {
		t.Fatal("KeePassXC's manifest did not come back")
	}
}

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

func TestTheExtensionsHostPlacesOnWindowsAndMacOS(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	t.Setenv(svcore.EnvHome, filepath.Join(home, "sv"))
	win, err := svops.BrowserSpotsOn("windows", svops.ExtensionHost)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range win {
		if !strings.HasSuffix(s.RegKey, `\NativeMessagingHosts\`+svext.HostName) || !strings.Contains(filepath.Base(s.Manifest), svext.HostName+"_") || s.Host != svext.HostName {
			t.Errorf("Windows %s: %+v", s.Name, s)
		}
	}
	mac, _ := svops.BrowserSpotsOn("darwin", svops.ExtensionHost)
	for _, s := range mac {
		if !strings.HasSuffix(s.Manifest, "/NativeMessagingHosts/"+svext.HostName+".json") {
			t.Errorf("macOS %s: %+v", s.Name, s)
		}
	}
}
