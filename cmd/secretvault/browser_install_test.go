package main

import (
	"bytes"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svops"
)

// Installing into browsers, in a home of the test's own: nothing here
// reads or writes the real ~/.mozilla or ~/.config.

// keepassxcManifest is the manifest KeePassXC writes for Firefox.
const keepassxcManifest = `{
    "allowed_extensions": [
        "keepassxc-browser@keepassxc.org"
    ],
    "description": "KeePassXC integration with native messaging support",
    "name": "org.keepassxc.keepassxc_browser",
    "path": "/usr/bin/keepassxc-proxy",
    "type": "stdio"
}
`

// browserHome points HOME, XDG_CONFIG_HOME and secretvault's own directory
// into a temporary directory, and checks every browser place is in it
// before anything is written.
func browserHome(t *testing.T) string {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the Linux places are tested")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv(svcore.EnvHome, filepath.Join(home, "sv"))
	spots, err := svops.BrowserSpots()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range spots {
		if !strings.HasPrefix(s.Manifest, home+"/") || !strings.HasPrefix(s.Profile, home+"/") {
			t.Fatalf("%s's place %s is outside the test's home", s.Name, s.Manifest)
		}
	}
	return home
}

func firefoxManifest(home string) string {
	return filepath.Join(home, ".mozilla", "native-messaging-hosts", "org.keepassxc.keepassxc_browser.json")
}

func chromiumManifest(home string) string {
	return filepath.Join(home, ".config", "chromium", "NativeMessagingHosts", "org.keepassxc.keepassxc_browser.json")
}

// snapshot describes every file under dir: to show a dry run changed
// nothing.
func snapshot(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		line := p + " " + st.Mode().String() + " " + st.ModTime().String()
		if st.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			line += " " + string(b)
		}
		if st.Mode()&fs.ModeSymlink != 0 {
			target, _ := os.Readlink(p)
			line += " -> " + target
		}
		lines = append(lines, line)
		return nil
	})
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}

var keepassxcTime = time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)

func plantKeePassXC(t *testing.T, path string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, []byte(keepassxcManifest), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o644)
	os.Chtimes(path, keepassxcTime, keepassxcTime)
}

func readJSON(t *testing.T, path string) svops.NativeManifest {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m svops.NativeManifest
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestInstallStandsInForKeePassXCAndUninstallPutsItBack(t *testing.T) {
	h := newHarness(t)
	home := browserHome(t)
	plantKeePassXC(t, firefoxManifest(home))
	os.MkdirAll(filepath.Join(home, ".config", "chromium"), 0o700) // Chromium is used, and has no host

	before := snapshot(t, home)
	out := h.ok("", "browser", "install", "--dry-run")
	for _, want := range []string{
		"firefox: replace " + firefoxManifest(home),
		"it names KeePassXC (/usr/bin/keepassxc-proxy) now; a copy is kept",
		"chromium: write " + chromiumManifest(home),
		"making " + filepath.Dir(chromiumManifest(home)),
		"KeePassXC writes its manifests back",
		"Nothing was changed",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "chrome:") || strings.Contains(out, "brave") {
		t.Errorf("the dry run plans for browsers not used here:\n%s", out)
	}
	if after := snapshot(t, home); after != before {
		t.Fatalf("the dry run changed files:\n%s\n---\n%s", before, after)
	}

	out = h.ok("", "browser", "install")
	exe, _ := svops.Executable()
	host, _ := svops.BrowserHostProgram(exe)
	ff := readJSON(t, firefoxManifest(home))
	if ff.Path != host || ff.Name != "org.keepassxc.keepassxc_browser" || len(ff.AllowedExtensions) != 1 || ff.AllowedOrigins != nil {
		t.Fatalf("the Firefox manifest: %+v", ff)
	}
	cr := readJSON(t, chromiumManifest(home))
	if cr.Path != host || len(cr.AllowedOrigins) != 2 || cr.AllowedExtensions != nil {
		t.Fatalf("the Chromium manifest: %+v", cr)
	}
	if !strings.Contains(out, "KeePassXC (/usr/bin/keepassxc-proxy), is kept to put back") {
		t.Errorf("install said:\n%s", out)
	}
	status := h.ok("", "browser", "status")
	for _, want := range []string{
		"firefox   secretvault (" + host + "); KeePassXC (/usr/bin/keepassxc-proxy) kept, to put back",
		"chromium  secretvault (" + host + ")",
		"chrome    no host (not used here)",
	} {
		if !strings.Contains(status, want) {
			t.Errorf("status does not say %q:\n%s", want, status)
		}
	}
	if out := h.ok("", "browser", "install"); strings.Count(out, "nothing to do: already done") != 2 {
		t.Errorf("a second install:\n%s", out)
	}

	before = snapshot(t, home)
	if out := h.ok("", "browser", "uninstall", "--dry-run"); !strings.Contains(out, "put back "+firefoxManifest(home)+" as it was") ||
		!strings.Contains(out, "remove "+chromiumManifest(home)) {
		t.Errorf("the uninstall dry run:\n%s", out)
	}
	if after := snapshot(t, home); after != before {
		t.Fatalf("the uninstall dry run changed files")
	}

	out = h.ok("", "browser", "uninstall")
	b, err := os.ReadFile(firefoxManifest(home))
	st, _ := os.Stat(firefoxManifest(home))
	if err != nil || string(b) != keepassxcManifest || st.Mode().Perm() != 0o644 || !st.ModTime().Equal(keepassxcTime) {
		t.Fatalf("KeePassXC's manifest came back as %q, %v, %v (%v)", b, st.Mode(), st.ModTime(), err)
	}
	if _, err := os.Stat(filepath.Dir(chromiumManifest(home))); !os.IsNotExist(err) {
		t.Fatalf("the directory install made for Chromium is still there (%v)", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "chromium")); err != nil {
		t.Fatal("uninstall removed Chromium's own directory")
	}
	for _, gone := range []string{"browser-install.json", "browser-backup"} {
		if _, err := os.Stat(filepath.Join(home, "sv", gone)); !os.IsNotExist(err) {
			t.Errorf("%s is left behind", gone)
		}
	}
	if !strings.Contains(out, "firefox: put back the manifest naming KeePassXC") || !strings.Contains(out, "chromium: removed") {
		t.Errorf("uninstall said:\n%s", out)
	}
	if _, errs, code := h.run("", "browser", "uninstall"); code != 1 || !strings.Contains(errs, "not installed") {
		t.Errorf("a second uninstall: %d %s", code, errs)
	}
}

func TestALinkedManifestComesBackALink(t *testing.T) {
	h := newHarness(t)
	home := browserHome(t)
	target := filepath.Join(home, "system", "keepassxc.json")
	plantKeePassXC(t, target)
	os.MkdirAll(filepath.Dir(firefoxManifest(home)), 0o700)
	if err := os.Symlink(target, firefoxManifest(home)); err != nil {
		t.Fatal(err)
	}
	h.ok("", "browser", "install", "--browser", "firefox")
	if st, _ := os.Lstat(firefoxManifest(home)); st.Mode()&fs.ModeSymlink != 0 {
		t.Fatal("install wrote through the link")
	}
	if b, _ := os.ReadFile(target); string(b) != keepassxcManifest {
		t.Fatal("install changed the file the link pointed at")
	}
	h.ok("", "browser", "uninstall")
	if got, err := os.Readlink(firefoxManifest(home)); err != nil || got != target {
		t.Fatalf("the link came back as %q, %v", got, err)
	}
}

func TestAManifestChangedSinceInstallIsLeftAlone(t *testing.T) {
	h := newHarness(t)
	home := browserHome(t)
	plantKeePassXC(t, firefoxManifest(home))
	h.ok("", "browser", "install", "--browser", "firefox")
	// KeePassXC starts, with browser integration on, and writes its own
	// manifest back.
	os.WriteFile(firefoxManifest(home), []byte(keepassxcManifest), 0o644)
	if status := h.ok("", "browser", "status"); !strings.Contains(status, "firefox   KeePassXC (/usr/bin/keepassxc-proxy); changed since secretvault installed it") {
		t.Errorf("status:\n%s", status)
	}
	if out := h.ok("", "browser", "install", "--browser", "firefox"); !strings.Contains(out, "changed since secretvault installed it") {
		t.Errorf("install over a changed manifest:\n%s", out)
	}
	if m := readJSON(t, firefoxManifest(home)); m.Path != "/usr/bin/keepassxc-proxy" {
		t.Fatal("install wrote over a manifest that is not its own")
	}
	out := h.ok("", "browser", "uninstall")
	backup := filepath.Join(home, "sv", "browser-backup", "firefox-org.keepassxc.keepassxc_browser.json")
	if !strings.Contains(out, "left as it is") || !strings.Contains(out, backup) {
		t.Errorf("uninstall said:\n%s", out)
	}
	if b, _ := os.ReadFile(backup); string(b) != keepassxcManifest {
		t.Error("the backup was not kept")
	}
	if _, err := os.Stat(filepath.Join(home, "sv", "browser-install.json")); !os.IsNotExist(err) {
		t.Error("the install record is left behind")
	}
	// Now it can be installed again, from scratch.
	h.ok("", "browser", "install", "--browser", "firefox")
	h.ok("", "browser", "uninstall")
	if b, _ := os.ReadFile(firefoxManifest(home)); !bytes.Equal(b, []byte(keepassxcManifest)) {
		t.Fatal("KeePassXC's manifest did not come back")
	}
}

func TestInstallNeedsABrowser(t *testing.T) {
	h := newHarness(t)
	home := browserHome(t)
	if _, errs, code := h.run("", "browser", "install"); code != 1 || !strings.Contains(errs, "no browser found here") {
		t.Errorf("no browser: %d %s", code, errs)
	}
	if _, errs, code := h.run("", "browser", "install", "--browser", "netscape"); code != 1 || !strings.Contains(errs, `unknown browser "netscape"`) {
		t.Errorf("an unknown browser: %d %s", code, errs)
	}
	h.ok("", "browser", "install", "--browser", "brave,vivaldi")
	for _, dir := range []string{"BraveSoftware/Brave-Browser", "vivaldi"} {
		if _, err := os.Stat(filepath.Join(home, ".config", dir, "NativeMessagingHosts", "org.keepassxc.keepassxc_browser.json")); err != nil {
			t.Errorf("%s: %v", dir, err)
		}
	}
	h.ok("", "browser", "uninstall")
	if entries, _ := os.ReadDir(filepath.Join(home, ".config")); len(entries) != 0 {
		t.Errorf("uninstall left %v", entries)
	}
}

func TestWindowsAndMacOSPlaces(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("LOCALAPPDATA", filepath.Join(home, "Local"))
	t.Setenv("APPDATA", filepath.Join(home, "Roaming"))
	t.Setenv(svcore.EnvHome, filepath.Join(home, "sv"))
	win, err := svops.BrowserSpotsOn("windows")
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]svops.BrowserSpot{}
	for _, s := range win {
		byName[s.Name] = s
	}
	// Brave and Vivaldi read Chrome's key, so they share its manifest.
	if byName["brave"].RegKey != byName["chrome"].RegKey || byName["vivaldi"].Manifest != byName["chrome"].Manifest {
		t.Errorf("brave %+v, chrome %+v", byName["brave"], byName["chrome"])
	}
	if k := byName["firefox"].RegKey; k != `Software\Mozilla\NativeMessagingHosts\org.keepassxc.keepassxc_browser` {
		t.Errorf("Firefox's key: %s", k)
	}
	if !strings.HasPrefix(byName["edge"].Manifest, filepath.Join(home, "sv")) {
		t.Errorf("Edge's manifest is not secretvault's own: %s", byName["edge"].Manifest)
	}
	mac, _ := svops.BrowserSpotsOn("darwin")
	for _, s := range mac {
		if s.RegKey != "" || !strings.HasPrefix(s.Manifest, filepath.Join(home, "Library", "Application Support")) || !strings.HasSuffix(s.Manifest, "/NativeMessagingHosts/org.keepassxc.keepassxc_browser.json") {
			t.Errorf("macOS %s: %+v", s.Name, s)
		}
	}
}
