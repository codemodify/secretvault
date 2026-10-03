package main

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svops"
)

// Installing into browsers, in a home of the test's own: nothing here
// reads or writes the real ~/.mozilla or ~/.config.

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
	for _, h := range svops.NativeHosts {
		spots, err := svops.BrowserSpots(h)
		if err != nil {
			t.Fatal(err)
		}
		for _, s := range spots {
			if !strings.HasPrefix(s.Manifest, home+"/") || !strings.HasPrefix(s.Profile, home+"/") {
				t.Fatalf("%s's place %s is outside the test's home", s.Name, s.Manifest)
			}
		}
	}
	return home
}

// firefoxExtManifest and chromiumExtManifest are the extension's host's.
func firefoxExtManifest(home string) string {
	return filepath.Join(home, ".mozilla", "native-messaging-hosts", svext.HostName+".json")
}

func chromiumExtManifest(home string) string {
	return filepath.Join(home, ".config", "chromium", "NativeMessagingHosts", svext.HostName+".json")
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

// otherManifest is a manifest for secretvault's host's name that
// secretvault did not write.
const otherManifest = `{"name":"` + svext.HostName + `","path":"/opt/other/host","type":"stdio"}` + "\n"

func plantOther(t *testing.T, path string) {
	t.Helper()
	os.MkdirAll(filepath.Dir(path), 0o700)
	if err := os.WriteFile(path, []byte(otherManifest), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestInstallWritesTheHostAndUninstallTakesItAway(t *testing.T) {
	h := newHarness(t)
	home := browserHome(t)
	os.MkdirAll(filepath.Join(home, ".mozilla"), 0o700)            // Firefox is used, and has no host
	os.MkdirAll(filepath.Join(home, ".config", "chromium"), 0o700) // and Chromium

	before := snapshot(t, home)
	out := h.ok("", "browser", "install", "--dry-run")
	for _, want := range []string{
		"for the secretvault extension:",
		"firefox: write " + firefoxExtManifest(home),
		"chromium: write " + chromiumExtManifest(home),
		"making " + filepath.Dir(chromiumExtManifest(home)),
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
	if cr.Name != svext.HostName || cr.Path != host || len(cr.AllowedOrigins) != 1 || cr.AllowedOrigins[0] != svext.ChromeOrigin || cr.AllowedExtensions != nil {
		t.Fatalf("the Chromium manifest: %+v", cr)
	}
	status := h.ok("", "browser", "status")
	for _, want := range []string{
		"secretvault's own extension (" + svext.HostName + ")",
		"firefox   secretvault (" + host + ")",
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
	if out := h.ok("", "browser", "uninstall", "--dry-run"); !strings.Contains(out, "remove "+firefoxExtManifest(home)) ||
		!strings.Contains(out, "remove "+chromiumExtManifest(home)) {
		t.Errorf("the uninstall dry run:\n%s", out)
	}
	if after := snapshot(t, home); after != before {
		t.Fatalf("the uninstall dry run changed files")
	}

	out = h.ok("", "browser", "uninstall")
	for _, gone := range []string{firefoxExtManifest(home), filepath.Dir(chromiumExtManifest(home)), filepath.Join(home, "sv", "browser-install.json")} {
		if _, err := os.Stat(gone); !os.IsNotExist(err) {
			t.Errorf("%s is left behind (%v)", gone, err)
		}
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "chromium")); err != nil {
		t.Fatal("uninstall removed Chromium's own directory")
	}
	if !strings.Contains(out, "firefox: removed") || !strings.Contains(out, "chromium: removed") {
		t.Errorf("uninstall said:\n%s", out)
	}
	if _, errs, code := h.run("", "browser", "uninstall"); code != 1 || !strings.Contains(errs, "not installed") {
		t.Errorf("a second uninstall: %d %s", code, errs)
	}
}

func TestAManifestSecretvaultDidNotWriteIsLeftAlone(t *testing.T) {
	h := newHarness(t)
	home := browserHome(t)
	plantOther(t, firefoxExtManifest(home))
	before := snapshot(t, home)
	if out := h.ok("", "browser", "install", "--browser", "firefox"); !strings.Contains(out, "nothing to do: "+svops.SkipOther) {
		t.Errorf("install over another manifest:\n%s", out)
	}
	if after := snapshot(t, home); after != before {
		t.Fatalf("install changed files:\n%s\n---\n%s", before, after)
	}
	if status := h.ok("", "browser", "status"); !strings.Contains(status, "firefox   another program (/opt/other/host)") {
		t.Errorf("status:\n%s", status)
	}
}

func TestAManifestChangedSinceInstallIsLeftAlone(t *testing.T) {
	h := newHarness(t)
	home := browserHome(t)
	h.ok("", "browser", "install", "--browser", "firefox")
	// Something else writes the manifest over.
	os.WriteFile(firefoxExtManifest(home), []byte(otherManifest), 0o644)
	if status := h.ok("", "browser", "status"); !strings.Contains(status, "firefox   another program (/opt/other/host); changed since secretvault installed it") {
		t.Errorf("status:\n%s", status)
	}
	if out := h.ok("", "browser", "install", "--browser", "firefox"); !strings.Contains(out, "changed since secretvault installed it") {
		t.Errorf("install over a changed manifest:\n%s", out)
	}
	if m := readJSON(t, firefoxExtManifest(home)); m.Path != "/opt/other/host" {
		t.Fatal("install wrote over a manifest that is not its own")
	}
	if out := h.ok("", "browser", "uninstall"); !strings.Contains(out, "left as it is") {
		t.Errorf("uninstall said:\n%s", out)
	}
	if b, _ := os.ReadFile(firefoxExtManifest(home)); string(b) != otherManifest {
		t.Fatal("uninstall took a manifest that is not its own")
	}
	if _, err := os.Stat(filepath.Join(home, "sv", "browser-install.json")); !os.IsNotExist(err) {
		t.Error("the install record is left behind")
	}
	// It is forgotten, and not secretvault's: installing leaves it alone.
	if out := h.ok("", "browser", "install", "--browser", "firefox"); !strings.Contains(out, svops.SkipOther) {
		t.Errorf("install after:\n%s", out)
	}
}

// An install record made when secretvault also stood in for another
// browser extension's host names hosts secretvault no longer is: those
// are not read, and nothing is done to their manifests or to what the
// install kept of them.
func TestARecordOfAHostNoLongerServedIsIgnored(t *testing.T) {
	h := newHarness(t)
	home := browserHome(t)
	os.MkdirAll(filepath.Join(home, ".mozilla"), 0o700)
	oldManifest := filepath.Join(home, ".mozilla", "native-messaging-hosts", "org.example.old_host.json")
	plantOther(t, oldManifest)
	kept := filepath.Join(home, "sv", "browser-backup", "firefox-org.example.old_host.json")
	plantOther(t, kept)
	rec := map[string]any{
		"when": "2026-09-30T10:00:00Z",
		"host": "/opt/older/secretvault-browser",
		"hosts": []map[string]any{
			{"browsers": []string{"firefox"}, "manifest": oldManifest, "sum": "00", "host_name": "org.example.old_host",
				"backup": map[string]any{"copy": kept, "mode": 420, "mod_time": "2025-01-02T03:04:05Z", "host": "/usr/bin/other"}},
			{"browsers": []string{"chromium"}, "manifest": filepath.Join(home, ".config", "chromium", "NativeMessagingHosts", "org.example.old_host.json"), "sum": "00"},
		},
	}
	b, _ := json.Marshal(rec)
	if err := os.WriteFile(filepath.Join(home, "sv", "browser-install.json"), b, 0o600); err != nil {
		t.Fatal(err)
	}
	status := h.ok("", "browser", "status")
	if strings.Contains(status, "Installed") || strings.Contains(status, "old_host") || !strings.Contains(status, "firefox   no host (used here)") {
		t.Errorf("status of an older record:\n%s", status)
	}
	if _, errs, code := h.run("", "browser", "uninstall"); code != 1 || !strings.Contains(errs, "not installed") {
		t.Errorf("uninstall of an older record: %d %s", code, errs)
	}
	// The install is not held up by the older record's program.
	h.ok("", "browser", "install", "--browser", "firefox")
	if m := readJSON(t, firefoxExtManifest(home)); m.Name != svext.HostName {
		t.Fatalf("the manifest: %+v", m)
	}
	h.ok("", "browser", "uninstall")
	for _, p := range []string{oldManifest, kept} {
		if b, _ := os.ReadFile(p); string(b) != otherManifest {
			t.Errorf("%s was touched", p)
		}
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
		if _, err := os.Stat(filepath.Join(home, ".config", dir, "NativeMessagingHosts", svext.HostName+".json")); err != nil {
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
	win, err := svops.BrowserSpotsOn("windows", svops.ExtensionHost)
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]svops.BrowserSpot{}
	for _, s := range win {
		byName[s.Name] = s
		if !strings.HasSuffix(s.RegKey, `\NativeMessagingHosts\`+svext.HostName) || !strings.Contains(filepath.Base(s.Manifest), svext.HostName+"_") || s.Host != svext.HostName {
			t.Errorf("Windows %s: %+v", s.Name, s)
		}
	}
	// Brave and Vivaldi read Chrome's key, so they share its manifest.
	if byName["brave"].RegKey != byName["chrome"].RegKey || byName["vivaldi"].Manifest != byName["chrome"].Manifest {
		t.Errorf("brave %+v, chrome %+v", byName["brave"], byName["chrome"])
	}
	if k := byName["firefox"].RegKey; k != `Software\Mozilla\NativeMessagingHosts\`+svext.HostName {
		t.Errorf("Firefox's key: %s", k)
	}
	if !strings.HasPrefix(byName["edge"].Manifest, filepath.Join(home, "sv")) {
		t.Errorf("Edge's manifest is not secretvault's own: %s", byName["edge"].Manifest)
	}
	mac, _ := svops.BrowserSpotsOn("darwin", svops.ExtensionHost)
	for _, s := range mac {
		if s.RegKey != "" || !strings.HasPrefix(s.Manifest, filepath.Join(home, "Library", "Application Support")) || !strings.HasSuffix(s.Manifest, "/NativeMessagingHosts/"+svext.HostName+".json") {
			t.Errorf("macOS %s: %+v", s.Name, s)
		}
	}
}
