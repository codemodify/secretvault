package svops

import (
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svrpc"
)

// Every plan a face confirms says itself in plain words first: a title,
// a summary, and (but for one with nothing to do) a button that says what
// it does; the technical lines are the details. docs/wording.md says how
// they are written; this holds the words to the rules a test can check.
func TestEveryPlanHasATitleAndASummary(t *testing.T) {
	firefox := BrowserSpot{Name: "firefox", Title: "Firefox", Manifest: "/home/ada/.mozilla/native-messaging-hosts/x.json"}
	chrome := BrowserSpot{Name: "chrome", Title: "Google Chrome", Manifest: "/home/ada/.config/google-chrome/NativeMessagingHosts/x.json"}
	browsers := &BrowserInstallPlan{Native: ExtensionHost, Host: "/usr/bin/secretvault", Hosts: []*HostPlan{
		{Browsers: []string{"firefox"}, Spot: firefox},
		{Browsers: []string{"chrome"}, Spot: chrome, Current: CurrentManifest{Exists: true, Host: "/usr/bin/other"}},
	}}
	done := &BrowserInstallPlan{Native: ExtensionHost, Host: "/usr/bin/secretvault", Hosts: []*HostPlan{
		{Browsers: []string{"firefox"}, Spot: firefox, Skip: SkipAlreadyDone},
	}}
	uninstall := []Uninstalled{{InstalledHost: InstalledHost{Browsers: []string{"firefox"}, Manifest: firefox.Manifest}}}
	takeover := &TakeoverPlan{Order: []string{"/home/ada/.local/share/dbus-1/services/org.freedesktop.secrets.service"},
		Restart: []string{"gnome-keyring-daemon.service"}, Notes: []string{"log out and back in"}}
	gnupg := &GnuPGPlan{Home: "/home/ada/.gnupg", Socket: "/run/user/1000/gnupg/S.gpg-agent", Agent: "/run/user/1000/secretvault/gpg-agent",
		AgentProgram: "agent-program /usr/bin/secretvault|--secretvault-gpg-agent", OwnHome: true, Unreachable: 2, Skipped: []string{"a key: no"}}
	helpers := &HelpersPlan{CLI: "/usr/bin/secretvault", Links: []HelperLinkState{{Name: "git-credential-secretvault", Path: "/usr/bin/git-credential-secretvault", Ours: true}},
		DockerConfig: "/home/ada/.docker/config.json"}

	plans := map[string]Plain{
		"browser install":            BrowserInstallPlain(browsers),
		"browser install, done":      BrowserInstallPlain(done),
		"browser uninstall":          BrowserUninstallPlain(uninstall),
		"keyring import":             KeyringImportPlain("/usr/bin/gnome-keyring-daemon", "personal", "imported", []string{"imported/login/wifi"}, nil),
		"keyring import, empty":      KeyringImportPlain("", "personal", "imported", nil, nil),
		"keyring takeover":           TakeoverPlain(takeover, "/usr/bin/gnome-keyring-daemon", true, "personal"),
		"keyring takeover, no-one":   TakeoverPlain(takeover, "", false, ""),
		"keyring restore":            RestorePlain(&TakeoverState{Created: takeover.Order, Previous: "/usr/bin/gnome-keyring-daemon"}),
		"gpg setup":                  GnuPGSetupPlain(gnupg, "personal"),
		"gpg remove":                 GnuPGRemovePlain("/home/ada/.gnupg"),
		"helpers setup":              HelpersSetupPlain(helpers),
		"helpers undo":               HelpersUndoPlain(helpers),
		"helpers undo, nothing":      HelpersUndoPlain(&HelpersPlan{CLI: "/usr/bin/secretvault"}),
		"login unlock":               LoginUnlockPlain("personal"),
		"import":                     ImportPlain("/tmp/logins.csv", "personal", []string{"web/a", "web/b"}, []string{"one odd row"}, false),
		"import, empty":              ImportPlain("/tmp/logins.csv", "personal", nil, nil, true),
		"host identity":              HostInitPlain(),
		"host allow, a unit":         HostRulePlain(svrpc.HostRule{Unit: "app.service", Credential: "db", Ref: "sv://ops/db#password"}, true),
		"host deny, a local service": HostRulePlain(svrpc.HostRule{User: "www", Program: "/usr/bin/app"}, false),
	}
	for name, p := range plans {
		if strings.TrimSpace(p.Title) == "" || strings.TrimSpace(p.Summary) == "" {
			t.Errorf("%s: no title or no summary: %+v", name, p)
		}
		// One to three sentences, the first not a path; and no
		// internal names in the words a person reads first.
		if n := strings.Count(p.Summary, ". ") + 1; n > 3 {
			t.Errorf("%s: a summary of %d sentences: %q", name, n, p.Summary)
		}
		for _, words := range append([]string{p.Title, p.Summary, p.Action}, p.Notes...) {
			for _, jargon := range []string{"/home/", "/usr/", "sv://", "manifest", "HKEY", "systemctl", "secretvaultd", "agent-program", "credsStore", "native-messaging"} {
				if strings.Contains(words, jargon) {
					t.Errorf("%s: %q in the plain words: %q", name, jargon, words)
				}
			}
		}
		if p.Action == "Set them up" || p.Action == "Do it" || p.Action == "OK" || p.Action == "Yes" {
			t.Errorf("%s: a button that does not say what it does: %q", name, p.Action)
		}
	}
	for _, name := range []string{"browser install", "keyring takeover", "gpg setup", "helpers setup", "helpers undo", "keyring restore", "browser uninstall", "import", "login unlock"} {
		if plans[name].Action == "" || len(plans[name].Details) == 0 && name != "login unlock" {
			t.Errorf("%s: no action, or no details: %+v", name, plans[name])
		}
	}
	for _, name := range []string{"browser install, done", "keyring import, empty", "helpers undo, nothing", "import, empty"} {
		if plans[name].Action != "" {
			t.Errorf("%s has nothing to do, and yet a button: %q", name, plans[name].Action)
		}
	}
	// The browsers are named as people know them, and so is the keyring.
	if p := plans["browser install"]; p.Title != "Let Firefox and Google Chrome use secretvault" || p.Action != "Allow Firefox and Google Chrome" ||
		!strings.Contains(strings.Join(p.Notes, " "), "Google Chrome already had such a file") {
		t.Errorf("the browser plan: %+v", p)
	}
	if p := plans["keyring restore"]; p.Title != "Give the keyring back to GNOME Keyring" {
		t.Errorf("the restore plan: %+v", p)
	}
	// The CLI's lines are the details, unchanged.
	if d := plans["browser install"].Details; d[0] != "The browsers would start /usr/bin/secretvault for the secretvault extension:" ||
		d[1] != "  firefox: write "+firefox.Manifest {
		t.Errorf("the browser plan's details: %q", d)
	}
}
