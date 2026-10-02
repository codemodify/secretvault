package svops

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svsecret"
)

// Making secretvault the desktop's keyring (the Secret Service,
// org.freedesktop.secrets) on Linux:
//
//   - KeyringHolderNow: who holds the keyring now;
//   - ReadKeyring and ImportKeyring: copy every secret out of the current
//     keyring into a vault;
//   - PlanTakeover, ApplyTakeover: make secretvault the keyring from now
//     on, after importing (the daemon's ServeKeyring turns its Secret
//     Service on, between the two halves);
//   - LoadTakeover, UndoTakeover: undo the takeover exactly.
//
// The takeover changes only files in the user's own directories, and
// records each change so that it can be undone:
//
//   - a D-Bus activation file for org.freedesktop.secrets pointing at
//     secretvaultd (the user's copy overrides the system's);
//   - for gnome-keyring: its "secrets" autostart entry hidden, and a drop-in
//     for its systemd user service that keeps its other parts (pkcs11) but
//     not the secrets one; then the service is restarted, letting go of the
//     name, which secretvaultd (queued for it) takes;
//   - where the desktop's portals.conf picks another Secret portal backend
//     (KDE picks kwallet), the user's copy of it choosing gnome-keyring,
//     which then reaches secretvault.
//
// Other keyrings (KWallet's ksecretd, KeePassXC, oo7) get the steps to do
// by hand: turning off their Secret Service integration is a setting of
// theirs.

// ErrKeyringNotHere says the takeover is for Linux.
var ErrKeyringNotHere = errors.New("taking over the system keyring is for Linux; on Windows and macOS secretvault bridges instead (docs/architecture.md)")

// KeyringHere reports, with ErrKeyringNotHere, whether the keyring can be
// imported from or taken over here.
func KeyringHere() error {
	if runtime.GOOS != "linux" {
		return ErrKeyringNotHere
	}
	return nil
}

// KeyringHolder is who holds org.freedesktop.secrets.
type KeyringHolder struct {
	BusErr error          // no session bus: nothing else is known
	Held   bool           // somebody holds the name
	Owner  svsecret.Owner // who, when Held
}

// KeyringHolderNow asks the session bus who holds the keyring.
func KeyringHolderNow(ctx context.Context) KeyringHolder {
	bus, err := svdbus.ConnectSession()
	if err != nil {
		return KeyringHolder{BusErr: err}
	}
	defer bus.Close()
	o, err := svsecret.CurrentOwner(ctx, bus)
	if err != nil {
		return KeyringHolder{}
	}
	return KeyringHolder{Held: true, Owner: o}
}

// DescribeExe names a program for people.
func DescribeExe(exe string) string {
	if exe == "" {
		return "an unidentified program"
	}
	return filepath.Base(exe) + " (" + exe + ")"
}

// ReadKeyring reads every secret the current keyring holds. reading, when
// set, is told who that is before the keyring is asked, since it may ask
// the person to unlock it. The caller wipes the secrets.
func ReadKeyring(ctx context.Context, reading func(svsecret.Owner)) ([]svsecret.Secret, []string, error) {
	bus, err := svdbus.ConnectSession()
	if err != nil {
		return nil, nil, err
	}
	defer bus.Close()
	o, err := svsecret.CurrentOwner(ctx, bus)
	if err != nil {
		return nil, nil, err
	}
	if strings.HasPrefix(filepath.Base(o.Exe), "secretvaultd") {
		return nil, nil, errors.New("secretvault is already the keyring: there is nothing to import")
	}
	if reading != nil {
		reading(o)
	}
	kc, err := svsecret.Open(ctx, bus)
	if err != nil {
		return nil, nil, err
	}
	defer kc.Close()
	return kc.ReadAll(ctx)
}

// KeyringItems are the items secrets become, under prefix, each named
// for its collection and label, and never one in taken (which it adds
// them to).
func KeyringItems(secrets []svsecret.Secret, prefix string, taken map[string]bool) []svrpc.Item {
	var out []svrpc.Item
	for _, s := range secrets {
		name := UniqueName(taken, prefix+"/"+PathSafe(s.Collection)+"/"+PathSafe(s.Label))
		taken[name] = true
		it := svrpc.Item{Kind: "password", Name: name, Label: s.Label, Attrs: s.Attributes,
			Fields: []svrpc.Field{{Name: "secret", Type: svcore.FieldConcealed, Value: s.Value}}}
		if s.ContentType != "" && s.ContentType != "text/plain" {
			it.Fields = append(it.Fields, svrpc.Field{Name: "content_type", Type: svcore.FieldText, Value: []byte(s.ContentType)})
		}
		out = append(out, it)
	}
	return out
}

// ImportKeyring stores secrets read from the keyring in a vault, under
// prefix, beside what is there, and returns how many it stored. With cl
// nil it stores nothing, a dry run, and names says what it would store.
func ImportKeyring(ctx context.Context, cl *secretvault.Client, vault, prefix string, secrets []svsecret.Secret) (names []string, n int, err error) {
	taken := map[string]bool{}
	if cl != nil {
		if existing, err := cl.List(ctx, vault, ""); err == nil {
			for _, e := range existing {
				taken[e.Item.Name] = true
			}
		}
	}
	for _, it := range KeyringItems(secrets, prefix, taken) {
		names = append(names, it.Name)
		if cl == nil {
			continue
		}
		if _, err := cl.Put(ctx, vault, it); err != nil {
			return names, n, fmt.Errorf("storing %s: %w", it.Name, err)
		}
		n++
	}
	return names, n, nil
}

// TakeoverState records what the takeover changed.
type TakeoverState struct {
	When     time.Time `json:"when"`
	Created  []string  `json:"created"`  // files the takeover made, to delete
	Restart  []string  `json:"restart"`  // systemd user units to restart on restore
	Previous string    `json:"previous"` // the keyring it took over from
}

// TakeoverPath is where the record of a takeover is kept.
func TakeoverPath() (string, error) {
	h, err := svcore.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "keyring-takeover.json"), nil
}

// LoadTakeover reads the record of the takeover; an error satisfying
// errors.Is(err, fs.ErrNotExist) means there was none.
func LoadTakeover() (*TakeoverState, error) {
	p, err := TakeoverPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var s TakeoverState
	return &s, json.Unmarshal(b, &s)
}

func userDir(env, fallback string) string {
	if d := os.Getenv(env); filepath.IsAbs(d) {
		return d
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, fallback)
}

// TakeoverPlan is a list of changes, shown for a dry run and then carried
// out.
type TakeoverPlan struct {
	Files   map[string]string // path -> contents
	Order   []string          // the files, in the order they are written
	Restart []string          // systemd user units to restart
	Notes   []string          // what is left to do by hand
}

func (p *TakeoverPlan) file(path, contents string) {
	if p.Files == nil {
		p.Files = map[string]string{}
	}
	p.Files[path] = contents
	p.Order = append(p.Order, path)
}

// execStartWithout rewrites a systemd ExecStart= line so that a
// --components=... list no longer has component.
func execStartWithout(execStart, component string) (string, bool) {
	re := regexp.MustCompile(`--components=("?)([^"\s]*)("?)`)
	m := re.FindStringSubmatch(execStart)
	if m == nil {
		return "", false
	}
	var keep []string
	for _, c := range strings.Split(m[2], ",") {
		if c != component && c != "" {
			keep = append(keep, c)
		}
	}
	if len(keep) == 0 {
		return "", false
	}
	return strings.Replace(execStart, m[0], "--components="+m[1]+strings.Join(keep, ",")+m[3], 1), true
}

// PlanTakeover works out the changes for taking over from the keyring
// at exe ("" when nobody holds it), for the daemon at daemon
// (SiblingProgram("secretvaultd")). It reads the system's files and asks
// systemctl (through CommandRunner), and changes nothing.
func PlanTakeover(exe, daemon string) (*TakeoverPlan, error) {
	p := &TakeoverPlan{}
	services := filepath.Join(userDir("XDG_DATA_HOME", ".local/share"), "dbus-1", "services", "org.freedesktop.secrets.service")
	p.file(services, "[D-BUS Service]\nName=org.freedesktop.secrets\nExec="+daemon+"\n")
	switch base := filepath.Base(exe); {
	case strings.HasPrefix(base, "gnome-keyring-daemon"):
		config := userDir("XDG_CONFIG_HOME", ".config")
		if b, err := os.ReadFile("/etc/xdg/autostart/gnome-keyring-secrets.desktop"); err == nil {
			p.file(filepath.Join(config, "autostart", "gnome-keyring-secrets.desktop"), strings.TrimRight(string(b), "\n")+"\nHidden=true\n")
		}
		out, err := CommandRunner("systemctl", "--user", "cat", "gnome-keyring-daemon.service")
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if rest, ok := strings.CutPrefix(line, "ExecStart="); ok && rest != "" {
					if rewritten, ok := execStartWithout(rest, "secrets"); ok {
						p.file(filepath.Join(config, "systemd", "user", "gnome-keyring-daemon.service.d", "50-secretvault.conf"),
							"# Written by 'secretvault keyring takeover': gnome-keyring keeps its\n"+
								"# other components, secretvault is the Secret Service.\n"+
								"[Service]\nExecStart=\nExecStart="+rewritten+"\n")
						p.Restart = append(p.Restart, "gnome-keyring-daemon.service")
					} else {
						p.Notes = append(p.Notes, "gnome-keyring runs only its secrets component: stop it with 'systemctl --user mask --now gnome-keyring-daemon.service gnome-keyring-daemon.socket'")
					}
				}
			}
		} else {
			p.Notes = append(p.Notes, "gnome-keyring is not a systemd user service here: log out and back in after the takeover")
		}
	case strings.HasPrefix(base, "ksecretd"), strings.HasPrefix(base, "kwalletd"):
		p.Notes = append(p.Notes, "KWallet serves the Secret Service: turn it off in System Settings > KWallet (or kwalletrc [org.freedesktop.secrets] apiEnabled=false) and restart kwalletd6")
	case strings.HasPrefix(base, "keepassxc"):
		p.Notes = append(p.Notes, "KeePassXC serves the Secret Service: turn off Settings > Secret Service Integration")
	case strings.HasPrefix(base, "oo7"):
		p.Notes = append(p.Notes, "oo7 serves the Secret Service: stop and disable its daemon")
	case exe != "":
		p.Notes = append(p.Notes, filepath.Base(exe)+" holds the keyring: turn off its Secret Service integration")
	}
	planPortal(p)
	return p, nil
}

// portalSecret is the portals.conf key that picks the Secret portal's
// backend, and gnomeKeyringPortal the backend that reaches whoever owns
// org.freedesktop.secrets (gnome-keyring.portal says DBusName=
// org.freedesktop.secrets): after the takeover, secretvaultd.
const (
	portalSecret       = "org.freedesktop.impl.portal.Secret"
	gnomeKeyringPortal = "gnome-keyring"
)

// planPortal makes Flatpak apps' Secret portal reach secretvault. The
// desktop's portals.conf may pick another backend (KDE picks kwallet);
// xdg-desktop-portal reads the first such file it finds, the user's before
// the system's, without merging, so the plan writes a copy of the one in
// force into the user's config, with only the Secret line changed.
func planPortal(p *TakeoverPlan) {
	var dataDirs []string
	for _, d := range filepath.SplitList(orDefault(os.Getenv("XDG_DATA_DIRS"), "/usr/local/share:/usr/share")) {
		dataDirs = append(dataDirs, filepath.Join(d, "xdg-desktop-portal"))
	}
	found := false
	for _, d := range dataDirs {
		if b, err := os.ReadFile(filepath.Join(d, "portals", gnomeKeyringPortal+".portal")); err == nil && strings.Contains(string(b), "DBusName=org.freedesktop.secrets") {
			found = true
			break
		}
	}
	if !found {
		p.Notes = append(p.Notes, "no Secret portal backend reaches org.freedesktop.secrets here (gnome-keyring.portal is not installed): Flatpak apps keep theirs")
		return
	}
	var names []string
	for _, desk := range strings.Split(os.Getenv("XDG_CURRENT_DESKTOP"), ":") {
		if desk != "" {
			names = append(names, strings.ToLower(desk)+"-portals.conf")
		}
	}
	names = append(names, "portals.conf")
	userConf := filepath.Join(userDir("XDG_CONFIG_HOME", ".config"), "xdg-desktop-portal")
	var confDirs []string
	for _, d := range filepath.SplitList(orDefault(os.Getenv("XDG_CONFIG_DIRS"), "/etc/xdg")) {
		confDirs = append(confDirs, filepath.Join(d, "xdg-desktop-portal"))
	}
	for _, n := range names {
		if _, err := os.Stat(filepath.Join(userConf, n)); err == nil {
			p.Notes = append(p.Notes, "for Flatpak apps, set "+portalSecret+"="+gnomeKeyringPortal+" under [preferred] in "+filepath.Join(userConf, n))
			return
		}
	}
	for _, n := range names {
		for _, d := range append(confDirs, dataDirs...) {
			b, err := os.ReadFile(filepath.Join(d, n))
			if err != nil {
				continue
			}
			conf, changed := withPortal(string(b), portalSecret, gnomeKeyringPortal)
			if changed {
				p.file(filepath.Join(userConf, n), "# Written by 'secretvault keyring takeover', from "+filepath.Join(d, n)+":\n"+
					"# the same, but Flatpak apps' secrets come from secretvault.\n"+conf)
				p.Restart = append(p.Restart, "xdg-desktop-portal.service")
			}
			return
		}
	}
	p.file(filepath.Join(userConf, "portals.conf"), "# Written by 'secretvault keyring takeover'.\n[preferred]\n"+portalSecret+"="+gnomeKeyringPortal+"\n")
	p.Restart = append(p.Restart, "xdg-desktop-portal.service")
}

// withPortal sets key=value under [preferred] in a portals.conf,
// reporting whether that changed anything.
func withPortal(conf, key, value string) (string, bool) {
	lines := strings.Split(strings.TrimRight(conf, "\n"), "\n")
	section, preferred := "", -1
	for i, line := range lines {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "[") {
			section = t
			if t == "[preferred]" {
				preferred = i
			}
			continue
		}
		if k, v, ok := strings.Cut(t, "="); ok && section == "[preferred]" && strings.TrimSpace(k) == key {
			if strings.TrimSpace(v) == value {
				return conf, false
			}
			lines[i] = key + "=" + value
			return strings.Join(lines, "\n") + "\n", true
		}
	}
	if preferred < 0 {
		lines = append(lines, "[preferred]")
		preferred = len(lines) - 1
	}
	lines = append(lines[:preferred+1], append([]string{key + "=" + value}, lines[preferred+1:]...)...)
	return strings.Join(lines, "\n") + "\n", true
}

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// ApplyTakeover writes the plan's files, none of which may exist yet, and
// the record that undoes them; previous is the keyring taken over from.
// It returns the files written, as far as it got. The daemon's Secret
// Service is turned on next (secretvault.Client.ServeKeyring), and then
// the plan's units restarted (RestartUnits).
func ApplyTakeover(p *TakeoverPlan, previous string) ([]string, error) {
	state := &TakeoverState{When: time.Now().UTC(), Previous: previous, Restart: p.Restart}
	for _, f := range p.Order {
		if _, err := os.Stat(f); err == nil {
			return nil, fmt.Errorf("%s already exists: not overwriting it", f)
		}
	}
	for _, f := range p.Order {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			return state.Created, err
		}
		if err := os.WriteFile(f, []byte(p.Files[f]), 0o644); err != nil {
			return state.Created, err
		}
		state.Created = append(state.Created, f)
	}
	sp, err := TakeoverPath()
	if err != nil {
		return state.Created, err
	}
	b, _ := json.MarshalIndent(state, "", "  ")
	if err := os.WriteFile(sp, b, 0o600); err != nil {
		return state.Created, err
	}
	return state.Created, nil
}

// RestartFailure is a unit that did not restart.
type RestartFailure struct {
	Unit   string
	Err    error
	Output []byte
}

// RestartUnits reloads systemd's user manager and restarts units, through
// CommandRunner, returning those that failed.
func RestartUnits(units []string) []RestartFailure {
	if len(units) == 0 {
		return nil
	}
	CommandRunner("systemctl", "--user", "daemon-reload")
	var failed []RestartFailure
	for _, r := range units {
		if out, err := CommandRunner("systemctl", "--user", "restart", r); err != nil {
			failed = append(failed, RestartFailure{Unit: r, Err: err, Output: out})
		}
	}
	return failed
}

// UndoTakeover removes the files the takeover made, restarts the units it
// restarted, and forgets it; it returns the files removed, as far as it
// got, and the units that did not restart. The daemon's Secret Service is
// turned off first (secretvault.Client.ServeKeyring).
func UndoTakeover(s *TakeoverState) ([]string, []RestartFailure, error) {
	var removed []string
	for _, f := range s.Created {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return removed, nil, err
		}
		removed = append(removed, f)
	}
	failed := RestartUnits(s.Restart)
	if sp, err := TakeoverPath(); err == nil {
		os.Remove(sp)
	}
	return removed, failed, nil
}
