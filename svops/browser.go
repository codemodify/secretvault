package svops

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svbrowser"
	"github.com/codemodify/secretvault/svcore"
)

// Making browsers start secretvault's host for KeePassXC-Browser, where
// they would start KeePassXC's keepassxc-proxy: PlanBrowserInstall and
// its Apply, UninstallBrowsers, and BrowserStatus.
//
// A browser finds the host by a manifest named for it,
// org.keepassxc.keepassxc_browser.json: in a directory of its own for each
// user on Linux and macOS, or wherever a registry key under
// HKEY_CURRENT_USER says on Windows. Installing writes secretvault's
// manifest there. A manifest already there (KeePassXC's, usually) is first
// copied into secretvault's own directory, and everything done is recorded
// in browser-install.json, so that uninstalling undoes it exactly: the old
// manifest comes back byte for byte with its mode and time (or as the
// link it was), and directories the install made go if they are empty.
//
// A manifest changed since the install is not ours any more: uninstalling
// leaves it alone and keeps the backup, and installing will not write over
// it. KeePassXC does that change: when it starts with browser integration
// on, it writes its manifests back.

// BrowserSpot is where one browser looks for the host.
type BrowserSpot struct {
	Name     string // as --browser takes it
	Title    string
	Manifest string // the manifest's path
	Profile  string // a directory whose presence says the browser is used here
	RegKey   string // Windows: the key under HKEY_CURRENT_USER naming the manifest
	Firefox  bool   // allowed_extensions, where the others take allowed_origins
}

// BrowserNames are the browsers secretvault installs for.
var BrowserNames = []string{"firefox", "chrome", "chromium", "brave", "edge", "vivaldi"}

// BrowserSpots are the browsers' per-user places here.
func BrowserSpots() ([]BrowserSpot, error) { return BrowserSpotsOn(runtime.GOOS) }

// BrowserSpotsOn are the browsers' per-user places on an OS, from the
// environment (HOME, XDG_CONFIG_HOME, LOCALAPPDATA, APPDATA), which tests
// point elsewhere.
func BrowserSpotsOn(goos string) ([]BrowserSpot, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	file := svbrowser.HostName + ".json"
	switch goos {
	case "windows":
		svHome, err := svcore.Home()
		if err != nil {
			return nil, err
		}
		local, roaming := os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA")
		key := func(vendor string) string {
			return `Software\` + vendor + `\NativeMessagingHosts\` + svbrowser.HostName
		}
		manifest := func(owner string) string {
			return filepath.Join(svHome, "browser", svbrowser.HostName+"_"+owner+".json")
		}
		// Brave and Vivaldi read Chrome's key.
		return []BrowserSpot{
			{"firefox", "Firefox", manifest("firefox"), filepath.Join(roaming, "Mozilla", "Firefox"), key("Mozilla"), true},
			{"chrome", "Google Chrome", manifest("chrome"), filepath.Join(local, "Google", "Chrome", "User Data"), key(`Google\Chrome`), false},
			{"chromium", "Chromium", manifest("chromium"), filepath.Join(local, "Chromium", "User Data"), key("Chromium"), false},
			{"brave", "Brave", manifest("chrome"), filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data"), key(`Google\Chrome`), false},
			{"edge", "Microsoft Edge", manifest("edge"), filepath.Join(local, "Microsoft", "Edge", "User Data"), key(`Microsoft\Edge`), false},
			{"vivaldi", "Vivaldi", manifest("chrome"), filepath.Join(local, "Vivaldi", "User Data"), key(`Google\Chrome`), false},
		}, nil
	case "darwin":
		lib := filepath.Join(home, "Library", "Application Support")
		spot := func(name, title, dir, profile string, firefox bool) BrowserSpot {
			return BrowserSpot{name, title, filepath.Join(lib, dir, "NativeMessagingHosts", file), filepath.Join(lib, profile), "", firefox}
		}
		return []BrowserSpot{
			spot("firefox", "Firefox", "Mozilla", "Firefox", true),
			spot("chrome", "Google Chrome", "Google/Chrome", "Google/Chrome", false),
			spot("chromium", "Chromium", "Chromium", "Chromium", false),
			spot("brave", "Brave", "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser", false),
			spot("edge", "Microsoft Edge", "Microsoft Edge", "Microsoft Edge", false),
			spot("vivaldi", "Vivaldi", "Vivaldi", "Vivaldi", false),
		}, nil
	}
	config := userDir("XDG_CONFIG_HOME", ".config")
	spot := func(name, title, dir string) BrowserSpot {
		return BrowserSpot{name, title, filepath.Join(config, dir, "NativeMessagingHosts", file), filepath.Join(config, dir), "", false}
	}
	return []BrowserSpot{
		{"firefox", "Firefox", filepath.Join(home, ".mozilla", "native-messaging-hosts", file), filepath.Join(home, ".mozilla"), "", true},
		spot("chrome", "Google Chrome", "google-chrome"),
		spot("chromium", "Chromium", "chromium"),
		spot("brave", "Brave", "BraveSoftware/Brave-Browser"),
		spot("edge", "Microsoft Edge", "microsoft-edge"),
		spot("vivaldi", "Vivaldi", "vivaldi"),
	}, nil
}

// Used reports whether the browser is used here: its profile directory
// is there.
func (s BrowserSpot) Used() bool {
	st, err := os.Stat(s.Profile)
	return err == nil && st.IsDir()
}

// NativeManifest is a native-messaging host manifest.
type NativeManifest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
	AllowedOrigins    []string `json:"allowed_origins,omitempty"`
}

// ManifestFor is secretvault's manifest for a browser, naming host.
func ManifestFor(s BrowserSpot, host string) []byte {
	m := NativeManifest{Name: svbrowser.HostName, Description: "secretvault, standing in for KeePassXC behind KeePassXC-Browser",
		Path: host, Type: "stdio"}
	if s.Firefox {
		m.AllowedExtensions = svbrowser.FirefoxExtensions
	} else {
		m.AllowedOrigins = svbrowser.ChromeOrigins
	}
	b, _ := json.MarshalIndent(m, "", "    ")
	return append(b, '\n')
}

// BrowserHostProgram is the program the manifests name: secretvault-browser
// beside the secretvault CLI, if it is the CLI under that name, else the
// CLI itself (which knows a browser's arguments when it sees them). cli is
// the CLI's path: "" for this program, which must then be the CLI (the
// managers pass CLIProgram(), and have none to offer when it is "").
func BrowserHostProgram(cli string) (string, error) {
	exe := cli
	if exe == "" {
		var err error
		if exe, err = Executable(); err != nil {
			return "", err
		}
	}
	name := "secretvault-browser"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	helper := filepath.Join(filepath.Dir(exe), name)
	if a, err := os.Stat(helper); err == nil {
		if b, err := os.Stat(exe); err == nil && os.SameFile(a, b) {
			return helper, nil
		}
	}
	return exe, nil
}

// BrowserInstall records what an install did.
type BrowserInstall struct {
	When  time.Time       `json:"when"`
	Host  string          `json:"host"`
	Hosts []InstalledHost `json:"hosts"`
}

// InstalledHost is one manifest an install wrote.
type InstalledHost struct {
	Browsers []string        `json:"browsers"`
	Manifest string          `json:"manifest"`
	Sum      string          `json:"sum"` // SHA-256 of what was written: while it matches, the file is ours
	Backup   *ManifestBackup `json:"backup,omitempty"`
	MadeDirs []string        `json:"made_dirs,omitempty"` // outermost first
	RegKey   string          `json:"reg_key,omitempty"`
	RegPrev  *string         `json:"reg_prev,omitempty"` // the key's value before; nil when there was no key
}

// ManifestBackup is the manifest an install replaced.
type ManifestBackup struct {
	Copy    string      `json:"copy,omitempty"` // a copy, in secretvault's own directory
	Link    string      `json:"link,omitempty"` // or where it pointed, when it was a symbolic link
	Mode    fs.FileMode `json:"mode"`
	ModTime time.Time   `json:"mod_time"`
	Host    string      `json:"host,omitempty"` // the program it named
}

func browserStatePath() (string, error) {
	h, err := svcore.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "browser-install.json"), nil
}

// LoadBrowserInstall reads the record of the install; an error satisfying
// errors.Is(err, fs.ErrNotExist) means there is none.
func LoadBrowserInstall() (*BrowserInstall, error) {
	p, err := browserStatePath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var s BrowserInstall
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &s, nil
}

// Save writes the record, or removes it when it holds nothing.
func (s *BrowserInstall) Save() error {
	p, err := browserStatePath()
	if err != nil {
		return err
	}
	if len(s.Hosts) == 0 {
		err := os.Remove(p)
		if errors.Is(err, fs.ErrNotExist) {
			err = nil
		}
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(s, "", "  ")
	return WriteReplacing(p, append(b, '\n'), 0o600)
}

// Find is the record of the manifest at a path.
func (s *BrowserInstall) Find(manifest string) *InstalledHost {
	for i := range s.Hosts {
		if s.Hosts[i].Manifest == manifest {
			return &s.Hosts[i]
		}
	}
	return nil
}

// CurrentManifest is what a manifest path holds now.
type CurrentManifest struct {
	Exists bool
	Link   string // where it points, when it is a symbolic link
	Sum    string // SHA-256 of its contents (of the file itself, not a link's target)
	Host   string // the program it names
	Mode   fs.FileMode
	MTime  time.Time
}

// ReadManifest says what a manifest path holds.
func ReadManifest(path string) (CurrentManifest, error) {
	var m CurrentManifest
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	m.Exists, m.Mode, m.MTime = true, st.Mode().Perm(), st.ModTime()
	if st.Mode()&fs.ModeSymlink != 0 {
		if m.Link, err = os.Readlink(path); err != nil {
			return m, err
		}
	} else if !st.Mode().IsRegular() {
		return m, fmt.Errorf("%s is not a file", path)
	}
	b, err := os.ReadFile(path) // through a link, to say what it names
	if err == nil {
		var nm NativeManifest
		if json.Unmarshal(b, &nm) == nil {
			m.Host = nm.Path
		}
		if m.Link == "" {
			sum := sha256.Sum256(b)
			m.Sum = hex.EncodeToString(sum[:])
		}
	}
	return m, nil
}

// DescribeHost names the program a manifest starts, ours being secretvault.
func DescribeHost(host, ours string) string {
	switch {
	case host == "":
		return "a manifest naming no program"
	case host == ours:
		return "secretvault (" + host + ")"
	case strings.Contains(strings.ToLower(filepath.Base(host)), "keepassxc"):
		return "KeePassXC (" + host + ")"
	}
	return "another program (" + host + ")"
}

// SelectSpots picks the browsers named (each name may list several,
// comma-separated), or, with none named, those used here.
func SelectSpots(spots []BrowserSpot, names []string) ([]BrowserSpot, error) {
	var want []string
	for _, n := range names {
		for _, part := range strings.Split(n, ",") {
			if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
				if !slices.Contains(BrowserNames, part) {
					return nil, fmt.Errorf("unknown browser %q (%s)", part, strings.Join(BrowserNames, ", "))
				}
				want = append(want, part)
			}
		}
	}
	var out []BrowserSpot
	for _, s := range spots {
		if len(want) > 0 {
			if slices.Contains(want, s.Name) {
				out = append(out, s)
			}
			continue
		}
		if s.Used() {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no browser found here (%s); name one with --browser", strings.Join(BrowserNames, ", "))
	}
	return out, nil
}

// HostPlan is what an install does to one manifest.
type HostPlan struct {
	Browsers []string
	Spot     BrowserSpot
	Current  CurrentManifest
	RegPrev  *string // Windows: the registry key's value now; nil when there is no key
	Skip     string  // why nothing is done, if nothing is
}

// Label names the browsers the manifest is for.
func (p *HostPlan) Label() string { return strings.Join(p.Browsers, ", ") }

// MakesDirs are the directories writing the manifest makes, outermost
// first.
func (p *HostPlan) MakesDirs() []string { return missingDirs(filepath.Dir(p.Spot.Manifest)) }

// BrowserInstallPlan is what an install would do: one HostPlan per
// manifest (on Windows, Brave and Vivaldi share Chrome's).
type BrowserInstallPlan struct {
	Host      string // the program the manifests name
	Hosts     []*HostPlan
	KeePassXC bool // a manifest to replace names KeePassXC, which writes its own back
	state     *BrowserInstall
}

// PlanBrowserInstall works out an install for the browsers named (those
// used here when none are), for the CLI at cli ("" for this program).
// It changes nothing.
func PlanBrowserInstall(names []string, cli string) (*BrowserInstallPlan, error) {
	spots, err := BrowserSpots()
	if err != nil {
		return nil, err
	}
	chosen, err := SelectSpots(spots, names)
	if err != nil {
		return nil, err
	}
	host, err := BrowserHostProgram(cli)
	if err != nil {
		return nil, err
	}
	state, err := LoadBrowserInstall()
	switch {
	case errors.Is(err, fs.ErrNotExist):
		state = &BrowserInstall{Host: host}
	case err != nil:
		return nil, err
	case state.Host != host:
		return nil, fmt.Errorf("the browsers were set up for %s; run 'secretvault browser uninstall' first", state.Host)
	}
	plan := &BrowserInstallPlan{Host: host, state: state}
	byManifest := map[string]*HostPlan{}
	for _, s := range chosen {
		if p := byManifest[s.Manifest]; p != nil {
			p.Browsers = append(p.Browsers, s.Name)
			continue
		}
		p := &HostPlan{Browsers: []string{s.Name}, Spot: s}
		byManifest[s.Manifest] = p
		plan.Hosts = append(plan.Hosts, p)
		if p.Current, err = ReadManifest(s.Manifest); err != nil {
			return nil, err
		}
		if s.RegKey != "" {
			if v, ok, err := registryValue(s.RegKey); err != nil {
				return nil, err
			} else if ok {
				p.RegPrev = &v
				if cur, err := ReadManifest(v); err == nil {
					p.Current.Host = cur.Host
				}
			}
		}
		if rec := state.Find(s.Manifest); rec != nil {
			if p.Current.Sum == rec.Sum && (s.RegKey == "" || p.RegPrev != nil && *p.RegPrev == s.Manifest) {
				p.Skip = "already done"
			} else {
				p.Skip = "its manifest changed since secretvault installed it (KeePassXC writes its own back when it starts); run 'secretvault browser uninstall' first"
			}
		}
	}
	for _, p := range plan.Hosts {
		if p.Skip == "" && strings.Contains(strings.ToLower(p.Current.Host), "keepassxc") {
			plan.KeePassXC = true
		}
	}
	return plan, nil
}

// Apply installs one host of the plan (not one it skips), and records it.
// It returns the record of what it did; on an error, as far as it got,
// which is recorded too, for an uninstall to undo.
func (plan *BrowserInstallPlan) Apply(p *HostPlan) (*InstalledHost, error) {
	if p.Skip != "" {
		return nil, fmt.Errorf("%s: nothing to do: %s", p.Label(), p.Skip)
	}
	rec, err := installHost(p, plan.Host)
	if rec != nil {
		plan.state.Hosts = append(plan.state.Hosts, *rec)
		plan.state.When = time.Now().UTC()
		if serr := plan.state.Save(); err == nil {
			err = serr
		}
	}
	return rec, err
}

// missingDirs are the directories that making dir would create, outermost
// first.
func missingDirs(dir string) []string {
	var out []string
	for d := dir; ; d = filepath.Dir(d) {
		if _, err := os.Lstat(d); err == nil || filepath.Dir(d) == d {
			break
		}
		out = append([]string{d}, out...)
	}
	return out
}

// installHost writes one manifest, and returns the record of what it did
// (as far as it got, when it fails).
func installHost(p *HostPlan, host string) (*InstalledHost, error) {
	s := p.Spot
	rec := &InstalledHost{Browsers: p.Browsers, Manifest: s.Manifest, RegKey: s.RegKey}
	data := ManifestFor(s, host)
	sum := sha256.Sum256(data)
	rec.Sum = hex.EncodeToString(sum[:])

	rec.MadeDirs = missingDirs(filepath.Dir(s.Manifest))
	undo := func() {
		if rec.Backup != nil && rec.Backup.Copy != "" {
			os.Remove(rec.Backup.Copy)
		}
		for i := len(rec.MadeDirs) - 1; i >= 0; i-- {
			os.Remove(rec.MadeDirs[i])
		}
	}
	if err := os.MkdirAll(filepath.Dir(s.Manifest), 0o700); err != nil {
		undo()
		return nil, err
	}
	if s.RegKey == "" && p.Current.Exists {
		b, err := backupManifest(p)
		if err != nil {
			undo()
			return nil, err
		}
		rec.Backup = b
	}
	if err := WriteReplacing(s.Manifest, data, 0o644); err != nil {
		undo()
		return nil, err
	}
	if s.RegKey != "" {
		rec.RegPrev = p.RegPrev
		if p.RegPrev != nil {
			rec.Backup = &ManifestBackup{Host: p.Current.Host}
		}
		if err := setRegistryValue(s.RegKey, s.Manifest); err != nil {
			return rec, err
		}
	}
	return rec, nil
}

// backupManifest keeps the manifest about to be replaced: a copy in
// secretvault's own directory, or where it points, if it is a link.
func backupManifest(p *HostPlan) (*ManifestBackup, error) {
	cur := p.Current
	b := &ManifestBackup{Link: cur.Link, Mode: cur.Mode, ModTime: cur.MTime, Host: cur.Host}
	if cur.Link != "" {
		return b, nil
	}
	data, err := os.ReadFile(p.Spot.Manifest)
	if err != nil {
		return nil, err
	}
	h, err := svcore.Home()
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(h, "browser-backup")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// A backup an earlier uninstall left (of a manifest changed since) is
	// kept too.
	for n := 1; ; n++ {
		name := p.Browsers[0] + "-" + filepath.Base(p.Spot.Manifest)
		if n > 1 {
			name = fmt.Sprintf("%s-%d-%s", p.Browsers[0], n, filepath.Base(p.Spot.Manifest))
		}
		b.Copy = filepath.Join(dir, name)
		err := WriteNew(b.Copy, data)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("keeping the old manifest: %w", err)
		}
	}
}

// ErrNoBrowserInstall says secretvault is installed in no browser.
var ErrNoBrowserInstall = errors.New("secretvault is not installed in any browser")

// Uninstalled is what an uninstall did, or would do, to one manifest.
type Uninstalled struct {
	InstalledHost
	Host    string // the program the install named, to describe the backup's against
	Changed bool   // the manifest changed since: left as it is, and forgotten
}

// Label names the browsers the manifest is for.
func (u *Uninstalled) Label() string { return strings.Join(u.Browsers, ", ") }

// UninstallBrowsers undoes the install, every manifest that is still as
// it left it, and forgets it; with dryRun it changes nothing, and says
// what it would do. It returns what it did, as far as it got.
func UninstallBrowsers(dryRun bool) ([]Uninstalled, error) {
	state, err := LoadBrowserInstall()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoBrowserInstall
	}
	if err != nil {
		return nil, err
	}
	var done []Uninstalled
	for i, rec := range state.Hosts {
		ours, err := StillOurs(rec)
		if err != nil {
			return done, err
		}
		u := Uninstalled{InstalledHost: rec, Host: state.Host, Changed: !ours}
		if ours && !dryRun {
			if err := uninstallHost(rec); err != nil {
				state.Hosts = state.Hosts[i:]
				state.Save()
				return done, fmt.Errorf("%s: %w", u.Label(), err)
			}
		}
		done = append(done, u)
	}
	if dryRun {
		return done, nil
	}
	state.Hosts = nil
	if err := state.Save(); err != nil {
		return done, err
	}
	if h, err := svcore.Home(); err == nil {
		os.Remove(filepath.Join(h, "browser-backup")) // if empty
	}
	return done, nil
}

// StillOurs reports whether a manifest (and, on Windows, its key) is as
// the install left it.
func StillOurs(rec InstalledHost) (bool, error) {
	cur, err := ReadManifest(rec.Manifest)
	if err != nil {
		return false, err
	}
	if cur.Sum != rec.Sum {
		return false, nil
	}
	if rec.RegKey != "" {
		v, ok, err := registryValue(rec.RegKey)
		if err != nil || !ok || v != rec.Manifest {
			return false, err
		}
	}
	return true, nil
}

// uninstallHost undoes installHost.
func uninstallHost(rec InstalledHost) error {
	if rec.RegKey != "" {
		var err error
		if rec.RegPrev != nil {
			err = setRegistryValue(rec.RegKey, *rec.RegPrev)
		} else {
			err = deleteRegistryKey(rec.RegKey)
		}
		if err != nil {
			return err
		}
	}
	b := rec.Backup
	switch {
	case rec.RegKey != "" || b == nil:
		if err := os.Remove(rec.Manifest); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	case b.Link != "":
		tmp := rec.Manifest + ".secretvault-link"
		os.Remove(tmp)
		if err := os.Symlink(b.Link, tmp); err != nil {
			return err
		}
		if err := os.Rename(tmp, rec.Manifest); err != nil {
			os.Remove(tmp)
			return err
		}
	default:
		data, err := os.ReadFile(b.Copy)
		if err != nil {
			return fmt.Errorf("the kept manifest: %w", err)
		}
		if err := WriteReplacing(rec.Manifest, data, b.Mode); err != nil {
			return err
		}
		if err := os.Chtimes(rec.Manifest, b.ModTime, b.ModTime); err != nil {
			return err
		}
		if again, err := os.ReadFile(rec.Manifest); err != nil || !bytes.Equal(again, data) {
			return fmt.Errorf("%s did not come back as it was", rec.Manifest)
		}
		os.Remove(b.Copy)
	}
	for i := len(rec.MadeDirs) - 1; i >= 0; i-- {
		os.Remove(rec.MadeDirs[i]) // only if empty
	}
	return nil
}

// BrowserState is which host one browser starts.
type BrowserState struct {
	Spot    BrowserSpot
	Path    string // the manifest it reads (from its registry key, on Windows)
	NoKey   bool   // Windows: there is no registry key, so no host
	Err     error  // the manifest could not be read
	Current CurrentManifest
	Ours    bool            // the install's record has it
	Changed bool            // and it changed since
	Backup  *ManifestBackup // what the install replaced, kept to put back
}

// BrowserStatus says which host each browser starts, with the record of
// the install (nil when there is none) and the program secretvault's
// manifests name (the install's, else BrowserHostProgram(cli)).
func BrowserStatus(cli string) (*BrowserInstall, string, []BrowserState, error) {
	spots, err := BrowserSpots()
	if err != nil {
		return nil, "", nil, err
	}
	host, err := BrowserHostProgram(cli)
	if err != nil {
		return nil, "", nil, err
	}
	state, err := LoadBrowserInstall()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, "", nil, err
	}
	if state != nil {
		host = state.Host
	}
	var out []BrowserState
	for _, s := range spots {
		st := BrowserState{Spot: s, Path: s.Manifest}
		if s.RegKey != "" {
			v, ok, err := registryValue(s.RegKey)
			if err != nil {
				return nil, "", nil, err
			}
			if !ok {
				st.NoKey = true
				out = append(out, st)
				continue
			}
			st.Path = v
		}
		if st.Current, st.Err = ReadManifest(st.Path); st.Err != nil {
			out = append(out, st)
			continue
		}
		if state != nil {
			if rec := state.Find(s.Manifest); rec != nil {
				st.Ours = true
				ours, _ := StillOurs(*rec)
				st.Changed = !ours
				st.Backup = rec.Backup
			}
		}
		out = append(out, st)
	}
	return state, host, out, nil
}
