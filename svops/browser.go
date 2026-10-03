package svops

import (
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

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svext"
)

// Making browsers start secretvault's native-messaging host:
// PlanBrowserInstall and its Apply, UninstallBrowsers, and BrowserStatus.
// The host (NativeHosts) is the secretvault CLI, as
// io.github.codemodify.secretvault, for secretvault's own extension
// (browser/extension, svext).
//
// A browser finds a host by a manifest named for it (the host's name and
// .json): in a directory of its own for each user on Linux and macOS, or
// wherever a registry key under HKEY_CURRENT_USER says on Windows.
// Installing writes secretvault's manifest there, and records everything
// it did in browser-install.json, so that uninstalling undoes it exactly:
// the manifest (and on Windows its key) goes, and directories the install
// made go if they are empty. A manifest or key already there, which
// secretvault did not write, is left alone: installing does nothing for
// that browser until it is gone.
//
// A manifest changed since the install is not ours any more: uninstalling
// leaves it alone, and installing will not write over it.

// NativeHost is a native-messaging host secretvault can be.
type NativeHost struct {
	Name        string   // the host's name; its manifest is Name.json
	Title       string   // for people
	Description string   // the manifest's
	Firefox     []string // the extensions it serves in Firefox (allowed_extensions)
	Chrome      []string // and in Chromium's family (allowed_origins)
}

var (
	// ExtensionHost is secretvault's own extension's host.
	ExtensionHost = NativeHost{Name: svext.HostName, Title: "the secretvault extension",
		Description: "secretvault, for its browser extension", Firefox: []string{svext.FirefoxID}, Chrome: []string{svext.ChromeOrigin}}

	// NativeHosts are the hosts secretvault can be: the extension's.
	NativeHosts = []NativeHost{ExtensionHost}
)

// NativeHostNamed is the host of a name, if secretvault is it.
func NativeHostNamed(name string) (NativeHost, bool) {
	for _, h := range NativeHosts {
		if h.Name == name {
			return h, true
		}
	}
	return NativeHost{}, false
}

// BrowserSpot is where one browser looks for one host.
type BrowserSpot struct {
	Name     string // as --browser takes it
	Title    string
	Manifest string // the manifest's path
	Profile  string // a directory whose presence says the browser is used here
	RegKey   string // Windows: the key under HKEY_CURRENT_USER naming the manifest
	Firefox  bool   // allowed_extensions, where the others take allowed_origins
	Host     string // the host's name (NativeHost.Name)
}

// BrowserNames are the browsers secretvault installs for.
var BrowserNames = []string{"firefox", "chrome", "chromium", "brave", "edge", "vivaldi"}

// BrowserSpots are the browsers' per-user places here, for host h.
func BrowserSpots(h NativeHost) ([]BrowserSpot, error) { return BrowserSpotsOn(runtime.GOOS, h) }

// BrowserSpotsOn are the browsers' per-user places on an OS for host h,
// from the environment (HOME, XDG_CONFIG_HOME, LOCALAPPDATA, APPDATA),
// which tests point elsewhere.
func BrowserSpotsOn(goos string, h NativeHost) ([]BrowserSpot, error) {
	spots, err := spotsOn(goos, h.Name)
	for i := range spots {
		spots[i].Host = h.Name
	}
	return spots, err
}

func spotsOn(goos, hostName string) ([]BrowserSpot, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	file := hostName + ".json"
	switch goos {
	case "windows":
		svHome, err := svcore.Home()
		if err != nil {
			return nil, err
		}
		local, roaming := os.Getenv("LOCALAPPDATA"), os.Getenv("APPDATA")
		key := func(vendor string) string {
			return `Software\` + vendor + `\NativeMessagingHosts\` + hostName
		}
		manifest := func(owner string) string {
			return filepath.Join(svHome, "browser", hostName+"_"+owner+".json")
		}
		// Brave and Vivaldi read Chrome's key.
		return []BrowserSpot{
			{"firefox", "Firefox", manifest("firefox"), filepath.Join(roaming, "Mozilla", "Firefox"), key("Mozilla"), true, hostName},
			{"chrome", "Google Chrome", manifest("chrome"), filepath.Join(local, "Google", "Chrome", "User Data"), key(`Google\Chrome`), false, hostName},
			{"chromium", "Chromium", manifest("chromium"), filepath.Join(local, "Chromium", "User Data"), key("Chromium"), false, hostName},
			{"brave", "Brave", manifest("chrome"), filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data"), key(`Google\Chrome`), false, hostName},
			{"edge", "Microsoft Edge", manifest("edge"), filepath.Join(local, "Microsoft", "Edge", "User Data"), key(`Microsoft\Edge`), false, hostName},
			{"vivaldi", "Vivaldi", manifest("chrome"), filepath.Join(local, "Vivaldi", "User Data"), key(`Google\Chrome`), false, hostName},
		}, nil
	case "darwin":
		lib := filepath.Join(home, "Library", "Application Support")
		spot := func(name, title, dir, profile string, firefox bool) BrowserSpot {
			return BrowserSpot{name, title, filepath.Join(lib, dir, "NativeMessagingHosts", file), filepath.Join(lib, profile), "", firefox, hostName}
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
		return BrowserSpot{name, title, filepath.Join(config, dir, "NativeMessagingHosts", file), filepath.Join(config, dir), "", false, hostName}
	}
	return []BrowserSpot{
		{"firefox", "Firefox", filepath.Join(home, ".mozilla", "native-messaging-hosts", file), filepath.Join(home, ".mozilla"), "", true, hostName},
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

// ManifestFor is secretvault's manifest for a browser's spot, naming the
// program host. It lets only the extensions the spot's host serves start
// it.
func ManifestFor(s BrowserSpot, host string) []byte {
	h, _ := NativeHostNamed(s.Host)
	m := NativeManifest{Name: h.Name, Description: h.Description, Path: host, Type: "stdio"}
	if s.Firefox {
		m.AllowedExtensions = h.Firefox
	} else {
		m.AllowedOrigins = h.Chrome
	}
	b, _ := json.MarshalIndent(m, "", "    ")
	return append(b, '\n')
}

// BrowserHostProgram is the program the manifests name: secretvault-browser
// beside the secretvault CLI, if it is the CLI under that name, else the
// CLI itself (which knows a browser's arguments when it sees them). cli is
// the CLI's path, links resolved: the CLI passes its own (Executable), the
// managers CLIProgram().
func BrowserHostProgram(cli string) (string, error) {
	if cli == "" {
		return "", ErrNoCLI
	}
	exe := cli
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
	Browsers []string `json:"browsers"`
	Manifest string   `json:"manifest"`
	Sum      string   `json:"sum"`                 // SHA-256 of what was written: while it matches, the file is ours
	MadeDirs []string `json:"made_dirs,omitempty"` // outermost first
	RegKey   string   `json:"reg_key,omitempty"`
	HostName string   `json:"host_name,omitempty"` // the native host's
}

// NativeHost is the host the manifest is for.
func (r InstalledHost) NativeHost() NativeHost {
	h, _ := NativeHostNamed(r.HostName)
	return h
}

func browserStatePath() (string, error) {
	h, err := svcore.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "browser-install.json"), nil
}

// LoadBrowserInstall reads the record of the install; an error satisfying
// errors.Is(err, fs.ErrNotExist) means there is none. What it records of
// hosts secretvault no longer is (another extension's host it once
// stood in for) is not read: there is nothing of secretvault's to undo
// there.
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
	s.Hosts = slices.DeleteFunc(s.Hosts, func(h InstalledHost) bool {
		_, ok := NativeHostNamed(h.HostName)
		return !ok
	})
	if len(s.Hosts) == 0 {
		return nil, fmt.Errorf("%s: %w", p, fs.ErrNotExist)
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

// Why a HostPlan does nothing (HostPlan.Skip), and what an install for
// another program says, in the CLI's words; a manager compares against
// them and says them in its own.
const (
	SkipAlreadyDone = "already done"
	SkipChanged     = "its manifest changed since secretvault installed it; run 'secretvault browser uninstall' first"
	SkipOther       = "a manifest secretvault did not write is there; remove it first"
)

// ErrUninstallFirst is an install for another program than the one the
// browsers were set up for.
var ErrUninstallFirst = errors.New("run 'secretvault browser uninstall' first")

// HostPlan is what an install does to one manifest.
type HostPlan struct {
	Browsers []string
	Spot     BrowserSpot
	Current  CurrentManifest
	Skip     string // why nothing is done, if nothing is
}

// Label names the browsers the manifest is for.
func (p *HostPlan) Label() string { return strings.Join(p.Browsers, ", ") }

// MakesDirs are the directories writing the manifest makes, outermost
// first.
func (p *HostPlan) MakesDirs() []string { return missingDirs(filepath.Dir(p.Spot.Manifest)) }

// BrowserInstallPlan is what an install would do: one HostPlan per
// manifest (on Windows, Brave and Vivaldi share Chrome's).
type BrowserInstallPlan struct {
	Native NativeHost // the native host installed
	Host   string     // the program the manifests name
	Hosts  []*HostPlan
	state  *BrowserInstall
}

// PlanBrowserInstall works out an install of the native host h for the
// browsers named (those used here when none are), for the CLI at cli. It
// changes nothing.
func PlanBrowserInstall(h NativeHost, names []string, cli string) (*BrowserInstallPlan, error) {
	spots, err := BrowserSpots(h)
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
		return nil, fmt.Errorf("the browsers were set up for %s; %w", state.Host, ErrUninstallFirst)
	}
	plan := &BrowserInstallPlan{Native: h, Host: host, state: state}
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
		key, hasKey := "", false
		if s.RegKey != "" {
			if key, hasKey, err = registryValue(s.RegKey); err != nil {
				return nil, err
			} else if hasKey {
				if cur, err := ReadManifest(key); err == nil {
					p.Current.Host = cur.Host
				}
			}
		}
		switch rec := state.Find(s.Manifest); {
		case rec != nil && p.Current.Sum == rec.Sum && (s.RegKey == "" || hasKey && key == s.Manifest):
			p.Skip = SkipAlreadyDone
		case rec != nil:
			p.Skip = SkipChanged
		case hasKey || s.RegKey == "" && p.Current.Exists:
			p.Skip = SkipOther
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
	// A plan shown to a person may have waited: what it saw must still
	// be there.
	now, err := ReadManifest(p.Spot.Manifest)
	if err != nil {
		return nil, err
	}
	changed := now.Exists != p.Current.Exists || now.Link != p.Current.Link || now.Sum != p.Current.Sum
	if p.Spot.RegKey != "" {
		_, ok, err := registryValue(p.Spot.RegKey)
		if err != nil {
			return nil, err
		}
		changed = changed || ok
	}
	if changed {
		return nil, fmt.Errorf("%s changed since the plan was made: make it again", p.Spot.Manifest)
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
	rec := &InstalledHost{Browsers: p.Browsers, Manifest: s.Manifest, RegKey: s.RegKey, HostName: s.Host}
	data := ManifestFor(s, host)
	sum := sha256.Sum256(data)
	rec.Sum = hex.EncodeToString(sum[:])

	rec.MadeDirs = missingDirs(filepath.Dir(s.Manifest))
	undo := func() {
		for i := len(rec.MadeDirs) - 1; i >= 0; i-- {
			os.Remove(rec.MadeDirs[i])
		}
	}
	if err := os.MkdirAll(filepath.Dir(s.Manifest), 0o700); err != nil {
		undo()
		return nil, err
	}
	if err := WriteReplacing(s.Manifest, data, 0o644); err != nil {
		undo()
		return nil, err
	}
	if s.RegKey != "" {
		if err := setRegistryValue(s.RegKey, s.Manifest); err != nil {
			return rec, err
		}
	}
	return rec, nil
}

// ErrNoBrowserInstall says secretvault is installed in no browser.
var ErrNoBrowserInstall = errors.New("secretvault is not installed in any browser")

// Uninstalled is what an uninstall did, or would do, to one manifest.
type Uninstalled struct {
	InstalledHost
	Changed bool // the manifest changed since: left as it is, and forgotten
}

// Label names the browsers the manifest is for.
func (u *Uninstalled) Label() string { return strings.Join(u.Browsers, ", ") }

// UninstallBrowsers undoes the install of the native host only (every
// host when nil): every manifest that is still as it left it, and
// forgets it; with dryRun it changes nothing, and says what it would do.
// It returns what it did, as far as it got.
func UninstallBrowsers(only *NativeHost, dryRun bool) ([]Uninstalled, error) {
	state, err := LoadBrowserInstall()
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoBrowserInstall
	}
	if err != nil {
		return nil, err
	}
	var done []Uninstalled
	var kept []InstalledHost
	for i, rec := range state.Hosts {
		if only != nil && rec.NativeHost().Name != only.Name {
			kept = append(kept, rec)
			continue
		}
		ours, err := StillOurs(rec)
		if err != nil {
			return done, err
		}
		u := Uninstalled{InstalledHost: rec, Changed: !ours}
		if ours && !dryRun {
			if err := uninstallHost(rec); err != nil {
				state.Hosts = append(kept, state.Hosts[i:]...)
				state.Save()
				return done, fmt.Errorf("%s: %w", u.Label(), err)
			}
		}
		done = append(done, u)
	}
	if len(done) == 0 {
		return nil, ErrNoBrowserInstall
	}
	if dryRun {
		return done, nil
	}
	state.Hosts = kept
	if err := state.Save(); err != nil {
		return done, err
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
		if err := deleteRegistryKey(rec.RegKey); err != nil {
			return err
		}
	}
	if err := os.Remove(rec.Manifest); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
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
	Ours    bool // the install's record has it
	Changed bool // and it changed since
}

// BrowserStatus says which program each browser starts for each native
// host (the state's Spot.Host says which), with the record of the install
// (nil when there is none) and the program secretvault's manifests name (the
// install's, else BrowserHostProgram(cli)). When a registry key cannot be
// read (Windows), the error comes with what was found before it.
func BrowserStatus(cli string) (*BrowserInstall, string, []BrowserState, error) {
	var spots []BrowserSpot
	for _, h := range NativeHosts {
		s, err := BrowserSpots(h)
		if err != nil {
			return nil, "", nil, err
		}
		spots = append(spots, s...)
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
				return state, host, out, err // with the browsers before it
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
			}
		}
		out = append(out, st)
	}
	return state, host, out, nil
}
