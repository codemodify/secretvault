package main

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

// `secretvault browser install`: making browsers start secretvault's host
// for KeePassXC-Browser, where they would start KeePassXC's
// keepassxc-proxy.
//
// A browser finds the host by a manifest named for it,
// org.keepassxc.keepassxc_browser.json: in a directory of its own for each
// user on Linux and macOS, or wherever a registry key under
// HKEY_CURRENT_USER says on Windows. install writes secretvault's manifest
// there. A manifest already there (KeePassXC's, usually) is first copied
// into secretvault's own directory, and everything done is recorded in
// browser-install.json, so that uninstall undoes it exactly: the old
// manifest comes back byte for byte with its mode and time (or as the
// link it was), and directories install made go if they are empty.
//
// A manifest changed since install is not ours any more: uninstall leaves
// it alone and keeps the backup, and install will not write over it.
// KeePassXC does that change: when it starts with browser integration on,
// it writes its manifests back.

// browserSpot is where one browser looks for the host.
type browserSpot struct {
	name     string // as --browser takes it
	title    string
	manifest string // the manifest's path
	profile  string // a directory whose presence says the browser is used here
	regKey   string // Windows: the key under HKEY_CURRENT_USER naming the manifest
	firefox  bool   // allowed_extensions, where the others take allowed_origins
}

var browserNames = []string{"firefox", "chrome", "chromium", "brave", "edge", "vivaldi"}

// browserSpots are the browsers' per-user places here.
func browserSpots() ([]browserSpot, error) { return browserSpotsOn(runtime.GOOS) }

// browserSpotsOn are the browsers' per-user places on an OS, from the
// environment (HOME, XDG_CONFIG_HOME, LOCALAPPDATA, APPDATA), which tests
// point elsewhere.
func browserSpotsOn(goos string) ([]browserSpot, error) {
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
		return []browserSpot{
			{"firefox", "Firefox", manifest("firefox"), filepath.Join(roaming, "Mozilla", "Firefox"), key("Mozilla"), true},
			{"chrome", "Google Chrome", manifest("chrome"), filepath.Join(local, "Google", "Chrome", "User Data"), key(`Google\Chrome`), false},
			{"chromium", "Chromium", manifest("chromium"), filepath.Join(local, "Chromium", "User Data"), key("Chromium"), false},
			{"brave", "Brave", manifest("chrome"), filepath.Join(local, "BraveSoftware", "Brave-Browser", "User Data"), key(`Google\Chrome`), false},
			{"edge", "Microsoft Edge", manifest("edge"), filepath.Join(local, "Microsoft", "Edge", "User Data"), key(`Microsoft\Edge`), false},
			{"vivaldi", "Vivaldi", manifest("chrome"), filepath.Join(local, "Vivaldi", "User Data"), key(`Google\Chrome`), false},
		}, nil
	case "darwin":
		lib := filepath.Join(home, "Library", "Application Support")
		spot := func(name, title, dir, profile string, firefox bool) browserSpot {
			return browserSpot{name, title, filepath.Join(lib, dir, "NativeMessagingHosts", file), filepath.Join(lib, profile), "", firefox}
		}
		return []browserSpot{
			spot("firefox", "Firefox", "Mozilla", "Firefox", true),
			spot("chrome", "Google Chrome", "Google/Chrome", "Google/Chrome", false),
			spot("chromium", "Chromium", "Chromium", "Chromium", false),
			spot("brave", "Brave", "BraveSoftware/Brave-Browser", "BraveSoftware/Brave-Browser", false),
			spot("edge", "Microsoft Edge", "Microsoft Edge", "Microsoft Edge", false),
			spot("vivaldi", "Vivaldi", "Vivaldi", "Vivaldi", false),
		}, nil
	}
	config := userDir("XDG_CONFIG_HOME", ".config")
	spot := func(name, title, dir string) browserSpot {
		return browserSpot{name, title, filepath.Join(config, dir, "NativeMessagingHosts", file), filepath.Join(config, dir), "", false}
	}
	return []browserSpot{
		{"firefox", "Firefox", filepath.Join(home, ".mozilla", "native-messaging-hosts", file), filepath.Join(home, ".mozilla"), "", true},
		spot("chrome", "Google Chrome", "google-chrome"),
		spot("chromium", "Chromium", "chromium"),
		spot("brave", "Brave", "BraveSoftware/Brave-Browser"),
		spot("edge", "Microsoft Edge", "microsoft-edge"),
		spot("vivaldi", "Vivaldi", "vivaldi"),
	}, nil
}

// nativeManifest is a native-messaging host manifest.
type nativeManifest struct {
	Name              string   `json:"name"`
	Description       string   `json:"description"`
	Path              string   `json:"path"`
	Type              string   `json:"type"`
	AllowedExtensions []string `json:"allowed_extensions,omitempty"`
	AllowedOrigins    []string `json:"allowed_origins,omitempty"`
}

func manifestFor(s browserSpot, host string) []byte {
	m := nativeManifest{Name: svbrowser.HostName, Description: "secretvault, standing in for KeePassXC behind KeePassXC-Browser",
		Path: host, Type: "stdio"}
	if s.firefox {
		m.AllowedExtensions = svbrowser.FirefoxExtensions
	} else {
		m.AllowedOrigins = svbrowser.ChromeOrigins
	}
	b, _ := json.MarshalIndent(m, "", "    ")
	return append(b, '\n')
}

// browserHostProgram is the program the manifests name: secretvault-browser
// beside this program, if it is this program under that name, else this
// program itself (which knows a browser's arguments when it sees them).
func browserHostProgram() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
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

// browserInstall records what install did.
type browserInstall struct {
	When  time.Time       `json:"when"`
	Host  string          `json:"host"`
	Hosts []installedHost `json:"hosts"`
}

// installedHost is one manifest install wrote.
type installedHost struct {
	Browsers []string        `json:"browsers"`
	Manifest string          `json:"manifest"`
	Sum      string          `json:"sum"` // SHA-256 of what was written: while it matches, the file is ours
	Backup   *manifestBackup `json:"backup,omitempty"`
	MadeDirs []string        `json:"made_dirs,omitempty"` // outermost first
	RegKey   string          `json:"reg_key,omitempty"`
	RegPrev  *string         `json:"reg_prev,omitempty"` // the key's value before; nil when there was no key
}

// manifestBackup is the manifest install replaced.
type manifestBackup struct {
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

func loadBrowserInstall() (*browserInstall, error) {
	p, err := browserStatePath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var s browserInstall
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%s: %w", p, err)
	}
	return &s, nil
}

func (s *browserInstall) save() error {
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
	return writeReplacing(p, append(b, '\n'), 0o600)
}

func (s *browserInstall) find(manifest string) *installedHost {
	for i := range s.Hosts {
		if s.Hosts[i].Manifest == manifest {
			return &s.Hosts[i]
		}
	}
	return nil
}

// writeReplacing writes a file through a temporary one beside it, so it
// is never seen half written.
func writeReplacing(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".secretvault-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// currentManifest is what a manifest path holds now.
type currentManifest struct {
	exists bool
	link   string // where it points, when it is a symbolic link
	sum    string // SHA-256 of its contents (of the file itself, not a link's target)
	host   string // the program it names
	mode   fs.FileMode
	mtime  time.Time
}

func readManifest(path string) (currentManifest, error) {
	var m currentManifest
	st, err := os.Lstat(path)
	if errors.Is(err, fs.ErrNotExist) {
		return m, nil
	}
	if err != nil {
		return m, err
	}
	m.exists, m.mode, m.mtime = true, st.Mode().Perm(), st.ModTime()
	if st.Mode()&fs.ModeSymlink != 0 {
		if m.link, err = os.Readlink(path); err != nil {
			return m, err
		}
	} else if !st.Mode().IsRegular() {
		return m, fmt.Errorf("%s is not a file", path)
	}
	b, err := os.ReadFile(path) // through a link, to say what it names
	if err == nil {
		var nm nativeManifest
		if json.Unmarshal(b, &nm) == nil {
			m.host = nm.Path
		}
		if m.link == "" {
			sum := sha256.Sum256(b)
			m.sum = hex.EncodeToString(sum[:])
		}
	}
	return m, nil
}

// describeHost names the program a manifest starts.
func describeHost(host, ours string) string {
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

// selectSpots picks the browsers named, or those used here.
func selectSpots(spots []browserSpot, names []string) ([]browserSpot, error) {
	var want []string
	for _, n := range names {
		for _, part := range strings.Split(n, ",") {
			if part = strings.ToLower(strings.TrimSpace(part)); part != "" {
				if !slices.Contains(browserNames, part) {
					return nil, fmt.Errorf("unknown browser %q (%s)", part, strings.Join(browserNames, ", "))
				}
				want = append(want, part)
			}
		}
	}
	var out []browserSpot
	for _, s := range spots {
		if len(want) > 0 {
			if slices.Contains(want, s.name) {
				out = append(out, s)
			}
			continue
		}
		if st, err := os.Stat(s.profile); err == nil && st.IsDir() {
			out = append(out, s)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no browser found here (%s); name one with --browser", strings.Join(browserNames, ", "))
	}
	return out, nil
}

// hostPlan is what install does to one manifest.
type hostPlan struct {
	browsers []string
	spot     browserSpot
	current  currentManifest
	regPrev  *string
	skip     string // why nothing is done, if nothing is
}

func (c *cli) browserInstall(args []string) error {
	fs := c.flags("browser install")
	var names multi
	fs.Var(&names, "browser", "install for `NAME` (repeatable; default: every browser used here): "+strings.Join(browserNames, ", "))
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--browser NAME]... [--dry-run]"); err != nil {
		return err
	}
	spots, err := browserSpots()
	if err != nil {
		return err
	}
	chosen, err := selectSpots(spots, names)
	if err != nil {
		return err
	}
	host, err := browserHostProgram()
	if err != nil {
		return err
	}
	state, err := loadBrowserInstall()
	switch {
	case errors.Is(err, fs2NotExist):
		state = &browserInstall{Host: host}
	case err != nil:
		return err
	case state.Host != host:
		return fmt.Errorf("the browsers were set up for %s; run 'secretvault browser uninstall' first", state.Host)
	}

	// One plan per manifest: on Windows, Brave and Vivaldi share Chrome's.
	var plans []*hostPlan
	byManifest := map[string]*hostPlan{}
	for _, s := range chosen {
		if p := byManifest[s.manifest]; p != nil {
			p.browsers = append(p.browsers, s.name)
			continue
		}
		p := &hostPlan{browsers: []string{s.name}, spot: s}
		byManifest[s.manifest] = p
		plans = append(plans, p)
		if p.current, err = readManifest(s.manifest); err != nil {
			return err
		}
		if s.regKey != "" {
			if v, ok, err := registryValue(s.regKey); err != nil {
				return err
			} else if ok {
				p.regPrev = &v
				if cur, err := readManifest(v); err == nil {
					p.current.host = cur.host
				}
			}
		}
		if rec := state.find(s.manifest); rec != nil {
			if p.current.sum == rec.Sum && (s.regKey == "" || p.regPrev != nil && *p.regPrev == s.manifest) {
				p.skip = "already done"
			} else {
				p.skip = "its manifest changed since secretvault installed it (KeePassXC writes its own back when it starts); run 'secretvault browser uninstall' first"
			}
		}
	}

	keepassxc := false
	if *dryRun {
		fmt.Fprintf(c.stdout, "The browsers would start %s for KeePassXC-Browser:\n", host)
	}
	for _, p := range plans {
		label := strings.Join(p.browsers, ", ")
		if p.skip != "" {
			fmt.Fprintf(c.stdout, "  %s: nothing to do: %s\n", label, p.skip)
			continue
		}
		if strings.Contains(strings.ToLower(p.current.host), "keepassxc") {
			keepassxc = true
		}
		if *dryRun {
			c.printHostPlan(p, host)
			continue
		}
		rec, err := installHost(p, host)
		if rec != nil {
			state.Hosts = append(state.Hosts, *rec)
			state.When = time.Now().UTC()
			if serr := state.save(); err == nil {
				err = serr
			}
		}
		if err != nil {
			return fmt.Errorf("%s: %w (undo what was done with 'secretvault browser uninstall')", label, err)
		}
		fmt.Fprintf(c.stdout, "%s: wrote %s\n", label, p.spot.manifest)
		if rec.Backup != nil {
			fmt.Fprintf(c.stdout, "  the manifest it replaced, %s, is kept to put back\n", describeHost(rec.Backup.Host, host))
		}
	}
	if keepassxc {
		fmt.Fprintln(c.stdout, "\nKeePassXC writes its manifests back each time it starts with browser integration on.")
		fmt.Fprintln(c.stdout, "Turn that off in KeePassXC (Settings > Browser Integration), or its advanced option to")
		fmt.Fprintln(c.stdout, "update the manifest files at startup. 'secretvault browser status' shows which host each browser starts.")
	}
	if *dryRun {
		fmt.Fprintln(c.stdout, "\nNothing was changed. Undo an install with 'secretvault browser uninstall'.")
		return nil
	}
	fmt.Fprintln(c.stdout, "\nRestart the browsers, then connect KeePassXC-Browser from its toolbar button.")
	fmt.Fprintln(c.stdout, "Undo with 'secretvault browser uninstall'.")
	return nil
}

func (c *cli) printHostPlan(p *hostPlan, host string) {
	label := strings.Join(p.browsers, ", ")
	switch {
	case p.spot.regKey != "":
		fmt.Fprintf(c.stdout, "  %s: write %s\n", label, p.spot.manifest)
		if p.regPrev != nil {
			fmt.Fprintf(c.stdout, "      point HKEY_CURRENT_USER\\%s at it; it names %s now, to put back on uninstall\n",
				p.spot.regKey, describeHost(p.current.host, host))
		} else {
			fmt.Fprintf(c.stdout, "      make HKEY_CURRENT_USER\\%s, naming it\n", p.spot.regKey)
		}
	case p.current.exists:
		fmt.Fprintf(c.stdout, "  %s: replace %s\n", label, p.spot.manifest)
		fmt.Fprintf(c.stdout, "      it names %s now; a copy is kept, to put back on uninstall\n", describeHost(p.current.host, host))
	default:
		fmt.Fprintf(c.stdout, "  %s: write %s\n", label, p.spot.manifest)
		if made := missingDirs(filepath.Dir(p.spot.manifest)); len(made) > 0 {
			fmt.Fprintf(c.stdout, "      making %s\n", strings.Join(made, ", "))
		}
	}
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
func installHost(p *hostPlan, host string) (*installedHost, error) {
	s := p.spot
	rec := &installedHost{Browsers: p.browsers, Manifest: s.manifest, RegKey: s.regKey}
	data := manifestFor(s, host)
	sum := sha256.Sum256(data)
	rec.Sum = hex.EncodeToString(sum[:])

	rec.MadeDirs = missingDirs(filepath.Dir(s.manifest))
	undo := func() {
		if rec.Backup != nil && rec.Backup.Copy != "" {
			os.Remove(rec.Backup.Copy)
		}
		for i := len(rec.MadeDirs) - 1; i >= 0; i-- {
			os.Remove(rec.MadeDirs[i])
		}
	}
	if err := os.MkdirAll(filepath.Dir(s.manifest), 0o700); err != nil {
		undo()
		return nil, err
	}
	if s.regKey == "" && p.current.exists {
		b, err := backupManifest(p)
		if err != nil {
			undo()
			return nil, err
		}
		rec.Backup = b
	}
	if err := writeReplacing(s.manifest, data, 0o644); err != nil {
		undo()
		return nil, err
	}
	if s.regKey != "" {
		rec.RegPrev = p.regPrev
		if p.regPrev != nil {
			rec.Backup = &manifestBackup{Host: p.current.host}
		}
		if err := setRegistryValue(s.regKey, s.manifest); err != nil {
			return rec, err
		}
	}
	return rec, nil
}

// backupManifest keeps the manifest about to be replaced: a copy in
// secretvault's own directory, or where it points, if it is a link.
func backupManifest(p *hostPlan) (*manifestBackup, error) {
	cur := p.current
	b := &manifestBackup{Link: cur.link, Mode: cur.mode, ModTime: cur.mtime, Host: cur.host}
	if cur.link != "" {
		return b, nil
	}
	data, err := os.ReadFile(p.spot.manifest)
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
		name := p.browsers[0] + "-" + filepath.Base(p.spot.manifest)
		if n > 1 {
			name = fmt.Sprintf("%s-%d-%s", p.browsers[0], n, filepath.Base(p.spot.manifest))
		}
		b.Copy = filepath.Join(dir, name)
		err := writeNew(b.Copy, data)
		if err == nil {
			return b, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, fmt.Errorf("keeping the old manifest: %w", err)
		}
	}
}

func (c *cli) browserUninstall(args []string) error {
	fs := c.flags("browser uninstall")
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--dry-run]"); err != nil {
		return err
	}
	state, err := loadBrowserInstall()
	if errors.Is(err, fs2NotExist) {
		return errors.New("secretvault is not installed in any browser")
	}
	if err != nil {
		return err
	}
	for i, rec := range state.Hosts {
		label := strings.Join(rec.Browsers, ", ")
		ours, err := stillOurs(rec)
		if err != nil {
			return err
		}
		if !ours {
			// Someone else's now: it is forgotten, and its backup left
			// where it is for the person to decide.
			fmt.Fprintf(c.stdout, "%s: %s changed since secretvault installed it: left as it is\n", label, rec.Manifest)
			if rec.Backup != nil && rec.Backup.Copy != "" {
				fmt.Fprintf(c.stdout, "  the manifest it replaced is still in %s\n", rec.Backup.Copy)
			}
			continue
		}
		if *dryRun {
			c.printUndo(rec)
			continue
		}
		if err := uninstallHost(rec); err != nil {
			state.Hosts = state.Hosts[i:]
			state.save()
			return fmt.Errorf("%s: %w", label, err)
		}
		switch {
		case rec.RegKey != "" && rec.RegPrev != nil:
			fmt.Fprintf(c.stdout, "%s: HKEY_CURRENT_USER\\%s names %s again\n", label, rec.RegKey, *rec.RegPrev)
		case rec.RegKey != "":
			fmt.Fprintf(c.stdout, "%s: removed HKEY_CURRENT_USER\\%s\n", label, rec.RegKey)
		case rec.Backup != nil:
			fmt.Fprintf(c.stdout, "%s: put back the manifest naming %s, at %s\n", label, describeHost(rec.Backup.Host, state.Host), rec.Manifest)
		default:
			fmt.Fprintf(c.stdout, "%s: removed %s\n", label, rec.Manifest)
		}
	}
	if *dryRun {
		fmt.Fprintln(c.stdout, "Nothing was changed.")
		return nil
	}
	state.Hosts = nil
	if err := state.save(); err != nil {
		return err
	}
	if h, err := svcore.Home(); err == nil {
		os.Remove(filepath.Join(h, "browser-backup")) // if empty
	}
	return nil
}

func (c *cli) printUndo(rec installedHost) {
	label := strings.Join(rec.Browsers, ", ")
	switch {
	case rec.RegKey != "" && rec.RegPrev != nil:
		fmt.Fprintf(c.stdout, "%s: point HKEY_CURRENT_USER\\%s back at %s, and remove %s\n", label, rec.RegKey, *rec.RegPrev, rec.Manifest)
	case rec.RegKey != "":
		fmt.Fprintf(c.stdout, "%s: remove HKEY_CURRENT_USER\\%s and %s\n", label, rec.RegKey, rec.Manifest)
	case rec.Backup != nil && rec.Backup.Link != "":
		fmt.Fprintf(c.stdout, "%s: make %s a link to %s again\n", label, rec.Manifest, rec.Backup.Link)
	case rec.Backup != nil:
		fmt.Fprintf(c.stdout, "%s: put back %s as it was, from %s\n", label, rec.Manifest, rec.Backup.Copy)
	default:
		fmt.Fprintf(c.stdout, "%s: remove %s\n", label, rec.Manifest)
	}
	for i := len(rec.MadeDirs) - 1; i >= 0; i-- {
		fmt.Fprintf(c.stdout, "  and %s, if empty\n", rec.MadeDirs[i])
	}
}

// stillOurs reports whether a manifest (and, on Windows, its key) is as
// install left it.
func stillOurs(rec installedHost) (bool, error) {
	cur, err := readManifest(rec.Manifest)
	if err != nil {
		return false, err
	}
	if cur.sum != rec.Sum {
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
func uninstallHost(rec installedHost) error {
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
		if err := os.Remove(rec.Manifest); err != nil && !errors.Is(err, fs2NotExist) {
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
		if err := writeReplacing(rec.Manifest, data, b.Mode); err != nil {
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

func (c *cli) browserStatus(args []string) error {
	if _, err := parse(c.flags("browser status"), args, 0, 0, ""); err != nil {
		return err
	}
	spots, err := browserSpots()
	if err != nil {
		return err
	}
	host, err := browserHostProgram()
	if err != nil {
		return err
	}
	state, err := loadBrowserInstall()
	if err != nil && !errors.Is(err, fs2NotExist) {
		return err
	}
	if state != nil {
		host = state.Host
		fmt.Fprintf(c.stdout, "Installed %s, starting %s (undo with 'secretvault browser uninstall').\n\n",
			state.When.Local().Format("2006-01-02 15:04"), state.Host)
	}
	for _, s := range spots {
		path := s.manifest
		if s.regKey != "" {
			v, ok, err := registryValue(s.regKey)
			if err != nil {
				return err
			}
			if !ok {
				fmt.Fprintf(c.stdout, "%-9s no host (no HKEY_CURRENT_USER\\%s)\n", s.name, s.regKey)
				continue
			}
			path = v
		}
		cur, err := readManifest(path)
		if err != nil {
			fmt.Fprintf(c.stdout, "%-9s %s: %v\n", s.name, path, err)
			continue
		}
		line := fmt.Sprintf("%-9s ", s.name)
		switch {
		case !cur.exists:
			used := "not used here"
			if st, err := os.Stat(s.profile); err == nil && st.IsDir() {
				used = "used here"
			}
			line += "no host (" + used + ")"
		default:
			line += describeHost(cur.host, host)
		}
		if state != nil {
			if rec := state.find(s.manifest); rec != nil {
				if ours, _ := stillOurs(*rec); !ours {
					line += "; changed since secretvault installed it"
				} else if rec.Backup != nil {
					line += "; " + describeHost(rec.Backup.Host, host) + " kept, to put back"
				}
			}
		}
		fmt.Fprintln(c.stdout, line)
	}
	return nil
}
