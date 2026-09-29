package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svsecret"
)

// `secretvault keyring`: making secretvault the desktop's keyring (the
// Secret Service, org.freedesktop.secrets) on Linux.
//
//	status     who holds the keyring now
//	import     copy every secret out of the current keyring into a vault
//	takeover   import, then make secretvault the keyring from now on
//	restore    undo takeover exactly
//
// takeover changes only files in the user's own directories, and records
// each change so restore can undo it:
//
//   - a D-Bus activation file for org.freedesktop.secrets pointing at
//     secretvaultd (the user's copy overrides the system's);
//   - for gnome-keyring: its "secrets" autostart entry hidden, and a drop-in
//     for its systemd user service that keeps its other parts (pkcs11) but
//     not the secrets one; then the service is restarted, letting go of the
//     name, which secretvaultd (queued for it) takes.
//
// Other keyrings (KWallet's ksecretd, KeePassXC, oo7) get the steps to do
// by hand: turning off their Secret Service integration is a setting of
// theirs.

// commandRunner runs system commands; tests stand in for it.
var commandRunner = func(name string, args ...string) ([]byte, error) {
	return exec.Command(name, args...).CombinedOutput()
}

func (c *cli) cmdKeyring(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	if runtime.GOOS != "linux" && args[0] != "status" {
		return errors.New("taking over the system keyring is for Linux; on Windows and macOS secretvault bridges instead (docs/architecture.md)")
	}
	switch args[0] {
	case "status":
		return c.keyringStatus(args[1:])
	case "import":
		return c.keyringImport(args[1:])
	case "takeover":
		return c.keyringTakeover(args[1:])
	case "restore":
		return c.keyringRestore(args[1:])
	}
	fmt.Fprintf(c.stderr, "secretvault keyring: unknown subcommand %q (status, import, takeover, restore)\n", args[0])
	return errUsage
}

func (c *cli) keyringStatus(args []string) error {
	if _, err := parse(c.flags("keyring status"), args, 0, 0, ""); err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if bus, err := svdbus.ConnectSession(); err == nil {
		defer bus.Close()
		if o, err := svsecret.CurrentOwner(ctx, bus); err == nil {
			fmt.Fprintf(c.stdout, "keyring:   %s (process %d)\n", describeExe(o.Exe), o.PID)
		} else {
			fmt.Fprintln(c.stdout, "keyring:   none (nothing holds org.freedesktop.secrets)")
		}
	} else {
		fmt.Fprintf(c.stdout, "keyring:   no session bus (%v)\n", err)
	}
	if cl, err := c.daemon(); err == nil {
		if st, err := cl.Status(ctx); err == nil {
			fmt.Fprintf(c.stdout, "secretvault: %s\n", st.SecretService)
		}
	}
	if s, err := loadTakeover(); err == nil {
		fmt.Fprintf(c.stdout, "takeover:  done %s (undo with 'secretvault keyring restore')\n", s.When.Local().Format("2006-01-02 15:04"))
	}
	return nil
}

func describeExe(exe string) string {
	if exe == "" {
		return "an unidentified program"
	}
	return filepath.Base(exe) + " (" + exe + ")"
}

// keyringImport copies every secret out of the current keyring.
func (c *cli) keyringImport(args []string) error {
	fs := c.flags("keyring import")
	prefix := fs.String("prefix", "imported", "put the secrets under this folder")
	dryRun := fs.Bool("dry-run", false, "list what would be imported, and import nothing")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "[--prefix P] [--dry-run]"); err != nil {
		return err
	}
	n, err := c.importFromKeyring(&u, *prefix, *dryRun)
	if err == nil && !*dryRun {
		fmt.Fprintf(c.stdout, "Imported %d secrets.\n", n)
	}
	return err
}

func (c *cli) importFromKeyring(u *unlockFlags, prefix string, dryRun bool) (int, error) {
	bus, err := svdbus.ConnectSession()
	if err != nil {
		return 0, err
	}
	defer bus.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	o, err := svsecret.CurrentOwner(ctx, bus)
	if err != nil {
		return 0, err
	}
	if strings.HasPrefix(filepath.Base(o.Exe), "secretvaultd") {
		return 0, errors.New("secretvault is already the keyring: there is nothing to import")
	}
	fmt.Fprintf(c.stderr, "Reading from %s; it may ask you to unlock it.\n", describeExe(o.Exe))
	kc, err := svsecret.Open(ctx, bus)
	if err != nil {
		return 0, err
	}
	defer kc.Close()
	secrets, warnings, err := kc.ReadAll(ctx)
	if err != nil {
		return 0, err
	}
	defer func() {
		for i := range secrets {
			secrets[i].Wipe()
		}
	}()
	for _, w := range warnings {
		fmt.Fprintln(c.stderr, "warning:", w)
	}
	var cl interface {
		Put(context.Context, string, svrpc.Item) (svrpc.Entry, error)
		List(context.Context, string, string) ([]svrpc.Entry, error)
	}
	taken := map[string]bool{}
	if !dryRun {
		d, err := c.open(u)
		if err != nil {
			return 0, err
		}
		cl = d
		if existing, err := d.List(ctx, c.vault, ""); err == nil {
			for _, e := range existing {
				taken[e.Item.Name] = true
			}
		}
	}
	n := 0
	for _, s := range secrets {
		name := uniqueName(taken, prefix+"/"+pathSafe(s.Collection)+"/"+pathSafe(s.Label))
		taken[name] = true
		if dryRun {
			fmt.Fprintln(c.stdout, name)
			continue
		}
		it := svrpc.Item{Kind: "password", Name: name, Label: s.Label, Attrs: s.Attributes,
			Fields: []svrpc.Field{{Name: "secret", Type: svcore.FieldConcealed, Value: s.Value}}}
		if s.ContentType != "" && s.ContentType != "text/plain" {
			it.Fields = append(it.Fields, svrpc.Field{Name: "content_type", Type: svcore.FieldText, Value: []byte(s.ContentType)})
		}
		if _, err := cl.Put(ctx, c.vault, it); err != nil {
			return n, fmt.Errorf("storing %s: %w", name, err)
		}
		n++
	}
	return n, nil
}

var unsafeSegment = regexp.MustCompile(`[\x00-\x1f\x7f/]`)

// pathSafe makes a label usable as one segment of an item name.
func pathSafe(s string) string {
	s = strings.TrimSpace(unsafeSegment.ReplaceAllString(s, "∕"))
	if s == "" || s == "." || s == ".." {
		return "unnamed"
	}
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func uniqueName(taken map[string]bool, name string) string {
	if !taken[name] {
		return name
	}
	for n := 2; ; n++ {
		if c := fmt.Sprintf("%s (%d)", name, n); !taken[c] {
			return c
		}
	}
}

// takeoverState records what takeover changed.
type takeoverState struct {
	When     time.Time `json:"when"`
	Created  []string  `json:"created"`  // files takeover made, to delete
	Restart  []string  `json:"restart"`  // systemd user units to restart on restore
	Previous string    `json:"previous"` // the keyring it took over from
}

func takeoverPath() (string, error) {
	h, err := svcore.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "keyring-takeover.json"), nil
}

func loadTakeover() (*takeoverState, error) {
	p, err := takeoverPath()
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var s takeoverState
	return &s, json.Unmarshal(b, &s)
}

func userDir(env, fallback string) string {
	if d := os.Getenv(env); filepath.IsAbs(d) {
		return d
	}
	h, _ := os.UserHomeDir()
	return filepath.Join(h, fallback)
}

// plan is a list of changes, shown for --dry-run and then carried out.
type plan struct {
	files   map[string]string // path -> contents
	order   []string
	restart []string
	notes   []string
}

func (p *plan) file(path, contents string) {
	if p.files == nil {
		p.files = map[string]string{}
	}
	p.files[path] = contents
	p.order = append(p.order, path)
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

// planTakeover works out the changes for the keyring at exe.
func planTakeover(exe, daemon string) (*plan, error) {
	p := &plan{}
	services := filepath.Join(userDir("XDG_DATA_HOME", ".local/share"), "dbus-1", "services", "org.freedesktop.secrets.service")
	p.file(services, "[D-BUS Service]\nName=org.freedesktop.secrets\nExec="+daemon+"\n")
	switch base := filepath.Base(exe); {
	case strings.HasPrefix(base, "gnome-keyring-daemon"):
		config := userDir("XDG_CONFIG_HOME", ".config")
		if b, err := os.ReadFile("/etc/xdg/autostart/gnome-keyring-secrets.desktop"); err == nil {
			p.file(filepath.Join(config, "autostart", "gnome-keyring-secrets.desktop"), strings.TrimRight(string(b), "\n")+"\nHidden=true\n")
		}
		out, err := commandRunner("systemctl", "--user", "cat", "gnome-keyring-daemon.service")
		if err == nil {
			for _, line := range strings.Split(string(out), "\n") {
				if rest, ok := strings.CutPrefix(line, "ExecStart="); ok && rest != "" {
					if rewritten, ok := execStartWithout(rest, "secrets"); ok {
						p.file(filepath.Join(config, "systemd", "user", "gnome-keyring-daemon.service.d", "50-secretvault.conf"),
							"# Written by 'secretvault keyring takeover': gnome-keyring keeps its\n"+
								"# other components, secretvault is the Secret Service.\n"+
								"[Service]\nExecStart=\nExecStart="+rewritten+"\n")
						p.restart = append(p.restart, "gnome-keyring-daemon.service")
					} else {
						p.notes = append(p.notes, "gnome-keyring runs only its secrets component: stop it with 'systemctl --user mask --now gnome-keyring-daemon.service gnome-keyring-daemon.socket'")
					}
				}
			}
		} else {
			p.notes = append(p.notes, "gnome-keyring is not a systemd user service here: log out and back in after the takeover")
		}
	case strings.HasPrefix(base, "ksecretd"), strings.HasPrefix(base, "kwalletd"):
		p.notes = append(p.notes, "KWallet serves the Secret Service: turn it off in System Settings > KWallet (or kwalletrc [org.freedesktop.secrets] apiEnabled=false) and restart kwalletd6")
	case strings.HasPrefix(base, "keepassxc"):
		p.notes = append(p.notes, "KeePassXC serves the Secret Service: turn off Settings > Secret Service Integration")
	case strings.HasPrefix(base, "oo7"):
		p.notes = append(p.notes, "oo7 serves the Secret Service: stop and disable its daemon")
	case exe != "":
		p.notes = append(p.notes, filepath.Base(exe)+" holds the keyring: turn off its Secret Service integration")
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
func planPortal(p *plan) {
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
		p.notes = append(p.notes, "no Secret portal backend reaches org.freedesktop.secrets here (gnome-keyring.portal is not installed): Flatpak apps keep theirs")
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
			p.notes = append(p.notes, "for Flatpak apps, set "+portalSecret+"="+gnomeKeyringPortal+" under [preferred] in "+filepath.Join(userConf, n))
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
				p.restart = append(p.restart, "xdg-desktop-portal.service")
			}
			return
		}
	}
	p.file(filepath.Join(userConf, "portals.conf"), "# Written by 'secretvault keyring takeover'.\n[preferred]\n"+portalSecret+"="+gnomeKeyringPortal+"\n")
	p.restart = append(p.restart, "xdg-desktop-portal.service")
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

func (c *cli) keyringTakeover(args []string) error {
	fs := c.flags("keyring takeover")
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	noImport := fs.Bool("no-import", false, "do not copy the current keyring's secrets first")
	prefix := fs.String("prefix", "imported", "folder for imported secrets")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "[--dry-run] [--no-import]"); err != nil {
		return err
	}
	if s, err := loadTakeover(); err == nil {
		return fmt.Errorf("the takeover was already done on %s", s.When.Local().Format("2006-01-02"))
	}
	daemon := siblingDaemon()
	if daemon == "" {
		return errors.New("no secretvaultd beside this program")
	}
	ctx, cancel := c.ctx()
	defer cancel()
	exe := ""
	if bus, err := svdbus.ConnectSession(); err == nil {
		if o, err := svsecret.CurrentOwner(ctx, bus); err == nil {
			exe = o.Exe
		}
		bus.Close()
	}
	p, err := planTakeover(exe, daemon)
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintf(c.stdout, "The keyring now: %s\n\n", describeExe(exe))
		if !*noImport && exe != "" {
			fmt.Fprintln(c.stdout, "1. Import its secrets (see 'secretvault keyring import --dry-run').")
		}
		for _, f := range p.order {
			fmt.Fprintf(c.stdout, "- write %s\n", f)
		}
		for _, r := range p.restart {
			fmt.Fprintf(c.stdout, "- restart %s (systemctl --user)\n", r)
		}
		fmt.Fprintln(c.stdout, "- turn on secretvaultd's Secret Service")
		for _, n := range p.notes {
			fmt.Fprintf(c.stdout, "- by hand: %s\n", n)
		}
		return nil
	}
	if !*noImport && exe != "" {
		n, err := c.importFromKeyring(&u, *prefix, false)
		if err != nil {
			return fmt.Errorf("importing first (use --no-import to skip): %w", err)
		}
		fmt.Fprintf(c.stdout, "Imported %d secrets.\n", n)
	}
	state := &takeoverState{When: time.Now().UTC(), Previous: exe, Restart: p.restart}
	for _, f := range p.order {
		if _, err := os.Stat(f); err == nil {
			return fmt.Errorf("%s already exists: not overwriting it", f)
		}
	}
	for _, f := range p.order {
		if err := os.MkdirAll(filepath.Dir(f), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(f, []byte(p.files[f]), 0o644); err != nil {
			return err
		}
		state.Created = append(state.Created, f)
		fmt.Fprintf(c.stdout, "Wrote %s\n", f)
	}
	sp, err := takeoverPath()
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(state, "", "  ")
	if err := os.WriteFile(sp, b, 0o600); err != nil {
		return err
	}
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	if err := cl.ServeKeyring(ctx, true); err != nil {
		return err
	}
	if len(p.restart) > 0 {
		commandRunner("systemctl", "--user", "daemon-reload")
		for _, r := range p.restart {
			if out, err := commandRunner("systemctl", "--user", "restart", r); err != nil {
				fmt.Fprintf(c.stderr, "warning: restarting %s: %v %s\n", r, err, out)
			}
		}
	}
	for _, n := range p.notes {
		fmt.Fprintln(c.stdout, "Still to do by hand:", n)
	}
	fmt.Fprintln(c.stdout, "secretvault is now the keyring. Undo with 'secretvault keyring restore'.")
	return nil
}

func (c *cli) keyringRestore(args []string) error {
	fs := c.flags("keyring restore")
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--dry-run]"); err != nil {
		return err
	}
	s, err := loadTakeover()
	if errors.Is(err, fs2NotExist) {
		return errors.New("there is no takeover to undo")
	}
	if err != nil {
		return err
	}
	if *dryRun {
		for _, f := range s.Created {
			fmt.Fprintf(c.stdout, "- remove %s\n", f)
		}
		for _, r := range s.Restart {
			fmt.Fprintf(c.stdout, "- restart %s (systemctl --user)\n", r)
		}
		fmt.Fprintln(c.stdout, "- turn off secretvaultd's Secret Service")
		return nil
	}
	if cl, err := c.daemon(); err == nil {
		ctx, cancel := c.ctx()
		defer cancel()
		if err := cl.ServeKeyring(ctx, false); err != nil {
			fmt.Fprintf(c.stderr, "warning: %v\n", err)
		}
	}
	for _, f := range s.Created {
		if err := os.Remove(f); err != nil && !errors.Is(err, fs2NotExist) {
			return err
		}
		fmt.Fprintf(c.stdout, "Removed %s\n", f)
	}
	if len(s.Restart) > 0 {
		commandRunner("systemctl", "--user", "daemon-reload")
		for _, r := range s.Restart {
			commandRunner("systemctl", "--user", "restart", r)
		}
	}
	sp, _ := takeoverPath()
	os.Remove(sp)
	fmt.Fprintf(c.stdout, "Restored: %s is the keyring again.\n", describeExe(s.Previous))
	return nil
}

var fs2NotExist = fs.ErrNotExist

// siblingDaemon is the secretvaultd beside this program.
func siblingDaemon() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	p := filepath.Join(filepath.Dir(exe), "secretvaultd")
	if _, err := os.Stat(p); err != nil {
		return ""
	}
	return p
}
