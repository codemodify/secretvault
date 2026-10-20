package svops

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svsync"
)

// Where things are kept: every folder and file secretvault keeps, and
// what it changed in other programs, with what each is, in plain words.
// The daemon lists its own (svrpc.MWhere, with what it uses: its
// environment and its config), and the CLI and the managers list them
// from their own environment when no daemon runs (WhereHere). Every face
// shows the same list.

// The files secretvaultd keeps in the data folder.
const (
	DeviceFile    = "device.json"
	DisksFile     = "disks.json"
	VaultsFolder  = "vaults"
	AuditFolder   = "audit"
	LoginFolder   = "login"
	SyncFolder    = "sync"
	GnuPGFolder   = "gnupg"
	ServerFolder  = "server" // secretvault-server's, by default
	BrowserFolder = "browser"
)

// The files `secretvaultd install` writes so that the daemon starts when
// the person logs in (svd's install_*.go write them; Where lists them).
const (
	DaemonUnitName    = "secretvaultd.service"
	DaemonLaunchLabel = "io.github.codemodify.secretvaultd"
	DaemonRunKey      = `Software\Microsoft\Windows\CurrentVersion\Run`
	DaemonRunValue    = "secretvaultd"
)

// DaemonUnitFile is the systemd user unit that starts the daemon.
func DaemonUnitFile() string {
	return filepath.Join(userDir("XDG_CONFIG_HOME", ".config"), "systemd", "user", DaemonUnitName)
}

// DaemonAutostartFile is the autostart entry that starts the daemon where
// there is no systemd user session.
func DaemonAutostartFile() string {
	return filepath.Join(userDir("XDG_CONFIG_HOME", ".config"), "autostart", "secretvaultd.desktop")
}

// DaemonLaunchAgentFile is the macOS LaunchAgent that starts the daemon.
func DaemonLaunchAgentFile() string {
	h, _ := os.UserHomeDir()
	return filepath.Join(h, "Library", "LaunchAgents", DaemonLaunchLabel+".plist")
}

// WhereVault is a vault the settings name, and its folder.
type WhereVault struct{ Name, Path string }

// WhereGnuPG is a GnuPG folder pointed at the daemon, and the links made
// for its gpg.
type WhereGnuPG struct{ Home, Socket, SSHSocket string }

// WhereOptions say whose places to list. The daemon passes its own;
// WhereHere fills them from this program's environment.
type WhereOptions struct {
	Config, Data string // the settings and data folders

	// Socket is the daemon's socket; its folder is the runtime folder.
	// SSHAgent and GPGAgent are the agents' sockets, "" for one not
	// served.
	Socket, SSHAgent, GPGAgent string

	Vaults []WhereVault // every vault, wherever it is kept
	GnuPG  []WhereGnuPG // the GnuPG folders pointed at the daemon

	// CLI is the secretvault program the helpers link to ("" when there
	// is none: no helper links are looked for).
	CLI string

	// Host lists the host daemon's own places (secretvaultd --host):
	// HostData and HostRuntime are its folders.
	Host                  bool
	HostData, HostRuntime string

	// Old is the folder secretvault kept everything in before
	// (svcore.LegacyDir), listed while it is there; "" to leave it out.
	Old string
}

// WhereHere lists the places as this program's environment says, for
// when no daemon runs to say it: the folders from svcore, the vaults and
// GnuPG folders from config.json (and the data folder's vaults folder,
// as the daemon finds them), the sockets where a daemon would make them.
func WhereHere() ([]svrpc.Place, error) {
	config, err := svcore.ConfigDir()
	if err != nil {
		return nil, err
	}
	data, err := svcore.DataDir()
	if err != nil {
		return nil, err
	}
	o := WhereOptions{Config: config, Data: data, Socket: svrpc.DefaultSocket(), CLI: CLIProgram()}
	if os.Getenv(svcore.EnvHome) == "" {
		o.Old, _ = svcore.LegacyDir()
	}
	var cfg struct {
		Vaults []struct {
			Name string `json:"name"`
			Path string `json:"path"`
		} `json:"vaults"`
		NoSSHAgent bool `json:"no_ssh_agent"`
		NoGPGAgent bool `json:"no_gpg_agent"`
		GnuPG      []struct {
			Home      string `json:"home"`
			Socket    string `json:"socket"`
			SSHSocket string `json:"ssh_socket"`
		} `json:"gnupg"`
	}
	if b, err := os.ReadFile(filepath.Join(config, ConfigFile)); err == nil {
		json.Unmarshal(b, &cfg)
	}
	known := map[string]bool{}
	for _, v := range cfg.Vaults {
		o.Vaults = append(o.Vaults, WhereVault{v.Name, v.Path})
		known[v.Name] = true
	}
	entries, _ := os.ReadDir(filepath.Join(data, VaultsFolder))
	for _, e := range entries {
		p := filepath.Join(data, VaultsFolder, e.Name())
		if _, err := os.Stat(filepath.Join(p, svformat.DescriptorName)); err == nil && e.IsDir() && !known[e.Name()] {
			o.Vaults = append(o.Vaults, WhereVault{e.Name(), p})
		}
	}
	for _, g := range cfg.GnuPG {
		o.GnuPG = append(o.GnuPG, WhereGnuPG{g.Home, g.Socket, g.SSHSocket})
	}
	if !cfg.NoSSHAgent {
		o.SSHAgent = svrpc.SSHAgentSocket()
	}
	if !cfg.NoGPGAgent && runtime.GOOS != "windows" {
		o.GPGAgent = svrpc.GPGAgentSocket()
	}
	return Where(o), nil
}

// places builds the list.
type places struct{ out []svrpc.Place }

// add lists path, as it is now, when always or when it is there.
func (p *places) add(group, path, what string, always bool) {
	if path == "" {
		return
	}
	pl := svrpc.Place{Group: group, Path: path, What: what}
	if st, err := os.Lstat(path); err == nil {
		pl.Exists, pl.Dir = true, st.IsDir()
	} else if !always {
		return
	}
	p.out = append(p.out, pl)
}

// addDir lists a folder that is not made yet as one.
func (p *places) addDir(group, path, what string) {
	p.add(group, path, what, true)
	if l := &p.out[len(p.out)-1]; !l.Exists {
		l.Dir = true
	}
}

// Where lists the places o names, grouped as svrpc.PlaceGroups, each
// with whether it is there now.
func Where(o WhereOptions) []svrpc.Place {
	if o.Host {
		return whereHost(o)
	}
	p := &places{}
	p.settings(o)
	p.data(o)
	p.running(o)
	p.otherPrograms(o)
	p.hostDaemon()
	return p.out
}

func (p *places) settings(o WhereOptions) {
	g := svrpc.PlaceSettings
	if !sameDir(o.Config, o.Data) {
		p.addDir(g, o.Config, "secretvault's settings, and its notes of what it changed in other programs, so that it can undo it.")
	}
	p.add(g, filepath.Join(o.Config, ConfigFile), "Your settings: which vaults there are and where, the default one, how you are asked, and what secretvault does for other programs.", true)
	p.add(g, filepath.Join(o.Config, BrowserInstallFile), "What secretvault wrote so that your browsers can reach it, so that it can take it away again.", true)
	p.add(g, filepath.Join(o.Config, TakeoverFile), "What secretvault changed to become your system keyring, so that it can give it back.", true)
	p.add(g, filepath.Join(o.Config, HelpersFile), "What docker used before secretvault, so that undoing the program helpers puts it back.", true)
	p.add(g, filepath.Join(o.Config, GUIFile), "How the desktop manager looks: dark or light as the desktop is, or always one of them (Tools › Appearance).", true)
}

func (p *places) data(o WhereOptions) {
	g := svrpc.PlaceData
	what := "Your vaults, and what secretvault keeps to run them: keys, logs and what it remembers."
	if sameDir(o.Config, o.Data) {
		what = "Your vaults, your settings, and what secretvault keeps to run them: keys, logs and what it remembers."
	}
	p.addDir(g, o.Data, what)
	p.addDir(g, filepath.Join(o.Data, VaultsFolder), "Where new vaults are made, a folder each.")
	vaults := append([]WhereVault(nil), o.Vaults...)
	sort.SliceStable(vaults, func(i, j int) bool { return vaults[i].Name < vaults[j].Name })
	for _, v := range vaults {
		what := fmt.Sprintf("The vault %q, encrypted: its items, files and history.", v.Name)
		if !within(o.Data, v.Path) {
			what = fmt.Sprintf("The vault %q, encrypted: its items, files and history, kept here rather than in the data folder.", v.Name)
		}
		p.addDir(g, v.Path, what)
	}
	p.addDir(g, filepath.Join(o.Data, AuditFolder), "The audit log of each vault, which only that vault can read: which program asked for what, and what happened.")
	p.add(g, filepath.Join(o.Data, DeviceFile), "This computer's ID, which marks every change it makes to a vault.", true)
	p.add(g, filepath.Join(o.Data, svcore.DeviceKeyFile), "This computer's signing key: every change it makes to a vault is signed with it, so that your other devices can tell who wrote what.", true)
	p.add(g, filepath.Join(o.Data, DisksFile), "Which encrypted disks belong to which vault, so that they can be listed while the vault is locked.", true)
	p.disks(o.Data)
	p.addDir(g, filepath.Join(o.Data, LoginFolder), "The keys of the vaults that open when you log in, sealed so that only your login on this computer can use them.")
	p.addDir(g, filepath.Join(o.Data, SyncFolder), "What this computer knows of each sync server: how far it has synced, and the waits of emergency access.")
	p.add(g, filepath.Join(o.Data, svsync.IdentityFile), "This computer's key for sync servers: it signs every request to them, and opens no vault.", true)
	p.addDir(g, filepath.Join(o.Data, GnuPGFolder), "The GnuPG folder secretvault sets up for gpg: public keys only, the secret keys staying in your vaults.")
	p.add(g, filepath.Join(o.Data, ServerFolder), "The vaults this computer keeps for other devices as a sync server (secretvault-server), encrypted.", false)
	if runtime.GOOS == "windows" {
		p.add(g, filepath.Join(o.Data, BrowserFolder), "The files that tell your browsers where secretvault is.", false)
	}
	if o.Old != "" && !sameDir(o.Old, o.Data) && !sameDir(o.Old, o.Config) {
		what := "Where secretvault kept everything before; now it holds only a note saying where each thing went."
		if leftovers(o.Old) {
			what = "Where secretvault kept everything before; what is still here was not moved, because the new place had one already (its note says which)."
		}
		p.add(g, o.Old, what, false)
	}
}

// disks lists the encrypted disks the daemon remembers (disks.json).
func (p *places) disks(data string) {
	var seen struct {
		Vaults map[string][]string `json:"vaults"`
	}
	b, err := os.ReadFile(filepath.Join(data, DisksFile))
	if err != nil || json.Unmarshal(b, &seen) != nil {
		return
	}
	names := make([]string, 0, len(seen.Vaults))
	for n := range seen.Vaults {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		for _, path := range seen.Vaults[n] {
			p.add(svrpc.PlaceData, path, fmt.Sprintf("An encrypted disk whose key is kept in the vault %q.", n), true)
		}
	}
}

// leftovers reports whether the old folder holds more than the move's
// note and link.
func leftovers(old string) bool {
	entries, err := os.ReadDir(old)
	if err != nil {
		return false
	}
	for _, e := range entries {
		if e.Name() == OldFolderNote || (e.Name() == GnuPGFolder && e.Type()&fs.ModeSymlink != 0) {
			continue
		}
		return true
	}
	return false
}

func (p *places) running(o WhereOptions) {
	g := svrpc.PlaceRunning
	sock := o.Socket
	if sock == "" {
		sock = svrpc.DefaultSocket()
	}
	p.addDir(g, filepath.Dir(sock), "Where the daemon's sockets are while it runs; nothing in it outlasts your session.")
	p.add(g, sock, "The daemon's door: secretvault's programs, and the programs it serves, talk to it here.", true)
	p.add(g, sock+".lock", "Keeps a second daemon from starting while one runs.", true)
	p.add(g, o.SSHAgent, "The SSH agent: programs pointed at it sign with the SSH keys in your vaults, after asking you.", true)
	p.add(g, o.GPGAgent, "gpg's agent: GnuPG folders pointed at secretvault sign and decrypt with your vaults' OpenPGP keys here.", true)
}

func (p *places) otherPrograms(o WhereOptions) {
	g := svrpc.PlaceOther
	// The browsers' files, from the install's record.
	if rec, err := loadBrowserInstallAt(filepath.Join(o.Config, BrowserInstallFile)); err == nil {
		for _, h := range rec.Hosts {
			names := browsersNamed(h.Browsers)
			p.add(g, h.Manifest, fmt.Sprintf("Lets %s start secretvault when %s asks for a login.", names, h.NativeHost().Title), true)
			if h.RegKey != "" {
				_, ok, _ := registryValue(h.RegKey)
				p.out = append(p.out, svrpc.Place{Group: g, Path: `HKEY_CURRENT_USER\` + h.RegKey, Exists: ok,
					What: fmt.Sprintf("Tells %s where that file is.", names)})
			}
		}
	}
	// The keyring takeover's files, from its record.
	if rec, err := loadTakeoverAt(filepath.Join(o.Config, TakeoverFile)); err == nil {
		for _, f := range rec.Created {
			p.add(g, f, takeoverWhat(f), true)
		}
	}
	// The helpers: the links beside the CLI, git's and docker's settings.
	if o.CLI != "" && runtime.GOOS != "windows" {
		if plan, err := PlanHelpers(o.CLI); err == nil {
			for _, l := range plan.Links {
				if l.Ours {
					p.add(g, l.Path, helperWhat[l.Name], true)
				}
			}
			if plan.GitHas {
				p.add(g, gitGlobalConfig(), "git asks secretvault for its logins: secretvault is one of its credential helpers here.", true)
			}
			if plan.DockerErr == nil && plan.DockerStore == helperStore {
				p.add(g, plan.DockerConfig, "docker keeps its registry logins in secretvault: it is named here as docker's store for them.", true)
			}
		}
	}
	// Starting at login (`secretvaultd install`).
	switch runtime.GOOS {
	case "windows":
		if registryHasValue(DaemonRunKey, DaemonRunValue) {
			p.out = append(p.out, svrpc.Place{Group: g, Path: `HKEY_CURRENT_USER\` + DaemonRunKey + `\` + DaemonRunValue, Exists: true,
				What: "Starts the secretvault daemon when you log in."})
		}
	case "darwin":
		p.add(g, DaemonLaunchAgentFile(), "Starts the secretvault daemon when you log in.", false)
	default:
		p.add(g, DaemonUnitFile(), "Starts the secretvault daemon when you log in.", false)
		p.add(g, DaemonAutostartFile(), "Starts the secretvault daemon when you log in.", false)
	}
	// The GnuPG folders pointed at the daemon.
	for _, h := range o.GnuPG {
		if !within(o.Data, h.Home) {
			p.add(g, filepath.Join(h.Home, "gpg.conf"), "gpg in the GnuPG folder "+h.Home+" starts secretvault when it finds no agent: secretvault added that line.", true)
		}
		p.add(g, h.Socket, "Sends gpg, in the GnuPG folder "+h.Home+", to secretvault for its keys.", true)
		p.add(g, h.SSHSocket, "Sends gpg's SSH agent, in the GnuPG folder "+h.Home+", to secretvault.", true)
	}
}

// browsersNamed names browsers as people know them: "Google Chrome and
// Brave".
func browsersNamed(names []string) string {
	if len(names) == 0 {
		return "your browser"
	}
	return andList(browserTitlesOf(names))
}

// takeoverWhat says what a file the keyring takeover wrote is for.
func takeoverWhat(f string) string {
	switch base := filepath.Base(f); {
	case base == "org.freedesktop.secrets.service":
		return "Makes secretvault your system keyring: apps that ask for the keyring start secretvault."
	case base == "gnome-keyring-secrets.desktop":
		return "Keeps GNOME Keyring from being your system keyring when you log in."
	case base == "50-secretvault.conf":
		return "Keeps GNOME Keyring running without its keyring part, which secretvault does instead."
	case strings.HasSuffix(base, "portals.conf"):
		return "Sends Flatpak apps' passwords to secretvault."
	}
	return "Written when secretvault became your system keyring; giving the keyring back removes it."
}

// helperWhat says what each helper link is for.
var helperWhat = map[string]string{
	"git-credential-secretvault":    "Lets git ask secretvault for its logins.",
	"docker-credential-secretvault": "Lets docker keep its registry logins in secretvault.",
	"age-plugin-secretvault":        "Lets age and SOPS decrypt with the age keys in your vaults.",
}

// gitGlobalConfig is git's own settings file: ~/.gitconfig, or git's file
// in the config folder when only that one is there.
func gitGlobalConfig() string {
	h, _ := os.UserHomeDir()
	home := filepath.Join(h, ".gitconfig")
	if _, err := os.Stat(home); err != nil {
		xdg := filepath.Join(userDir("XDG_CONFIG_HOME", ".config"), "git", "config")
		if _, err := os.Stat(xdg); err == nil {
			return xdg
		}
	}
	return home
}

// hostDaemon lists the host daemon's places when this machine has one.
func (p *places) hostDaemon() {
	if runtime.GOOS != "linux" {
		return
	}
	data, rt := svrpc.HostDataDir(), svrpc.HostRuntimeDir()
	service := filepath.Join(svrpc.HostUnitDir, svrpc.HostServiceUnit)
	_, err1 := os.Lstat(data)
	_, err2 := os.Lstat(service)
	if err1 != nil && err2 != nil {
		return
	}
	g := svrpc.PlaceHost
	p.addDir(g, data, "The host daemon's vaults, rules and log, which only root can read.")
	p.addDir(g, rt, "The host daemon's sockets: for systemd's credentials, for local services, and for root.")
	p.add(g, service, "Runs the host daemon as a system service.", true)
	p.add(g, filepath.Join(svrpc.HostUnitDir, svrpc.HostSocketUnit), "Holds the host daemon's credential socket from early boot, so that services starting before it wait for it.", true)
	p.add(g, svrpc.HostCredstore, "The host identity, sealed by systemd-creds so that only this machine can open it.", false)
}

// whereHost lists the host daemon's own places (secretvaultd --host).
func whereHost(o WhereOptions) []svrpc.Place {
	p := &places{}
	data, rt := o.HostData, o.HostRuntime
	if data == "" {
		data = svrpc.HostDataDir()
	}
	if rt == "" {
		rt = svrpc.HostRuntimeDir()
	}
	g := svrpc.PlaceSettings
	p.add(g, filepath.Join(data, ConfigFile), "The host daemon's settings: its vaults and where they are.", true)
	p.add(g, filepath.Join(data, "host.json"), "The rules: which service gets which secret.", true)
	g = svrpc.PlaceData
	p.addDir(g, data, "The host daemon's vaults, rules and log, which only root can read.")
	p.addDir(g, filepath.Join(data, VaultsFolder), "Where new vaults are made, a folder each.")
	vaults := append([]WhereVault(nil), o.Vaults...)
	sort.SliceStable(vaults, func(i, j int) bool { return vaults[i].Name < vaults[j].Name })
	for _, v := range vaults {
		p.addDir(g, v.Path, fmt.Sprintf("The vault %q, encrypted: its items, files and history.", v.Name))
	}
	p.add(g, filepath.Join(data, "host.identity"), "The host identity, when systemd does not pass it sealed: it opens the host's vaults.", false)
	p.add(g, filepath.Join(data, "host.log"), "What the host daemon handed out and refused, and to whom.", true)
	p.addDir(g, filepath.Join(data, AuditFolder), "The audit log of each vault, which only that vault can read.")
	p.add(g, filepath.Join(data, DeviceFile), "This machine's ID, which marks every change it makes to a vault.", true)
	p.add(g, filepath.Join(data, svcore.DeviceKeyFile), "This machine's signing key: every change it makes to a vault is signed with it.", true)
	p.addDir(g, filepath.Join(data, SyncFolder), "What this machine knows of each sync server.")
	p.add(g, filepath.Join(data, svsync.IdentityFile), "This machine's key for sync servers: it signs every request to them, and opens no vault.", false)
	g = svrpc.PlaceRunning
	p.addDir(g, rt, "Where the host daemon's sockets are while it runs.")
	p.add(g, filepath.Join(rt, svrpc.HostCredentialSocketName), "systemd fetches services' credentials here.", true)
	p.add(g, filepath.Join(rt, svrpc.HostServiceSocketName), "Local services that are not units fetch what the rules give them here.", true)
	p.add(g, filepath.Join(rt, svrpc.HostAdminSocketName), "root manages the host daemon here ('secretvault host').", true)
	g = svrpc.PlaceOther
	p.add(g, filepath.Join(svrpc.HostUnitDir, svrpc.HostServiceUnit), "Runs the host daemon as a system service.", false)
	p.add(g, filepath.Join(svrpc.HostUnitDir, svrpc.HostSocketUnit), "Holds the credential socket from early boot, so that services starting before the daemon wait for it.", false)
	p.add(g, svrpc.HostCredstore, "The host identity, sealed by systemd-creds so that only this machine can open it.", false)
	return p.out
}

// within reports whether path is dir or inside it.
func within(dir, path string) bool {
	rel, err := filepath.Rel(filepath.Clean(dir), filepath.Clean(path))
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}

// WhereGroups splits places by group, in the groups' order, leaving out
// empty groups.
func WhereGroups(places []svrpc.Place) [][]svrpc.Place {
	var out [][]svrpc.Place
	for _, g := range svrpc.PlaceGroups {
		var in []svrpc.Place
		for _, p := range places {
			if p.Group == g {
				in = append(in, p)
			}
		}
		if len(in) > 0 {
			out = append(out, in)
		}
	}
	return out
}

// WhereAbout says what the list is, for the faces to show above it.
const WhereAbout = "Every folder and file secretvault keeps, and what it changed in other programs, with what each holds."

// WhereMissing marks a place that is not there now.
const WhereMissing = "not there yet"
