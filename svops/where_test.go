package svops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// placeAt finds the place at path.
func placeAt(t *testing.T, places []svrpc.Place, path string) svrpc.Place {
	t.Helper()
	for _, p := range places {
		if p.Path == path {
			return p
		}
	}
	t.Fatalf("%s is not listed", path)
	return svrpc.Place{}
}

func TestWhereListsEveryFolderAndFileGroupedWithWhatEachHolds(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	config, data := filepath.Join(home, ".config", "secretvault"), filepath.Join(home, ".data", "secretvault")
	run := filepath.Join(home, "run", "secretvault")
	elsewhere := filepath.Join(home, "Sync", "work")
	for _, d := range []string{config, filepath.Join(data, "vaults", "personal"), elsewhere, run} {
		os.MkdirAll(d, 0o700)
	}
	os.WriteFile(filepath.Join(config, ConfigFile), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(data, DeviceFile), []byte("{}"), 0o600)
	os.WriteFile(filepath.Join(run, "secretvaultd.sock"), nil, 0o600)
	// What secretvault changed in other programs, from its records.
	manifest := filepath.Join(home, ".mozilla", "native-messaging-hosts", ExtensionHost.Name+".json")
	os.MkdirAll(filepath.Dir(manifest), 0o700)
	os.WriteFile(manifest, []byte("{}"), 0o644)
	rec, _ := json.Marshal(BrowserInstall{Host: "/usr/bin/secretvault", Hosts: []InstalledHost{{Browsers: []string{"firefox"}, Manifest: manifest, HostName: ExtensionHost.Name}}})
	os.WriteFile(filepath.Join(config, BrowserInstallFile), rec, 0o600)
	activation := filepath.Join(home, ".local", "share", "dbus-1", "services", "org.freedesktop.secrets.service")
	takeover, _ := json.Marshal(TakeoverState{Created: []string{activation}})
	os.WriteFile(filepath.Join(config, TakeoverFile), takeover, 0o600)
	// A disk the daemon remembers.
	disk := filepath.Join(home, "disks", "photos.img")
	seen, _ := json.Marshal(map[string]any{"vaults": map[string][]string{"personal": {disk}}})
	os.WriteFile(filepath.Join(data, DisksFile), seen, 0o600)

	places := Where(WhereOptions{
		Config: config, Data: data, Socket: filepath.Join(run, "secretvaultd.sock"), SSHAgent: filepath.Join(run, "ssh-agent.sock"),
		Vaults: []WhereVault{{"work", elsewhere}, {"personal", filepath.Join(data, "vaults", "personal")}},
		GnuPG:  []WhereGnuPG{{Home: filepath.Join(home, ".gnupg"), Socket: filepath.Join(home, "run", "gnupg", "S.gpg-agent")}},
	})

	// The groups come in their order, each whole.
	var groups []string
	for _, p := range places {
		if len(groups) == 0 || groups[len(groups)-1] != p.Group {
			if slices.Contains(groups, p.Group) {
				t.Fatalf("the group %s comes twice", p.Group)
			}
			groups = append(groups, p.Group)
		}
		if p.What == "" || !strings.HasSuffix(p.What, ".") {
			t.Errorf("%s: what it is: %q", p.Path, p.What)
		}
	}
	want := []string{svrpc.PlaceSettings, svrpc.PlaceData, svrpc.PlaceRunning, svrpc.PlaceOther}
	if !slices.Equal(groups[:4], want) {
		t.Fatalf("groups %v", groups)
	}

	if p := placeAt(t, places, config); p.Group != svrpc.PlaceSettings || !p.Dir || !p.Exists {
		t.Errorf("the settings folder: %+v", p)
	}
	if p := placeAt(t, places, filepath.Join(config, ConfigFile)); !p.Exists || p.Dir {
		t.Errorf("config.json: %+v", p)
	}
	if p := placeAt(t, places, filepath.Join(config, HelpersFile)); p.Exists {
		t.Errorf("helpers.json is not there: %+v", p)
	}
	if p := placeAt(t, places, data); p.Group != svrpc.PlaceData || !p.Exists {
		t.Errorf("the data folder: %+v", p)
	}
	if p := placeAt(t, places, elsewhere); p.Group != svrpc.PlaceData || !strings.Contains(p.What, `"work"`) || !strings.Contains(p.What, "rather than in the data folder") {
		t.Errorf("a vault kept elsewhere: %+v", p)
	}
	if p := placeAt(t, places, filepath.Join(data, "vaults", "personal")); strings.Contains(p.What, "rather than") {
		t.Errorf("a vault in the data folder: %+v", p)
	}
	if p := placeAt(t, places, filepath.Join(data, LoginFolder)); p.Exists || !p.Dir {
		t.Errorf("a folder not made yet: %+v", p)
	}
	if p := placeAt(t, places, disk); p.Group != svrpc.PlaceData || !strings.Contains(p.What, `"personal"`) {
		t.Errorf("a disk: %+v", p)
	}
	if p := placeAt(t, places, run); p.Group != svrpc.PlaceRunning || !p.Exists {
		t.Errorf("the runtime folder: %+v", p)
	}
	if p := placeAt(t, places, filepath.Join(run, "ssh-agent.sock")); p.Exists {
		t.Errorf("the SSH agent's socket: %+v", p)
	}
	if p := placeAt(t, places, manifest); p.Group != svrpc.PlaceOther || !p.Exists || !strings.Contains(p.What, "Firefox") {
		t.Errorf("the browser's file: %+v", p)
	}
	if p := placeAt(t, places, activation); p.Group != svrpc.PlaceOther || p.Exists || !strings.Contains(p.What, "system keyring") {
		t.Errorf("the keyring's file: %+v", p)
	}
	if p := placeAt(t, places, filepath.Join(home, ".gnupg", "gpg.conf")); p.Group != svrpc.PlaceOther {
		t.Errorf("a GnuPG folder elsewhere: %+v", p)
	}
	placeAt(t, places, filepath.Join(home, "run", "gnupg", "S.gpg-agent"))

	grouped := WhereGroups(places)
	if len(grouped) < 4 || grouped[0][0].Group != svrpc.PlaceSettings {
		t.Fatalf("grouped: %v", grouped)
	}
}

func TestWithOneFolderTheSettingsAreListedInIt(t *testing.T) {
	dir := t.TempDir()
	places := Where(WhereOptions{Config: dir, Data: dir, Socket: filepath.Join(t.TempDir(), "s.sock")})
	n := 0
	for _, p := range places {
		if p.Path == dir {
			n++
			if p.Group != svrpc.PlaceData || !strings.Contains(p.What, "settings") {
				t.Errorf("the folder: %+v", p)
			}
		}
	}
	if n != 1 {
		t.Fatalf("the one folder is listed %d times", n)
	}
	placeAt(t, places, filepath.Join(dir, ConfigFile))
}

func TestWithNoDaemonThePlacesComeFromTheEnvironment(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the Linux layout")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_RUNTIME_DIR", filepath.Join(home, "run"))
	t.Setenv(svrpc.EnvSocket, "")
	t.Setenv(svcore.EnvHome, "")
	t.Setenv(svcore.EnvConfig, "")
	config, data := filepath.Join(home, ".config", "secretvault"), filepath.Join(home, ".data", "secretvault")
	os.MkdirAll(filepath.Join(data, "vaults", "found"), 0o700)
	os.WriteFile(filepath.Join(data, "vaults", "found", "vault.json"), []byte("{}"), 0o600)
	os.MkdirAll(config, 0o700)
	os.WriteFile(filepath.Join(config, ConfigFile), []byte(`{"vaults":[{"name":"far","path":"/srv/far"}],"no_ssh_agent":true}`), 0o600)
	old := filepath.Join(home, ".local", "share", "secretvault")
	os.MkdirAll(old, 0o700)
	os.WriteFile(filepath.Join(old, OldFolderNote), []byte(oldFolderNoteHead+"\n"), 0o600)

	places, err := WhereHere()
	if err != nil {
		t.Fatal(err)
	}
	placeAt(t, places, config)
	placeAt(t, places, filepath.Join(data, "vaults", "found"))
	if p := placeAt(t, places, "/srv/far"); p.Exists {
		t.Errorf("%+v", p)
	}
	placeAt(t, places, filepath.Join(home, "run", "secretvault", "secretvaultd.sock"))
	if p := placeAt(t, places, old); !strings.Contains(p.What, "only a note") {
		t.Errorf("the old folder: %+v", p)
	}
	for _, p := range places {
		if strings.HasSuffix(p.Path, "ssh-agent.sock") {
			t.Errorf("the SSH agent is off, but listed: %+v", p)
		}
	}
}

func TestTheHostDaemonListsItsOwnPlaces(t *testing.T) {
	data, rt := t.TempDir(), t.TempDir()
	places := Where(WhereOptions{Host: true, HostData: data, HostRuntime: rt, Vaults: []WhereVault{{"prod", filepath.Join(data, "vaults", "prod")}}})
	placeAt(t, places, filepath.Join(data, "host.json"))
	placeAt(t, places, filepath.Join(rt, svrpc.HostCredentialSocketName))
	if p := placeAt(t, places, filepath.Join(data, "vaults", "prod")); p.Group != svrpc.PlaceData {
		t.Errorf("%+v", p)
	}
}
