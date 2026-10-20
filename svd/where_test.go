package svd

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codemodify/secretvault/svrpc"
)

// The settings go to the settings folder, everything else to the data
// folder; the daemon says where, to secretvault's own programs only.
func TestTheDaemonKeepsSettingsAndDataApartAndSaysWhere(t *testing.T) {
	config := filepath.Join(t.TempDir(), "config")
	h := newHarness(t, func(o *Options) { o.Config = config })
	cli := h.setup()

	if _, err := os.Stat(filepath.Join(config, "config.json")); err != nil {
		t.Fatalf("the settings: %v", err)
	}
	if _, err := os.Stat(filepath.Join(h.home, "config.json")); err == nil {
		t.Fatal("the settings are in the data folder")
	}
	if _, err := os.Stat(filepath.Join(h.home, "vaults", "personal")); err != nil {
		t.Fatalf("the vault: %v", err)
	}
	st, err := cli.Status(ctx(t))
	if err != nil || st.Home != h.home || st.Config != config {
		t.Fatalf("status: home %q, config %q, %v", st.Home, st.Config, err)
	}

	places, err := cli.Where(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	find := func(path string) svrpc.Place {
		t.Helper()
		for _, p := range places {
			if p.Path == path {
				return p
			}
		}
		t.Fatalf("%s is not listed in %+v", path, places)
		return svrpc.Place{}
	}
	if p := find(filepath.Join(config, "config.json")); p.Group != svrpc.PlaceSettings || !p.Exists {
		t.Errorf("config.json: %+v", p)
	}
	if p := find(filepath.Join(h.home, "vaults", "personal")); p.Group != svrpc.PlaceData || !p.Exists || !p.Dir {
		t.Errorf("the vault: %+v", p)
	}
	if p := find(filepath.Join(h.home, "device-signing.key")); !p.Exists {
		t.Errorf("the device key: %+v", p)
	}
	if p := find(h.sock); p.Group != svrpc.PlaceRunning || !p.Exists {
		t.Errorf("the socket: %+v", p)
	}

	// Another program is not told.
	other := h.connect("/usr/bin/mail", nil)
	if _, err := other.Where(ctx(t)); codeOf(err) != svrpc.CodeDenied {
		t.Fatalf("another program: %v", err)
	}
}

// A daemon given only a data folder keeps its settings there too.
func TestADaemonGivenOneFolderKeepsEverythingInIt(t *testing.T) {
	h := newHarness(t)
	h.setup()
	if _, err := os.Stat(filepath.Join(h.home, "config.json")); err != nil {
		t.Fatal(err)
	}
}
