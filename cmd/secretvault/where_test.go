package main

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// 'secretvault where' says where the daemon keeps things, grouped, path
// then what, and marks what is not there yet.
func TestWhereListsTheDaemonsPlaces(t *testing.T) {
	h := newHarness(t)
	h.init()
	out := h.ok("", "where")
	for _, want := range []string{
		"\nSettings\n", "\nData\n", "\nWhile running\n",
		"  " + filepath.Join(h.home, "vaults", "default") + string(filepath.Separator) + "\n      The vault \"default\", encrypted",
		"  " + h.sock + "\n",
		filepath.Join(h.home, "login") + string(filepath.Separator) + "  (not there yet)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("no %q in:\n%s", want, out)
		}
	}
	if strings.Index(out, "\nSettings\n") > strings.Index(out, "\nData\n") {
		t.Errorf("the groups are out of order:\n%s", out)
	}

	var places []svrpc.Place
	if err := json.Unmarshal([]byte(h.ok("", "where", "--json")), &places); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range places {
		if p.Path == filepath.Join(h.home, "config.json") {
			found = p.Group == svrpc.PlaceSettings && p.Exists && !p.Dir
		}
	}
	if !found {
		t.Fatalf("config.json is not in %+v", places)
	}
}

// With no daemon running, it lists the places as this program would use
// them, and says so; it starts no daemon.
func TestWhereWithNoDaemonSaysWhereItWouldBe(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv(svcore.EnvHome, filepath.Join(home, "data"))
	t.Setenv(svcore.EnvConfig, filepath.Join(home, "config"))
	var out, errb bytes.Buffer
	started := false
	c := &cli{stdout: &out, stderr: &errb, connect: func(o secretvault.Options) (*secretvault.Client, error) {
		started = !o.NoStart
		return nil, secretvault.ErrNoDaemon
	}}
	if code := c.run([]string{"where"}); code != 0 {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if started {
		t.Fatal("it would have started a daemon")
	}
	if !strings.Contains(errb.String(), "not running") || !strings.Contains(out.String(), filepath.Join(home, "config", "config.json")+"  (not there yet)") {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", out.String(), errb.String())
	}
}
