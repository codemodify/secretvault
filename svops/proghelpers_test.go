package svops

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// The helpers set up and undone in a directory of the test's own, git
// stood in for, docker's config the test's.
func TestHelpersAreSetUpAndUndoneLeavingTheRestAlone(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the helpers are links")
	}
	dir := t.TempDir()
	cli := filepath.Join(dir, "bin", "secretvault")
	os.MkdirAll(filepath.Dir(cli), 0o755)
	os.WriteFile(cli, []byte("#!/bin/sh\n"), 0o755)
	// Someone else's age plugin is there already.
	os.WriteFile(filepath.Join(dir, "bin", "age-plugin-secretvault"), []byte("not ours"), 0o755)
	t.Setenv("DOCKER_CONFIG", filepath.Join(dir, "docker"))
	t.Setenv("SECRETVAULT_HOME", filepath.Join(dir, "sv"))
	os.MkdirAll(filepath.Join(dir, "sv"), 0o700)
	os.MkdirAll(filepath.Join(dir, "docker"), 0o700)
	os.WriteFile(filepath.Join(dir, "docker", "config.json"), []byte(`{"auths": {"r.example": {}}, "credsStore": "desktop"}`), 0o600)

	var git []string // credential.helper, as git keeps it
	var ran []string
	run := CommandRunner
	t.Cleanup(func() { CommandRunner = run })
	CommandRunner = func(name string, args ...string) ([]byte, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		switch {
		case slices.Contains(args, "--get-all"):
			if len(git) == 0 {
				return nil, errors.New("exit status 1")
			}
			return []byte(strings.Join(git, "\n") + "\n"), nil
		case slices.Contains(args, "--add"):
			git = append(git, args[len(args)-1])
		case slices.Contains(args, "--unset-all"):
			git = slices.DeleteFunc(git, func(h string) bool { return h == "secretvault" })
		}
		return nil, nil
	}
	git = []string{"cache"}

	if _, err := PlanHelpers(""); !errors.Is(err, ErrNoCLI) {
		t.Fatalf("no CLI: %v", err)
	}
	p, err := PlanHelpers(cli)
	if err != nil {
		t.Fatal(err)
	}
	if p.Undoable() || !slices.Equal(p.UndoLines(), []string{HelpersNothingToUndo}) {
		t.Fatalf("nothing set up, and yet undoable: %q", p.UndoLines())
	}
	lines := strings.Join(p.SetupLines(), "\n")
	for _, want := range []string{"link " + filepath.Join(dir, "bin", "git-credential-secretvault"), "a file, not a link, left alone", "after cache", `in place of "desktop"`} {
		if !strings.Contains(lines, want) {
			t.Errorf("the plan lacks %q:\n%s", want, lines)
		}
	}
	// A plan that waited while docker's config changed is made again.
	os.WriteFile(filepath.Join(dir, "docker", "config.json"), []byte(`{"auths": {"r.example": {}}, "credsStore": "pass"}`), 0o600)
	if _, err := p.Apply(); err == nil || !strings.Contains(err.Error(), "changed since the plan was made") {
		t.Fatalf("a stale plan: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "bin", "git-credential-secretvault")); err == nil || len(git) != 1 {
		t.Fatal("a stale plan changed something")
	}
	os.WriteFile(filepath.Join(dir, "docker", "config.json"), []byte(`{"auths": {"r.example": {}}, "credsStore": "desktop"}`), 0o600)
	if _, err := p.Apply(); err != nil {
		t.Fatal(err)
	}
	if target, err := os.Readlink(filepath.Join(dir, "bin", "git-credential-secretvault")); err != nil || target != "secretvault" {
		t.Fatalf("the git link: %q %v", target, err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "bin", "age-plugin-secretvault")); string(b) != "not ours" {
		t.Fatal("someone else's file was replaced")
	}
	if !slices.Equal(git, []string{"cache", "secretvault"}) {
		t.Fatalf("git's helpers: %q", git)
	}
	var cfg map[string]any
	b, _ := os.ReadFile(filepath.Join(dir, "docker", "config.json"))
	if json.Unmarshal(b, &cfg) != nil || cfg["credsStore"] != "secretvault" || cfg["auths"] == nil {
		t.Fatalf("docker's config: %s", b)
	}

	// Undone: only what is secretvault's goes.
	p, err = PlanHelpers(cli)
	if err != nil || !p.GitHas || p.DockerStore != "secretvault" {
		t.Fatalf("after: %+v %v", p, err)
	}
	if rows := p.StatusRows(); len(rows) != len(p.Links)+2 || rows[0] != [2]string{"git-credential-secretvault", "a link to " + cli} ||
		rows[2][1] != "a file, not a link (not secretvault's)" || rows[3] != [2]string{"git", "credential.helper includes secretvault"} ||
		!strings.HasPrefix(rows[4][1], "credsStore is secretvault (") || !p.Undoable() {
		t.Fatalf("the status after: %q", rows)
	}
	if _, err := p.Undo(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "bin", "git-credential-secretvault")); err == nil {
		t.Fatal("the link is still there")
	}
	if _, err := os.Stat(filepath.Join(dir, "bin", "age-plugin-secretvault")); err != nil {
		t.Fatal("someone else's file was removed")
	}
	if !slices.Equal(git, []string{"cache"}) {
		t.Fatalf("git's helpers: %q", git)
	}
	b, _ = os.ReadFile(filepath.Join(dir, "docker", "config.json"))
	cfg = nil
	if json.Unmarshal(b, &cfg) != nil || cfg["credsStore"] != "desktop" || cfg["auths"] == nil {
		t.Fatalf("docker's config: %s", b)
	}
}
