package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The helpers set up and undone in a directory of the test's own: HOME,
// the XDG directories, docker's config, secretvault's home and socket
// are the test's, git is stood in for, and the CLI the links lead to is a
// file the test made. Nothing here reaches ~/.gitconfig, ~/.docker or the
// repository's bin/.

// helpersEnv is a home of the test's own, a stand-in CLI in its bin/,
// and git, as svops.CommandRunner runs it, keeping credential.helper in
// *git.
type helpersEnv struct {
	t      *testing.T
	dir    string
	exe    string
	docker string // docker's config.json
	git    *[]string
	ran    *[]string
}

func newHelpersEnv(t *testing.T) *helpersEnv {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("the helpers are links")
	}
	dir := t.TempDir()
	for k, v := range map[string]string{
		"HOME": filepath.Join(dir, "home"), "XDG_CONFIG_HOME": filepath.Join(dir, "config"),
		"XDG_DATA_HOME": filepath.Join(dir, "data"), "XDG_STATE_HOME": filepath.Join(dir, "state"),
		"XDG_CACHE_HOME": filepath.Join(dir, "cache"), "XDG_RUNTIME_DIR": filepath.Join(dir, "run"),
		"DOCKER_CONFIG": filepath.Join(dir, "docker"), svcore.EnvHome: filepath.Join(dir, "sv"),
		svrpc.EnvSocket: filepath.Join(dir, "nowhere.sock"),
	} {
		t.Setenv(k, v)
	}
	for _, d := range []string{"home", "sv", "docker", "bin"} {
		os.MkdirAll(filepath.Join(dir, d), 0o700)
	}
	e := &helpersEnv{t: t, dir: dir, exe: filepath.Join(dir, "bin", "secretvault"), docker: filepath.Join(dir, "docker", "config.json")}
	if err := os.WriteFile(e.exe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if p, err := svops.DockerConfigPath(); err != nil || p != e.docker {
		t.Fatalf("docker's config is %q, not the test's (%v)", p, err)
	}
	var git, ran []string
	e.git, e.ran = &git, &ran
	run := svops.CommandRunner
	t.Cleanup(func() { svops.CommandRunner = run })
	svops.CommandRunner = func(name string, args ...string) ([]byte, error) {
		ran = append(ran, name+" "+strings.Join(args, " "))
		if name != "git" {
			return nil, errors.New("not run in tests: " + name)
		}
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
	return e
}

// run runs the CLI, as the program at e.exe.
func (e *helpersEnv) run(args ...string) (string, string, int) {
	var out, errb bytes.Buffer
	c := &cli{stdin: strings.NewReader(""), stdout: &out, stderr: &errb,
		self: func() (string, error) { return e.exe, nil }}
	code := c.run(args)
	return out.String(), errb.String(), code
}

func (e *helpersEnv) ok(args ...string) string {
	e.t.Helper()
	out, errs, code := e.run(args...)
	if code != 0 {
		e.t.Fatalf("secretvault %s: exit %d\nstdout: %s\nstderr: %s", strings.Join(args, " "), code, out, errs)
	}
	return out
}

func (e *helpersEnv) link(name string) string { return filepath.Join(e.dir, "bin", name) }

func (e *helpersEnv) credsStore() string {
	e.t.Helper()
	b, err := os.ReadFile(e.docker)
	if err != nil {
		e.t.Fatal(err)
	}
	var cfg map[string]any
	if err := json.Unmarshal(b, &cfg); err != nil {
		e.t.Fatal(err)
	}
	if cfg["auths"] == nil {
		e.t.Fatalf("docker's other settings went: %s", b)
	}
	s, _ := cfg["credsStore"].(string)
	return s
}

func TestHelpersAreSetUpForTheCLIAndUndone(t *testing.T) {
	e := newHelpersEnv(t)
	*e.git = []string{"cache"}
	os.WriteFile(e.docker, []byte(`{"auths": {"r.example": {}}, "credsStore": "desktop"}`), 0o600)
	// Someone else's age plugin is there already.
	os.WriteFile(e.link("age-plugin-secretvault"), []byte("not ours"), 0o755)

	out := e.ok("helpers")
	for _, want := range []string{
		"git-credential-secretvault     not there",
		"age-plugin-secretvault         a file, not a link (not secretvault's)",
		"git                            secretvault is not among git's credential helpers",
		"docker                         credsStore is desktop",
		"Set them up with 'secretvault helpers setup'",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status does not say %q:\n%s", want, out)
		}
	}

	before := snapshot(t, e.dir)
	out = e.ok("helpers", "setup", "--dry-run")
	for _, want := range []string{
		"Setting the helpers up, as links to " + e.exe + ", would:",
		"- link " + e.link("git-credential-secretvault") + " to secretvault",
		"- " + e.link("age-plugin-secretvault") + ": a file, not a link, left alone",
		"- git config --global --add credential.helper secretvault (after cache, which git asks first)",
		`- set "credsStore": "secretvault" in ` + e.docker + `, in place of "desktop"`,
		"Nothing was changed.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the dry run does not say %q:\n%s", want, out)
		}
	}
	if after := snapshot(t, e.dir); after != before {
		t.Fatalf("the dry run changed files:\n%s\n---\n%s", before, after)
	}
	if !slices.Equal(*e.git, []string{"cache"}) {
		t.Fatalf("the dry run changed git's helpers: %q", *e.git)
	}

	out = e.ok("helpers", "setup")
	for _, want := range []string{"linked " + e.link("git-credential-secretvault"), "linked " + e.link("docker-credential-secretvault"),
		"git's credential helpers include secretvault", "docker's credsStore is secretvault, in " + e.docker,
		"Undo with 'secretvault helpers undo'."} {
		if !strings.Contains(out, want) {
			t.Errorf("setup does not say %q:\n%s", want, out)
		}
	}
	for _, name := range []string{"git-credential-secretvault", "docker-credential-secretvault"} {
		if target, err := os.Readlink(e.link(name)); err != nil || target != "secretvault" {
			t.Fatalf("%s leads to %q (%v)", name, target, err)
		}
	}
	if b, _ := os.ReadFile(e.link("age-plugin-secretvault")); string(b) != "not ours" {
		t.Fatal("someone else's file was replaced")
	}
	if !slices.Equal(*e.git, []string{"cache", "secretvault"}) {
		t.Fatalf("git's helpers: %q", *e.git)
	}
	if s := e.credsStore(); s != "secretvault" {
		t.Fatalf("docker's credsStore is %q", s)
	}

	out = e.ok("helpers", "status")
	for _, want := range []string{
		"git-credential-secretvault     a link to " + e.exe,
		"git                            credential.helper includes secretvault",
		"docker                         credsStore is secretvault (" + e.docker + ")",
		"Undo with 'secretvault helpers undo'.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("status after does not say %q:\n%s", want, out)
		}
	}
	if out := e.ok("helpers", "setup"); !strings.Contains(out, "already a link to secretvault") || !strings.Contains(out, "Nothing was changed.") {
		t.Errorf("a second setup:\n%s", out)
	}

	before = snapshot(t, e.dir)
	out = e.ok("helpers", "undo", "--dry-run")
	for _, want := range []string{
		"Undoing the helpers would:",
		"- remove the link " + e.link("git-credential-secretvault"),
		"- git config --global --unset-all credential.helper '^secretvault$'",
		`- put "credsStore": "desktop" back in ` + e.docker,
		"Nothing was changed.",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the undo dry run does not say %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "age-plugin") {
		t.Errorf("the undo would take someone else's file:\n%s", out)
	}
	if after := snapshot(t, e.dir); after != before {
		t.Fatalf("the undo dry run changed files")
	}

	out = e.ok("helpers", "undo")
	if !strings.Contains(out, "removed "+e.link("git-credential-secretvault")) || !strings.Contains(out, "docker's credsStore is desktop again") {
		t.Errorf("undo said:\n%s", out)
	}
	for _, name := range []string{"git-credential-secretvault", "docker-credential-secretvault"} {
		if _, err := os.Lstat(e.link(name)); err == nil {
			t.Fatalf("%s is still there", name)
		}
	}
	if _, err := os.Stat(e.link("age-plugin-secretvault")); err != nil {
		t.Fatal("someone else's file was removed")
	}
	if _, err := os.Stat(e.exe); err != nil {
		t.Fatal("the CLI itself was removed")
	}
	if !slices.Equal(*e.git, []string{"cache"}) {
		t.Fatalf("git's helpers: %q", *e.git)
	}
	if s := e.credsStore(); s != "desktop" {
		t.Fatalf("docker's credsStore is %q", s)
	}
	if out := e.ok("helpers", "undo"); strings.TrimSpace(out) != svops.HelpersNothingToUndo {
		t.Errorf("a second undo:\n%s", out)
	}
	for _, r := range *e.ran {
		if !strings.HasPrefix(r, "git config --global ") {
			t.Errorf("ran %q", r)
		}
	}
}

func TestHelpersSetupWritesADockerConfigWhereThereWasNone(t *testing.T) {
	e := newHelpersEnv(t)
	os.Remove(filepath.Dir(e.docker))
	e.ok("helpers", "setup")
	if b, err := os.ReadFile(e.docker); err != nil || !strings.Contains(string(b), `"credsStore": "secretvault"`) {
		t.Fatalf("docker's config: %q %v", b, err)
	}
	if out := e.ok("helpers", "undo", "--dry-run"); !strings.Contains(out, `- take "credsStore": "secretvault" out of `+e.docker) {
		t.Errorf("the undo dry run:\n%s", out)
	}
	e.ok("helpers", "undo")
	if b, err := os.ReadFile(e.docker); err != nil || strings.Contains(string(b), "credsStore") {
		t.Fatalf("docker's config after undo: %q %v", b, err)
	}
}

func TestHelpersRefusesWhatItDoesNotKnow(t *testing.T) {
	e := newHelpersEnv(t)
	if _, errs, code := e.run("helpers", "teardown"); code != 2 || !strings.Contains(errs, `unknown subcommand "teardown"`) {
		t.Fatalf("an unknown subcommand: %d %q", code, errs)
	}
	if _, _, code := e.run("helpers", "setup", "extra"); code != 2 {
		t.Fatalf("an argument too many: %d", code)
	}
	os.WriteFile(e.docker, []byte("not json"), 0o600)
	out := e.ok("helpers", "setup")
	if !strings.Contains(out, "linked "+e.link("git-credential-secretvault")) {
		t.Errorf("setup said:\n%s", out)
	}
	if b, _ := os.ReadFile(e.docker); string(b) != "not json" {
		t.Fatalf("a docker config that is not JSON was changed: %q", b)
	}
	if out := e.ok("helpers"); !strings.Contains(out, "is not JSON: left alone") {
		t.Errorf("status:\n%s", out)
	}
}
