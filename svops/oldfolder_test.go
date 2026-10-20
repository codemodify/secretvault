package svops

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcore"
)

// oldLayout is a temporary home with the folder an earlier version kept
// everything in, and the two folders it moves to. Nothing here is the
// person's own.
type oldLayout struct {
	t                       *testing.T
	home, old, config, data string
	elsewhere               string // a vault kept outside the old folder
}

func newOldLayout(t *testing.T) *oldLayout {
	t.Helper()
	home := t.TempDir()
	l := &oldLayout{t: t, home: home,
		old:       filepath.Join(home, ".local", "share", "secretvault"),
		config:    filepath.Join(home, ".config", "secretvault"),
		data:      filepath.Join(home, ".data", "secretvault"),
		elsewhere: filepath.Join(home, "Sync", "work-vault"),
	}
	l.write(filepath.Join(l.old, "device.json"), `{"id":"device"}`)
	l.write(filepath.Join(l.old, "device-signing.key"), "signing key")
	l.write(filepath.Join(l.old, "disks.json"), `{"vaults":{}}`)
	l.write(filepath.Join(l.old, "browser-install.json"), `{"hosts":[]}`)
	l.write(filepath.Join(l.old, "vaults", "test", "vault.json"), "descriptor")
	l.write(filepath.Join(l.old, "vaults", "test", "objects", "ab", "cdef"), "an object")
	l.write(filepath.Join(l.old, "audit", "x.log"), "a line\n")
	l.write(filepath.Join(l.old, "sync", "abc.json"), `{"cursor":3}`)
	l.write(filepath.Join(l.elsewhere, "vault.json"), "the work vault")
	cfg := map[string]any{
		"vaults": []any{
			map[string]any{"name": "test", "path": filepath.Join(l.old, "vaults", "test"), "auto_lock": map[string]any{"idle_minutes": 15, "on_screen_lock": true}},
			map[string]any{"name": "work", "path": l.elsewhere, "auto_lock": map[string]any{}},
		},
		"default":        "test",
		"secret_service": true,
		"future_setting": map[string]any{"kept": []any{1, 2, 12345678901234567}},
	}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	l.write(filepath.Join(l.old, "config.json"), string(b))
	return l
}

func (l *oldLayout) write(p, content string) {
	l.t.Helper()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		l.t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		l.t.Fatal(err)
	}
}

func (l *oldLayout) read(p string) string {
	l.t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		l.t.Fatal(err)
	}
	return string(b)
}

func (l *oldLayout) gone(p string) {
	l.t.Helper()
	if _, err := os.Lstat(p); err == nil {
		l.t.Errorf("%s is still there", p)
	}
}

func (l *oldLayout) move() *FolderMove {
	l.t.Helper()
	var logged []string
	m, err := MoveOldFolder(MoveOptions{Old: l.old, Config: l.config, Data: l.data, Log: func(s string) { logged = append(logged, s) },
		GnuPGSockets: func(home string) (string, string, error) {
			return filepath.Join(l.home, "run", "gnupg", "d.new", "S.gpg-agent"), filepath.Join(l.home, "run", "gnupg", "d.new", "S.gpg-agent.ssh"), nil
		}})
	if err != nil {
		l.t.Fatal(err)
	}
	return m
}

// vaultPaths are config.json's vaults' paths, by name, from where it is.
func (l *oldLayout) vaultPaths(dir string) map[string]string {
	l.t.Helper()
	var cfg struct {
		Vaults []struct{ Name, Path string } `json:"vaults"`
	}
	if err := json.Unmarshal([]byte(l.read(filepath.Join(dir, ConfigFile))), &cfg); err != nil {
		l.t.Fatal(err)
	}
	out := map[string]string{}
	for _, v := range cfg.Vaults {
		out[v.Name] = v.Path
	}
	return out
}

func TestTheOldFolderMovesToTheSettingsAndDataFolders(t *testing.T) {
	l := newOldLayout(t)
	m := l.move()

	// The settings and the records of other programs' changes...
	for _, f := range []string{"config.json", "browser-install.json"} {
		l.read(filepath.Join(l.config, f))
		l.gone(filepath.Join(l.old, f))
		l.gone(filepath.Join(l.data, f))
	}
	// ...and everything else, whole.
	if got := l.read(filepath.Join(l.data, "vaults", "test", "objects", "ab", "cdef")); got != "an object" {
		t.Fatalf("the vault's object: %q", got)
	}
	for _, f := range []string{"device.json", "device-signing.key", "disks.json", "audit/x.log", "sync/abc.json"} {
		l.read(filepath.Join(l.data, f))
		l.gone(filepath.Join(l.old, f))
	}
	if len(m.Kept)+len(m.Failed) != 0 || len(m.Moved) != 8 {
		t.Fatalf("moved %d, kept %v, failed %v", len(m.Moved), m.Kept, m.Failed)
	}
	// The old folder keeps only the note saying where everything went.
	entries, _ := os.ReadDir(l.old)
	if len(entries) != 1 || entries[0].Name() != OldFolderNote {
		t.Fatalf("the old folder holds %v", entries)
	}
	note := l.read(filepath.Join(l.old, OldFolderNote))
	if !strings.Contains(note, l.config) || !strings.Contains(note, l.data) || !strings.Contains(note, "secretvault where") || !strings.Contains(note, "delete this folder") {
		t.Fatalf("the note:\n%s", note)
	}
	if !strings.Contains(m.Summary(), l.old) || !strings.Contains(m.Summary(), l.data) {
		t.Fatalf("summary: %s", m.Summary())
	}
}

func TestVaultPathsInTheOldFolderArePointedAtTheNewOneAndOthersAreLeftAlone(t *testing.T) {
	l := newOldLayout(t)
	m := l.move()
	paths := l.vaultPaths(l.config)
	if paths["test"] != filepath.Join(l.data, "vaults", "test") {
		t.Errorf("the vault in the old folder is at %q", paths["test"])
	}
	if paths["work"] != l.elsewhere {
		t.Errorf("the vault kept elsewhere is now said to be at %q", paths["work"])
	}
	if got := l.read(filepath.Join(l.elsewhere, "vault.json")); got != "the work vault" {
		t.Errorf("the vault kept elsewhere: %q", got)
	}
	if len(m.Changed) != 1 || !strings.Contains(m.Changed[0], `"test"`) {
		t.Errorf("changed %v", m.Changed)
	}
	// What secretvault does not know of in the settings is kept as it was.
	var cfg map[string]any
	d := json.NewDecoder(strings.NewReader(l.read(filepath.Join(l.config, ConfigFile))))
	d.UseNumber()
	if err := d.Decode(&cfg); err != nil {
		t.Fatal(err)
	}
	future, _ := json.Marshal(cfg["future_setting"])
	if string(future) != `{"kept":[1,2,12345678901234567]}` || cfg["default"] != "test" || cfg["secret_service"] != true {
		t.Errorf("the settings lost something: %v", cfg)
	}
	if st, err := os.Stat(filepath.Join(l.config, ConfigFile)); err != nil || st.Mode().Perm() != 0o600 {
		t.Errorf("config.json: %v %v", st.Mode(), err)
	}
}

func TestWhatTheNewPlaceHasAlreadyIsNotWrittenOver(t *testing.T) {
	l := newOldLayout(t)
	l.write(filepath.Join(l.data, "device.json"), `{"id":"newer"}`)
	l.write(filepath.Join(l.data, "vaults", "other", "vault.json"), "another vault")
	l.write(filepath.Join(l.data, "vaults", "test", "vault.json"), "a different descriptor")
	m := l.move()

	if got := l.read(filepath.Join(l.data, "device.json")); got != `{"id":"newer"}` {
		t.Fatalf("device.json was written over: %q", got)
	}
	if got := l.read(filepath.Join(l.old, "device.json")); got != `{"id":"device"}` {
		t.Fatalf("the old device.json: %q", got)
	}
	// Folders both have are merged: what only the old one has moves, what
	// both have stays in both.
	if got := l.read(filepath.Join(l.data, "vaults", "test", "objects", "ab", "cdef")); got != "an object" {
		t.Fatalf("merged: %q", got)
	}
	if got := l.read(filepath.Join(l.data, "vaults", "test", "vault.json")); got != "a different descriptor" {
		t.Fatalf("the vault's descriptor was written over: %q", got)
	}
	l.read(filepath.Join(l.old, "vaults", "test", "vault.json"))
	l.read(filepath.Join(l.data, "vaults", "other", "vault.json"))
	want := []string{filepath.Join(l.old, "device.json"), filepath.Join(l.old, "vaults", "test", "vault.json")}
	if !slices.Equal(m.Kept, want) {
		t.Fatalf("kept %v, want %v", m.Kept, want)
	}
	// The vault is still in the old folder, so the settings say so.
	if p := l.vaultPaths(l.config)["test"]; p != filepath.Join(l.old, "vaults", "test") {
		t.Fatalf("the vault left in the old folder is said to be at %q", p)
	}
	note := l.read(filepath.Join(l.old, OldFolderNote))
	if !strings.Contains(note, want[0]) || !strings.Contains(note, want[1]) || strings.Contains(note, "delete this folder") {
		t.Fatalf("the note:\n%s", note)
	}
}

func TestMovingAgainDoesNothing(t *testing.T) {
	l := newOldLayout(t)
	l.move()
	before := l.read(filepath.Join(l.config, ConfigFile))
	noteAt := func() time.Time {
		st, err := os.Stat(filepath.Join(l.old, OldFolderNote))
		if err != nil {
			t.Fatal(err)
		}
		return st.ModTime()
	}
	at := noteAt()
	time.Sleep(10 * time.Millisecond)
	if (MoveOptions{Old: l.old, Config: l.config, Data: l.data}).pending() {
		t.Fatal("something is still to move")
	}
	m := l.move()
	if m.Did() || len(m.Kept)+len(m.Failed) != 0 || m.Summary() != "" {
		t.Fatalf("a second run did %+v", m)
	}
	if l.read(filepath.Join(l.config, ConfigFile)) != before || !noteAt().Equal(at) {
		t.Fatal("a second run changed something")
	}
}

func TestAMoveCutShortIsFinished(t *testing.T) {
	l := newOldLayout(t)
	// An earlier run moved the settings and some data, and was stopped
	// while copying the vaults across filesystems, after copying the
	// device key but before removing the original.
	for _, f := range []string{"config.json", "browser-install.json"} {
		os.MkdirAll(l.config, 0o700)
		if err := os.Rename(filepath.Join(l.old, f), filepath.Join(l.config, f)); err != nil {
			t.Fatal(err)
		}
	}
	os.MkdirAll(l.data, 0o700)
	if err := os.Rename(filepath.Join(l.old, "audit"), filepath.Join(l.data, "audit")); err != nil {
		t.Fatal(err)
	}
	l.write(filepath.Join(l.data, "device-signing.key"), "signing key")
	l.write(filepath.Join(l.data, movingPrefix+"vaults-0123456789ab", "test", "vault.json"), "half a copy")

	m := l.move()
	if len(m.Kept)+len(m.Failed) != 0 {
		t.Fatalf("kept %v, failed %v", m.Kept, m.Failed)
	}
	l.read(filepath.Join(l.data, "vaults", "test", "objects", "ab", "cdef"))
	l.read(filepath.Join(l.data, "device.json"))
	l.gone(filepath.Join(l.old, "device-signing.key")) // the same as the copy: removed
	l.gone(filepath.Join(l.data, movingPrefix+"vaults-0123456789ab"))
	if p := l.vaultPaths(l.config)["test"]; p != filepath.Join(l.data, "vaults", "test") {
		t.Fatalf("the vault is said to be at %q", p)
	}
	entries, _ := os.ReadDir(l.old)
	if len(entries) != 1 || entries[0].Name() != OldFolderNote {
		t.Fatalf("the old folder holds %v", entries)
	}
}

func TestAcrossFilesystemsFilesAreCopiedCheckedThenRemoved(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("stands in EXDEV")
	}
	l := newOldLayout(t)
	saved := rename
	t.Cleanup(func() { rename = saved })
	// Every rename between the two trees fails as across filesystems;
	// the copy's own rename, beside its place, works.
	rename = func(from, to string) error {
		if strings.HasPrefix(from, l.old) {
			return &os.LinkError{Op: "rename", Old: from, New: to, Err: syscall.EXDEV}
		}
		return saved(from, to)
	}
	if err := os.Symlink("vault.json", filepath.Join(l.old, "vaults", "test", "link")); err != nil {
		t.Fatal(err)
	}
	os.Chmod(filepath.Join(l.old, "device-signing.key"), 0o400)
	m := l.move()
	if len(m.Kept)+len(m.Failed) != 0 || len(m.Moved) != 8 {
		t.Fatalf("moved %v, kept %v, failed %v", m.Moved, m.Kept, m.Failed)
	}
	if got := l.read(filepath.Join(l.data, "vaults", "test", "objects", "ab", "cdef")); got != "an object" {
		t.Fatalf("copied: %q", got)
	}
	if target, err := os.Readlink(filepath.Join(l.data, "vaults", "test", "link")); err != nil || target != "vault.json" {
		t.Fatalf("a link was copied as %q, %v", target, err)
	}
	if st, err := os.Stat(filepath.Join(l.data, "device-signing.key")); err != nil || st.Mode().Perm() != 0o400 {
		t.Fatalf("the key's mode: %v %v", st.Mode(), err)
	}
	l.gone(filepath.Join(l.old, "vaults"))
	matches, _ := filepath.Glob(filepath.Join(l.data, movingPrefix+"*"))
	if len(matches) != 0 {
		t.Fatalf("copies left behind: %v", matches)
	}
}

func TestACopyThatDiffersIsNotKept(t *testing.T) {
	src := filepath.Join(t.TempDir(), "a")
	os.MkdirAll(filepath.Join(src, "sub"), 0o700)
	os.WriteFile(filepath.Join(src, "sub", "f"), []byte("one"), 0o600)
	dst := filepath.Join(t.TempDir(), "b")
	if err := copyTree(src, dst); err != nil {
		t.Fatal(err)
	}
	if err := sameTree(src, dst); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dst, "sub", "f"), []byte("two"), 0o600)
	if err := sameTree(src, dst); err == nil {
		t.Fatal("a copy that differs passed the check")
	}
}

func TestAGnuPGFolderMovesAndGPGIsPointedAtItAgain(t *testing.T) {
	l := newOldLayout(t)
	gnupg := filepath.Join(l.old, "gnupg")
	l.write(filepath.Join(gnupg, "gpg.conf"), "agent-program /usr/bin/secretvault|--secretvault-gpg-agent\n")
	var cfg map[string]any
	json.Unmarshal([]byte(l.read(filepath.Join(l.old, ConfigFile))), &cfg)
	cfg["gnupg"] = []any{
		map[string]any{"home": gnupg, "socket": filepath.Join(l.home, "run", "gnupg", "d.old", "S.gpg-agent"), "ssh_socket": filepath.Join(l.home, "run", "gnupg", "d.old", "S.gpg-agent.ssh")},
		map[string]any{"home": filepath.Join(l.home, ".gnupg"), "socket": filepath.Join(l.home, "run", "gnupg", "S.gpg-agent")},
	}
	b, _ := json.Marshal(cfg)
	l.write(filepath.Join(l.old, ConfigFile), string(b))

	l.move()
	var got struct {
		GnuPG []struct {
			Home      string `json:"home"`
			Socket    string `json:"socket"`
			SSHSocket string `json:"ssh_socket"`
		} `json:"gnupg"`
	}
	json.Unmarshal([]byte(l.read(filepath.Join(l.config, ConfigFile))), &got)
	if len(got.GnuPG) != 2 || got.GnuPG[0].Home != filepath.Join(l.data, "gnupg") ||
		got.GnuPG[0].Socket != filepath.Join(l.home, "run", "gnupg", "d.new", "S.gpg-agent") ||
		got.GnuPG[0].SSHSocket != filepath.Join(l.home, "run", "gnupg", "d.new", "S.gpg-agent.ssh") {
		t.Fatalf("the moved GnuPG folder: %+v", got.GnuPG)
	}
	if got.GnuPG[1].Home != filepath.Join(l.home, ".gnupg") || got.GnuPG[1].Socket != filepath.Join(l.home, "run", "gnupg", "S.gpg-agent") {
		t.Fatalf("a GnuPG folder elsewhere was changed: %+v", got.GnuPG[1])
	}
	// A GNUPGHOME naming the old place still leads to it.
	if target, err := os.Readlink(gnupg); err != nil || target != filepath.Join(l.data, "gnupg") {
		t.Fatalf("the old place: %q, %v", target, err)
	}
	l.read(filepath.Join(gnupg, "gpg.conf"))
	if m := l.move(); m.Did() || len(m.Kept) != 0 {
		t.Fatalf("a second run: %+v", m)
	}
}

func TestNothingMovesWhenTheDataFolderIsChosen(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv(svcore.EnvConfig, "")
	old := filepath.Join(home, ".local", "share", "secretvault")
	os.MkdirAll(old, 0o700)
	os.WriteFile(filepath.Join(old, "device.json"), []byte("{}"), 0o600)
	t.Setenv(svcore.EnvHome, old)
	if m, err := MoveOldFolderHere(nil); err != nil || m.Did() {
		t.Fatalf("%+v %v", m, err)
	}
	if _, err := os.Stat(filepath.Join(old, "device.json")); err != nil {
		t.Fatal(err)
	}
}

func TestOnlyOneProgramMovesTheOldFolderAndNotWhileADaemonRuns(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the Linux layout")
	}
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_DATA_HOME", "")
	t.Setenv("XDG_CONFIG_HOME", "")
	t.Setenv(svcore.EnvConfig, "")
	t.Setenv(svcore.EnvHome, "")
	old := filepath.Join(home, ".local", "share", "secretvault")
	os.MkdirAll(old, 0o700)
	os.WriteFile(filepath.Join(old, "device.json"), []byte("{}"), 0o600)
	sock := filepath.Join(t.TempDir(), "run", "secretvaultd.sock")
	os.MkdirAll(filepath.Dir(sock), 0o700)

	// A daemon holds the socket's lock: nothing moves.
	unlock, ok, err := tryLock(sock + ".lock")
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	if m, err := MoveOldFolderUnlessRunning(sock, nil); err != nil || m.Did() {
		t.Fatalf("while a daemon runs: %+v %v", m, err)
	}
	unlock()
	m, err := MoveOldFolderUnlessRunning(sock, nil)
	if err != nil || !m.Did() {
		t.Fatalf("with no daemon: %+v %v", m, err)
	}
	if _, err := os.Stat(filepath.Join(home, ".data", "secretvault", "device.json")); err != nil {
		t.Fatal(err)
	}
	// The lock is free again for the daemon.
	if unlock, ok, _ := tryLock(sock + ".lock"); !ok {
		t.Fatal("the lock was kept")
	} else {
		unlock()
	}
}

func TestAnOldFolderThatIsALinkIsLeftAlone(t *testing.T) {
	l := newOldLayout(t)
	real := filepath.Join(l.home, "disk", "secretvault")
	os.MkdirAll(filepath.Dir(real), 0o700)
	if err := os.Rename(l.old, real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, l.old); err != nil {
		t.Skip(err)
	}
	if m := l.move(); m.Did() {
		t.Fatalf("%+v", m)
	}
	l.read(filepath.Join(real, "device.json"))
}
