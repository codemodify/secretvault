package svops

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/codemodify/secretvault/svcore"
)

// Moving out of the one folder secretvault used to keep everything in
// (svcore.LegacyDir: ~/.local/share/secretvault on Linux) into the two it
// keeps now: the settings folder (svcore.ConfigDir) and the data folder
// (svcore.DataDir). secretvaultd does it as it starts, holding the lock
// that keeps a second daemon away, before it reads anything; the CLI and
// the managers do it before they start a daemon, unless one runs
// (MoveOldFolderUnlessRunning). Nothing is moved when $SECRETVAULT_HOME
// is set: a folder chosen by hand stays where it is.
//
//   - The settings (config.json) and the records of what secretvault
//     changed in other programs (SettingsFiles) go to the settings
//     folder; everything else to the data folder.
//   - Each is renamed, or, across filesystems, copied (each file synced),
//     checked against the original, and only then the original removed.
//   - Nothing is ever written over: what the new place already has is
//     left in both places, and said so. A folder both have is merged,
//     file by file, by the same rule.
//   - config.json's paths into the old folder (a vault's, a GnuPG
//     folder's) are pointed at where each went; paths elsewhere are left
//     alone.
//   - The old folder keeps only a note (README.txt) saying where
//     everything went, and, when secretvault's GnuPG folder moved, a link
//     to it, for a GNUPGHOME that still names the old one.
//
// Doing it again does nothing, and an earlier run cut short is finished.

// ConfigFile is secretvaultd's settings file, in the settings folder.
const ConfigFile = "config.json"

// SettingsFiles are the files kept in the settings folder: the settings,
// and the records of what secretvault changed in other programs, which
// undoing reads.
var SettingsFiles = []string{ConfigFile, BrowserInstallFile, TakeoverFile, HelpersFile, GUIFile}

// OldFolderNote is the note left in the old folder.
const OldFolderNote = "README.txt"

// oldFolderNoteHead is its first line, which tells it from a file of the
// person's own.
const oldFolderNoteHead = "secretvault no longer keeps its files in this folder."

// movingPrefix starts the name of a copy being made across filesystems,
// beside where it goes; one left by a run cut short is removed.
const movingPrefix = ".secretvault-moving-"

// FolderMove is what moving the old folder did.
type FolderMove struct {
	Old, Config, Data string
	Moved             []string // what went where, a line each
	Kept              []string // left in the old folder: the new place has one already
	Changed           []string // paths in the settings pointed at their new places
	Failed            []string // what could not be moved, and why
}

// Did reports whether anything was moved or changed.
func (m *FolderMove) Did() bool { return len(m.Moved) > 0 || len(m.Changed) > 0 }

// Summary says what was done in a sentence, "" when nothing was.
func (m *FolderMove) Summary() string {
	if !m.Did() && len(m.Failed) == 0 {
		return ""
	}
	s := fmt.Sprintf("secretvault moved its files out of %s: the settings to %s, everything else to %s", m.Old, m.Config, m.Data)
	switch n := len(m.Kept) + len(m.Failed); n {
	case 0:
	case 1:
		s += fmt.Sprintf("; one thing stayed where it was (%s says which)", filepath.Join(m.Old, OldFolderNote))
	default:
		s += fmt.Sprintf("; %d things stayed where they were (%s says which)", n, filepath.Join(m.Old, OldFolderNote))
	}
	return s + "."
}

// MoveOptions say what to move where.
type MoveOptions struct {
	Old, Config, Data string

	// Log is told each thing done, a line each (nil: nobody).
	Log func(string)

	// GnuPGSockets is where gpg looks for its agent's sockets for a GnuPG
	// folder that moved (gpgconf --list-dirs, through GnuPGDir, when nil;
	// tests stand in).
	GnuPGSockets func(home string) (agent, ssh string, err error)
}

// MoveOldFolderHere moves this user's old folder, as the environment
// places the folders, unless $SECRETVAULT_HOME is set. secretvaultd calls
// it as it starts, holding its socket's lock; any other program calls
// MoveOldFolderUnlessRunning.
func MoveOldFolderHere(log func(string)) (*FolderMove, error) {
	o, ok, err := moveOptionsHere()
	if err != nil || !ok {
		return &FolderMove{}, err
	}
	o.Log = log
	return MoveOldFolder(o)
}

// MoveOldFolderUnlessRunning is MoveOldFolderHere for a program that may
// start a daemon on socket (the CLI, the managers): it does nothing while
// a daemon runs there, since the daemon moves the folder as it starts,
// and keeps one from starting meanwhile. With nothing to move, it does
// not even look.
func MoveOldFolderUnlessRunning(socket string, log func(string)) (*FolderMove, error) {
	o, ok, err := moveOptionsHere()
	if err != nil || !ok || !o.pending() {
		return &FolderMove{}, err
	}
	if err := os.MkdirAll(filepath.Dir(socket), 0o700); err != nil {
		return &FolderMove{}, err
	}
	unlock, ok, err := tryLock(socket + ".lock")
	if err != nil || !ok {
		return &FolderMove{}, err
	}
	defer unlock()
	o.Log = log
	return MoveOldFolder(o)
}

func moveOptionsHere() (MoveOptions, bool, error) {
	if os.Getenv(svcore.EnvHome) != "" {
		return MoveOptions{}, false, nil
	}
	old, err := svcore.LegacyDir()
	if err != nil {
		return MoveOptions{}, false, err
	}
	config, err := svcore.ConfigDir()
	if err != nil {
		return MoveOptions{}, false, err
	}
	data, err := svcore.DataDir()
	if err != nil {
		return MoveOptions{}, false, err
	}
	return MoveOptions{Old: old, Config: config, Data: data}, true, nil
}

// target is where an entry of the old folder goes: the settings folder
// or the data folder.
func (o MoveOptions) target(name string) string {
	if slices.Contains(SettingsFiles, name) {
		return o.Config
	}
	return o.Data
}

// leftHere reports whether an entry of the old folder is one the move
// leaves there: the note, and the link to the GnuPG folder.
func (o MoveOptions) leftHere(name string) bool {
	p := filepath.Join(o.Old, name)
	if name == OldFolderNote {
		b, err := os.ReadFile(p)
		return err == nil && bytes.HasPrefix(b, []byte(oldFolderNoteHead))
	}
	if t, err := os.Readlink(p); err == nil {
		return t == filepath.Join(o.target(name), name)
	}
	return false
}

// pending reports whether the old folder has anything to move: something
// whose new place does not have it yet, or a folder to merge.
func (o MoveOptions) pending() bool {
	st, err := os.Lstat(o.Old)
	if err != nil || !st.IsDir() {
		return false
	}
	entries, _ := os.ReadDir(o.Old)
	for _, e := range entries {
		dir := o.target(e.Name())
		if sameDir(dir, o.Old) || o.leftHere(e.Name()) {
			continue
		}
		dst, err := os.Lstat(filepath.Join(dir, e.Name()))
		if err != nil || (dst.IsDir() && e.IsDir()) {
			return true
		}
	}
	return false
}

// MoveOldFolder moves what is in o.Old to o.Config and o.Data. It
// returns an error only when it could not start; what it could not move
// is in Failed, and stays where it was.
func MoveOldFolder(o MoveOptions) (*FolderMove, error) {
	m := &mover{o: o, res: &FolderMove{Old: o.Old, Config: o.Config, Data: o.Data}}
	if o.Log == nil {
		m.o.Log = func(string) {}
	}
	st, err := os.Lstat(o.Old)
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return m.res, nil
	case err != nil:
		return m.res, err
	case st.Mode()&fs.ModeSymlink != 0:
		m.o.Log(fmt.Sprintf("%s is a link to elsewhere: secretvault left it and what it holds alone (set %s to that folder to keep using it)", o.Old, svcore.EnvHome))
		return m.res, nil
	case !st.IsDir():
		return m.res, nil
	}
	entries, err := os.ReadDir(o.Old)
	if err != nil {
		return m.res, err
	}
	gnupgMoved := false
	for _, e := range entries {
		name := e.Name()
		dir := o.target(name)
		if sameDir(dir, o.Old) || o.leftHere(name) {
			continue
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			m.fail(filepath.Join(o.Old, name), err)
			continue
		}
		moved := m.move(filepath.Join(o.Old, name), filepath.Join(dir, name))
		if name == "gnupg" && moved && e.IsDir() {
			gnupgMoved = true
		}
	}
	m.repoint()
	if gnupgMoved {
		// A GNUPGHOME naming the old folder keeps working.
		link, to := filepath.Join(o.Old, "gnupg"), filepath.Join(o.Data, "gnupg")
		if err := os.Symlink(to, link); err == nil {
			m.o.Log(fmt.Sprintf("linked %s to %s, for a GNUPGHOME that names the old place", link, to))
		}
	}
	if m.res.Did() || len(m.res.Kept)+len(m.res.Failed) > 0 {
		m.note()
	}
	return m.res, nil
}

// mover is one run of MoveOldFolder.
type mover struct {
	o   MoveOptions
	res *FolderMove
}

func (m *mover) moved(src, dst string) {
	line := src + " -> " + dst
	m.res.Moved = append(m.res.Moved, line)
	m.o.Log("moved " + line)
}

func (m *mover) kept(src, dst string) {
	m.res.Kept = append(m.res.Kept, src)
	m.o.Log(fmt.Sprintf("left %s where it is: %s is there already, and is not written over", src, dst))
}

func (m *mover) fail(src string, err error) {
	m.res.Failed = append(m.res.Failed, fmt.Sprintf("%s: %v", src, err))
	m.o.Log(fmt.Sprintf("could not move %s: %v; it stays where it is", src, err))
}

// move moves src to dst, which must not be there: a folder both have is
// merged. It reports whether all of src went.
func (m *mover) move(src, dst string) bool {
	sst, err := os.Lstat(src)
	if err != nil {
		m.fail(src, err)
		return false
	}
	dstat, err := os.Lstat(dst)
	switch {
	case err == nil && sst.IsDir() && dstat.IsDir() && dstat.Mode()&fs.ModeSymlink == 0:
		entries, err := os.ReadDir(src)
		if err != nil {
			m.fail(src, err)
			return false
		}
		all := true
		for _, e := range entries {
			all = m.move(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())) && all
		}
		if all {
			os.Remove(src) // empty now
		}
		return all
	case err == nil && sameEntry(src, dst, sst, dstat):
		// What a run cut short copied, and did not remove yet.
		if err := os.Remove(src); err != nil {
			m.fail(src, err)
			return false
		}
		m.o.Log(fmt.Sprintf("removed %s: %s is the same, moved there before", src, dst))
		return true
	case err == nil:
		m.kept(src, dst)
		return false
	case !errors.Is(err, fs.ErrNotExist):
		m.fail(src, err)
		return false
	}
	// A copy left by a run cut short holds nothing the original lacks.
	stale, _ := filepath.Glob(filepath.Join(filepath.Dir(dst), movingPrefix+globEscape(filepath.Base(dst))+"-*"))
	for _, s := range stale {
		os.RemoveAll(s)
	}
	err = rename(src, dst)
	if err != nil && crossDevice(err) {
		err = copyAcross(src, dst)
		if err == nil {
			if rerr := os.RemoveAll(src); rerr != nil {
				m.o.Log(fmt.Sprintf("copied %s to %s, but could not remove the original: %v", src, dst, rerr))
			}
		}
	}
	if err != nil {
		m.fail(src, err)
		return false
	}
	m.moved(src, dst)
	return true
}

// sameEntry reports whether two files are the same: links to the same
// place, or regular files with the same contents.
func sameEntry(a, b string, sa, sb fs.FileInfo) bool {
	switch {
	case sa.Mode()&fs.ModeSymlink != 0 && sb.Mode()&fs.ModeSymlink != 0:
		ta, err1 := os.Readlink(a)
		tb, err2 := os.Readlink(b)
		return err1 == nil && err2 == nil && ta == tb
	case sa.Mode().IsRegular() && sb.Mode().IsRegular() && sa.Size() == sb.Size():
		ha, err1 := fileSum(a)
		hb, err2 := fileSum(b)
		return err1 == nil && err2 == nil && ha == hb
	}
	return false
}

// rename is os.Rename (tests make it fail as across filesystems).
var rename = os.Rename

// copyAcross copies src to dst on another filesystem: into a copy beside
// dst, each file synced, checked against src, then renamed into place.
func copyAcross(src, dst string) error {
	parent, base := filepath.Dir(dst), filepath.Base(dst)
	var r [6]byte
	rand.Read(r[:])
	tmp := filepath.Join(parent, movingPrefix+base+"-"+hex.EncodeToString(r[:]))
	err := copyTree(src, tmp)
	if err == nil {
		err = sameTree(src, tmp)
	}
	if err == nil {
		if _, lerr := os.Lstat(dst); lerr == nil {
			err = fmt.Errorf("%s appeared meanwhile", dst)
		}
	}
	if err == nil {
		err = os.Rename(tmp, dst)
	}
	if err != nil {
		os.RemoveAll(tmp)
		return err
	}
	syncDir(parent)
	return nil
}

func globEscape(s string) string {
	return strings.NewReplacer(`*`, `\*`, `?`, `\?`, `[`, `\[`).Replace(s)
}

// copyTree copies src to dst (which is not there): folders, files with
// their modes and times, links as links. Each file and folder is synced.
func copyTree(src, dst string) error {
	st, err := os.Lstat(src)
	if err != nil {
		return err
	}
	switch {
	case st.Mode()&fs.ModeSymlink != 0:
		t, err := os.Readlink(src)
		if err != nil {
			return err
		}
		return os.Symlink(t, dst)
	case st.IsDir():
		if err := os.Mkdir(dst, st.Mode().Perm()); err != nil {
			return err
		}
		entries, err := os.ReadDir(src)
		if err != nil {
			return err
		}
		for _, e := range entries {
			if err := copyTree(filepath.Join(src, e.Name()), filepath.Join(dst, e.Name())); err != nil {
				return err
			}
		}
		syncDir(dst)
		return nil
	case st.Mode().IsRegular():
		in, err := os.Open(src)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_EXCL, st.Mode().Perm())
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		if err == nil {
			err = out.Sync()
		}
		if cerr := out.Close(); err == nil {
			err = cerr
		}
		if err == nil {
			os.Chtimes(dst, st.ModTime(), st.ModTime())
		}
		return err
	}
	// A socket or a pipe (a GnuPG folder's, once): there is nothing in it
	// to keep, and whoever made it makes it again.
	return nil
}

// sameTree checks that b holds what a holds: the same folders, files with
// the same contents, links to the same places.
func sameTree(a, b string) error {
	return filepath.WalkDir(a, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(a, p)
		q := filepath.Join(b, rel)
		sa, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !sa.Mode().IsRegular() && !sa.IsDir() && sa.Mode()&fs.ModeSymlink == 0 {
			return nil // not copied (copyTree)
		}
		sb, err := os.Lstat(q)
		if err != nil {
			return fmt.Errorf("the copy lacks %s", rel)
		}
		if sa.Mode().Type() != sb.Mode().Type() {
			return fmt.Errorf("the copy of %s is not the same kind of file", rel)
		}
		switch {
		case sa.Mode()&fs.ModeSymlink != 0:
			ta, _ := os.Readlink(p)
			tb, _ := os.Readlink(q)
			if ta != tb {
				return fmt.Errorf("the copy of the link %s leads elsewhere", rel)
			}
		case sa.Mode().IsRegular():
			ha, err := fileSum(p)
			if err != nil {
				return err
			}
			hb, err := fileSum(q)
			if err != nil {
				return err
			}
			if ha != hb || sa.Size() != sb.Size() {
				return fmt.Errorf("the copy of %s differs from it", rel)
			}
		}
		return nil
	})
}

func fileSum(p string) ([32]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return [32]byte{}, err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return [32]byte{}, err
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return sum, nil
}

// syncDir makes a folder's entries last, where folders can be synced
// (the files in it were synced themselves).
func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		f.Sync()
		f.Close()
	}
}

// newPlace is where a path inside the old folder is now: its new place
// when it was moved there, else "" (it is still where it was, or it is
// gone from both).
func (m *mover) newPlace(p string) string {
	if !filepath.IsAbs(p) {
		return ""
	}
	rel, err := filepath.Rel(m.o.Old, filepath.Clean(p))
	if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return ""
	}
	first, _, _ := strings.Cut(rel, string(filepath.Separator))
	np := filepath.Join(m.o.target(first), rel)
	if np == filepath.Clean(p) {
		return ""
	}
	if _, err := os.Lstat(p); err == nil {
		return "" // still there: not moved
	}
	if _, err := os.Lstat(np); err != nil {
		return ""
	}
	return np
}

// repoint points config.json's paths into the old folder at where each
// went, and asks gpg again where it looks for its agent in a GnuPG folder
// that moved.
func (m *mover) repoint() {
	p := filepath.Join(m.o.Config, ConfigFile)
	b, err := os.ReadFile(p)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			m.o.Log(fmt.Sprintf("%s: %v", p, err))
		}
		return
	}
	var cfg map[string]any
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	if err := dec.Decode(&cfg); err != nil {
		m.o.Log(fmt.Sprintf("%s is not JSON: its paths were left as they are (%v)", p, err))
		return
	}
	changed := false
	note := func(what, from, to string) {
		line := fmt.Sprintf("%s: %s is now %s (was %s)", ConfigFile, what, to, from)
		m.res.Changed = append(m.res.Changed, line)
		m.o.Log(line)
		changed = true
	}
	for _, v := range listOf(cfg["vaults"]) {
		if np := m.newPlace(stringOf(v["path"])); np != "" {
			note(fmt.Sprintf("the vault %q", stringOf(v["name"])), stringOf(v["path"]), np)
			v["path"] = np
		}
	}
	for _, g := range listOf(cfg["gnupg"]) {
		home := stringOf(g["home"])
		np := m.newPlace(home)
		if np == "" {
			continue
		}
		note("the GnuPG folder", home, np)
		g["home"] = np
		agent, ssh := m.gnupgSockets(np)
		for key, now := range map[string]string{"socket": agent, "ssh_socket": ssh} {
			was := stringOf(g[key])
			switch moved := m.newPlace(was); {
			case moved != "":
				g[key] = moved
			case now != "" && was != "":
				g[key] = now
			default:
				continue
			}
			if g[key] != was {
				note("where gpg looks for its agent in it", was, stringOf(g[key]))
			}
		}
	}
	if !changed {
		return
	}
	out, err := json.MarshalIndent(cfg, "", "  ")
	if err == nil {
		err = WriteReplacing(p, append(out, '\n'), 0o600)
	}
	if err != nil {
		m.o.Log(fmt.Sprintf("could not point %s at the new places: %v", p, err))
	}
}

// gnupgSockets asks where gpg looks for its agent in home ("" each when
// it cannot be asked).
func (m *mover) gnupgSockets(home string) (agent, ssh string) {
	ask := m.o.GnuPGSockets
	if ask == nil {
		ask = func(home string) (string, string, error) {
			_, gpgconf, err := GnuPGPrograms("")
			if err != nil {
				return "", "", err
			}
			a, err := GnuPGDir(gpgconf, home, "agent-socket")
			if err != nil {
				return "", "", err
			}
			s, _ := GnuPGDir(gpgconf, home, "agent-ssh-socket")
			return a, s, nil
		}
	}
	a, s, err := ask(home)
	if err != nil {
		return "", ""
	}
	return a, s
}

func listOf(v any) []map[string]any {
	l, _ := v.([]any)
	var out []map[string]any
	for _, e := range l {
		if m, ok := e.(map[string]any); ok {
			out = append(out, m)
		}
	}
	return out
}

func stringOf(v any) string {
	s, _ := v.(string)
	return s
}

// note writes the old folder's README.txt.
func (m *mover) note() {
	var b strings.Builder
	fmt.Fprintln(&b, oldFolderNoteHead)
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "Its settings, and its records of what it changed in other programs, are in\n  %s\n", m.o.Config)
	fmt.Fprintf(&b, "Everything else (your vaults, keys, logs and what it remembers) is in\n  %s\n", m.o.Data)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "'secretvault where' lists every place secretvault keeps or changes anything.")
	if _, err := os.Lstat(filepath.Join(m.o.Old, "gnupg")); err == nil && m.o.leftHere("gnupg") {
		fmt.Fprintln(&b)
		fmt.Fprintf(&b, "gnupg here is a link to %s, for a GNUPGHOME that still names\nthis folder: point it at the new place, then delete the link.\n", filepath.Join(m.o.Data, "gnupg"))
	}
	if left := append(slices.Clone(m.res.Kept), m.res.Failed...); len(left) > 0 {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Left here, because the new place already had one, or it could not be moved")
		fmt.Fprintln(&b, "(secretvault uses what is in the new place):")
		for _, l := range left {
			fmt.Fprintf(&b, "  %s\n", l)
		}
	} else {
		fmt.Fprintln(&b)
		fmt.Fprintln(&b, "Nothing else is left here: you can delete this folder.")
	}
	p := filepath.Join(m.o.Old, OldFolderNote)
	if _, err := os.Lstat(p); err == nil && !m.o.leftHere(OldFolderNote) {
		return // a README.txt of the person's own, which was kept: not written over
	}
	if err := WriteReplacing(p, []byte(b.String()), 0o600); err != nil {
		m.o.Log(fmt.Sprintf("could not leave a note in %s: %v", m.o.Old, err))
	}
}
