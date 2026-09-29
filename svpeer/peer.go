// Package svpeer identifies the program on the other end of a request:
// which process, which user, which executable, which sandboxed app, which
// terminal session. secretvaultd's consent broker keys every remembered
// decision on the Identity this package produces, and shows Display to
// the person it asks.
//
// Identification is only as strong as the operating system makes it. The
// kernel vouches for the process ID and user of a socket peer; everything
// else is read from the kernel's view of that process, which the process
// cannot rewrite, but which another program running as the same user can
// sometimes imitate (see docs/security.md, "Programs running as you").
package svpeer

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// Process is what is known about a peer.
type Process struct {
	PID int
	UID int

	// Exe is the resolved path of the program's executable, "" if unknown.
	Exe string

	// Comm is the process's own name for itself (at most 15 bytes on
	// Linux). The process can change it at will, so it is only ever shown,
	// never trusted.
	Comm string

	// Script is the script an interpreter was started on (python3 tool.py),
	// when Exe is a known interpreter.
	Script string

	// SystemOwned is true when Exe belongs to the administrator (owned by
	// root, not writable by anyone else): installed by the package manager
	// or an admin, so its path is a stable identity across updates.
	SystemOwned bool

	// ExeHash is the SHA-256 of a user-writable executable, which then
	// becomes part of its identity: if the file changes, it is asked about
	// again.
	ExeHash string

	// Flatpak and Snap are the sandboxed app's ID. Inside the sandbox the
	// app cannot change them, so they are the strongest identity there is
	// on Linux.
	Flatpak string
	Snap    string

	// Terminal is the terminal session the process belongs to, "" when it
	// has no controlling terminal. It is stable for the session's life and
	// different for every new session, even on a reused terminal device.
	Terminal string

	// TTY is the terminal's name, for display ("pts/3").
	TTY string
}

// ErrUnsupported is identification on a platform this build cannot do it on.
var ErrUnsupported = errors.New("svpeer: cannot identify peers on this platform")

// ErrOtherUser is a peer running as a different user.
var ErrOtherUser = errors.New("svpeer: the peer runs as another user")

// FromConn identifies the process on the other end of a local socket and
// checks that it runs as the same user as this process.
func FromConn(c net.Conn) (*Process, error) {
	pid, uid, err := peerCred(c)
	if err != nil {
		return nil, err
	}
	if uid != os.Getuid() {
		return nil, fmt.Errorf("%w (uid %d)", ErrOtherUser, uid)
	}
	p, err := Describe(pid)
	if err != nil {
		return nil, err
	}
	p.UID = uid
	return p, nil
}

// FromConnAnyUser is FromConn without the same-user check, for a daemon
// that serves other users by policy (secretvaultd's host mode): the
// caller decides what the peer's UID may do.
func FromConnAnyUser(c net.Conn) (*Process, error) {
	pid, uid, err := peerCred(c)
	if err != nil {
		return nil, err
	}
	p, err := Describe(pid)
	if err != nil {
		return nil, err
	}
	p.UID = uid
	return p, nil
}

// PeerCred is the kernel's word on the other end of a local socket: its
// process and user IDs, whoever it runs as.
func PeerCred(c net.Conn) (pid, uid int, err error) { return peerCred(c) }

// Describe identifies a process by its ID (for callers known by PID, such
// as D-Bus clients).
func Describe(pid int) (*Process, error) {
	p := &Process{PID: pid, UID: -1}
	if err := describe(p); err != nil {
		return nil, err
	}
	if p.Exe != "" && p.Flatpak == "" && p.Snap == "" && !p.SystemOwned {
		p.ExeHash = hashFile(p.Exe)
	}
	return p, nil
}

// Parent identifies the program that started process pid: the browser
// behind the native-messaging host it ran, say. pid's parent is read
// again after it has been described, so a parent that exited meanwhile
// (its child then passes to another, and its process ID may be reused)
// is not mistaken for the program that took over its ID.
func Parent(pid int) (*Process, error) {
	ppid, err := parentPID(pid)
	if err != nil {
		return nil, err
	}
	if ppid <= 1 {
		return nil, fmt.Errorf("svpeer: process %d has no parent of its own", pid)
	}
	p, err := Describe(ppid)
	if err != nil {
		return nil, err
	}
	if again, err := parentPID(pid); err != nil || again != ppid {
		return nil, fmt.Errorf("svpeer: the parent of process %d went away while it was read", pid)
	}
	return p, nil
}

// ForPath describes the program at path, for deciding about it before it
// runs ("always allow /usr/bin/backup"). "flatpak:<app>" and "snap:<name>"
// name sandboxed apps.
func ForPath(path string) (*Process, error) {
	if app, ok := strings.CutPrefix(path, "flatpak:"); ok && app != "" {
		return &Process{Flatpak: app}, nil
	}
	if name, ok := strings.CutPrefix(path, "snap:"); ok && name != "" {
		return &Process{Snap: name}, nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		abs = real
	}
	st, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("svpeer: %s is not a program file", abs)
	}
	p := &Process{Exe: abs, SystemOwned: systemOwned(st)}
	if !p.SystemOwned {
		p.ExeHash = hashFile(abs)
	}
	return p, nil
}

// Identity is the stable key a decision about this program is stored
// under. It never includes the process ID.
func (p *Process) Identity() string {
	switch {
	case p.Flatpak != "":
		return "flatpak:" + p.Flatpak
	case p.Snap != "":
		return "snap:" + p.Snap
	case p.Exe == "":
		return fmt.Sprintf("unknown:pid-%d", p.PID)
	}
	id := "exe:" + p.Exe
	if p.Script != "" {
		id += " " + p.Script
	}
	if !p.SystemOwned && p.ExeHash != "" {
		id += "#sha256:" + p.ExeHash
	}
	return id
}

// Display is how the program is named to a person.
func (p *Process) Display() string {
	switch {
	case p.Flatpak != "":
		return p.Flatpak + " (Flatpak)"
	case p.Snap != "":
		return p.Snap + " (Snap)"
	case p.Exe == "" && p.Comm != "":
		return fmt.Sprintf("an unidentified program calling itself %q (process %d)", p.Comm, p.PID)
	case p.Exe == "":
		return fmt.Sprintf("an unidentified program (process %d)", p.PID)
	}
	name := filepath.Base(p.Exe)
	if p.Script != "" {
		return fmt.Sprintf("%s (%s %s)", filepath.Base(p.Script), name, p.Script)
	}
	return fmt.Sprintf("%s (%s)", name, p.Exe)
}

// interpreters run scripts: their identity includes the script.
var interpreters = map[string]bool{
	"python": true, "python2": true, "python3": true, "perl": true, "ruby": true,
	"node": true, "nodejs": true, "bun": true, "deno": true, "php": true,
	"bash": true, "sh": true, "dash": true, "zsh": true, "fish": true,
	"java": true, "lua": true, "osascript": true, "pwsh": true, "powershell.exe": true,
}

func isInterpreter(exe string) bool {
	base := strings.ToLower(filepath.Base(exe))
	base = strings.TrimSuffix(base, ".exe")
	if interpreters[base] {
		return true
	}
	// python3.12, perl5.38 and the like.
	for name := range interpreters {
		if strings.HasPrefix(base, name) && len(base) > len(name) && (base[len(name)] == '.' || base[len(name)] >= '0' && base[len(name)] <= '9') {
			return true
		}
	}
	return false
}

// inlineFlags are the options with which each interpreter runs code from
// its command line (or a module) instead of a script file.
var inlineFlags = map[string][]string{
	"python": {"-c", "-m"}, "perl": {"-e", "-E"}, "ruby": {"-e"}, "node": {"-e", "-p", "--eval", "--print"},
	"php": {"-r"}, "lua": {"-e"}, "osascript": {"-e"}, "pwsh": {"-c", "-command"}, "java": {"-jar"},
}

// scriptArg picks the script from an interpreter's arguments: the first
// argument that is not an option, unless the code came inline.
func scriptArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	base := strings.TrimSuffix(strings.ToLower(filepath.Base(args[0])), ".exe")
	inline := []string{"-c"} // shells
	for name, flags := range inlineFlags {
		if strings.HasPrefix(base, name) {
			inline = flags
		}
	}
	for i := 1; i < len(args); i++ {
		a := args[i]
		for _, f := range inline {
			if strings.EqualFold(a, f) {
				if f == "-jar" && i+1 < len(args) {
					return args[i+1] // java -jar app.jar: the jar is the program
				}
				return ""
			}
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		return a
	}
	return ""
}

var hashCache sync.Map // key: path|size|mtime -> hex

// hashFile hashes an executable, caching by path, size and modification
// time, so a large program is hashed once, not on every request.
func hashFile(path string) string {
	fi, err := os.Stat(path)
	if err != nil || !fi.Mode().IsRegular() {
		return ""
	}
	key := fmt.Sprintf("%s|%d|%d", path, fi.Size(), fi.ModTime().UnixNano())
	if v, ok := hashCache.Load(key); ok {
		return v.(string)
	}
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	sum := hex.EncodeToString(h.Sum(nil))
	hashCache.Store(key, sum)
	return sum
}
