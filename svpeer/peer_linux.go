//go:build linux

package svpeer

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func peerCred(c net.Conn) (pid, uid int, err error) {
	sc, ok := c.(syscall.Conn)
	if !ok {
		return 0, 0, errors.New("svpeer: not a socket")
	}
	raw, err := sc.SyscallConn()
	if err != nil {
		return 0, 0, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return 0, 0, err
	}
	if credErr != nil {
		return 0, 0, credErr
	}
	return int(cred.Pid), int(cred.Uid), nil
}

func describe(p *Process) error {
	proc := fmt.Sprintf("/proc/%d", p.PID)
	if _, err := os.Stat(proc); err != nil {
		return fmt.Errorf("svpeer: process %d: %w", p.PID, err)
	}
	// A process that made itself non-dumpable (ssh-agent, gpg-agent and
	// others do) hides its executable from everyone but root. It is then
	// known only by its process ID: unidentifiable, asked about every
	// time, and never the subject of a lasting decision.
	if exe, err := os.Readlink(proc + "/exe"); err == nil {
		p.Exe = strings.TrimSuffix(exe, " (deleted)")
	}
	if stat, err := readStat(p.PID); err == nil {
		p.Comm = stat.comm
	}

	if st, err := os.Stat(p.Exe); p.Exe != "" && err == nil {
		p.SystemOwned = systemOwned(st)
	}
	if p.Exe != "" && isInterpreter(p.Exe) {
		if b, err := os.ReadFile(proc + "/cmdline"); err == nil {
			args := strings.Split(strings.TrimRight(string(b), "\x00"), "\x00")
			p.Script = scriptArg(args)
		}
	}
	if stat, err := readStat(p.PID); err == nil && stat.tty != 0 {
		p.TTY = ttyName(stat.tty)
		// The session leader's start time tells this session apart from
		// a later one that reuses the same session ID and terminal.
		start := ""
		if leader, err := readStat(stat.session); err == nil {
			start = leader.start
		}
		p.Terminal = fmt.Sprintf("tty=%d;sid=%d;start=%s", stat.tty, stat.session, start)
	}
	p.Flatpak = flatpakApp(proc)
	if p.Flatpak == "" {
		p.Snap = snapName(proc)
	}
	return nil
}

// parentPID reads a process's parent from /proc/<pid>/stat.
func parentPID(pid int) (int, error) {
	st, err := readStat(pid)
	if err != nil {
		return 0, fmt.Errorf("svpeer: process %d: %w", pid, err)
	}
	return st.ppid, nil
}

type procStat struct {
	comm    string
	ppid    int
	session int
	tty     int
	start   string
}

// readStat reads the fields we need from /proc/<pid>/stat. The command
// name (field 2) may contain spaces and parentheses, so fields are counted
// from after its last ')'.
func readStat(pid int) (procStat, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return procStat{}, err
	}
	i := bytes.LastIndexByte(b, ')')
	open := bytes.IndexByte(b, '(')
	if i < 0 || open < 0 || open > i {
		return procStat{}, errors.New("svpeer: malformed stat")
	}
	f := strings.Fields(string(b[i+1:]))
	// f[0] is field 3 (state); ppid is field 4, session 6, tty_nr 7,
	// starttime 22.
	if len(f) < 20 {
		return procStat{}, errors.New("svpeer: short stat")
	}
	ppid, err0 := strconv.Atoi(f[1])
	sid, err1 := strconv.Atoi(f[3])
	tty, err2 := strconv.Atoi(f[4])
	if err0 != nil || err1 != nil || err2 != nil {
		return procStat{}, errors.New("svpeer: malformed stat")
	}
	return procStat{comm: string(b[open+1 : i]), ppid: ppid, session: sid, tty: tty, start: f[19]}, nil
}

// ttyName names a terminal device number the way ps does.
func ttyName(dev int) string {
	major := (dev >> 8) & 0xfff
	minor := (dev & 0xff) | ((dev >> 12) & 0xfff00)
	switch {
	case major >= 136 && major <= 143:
		return fmt.Sprintf("pts/%d", minor+(major-136)*256)
	case major == 4 && minor < 64:
		return fmt.Sprintf("tty%d", minor)
	case major == 4:
		return fmt.Sprintf("ttyS%d", minor-64)
	}
	return fmt.Sprintf("tty(%d,%d)", major, minor)
}

// flatpakApp reads the sandbox's app ID from the file Flatpak puts at the
// root of every sandbox; the app cannot change it.
func flatpakApp(proc string) string {
	f, err := os.Open(proc + "/root/.flatpak-info")
	if err != nil {
		return ""
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	inApp := false
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if strings.HasPrefix(line, "[") {
			inApp = line == "[Application]"
			continue
		}
		if name, ok := strings.CutPrefix(line, "name="); ok && inApp {
			return name
		}
	}
	return ""
}

// snapName reads the snap from the process's AppArmor label, which snapd
// sets to snap.<name>.<app> and the confined process cannot change.
func snapName(proc string) string {
	for _, p := range []string{proc + "/attr/apparmor/current", proc + "/attr/current"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		label := strings.Fields(string(b))
		if len(label) == 0 {
			continue
		}
		parts := strings.Split(label[0], ".")
		if len(parts) >= 3 && parts[0] == "snap" {
			return parts[1]
		}
	}
	return ""
}
