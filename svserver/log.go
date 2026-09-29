package svserver

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// A vault's change log gives every file created or removed a sequence
// number, so a device can ask for "everything after n". It is a text file
// that is only ever appended to, each line synced before it counts:
//
//	svlog1 <log id>
//	<seq> + <name> <size> <sha256>
//	<seq> - <name>
//
// Sequence numbers run 1, 2, 3, ... without a gap. A line cut short by a
// crash is dropped when the log is next opened; the file it described is
// still on disk, and is logged again by the reconciliation that follows
// (vault.go), so nothing is lost.

const logMagic = "svlog1"

type changeLog struct {
	f       *os.File
	id      string
	size    int64
	entries []Change

	// broken is set when a failed append could not be undone: the file
	// may end in a partial line, so nothing more may be appended.
	broken error
}

// openLog opens the log at path, starting a new one if there is none.
func openLog(path string) (*changeLog, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return newLog(path)
	}
	if err != nil {
		return nil, err
	}
	nl := bytes.IndexByte(b, '\n')
	if nl < 0 {
		// Cut short while it was being made: nothing was ever logged.
		return newLog(path)
	}
	magic, id, _ := strings.Cut(string(b[:nl]), " ")
	if magic != logMagic || len(id) != 32 {
		return nil, fmt.Errorf("svserver: %s is not a change log", path)
	}
	l := &changeLog{id: id}
	good := nl + 1
	rest := b[good:]
	for len(rest) > 0 {
		end := bytes.IndexByte(rest, '\n')
		if end < 0 {
			break // a torn last line
		}
		c, err := parseLogLine(string(rest[:end]))
		if err != nil || c.Seq != uint64(len(l.entries))+1 {
			return nil, fmt.Errorf("svserver: %s: line %d is damaged", path, len(l.entries)+2)
		}
		l.entries = append(l.entries, c)
		good += end + 1
		rest = rest[end+1:]
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	if good < len(b) {
		if err := f.Truncate(int64(good)); err != nil {
			f.Close()
			return nil, err
		}
		if err := f.Sync(); err != nil {
			f.Close()
			return nil, err
		}
	}
	l.f, l.size = f, int64(good)
	return l, nil
}

// newLog starts an empty log with a fresh ID, replacing whatever is at
// path (only ever an empty or torn log).
func newLog(path string) (*changeLog, error) {
	var raw [16]byte
	rand.Read(raw[:])
	id := hex.EncodeToString(raw[:])
	header := logMagic + " " + id + "\n"
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(header), 0o600); err != nil {
		return nil, err
	}
	if err := syncFile(tmp); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return nil, err
	}
	syncDir(filepath.Dir(path))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	return &changeLog{f: f, id: id, size: int64(len(header))}, nil
}

func parseLogLine(s string) (Change, error) {
	f := strings.Fields(s)
	bad := fmt.Errorf("bad log line %q", s)
	if len(f) < 3 {
		return Change{}, bad
	}
	seq, err := strconv.ParseUint(f[0], 10, 64)
	if err != nil {
		return Change{}, bad
	}
	c := Change{Seq: seq, Name: f[2]}
	switch {
	case f[1] == "+" && len(f) == 5:
		c.Op, c.SHA256 = OpCreate, f[4]
		if c.Size, err = strconv.ParseInt(f[3], 10, 64); err != nil || len(c.SHA256) != 64 {
			return Change{}, bad
		}
	case f[1] == "-" && len(f) == 3:
		c.Op = OpRemove
	default:
		return Change{}, bad
	}
	return c, nil
}

func formatLogLine(c Change) string {
	if c.Op == OpCreate {
		return fmt.Sprintf("%d + %s %d %s\n", c.Seq, c.Name, c.Size, c.SHA256)
	}
	return fmt.Sprintf("%d - %s\n", c.Seq, c.Name)
}

// append logs a change, giving it the next sequence number, and returns
// it once it is on disk.
func (l *changeLog) append(c Change) (Change, error) {
	if l.broken != nil {
		return Change{}, l.broken
	}
	c.Seq = l.latest() + 1
	line := formatLogLine(c)
	_, err := l.f.Write([]byte(line))
	if err == nil {
		err = l.f.Sync()
	}
	if err != nil {
		// Take back whatever part of the line reached the file, so the
		// next append does not continue a torn one.
		if terr := l.f.Truncate(l.size); terr != nil {
			l.broken = fmt.Errorf("svserver: the change log could not be repaired after a failed write: %v", terr)
		}
		return Change{}, err
	}
	l.size += int64(len(line))
	l.entries = append(l.entries, c)
	return c, nil
}

func (l *changeLog) latest() uint64 { return uint64(len(l.entries)) }

// after returns up to limit changes after seq, and whether there are more.
func (l *changeLog) after(seq uint64, limit int) ([]Change, bool) {
	if seq >= l.latest() {
		return nil, false
	}
	rest := l.entries[seq:]
	if len(rest) > limit {
		return append([]Change(nil), rest[:limit]...), true
	}
	return append([]Change(nil), rest...), false
}

func (l *changeLog) close() error { return l.f.Close() }

func syncFile(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	err = f.Sync()
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

// syncDir makes a new directory entry durable, where the OS allows it
// (Windows does not open directories this way; NTFS journals entries).
func syncDir(dir string) {
	if f, err := os.Open(dir); err == nil {
		_ = f.Sync()
		f.Close()
	}
}
