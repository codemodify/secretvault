package svbroker

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
)

// The audit log records every access decision about a vault, on this
// device: which program, what it asked for, and what happened. It lives
// beside the daemon's data, one file per vault:
//
//	<dir>/<vault id>.log   one sealed entry per line (base64url)
//	<dir>/<vault id>.pub   the public key entries are sealed to
//
// Entries are sealed with HPKE to a key derived from the vault key, so the
// daemon can append while the vault is locked (a locked vault is exactly
// when refused and pending requests happen) but only an unlocked vault can
// read them back. Each entry carries the SHA-256 of the line before it, so
// removing or reordering lines shows.

// Entry is one audit record.
type Entry struct {
	Time     time.Time `json:"time"`
	Program  string    `json:"program"`
	Identity string    `json:"identity,omitempty"`
	PID      int       `json:"pid,omitempty"`
	Op       Op        `json:"op"`
	Item     string    `json:"item,omitempty"`
	Outcome  string    `json:"outcome"` // allowed, denied, canceled, failed
	Reason   string    `json:"reason,omitempty"`
	Prev     string    `json:"prev,omitempty"`
}

// ErrLogDamaged is an audit log whose chain is broken: lines were removed,
// reordered or altered.
var ErrLogDamaged = errors.New("svbroker: the audit log has been altered")

// Audit writes and reads audit logs.
type Audit struct {
	dir string

	mu      sync.Mutex
	pubs    map[string][]byte  // vault ID -> log public key
	last    map[string]string  // vault ID -> hash of the last line written
	pending map[string][]Entry // entries for vaults whose key is not known yet
}

// NewAudit keeps logs in dir (created 0700 when first needed).
func NewAudit(dir string) *Audit {
	return &Audit{dir: dir, pubs: map[string][]byte{}, last: map[string]string{}, pending: map[string][]Entry{}}
}

func (a *Audit) paths(vid string) (log, pub string) {
	return filepath.Join(a.dir, vid+".log"), filepath.Join(a.dir, vid+".pub")
}

func logKey(v *svcore.Vault) (*svcrypto.Identity, error) {
	seed, err := v.DeriveKey("audit log key", 32)
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	return v.Suite().DeriveLogKey(seed)
}

func logInfo(vid string) []byte { return []byte("secretvault audit " + vid) }

// Unlocked learns (and saves) the vault's log key, and writes out entries
// that waited for it.
func (a *Audit) Unlocked(v *svcore.Vault) error {
	id, err := logKey(v)
	if err != nil {
		return err
	}
	vid := v.ID().String()
	pub := id.Recipient()
	a.mu.Lock()
	defer a.mu.Unlock()
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return err
	}
	_, pubPath := a.paths(vid)
	if err := os.WriteFile(pubPath, []byte(base64.RawURLEncoding.EncodeToString(pub)+"\n"), 0o600); err != nil {
		return err
	}
	a.pubs[vid] = pub
	pending := a.pending[vid]
	delete(a.pending, vid)
	for _, e := range pending {
		if err := a.appendLocked(v, vid, e); err != nil {
			return err
		}
	}
	return nil
}

// Record appends an entry. While the vault's log key is unknown (never
// unlocked on this device) the entry waits in memory.
func (a *Audit) Record(v *svcore.Vault, e Entry) error {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	vid := v.ID().String()
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.pubs[vid] == nil {
		_, pubPath := a.paths(vid)
		if b, err := os.ReadFile(pubPath); err == nil {
			if pub, err := base64.RawURLEncoding.DecodeString(string(bytes.TrimSpace(b))); err == nil {
				a.pubs[vid] = pub
			}
		}
	}
	if a.pubs[vid] == nil {
		if len(a.pending[vid]) < 1000 {
			a.pending[vid] = append(a.pending[vid], e)
		}
		return nil
	}
	return a.appendLocked(v, vid, e)
}

func (a *Audit) appendLocked(v *svcore.Vault, vid string, e Entry) error {
	logPath, _ := a.paths(vid)
	if _, ok := a.last[vid]; !ok {
		a.last[vid] = lastLineHash(logPath)
	}
	e.Prev = a.last[vid]
	plain, err := json.Marshal(e)
	if err != nil {
		return err
	}
	sealed, err := v.Suite().SealToLog(a.pubs[vid], plain, logInfo(vid))
	if err != nil {
		return err
	}
	line := base64.RawURLEncoding.EncodeToString(sealed)
	if err := os.MkdirAll(a.dir, 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	_, err = f.WriteString(line + "\n")
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(line))
	a.last[vid] = hex.EncodeToString(sum[:])
	return nil
}

func lastLineHash(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	lines := bytes.Split(bytes.TrimRight(b, "\n"), []byte("\n"))
	last := lines[len(lines)-1]
	if len(last) == 0 {
		return ""
	}
	sum := sha256.Sum256(last)
	return hex.EncodeToString(sum[:])
}

// Read returns the newest limit entries (all when limit <= 0), oldest
// first. The vault must be unlocked. If the chain is broken the entries
// that could be read are returned with ErrLogDamaged.
func (a *Audit) Read(v *svcore.Vault, limit int) ([]Entry, error) {
	id, err := logKey(v)
	if err != nil {
		return nil, err
	}
	vid := v.ID().String()
	logPath, _ := a.paths(vid)
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.Open(logPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Entry
	damaged := false
	prev := ""
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		line := s.Text()
		sealed, err := base64.RawURLEncoding.DecodeString(line)
		var e Entry
		if err == nil {
			var plain []byte
			if plain, err = id.Open(sealed, logInfo(vid)); err == nil {
				err = json.Unmarshal(plain, &e)
			}
		}
		if err != nil || e.Prev != prev {
			damaged = true
		}
		if err == nil {
			out = append(out, e)
		}
		sum := sha256.Sum256([]byte(line))
		prev = hex.EncodeToString(sum[:])
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	if damaged {
		return out, ErrLogDamaged
	}
	return out, s.Err()
}
