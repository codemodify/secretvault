package svdeliver

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
)

// The audit log records every request the delivery API answers but
// GET /v1/deliver/status: when, from which address, who (the identity
// and the role that decided), what (the operation, the vault, the item,
// the field), and the outcome, with the reason for a refusal. It never
// holds a secret value, a token, an ID token or a share.
//
// It is one file, audit.log, of one sealed entry per line (base64url).
// Entries are sealed with HPKE to a key pair derived from the root key.
// The public half is in seal.json, so the log is written while the server
// is sealed too (unseal attempts, refused requests); only an unsealed
// server reads it back. Each entry carries its sequence number and the
// SHA-256 of the line before it, so removing, reordering or altering
// lines shows. Each is synced to disk before the request is answered: a
// request whose entry could not be written gets an error, never a secret.
//
// svbroker's audit log was not reused: it is kept per vault, under a key
// derived from that vault's key, and its entries describe a local program
// (its path and process). Here most entries concern no vault at all
// (logins, unseals, admin calls), the log must be writable while no
// vault is open, and an entry needs the caller's address and role.

// Outcomes of a request.
const (
	OutcomeAllowed = "allowed" // done
	OutcomeDenied  = "denied"  // not authenticated, or not allowed
	OutcomeFailed  = "failed"  // a bad request, or an error
	OutcomeSealed  = "sealed"  // refused because the server is sealed
)

// AuditEntry is one request.
type AuditEntry struct {
	Seq      uint64    `json:"seq"`
	Time     time.Time `json:"time"`
	IP       string    `json:"ip,omitempty"`
	Identity string    `json:"identity,omitempty"`
	Role     string    `json:"role,omitempty"`
	Op       string    `json:"op"`
	Vault    string    `json:"vault,omitempty"`
	Item     string    `json:"item,omitempty"`
	Field    string    `json:"field,omitempty"`
	Target   string    `json:"target,omitempty"` // what an admin call acted on: a token, role, vault or issuer
	Outcome  string    `json:"outcome"`
	Status   int       `json:"status,omitempty"` // the HTTP status answered
	Reason   string    `json:"reason,omitempty"`
	Prev     string    `json:"prev,omitempty"` // hex SHA-256 of the line before
}

// maxAuditText caps each text of an entry.
const maxAuditText = 1024

// ErrAuditDamaged is an audit log whose chain is broken.
var ErrAuditDamaged = errors.New("svdeliver: the audit log has been altered: lines are missing, out of order or changed")

type auditLog struct {
	path  string
	suite svcrypto.Suite
	info  []byte

	mu   sync.Mutex
	pub  []byte
	f    *os.File
	last string // hash of the last line
	seq  uint64
}

// openAudit opens the log for appending, finding where its chain ends. A
// last line cut short by a crash is dropped.
func openAudit(path string, suite svcrypto.Suite, pub, info []byte) (*auditLog, error) {
	a := &auditLog{path: path, suite: suite, info: info, pub: pub}
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(f, 64<<10)
	var good int64
	for {
		line, err := r.ReadBytes('\n')
		if len(line) > 0 && line[len(line)-1] == '\n' {
			good += int64(len(line))
			sum := sha256.Sum256(bytes.TrimSuffix(line, []byte("\n")))
			a.last = hex.EncodeToString(sum[:])
			a.seq++
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			f.Close()
			return nil, err
		}
	}
	if st, err := f.Stat(); err == nil && st.Size() > good {
		if err := f.Truncate(good); err != nil {
			f.Close()
			return nil, err
		}
	}
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		f.Close()
		return nil, err
	}
	a.f = f
	return a, nil
}

// setKey replaces the public key entries are sealed to: the one derived
// from the root key, once the server is unsealed, should the one in
// seal.json have been swapped.
func (a *auditLog) setKey(pub []byte) {
	a.mu.Lock()
	a.pub = append([]byte(nil), pub...)
	a.mu.Unlock()
}

// record appends an entry and syncs it to disk.
func (a *auditLog) record(e AuditEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return errors.New("svdeliver: the audit log is closed")
	}
	e.Seq, e.Prev = a.seq+1, a.last
	// Callers choose some of these (a role's name, a field's), so they are
	// capped, and kept to valid UTF-8.
	for _, s := range []*string{&e.Identity, &e.Role, &e.Op, &e.Vault, &e.Item, &e.Field, &e.Target, &e.Reason} {
		if len(*s) > maxAuditText {
			*s = (*s)[:maxAuditText] + "..."
		}
		*s = strings.ToValidUTF8(*s, "?")
	}
	plain, err := json.Marshal(e)
	if err != nil {
		return err
	}
	sealed, err := a.suite.SealToLog(a.pub, plain, a.info)
	if err != nil {
		return err
	}
	line := b64url.EncodeToString(sealed)
	if _, err := a.f.WriteString(line + "\n"); err != nil {
		return err
	}
	if err := a.f.Sync(); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(line))
	a.seq, a.last = e.Seq, hex.EncodeToString(sum[:])
	return nil
}

func (a *auditLog) close() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.f == nil {
		return nil
	}
	err := a.f.Close()
	a.f = nil
	return err
}

// read opens every entry with the log's private key and checks the chain.
// It returns up to limit entries after seq after (the newest limit when
// after is 0), oldest first. A broken chain returns what could be read,
// with ErrAuditDamaged and where the chain breaks.
func (a *auditLog) read(key *svcrypto.Identity, after uint64, limit int) ([]AuditEntry, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	f, err := os.Open(a.path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []AuditEntry
	var broken error
	prev, n := "", uint64(0)
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		line := s.Text()
		n++
		var e AuditEntry
		sealed, err := b64url.DecodeString(line)
		if err == nil {
			var plain []byte
			if plain, err = key.Open(sealed, a.info); err == nil {
				err = json.Unmarshal(plain, &e)
			}
		}
		switch {
		case broken != nil:
		case err != nil:
			broken = fmt.Errorf("%w (line %d does not open)", ErrAuditDamaged, n)
		case e.Prev != prev || e.Seq != n:
			broken = fmt.Errorf("%w (the chain breaks at line %d)", ErrAuditDamaged, n)
		}
		if err == nil && (after == 0 || e.Seq > after) {
			out = append(out, e)
			if after > 0 && limit > 0 && len(out) == limit {
				// Read on only to check the chain.
				after = ^uint64(0)
			}
		}
		sum := sha256.Sum256([]byte(line))
		prev = hex.EncodeToString(sum[:])
	}
	if err := s.Err(); err != nil {
		return out, err
	}
	if after == 0 && limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, broken
}
