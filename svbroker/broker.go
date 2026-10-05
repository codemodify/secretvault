// Package svbroker decides whether a program may do something to a vault:
// it keeps the decisions people made (grants), answers "is this allowed,
// denied, or must we ask?", and writes every decision to the vault's
// audit log. It does not ask anybody itself: secretvaultd asks, then
// records the answer here.
//
// Three kinds of decision exist:
//
//   - stored grants ("always allow", "always deny"), kept in the vault as
//     encrypted records of kind "grant", per device, until revoked;
//   - session grants ("allow until locked"), kept in memory until the
//     vault locks;
//   - connection grants: a client that proved it holds a key of the vault
//     (by unlocking it) may use that vault for as long as it stays
//     connected, until the vault locks.
//
// A deny anywhere wins over an allow anywhere.
package svbroker

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svformat"
)

// Op is what a program wants to do.
type Op string

const (
	OpRead    Op = "read"    // read an item's contents
	OpList    Op = "list"    // see item names and metadata
	OpWrite   Op = "write"   // create or change items
	OpDelete  Op = "delete"  // delete items
	OpManage  Op = "manage"  // keyslots, grants, the audit log
	OpSign    Op = "sign"    // sign with a key held in the vault, without seeing it
	OpDecrypt Op = "decrypt" // decrypt with a key held in the vault, without seeing it
	OpMount   Op = "mount"   // open a container with its key, without seeing the key
)

// OpCreateVault is a program asking for a new vault (vault.request). It
// is no vault's to grant: it appears in audit logs, and in the daemon's
// own decisions about programs asking for vaults, never in a grant, and
// AllOps leaves it out.
const OpCreateVault Op = "create-vault"

// AllOps is every operation, for grants that cover a whole vault.
var AllOps = []Op{OpRead, OpList, OpWrite, OpDelete, OpManage, OpSign, OpDecrypt, OpMount}

// Decision is what was decided.
type Decision string

const (
	AllowOnce      Decision = "allow-once"
	AllowUntilLock Decision = "allow-until-lock"
	AllowAlways    Decision = "allow-always"
	DenyOnce       Decision = "deny-once"
	DenyAlways     Decision = "deny-always"
)

// Allows reports whether the decision permits the request.
func (d Decision) Allows() bool {
	return d == AllowOnce || d == AllowUntilLock || d == AllowAlways
}

// RecordKind is the vault record kind stored grants are kept under.
const RecordKind = "grant"

// Grant is one remembered decision.
type Grant struct {
	Device   svformat.ID `json:"device"`
	Identity string      `json:"identity"`
	Program  string      `json:"program"`
	Item     string      `json:"item,omitempty"`      // object ID; "" for the whole vault
	ItemName string      `json:"item_name,omitempty"` // as it was named when granted
	Ops      []Op        `json:"ops"`
	Decision Decision    `json:"decision"`
	Created  time.Time   `json:"created"`
}

// View is a grant as listed: stored or session.
type View struct {
	ID    string // record ID for stored grants; "s:<n>" for session grants
	Grant Grant
	Scope string // "stored" or "session"
}

func (g *Grant) covers(identity, item string, op Op) bool {
	return g.Identity == identity && (g.Item == "" || g.Item == item) && slices.Contains(g.Ops, op)
}

// Broker holds the in-memory decisions and knows how to reach the stored
// ones. One Broker serves every vault of a daemon.
type Broker struct {
	device svformat.ID
	now    func() time.Time

	mu      sync.Mutex
	session map[string][]*sessionGrant // vault ID -> grants until lock
	conns   map[any]map[string]bool    // connection -> vault IDs it proved a key for
	nextID  int
}

type sessionGrant struct {
	id string
	g  Grant
}

// New returns a Broker for this device.
func New(device svformat.ID) *Broker {
	return &Broker{
		device:  device,
		now:     time.Now,
		session: map[string][]*sessionGrant{},
		conns:   map[any]map[string]bool{},
	}
}

// Check says what the remembered decisions say about identity doing op to
// item (an object ID, "" for vault-wide operations) of vault v, reached
// over conn. found is false when nothing covers it and a person must be
// asked.
func (b *Broker) Check(v *svcore.Vault, conn any, identity, item string, op Op) (d Decision, found bool, err error) {
	vid := v.ID().String()
	b.mu.Lock()
	if b.conns[conn][vid] {
		b.mu.Unlock()
		return AllowUntilLock, true, nil
	}
	var allow, deny bool
	for _, s := range b.session[vid] {
		if s.g.covers(identity, item, op) {
			if s.g.Decision.Allows() {
				allow = true
			} else {
				deny = true
			}
		}
	}
	b.mu.Unlock()

	stored, err := b.stored(v)
	if err != nil {
		return "", false, err
	}
	for _, s := range stored {
		if s.Grant.covers(identity, item, op) {
			if s.Grant.Decision.Allows() {
				allow = true
			} else {
				deny = true
			}
		}
	}
	switch {
	case deny:
		return DenyAlways, true, nil
	case allow:
		return AllowAlways, true, nil
	}
	return "", false, nil
}

// stored reads this device's stored grants from the vault.
func (b *Broker) stored(v *svcore.Vault) ([]View, error) {
	recs, err := v.Records(RecordKind)
	if err != nil {
		return nil, err
	}
	var out []View
	for _, r := range recs {
		var g Grant
		if json.Unmarshal(r.Data, &g) != nil || g.Device != b.device {
			continue
		}
		out = append(out, View{ID: r.ID.String(), Grant: g, Scope: "stored"})
	}
	return out, nil
}

// Remember records a decision a person made. Once-only decisions are not
// remembered at all.
func (b *Broker) Remember(v *svcore.Vault, g Grant) error {
	g.Device = b.device
	if g.Created.IsZero() {
		g.Created = b.now().UTC()
	}
	switch g.Decision {
	case AllowOnce, DenyOnce:
		return nil
	case AllowUntilLock:
		b.mu.Lock()
		defer b.mu.Unlock()
		b.nextID++
		vid := v.ID().String()
		b.session[vid] = append(b.session[vid], &sessionGrant{id: fmt.Sprintf("s:%d", b.nextID), g: g})
		return nil
	case AllowAlways, DenyAlways:
		_, err := v.PutRecord(RecordKind, svformat.ID{}, g)
		return err
	}
	return fmt.Errorf("svbroker: unknown decision %q", g.Decision)
}

// AllowConn records that conn proved a key of vault v.
func (b *Broker) AllowConn(conn any, v *svcore.Vault) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conns[conn] == nil {
		b.conns[conn] = map[string]bool{}
	}
	b.conns[conn][v.ID().String()] = true
}

// DropConn forgets a connection that went away.
func (b *Broker) DropConn(conn any) {
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.conns, conn)
}

// Locked forgets every in-memory decision about a vault that just locked.
func (b *Broker) Locked(vaultID svformat.ID) {
	vid := vaultID.String()
	b.mu.Lock()
	defer b.mu.Unlock()
	delete(b.session, vid)
	for _, vaults := range b.conns {
		delete(vaults, vid)
	}
}

// ConnAllowed reports whether conn proved a key of vault v.
func (b *Broker) ConnAllowed(conn any, v *svcore.Vault) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conns[conn][v.ID().String()]
}

// List returns every stored and session grant of a vault.
func (b *Broker) List(v *svcore.Vault) ([]View, error) {
	out, err := b.stored(v)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	for _, s := range b.session[v.ID().String()] {
		out = append(out, View{ID: s.id, Grant: s.g, Scope: "session"})
	}
	b.mu.Unlock()
	sort.SliceStable(out, func(i, j int) bool { return out[i].Grant.Created.Before(out[j].Grant.Created) })
	return out, nil
}

// ErrNoGrant is a revoke of a grant that does not exist.
var ErrNoGrant = errors.New("svbroker: no such grant")

// Revoke removes a grant by the ID List gave it.
func (b *Broker) Revoke(v *svcore.Vault, id string) error {
	b.mu.Lock()
	vid := v.ID().String()
	for i, s := range b.session[vid] {
		if s.id == id {
			b.session[vid] = slices.Delete(b.session[vid], i, i+1)
			b.mu.Unlock()
			return nil
		}
	}
	b.mu.Unlock()
	rid, err := svformat.ParseID(id)
	if err != nil {
		return ErrNoGrant
	}
	stored, err := b.stored(v)
	if err != nil {
		return err
	}
	for _, s := range stored {
		if s.ID == id {
			return v.DeleteRecord(rid)
		}
	}
	return ErrNoGrant
}
