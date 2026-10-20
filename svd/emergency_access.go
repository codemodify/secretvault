package svd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svserver"
	"github.com/codemodify/secretvault/svstore"
	"github.com/codemodify/secretvault/svsync"
)

// Emergency access, the trustee's side (the owner's is emergency.go):
// accepting an invite, asking for access, and opening the vault once the
// wait is over.

// EmergencyAccess is emergency access this device holds to someone else's
// vault, as the config keeps it. Nothing in it is secret: the escrow is
// sealed to the trustee's identity, which is never kept.
type EmergencyAccess struct {
	Name   string        `json:"name"`            // what it is called here, and its vault once opened
	Owner  string        `json:"owner,omitempty"` // what the owner calls the vault (the invite's name)
	Remote svsync.Remote `json:"remote"`
	Grant  string        `json:"grant"`

	// VaultID and Check pin the vault the invite named (its ID, and its
	// first epoch's check value, in hex), so a server cannot hand over
	// another.
	VaultID string `json:"vault_id"`
	Check   string `json:"check"`

	// Recipient is the identity it was accepted with (its public text).
	Recipient string    `json:"recipient"`
	Accepted  time.Time `json:"accepted"`

	// Escrow is the release key, sealed to the identity, once released.
	Escrow []byte `json:"escrow,omitempty"`

	// Vault is the vault here, once opened.
	Vault string `json:"vault,omitempty"`

	// What the server last said.
	State      string     `json:"state,omitempty"`
	Wait       int64      `json:"wait,omitempty"`
	Requested  *time.Time `json:"requested,omitempty"`
	ReleasesAt *time.Time `json:"releases_at,omitempty"`
	Denied     *time.Time `json:"denied,omitempty"`
	Released   *time.Time `json:"released,omitempty"`
}

func (a *EmergencyAccess) label() string {
	if a.Owner != "" && a.Owner != a.Name {
		return fmt.Sprintf("%q (%s)", a.Owner, a.Name)
	}
	return fmt.Sprintf("%q", a.Name)
}

// learn keeps what the server said of the grant.
func (a *EmergencyAccess) learn(g svsync.Grant) {
	a.State, a.Wait, a.Requested, a.ReleasesAt, a.Denied, a.Released = g.State, g.Wait, g.Requested, g.ReleasesAt, g.Denied, g.Released
}

func (a *EmergencyAccess) info() svrpc.EmergencyAccess {
	return svrpc.EmergencyAccess{Name: a.Name, Owner: a.Owner, URL: a.Remote.URL, Grant: a.Grant, Vault: a.Vault,
		State: a.State, Wait: a.Wait, Requested: a.Requested, ReleasesAt: a.ReleasesAt, Denied: a.Denied, Released: a.Released}
}

// access finds the access this device holds by name, or by its grant.
func (d *Daemon) access(ref string) (EmergencyAccess, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, a := range d.cfg.Emergency {
		if a.Name == ref || a.Grant == ref {
			return a, nil
		}
	}
	return EmergencyAccess{}, svrpc.Errorf(svrpc.CodeNotFound, "no emergency access called %q here ('secretvault emergency ls' lists it)", ref)
}

// addAccess records new access in the config.
func (d *Daemon) addAccess(a EmergencyAccess) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if slices.ContainsFunc(d.cfg.Emergency, func(x EmergencyAccess) bool { return x.Name == a.Name }) {
		return svrpc.Errorf(svrpc.CodeExists, "there is already emergency access called %q here", a.Name)
	}
	d.cfg.Emergency = append(d.cfg.Emergency, a)
	if err := d.cfg.save(d.config); err != nil {
		d.cfg.Emergency = d.cfg.Emergency[:len(d.cfg.Emergency)-1]
		return err
	}
	return nil
}

// updateAccess changes the access called name in the config, under the
// daemon's lock, so that two commands at once do not undo each other's
// change, and returns it as changed.
func (d *Daemon) updateAccess(name string, change func(a *EmergencyAccess)) (EmergencyAccess, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	i := slices.IndexFunc(d.cfg.Emergency, func(x EmergencyAccess) bool { return x.Name == name })
	if i < 0 {
		return EmergencyAccess{}, svrpc.Errorf(svrpc.CodeNotFound, "no emergency access called %q here", name)
	}
	old := d.cfg.Emergency[i]
	a := old
	change(&a)
	d.cfg.Emergency[i] = a
	if err := d.cfg.save(d.config); err != nil {
		d.cfg.Emergency[i] = old
		return EmergencyAccess{}, err
	}
	return a, nil
}

// errRevoked answers a trustee whose device the server no longer knows
// for a grant.
var errRevoked = svrpc.Errorf(svrpc.CodeDenied, "the server no longer knows this device for that grant: it was revoked")

// heldAccess describes the access this device holds, as each server says
// it stands.
func (d *Daemon) heldAccess(ctx context.Context) []svrpc.EmergencyAccess {
	d.mu.Lock()
	all := slices.Clone(d.cfg.Emergency)
	d.mu.Unlock()
	out := []svrpc.EmergencyAccess{}
	for _, a := range all {
		c, err := d.syncClient(a.Remote)
		if err == nil {
			cctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			var g svsync.Grant
			g, err = c.Grant(cctx, a.Grant)
			cancel()
			if err == nil {
				if now, uerr := d.updateAccess(a.Name, func(x *EmergencyAccess) { x.learn(g) }); uerr == nil {
					a = now
				} else {
					a.learn(g)
					d.opts.Log(fmt.Sprintf("emergency access %s: %v", a.Name, uerr))
				}
			}
		}
		info := a.info()
		switch {
		case errors.Is(err, svsync.ErrNotEnrolled):
			info.Error = errRevoked.Message
		case err != nil:
			info.Error = syncWords(err)
		}
		out = append(out, info)
	}
	return out
}

// serverRefused turns a server's refusal into what to tell the person:
// its own words.
func serverRefused(err error, code int) error {
	var se *svsync.ServerError
	if errors.As(err, &se) {
		return svrpc.Errorf(code, "%s", se.Message)
	}
	return syncErr(err)
}

func (d *Daemon) emergencyAccept(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.EmergencyAcceptParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	defer clear(p.Identity)
	if !cl.cli {
		return nil, errOwnPrograms
	}
	inv, err := svsync.ParseEmergencyInvite(p.Invite)
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s", syncWords(err))
	}
	id, err := parseIdentity(p.Identity)
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	name := p.Name
	if name == "" {
		name = inv.Name
		if checkVaultName(name) != nil {
			name = "emergency-" + inv.Grant[:8]
		}
	}
	if err := checkVaultName(name); err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	d.mu.Lock()
	_, taken := d.vaults[name]
	for _, a := range d.cfg.Emergency {
		if a.Grant == inv.Grant && a.Remote.URL == inv.URL {
			d.mu.Unlock()
			return nil, svrpc.Errorf(svrpc.CodeExists, "this device accepted that grant already, as %q", a.Name)
		}
		taken = taken || a.Name == name
	}
	d.mu.Unlock()
	if taken {
		return nil, svrpc.Errorf(svrpc.CodeExists, "%q is taken here (a vault, or other emergency access): accept it under another name (--as NAME)", name)
	}
	c, err := d.syncClient(inv.Remote)
	if err != nil {
		return nil, syncErr(err)
	}
	grant, _ := svformat.ParseID(inv.Grant)
	vid, _ := svformat.ParseID(inv.VaultID)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	var seed []byte
	recipient := svformat.EncodeRecipient(id.Suite(), id.Recipient())
	ch, err := c.GrantChallenge(ctx, inv.Grant)
	switch {
	case err == nil:
		// Only the identity the grant was made for opens its challenge:
		// the seed of the key that signs, for this device alone, that it
		// accepts. The seed never leaves this device.
		if seed, err = id.Open(ch, svformat.EmergencyChallengeInfo(vid, grant)); err != nil {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "that identity is not the one the grant was made for")
		}
		defer clear(seed)
	case errors.Is(err, svsync.ErrConflict):
		// Accepted already: by this device (a retry, after its answer was
		// lost), or by another. A retry proves nothing about the identity
		// given now, so none is recorded: opening checks it.
		recipient = ""
	case errors.Is(err, svsync.ErrNotFound):
		return nil, svrpc.Errorf(svrpc.CodeNotFound, "the server holds no such grant: it was revoked, or the invite is not for this server")
	default:
		return nil, syncErr(err)
	}
	g, err := c.AcceptGrant(ctx, inv.Grant, seed, deviceLabel(p.Label))
	if err != nil {
		if errors.Is(err, svsync.ErrConflict) {
			return nil, svrpc.Errorf(svrpc.CodeExists, "that grant was accepted already, by another device")
		}
		return nil, serverRefused(err, svrpc.CodeFailed)
	}
	a := EmergencyAccess{Name: name, Owner: inv.Name, Remote: inv.Remote, Grant: inv.Grant, VaultID: inv.VaultID, Check: inv.Check,
		Recipient: recipient, Accepted: d.opts.Now().UTC()}
	a.learn(g)
	if err := d.addAccess(a); err != nil {
		return nil, err
	}
	d.opts.Log(fmt.Sprintf("accepted emergency access to %s as %s", inv.URL, name))
	return a.info(), nil
}

func (d *Daemon) emergencyRequest(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.EmergencyAccessRef
	if err := decode(&p); err != nil {
		return nil, err
	}
	if !cl.cli {
		return nil, errOwnPrograms
	}
	a, err := d.access(p.Name)
	if err != nil {
		return nil, err
	}
	c, err := d.syncClient(a.Remote)
	if err != nil {
		return nil, syncErr(err)
	}
	g, err := c.RequestAccess(ctx, a.Grant)
	switch {
	case errors.Is(err, svsync.ErrNotEnrolled):
		return nil, errRevoked
	case err != nil:
		return nil, serverRefused(err, svrpc.CodeFailed)
	}
	if a, err = d.updateAccess(a.Name, func(x *EmergencyAccess) { x.learn(g) }); err != nil {
		return nil, err
	}
	d.opts.Log(fmt.Sprintf("asked for emergency access %s; released at %s unless denied", a.Name, when(g.ReleasesAt)))
	return a.info(), nil
}

func (d *Daemon) emergencyOpen(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.EmergencyOpenParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	defer clear(p.Identity)
	if !cl.cli {
		return nil, errOwnPrograms
	}
	a, err := d.access(p.Name)
	if err != nil {
		return nil, err
	}
	id, err := parseIdentity(p.Identity)
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	recipient := svformat.EncodeRecipient(id.Suite(), id.Recipient())
	if a.Recipient != "" && recipient != a.Recipient {
		return nil, svrpc.Errorf(svrpc.CodeWrongKey, "that is not the identity %q was accepted with", a.Name)
	}
	c, err := d.syncClient(a.Remote)
	if err != nil {
		return nil, syncErr(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	rel, err := c.ReleaseAccess(ctx, a.Grant)
	switch {
	case errors.Is(err, svsync.ErrNotEnrolled):
		return nil, errRevoked
	case errors.Is(err, svsync.ErrConflict):
		// Not yet, denied, or not asked for: the server says which.
		return nil, serverRefused(err, svrpc.CodeDenied)
	case err != nil:
		return nil, syncErr(err)
	}
	grant, _ := svformat.ParseID(a.Grant)
	vid, _ := svformat.ParseID(a.VaultID)
	release, err := id.Open(rel.Escrow, svformat.EmergencyReleaseInfo(vid, grant))
	if err != nil {
		if a.Recipient == "" {
			return nil, svrpc.Errorf(svrpc.CodeWrongKey, "that is not the identity the grant was made for")
		}
		return nil, svrpc.Errorf(svrpc.CodeFailed, "the server's release key is not sealed to this identity for that vault")
	}
	defer clear(release)
	released := rel.Released
	a, err = d.updateAccess(a.Name, func(x *EmergencyAccess) {
		x.Escrow, x.Recipient = rel.Escrow, recipient
		x.State, x.Released = svserver.GrantReleased, &released
	})
	if err != nil {
		return nil, err
	}

	mv, err := d.vault(a.Vault)
	if a.Vault == "" || err != nil {
		if mv, err = d.fetchEmergencyVault(ctx, c, &a, p.Path); err != nil {
			return nil, err
		}
	} else if mv.cfg.Emergency != a.Name {
		return nil, svrpc.Errorf(svrpc.CodeExists, "vault %q here is not the one %q opens", a.Vault, a.Name)
	}
	key := svcore.EmergencyKey(id, grant, release)
	if mv.v.Locked() {
		err = d.unlockWith(mv, key)
	} else {
		err = mv.v.CheckKey(key)
	}
	if err != nil {
		return nil, err
	}
	d.proved(cl, mv)
	d.audit.Record(mv.v, svbroker.Entry{Program: cl.display(), Identity: cl.identity(), PID: cl.proc.PID, Op: svbroker.OpManage,
		Outcome: "allowed", Reason: fmt.Sprintf("opened with emergency access (grant %s)", a.Grant)})
	return d.info(mv), nil
}

// fetchEmergencyVault fetches the vault a released grant opens into an
// empty folder, checks it is the one the invite named, and registers it
// read-only, pulling from the server from then on.
func (d *Daemon) fetchEmergencyVault(ctx context.Context, c *svsync.Client, a *EmergencyAccess, path string) (*managedVault, error) {
	d.mu.Lock()
	_, taken := d.vaults[a.Name]
	d.mu.Unlock()
	if taken {
		return nil, svrpc.Errorf(svrpc.CodeExists, "there is already a vault named %q here", a.Name)
	}
	if path == "" {
		path = filepath.Join(d.home, "vaults", a.Name)
	}
	if entries, err := os.ReadDir(path); err == nil && len(entries) > 0 {
		return nil, svrpc.Errorf(svrpc.CodeExists, "%s is not empty: a vault is fetched into an empty folder", path)
	}
	_, statErr := os.Stat(path)
	made := errors.Is(statErr, os.ErrNotExist)
	store, err := svstore.OpenDir(path)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (*managedVault, error) {
		if made {
			os.RemoveAll(path)
		}
		os.Remove(d.syncStatePath(a.Remote))
		return nil, err
	}
	st, err := d.loadSyncState(a.Remote)
	if err != nil {
		return fail(err)
	}
	if _, err := svsync.Clone(ctx, c, store, st); err != nil {
		return fail(syncErr(err))
	}
	// A server could hand over a vault of its own making: the invite
	// named this one by its ID and first check value, which only a key
	// of the real vault matches (every later epoch is checked down to it
	// when the vault opens).
	desc, err := descriptor(store)
	if err != nil {
		return fail(err)
	}
	if desc.ID.String() != a.VaultID || hex.EncodeToString(desc.Epochs[0].Check) != a.Check {
		return fail(svrpc.Errorf(svrpc.CodeFailed, "the server sent a vault other than the one you were granted; nothing was kept"))
	}
	r := a.Remote
	mv, err := d.openVault(VaultConfig{Name: a.Name, Path: path, AutoLock: d.defaultAutoLock(), Sync: &r, Emergency: a.Name})
	if err != nil {
		return fail(err)
	}
	if err := d.register(mv); err != nil {
		return fail(err)
	}
	if *a, err = d.updateAccess(a.Name, func(x *EmergencyAccess) { x.Vault = x.Name }); err != nil {
		return nil, err
	}
	if err := d.startSync(mv); err != nil {
		d.opts.Log(fmt.Sprintf("sync for %s: %v", mv.cfg.Name, err))
	}
	return mv, nil
}

// emergencyKey is the key the text of an identity file makes for a vault
// opened with emergency access: the identity, with the release key kept
// (sealed to it) when the grant was released.
func (d *Daemon) emergencyKey(mv *managedVault, text []byte) (svcore.Key, func(), error) {
	wipe := func() { clear(text) }
	id, err := parseIdentity(text)
	if err != nil {
		return nil, wipe, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	a, err := d.access(mv.cfg.Emergency)
	if err != nil {
		return nil, wipe, err
	}
	if len(a.Escrow) == 0 {
		return nil, wipe, svrpc.Errorf(svrpc.CodeNotFound, "this device has no release key for %q yet: 'secretvault emergency open %s --identity FILE'", a.Name, a.Name)
	}
	grant, _ := svformat.ParseID(a.Grant)
	vid, _ := svformat.ParseID(a.VaultID)
	release, err := id.Open(a.Escrow, svformat.EmergencyReleaseInfo(vid, grant))
	if err != nil {
		return nil, wipe, svrpc.ErrWrongKey
	}
	return svcore.EmergencyKey(id, grant, release), func() { clear(release); clear(text) }, nil
}

// readOnlyStore refuses every write to a vault opened with emergency
// access: it is someone else's, and its copy here only follows the
// server's.
type readOnlyStore struct{ svstore.Backend }

var errReadOnly = errors.New("this vault is someone else's, opened with emergency access: it is read-only here")

func (readOnlyStore) Create(string, []byte) error { return errReadOnly }
func (readOnlyStore) Write(string, []byte) error  { return errReadOnly }
func (readOnlyStore) Remove(string) error         { return errReadOnly }
