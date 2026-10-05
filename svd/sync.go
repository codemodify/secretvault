package svd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svstore"
	"github.com/codemodify/secretvault/svsync"
)

// A vault whose config names a sync server (VaultConfig.Sync) is kept in
// step with it by a watcher (svsync.Watch) for as long as the daemon runs,
// locked or not: what travels is ciphertext. The watcher syncs as soon as
// the server reports a change, as soon as this daemon writes to the vault
// (hookedStore), and once a minute. What it fetches is read into the open
// vault at once (Refresh), and a rotation made on another device locks
// the vault here, since the key it holds is no longer the current one.

// vaultSync keeps one vault in step with its server.
type vaultSync struct {
	client  *svsync.Client
	ctx     context.Context // until the watcher stops
	trigger chan struct{}
	stop    context.CancelFunc
	done    chan struct{}
	em      *emergencyWatch // what the vault's emergency grants were when last looked at (emergency.go)

	mu      sync.Mutex
	status  svrpc.SyncStatus
	started int           // syncs started
	ended   int           // syncs ended
	wake    chan struct{} // closed, and replaced, when a sync ends
}

// kick asks for a sync without waiting for it.
func (s *vaultSync) kick() {
	select {
	case s.trigger <- struct{}{}:
	default:
	}
}

// now asks for a sync and waits for one that started after the request
// to end, returning the status it left.
func (s *vaultSync) now(ctx context.Context) (svrpc.SyncStatus, error) {
	s.mu.Lock()
	target := s.started + 1
	s.mu.Unlock()
	s.kick()
	for {
		s.mu.Lock()
		if s.ended >= target {
			st := s.status
			s.mu.Unlock()
			if st.Error != "" {
				return st, errors.New(st.Error)
			}
			return st, nil
		}
		wake := s.wake
		s.mu.Unlock()
		select {
		case <-wake:
		case <-s.done:
			return svrpc.SyncStatus{}, errors.New("sync stopped")
		case <-ctx.Done():
			return svrpc.SyncStatus{}, ctx.Err()
		}
	}
}

func (s *vaultSync) snapshot() svrpc.SyncStatus {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.status
}

func (s *vaultSync) close() {
	s.stop()
	<-s.done
}

// hookedStore calls wrote after every change to the vault's files, so
// that a synced vault sends its changes at once.
type hookedStore struct {
	svstore.Backend
	wrote func()
}

func (h hookedStore) Create(name string, data []byte) error {
	err := h.Backend.Create(name, data)
	if err == nil {
		h.wrote()
	}
	return err
}

func (h hookedStore) Write(name string, data []byte) error {
	err := h.Backend.Write(name, data)
	if err == nil {
		h.wrote()
	}
	return err
}

func (h hookedStore) Remove(name string) error {
	err := h.Backend.Remove(name)
	if err == nil {
		h.wrote()
	}
	return err
}

// hook wraps a vault's folder so that writes through it reach the
// vault's sync, if it has one. The watcher itself uses the folder
// unwrapped: what it fetches needs no sending back.
func (d *Daemon) hook(mv *managedVault, store svstore.Backend) svstore.Backend {
	mv.store = store
	return hookedStore{Backend: store, wrote: func() {
		if s := mv.syncer(); s != nil {
			s.kick()
		}
	}}
}

func (mv *managedVault) syncer() *vaultSync {
	mv.mu.Lock()
	defer mv.mu.Unlock()
	return mv.sync
}

// StartSync starts syncing every vault configured for it, and lets vaults
// be set up for sync later, until ctx ends.
func (d *Daemon) StartSync(ctx context.Context) {
	d.mu.Lock()
	d.syncCtx = ctx
	var synced []*managedVault
	for _, mv := range d.vaults {
		if mv.cfg.Sync != nil && mv.v != nil {
			synced = append(synced, mv)
		}
	}
	d.mu.Unlock()
	for _, mv := range synced {
		if err := d.startSync(mv); err != nil {
			d.opts.Log(fmt.Sprintf("sync for %s: %v", mv.cfg.Name, err))
		}
	}
}

// syncIdentity is this device's key for sync servers, made on first use.
func (d *Daemon) syncIdentity() (*svsync.Identity, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.syncID == nil {
		id, err := svsync.LoadIdentity(d.home)
		if err != nil {
			return nil, err
		}
		d.syncID = id
	}
	return d.syncID, nil
}

// syncStatePath is where what this device knows about a server's copy of
// a vault is kept: outside the vault's folder, which is what gets synced,
// and named for the server and vault, so another server starts afresh.
func (d *Daemon) syncStatePath(r svsync.Remote) string {
	sum := sha256.Sum256([]byte(r.URL + "\n" + r.Vault))
	return filepath.Join(d.home, "sync", hex.EncodeToString(sum[:12])+".json")
}

// syncClient is a client for a vault on a server, signing as this device
// with the daemon's clock.
func (d *Daemon) syncClient(r svsync.Remote) (*svsync.Client, error) {
	id, err := d.syncIdentity()
	if err != nil {
		return nil, err
	}
	c, err := svsync.NewClient(r, id)
	if err != nil {
		return nil, err
	}
	c.Now = d.opts.Now
	return c, nil
}

func (d *Daemon) loadSyncState(r svsync.Remote) (*svsync.State, error) {
	path := d.syncStatePath(r)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	return svsync.LoadState(path)
}

// startSync starts the watcher for a vault configured for sync.
func (d *Daemon) startSync(mv *managedVault) error {
	d.mu.Lock()
	ctx := d.syncCtx
	d.mu.Unlock()
	if ctx == nil {
		return errors.New("this daemon does not sync")
	}
	r := *mv.cfg.Sync
	c, err := d.syncClient(r)
	if err != nil {
		return err
	}
	st, err := d.loadSyncState(r)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	s := &vaultSync{
		client:  c,
		ctx:     ctx,
		trigger: make(chan struct{}, 1),
		stop:    cancel,
		done:    make(chan struct{}),
		wake:    make(chan struct{}),
		status:  svrpc.SyncStatus{Vault: mv.cfg.Name, URL: r.URL, ServerVault: r.Vault, Device: c.Identity().Key()},
		em:      d.newEmergencyWatch(ctx, r),
	}
	mv.mu.Lock()
	old := mv.sync
	mv.sync = s
	mv.mu.Unlock()
	if old != nil {
		old.close()
	}
	go func() {
		defer close(s.done)
		svsync.Watch(ctx, mv.store, c, st, svsync.WatchOptions{
			// Someone else's vault, opened with emergency access, only
			// ever follows the server.
			ReadOnly: mv.cfg.Emergency != "",
			Trigger:  s.trigger,
			Changed:  func(svsync.Report) { d.pulled(mv) },
			Failed: func(err error) {
				d.opts.Log(fmt.Sprintf("sync for %s: %v", mv.cfg.Name, err))
			},
			Starting: func() {
				s.mu.Lock()
				s.started++
				s.mu.Unlock()
			},
			Synced: func(rep svsync.Report, err error) {
				d.emergencySynced(mv, s, rep, err)
				s.mu.Lock()
				defer s.mu.Unlock()
				now := d.opts.Now()
				s.status.Last = now
				s.status.Error = ""
				if err != nil {
					s.status.Error = syncWords(err)
				} else {
					s.status.LastOK = now
				}
				s.status.Pulled += rep.Pulled
				s.status.Pushed += rep.Pushed + rep.Deleted
				s.status.Removed += rep.Removed
				s.status.Kept += rep.Kept
				s.ended++
				close(s.wake)
				s.wake = make(chan struct{})
			},
		})
	}()
	return nil
}

// stopSync stops a vault's watcher, if it has one.
func (d *Daemon) stopSync(mv *managedVault) {
	mv.mu.Lock()
	s := mv.sync
	mv.sync = nil
	mv.mu.Unlock()
	if s != nil {
		s.close()
	}
}

// stopAllSync stops every watcher, as the daemon stops.
func (d *Daemon) stopAllSync() {
	d.mu.Lock()
	d.syncCtx = nil
	var all []*managedVault
	for _, mv := range d.vaults {
		all = append(all, mv)
	}
	d.mu.Unlock()
	for _, mv := range all {
		d.stopSync(mv)
	}
}

// pulled reads what a sync fetched into the open vault.
func (d *Daemon) pulled(mv *managedVault) {
	switch err := mv.v.Refresh(); {
	case err == nil, errors.Is(err, svcore.ErrLocked):
	case errors.Is(err, svcore.ErrRotated):
		// The vault dropped its keys itself: they are no longer current.
		d.locked(mv, "its key was rotated on another device")
	default:
		d.opts.Log(fmt.Sprintf("reading what sync fetched into %s: %v", mv.cfg.Name, err))
	}
	d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name})
}

// syncBefore brings a synced vault up to date before an operation that
// must not be made on a stale copy (a rotation, which two devices must
// not make apart). Vaults that do not sync pass at once.
func (d *Daemon) syncBefore(ctx context.Context, mv *managedVault, what string) error {
	s := mv.syncer()
	if s == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if _, err := s.now(ctx); err != nil {
		return svrpc.Errorf(svrpc.CodeFailed, "could not sync %s before %s (%v); doing it on a copy that may be behind could split the vault in two", mv.cfg.Name, what, err)
	}
	return nil
}

// syncWords is a sync error as the person should read it.
func syncWords(err error) string {
	var se *svsync.ServerError
	switch {
	case errors.As(err, &se):
		return "the server said: " + strings.TrimPrefix(se.Error(), "svsync: ")
	case errors.Is(err, svsync.ErrPin):
		return "the server's certificate is not the one pinned for it (a different server, or someone in between)"
	}
	return strings.TrimPrefix(err.Error(), "svsync: ")
}

func syncErr(err error) error {
	if err == nil {
		return nil
	}
	var e *svrpc.Error
	if errors.As(err, &e) {
		return err
	}
	return svrpc.Errorf(svrpc.CodeFailed, "%s", syncWords(err))
}

// errOwnPrograms refuses a request that changes where the daemon keeps
// or sends vaults: only secretvault's own programs may make it.
var errOwnPrograms = svrpc.Errorf(svrpc.CodeDenied, "only secretvault's own programs may change which vaults are kept and synced")

// synced resolves a vault that syncs, for a request from secretvault's
// own programs, after consent to manage it.
func (d *Daemon) synced(ctx context.Context, cl *client, vault string) (*managedVault, *vaultSync, error) {
	if !cl.cli {
		return nil, nil, errOwnPrograms
	}
	mv, err := d.managed(ctx, cl, vault, "", "", svbroker.OpManage)
	if err != nil {
		return nil, nil, err
	}
	s := mv.syncer()
	if s == nil {
		return nil, nil, svrpc.Errorf(svrpc.CodeNotFound, "vault %q does not sync (set it up with 'secretvault sync setup URL')", mv.cfg.Name)
	}
	return mv, s, nil
}

// deviceLabel names this device to the others on a server by default.
func deviceLabel(label string) string {
	if label != "" {
		return label
	}
	h, _ := os.Hostname()
	return h
}

func init() {
	registerMethod(svrpc.MSyncSetup, (*Daemon).syncSetup)
	registerMethod(svrpc.MSyncJoin, (*Daemon).syncJoin)
	registerMethod(svrpc.MSyncInvite, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.VaultRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		_, s, err := d.synced(ctx, cl, p.Vault)
		if err != nil {
			return nil, err
		}
		inv, err := s.client.Enrol(ctx)
		if err != nil {
			return nil, syncErr(err)
		}
		return svrpc.SyncInvite{Invite: inv.String(), Expires: inv.Expires}, nil
	})
	registerMethod(svrpc.MSyncStatus, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.VaultRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		if !cl.cli {
			return nil, errOwnPrograms
		}
		out := []svrpc.SyncStatus{}
		if p.Vault != "" {
			mv, err := d.vault(p.Vault)
			if err != nil {
				return nil, err
			}
			if s := mv.syncer(); s != nil {
				out = append(out, s.snapshot())
			}
			return out, nil
		}
		for _, info := range d.vaultInfos() {
			d.mu.Lock()
			mv := d.vaults[info.Name]
			d.mu.Unlock()
			if mv == nil {
				continue
			}
			if s := mv.syncer(); s != nil {
				out = append(out, s.snapshot())
			}
		}
		return out, nil
	})
	registerMethod(svrpc.MSyncNow, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.VaultRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		_, s, err := d.synced(ctx, cl, p.Vault)
		if err != nil {
			return nil, err
		}
		st, err := s.now(ctx)
		if err != nil {
			return nil, syncErr(err)
		}
		return st, nil
	})
	registerMethod(svrpc.MSyncDevices, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.VaultRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		_, s, err := d.synced(ctx, cl, p.Vault)
		if err != nil {
			return nil, err
		}
		devs, err := s.client.Devices(ctx)
		if err != nil {
			return nil, syncErr(err)
		}
		me := s.client.Identity().Key()
		out := make([]svrpc.SyncDevice, len(devs))
		for i, dv := range devs {
			out[i] = svrpc.SyncDevice{Key: dv.Key, Label: dv.Label, Added: dv.Added, AddedBy: dv.AddedBy, LastSeen: dv.LastSeen, This: dv.Key == me}
		}
		return out, nil
	})
	registerMethod(svrpc.MSyncRemove, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.SyncRemoveParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, s, err := d.synced(ctx, cl, p.Vault)
		if err != nil {
			return nil, err
		}
		if p.Key == s.client.Identity().Key() {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "that is this device: to stop syncing here, use 'secretvault sync off'")
		}
		if err := s.client.RemoveDevice(ctx, p.Key); err != nil {
			return nil, syncErr(err)
		}
		d.recorder(cl, mv, "", svbroker.OpManage)("allowed", "removed device "+p.Key+" from the sync server")
		return nil, nil
	})
	registerMethod(svrpc.MSyncOff, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.VaultRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, _, err := d.synced(ctx, cl, p.Vault)
		if err != nil {
			return nil, err
		}
		r := *mv.cfg.Sync
		d.stopSync(mv)
		if err := d.setSyncConfig(mv, nil); err != nil {
			return nil, err
		}
		os.Remove(d.syncStatePath(r))
		d.recorder(cl, mv, "", svbroker.OpManage)("allowed", "stopped syncing with "+r.URL)
		return nil, nil
	})
}

// setSyncConfig records where a vault syncs to (nil: nowhere).
func (d *Daemon) setSyncConfig(mv *managedVault, r *svsync.Remote) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := range d.cfg.Vaults {
		if d.cfg.Vaults[i].Name == mv.cfg.Name {
			old := d.cfg.Vaults[i].Sync
			d.cfg.Vaults[i].Sync = r
			if err := d.cfg.save(d.home); err != nil {
				d.cfg.Vaults[i].Sync = old
				return err
			}
			mv.cfg.Sync = r
			return nil
		}
	}
	return svrpc.Errorf(svrpc.CodeNoVault, "there is no vault named %q", mv.cfg.Name)
}

// syncSetup makes a vault on a server from this device's copy, and keeps
// the two in step from then on.
func (d *Daemon) syncSetup(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.SyncSetupParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	if !cl.cli {
		return nil, errOwnPrograms
	}
	mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
	if err != nil {
		return nil, err
	}
	if mv.cfg.Sync != nil {
		return nil, svrpc.Errorf(svrpc.CodeExists, "vault %q already syncs with %s ('secretvault sync off' first)", mv.cfg.Name, mv.cfg.Sync.URL)
	}
	d.mu.Lock()
	running := d.syncCtx != nil
	d.mu.Unlock()
	if !running {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "this daemon does not sync")
	}
	r := svsync.Remote{URL: strings.TrimSuffix(p.URL, "/"), Vault: mv.v.ID().String(), Fingerprint: p.Fingerprint}
	c, err := d.syncClient(r)
	if err != nil {
		return nil, syncErr(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	if err := c.CreateVault(ctx, p.AdminToken, deviceLabel(p.Label)); err != nil {
		return nil, syncErr(err)
	}
	// The first sync, here rather than in the watcher, so that whatever
	// goes wrong is told to the person setting it up.
	st, err := d.loadSyncState(r)
	if err != nil {
		return nil, err
	}
	rep, err := svsync.Sync(ctx, mv.store, c, st)
	if err != nil {
		return nil, syncErr(err)
	}
	if err := d.setSyncConfig(mv, &r); err != nil {
		return nil, err
	}
	if err := d.startSync(mv); err != nil {
		return nil, err
	}
	d.recorder(cl, mv, "", svbroker.OpManage)("allowed", "started syncing with "+r.URL)
	s := mv.syncer()
	s.mu.Lock()
	defer s.mu.Unlock()
	now := d.opts.Now()
	s.status.Last, s.status.LastOK = now, now
	s.status.Pushed += rep.Pushed + rep.Deleted
	s.status.Pulled += rep.Pulled
	return s.status, nil
}

// syncJoin fetches a vault from a server with an invite, and registers it.
func (d *Daemon) syncJoin(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.SyncJoinParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	if !cl.cli {
		return nil, errOwnPrograms
	}
	inv, err := svsync.ParseInvite(p.Invite)
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s", syncWords(err))
	}
	if err := checkVaultName(p.Name); err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	d.mu.Lock()
	_, taken := d.vaults[p.Name]
	running := d.syncCtx != nil
	d.mu.Unlock()
	if taken {
		return nil, svrpc.Errorf(svrpc.CodeExists, "there is already a vault named %q", p.Name)
	}
	if !running {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "this daemon does not sync")
	}
	path := p.Path
	if path == "" {
		path = filepath.Join(d.home, "vaults", p.Name)
	}
	if entries, err := os.ReadDir(path); err == nil && len(entries) > 0 {
		return nil, svrpc.Errorf(svrpc.CodeExists, "%s is not empty: a vault is fetched into an empty folder", path)
	}
	_, statErr := os.Stat(path)
	made := errors.Is(statErr, os.ErrNotExist)

	c, err := d.syncClient(inv.Remote)
	if err != nil {
		return nil, syncErr(err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	if err := c.Join(ctx, inv.Code, deviceLabel(p.Label)); err != nil {
		return nil, syncErr(err)
	}
	store, err := svstore.OpenDir(path)
	if err != nil {
		return nil, err
	}
	st, err := d.loadSyncState(inv.Remote)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (any, error) {
		if made {
			os.RemoveAll(path)
		}
		os.Remove(d.syncStatePath(inv.Remote))
		return nil, syncErr(err)
	}
	if _, err := svsync.Clone(ctx, c, store, st); err != nil {
		return fail(err)
	}
	if _, err := os.Stat(filepath.Join(path, svformat.DescriptorName)); err != nil {
		return fail(errors.New("the server has no vault under that name yet"))
	}
	r := inv.Remote
	mv, err := d.openVault(VaultConfig{Name: p.Name, Path: path, AutoLock: d.defaultAutoLock(), Sync: &r})
	if err != nil {
		return fail(err)
	}
	if err := d.register(mv); err != nil {
		return fail(err)
	}
	if err := d.startSync(mv); err != nil {
		d.opts.Log(fmt.Sprintf("sync for %s: %v", mv.cfg.Name, err))
	}
	return d.info(mv), nil
}
