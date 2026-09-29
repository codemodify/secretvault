package svd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svstore"
)

// managedVault is a registered vault and its lock state.
type managedVault struct {
	cfg   VaultConfig
	v     *svcore.Vault   // nil when the folder is missing
	store svstore.Backend // the vault's folder, as the sync sees it (hook)

	// prompt serialises prompts about this vault, so ten requests arriving
	// together cause one prompt, not ten.
	prompt sync.Mutex

	mu        sync.Mutex
	idle      *time.Timer
	sync      *vaultSync // when the vault syncs with a server
	refreshed time.Time  // when fresh last read the folder
}

func (d *Daemon) openVault(vc VaultConfig) (*managedVault, error) {
	mv := &managedVault{cfg: vc}
	store, err := svstore.OpenDir(vc.Path)
	if err != nil {
		return mv, err
	}
	if _, err := os.Stat(filepath.Join(vc.Path, svformat.DescriptorName)); err != nil {
		return mv, fmt.Errorf("no vault there")
	}
	v, err := svcore.Open(d.hook(mv, store), d.svOpts)
	if err != nil {
		return mv, err
	}
	mv.v = v
	return mv, nil
}

// vault finds a registered vault by name ("" for the default).
func (d *Daemon) vault(name string) (*managedVault, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if name == "" {
		name = d.cfg.Default
		if name == "" {
			return nil, svrpc.Errorf(svrpc.CodeNotFound, "there is no vault yet (create one with 'secretvault init')")
		}
	}
	mv, ok := d.vaults[name]
	if !ok {
		return nil, svrpc.Errorf(svrpc.CodeNotFound, "there is no vault named %q", name)
	}
	if mv.v == nil {
		return nil, svrpc.Errorf(svrpc.CodeNotFound, "vault %q is registered but its folder %s is missing", name, mv.cfg.Path)
	}
	return mv, nil
}

func (d *Daemon) vaultInfos() []svrpc.VaultInfo {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []svrpc.VaultInfo
	for name, mv := range d.vaults {
		info := svrpc.VaultInfo{Name: name, Path: mv.cfg.Path, Default: name == d.cfg.Default, Locked: true, AutoLock: mv.cfg.AutoLock, LoginUnlock: mv.cfg.LoginUnlock}
		if mv.v != nil {
			info.ID = mv.v.ID().String()
			info.Suite = mv.v.Suite().String()
			info.Locked = mv.v.Locked()
			info.Created = mv.v.Created()
		}
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (d *Daemon) info(mv *managedVault) svrpc.VaultInfo {
	for _, i := range d.vaultInfos() {
		if i.Name == mv.cfg.Name {
			return i
		}
	}
	return svrpc.VaultInfo{Name: mv.cfg.Name}
}

// unlockWith unlocks a vault with a key and starts its idle timer.
func (d *Daemon) unlockWith(mv *managedVault, k svcore.Key) error {
	if err := mv.v.Unlock(k); err != nil {
		return err
	}
	if err := d.audit.Unlocked(mv.v); err != nil {
		d.opts.Log(fmt.Sprintf("audit log for %s: %v", mv.cfg.Name, err))
	}
	d.touch(mv)
	d.notify(svrpc.EVaultUnlocked, svrpc.VaultEvent{Vault: mv.cfg.Name})
	return nil
}

// fresh reads what other devices wrote into a vault kept in a synced
// folder (Syncthing, Dropbox, ...), at most once a second, before a
// request uses it. A vault synced with a server needs none of this: its
// watcher reads each change in as it arrives (pulled).
func (d *Daemon) fresh(mv *managedVault) {
	if mv.syncer() != nil || mv.v.Locked() {
		return
	}
	now := d.opts.Now()
	mv.mu.Lock()
	if now.Sub(mv.refreshed) < time.Second && now.After(mv.refreshed) {
		mv.mu.Unlock()
		return
	}
	mv.refreshed = now
	mv.mu.Unlock()
	switch err := mv.v.Refresh(); {
	case err == nil, errors.Is(err, svcore.ErrLocked):
	case errors.Is(err, svcore.ErrRotated):
		d.locked(mv, "its key was rotated on another device")
	default:
		d.opts.Log(fmt.Sprintf("reading %s's folder: %v", mv.cfg.Name, err))
	}
}

// touch restarts the idle timer after a use of the vault.
func (d *Daemon) touch(mv *managedVault) {
	mins := mv.cfg.AutoLock.IdleMinutes
	mv.mu.Lock()
	defer mv.mu.Unlock()
	if mv.idle != nil {
		mv.idle.Stop()
		mv.idle = nil
	}
	if mins > 0 {
		mv.idle = time.AfterFunc(time.Duration(mins)*d.opts.IdleUnit, func() { d.lock(mv, "idle") })
	}
}

// lock locks a vault and forgets every in-memory decision about it.
func (d *Daemon) lock(mv *managedVault, why string) {
	if mv.v == nil || mv.v.Locked() {
		return
	}
	mv.v.Lock()
	d.locked(mv, why)
}

// locked does what follows a vault locking, whether the daemon locked it
// or it locked itself (after a rotation elsewhere).
func (d *Daemon) locked(mv *managedVault, why string) {
	mv.mu.Lock()
	if mv.idle != nil {
		mv.idle.Stop()
		mv.idle = nil
	}
	mv.mu.Unlock()
	d.broker.Locked(mv.v.ID())
	d.opts.Log(fmt.Sprintf("locked %s (%s)", mv.cfg.Name, why))
	d.notify(svrpc.EVaultLocked, svrpc.VaultEvent{Vault: mv.cfg.Name})
}

// createVault makes a new vault and registers it.
func (d *Daemon) createVault(p svrpc.VaultCreateParams) (*managedVault, string, error) {
	if p.Name == "" {
		p.Name = "default"
	}
	if err := checkVaultName(p.Name); err != nil {
		return nil, "", svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	suite := svcrypto.Modern
	if p.Suite != "" {
		s, err := svcrypto.ParseSuite(p.Suite)
		if err != nil {
			return nil, "", svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
		}
		suite = s
	}
	if len(p.Passphrase) < MinPassphrase {
		return nil, "", svrpc.Errorf(svrpc.CodeInvalidParams, "the passphrase is too short: use at least %d characters", MinPassphrase)
	}
	path := p.Path
	if path == "" {
		path = filepath.Join(d.home, "vaults", p.Name)
	}
	d.mu.Lock()
	if _, taken := d.vaults[p.Name]; taken {
		d.mu.Unlock()
		return nil, "", svrpc.Errorf(svrpc.CodeExists, "there is already a vault named %q", p.Name)
	}
	d.mu.Unlock()
	if _, err := os.Stat(filepath.Join(path, svformat.DescriptorName)); err == nil {
		return nil, "", svrpc.Errorf(svrpc.CodeExists, "a vault already exists at %s (register it with 'secretvault vault add')", path)
	}
	store, err := svstore.OpenDir(path)
	if err != nil {
		return nil, "", err
	}
	mv := &managedVault{cfg: VaultConfig{Name: p.Name, Path: path, AutoLock: DefaultAutoLock}}
	v, _, err := svcore.Create(d.hook(mv, store), suite, svcore.NewSlot{Type: svformat.SlotPassphrase, Label: "passphrase", Passphrase: p.Passphrase}, d.svOpts)
	if err != nil {
		return nil, "", err
	}
	mv.v = v
	recovery := ""
	if p.Recovery {
		info, err := v.AddSlot(svcore.NewSlot{Type: svformat.SlotRecovery, Label: "recovery key"})
		if err != nil {
			v.Lock()
			return nil, "", err
		}
		recovery = info.RecoveryKey
	}
	if err := d.register(mv); err != nil {
		v.Lock()
		return nil, "", err
	}
	if err := d.audit.Unlocked(v); err != nil {
		d.opts.Log(fmt.Sprintf("audit log for %s: %v", p.Name, err))
	}
	d.touch(mv)
	return mv, recovery, nil
}

// MinPassphrase is the shortest passphrase accepted for a new vault.
const MinPassphrase = 8

func (d *Daemon) register(mv *managedVault) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, taken := d.vaults[mv.cfg.Name]; taken {
		return svrpc.Errorf(svrpc.CodeExists, "there is already a vault named %q", mv.cfg.Name)
	}
	d.cfg.Vaults = append(d.cfg.Vaults, mv.cfg)
	if d.cfg.Default == "" {
		d.cfg.Default = mv.cfg.Name
	}
	if err := d.cfg.save(d.home); err != nil {
		d.cfg.Vaults = d.cfg.Vaults[:len(d.cfg.Vaults)-1]
		return err
	}
	d.vaults[mv.cfg.Name] = mv
	return nil
}

// addVault registers an existing vault folder.
func (d *Daemon) addVault(p svrpc.VaultAddParams) (*managedVault, error) {
	if err := checkVaultName(p.Name); err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	path, err := filepath.Abs(p.Path)
	if err != nil {
		return nil, err
	}
	mv, err := d.openVault(VaultConfig{Name: p.Name, Path: path, AutoLock: DefaultAutoLock})
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeNotFound, "%s: %v", path, err)
	}
	if err := d.register(mv); err != nil {
		return nil, err
	}
	return mv, nil
}

// forgetVault unregisters a vault (its folder is left alone).
func (d *Daemon) forgetVault(name string) error {
	mv, err := d.vault(name)
	if err != nil {
		return err
	}
	d.lock(mv, "forgotten")
	d.stopSync(mv)
	d.mu.Lock()
	defer d.mu.Unlock()
	delete(d.vaults, mv.cfg.Name)
	for i, vc := range d.cfg.Vaults {
		if vc.Name == mv.cfg.Name {
			d.cfg.Vaults = append(d.cfg.Vaults[:i], d.cfg.Vaults[i+1:]...)
			break
		}
	}
	if d.cfg.Default == mv.cfg.Name {
		d.cfg.Default = ""
		if len(d.cfg.Vaults) > 0 {
			d.cfg.Default = d.cfg.Vaults[0].Name
		}
	}
	return d.cfg.save(d.home)
}

func (d *Daemon) setDefault(name string) error {
	mv, err := d.vault(name)
	if err != nil {
		return err
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cfg.Default = mv.cfg.Name
	return d.cfg.save(d.home)
}
