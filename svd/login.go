package svd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// Opening vaults at login.
//
// A vault can be opened when the person logs in, as a login keyring is,
// instead of at the first request. It gets a keyfile slot labelled
// "login", whose key the OS seals to this user on this machine (svseal:
// systemd-creds, DPAPI, the keychain) in a file of the data directory.
// When the daemon starts with the session, it has the OS open the key and
// unlocks the vault; the vault then locks when the session ends, not on
// idle or screen lock, unless the person sets it to.
//
// Programs still ask before they read anything: what login unlock spares
// is the passphrase, not the consent.

// loginFile is a vault's sealed login key.
type loginFile struct {
	Slot   svformat.ID `json:"slot"`
	Sealer string      `json:"sealer"`
	Sealed []byte      `json:"sealed"`
}

func (d *Daemon) loginPath(mv *managedVault) string {
	return filepath.Join(d.home, "login", mv.v.ID().String()+".json")
}

// sealName binds a sealed key to its vault.
func sealName(mv *managedVault) string { return "secretvault-login-" + mv.v.ID().String() }

// UnlockAtLogin opens every vault set to open at login. The daemon calls
// it once, as it starts with the session.
func (d *Daemon) UnlockAtLogin() {
	d.mu.Lock()
	var mvs []*managedVault
	for _, mv := range d.vaults {
		if mv.cfg.LoginUnlock && mv.v != nil {
			mvs = append(mvs, mv)
		}
	}
	d.mu.Unlock()
	for _, mv := range mvs {
		if err := d.unlockAtLogin(mv); err != nil {
			d.opts.Log(fmt.Sprintf("opening %s at login: %v", mv.cfg.Name, err))
		}
	}
}

// loginKey reads a vault's sealed login key and has the OS open it.
func (d *Daemon) loginKey(mv *managedVault) (loginFile, []byte, error) {
	var lf loginFile
	b, err := os.ReadFile(d.loginPath(mv))
	if err != nil {
		return lf, nil, err
	}
	if err := json.Unmarshal(b, &lf); err != nil {
		return lf, nil, fmt.Errorf("%s: %v", d.loginPath(mv), err)
	}
	key, err := d.opts.Sealer.Unseal(sealName(mv), lf.Sealed)
	return lf, key, err
}

// loginRotated records that the login key's slot is now slot, after a
// rotation made it again for the new vault key.
func (d *Daemon) loginRotated(mv *managedVault, lf loginFile, slot svformat.ID) error {
	lf.Slot = slot
	b, _ := json.MarshalIndent(lf, "", "  ")
	return writeFileAtomic(d.loginPath(mv), append(b, '\n'))
}

func (d *Daemon) unlockAtLogin(mv *managedVault) error {
	if !mv.v.Locked() {
		return nil
	}
	_, key, err := d.loginKey(mv)
	if err != nil {
		return err
	}
	defer clear(key)
	if err := d.unlockWith(mv, svcore.Keyfile(key)); err != nil {
		return err
	}
	d.opts.Log(fmt.Sprintf("opened %s at login", mv.cfg.Name))
	return nil
}

func init() {
	registerMethod(svrpc.MVaultLogin, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.VaultLoginParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		// Only secretvault's own programs, and only with the vault open
		// to them: this makes a way in that needs no passphrase.
		if !cl.cli {
			return nil, errOwnPrograms
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		record := d.recorder(cl, mv, "", svbroker.OpManage)
		if p.On {
			if err := d.loginOn(mv); err != nil {
				return nil, err
			}
			record("allowed", "set to open at login, with "+d.opts.Sealer.Name())
		} else {
			if err := d.loginOff(mv); err != nil {
				return nil, err
			}
			record("allowed", "no longer opens at login")
		}
		return d.info(mv), nil
	})
}

func (d *Daemon) loginOn(mv *managedVault) error {
	if mv.cfg.LoginUnlock {
		return svrpc.Errorf(svrpc.CodeExists, "vault %q already opens at login", mv.cfg.Name)
	}
	if err := d.opts.Sealer.Available(); err != nil {
		return svrpc.Errorf(svrpc.CodeFailed, "this system cannot keep a key for you at login: %v", err)
	}
	key := svcrypto.RandomBytes(64)
	defer clear(key)
	sealed, err := d.opts.Sealer.Seal(sealName(mv), key)
	if err != nil {
		return err
	}
	// The check the OS can open it again, before anything depends on it.
	back, err := d.opts.Sealer.Unseal(sealName(mv), sealed)
	ok := err == nil && string(back) == string(key)
	clear(back)
	if !ok {
		return svrpc.Errorf(svrpc.CodeFailed, "%s sealed the key but cannot open it again: %v", d.opts.Sealer.Name(), err)
	}
	info, err := mv.v.AddSlot(svcore.NewSlot{Type: svformat.SlotKeyfile, Label: "login", Keyfile: key})
	if err != nil {
		return err
	}
	b, _ := json.MarshalIndent(loginFile{Slot: info.ID, Sealer: d.opts.Sealer.Name(), Sealed: sealed}, "", "  ")
	path := d.loginPath(mv)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err == nil {
		err = writeFileAtomic(path, append(b, '\n'))
	}
	if err != nil {
		mv.v.RemoveSlot(info.ID)
		return err
	}
	return d.setLogin(mv, true)
}

func (d *Daemon) loginOff(mv *managedVault) error {
	if !mv.cfg.LoginUnlock {
		return svrpc.Errorf(svrpc.CodeNotFound, "vault %q does not open at login", mv.cfg.Name)
	}
	path := d.loginPath(mv)
	if b, err := os.ReadFile(path); err == nil {
		var lf loginFile
		if json.Unmarshal(b, &lf) == nil && !lf.Slot.IsZero() {
			if err := mv.v.RemoveSlot(lf.Slot); err != nil && !errors.Is(err, svcore.ErrLastSlot) {
				d.opts.Log(fmt.Sprintf("removing %s's login keyslot: %v", mv.cfg.Name, err))
			}
		}
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return d.setLogin(mv, false)
}

// setLogin records whether a vault opens at login, with the auto-lock
// that goes with it.
func (d *Daemon) setLogin(mv *managedVault, on bool) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	lock := DefaultAutoLock
	if on {
		lock = LoginAutoLock
	}
	for i := range d.cfg.Vaults {
		if d.cfg.Vaults[i].Name == mv.cfg.Name {
			old := d.cfg.Vaults[i]
			d.cfg.Vaults[i].LoginUnlock, d.cfg.Vaults[i].AutoLock = on, lock
			if err := d.cfg.save(d.home); err != nil {
				d.cfg.Vaults[i] = old
				return err
			}
			mv.cfg.LoginUnlock, mv.cfg.AutoLock = on, lock
			return nil
		}
	}
	return svrpc.Errorf(svrpc.CodeNoVault, "there is no vault named %q", mv.cfg.Name)
}

// writeFileAtomic writes a private file whole or not at all.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
