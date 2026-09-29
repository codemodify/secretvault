package svdeliver

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svstore"
)

// Delivery vaults are vault folders the server holds open with its own
// identity, through a recipient keyslot the vault's owner gave it
// (secretvault share RECIPIENT). The folder is kept up to date by
// whatever syncs it: this server's own sync hub (a vault added by its
// name there), or Syncthing, git, rsync and the like. The server only
// ever reads it, through a backend that refuses every write, and reads
// what arrived at most once a second, before a request uses the vault.
//
// A vault that cannot be opened (not shared with the server yet, or cut
// off by a rotation) is tried again when asked for, at most every five
// seconds.

type deliveryVault struct {
	cfg VaultConfig

	mu        sync.Mutex
	v         *svcore.Vault
	suite     svcrypto.Suite
	problem   error
	tried     time.Time
	refreshed time.Time
}

const reopenEvery = 5 * time.Second

// get returns the vault, open and fresh.
func (d *deliveryVault) get(ids map[svcrypto.Suite]*svcrypto.Identity, now time.Time) (*svcore.Vault, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.v != nil && !d.v.Locked() {
		if now.Sub(d.refreshed) < time.Second && !now.Before(d.refreshed) {
			return d.v, nil
		}
		d.refreshed = now
		// A vault rotated elsewhere locks itself here; it opens again
		// below with the server's slot of the new epoch, if it was kept.
		if err := d.v.Refresh(); err != nil && !errors.Is(err, svcore.ErrRotated) && !errors.Is(err, svcore.ErrLocked) {
			return d.v, nil // what was read before still stands
		}
		if !d.v.Locked() {
			return d.v, nil
		}
		d.tried = time.Time{}
	}
	if d.problem != nil && now.Sub(d.tried) < reopenEvery && !now.Before(d.tried) {
		return nil, d.problem
	}
	d.tried = now
	v, err := d.open(ids)
	if err != nil {
		d.problem = err
		return nil, err
	}
	d.v, d.problem, d.refreshed = v, nil, now
	return v, nil
}

func (d *deliveryVault) open(ids map[svcrypto.Suite]*svcrypto.Identity) (*svcore.Vault, error) {
	v, err := openVaultReadOnly(d.cfg.Path)
	if err != nil {
		return nil, err
	}
	if v.ID().String() != d.cfg.ID {
		return nil, fmt.Errorf("%s now holds another vault (%s) than the one added (%s)", d.cfg.Path, v.ID(), d.cfg.ID)
	}
	d.suite = v.Suite()
	id := ids[v.Suite()]
	if id == nil {
		return nil, fmt.Errorf("the server has no identity for %s", v.Suite())
	}
	switch err := v.Unlock(svcore.IdentityKey(id)); {
	case err == nil:
		return v, nil
	case errors.Is(err, svcore.ErrWrongKey):
		return nil, errors.New("it has not been shared with the server: on a device that opens it, run 'secretvault share RECIPIENT' with the server's recipient")
	case errors.Is(err, svcore.ErrKeyRemoved):
		return nil, errors.New("the server was left out when the vault key was rotated: share it with the server again")
	default:
		return nil, err
	}
}

// state reports whether the vault is open, and if not, why.
func (d *deliveryVault) state(ids map[svcrypto.Suite]*svcrypto.Identity, now time.Time) (svcrypto.Suite, error) {
	_, err := d.get(ids, now)
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.suite, err
}

func (d *deliveryVault) close() {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.v != nil {
		d.v.Lock()
		d.v = nil
	}
}

// openVaultReadOnly returns a locked handle on the vault in dir, through a
// backend that refuses every write.
func openVaultReadOnly(dir string) (*svcore.Vault, error) {
	st, err := os.Stat(dir)
	if err != nil {
		return nil, err
	}
	if !st.IsDir() {
		return nil, fmt.Errorf("%s is not a folder", dir)
	}
	store, err := svstore.OpenDir(dir)
	if err != nil {
		return nil, err
	}
	v, err := svcore.Open(readOnly{store}, svcore.Options{})
	if errors.Is(err, svcore.ErrNotVault) {
		return nil, fmt.Errorf("there is no vault in %s (yet)", dir)
	}
	return v, err
}

// readOnly is a backend that can only be read.
type readOnly struct{ svstore.Backend }

var errReadOnly = errors.New("svdeliver: delivery vaults are only read, never written")

func (readOnly) Create(string, []byte) error { return errReadOnly }
func (readOnly) Write(string, []byte) error  { return errReadOnly }
func (readOnly) Remove(string) error         { return errReadOnly }
