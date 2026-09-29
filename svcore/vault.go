// Package svcore is the vault engine every face of secretvault runs on: it
// creates, unlocks and locks vaults, manages their keyslots, and stores
// items as immutable, content-addressed revisions (svformat) in a Backend
// (svstore). It is a library with no I/O of its own beyond the backend; the
// daemon, the CLI and the tests all drive it the same way.
package svcore

import (
	"bytes"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

var (
	// ErrLocked is an operation that needs the vault open while it is locked.
	ErrLocked = errors.New("svcore: the vault is locked")

	// ErrWrongKey is an unlock where no keyslot accepted the key given.
	ErrWrongKey = errors.New("svcore: no keyslot accepts that key")

	// ErrNotVault is a backend with no vault in it.
	ErrNotVault = errors.New("svcore: there is no vault here")

	// ErrExists is a Create where a vault already is.
	ErrExists = errors.New("svcore: a vault already exists here")

	// ErrNotFound is an item that does not exist.
	ErrNotFound = errors.New("svcore: no such item")

	// ErrLastSlot is removing the only keyslot, which would lose the vault.
	ErrLastSlot = errors.New("svcore: that is the vault's only keyslot")
)

// Options configure a vault handle.
type Options struct {
	// Device is recorded in every revision this handle writes. Zero means
	// "not recorded".
	Device svformat.ID

	// Now is the clock (tests replace it). Defaults to time.Now.
	Now func() time.Time
}

// Vault is an open handle on one vault. It is safe for concurrent use.
type Vault struct {
	store svstore.Backend
	desc  svformat.Descriptor
	suite svcrypto.Suite
	opts  Options

	mu         sync.Mutex
	master     *svcrypto.Secret // nil while locked
	wrap       *svcrypto.Secret // wraps object keys; derived from master
	unlockedBy svformat.ID
	idx        *index
	lastTime   int64
}

// Create makes a new vault in an empty backend, with one keyslot, and
// returns it unlocked. suite 0 means svcrypto.Modern.
func Create(store svstore.Backend, suite svcrypto.Suite, first NewSlot, opts Options) (*Vault, SlotInfo, error) {
	if suite == 0 {
		suite = svcrypto.Modern
	}
	if !suite.Valid() {
		return nil, SlotInfo{}, svcrypto.ErrSuite
	}
	if _, err := store.Read(svformat.DescriptorName); err == nil {
		return nil, SlotInfo{}, ErrExists
	} else if !errors.Is(err, svstore.ErrNotExist) {
		return nil, SlotInfo{}, err
	}
	v := &Vault{store: store, suite: suite, opts: opts.withDefaults()}
	id, master := svformat.NewID(), svcrypto.RandomKey()
	v.desc = svformat.Descriptor{
		Format:  svformat.DescriptorFormat,
		ID:      id,
		Suite:   suite.String(),
		Created: v.opts.Now().UTC(),
		Epochs:  []svformat.Epoch{{N: 1, Check: svformat.CheckValue(id, master)}},
	}
	v.setOpen(master)

	// The slot goes first: a crash between the two leaves a stray slot file
	// in an empty directory, never a vault that no key opens.
	info, err := v.AddSlot(first)
	if err != nil {
		v.Lock()
		return nil, SlotInfo{}, err
	}
	desc, err := json.MarshalIndent(v.desc, "", "  ")
	if err != nil {
		v.Lock()
		return nil, SlotInfo{}, err
	}
	if err := store.Create(svformat.DescriptorName, append(desc, '\n')); err != nil {
		store.Remove(svformat.SlotName(info.ID))
		v.Lock()
		if errors.Is(err, svstore.ErrExist) {
			return nil, SlotInfo{}, ErrExists
		}
		return nil, SlotInfo{}, err
	}
	v.unlockedBy = info.ID
	return v, info, nil
}

// Open returns a locked handle on the vault in store.
func Open(store svstore.Backend, opts Options) (*Vault, error) {
	b, err := store.Read(svformat.DescriptorName)
	if errors.Is(err, svstore.ErrNotExist) {
		return nil, ErrNotVault
	}
	if err != nil {
		return nil, err
	}
	desc, suite, err := svformat.ParseDescriptor(b)
	if err != nil {
		return nil, err
	}
	if len(desc.Epochs) != 1 {
		return nil, fmt.Errorf("svcore: vault has %d key epochs; this version supports 1", len(desc.Epochs))
	}
	return &Vault{store: store, desc: desc, suite: suite, opts: opts.withDefaults()}, nil
}

func (o Options) withDefaults() Options {
	if o.Now == nil {
		o.Now = time.Now
	}
	return o
}

// ID is the vault's ID.
func (v *Vault) ID() svformat.ID { return v.desc.ID }

// Suite is the vault's cipher suite.
func (v *Vault) Suite() svcrypto.Suite { return v.suite }

// Created is when the vault was made.
func (v *Vault) Created() time.Time { return v.desc.Created }

func (v *Vault) epoch() uint32 { return uint32(len(v.desc.Epochs)) }

// Locked reports whether the vault is locked.
func (v *Vault) Locked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.master == nil
}

// UnlockedBy is the keyslot the vault was last unlocked with (for Create,
// the first slot).
func (v *Vault) UnlockedBy() svformat.ID {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.unlockedBy
}

// Unlock opens the vault with a key, trying every keyslot of the key's type.
// An unlocked vault is re-unlocked (the key is still checked).
func (v *Vault) Unlock(k Key) error {
	master, slot, err := v.findMaster(k)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.setOpen(master)
	v.unlockedBy = slot
	v.mu.Unlock()
	return v.Refresh()
}

// CheckKey reports whether k opens the vault, without changing whether
// it is locked: for asking someone to prove they hold a key.
func (v *Vault) CheckKey(k Key) error {
	master, _, err := v.findMaster(k)
	clear(master)
	return err
}

// findMaster recovers the master key with k from the first keyslot that
// takes it.
func (v *Vault) findMaster(k Key) ([]byte, svformat.ID, error) {
	slots, err := v.slots()
	if err != nil {
		return nil, svformat.ID{}, err
	}
	for _, s := range slots {
		if s.Type != k.slotType() || s.Epoch != v.epoch() {
			continue
		}
		master, err := k.open(v, s)
		if err != nil {
			continue
		}
		if subtle.ConstantTimeCompare(svformat.CheckValue(v.desc.ID, master), v.desc.Epochs[s.Epoch-1].Check) != 1 {
			// The slot opened, but to some other key: planted or from
			// another vault. Keep looking.
			clear(master)
			continue
		}
		return master, s.ID, nil
	}
	return nil, svformat.ID{}, ErrWrongKey
}

// setOpen installs the master key (and zeroes the caller's copy).
func (v *Vault) setOpen(master []byte) {
	v.dropKeys()
	wrap := svcrypto.Derive(master, v.desc.ID[:], "sv1 wrap", svcrypto.KeySize)
	v.master = svcrypto.SecretFrom(master)
	v.wrap = svcrypto.SecretFrom(wrap)
	v.idx = newIndex()
}

func (v *Vault) dropKeys() {
	v.master.Destroy()
	v.wrap.Destroy()
	v.master, v.wrap = nil, nil
	if v.idx != nil {
		v.idx.wipe()
		v.idx = nil
	}
}

// Lock forgets the keys and every decrypted item.
func (v *Vault) Lock() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.dropKeys()
}

// tick is the hybrid logical clock: wall time, but always after every
// parent and every revision this handle wrote before.
func (v *Vault) tick(parents []*revision) int64 {
	t := v.opts.Now().UnixNano()
	t = max(t, v.lastTime+1)
	for _, p := range parents {
		t = max(t, p.hdr.Time+1)
	}
	v.lastTime = t
	return t
}

// A Key is something that may open a keyslot.
type Key interface {
	slotType() string
	open(v *Vault, s *svformat.Slot) ([]byte, error)
}

type passphraseKey []byte

// Passphrase is a key for passphrase slots.
func Passphrase(p []byte) Key { return passphraseKey(p) }

func (passphraseKey) slotType() string { return svformat.SlotPassphrase }

func (k passphraseKey) open(v *Vault, s *svformat.Slot) ([]byte, error) {
	kek, err := s.KDF.DeriveKey(k)
	if err != nil {
		return nil, err
	}
	defer clear(kek)
	return v.suite.Open(kek, s.Wrapped, s.AAD())
}

type recoveryKey []byte

// RecoveryKey is a key for recovery slots: the 32 bytes behind the printed
// SVRK1-... text (svformat.ParseRecoveryKey).
func RecoveryKey(k []byte) Key { return recoveryKey(k) }

func (recoveryKey) slotType() string { return svformat.SlotRecovery }

func (k recoveryKey) open(v *Vault, s *svformat.Slot) ([]byte, error) {
	kek := svcrypto.Derive(k, v.desc.ID[:], "sv1 recovery kek", svcrypto.KeySize)
	defer clear(kek)
	return v.suite.Open(kek, s.Wrapped, s.AAD())
}

type keyfileKey []byte

// Keyfile is a key for keyfile slots: the file's whole contents.
func Keyfile(data []byte) Key { return keyfileKey(data) }

func (keyfileKey) slotType() string { return svformat.SlotKeyfile }

func (k keyfileKey) open(v *Vault, s *svformat.Slot) ([]byte, error) {
	kek := svcrypto.Derive(k, v.desc.ID[:], "sv1 keyfile kek", svcrypto.KeySize)
	defer clear(kek)
	return v.suite.Open(kek, s.Wrapped, s.AAD())
}

type identityKey struct{ id *svcrypto.Identity }

// IdentityKey is a key for recipient slots addressed to id.
func IdentityKey(id *svcrypto.Identity) Key { return identityKey{id} }

func (identityKey) slotType() string { return svformat.SlotRecipient }

func (k identityKey) open(v *Vault, s *svformat.Slot) ([]byte, error) {
	if k.id.Suite() != v.suite || !bytes.Equal(s.Recipient, k.id.Recipient()) {
		return nil, ErrWrongKey
	}
	return k.id.Open(s.Wrapped, s.AAD())
}

// DeriveKey derives a key for a purpose outside the vault format itself
// (the daemon's audit log, say) from the vault master key. Each label
// gives an independent key; none equals a key the format uses.
func (v *Vault) DeriveKey(label string, n int) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.master == nil {
		return nil, ErrLocked
	}
	return svcrypto.Derive(v.master.Bytes(), v.desc.ID[:], "app "+label, n), nil
}
