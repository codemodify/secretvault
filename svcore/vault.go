// Package svcore is the vault engine every face of secretvault runs on: it
// creates, unlocks and locks vaults, manages their keyslots, and stores
// items as immutable, content-addressed revisions (svformat) in a Backend
// (svstore). It is a library with no I/O of its own beyond the backend; the
// daemon, the CLI and the tests all drive it the same way.
package svcore

import (
	"bytes"
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

	// ErrItemExists is a PutNew whose name an item already has.
	ErrItemExists = errors.New("svcore: an item of that name already exists")

	// ErrLastSlot is removing the only keyslot, which would lose the vault.
	ErrLastSlot = errors.New("svcore: that is the vault's only keyslot")
)

// Options configure a vault handle.
type Options struct {
	// Device is recorded in every revision this handle writes. Zero means
	// "not recorded" (with a Signer: the Signer's key ID).
	Device svformat.ID

	// Signer signs every revision this handle writes (devices.go). Nil
	// means they are not signed, which a vault whose policy requires
	// signatures refuses. Signatures verify, for this handle and every
	// other, once the key is registered in the vault (RegisterDevice).
	Signer *DeviceKey

	// Now is the clock (tests replace it). Defaults to time.Now.
	Now func() time.Time
}

// Vault is an open handle on one vault. It is safe for concurrent use.
type Vault struct {
	store svstore.Backend
	desc  svformat.Descriptor
	suite svcrypto.Suite
	opts  Options

	// epochs are the check values of every generation of the master key
	// (epochs[i] is epoch i+1), and epochRecs the records of those after
	// the first. While locked they are what the folder holds; once open,
	// only those the key vouched for (epochs.go). epochProblems are the
	// records that do not count.
	epochs        []svformat.Epoch
	epochRecs     map[uint32]*svformat.EpochRecord
	epochProblems []Problem

	mu         sync.Mutex
	masters    map[uint32]*svcrypto.Secret // every epoch's master key; nil while locked
	wraps      map[uint32]*svcrypto.Secret // every epoch's key for wrapping object keys
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
	v.epochs, v.epochRecs = v.desc.Epochs, map[uint32]*svformat.EpochRecord{}
	v.install(&opened{masters: map[uint32][]byte{1: master}, epoch: 1})

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
		return nil, fmt.Errorf("svcore: the descriptor lists %d epochs; later epochs belong in %s/", len(desc.Epochs), svformat.EpochsDir)
	}
	v := &Vault{store: store, desc: desc, suite: suite, opts: opts.withDefaults()}
	if err := v.loadEpochs(); err != nil {
		return nil, err
	}
	return v, nil
}

func (o Options) withDefaults() Options {
	if o.Now == nil {
		o.Now = time.Now
	}
	if o.Signer != nil && o.Device.IsZero() {
		o.Device = o.Signer.ID()
	}
	return o
}

// ID is the vault's ID.
func (v *Vault) ID() svformat.ID { return v.desc.ID }

// Suite is the vault's cipher suite.
func (v *Vault) Suite() svcrypto.Suite { return v.suite }

// Created is when the vault was made.
func (v *Vault) Created() time.Time { return v.desc.Created }

func (v *Vault) epoch() uint32 { return uint32(len(v.epochs)) }

// Epoch is the current generation of the vault master key: 1 for a vault
// never rotated.
func (v *Vault) Epoch() uint32 {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.epoch()
}

// Locked reports whether the vault is locked.
func (v *Vault) Locked() bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	return v.masters == nil
}

// master is the current epoch's master key (nil while locked).
func (v *Vault) master() *svcrypto.Secret { return v.masters[v.epoch()] }

// wrap is the current epoch's wrapping key.
func (v *Vault) wrap() *svcrypto.Secret { return v.wraps[v.epoch()] }

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
	v.mu.Lock()
	err := v.loadEpochs()
	v.mu.Unlock()
	if err != nil {
		return err
	}
	o, err := v.openChain(k)
	if err != nil {
		return err
	}
	v.mu.Lock()
	v.install(o)
	v.mu.Unlock()
	return v.Refresh()
}

// CheckKey reports whether k opens the vault, without changing whether
// it is locked: for asking someone to prove they hold a key.
func (v *Vault) CheckKey(k Key) error {
	o, err := v.openChain(k)
	if err != nil {
		return err
	}
	clearAll(o.masters)
	return nil
}

func destroyAll(m map[uint32]*svcrypto.Secret) {
	for _, s := range m {
		s.Destroy()
	}
}

func (v *Vault) dropKeys() {
	destroyAll(v.masters)
	destroyAll(v.wraps)
	v.masters, v.wraps = nil, nil
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

type emergencyKey struct {
	id      *svcrypto.Identity
	grant   svformat.ID
	release []byte
}

// EmergencyKey is a key for the emergency slots of one grant: the
// trustee's identity, and the release key the sync server escrowed for
// them (svformat/emergency.go). Either alone opens nothing.
func EmergencyKey(id *svcrypto.Identity, grant svformat.ID, release []byte) Key {
	return emergencyKey{id, grant, release}
}

func (emergencyKey) slotType() string { return svformat.SlotEmergency }

func (k emergencyKey) open(v *Vault, s *svformat.Slot) ([]byte, error) {
	if k.id.Suite() != v.suite || s.Emergency == nil || s.Emergency.Grant != k.grant || !bytes.Equal(s.Recipient, k.id.Recipient()) {
		return nil, ErrWrongKey
	}
	inner, err := k.id.Open(s.Wrapped, s.AAD())
	if err != nil {
		return nil, err
	}
	defer clear(inner)
	kek := svcrypto.Derive(k.release, v.desc.ID[:], svformat.EmergencyKEKLabel, svcrypto.KeySize)
	defer clear(kek)
	return v.suite.Open(kek, inner, s.AAD())
}

// DeriveKey derives a key for a purpose outside the vault format itself
// (the daemon's audit log, say) from the vault master key. Each label
// gives an independent key; none equals a key the format uses.
//
// Keys are derived from the first epoch's master key, so they stay the same
// across rotations (a device-local audit log stays readable).
func (v *Vault) DeriveKey(label string, n int) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return nil, ErrLocked
	}
	return svcrypto.Derive(v.masters[1].Bytes(), v.desc.ID[:], "app "+label, n), nil
}
