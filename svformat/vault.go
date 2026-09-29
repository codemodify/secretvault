package svformat

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
)

// A vault is a set of named files (docs/format.md, "Layout"):
//
//	vault.json                                  the descriptor
//	slots/<slot id>.json                        one file per keyslot
//	objects/<id[0:2]>/<object id>/<rev id>.svr  one file per revision
//
// Slot and revision files are written once and never changed, so a vault
// directory can be synchronised by anything that copies files (Syncthing,
// Dropbox, git, rsync) without two devices ever editing the same file. The
// descriptor changes only when an epoch is added.

// Names of the files in a vault.
const (
	DescriptorName = "vault.json"
	SlotsDir       = "slots"
	ObjectsDir     = "objects"
	RevisionExt    = ".svr"
)

// SlotName is where a keyslot lives.
func SlotName(id ID) string { return SlotsDir + "/" + id.String() + ".json" }

// RevisionName is where a revision lives.
func RevisionName(object ID, rev RevID) string {
	o := object.String()
	return ObjectsDir + "/" + o[:2] + "/" + o + "/" + rev.String() + RevisionExt
}

// ParseRevisionName reads the object and revision IDs back out of a
// revision's name. ok is false for any other name.
func ParseRevisionName(name string) (object ID, rev RevID, ok bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 4 || parts[0] != ObjectsDir || !strings.HasSuffix(parts[3], RevisionExt) {
		return object, rev, false
	}
	object, err := ParseID(parts[2])
	if err != nil || parts[1] != parts[2][:2] {
		return object, rev, false
	}
	rev, err = ParseRevID(strings.TrimSuffix(parts[3], RevisionExt))
	return object, rev, err == nil
}

// ParseSlotName reads the slot ID back out of a keyslot's name.
func ParseSlotName(name string) (ID, bool) {
	dir, file := path.Split(name)
	if dir != SlotsDir+"/" || !strings.HasSuffix(file, ".json") {
		return ID{}, false
	}
	id, err := ParseID(strings.TrimSuffix(file, ".json"))
	return id, err == nil
}

// DescriptorFormat and SlotFormat mark the JSON files of this version.
const (
	DescriptorFormat = "secretvault/v1"
	SlotFormat       = "secretvault/v1/slot"
)

// Descriptor is vault.json: what a vault is, readable without any key.
type Descriptor struct {
	Format  string    `json:"format"`
	ID      ID        `json:"id"`
	Suite   string    `json:"suite"`
	Created time.Time `json:"created"`
	Epochs  []Epoch   `json:"epochs"`
}

// Epoch is one generation of the vault master key. Every vault starts at
// epoch 1; rotating the master key (to cut off a removed member) adds one.
type Epoch struct {
	N uint32 `json:"n"`
	// Check is 16 bytes derived from the epoch's master key, so an unlock
	// can tell "this keyslot opened, but to some other key" from success.
	Check []byte `json:"check"`
}

// CheckValue is the Epoch.Check for a master key.
func CheckValue(vault ID, masterKey []byte) []byte {
	return svcrypto.Derive(masterKey, vault[:], "sv1 check", 16)
}

// ErrDescriptor is a vault.json that is not a usable v1 descriptor.
var ErrDescriptor = errors.New("svformat: bad vault descriptor")

// ParseDescriptor reads and checks vault.json.
func ParseDescriptor(b []byte) (Descriptor, svcrypto.Suite, error) {
	var d Descriptor
	if err := json.Unmarshal(b, &d); err != nil {
		return d, 0, fmt.Errorf("%w: %v", ErrDescriptor, err)
	}
	if d.Format != DescriptorFormat {
		return d, 0, fmt.Errorf("%w: format %q", ErrDescriptor, d.Format)
	}
	suite, err := svcrypto.ParseSuite(d.Suite)
	if err != nil {
		return d, 0, fmt.Errorf("%w: %v", ErrDescriptor, err)
	}
	if d.ID.IsZero() || len(d.Epochs) == 0 {
		return d, 0, fmt.Errorf("%w: no ID or no epochs", ErrDescriptor)
	}
	for i, e := range d.Epochs {
		if e.N != uint32(i+1) || len(e.Check) != 16 {
			return d, 0, fmt.Errorf("%w: epoch %d", ErrDescriptor, i+1)
		}
	}
	return d, suite, nil
}

// Keyslot types.
const (
	SlotPassphrase = "passphrase" // a passphrase through the suite's KDF
	SlotRecovery   = "recovery"   // a printed 256-bit recovery key
	SlotKeyfile    = "keyfile"    // the contents of a file
	SlotRecipient  = "recipient"  // an HPKE identity: a device, a person, a server
)

// GrantContent is the grant every keyslot has today: it opens the vault
// master key, and so everything. The field exists so that narrower grants
// (for example a key that only allows searching a locked vault) can be
// added without a new format.
const GrantContent = "content"

// Slot is one keyslot file: one way to recover the vault master key of one
// epoch. A vault has as many as its owners want, and needs any one.
type Slot struct {
	Format    string              `json:"format"`
	ID        ID                  `json:"id"`
	Vault     ID                  `json:"vault"`
	Epoch     uint32              `json:"epoch"`
	Type      string              `json:"type"`
	Label     string              `json:"label,omitempty"`
	Created   time.Time           `json:"created"`
	Grants    []string            `json:"grants"`
	KDF       *svcrypto.KDFParams `json:"kdf,omitempty"`       // passphrase
	Recipient []byte              `json:"recipient,omitempty"` // recipient: the public key
	Wrapped   []byte              `json:"wrapped"`             // the sealed master key
}

// AAD is what the wrapped master key is bound to: the vault, the slot, its
// epoch, type, label and grants. A slot file cannot be relabelled, moved to
// another vault or given wider grants without failing to open.
func (s *Slot) AAD() []byte {
	var t tlvBuilder
	t.add(0x01, s.Vault[:])
	t.add(0x02, s.ID[:])
	t.u32(0x03, s.Epoch)
	t.add(0x04, []byte(s.Type))
	t.add(0x05, []byte(s.Label))
	t.add(0x06, []byte(strings.Join(s.Grants, ",")))
	b, err := t.encode()
	if err != nil {
		panic(err) // a label beyond 64 KiB; refused by ParseSlot and NewSlot callers
	}
	return append([]byte("secretvault sv1 slot"), b...)
}

// ErrSlot is a keyslot file that is not a usable v1 slot.
var ErrSlot = errors.New("svformat: bad keyslot")

// ParseSlot reads and checks a keyslot file.
func ParseSlot(b []byte) (*Slot, error) {
	var s Slot
	if err := json.Unmarshal(b, &s); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSlot, err)
	}
	if s.Format != SlotFormat || s.ID.IsZero() || s.Vault.IsZero() || s.Epoch == 0 || len(s.Wrapped) == 0 || len(s.Label) > 1024 {
		return nil, fmt.Errorf("%w: incomplete", ErrSlot)
	}
	switch s.Type {
	case SlotPassphrase:
		if s.KDF == nil {
			return nil, fmt.Errorf("%w: passphrase slot without KDF", ErrSlot)
		}
	case SlotRecipient:
		if len(s.Recipient) == 0 {
			return nil, fmt.Errorf("%w: recipient slot without a public key", ErrSlot)
		}
	case SlotRecovery, SlotKeyfile:
	default:
		return nil, fmt.Errorf("%w: unknown type %q", ErrSlot, s.Type)
	}
	return &s, nil
}

// Epochs after the first live in files of their own, one per rotation of
// the vault master key:
//
//	epochs/<n>.json   n = 2, 3, ... (eight digits)
//
// Each records its key's check value and the previous epoch's master key,
// sealed under a key derived from the new one, so whoever holds the
// current key can read the whole history, and whoever was cut off at a
// rotation can read nothing written after it. Writing the record is the
// rotation's commit point; it is created once and never changed, so two
// devices rotating at once collide on the name instead of forking.

// EpochsDir holds the epoch records.
const EpochsDir = "epochs"

// EpochFormat marks an epoch record.
const EpochFormat = "secretvault/v1/epoch"

// EpochName is where epoch n's record lives.
func EpochName(n uint32) string { return fmt.Sprintf("%s/%08d.json", EpochsDir, n) }

// EpochRecord is one rotation of the vault master key.
type EpochRecord struct {
	Format  string    `json:"format"`
	Vault   ID        `json:"vault"`
	N       uint32    `json:"n"`
	Created time.Time `json:"created"`
	Check   []byte    `json:"check"` // CheckValue of this epoch's master key
	Prev    []byte    `json:"prev"`  // the previous master key, sealed (EpochPrevAAD)
}

// EpochPrevKeyLabel names the key, derived from epoch n's master key, that
// seals epoch n-1's.
const EpochPrevKeyLabel = "sv1 epoch prev"

// EpochPrevAAD binds a sealed previous key to its vault and epoch.
func EpochPrevAAD(vault ID, n uint32) []byte {
	aad := append([]byte("secretvault sv1 epoch prev"), vault[:]...)
	return append(aad, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// ErrEpoch is an epoch record that is not usable.
var ErrEpoch = errors.New("svformat: bad epoch record")

// ParseEpoch reads and checks an epoch record.
func ParseEpoch(b []byte) (*EpochRecord, error) {
	var e EpochRecord
	if err := json.Unmarshal(b, &e); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrEpoch, err)
	}
	if e.Format != EpochFormat || e.Vault.IsZero() || e.N < 2 || len(e.Check) != 16 || len(e.Prev) == 0 {
		return nil, fmt.Errorf("%w: incomplete", ErrEpoch)
	}
	return &e, nil
}
