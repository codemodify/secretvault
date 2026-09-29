package svcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// NewSlot describes a keyslot to add. Type is one of the svformat.Slot*
// types; the matching field carries the key.
type NewSlot struct {
	Type  string
	Label string

	Passphrase   []byte              // SlotPassphrase
	KDF          *svcrypto.KDFParams // SlotPassphrase: nil for the suite default
	Keyfile      []byte              // SlotKeyfile: the file's contents
	Recipient    []byte              // SlotRecipient, SlotEmergency: the public key
	SecurityKeys SecurityKeys        // SlotFIDO2: reaches the key to enrol
	FIDO2UV      *bool               // SlotFIDO2: use the key's PIN; nil: when it has one
	Grant        svformat.ID         // SlotEmergency: the grant on the sync server
	ReleaseKey   []byte              // SlotEmergency: the release key the server escrows

	enrolled *enrolled // SlotFIDO2: the credential, once made
}

// SlotInfo describes a keyslot, without anything secret in it, except
// RecoveryKey, which AddSlot fills once for a new recovery slot: it exists
// nowhere else, and must be shown to the person and then forgotten.
type SlotInfo struct {
	ID          svformat.ID
	Type        string
	Label       string
	Created     time.Time
	Epoch       uint32
	KDF         *svcrypto.KDFParams
	Recipient   []byte
	FIDO2       *svformat.FIDO2
	Grant       svformat.ID // an emergency slot's grant
	RecoveryKey string
}

// AddSlot adds a keyslot that opens the vault's current master key. For
// a fido2 slot the security key is asked first, which takes the person's
// touch (twice) and perhaps its PIN; the vault stays usable meanwhile.
func (v *Vault) AddSlot(ns NewSlot) (SlotInfo, error) {
	if ns.Type == svformat.SlotFIDO2 {
		if v.Locked() {
			return SlotInfo{}, ErrLocked
		}
		if err := v.enroll(&ns, true); err != nil {
			return SlotInfo{}, err
		}
		defer ns.enrolled.wipe()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return SlotInfo{}, ErrLocked
	}
	return v.addSlot(ns, v.epoch(), v.master().Bytes())
}

// addSlot writes a keyslot for master, of the given epoch (the current
// one, or the next during a rotation). The caller holds v.mu.
func (v *Vault) addSlot(ns NewSlot, epoch uint32, master []byte) (SlotInfo, error) {
	if len(ns.Label) > 256 {
		return SlotInfo{}, errors.New("svcore: slot label is longer than 256 bytes")
	}
	s := &svformat.Slot{
		Format:  svformat.SlotFormat,
		ID:      svformat.NewID(),
		Vault:   v.desc.ID,
		Epoch:   epoch,
		Type:    ns.Type,
		Label:   ns.Label,
		Created: v.opts.Now().UTC(),
		Grants:  []string{svformat.GrantContent},
	}
	info := SlotInfo{}
	var kek []byte
	defer func() { clear(kek) }()
	var err error
	switch ns.Type {
	case svformat.SlotPassphrase:
		if len(ns.Passphrase) == 0 {
			return SlotInfo{}, errors.New("svcore: empty passphrase")
		}
		p := v.suite.NewKDFParams()
		if ns.KDF != nil {
			p = *ns.KDF
		}
		if kek, err = p.DeriveKey(ns.Passphrase); err != nil {
			return SlotInfo{}, err
		}
		s.KDF = &p
		s.Wrapped, err = v.suite.Seal(kek, master, s.AAD())
	case svformat.SlotRecovery:
		rk := svcrypto.RandomKey()
		kek = svcrypto.Derive(rk, v.desc.ID[:], "sv1 recovery kek", svcrypto.KeySize)
		info.RecoveryKey = svformat.EncodeRecoveryKey(rk)
		clear(rk)
		s.Wrapped, err = v.suite.Seal(kek, master, s.AAD())
	case svformat.SlotKeyfile:
		if len(ns.Keyfile) < 32 {
			return SlotInfo{}, errors.New("svcore: a keyfile must hold at least 32 bytes")
		}
		kek = svcrypto.Derive(ns.Keyfile, v.desc.ID[:], "sv1 keyfile kek", svcrypto.KeySize)
		s.Wrapped, err = v.suite.Seal(kek, master, s.AAD())
	case svformat.SlotRecipient:
		if err := v.suite.CheckRecipient(ns.Recipient); err != nil {
			return SlotInfo{}, err
		}
		s.Recipient = append([]byte(nil), ns.Recipient...)
		s.Wrapped, err = v.suite.SealTo(s.Recipient, master, s.AAD())
	case svformat.SlotEmergency:
		// Sealed under the release key, then to the trustee: it takes
		// both to open (svformat/emergency.go).
		if err := v.suite.CheckRecipient(ns.Recipient); err != nil {
			return SlotInfo{}, err
		}
		if len(ns.ReleaseKey) != svformat.ReleaseKeySize || ns.Grant.IsZero() {
			return SlotInfo{}, errors.New("svcore: an emergency slot needs its grant and a 32-byte release key")
		}
		s.Recipient = append([]byte(nil), ns.Recipient...)
		s.Emergency = &svformat.Emergency{Grant: ns.Grant}
		kek = svcrypto.Derive(ns.ReleaseKey, v.desc.ID[:], svformat.EmergencyKEKLabel, svcrypto.KeySize)
		var inner []byte
		if inner, err = v.suite.Seal(kek, master, s.AAD()); err == nil {
			s.Wrapped, err = v.suite.SealTo(s.Recipient, inner, s.AAD())
		}
	case svformat.SlotFIDO2:
		if ns.enrolled == nil {
			return SlotInfo{}, errors.New("svcore: the security key was not enrolled")
		}
		params := ns.enrolled.params
		s.FIDO2 = &params
		kek = v.fido2KEK(ns.enrolled.output)
		s.Wrapped, err = v.suite.Seal(kek, master, s.AAD())
	default:
		return SlotInfo{}, fmt.Errorf("svcore: unknown keyslot type %q", ns.Type)
	}
	if err != nil {
		return SlotInfo{}, err
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return SlotInfo{}, err
	}
	if err := v.store.Create(svformat.SlotName(s.ID), append(b, '\n')); err != nil {
		return SlotInfo{}, err
	}
	rk := info.RecoveryKey
	info = slotInfo(s)
	info.RecoveryKey = rk
	return info, nil
}

func slotInfo(s *svformat.Slot) SlotInfo {
	info := SlotInfo{ID: s.ID, Type: s.Type, Label: s.Label, Created: s.Created, Epoch: s.Epoch, KDF: s.KDF, Recipient: s.Recipient, FIDO2: s.FIDO2}
	if s.Emergency != nil {
		info.Grant = s.Emergency.Grant
	}
	return info
}

// Slots lists the vault's keyslots. It works while locked.
func (v *Vault) Slots() ([]SlotInfo, error) {
	slots, err := v.slots()
	if err != nil {
		return nil, err
	}
	out := make([]SlotInfo, len(slots))
	for i, s := range slots {
		out[i] = slotInfo(s)
	}
	return out, nil
}

// slots reads every keyslot that belongs to this vault, oldest first.
// Files that do not parse or name another vault are skipped: a keyslot can
// only ever add a way in, so ignoring a bad one loses nothing.
func (v *Vault) slots() ([]*svformat.Slot, error) {
	names, err := v.store.List(svformat.SlotsDir)
	if err != nil {
		return nil, err
	}
	var out []*svformat.Slot
	for _, n := range names {
		id, ok := svformat.ParseSlotName(n)
		if !ok {
			continue
		}
		b, err := v.store.Read(n)
		if err != nil {
			if errors.Is(err, svstore.ErrNotExist) {
				continue
			}
			return nil, err
		}
		s, err := svformat.ParseSlot(b)
		if err != nil || s.ID != id || s.Vault != v.desc.ID {
			continue
		}
		out = append(out, s)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

// RemoveSlot deletes a keyslot. The vault must be unlocked, so a slot can
// only be removed by someone who could open the vault anyway, and the last
// slot of the current epoch cannot be removed at all.
//
// Removing a slot stops that key from opening this copy of the vault. It
// does not undo what the key's holder may already have: a copy of the
// slot file, or the master key itself. Cutting someone off for good needs
// a new epoch (a new master key), which a later version adds.
func (v *Vault) RemoveSlot(id svformat.ID) error {
	v.mu.Lock()
	locked := v.masters == nil
	v.mu.Unlock()
	if locked {
		return ErrLocked
	}
	slots, err := v.slots()
	if err != nil {
		return err
	}
	found, others := false, 0
	for _, s := range slots {
		if s.ID == id {
			found = true
		} else if s.Epoch == v.epoch() {
			others++
		}
	}
	if !found {
		return fmt.Errorf("svcore: no keyslot %s", id)
	}
	if others == 0 {
		return ErrLastSlot
	}
	return v.store.Remove(svformat.SlotName(id))
}
