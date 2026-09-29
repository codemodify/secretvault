package svcore

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// Rotating the vault master key.
//
// Removing a keyslot stops that key opening the vault, but whoever held it
// may have kept the master key it opened. A rotation makes a new master key
// that only the keyslots given here open: from then on, what is written is
// out of the old key's reach. Earlier contents stay readable to holders of
// the new key through the epoch chain, and every item's current state is
// written again under the new key, so a person cut off keeps at most what
// they could already read.
//
// The order makes a crash harmless at any point:
//
//  1. the new epoch's keyslots are written (inert until the epoch exists);
//  2. the epoch record is written: the commit point. It lists every
//     revision there is, since from then on no other revision sealed under
//     an older key counts, and it is authenticated under the current key;
//  3. the old epoch's keyslots are removed;
//  4. every live item and record is written again under the new key,
//     signed by this handle's device if it signs; device and policy
//     records, and a winner whose signature is bad or unverified, are
//     left as they are (writeAgain, devices.go).
//
// A crash before 2 leaves stray keyslots nothing reads; after 2, an
// unfinished step 3 or 4 is finished by rotating again or by the next
// write, and nothing is unreadable meanwhile.

// ErrRotating is a rotation that met another one made at the same time.
var ErrRotating = errors.New("svcore: another device rotated the vault key at the same time; unlock and try again")

// Rotate replaces the master key. slots are the keyslots the new key gets
// (passphrase, recovery, keyfile, recipient, fido2, emergency). With
// keepRecipients, every recipient slot of the current epoch (a device, a
// person) is carried over too, unless drop says otherwise: that is how a
// person is cut off. Nothing else is carried over: a keyfile, a security
// key or an emergency grant opens the new key only if it is among slots,
// since a security key has to be touched to seal anything for it, and an
// emergency slot's release key is not in the slot.
func (v *Vault) Rotate(slots []NewSlot, keepRecipients bool, drop func(SlotInfo) bool) ([]SlotInfo, error) {
	// Security keys are enrolled before anything is locked or written:
	// each takes the person's touch.
	slots = append([]NewSlot(nil), slots...)
	for i := range slots {
		if slots[i].Type != svformat.SlotFIDO2 {
			continue
		}
		if v.Locked() {
			return nil, ErrLocked
		}
		if err := v.enroll(&slots[i], false); err != nil {
			return nil, err
		}
		defer slots[i].enrolled.wipe()
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.masters == nil {
		return nil, ErrLocked
	}
	current, err := v.slots()
	if err != nil {
		return nil, err
	}
	if keepRecipients {
		for _, s := range current {
			if s.Type == svformat.SlotRecipient && s.Epoch == v.epoch() && (drop == nil || !drop(slotInfo(s))) {
				slots = append(slots, NewSlot{Type: svformat.SlotRecipient, Label: s.Label, Recipient: s.Recipient})
			}
		}
	}
	if len(slots) == 0 {
		return nil, errors.New("svcore: a rotation needs at least one keyslot for the new key")
	}
	n := v.epoch() + 1
	master := svcrypto.RandomKey()
	defer clear(master)

	// 1. The new keyslots.
	var infos []SlotInfo
	for _, ns := range slots {
		info, err := v.addSlot(ns, n, master)
		if err != nil {
			for _, done := range infos {
				v.store.Remove(svformat.SlotName(done.ID))
			}
			return nil, err
		}
		infos = append(infos, info)
	}

	// 2. The epoch record.
	prevKey := svcrypto.Derive(master, v.desc.ID[:], svformat.EpochPrevKeyLabel, svcrypto.KeySize)
	sealed, err := v.suite.Seal(prevKey, v.master().Bytes(), svformat.EpochPrevAAD(v.desc.ID, n))
	clear(prevKey)
	if err != nil {
		return nil, err
	}
	var revs []svformat.RevID
	for _, o := range v.idx.objects {
		for id := range o.revs {
			revs = append(revs, id)
		}
	}
	rec := &svformat.EpochRecord{Format: svformat.EpochFormat, Vault: v.desc.ID, N: n, Created: v.opts.Now().UTC(),
		Check: svformat.CheckValue(v.desc.ID, master), Prev: sealed, Revisions: svformat.RevisionList(revs)}
	rec.Auth = svformat.EpochAuth(v.master().Bytes(), rec)
	b, err := jsonIndent(rec)
	if err != nil {
		return nil, err
	}
	if err := v.store.Create(svformat.EpochName(n), b); err != nil {
		for _, done := range infos {
			v.store.Remove(svformat.SlotName(done.ID))
		}
		if errors.Is(err, svstore.ErrExist) {
			return nil, v.whoRotated(n)
		}
		return nil, err
	}
	v.epochs = append(slices.Clone(v.epochs), svformat.Epoch{N: n, Check: rec.Check})
	recs := maps.Clone(v.epochRecs)
	recs[n] = rec
	v.epochRecs = recs
	v.masters[n] = svcrypto.SecretFrom(append([]byte(nil), master...))
	v.wraps[n] = svcrypto.SecretFrom(svcrypto.Derive(master, v.desc.ID[:], "sv1 wrap", svcrypto.KeySize))
	if len(infos) > 0 {
		v.unlockedBy = infos[0].ID
	}

	// 3. The old keyslots.
	for _, s := range current {
		if s.Epoch < n {
			if err := v.store.Remove(svformat.SlotName(s.ID)); err != nil {
				return infos, fmt.Errorf("svcore: the key was rotated, but an old keyslot could not be removed: %w", err)
			}
		}
	}

	// 4. Everything current, again under the new key (signed by this
	// device, if it signs; devices.go says what is left as it is).
	for id, o := range v.idx.objects {
		if len(o.heads) == 0 || o.heads[0].hdr.Epoch == n {
			continue
		}
		if err := v.writeAgain(id, o, false); err != nil {
			return infos, fmt.Errorf("svcore: the key was rotated, but not everything was re-encrypted yet: %w", err)
		}
	}
	return infos, nil
}

// whoRotated explains an epoch record that got there first: another
// rotation, or one planted by someone who cannot open the vault, which
// blocks rotating until it is removed. The caller holds v.mu.
func (v *Vault) whoRotated(n uint32) error {
	b, err := v.store.Read(svformat.EpochName(n))
	if err != nil {
		return ErrRotating
	}
	rec, err := svformat.ParseEpoch(b)
	if err == nil && rec.Vault == v.desc.ID && rec.N == n && svformat.CheckEpochAuth(v.master().Bytes(), rec) {
		return ErrRotating
	}
	return fmt.Errorf("svcore: %s was put there by someone who cannot open the vault; remove it, then rotate again", svformat.EpochName(n))
}

func jsonIndent(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return append(b, '\n'), err
}
