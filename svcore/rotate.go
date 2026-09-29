package svcore

import (
	"encoding/json"
	"errors"
	"fmt"

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
//  2. the epoch record is written: the commit point;
//  3. the old epoch's keyslots are removed;
//  4. every live item and record is written again under the new key.
//
// A crash before 2 leaves stray keyslots nothing reads; after 2, an
// unfinished step 3 or 4 is finished by rotating again or by the next
// write, and nothing is unreadable meanwhile.

// ErrRotating is a rotation that met another one made at the same time.
var ErrRotating = errors.New("svcore: another device rotated the vault key at the same time; unlock and try again")

// Rotate replaces the master key. slots are the keyslots the new key gets
// (passphrase, recovery, keyfile, recipient). With keepRecipients, every
// recipient slot of the current epoch (a device, a person) is carried over
// too, unless drop says otherwise: that is how a person is cut off.
func (v *Vault) Rotate(slots []NewSlot, keepRecipients bool, drop func(SlotInfo) bool) ([]SlotInfo, error) {
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
	rec := svformat.EpochRecord{Format: svformat.EpochFormat, Vault: v.desc.ID, N: n, Created: v.opts.Now().UTC(),
		Check: svformat.CheckValue(v.desc.ID, master), Prev: sealed}
	b, err := jsonIndent(rec)
	if err != nil {
		return nil, err
	}
	if err := v.store.Create(svformat.EpochName(n), b); err != nil {
		for _, done := range infos {
			v.store.Remove(svformat.SlotName(done.ID))
		}
		if errors.Is(err, svstore.ErrExist) {
			return nil, ErrRotating
		}
		return nil, err
	}
	v.epochs = append(v.epochs, svformat.Epoch{N: n, Check: rec.Check})
	v.prev[n] = sealed
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

	// 4. Everything current, again under the new key.
	for id, o := range v.idx.objects {
		if len(o.heads) == 0 || o.heads[0].deleted || o.heads[0].hdr.Epoch == n {
			continue
		}
		h := o.heads[0]
		p := payload{Type: h.kind}
		switch {
		case h.kind == payloadItem && h.item != nil:
			it := h.item.clone()
			p.Item = &it
		case h.record != nil:
			p.Record = append([]byte(nil), h.record...)
		default:
			continue
		}
		if _, err := v.write(id, o.heads, p); err != nil {
			return infos, fmt.Errorf("svcore: the key was rotated, but not everything was re-encrypted yet: %w", err)
		}
	}
	return infos, nil
}

func jsonIndent(v any) ([]byte, error) {
	b, err := json.MarshalIndent(v, "", "  ")
	return append(b, '\n'), err
}
