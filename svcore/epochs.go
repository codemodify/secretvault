package svcore

import (
	"crypto/subtle"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// Epochs, as svcore trusts them.
//
// Epoch 1 is in the descriptor; every later one has a record of its own
// (svformat.EpochRecord), which anyone who can write to the vault's folder
// could plant. So a record counts only once it is authenticated under the
// previous epoch's key, which only someone who could open the vault holds:
//
//   - Unlocking tries the key's slots from the newest epoch down, and walks
//     the chain down from the one that opens, checking every record on the
//     way. When the key opens only an older epoch, the record after it
//     decides: made with that epoch's key, it is a real rotation that left
//     the key out (ErrKeyRemoved); otherwise it is planted, and ignored
//     with everything after it.
//   - An open vault that finds a record for the next epoch (Refresh) locks
//     itself only if the record was made with its current key (ErrRotated);
//     a planted one is reported and ignored.
//
// And after a rotation, the only revisions of earlier epochs that count
// are those its record lists (loadRevision): someone cut off still holds
// the old key, and must not be able to add to the vault with it.

// ErrRotated is a vault whose master key was rotated elsewhere since this
// handle unlocked it: it has been locked, and opens again with a key from
// the new epoch.
var ErrRotated = errors.New("svcore: the vault key was rotated on another device; unlock it again")

// ErrKeyRemoved is a key that opens only an earlier epoch of the vault:
// it was left out when the vault key was rotated, which is how people and
// devices are cut off.
var ErrKeyRemoved = errors.New("svcore: this key no longer opens the vault: it was left out when the vault key was rotated")

// ErrLateRevision is a revision sealed under an epoch's key after the
// next epoch began: written by someone the rotation cut off, or by a
// device that had not heard of the rotation yet. It is ignored.
var ErrLateRevision = errors.New("svcore: sealed with a key that had already been replaced (by someone cut off, or a device that had not heard of the rotation); ignored")

// errPlanted is an epoch record not made by anyone who could open the
// vault.
var errPlanted = fmt.Errorf("%w: not made by anyone who could open the vault; ignored", svformat.ErrEpoch)

// readEpochs reads the epoch records that make an unbroken chain 2, 3, ...
// after the descriptor's epoch 1. A record that does not parse, belongs to
// another vault or follows a gap is a problem, never an error: anyone who
// can write to the folder could put it there, and it must not stop the
// vault opening.
func (v *Vault) readEpochs() (map[uint32]*svformat.EpochRecord, []Problem, error) {
	names, err := v.store.List(svformat.EpochsDir)
	if err != nil {
		return nil, nil, err
	}
	all := map[uint32]*svformat.EpochRecord{}
	var problems []Problem
	for _, n := range names {
		b, err := v.store.Read(n)
		if err != nil {
			if errors.Is(err, svstore.ErrNotExist) {
				continue
			}
			return nil, nil, err
		}
		r, err := svformat.ParseEpoch(b)
		switch {
		case err != nil:
			problems = append(problems, Problem{n, err})
		case r.Vault != v.desc.ID || n != svformat.EpochName(r.N):
			problems = append(problems, Problem{n, fmt.Errorf("%w: it does not belong here", svformat.ErrEpoch)})
		default:
			all[r.N] = r
		}
	}
	chain := map[uint32]*svformat.EpochRecord{}
	for n := uint32(2); all[n] != nil; n++ {
		chain[n] = all[n]
	}
	for _, n := range slices.Sorted(maps.Keys(all)) {
		if chain[n] == nil {
			problems = append(problems, Problem{svformat.EpochName(n), fmt.Errorf("%w: epoch %d follows a missing one", svformat.ErrEpoch, n)})
		}
	}
	return chain, problems, nil
}

// loadEpochs reads the records afresh, for an unlock: which of them count
// is settled by the key (openChain, install). The caller holds v.mu.
func (v *Vault) loadEpochs() error {
	recs, problems, err := v.readEpochs()
	if err != nil {
		return err
	}
	epochs := []svformat.Epoch{v.desc.Epochs[0]}
	for n := uint32(2); recs[n] != nil; n++ {
		epochs = append(epochs, svformat.Epoch{N: n, Check: recs[n].Check})
	}
	v.epochs, v.epochRecs, v.epochProblems = epochs, recs, problems
	return nil
}

// opened is what a key opened: every epoch's master key from the highest
// it reaches down to 1.
type opened struct {
	masters map[uint32][]byte
	epoch   uint32
	slot    svformat.ID
}

func clearAll(m map[uint32][]byte) {
	for _, b := range m {
		clear(b)
	}
}

// openChain finds the highest epoch k opens, through a keyslot of k's
// type, and recovers every earlier epoch's key from the chain.
func (v *Vault) openChain(k Key) (*opened, error) {
	slots, err := v.slots()
	if err != nil {
		return nil, err
	}
	v.mu.Lock()
	epochs, records := v.epochs, v.epochRecs
	v.mu.Unlock()
	newest := uint32(len(epochs))
	if p, ok := k.(slotPicker); ok {
		return v.openPicked(p, k.slotType(), slots, epochs, records)
	}
	removed := false
	for e := newest; e >= 1; e-- {
		for _, s := range slots {
			if s.Type != k.slotType() || s.Epoch != e {
				continue
			}
			master, err := k.open(v, s)
			if err != nil {
				continue
			}
			if subtle.ConstantTimeCompare(svformat.CheckValue(v.desc.ID, master), epochs[e-1].Check) != 1 {
				// The slot opened, but to some other key: planted or from
				// another vault. Keep looking.
				clear(master)
				continue
			}
			masters, ok := v.verifyChain(epochs, records, master, e)
			if !ok {
				continue
			}
			if e < newest && svformat.CheckEpochAuth(masters[e], records[e+1]) {
				// A real rotation, which this key was left out of.
				clearAll(masters)
				removed = true
				continue
			}
			return &opened{masters: masters, epoch: e, slot: s.ID}, nil
		}
	}
	if removed {
		return nil, ErrKeyRemoved
	}
	return nil, ErrWrongKey
}

// openPicked is openChain for a key that answers for one of several
// slots at once (a security key: asked once, whichever slot it holds).
// It is offered every slot of its type, newest epoch first, and the slot
// it opens goes through the same checks as any other.
func (v *Vault) openPicked(p slotPicker, typ string, slots []*svformat.Slot, epochs []svformat.Epoch, records map[uint32]*svformat.EpochRecord) (*opened, error) {
	newest := uint32(len(epochs))
	var mine []*svformat.Slot
	for e := newest; e >= 1; e-- {
		for _, s := range slots {
			if s.Type == typ && s.Epoch == e {
				mine = append(mine, s)
			}
		}
	}
	if len(mine) == 0 {
		return nil, fmt.Errorf("%w: the vault has no %s keyslot", ErrWrongKey, typ)
	}
	s, master, err := p.pick(v, mine)
	if err != nil {
		return nil, err
	}
	e := s.Epoch
	if subtle.ConstantTimeCompare(svformat.CheckValue(v.desc.ID, master), epochs[e-1].Check) != 1 {
		clear(master)
		return nil, ErrWrongKey
	}
	masters, ok := v.verifyChain(epochs, records, master, e)
	if !ok {
		return nil, ErrWrongKey
	}
	if e < newest && svformat.CheckEpochAuth(masters[e], records[e+1]) {
		clearAll(masters)
		return nil, ErrKeyRemoved
	}
	return &opened{masters: masters, epoch: e, slot: s.ID}, nil
}

// verifyChain recovers the keys of epochs e-1 down to 1 from epoch e's,
// checking each record on the way: its sealed key must open, match the
// check value, and have made the record. It takes master, and on failure
// clears everything.
func (v *Vault) verifyChain(epochs []svformat.Epoch, records map[uint32]*svformat.EpochRecord, master []byte, e uint32) (map[uint32][]byte, bool) {
	masters := map[uint32][]byte{e: master}
	cur := master
	for n := e; n >= 2; n-- {
		rec := records[n]
		prevKey := svcrypto.Derive(cur, v.desc.ID[:], svformat.EpochPrevKeyLabel, svcrypto.KeySize)
		older, err := v.suite.Open(prevKey, rec.Prev, svformat.EpochPrevAAD(v.desc.ID, n))
		clear(prevKey)
		if err != nil || subtle.ConstantTimeCompare(svformat.CheckValue(v.desc.ID, older), epochs[n-2].Check) != 1 || !svformat.CheckEpochAuth(older, rec) {
			clear(older)
			clearAll(masters)
			return nil, false
		}
		masters[n-1] = older
		cur = older
	}
	return masters, true
}

// install makes o the vault's keys, the epoch it opened the current one,
// and forgets any record past it (planted: openChain returns an older
// epoch only then). It takes o's keys. The caller holds v.mu.
func (v *Vault) install(o *opened) {
	v.dropKeys()
	if o.epoch < v.epoch() {
		v.epochs = slices.Clone(v.epochs[:o.epoch])
		recs := map[uint32]*svformat.EpochRecord{}
		for n := uint32(2); n <= o.epoch; n++ {
			recs[n] = v.epochRecs[n]
		}
		v.epochRecs = recs
	}
	v.masters = map[uint32]*svcrypto.Secret{}
	v.wraps = map[uint32]*svcrypto.Secret{}
	for n, m := range o.masters {
		v.wraps[n] = svcrypto.SecretFrom(svcrypto.Derive(m, v.desc.ID[:], "sv1 wrap", svcrypto.KeySize))
		v.masters[n] = svcrypto.SecretFrom(m)
	}
	v.unlockedBy = o.slot
	v.idx = newIndex()
}

// checkRotation looks for a rotation made elsewhere: a record for the next
// epoch, made with the current key, means that key is no longer current,
// and the vault locks itself. Records nobody with the key made are
// reported and ignored. The caller holds v.mu, with the vault open.
func (v *Vault) checkRotation() error {
	recs, problems, err := v.readEpochs()
	if err != nil {
		return err
	}
	cur := v.epoch()
	if next := recs[cur+1]; next != nil {
		if svformat.CheckEpochAuth(v.masters[cur].Bytes(), next) {
			v.dropKeys()
			return ErrRotated
		}
		for n := cur + 1; recs[n] != nil; n++ {
			problems = append(problems, Problem{svformat.EpochName(n), errPlanted})
		}
	}
	v.epochProblems = problems
	return nil
}

// committed reports whether a revision of an earlier epoch counts: it
// must have existed when the next epoch began.
func (v *Vault) committed(epoch uint32, rev svformat.RevID) bool {
	if epoch >= v.epoch() {
		return true
	}
	rec := v.epochRecs[epoch+1]
	return rec != nil && rec.HasRevision(rev)
}
