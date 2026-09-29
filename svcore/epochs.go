package svcore

import (
	"errors"
	"fmt"
	"sort"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// ErrRotated is a vault whose master key was rotated elsewhere since this
// handle unlocked it: it has been locked, and opens again with a key from
// the new epoch.
var ErrRotated = errors.New("svcore: the vault key was rotated on another device; unlock it again")

// loadEpochs reads epoch 1 from the descriptor and every later epoch from
// its record. Records must run 2, 3, ... without a gap.
func (v *Vault) loadEpochs() error {
	names, err := v.store.List(svformat.EpochsDir)
	if err != nil {
		return err
	}
	var recs []*svformat.EpochRecord
	for _, n := range names {
		b, err := v.store.Read(n)
		if err != nil {
			if errors.Is(err, svstore.ErrNotExist) {
				continue
			}
			return err
		}
		r, err := svformat.ParseEpoch(b)
		if err != nil {
			return err
		}
		if r.Vault != v.desc.ID || n != svformat.EpochName(r.N) {
			return fmt.Errorf("%w: %s does not belong here", svformat.ErrEpoch, n)
		}
		recs = append(recs, r)
	}
	sort.Slice(recs, func(i, j int) bool { return recs[i].N < recs[j].N })
	epochs := []svformat.Epoch{v.desc.Epochs[0]}
	prev := map[uint32][]byte{}
	for i, r := range recs {
		if r.N != uint32(i+2) {
			return fmt.Errorf("%w: epoch %d is missing", svformat.ErrEpoch, i+2)
		}
		epochs = append(epochs, svformat.Epoch{N: r.N, Check: r.Check})
		prev[r.N] = r.Prev
	}
	v.epochs, v.prev = epochs, prev
	return nil
}
