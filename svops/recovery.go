package svops

import (
	"errors"
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
)

// Recovery keys split into shares (any k of n open the vault, fewer
// reveal nothing), and put back together from them.

// SplitThreshold checks a split of n shares needing k, k 0 meaning a
// majority, and returns the k to use.
func SplitThreshold(n, k int) (int, error) {
	if k == 0 {
		k = n/2 + 1
	}
	if n < 2 || n > 255 || k < 2 || k > n {
		return 0, fmt.Errorf("%d of %d shares: use 2 to 255 shares, and a threshold from 2 up to the number of shares", k, n)
	}
	return k, nil
}

// SplitLabel is the label a recovery keyslot split into shares gets when
// none is given.
func SplitLabel(n, k int) string { return fmt.Sprintf("recovery key, %d of %d shares", k, n) }

// SplitRecoveryKey splits a new recovery key (its text, as the daemon
// returns it) into n shares needing k, each as the text to hand out. The
// whole key is never to be shown when it is split.
func SplitRecoveryKey(text string, n, k int) ([]string, error) {
	rk, err := svformat.ParseRecoveryKey(text)
	if err != nil {
		return nil, err
	}
	shares, err := svcrypto.SplitSecret(rk, n, k)
	clear(rk)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(shares))
	for i, s := range shares {
		out[i] = svformat.EncodeRecoveryShare(s, k)
		clear(s)
	}
	return out, nil
}

// ShareCollector gathers recovery shares as they are typed, until there
// are as many as the first one says it takes. A share typed twice, or
// from another split, is caught by Add, or by the key's own checksum in
// Key.
type ShareCollector struct {
	shares [][]byte
	need   int
}

// Need is how many shares it takes: 0 until the first is added.
func (s *ShareCollector) Need() int { return s.need }

// Have is how many have been added.
func (s *ShareCollector) Have() int { return len(s.shares) }

// Done reports whether there are enough.
func (s *ShareCollector) Done() bool { return s.need > 0 && len(s.shares) >= s.need }

// Add reads one share's text; an error says, in words, why it was not
// taken, and the collector is as it was.
func (s *ShareCollector) Add(text []byte) error {
	share, k, err := svformat.ParseRecoveryShare(string(text))
	if err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "svformat: "))
	}
	if s.need != 0 && k != s.need {
		clear(share)
		return fmt.Errorf("That share is from a split that needs %d, not %d: it belongs to another recovery key.", k, s.need)
	}
	s.need = k
	s.shares = append(s.shares, share)
	return nil
}

// Key is the recovery key the shares rebuild, as text. The caller clears
// it.
func (s *ShareCollector) Key() ([]byte, error) {
	rk, err := svcrypto.CombineShares(s.shares)
	if err != nil {
		return nil, fmt.Errorf("those shares do not fit together: %w", err)
	}
	defer clear(rk)
	return []byte(svformat.EncodeRecoveryKey(rk)), nil
}

// Wipe clears the shares.
func (s *ShareCollector) Wipe() {
	for _, sh := range s.shares {
		clear(sh)
	}
	s.shares = nil
}
