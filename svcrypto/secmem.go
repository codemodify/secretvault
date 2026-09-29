package svcrypto

import "sync"

// A Secret is key material kept out of the Go heap where the operating
// system allows it: in its own mapping, locked into RAM so it is never
// written to swap, and (on Linux) excluded from core dumps. Destroy zeroes
// it and gives the memory back.
//
// This is hygiene, not a boundary. A process that can read our memory can
// read the key while it is in use; what a Secret prevents is the key
// outliving its use in swap, dumps and freed heap pages.
type Secret struct {
	mu     sync.Mutex
	b      []byte
	region []byte // the whole mapping, when b lives in one
	locked bool
}

// NewSecret allocates n zero bytes of protected memory. It never fails:
// where locking is refused (a low RLIMIT_MEMLOCK, say) the bytes are still
// separately mapped and zeroed on Destroy, and Locked reports false.
func NewSecret(n int) *Secret {
	s := &Secret{}
	if region, locked, ok := allocProtected(n); ok {
		s.region, s.locked = region, locked
		s.b = region[:n:n]
	} else {
		s.b = make([]byte, n)
	}
	return s
}

// SecretFrom copies b into a new Secret and zeroes b.
func SecretFrom(b []byte) *Secret {
	s := NewSecret(len(b))
	copy(s.b, b)
	clear(b)
	return s
}

// Bytes is the protected memory itself. It is valid until Destroy; do not
// keep it or copies of it beyond that.
func (s *Secret) Bytes() []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b
}

// Locked reports whether the memory is locked against swapping.
func (s *Secret) Locked() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.locked
}

// Destroy zeroes the secret and releases its memory. It is safe to call
// more than once and on a nil Secret.
func (s *Secret) Destroy() {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	clear(s.b)
	if s.region != nil {
		clear(s.region)
		freeProtected(s.region, s.locked)
	}
	s.b, s.region, s.locked = nil, nil, false
}

// HardenProcess makes the running process a worse place to find keys: no
// core dumps, and on Linux not dumpable at all, which also stops other
// processes of the same user attaching a debugger where Yama allows it.
// secretvaultd, which holds unlocked vaults, calls it first thing.
//
// A non-dumpable process cannot be identified by others (its /proc entry
// becomes root's), so clients of the daemon, which must be identifiable,
// call NoCoreDumps instead.
func HardenProcess() error { return hardenProcess() }

// NoCoreDumps stops the running process from ever writing a core file.
func NoCoreDumps() error { return noCoreDumps() }
