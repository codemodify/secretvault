package svdeliver

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
)

// The seal. Everything of the delivery server's own that is secret is
// sealed, on disk, under one root key, which is itself on disk only
// sealed under other keys:
//
//	root key R      32 random bytes, made once at init; never changes
//	unseal key U    32 random bytes; R is sealed under a key derived from it.
//	                It is split into n Shamir shares, any k of which rebuild
//	                it, and exists whole only in memory, for a moment, when
//	                the shares are combined.
//	credential C    optional: 32 random bytes that R is also sealed under,
//	                for unattended start. It is given to systemd-creds to seal
//	                to the machine's TPM, and read at start from
//	                $CREDENTIALS_DIRECTORY.
//
// Under keys derived from R: the server's identities (one per cipher
// suite; delivery vaults give them recipient keyslots), the policy
// (vaults, issuers, client CA, roles, tokens and the admin token's hash)
// and the audit log's key pair, whose public half is kept in the clear
// so the log can be written while the server is sealed.
//
// Rekeying makes a new U (and new shares), and a new C if asked, and
// seals R under them; R, and everything under it, stays as it was.

// Files in the delivery directory.
const (
	SealFile   = "seal.json"
	PolicyFile = "policy.sealed"
	ConfigFile = "config.json"
	AuditFile  = "audit.log"
)

const sealFormat = "secretvault-deliver/v1/seal"

// sealFile is seal.json.
type sealFile struct {
	Format  string    `json:"format"`
	ID      []byte    `json:"id"` // 16 random bytes that scope every key derived here
	Suite   string    `json:"suite"`
	Created time.Time `json:"created"`
	Rekeyed time.Time `json:"rekeyed,omitzero"`

	// The unseal key's split.
	Shares    int `json:"shares"`
	Threshold int `json:"threshold"`

	// Unseal and Credential are R sealed under U and C.
	Unseal     []byte `json:"unseal"`
	Credential []byte `json:"credential,omitempty"`

	// Identities are the server's private keys, sealed under R.
	Identities []byte `json:"identities"`

	// AuditKey is the public key audit entries are sealed to.
	AuditKey []byte `json:"audit_key"`
}

// Key slots for the root key.
const (
	slotUnseal     = "unseal"
	slotCredential = "credential"
)

func (f *sealFile) suite() svcrypto.Suite {
	s, err := svcrypto.ParseSuite(f.Suite)
	if err != nil {
		return 0
	}
	return s
}

func (f *sealFile) aad(what string) []byte {
	return []byte("secretvault deliver " + what + " " + hex.EncodeToString(f.ID))
}

// sealRoot seals R under a slot's key.
func (f *sealFile) sealRoot(root, key []byte, slot string) ([]byte, error) {
	kek := svcrypto.Derive(key, f.ID, "deliver "+slot+" kek", svcrypto.KeySize)
	defer clear(kek)
	return f.suite().Seal(kek, root, f.aad(slot))
}

// openRoot opens R with a slot's key.
func (f *sealFile) openRoot(key []byte, slot string) (*svcrypto.Secret, error) {
	sealed := f.Unseal
	if slot == slotCredential {
		sealed = f.Credential
	}
	if len(sealed) == 0 {
		return nil, errors.New("there is no credential slot")
	}
	kek := svcrypto.Derive(key, f.ID, "deliver "+slot+" kek", svcrypto.KeySize)
	defer clear(kek)
	root, err := f.suite().Open(kek, sealed, f.aad(slot))
	if err != nil {
		return nil, err
	}
	if len(root) != svcrypto.KeySize {
		clear(root)
		return nil, svcrypto.ErrOpen
	}
	return svcrypto.SecretFrom(root), nil
}

// derived is a key for one purpose, derived from R.
func (f *sealFile) derived(root *svcrypto.Secret, purpose string) []byte {
	return svcrypto.Derive(root.Bytes(), f.ID, "deliver "+purpose, svcrypto.KeySize)
}

func (f *sealFile) seal(root *svcrypto.Secret, purpose string, plain []byte) ([]byte, error) {
	k := f.derived(root, purpose)
	defer clear(k)
	return f.suite().Seal(k, plain, f.aad(purpose))
}

func (f *sealFile) open(root *svcrypto.Secret, purpose string, sealed []byte) ([]byte, error) {
	k := f.derived(root, purpose)
	defer clear(k)
	return f.suite().Open(k, sealed, f.aad(purpose))
}

// auditKey is the audit log's key pair.
func (f *sealFile) auditKey(root *svcrypto.Secret) (*svcrypto.Identity, error) {
	seed := f.derived(root, "audit log")
	defer clear(seed)
	return f.suite().DeriveLogKey(seed)
}

// identities opens the server's identities.
func (f *sealFile) identities(root *svcrypto.Secret) (map[svcrypto.Suite]*svcrypto.Identity, error) {
	plain, err := f.open(root, "identities", f.Identities)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	var texts map[string]string
	if err := json.Unmarshal(plain, &texts); err != nil {
		return nil, err
	}
	out := map[svcrypto.Suite]*svcrypto.Identity{}
	for _, t := range texts {
		suite, priv, err := svformat.ParseIdentity(t)
		if err != nil {
			return nil, err
		}
		id, err := suite.ParseIdentity(priv)
		clear(priv)
		if err != nil {
			return nil, err
		}
		out[suite] = id
	}
	return out, nil
}

func readSeal(dir string) (*sealFile, error) {
	b, err := os.ReadFile(filepath.Join(dir, SealFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s has no delivery server in it: run 'secretvault-server init' first", dir)
	}
	if err != nil {
		return nil, err
	}
	var f sealFile
	if err := json.Unmarshal(b, &f); err != nil || f.Format != sealFormat {
		return nil, fmt.Errorf("%s is not a delivery server's seal file", filepath.Join(dir, SealFile))
	}
	if f.suite() == 0 || len(f.ID) != 16 || f.Threshold < 2 || f.Shares < f.Threshold || len(f.Unseal) == 0 {
		return nil, fmt.Errorf("%s is damaged", filepath.Join(dir, SealFile))
	}
	return &f, nil
}

func writeSeal(dir string, f *sealFile) error {
	b, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, SealFile), append(b, '\n'))
}

// InitOptions configure Init.
type InitOptions struct {
	// Shares and Threshold split the unseal key: any Threshold of Shares
	// shares unseal the server. Zero means 5 and 3.
	Shares, Threshold int

	// Credential also makes a credential key for unattended start.
	Credential bool

	// Suite is the cipher suite of the server's own seals. Zero means
	// svcrypto.Modern.
	Suite svcrypto.Suite

	// Now is the clock. Defaults to time.Now.
	Now func() time.Time
}

// InitResult is what Init made that exists nowhere else. Show it to the
// operators once, then forget it.
type InitResult struct {
	Shares     []string // SVUS1-...: one for each operator
	Threshold  int
	Credential string // SVUK1-...: for systemd-creds, when asked for
	AdminToken string

	// Recipients are the server's identities' public halves, by suite:
	// what a vault's owner shares the vault with.
	Recipients map[string]string
}

// Init makes a new, sealed delivery server in dir: its root and unseal
// keys, its identities, an empty policy with an admin token, and a config
// skeleton (config.json, left alone if there is one).
func Init(dir string, o InitOptions) (*InitResult, error) {
	if o.Shares == 0 && o.Threshold == 0 {
		o.Shares, o.Threshold = 5, 3
	}
	if o.Threshold < 2 || o.Shares < o.Threshold || o.Shares > 255 {
		return nil, fmt.Errorf("cannot split into %d shares with threshold %d (need 2 <= threshold <= shares <= 255)", o.Shares, o.Threshold)
	}
	if o.Suite == 0 {
		o.Suite = svcrypto.Modern
	}
	if !o.Suite.Valid() {
		return nil, svcrypto.ErrSuite
	}
	if o.Now == nil {
		o.Now = time.Now
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, SealFile)); err == nil {
		return nil, fmt.Errorf("%s already has a delivery server in it", dir)
	}
	f := &sealFile{
		Format:    sealFormat,
		ID:        svcrypto.RandomBytes(16),
		Suite:     o.Suite.String(),
		Created:   o.Now().UTC(),
		Shares:    o.Shares,
		Threshold: o.Threshold,
	}
	root := svcrypto.SecretFrom(svcrypto.RandomKey())
	defer root.Destroy()
	res := &InitResult{Threshold: o.Threshold, Recipients: map[string]string{}}

	// The identities.
	texts := map[string]string{}
	for _, s := range []svcrypto.Suite{svcrypto.Modern, svcrypto.NIST} {
		id, err := s.NewIdentity()
		if err != nil {
			return nil, err
		}
		priv, err := id.Bytes()
		if err != nil {
			return nil, err
		}
		texts[s.String()] = svformat.EncodeIdentity(s, priv)
		clear(priv)
		res.Recipients[s.String()] = svformat.EncodeRecipient(s, id.Recipient())
	}
	plain, err := json.Marshal(texts)
	if err != nil {
		return nil, err
	}
	f.Identities, err = f.seal(root, "identities", plain)
	clear(plain)
	if err != nil {
		return nil, err
	}
	logKey, err := f.auditKey(root)
	if err != nil {
		return nil, err
	}
	f.AuditKey = logKey.Recipient()

	// The keys R is sealed under.
	shares, err := f.rekey(root, o.Shares, o.Threshold)
	if err != nil {
		return nil, err
	}
	res.Shares = shares
	if o.Credential {
		if res.Credential, err = f.newCredential(root); err != nil {
			return nil, err
		}
	}

	// The policy, with the admin token.
	admin := newSecretToken(adminPrefix)
	res.AdminToken = admin
	p := &policy{AdminHash: tokenHash(admin)}
	if err := savePolicy(dir, f, root, p); err != nil {
		return nil, err
	}
	if _, err := os.Stat(filepath.Join(dir, ConfigFile)); errors.Is(err, fs.ErrNotExist) {
		if err := writeAtomic(filepath.Join(dir, ConfigFile), configSkeleton()); err != nil {
			return nil, err
		}
	}
	// The seal file goes last: its presence is what says the server
	// exists, so a crash before here leaves a directory init can use again.
	if err := writeSeal(dir, f); err != nil {
		return nil, err
	}
	return res, nil
}

// rekey makes a new unseal key, seals R under it, and returns its shares
// as text. The unseal key itself is forgotten.
func (f *sealFile) rekey(root *svcrypto.Secret, n, k int) ([]string, error) {
	u := svcrypto.RandomKey()
	defer clear(u)
	sealed, err := f.sealRoot(root.Bytes(), u, slotUnseal)
	if err != nil {
		return nil, err
	}
	parts, err := svcrypto.SplitSecret(u, n, k)
	if err != nil {
		return nil, err
	}
	out := make([]string, len(parts))
	for i, p := range parts {
		out[i] = svformat.EncodeUnsealShare(p, k)
		clear(p)
	}
	f.Unseal, f.Shares, f.Threshold = sealed, n, k
	return out, nil
}

// newCredential makes a new credential key, seals R under it (replacing
// any credential slot there was), and returns it as text.
func (f *sealFile) newCredential(root *svcrypto.Secret) (string, error) {
	c := svcrypto.RandomKey()
	defer clear(c)
	sealed, err := f.sealRoot(root.Bytes(), c, slotCredential)
	if err != nil {
		return "", err
	}
	f.Credential = sealed
	return svformat.EncodeUnsealKey(c), nil
}

// shareProgress holds the shares given so far towards unsealing (or
// rekeying), in memory only, until there are enough or they time out.
type shareProgress struct {
	threshold int
	shares    []*svcrypto.Secret
	started   time.Time
}

// errShare is a share refused without counting it.
type errShare string

func (e errShare) Error() string { return string(e) }

func (p *shareProgress) count() int { return len(p.shares) }

// expires is when the shares given so far are forgotten.
func (p *shareProgress) expires(timeout time.Duration) time.Time {
	return p.started.Add(timeout)
}

func (p *shareProgress) reset() {
	for _, s := range p.shares {
		s.Destroy()
	}
	p.shares, p.started = nil, time.Time{}
}

// add takes one share, as typed. It returns true once there are enough to
// combine. Shares older than timeout are forgotten first.
func (p *shareProgress) add(text string, threshold int, now time.Time, timeout time.Duration) (bool, error) {
	if len(p.shares) > 0 && now.Sub(p.started) > timeout {
		p.reset()
	}
	share, k, err := svformat.ParseUnsealShare(text)
	if err != nil {
		return false, errShare(strings.TrimPrefix(err.Error(), "svformat: "))
	}
	s := svcrypto.SecretFrom(share)
	if k != threshold {
		s.Destroy()
		return false, errShare(fmt.Sprintf("that share is from a split that needs %d shares, not this server's %d: it belongs to an older split, or to another server", k, threshold))
	}
	for _, have := range p.shares {
		if have.Bytes()[0] == s.Bytes()[0] {
			s.Destroy()
			return false, errShare("that share was given already")
		}
	}
	if len(p.shares) == 0 {
		p.started = now
	}
	p.threshold = threshold
	p.shares = append(p.shares, s)
	return len(p.shares) >= threshold, nil
}

// combine rebuilds the key from the shares given, and forgets them.
func (p *shareProgress) combine() ([]byte, error) {
	defer p.reset()
	parts := make([][]byte, len(p.shares))
	for i, s := range p.shares {
		parts[i] = s.Bytes()
	}
	return svcrypto.CombineShares(parts)
}

// writeAtomic writes a file (0600) through a synced temporary file and a
// rename, so it is whole or not there.
func writeAtomic(path string, data []byte) error {
	tmp := path + ".new"
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp, path)
	}
	if err != nil {
		os.Remove(tmp)
		return err
	}
	if d, err := os.Open(filepath.Dir(path)); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
