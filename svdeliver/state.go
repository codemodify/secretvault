package svdeliver

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
)

// policy is everything that decides who gets in: the delivery vaults,
// the issuers, the client CA, the roles, the tokens and the admin token's
// hash. It is kept sealed under the root key (policy.sealed), so that
// whoever can write to the delivery directory cannot grant themselves
// anything, and whoever can read it learns nothing. It can therefore
// only be read or changed while the server is unsealed.
type policy struct {
	AdminHash string                  `json:"admin_hash"`
	Vaults    map[string]*VaultConfig `json:"vaults,omitempty"`
	Issuers   map[string]*Issuer      `json:"issuers,omitempty"`
	ClientCA  string                  `json:"client_ca,omitempty"`
	Roles     map[string]*Role        `json:"roles,omitempty"`
	Tokens    map[string]*tokenRecord `json:"tokens,omitempty"`
}

// VaultConfig is a delivery vault: a vault folder the server holds open.
type VaultConfig struct {
	Name string `json:"name"`
	Path string `json:"path"`

	// ID pins the vault found at Path when it was added, so that another
	// vault put in its place (which could give the server's identity a
	// keyslot as easily as the real one) is refused.
	ID    string    `json:"id"`
	Added time.Time `json:"added"`
}

// tokenRecord is a token as kept: its hash, never the token.
type tokenRecord struct {
	Name    string    `json:"name"`
	Hash    string    `json:"hash"` // hex SHA-256 of the token
	Created time.Time `json:"created"`
	Expires time.Time `json:"expires,omitzero"`
	CIDRs   []string  `json:"cidrs,omitempty"`
}

func (p *policy) clone() *policy {
	b, err := json.Marshal(p)
	if err != nil {
		panic(err) // a policy is plain data
	}
	var out policy
	if err := json.Unmarshal(b, &out); err != nil {
		panic(err)
	}
	return &out
}

// check validates the whole policy, as it will be saved.
func (p *policy) check() error {
	for name, iss := range p.Issuers {
		if iss.Name != name {
			return fmt.Errorf("issuer %s is filed under %s", iss.Name, name)
		}
		if err := iss.check(); err != nil {
			return err
		}
	}
	for name, r := range p.Roles {
		if r.Name != name {
			return fmt.Errorf("role %s is filed under %s", r.Name, name)
		}
		if err := r.check(p.Issuers); err != nil {
			return err
		}
	}
	for _, t := range p.Tokens {
		for _, c := range t.CIDRs {
			if _, err := netip.ParsePrefix(c); err != nil {
				return fmt.Errorf("token %s: %q is not a CIDR", t.Name, c)
			}
		}
	}
	if p.ClientCA != "" {
		if _, err := parseCA(p.ClientCA); err != nil {
			return err
		}
	}
	return nil
}

func loadPolicy(dir string, f *sealFile, root *svcrypto.Secret) (*policy, error) {
	b, err := os.ReadFile(filepath.Join(dir, PolicyFile))
	if err != nil {
		return nil, err
	}
	plain, err := f.open(root, "policy", b)
	if err != nil {
		return nil, fmt.Errorf("%s does not open with this server's key: it was altered, or belongs to another server", PolicyFile)
	}
	defer clear(plain)
	var p policy
	if err := json.Unmarshal(plain, &p); err != nil {
		return nil, fmt.Errorf("%s: %v", PolicyFile, err)
	}
	return &p, nil
}

func savePolicy(dir string, f *sealFile, root *svcrypto.Secret, p *policy) error {
	plain, err := json.Marshal(p)
	if err != nil {
		return err
	}
	defer clear(plain)
	sealed, err := f.seal(root, "policy", plain)
	if err != nil {
		return err
	}
	return writeAtomic(filepath.Join(dir, PolicyFile), sealed)
}

// Tokens are 32 random bytes in unpadded base64url, after a prefix that
// says what they are.
const (
	tokenPrefix   = "svdt_" // a token an admin made
	sessionPrefix = "svds_" // a session, from a login
	adminPrefix   = "svda_" // the admin token
)

func newSecretToken(prefix string) string {
	return prefix + b64url.EncodeToString(svcrypto.RandomBytes(32))
}

// tokenHash is how a token is kept and looked up. A token is 256 random
// bits, so a plain hash is enough: there is nothing to guess.
func tokenHash(t string) string {
	s := sha256.Sum256([]byte(t))
	return hex.EncodeToString(s[:])
}

// fromAllowed reports whether a token may be used from ip.
func (t *tokenRecord) fromAllowed(ip string) bool {
	if len(t.CIDRs) == 0 {
		return true
	}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, c := range t.CIDRs {
		if p, err := netip.ParsePrefix(c); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

// settings are config.json: how the server behaves, never who gets in
// (that is the sealed policy). It is read when the server starts.
type settings struct {
	// SessionTTL is how long a session from an OIDC login lasts unless
	// its role says otherwise. Default 15m.
	SessionTTL string `json:"session_ttl,omitempty"`

	// UnsealTimeout is how long shares given towards unsealing (or
	// rekeying) are kept before they must be given again. Default 10m.
	UnsealTimeout string `json:"unseal_timeout,omitempty"`

	// UnsealCredential names the systemd credential that holds the
	// credential key, in $CREDENTIALS_DIRECTORY. Default
	// "secretvault-unseal".
	UnsealCredential string `json:"unseal_credential,omitempty"`

	// Rate is how many requests a second each IP address may make, in
	// bursts of ten seconds' worth. Zero means 20; below zero, no limit.
	Rate float64 `json:"rate,omitempty"`

	sessionTTL, unsealTimeout time.Duration
}

// DefaultCredential is the systemd credential's default name.
const DefaultCredential = "secretvault-unseal"

func configSkeleton() []byte {
	s := settings{SessionTTL: "15m", UnsealTimeout: "10m", UnsealCredential: DefaultCredential, Rate: 20}
	b, _ := json.MarshalIndent(s, "", "  ")
	return append(b, '\n')
}

func readSettings(dir string) (*settings, error) {
	s := &settings{}
	b, err := os.ReadFile(filepath.Join(dir, ConfigFile))
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return nil, err
	default:
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err := d.Decode(s); err != nil {
			return nil, fmt.Errorf("%s: %v", filepath.Join(dir, ConfigFile), err)
		}
	}
	s.sessionTTL, s.unsealTimeout = 15*time.Minute, 10*time.Minute
	for _, d := range []struct {
		text string
		out  *time.Duration
		max  time.Duration
		name string
	}{{s.SessionTTL, &s.sessionTTL, MaxSessionTTL, "session_ttl"}, {s.UnsealTimeout, &s.unsealTimeout, 24 * time.Hour, "unseal_timeout"}} {
		if d.text == "" {
			continue
		}
		v, err := time.ParseDuration(d.text)
		if err != nil || v < time.Minute || v > d.max {
			return nil, fmt.Errorf("%s: %s %q is not a duration between 1m and %v", ConfigFile, d.name, d.text, d.max)
		}
		*d.out = v
	}
	if s.UnsealCredential == "" {
		s.UnsealCredential = DefaultCredential
	}
	if filepath.Base(s.UnsealCredential) != s.UnsealCredential || s.UnsealCredential == "." || s.UnsealCredential == ".." {
		return nil, fmt.Errorf("%s: unseal_credential %q is not a credential's name", ConfigFile, s.UnsealCredential)
	}
	if s.Rate == 0 {
		s.Rate = 20
	}
	return s, nil
}
