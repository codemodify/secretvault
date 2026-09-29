package svsync

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/codemodify/secretvault/svserver"
)

// IdentityFile is where, in secretvault's data directory, a device keeps
// the key it signs sync requests with.
const IdentityFile = "sync-device.key"

// Identity is this device's key for sync servers: an Ed25519 key that
// signs every request. It opens no vault; it only lets the device fetch
// and store a vault's ciphertext on servers it is enrolled with.
type Identity struct {
	key ed25519.PrivateKey
}

// LoadIdentity returns the device key kept in dir (IdentityFile, 0600),
// making one the first time.
func LoadIdentity(dir string) (*Identity, error) {
	p := filepath.Join(dir, IdentityFile)
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		if err := createIdentity(dir, p); err != nil {
			return nil, err
		}
		b, err = os.ReadFile(p)
	}
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("svsync: %s is not a device key", p)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("svsync: %s: %w", p, err)
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("svsync: %s is not an Ed25519 key", p)
	}
	return &Identity{key: key}, nil
}

// createIdentity writes a new key to p, unless another process got there
// first (then its key is the one).
func createIdentity(dir, p string) error {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	clear(key)
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := writeTemp(dir, data)
	clear(data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	// A hard link is create-if-absent and atomic at once.
	if err := os.Link(tmp, p); err != nil && !errors.Is(err, fs.ErrExist) {
		// No hard links here: an exclusive rename is the next best thing.
		if _, serr := os.Stat(p); errors.Is(serr, fs.ErrNotExist) {
			return os.Rename(tmp, p)
		}
	}
	syncDir(dir)
	return nil
}

// NewIdentity returns a key held only in memory (for tests, and for
// devices that keep it elsewhere).
func NewIdentity() *Identity {
	_, key, _ := ed25519.GenerateKey(nil)
	return &Identity{key: key}
}

// Public is the device's public key.
func (id *Identity) Public() ed25519.PublicKey { return id.key.Public().(ed25519.PublicKey) }

// Key is the public key as servers list it (unpadded base64url).
func (id *Identity) Key() string { return svserver.EncodeKey(id.Public()) }
