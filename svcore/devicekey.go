package svcore

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/codemodify/secretvault/svformat"
)

// DeviceKeyFile is where, in secretvault's data directory, a device keeps
// the key it signs the revisions it writes with.
//
// It is a key of its own, not the sync device key (svsync.IdentityFile):
// that one signs requests to sync servers, which list it and see it on
// every request, so a revision signed with it would tell the server which
// enrolled device wrote it; and a key that signs for two protocols can be
// made to sign for one what was meant for the other. Keeping them apart
// also lets either be replaced without the other.
const DeviceKeyFile = "device-signing.key"

// DeviceKey is this device's Ed25519 key for signing the revisions it
// writes (docs/format.md, "Signatures"). The same key serves every vault
// the device writes to; each vault's registry says which device it is.
//
// The key is ordinary Go memory, as the sync key is: crypto/ed25519 keeps
// its own expanded copy of any key it signs with, which cannot be locked
// or wiped, so locked memory for ours would protect nothing.
type DeviceKey struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
	id   svformat.ID
}

// LoadDeviceKey returns the device key kept in dir (DeviceKeyFile, 0600),
// making one the first time.
func LoadDeviceKey(dir string) (*DeviceKey, error) {
	p := filepath.Join(dir, DeviceKeyFile)
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		if err := createDeviceKey(dir, p); err != nil {
			return nil, err
		}
		b, err = os.ReadFile(p)
	}
	if err != nil {
		return nil, err
	}
	defer clear(b)
	blk, _ := pem.Decode(b)
	if blk == nil || blk.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("svcore: %s is not a device key", p)
	}
	defer clear(blk.Bytes)
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("svcore: %s: %w", p, err)
	}
	key, ok := k.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("svcore: %s is not an Ed25519 key", p)
	}
	return deviceKey(key), nil
}

// NewDeviceKey returns a key held only in memory (for tests, and for
// programs that keep their key elsewhere).
func NewDeviceKey() *DeviceKey {
	_, key, _ := ed25519.GenerateKey(nil)
	return deviceKey(key)
}

func deviceKey(key ed25519.PrivateKey) *DeviceKey {
	pub := append(ed25519.PublicKey(nil), key.Public().(ed25519.PublicKey)...)
	return &DeviceKey{priv: key, pub: pub, id: svformat.DeviceKeyID(pub)}
}

// Public is the key's public half.
func (k *DeviceKey) Public() ed25519.PublicKey { return k.pub }

// ID is the key's ID (svformat.DeviceKeyID): its object ID in every
// vault's registry, and the fingerprint people compare.
func (k *DeviceKey) ID() svformat.ID { return k.id }

func (k *DeviceKey) private() ed25519.PrivateKey { return k.priv }

// createDeviceKey writes a new key to p, unless another process got there
// first (then its key is the one).
func createDeviceKey(dir, p string) error {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		return err
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	clear(key)
	if err != nil {
		return err
	}
	data := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	clear(der)
	defer clear(data)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, 0o600)
	}
	if err != nil {
		return err
	}
	// A hard link is create-if-absent and atomic at once.
	if err := os.Link(tmp, p); err != nil && !errors.Is(err, fs.ErrExist) {
		// No hard links here: an exclusive rename is the next best thing.
		if _, serr := os.Stat(p); errors.Is(serr, fs.ErrNotExist) {
			return os.Rename(tmp, p)
		}
	}
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}
