package svimport

import (
	"bytes"
	"crypto/aes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"strings"
	"sync"

	"github.com/codemodify/secretvault/svcrypto"
)

// The KDBX composite key, and the key derivation that transforms it.

// kdbxCompositeKey is SHA-256 over the key's parts, in order: the
// password's SHA-256, then the key file's 32-byte key.
func kdbxCompositeKey(pass, keyfile []byte) ([]byte, error) {
	h := sha256.New()
	if len(pass) > 0 {
		p := sha256.Sum256(pass)
		h.Write(p[:])
		clear(p[:])
	}
	if len(keyfile) > 0 {
		k, err := keyfileKey(keyfile)
		if err != nil {
			return nil, err
		}
		h.Write(k)
		clear(k)
	}
	return h.Sum(nil), nil
}

// keyfileKey reads a KeePass key file (https://keepass.info/help/base/keys.html#keyfiles):
//   - XML, version 1.0: <Key><Data>base64</Data></Key>;
//   - XML, version 2.0: <Key><Data Hash="8 hex">hex, spaced</Data></Key>,
//     the hash being the start of the key's SHA-256;
//   - 32 bytes: the key itself;
//   - 64 hex digits: the key in hex;
//   - anything else: its SHA-256.
func keyfileKey(b []byte) ([]byte, error) {
	if t := bytes.TrimSpace(b); bytes.HasPrefix(t, []byte("<?xml")) || bytes.HasPrefix(t, []byte("<KeyFile")) {
		var kf struct {
			Version string `xml:"Meta>Version"`
			Data    struct {
				Hash string `xml:"Hash,attr"`
				Text string `xml:",chardata"`
			} `xml:"Key>Data"`
		}
		if err := xml.Unmarshal(t, &kf); err == nil && strings.TrimSpace(kf.Data.Text) != "" {
			text := strings.Join(strings.Fields(kf.Data.Text), "")
			if strings.HasPrefix(strings.TrimSpace(kf.Version), "2.") {
				key, err := hex.DecodeString(text)
				if err != nil {
					return nil, fmt.Errorf("%w: the key file's data is not hex", ErrFormat)
				}
				sum := sha256.Sum256(key)
				if kf.Data.Hash != "" && !strings.EqualFold(hex.EncodeToString(sum[:4]), kf.Data.Hash) {
					return nil, fmt.Errorf("%w: the key file does not match its own checksum", ErrFormat)
				}
				return key, nil
			}
			key, err := base64.StdEncoding.DecodeString(text)
			if err != nil {
				return nil, fmt.Errorf("%w: the key file's data is not base64", ErrFormat)
			}
			return key, nil
		}
	}
	if len(b) == 32 {
		return append([]byte(nil), b...), nil
	}
	if len(b) == 64 {
		if key, err := hex.DecodeString(string(b)); err == nil {
			return key, nil
		}
	}
	sum := sha256.Sum256(b)
	return sum[:], nil
}

// Bounds on what a file may ask of the KDF, so a planted file cannot hang
// or exhaust the machine.
const (
	maxAESRounds   = 1 << 31
	maxArgonPasses = 1 << 16
)

// transformKey runs the header's key derivation over the composite key.
func (h *kdbxHeader) transformKey(composite []byte) ([]byte, error) {
	if h.major < 4 {
		return aesKDF(composite, h.transformSeed, h.rounds)
	}
	switch uuid := string(h.kdf.bytes("$UUID")); uuid {
	case kdfAES3, kdfAES4:
		rounds, _ := h.kdf.uint("R")
		return aesKDF(composite, h.kdf.bytes("S"), rounds)
	case kdfArgon2d, kdfArgon2id:
		variant := svcrypto.Argon2d
		if uuid == kdfArgon2id {
			variant = svcrypto.Argon2id
		}
		passes, _ := h.kdf.uint("I")
		mem, _ := h.kdf.uint("M")
		lanes, _ := h.kdf.uint("P")
		version, _ := h.kdf.uint("V")
		if passes > maxArgonPasses || mem/1024 > 1<<32-1 || lanes > 255 {
			return nil, fmt.Errorf("%w: Argon2 t=%d m=%dKiB p=%d is beyond what secretvault will run", ErrUnsupported, passes, mem/1024, lanes)
		}
		k, err := svcrypto.Argon2(variant, svcrypto.Argon2Input{
			Password: composite, Salt: h.kdf.bytes("S"), Secret: h.kdf.bytes("K"), Data: h.kdf.bytes("A"),
			Time: uint32(passes), MemoryKiB: uint32(mem / 1024), Threads: uint32(lanes), KeyLen: 32, Version: uint32(version),
		})
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrUnsupported, err)
		}
		return k, nil
	default:
		return nil, fmt.Errorf("%w: KDBX key derivation %x", ErrUnsupported, uuid)
	}
}

// aesKDF is KeePass's AES-KDF: each 16-byte half of the key encrypted
// rounds times with AES-256-ECB under the seed, then SHA-256.
func aesKDF(key, seed []byte, rounds uint64) ([]byte, error) {
	if len(seed) != 32 || len(key) != 32 {
		return nil, fmt.Errorf("%w: AES-KDF seed", ErrFormat)
	}
	if rounds > maxAESRounds {
		return nil, fmt.Errorf("%w: AES-KDF with %d rounds is beyond what secretvault will run", ErrUnsupported, rounds)
	}
	blk, err := aes.NewCipher(seed)
	if err != nil {
		return nil, err
	}
	out := append([]byte(nil), key...)
	var wg sync.WaitGroup
	for half := 0; half < 2; half++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			b := out[16*half : 16*half+16]
			for range rounds {
				blk.Encrypt(b, b)
			}
		}()
	}
	wg.Wait()
	sum := sha256.Sum256(out)
	clear(out)
	return sum[:], nil
}
