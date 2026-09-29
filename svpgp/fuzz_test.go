package svpgp

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Whatever the parsers accept must be usable, and nothing, accepted or
// not, may panic or run away with memory or time. The seeds are the RFC
// 9580 vectors and messages made here.

func fuzzSeeds(f *testing.F) {
	files, _ := filepath.Glob(filepath.Join("testdata", "rfc9580", "*.asc"))
	for _, name := range files {
		data, err := os.ReadFile(name)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
		if block, err := Dearmor(bytes.NewReader(data)); err == nil {
			if bin, err := io.ReadAll(block.Body); err == nil {
				f.Add(bin)
			}
		}
	}
	k, err := GenerateKey(KeyOptions{Version: 4, UserIDs: []string{"Fuzz"}})
	if err != nil {
		f.Fatal(err)
	}
	pub, _ := k.Armor(false)
	f.Add(pub)
	var out bytes.Buffer
	Sign(&out, bytes.NewReader([]byte("seed")), k, SignOptions{Mode: SignInline})
	f.Add(out.Bytes())
	out.Reset()
	w, _ := Encrypt(&out, []*Key{k.Public()}, EncryptOptions{Signer: k, Compression: ZLIB})
	w.Write([]byte("seed"))
	w.Close()
	f.Add(out.Bytes())
}

// FuzzPackets feeds every packet in a stream to the parser for its type.
func FuzzPackets(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		pr := newPacketReader(bytes.NewReader(data))
		for range 64 {
			tag, body, err := pr.next()
			if err != nil {
				return
			}
			if tag.streamed() {
				io.Copy(io.Discard, io.LimitReader(body, 1<<20))
				continue
			}
			b, err := body.readAll(1 << 20)
			if err != nil {
				return
			}
			switch tag {
			case ptPublicKey, ptPublicSubkey:
				if pk, _, err := parsePublicKey(b, false); err == nil && !bytes.Equal(pk.body, b) {
					t.Fatal("a parsed public key does not keep its body")
				}
			case ptSecretKey, ptSecretSubkey:
				if sk, err := parseSecretKey(b, tag); err == nil {
					if body, err := sk.body(); err == nil && sk.prot.usage == usageNone && sk.unavailable == nil {
						back, err := parseSecretKey(body, tag)
						if err != nil || !bytes.Equal(back.secret.Bytes(), sk.secret.Bytes()) {
							t.Fatalf("an unprotected secret key does not round-trip: %v", err)
						}
					}
					sk.destroy()
				}
			case ptSignature:
				if s, err := parseSignature(b, 0); err == nil {
					back, err := parseSignature(s.body, 0)
					if err != nil || !bytes.Equal(back.hashedPrefix(), s.hashedPrefix()) && s.version != 3 {
						t.Fatalf("a signature does not parse again: %v", err)
					}
				}
			case ptPKESK:
				parsePKESK(b)
			case ptSKESK:
				if k, err := parseSKESK(b); err == nil && k.s2k.typ == s2kIterated {
					_ = k.s2k.bytes()
				}
			case ptOnePass:
				parseOnePass(b)
			}
		}
	})
}

var fuzzLimits = &Limits{MaxMessageSize: 1 << 20, MaxArgon2Memory: 64, MaxArgon2Passes: 2, MaxNesting: 4}

// FuzzReadKeys reads keyrings: what is read must write out and read back
// as the same keys.
func FuzzReadKeys(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		keys, err := ReadKeys(bytes.NewReader(data))
		if err != nil {
			return
		}
		for _, k := range keys {
			_ = k.Valid(time.Now())
			_ = k.UserIDs()
			_ = k.Subkeys()
			_ = k.String()
			var out bytes.Buffer
			if err := k.Serialize(&out, false); err != nil {
				t.Fatalf("a key that was read does not serialize: %v", err)
			}
			back, err := ReadKeys(bytes.NewReader(out.Bytes()))
			if err != nil || len(back) != 1 || !bytes.Equal(back[0].Fingerprint(), k.Fingerprint()) {
				t.Fatalf("a serialized key does not read back: %v", err)
			}
			k.Close()
		}
	})
}

// FuzzReadMessage reads messages with a secret key and a passphrase at hand.
func FuzzReadMessage(f *testing.F) {
	fuzzSeeds(f)
	data, err := os.ReadFile(filepath.Join("testdata", "rfc9580", "a4-v6-secret-key.asc"))
	if err != nil {
		f.Fatal(err)
	}
	key, err := ReadKey(bytes.NewReader(data))
	if err != nil {
		f.Fatal(err)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		EncryptedTo(bytes.NewReader(data))
		msg, err := ReadMessage(bytes.NewReader(data), ReadOptions{
			Keyring:    []*Key{key},
			Passphrase: func() ([]byte, error) { return []byte("password"), nil },
			Limits:     fuzzLimits,
		})
		if err != nil {
			return
		}
		if int64(len(msg.Body)) > fuzzLimits.MaxMessageSize {
			t.Fatalf("a %d-byte body got past the limit", len(msg.Body))
		}
		for _, r := range msg.Signatures {
			if r.Valid && r.Key == nil {
				t.Fatal("a valid signature without a key")
			}
		}
	})
}

// FuzzDearmor decodes armor: what decodes must armor and decode back to the
// same bytes.
func FuzzDearmor(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		block, err := Dearmor(bytes.NewReader(data))
		if err != nil {
			return
		}
		body, err := io.ReadAll(io.LimitReader(block.Body, 1<<20))
		if err != nil {
			return
		}
		again, err := Dearmor(bytes.NewReader(armorBytes(block.Type, body, true)))
		if err != nil {
			t.Fatalf("re-armored data does not decode: %v", err)
		}
		back, err := io.ReadAll(again.Body)
		if err != nil || !bytes.Equal(back, body) {
			t.Fatalf("armor does not round-trip: %v", err)
		}
	})
}
