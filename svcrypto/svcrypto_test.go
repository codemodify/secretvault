package svcrypto

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"testing"
)

var suites = []Suite{Modern, NIST}

func cheapKDF(t *testing.T) {
	t.Helper()
	a, p := DefaultArgon2, DefaultPBKDF2
	DefaultArgon2 = KDFParams{Alg: Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	DefaultPBKDF2 = KDFParams{Alg: PBKDF2SHA256, Iterations: 10}
	t.Cleanup(func() { DefaultArgon2, DefaultPBKDF2 = a, p })
}

func TestSealOpensOnlyWithTheSameKeyAndAAD(t *testing.T) {
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			key, aad, msg := RandomKey(), []byte("context"), []byte("attack at dawn")
			sealed, err := s.Seal(key, msg, aad)
			if err != nil {
				t.Fatal(err)
			}
			if len(sealed) != len(msg)+s.Overhead() {
				t.Fatalf("sealed is %d bytes, want %d", len(sealed), len(msg)+s.Overhead())
			}
			got, err := s.Open(key, sealed, aad)
			if err != nil || !bytes.Equal(got, msg) {
				t.Fatalf("Open = %q, %v", got, err)
			}
			if _, err := s.Open(RandomKey(), sealed, aad); !errors.Is(err, ErrOpen) {
				t.Errorf("another key opened it: %v", err)
			}
			if _, err := s.Open(key, sealed, []byte("other")); !errors.Is(err, ErrOpen) {
				t.Errorf("other aad opened it: %v", err)
			}
			for i := range sealed {
				bad := bytes.Clone(sealed)
				bad[i] ^= 0x01
				if _, err := s.Open(key, bad, aad); !errors.Is(err, ErrOpen) {
					t.Fatalf("flipping byte %d still opened: %v", i, err)
				}
			}
			if _, err := s.Open(key, sealed[:s.Overhead()-1], aad); !errors.Is(err, ErrOpen) {
				t.Errorf("truncated input opened: %v", err)
			}
		})
	}
}

func TestSealNeverRepeatsACiphertext(t *testing.T) {
	for _, s := range suites {
		key := RandomKey()
		a, _ := s.Seal(key, []byte("same"), nil)
		b, _ := s.Seal(key, []byte("same"), nil)
		if bytes.Equal(a, b) {
			t.Errorf("%v: two seals of one message are identical", s)
		}
	}
}

func TestTheSuitesAreNotInterchangeable(t *testing.T) {
	key := RandomKey()
	sealed, _ := Modern.Seal(key, bytes.Repeat([]byte{7}, 64), nil)
	if _, err := NIST.Open(key, sealed, nil); err == nil {
		t.Fatal("a Modern ciphertext opened as NIST")
	}
}

func TestSuiteNamesRoundTrip(t *testing.T) {
	for _, s := range suites {
		got, err := ParseSuite(s.String())
		if err != nil || got != s {
			t.Errorf("ParseSuite(%q) = %v, %v", s, got, err)
		}
	}
	if _, err := ParseSuite("rot13"); !errors.Is(err, ErrSuite) {
		t.Errorf("unknown suite parsed: %v", err)
	}
}

func TestDeriveSeparatesLabelsAndSalts(t *testing.T) {
	key := RandomKey()
	a := Derive(key, []byte("vault-1"), "wrap", 32)
	if bytes.Equal(a, Derive(key, []byte("vault-1"), "check", 32)) {
		t.Error("two labels gave one key")
	}
	if bytes.Equal(a, Derive(key, []byte("vault-2"), "wrap", 32)) {
		t.Error("two salts gave one key")
	}
	if !bytes.Equal(a, Derive(key, []byte("vault-1"), "wrap", 32)) {
		t.Error("Derive is not deterministic")
	}
}

func TestPassphraseKeysDependOnEveryInput(t *testing.T) {
	cheapKDF(t)
	for _, s := range suites {
		p := s.NewKDFParams()
		k1, err := p.DeriveKey([]byte("correct horse"))
		if err != nil {
			t.Fatal(err)
		}
		k2, _ := p.DeriveKey([]byte("correct horse"))
		if !bytes.Equal(k1, k2) || len(k1) != KeySize {
			t.Fatalf("%v: not deterministic or wrong size", s)
		}
		if k3, _ := p.DeriveKey([]byte("correct horsf")); bytes.Equal(k1, k3) {
			t.Errorf("%v: two passphrases gave one key", s)
		}
		q := s.NewKDFParams()
		if k4, _ := q.DeriveKey([]byte("correct horse")); bytes.Equal(k1, k4) {
			t.Errorf("%v: two salts gave one key", s)
		}
	}
}

func TestTheArgon2idKeyMatchesTheReferenceImplementation(t *testing.T) {
	// Expected output from the reference implementation (phc-winner-argon2):
	//   echo -n password | argon2 $(printf '\x02%.0s' {1..16}) -id -t 1 -k 64 -p 1 -l 32 -r
	// It pins how we call Argon2id, so a changed call cannot silently change
	// every stored key.
	p := KDFParams{Alg: Argon2id, Salt: bytes.Repeat([]byte{2}, 16), Time: 1, MemoryKiB: 64, Threads: 1}
	k, err := p.DeriveKey([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "74918277366de18108628ffd064a70ba7976d61e72c89c22a835fc81897567e0"
	if got := hex.EncodeToString(k); got != want {
		t.Fatalf("argon2id derivation changed:\n got %s\nwant %s", got, want)
	}
}

func TestThePBKDF2KeyMatchesAnIndependentImplementation(t *testing.T) {
	// python3 -c "import hashlib;print(hashlib.pbkdf2_hmac('sha256',b'password',bytes([2]*16),1000,32).hex())"
	p := KDFParams{Alg: PBKDF2SHA256, Salt: bytes.Repeat([]byte{2}, 16), Iterations: 1000}
	k, err := p.DeriveKey([]byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "32ca9e5d739445ab2354802f6af4116dc186b2bf7dfebdd78dc51bc7b3ad151a"
	if got := hex.EncodeToString(k); got != want {
		t.Fatalf("pbkdf2 derivation changed:\n got %s\nwant %s", got, want)
	}
}

func TestKDFParamsRefuseHostileCosts(t *testing.T) {
	salt := make([]byte, 16)
	for _, p := range []KDFParams{
		{Alg: Argon2id, Salt: salt, Time: 1, MemoryKiB: 1 << 30, Threads: 1},
		{Alg: Argon2id, Salt: salt, Time: 1000, MemoryKiB: 64, Threads: 1},
		{Alg: Argon2id, Salt: salt, Time: 1, MemoryKiB: 64, Threads: 0},
		{Alg: Argon2id, Salt: salt[:4], Time: 1, MemoryKiB: 64, Threads: 1},
		{Alg: PBKDF2SHA256, Salt: salt, Iterations: 0},
		{Alg: PBKDF2SHA256, Salt: salt, Iterations: 1 << 31},
		{Alg: "md5", Salt: salt},
	} {
		if _, err := p.DeriveKey([]byte("x")); !errors.Is(err, ErrKDFParams) {
			t.Errorf("%+v was accepted: %v", p, err)
		}
	}
}

func TestIdentitiesSealAndOpen(t *testing.T) {
	for _, s := range suites {
		t.Run(s.String(), func(t *testing.T) {
			id, err := s.NewIdentity()
			if err != nil {
				t.Fatal(err)
			}
			pub := id.Recipient()
			if err := s.CheckRecipient(pub); err != nil {
				t.Fatal(err)
			}
			sealed, err := s.SealTo(pub, []byte("vault master key"), []byte("slot-1"))
			if err != nil {
				t.Fatal(err)
			}
			got, err := id.Open(sealed, []byte("slot-1"))
			if err != nil || string(got) != "vault master key" {
				t.Fatalf("Open = %q, %v", got, err)
			}
			if _, err := id.Open(sealed, []byte("slot-2")); !errors.Is(err, ErrOpen) {
				t.Errorf("other info opened it: %v", err)
			}
			other, _ := s.NewIdentity()
			if _, err := other.Open(sealed, []byte("slot-1")); !errors.Is(err, ErrOpen) {
				t.Errorf("another identity opened it: %v", err)
			}

			raw, err := id.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			back, err := s.ParseIdentity(raw)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(back.Recipient(), pub) {
				t.Fatal("identity did not round-trip")
			}
			if got, err := back.Open(sealed, []byte("slot-1")); err != nil || string(got) != "vault master key" {
				t.Fatalf("parsed identity: %q, %v", got, err)
			}
		})
	}
}

func TestShamirRebuildsFromAnyThreshold(t *testing.T) {
	secret := RandomKey()
	shares, err := SplitSecret(secret, 5, 3)
	if err != nil {
		t.Fatal(err)
	}
	for a := range 5 {
		for b := a + 1; b < 5; b++ {
			for c := b + 1; c < 5; c++ {
				got, err := CombineShares([][]byte{shares[a], shares[b], shares[c]})
				if err != nil || !bytes.Equal(got, secret) {
					t.Fatalf("shares %d,%d,%d: %x, %v", a, b, c, got, err)
				}
			}
		}
	}
	all, _ := CombineShares(shares)
	if !bytes.Equal(all, secret) {
		t.Error("all five shares did not rebuild the secret")
	}
	if two, _ := CombineShares(shares[:2]); bytes.Equal(two, secret) {
		t.Error("two shares of a 3-threshold rebuilt the secret")
	}
	if _, err := CombineShares([][]byte{shares[0], shares[0]}); !errors.Is(err, ErrShares) {
		t.Errorf("a repeated share combined: %v", err)
	}
	if _, err := SplitSecret(secret, 2, 3); err == nil {
		t.Error("a threshold above the share count was accepted")
	}
}

func TestGaloisFieldInverse(t *testing.T) {
	for a := 1; a < 256; a++ {
		if gfMul(byte(a), gfInv(byte(a))) != 1 {
			t.Fatalf("%d * inv(%d) != 1", a, a)
		}
	}
}

func streamRoundTrip(t *testing.T, s Suite, size int) {
	t.Helper()
	key, aad := RandomKey(), []byte("blob-7")
	msg := RandomBytes(size)
	var buf bytes.Buffer
	w, err := s.NewStreamWriter(key, aad, &buf)
	if err != nil {
		t.Fatal(err)
	}
	// Write in awkward pieces to cross chunk boundaries unevenly.
	for rest := msg; len(rest) > 0; {
		n := min(len(rest), 1000+len(rest)%7777)
		if _, err := w.Write(rest[:n]); err != nil {
			t.Fatal(err)
		}
		rest = rest[n:]
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	r, err := s.NewStreamReader(key, aad, bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r)
	if err != nil || !bytes.Equal(got, msg) {
		t.Fatalf("size %d: got %d bytes, %v", size, len(got), err)
	}
}

func TestStreamsRoundTripAtEveryBoundary(t *testing.T) {
	for _, s := range suites {
		for _, size := range []int{0, 1, StreamChunkSize - 1, StreamChunkSize, StreamChunkSize + 1, 3*StreamChunkSize + 5} {
			streamRoundTrip(t, s, size)
		}
	}
}

func TestStreamsRefuseTruncationAndTampering(t *testing.T) {
	for _, s := range suites {
		key := RandomKey()
		var buf bytes.Buffer
		w, _ := s.NewStreamWriter(key, nil, &buf)
		w.Write(RandomBytes(2*StreamChunkSize + 10))
		w.Close()
		full := buf.Bytes()

		read := func(b []byte, aad []byte) error {
			r, err := s.NewStreamReader(key, aad, bytes.NewReader(b))
			if err != nil {
				return err
			}
			_, err = io.ReadAll(r)
			return err
		}
		if err := read(full, nil); err != nil {
			t.Fatalf("%v: intact stream failed: %v", s, err)
		}
		// Cut exactly after the first full chunk: must not read as shorter.
		cut := streamSaltSize + streamEncChunk
		if err := read(full[:cut], nil); !errors.Is(err, ErrStream) {
			t.Errorf("%v: stream cut at a chunk boundary read cleanly: %v", s, err)
		}
		if err := read(full[:len(full)-1], nil); !errors.Is(err, ErrStream) {
			t.Errorf("%v: stream missing its last byte read cleanly: %v", s, err)
		}
		bad := bytes.Clone(full)
		bad[streamSaltSize+streamEncChunk+100] ^= 1
		if err := read(bad, nil); !errors.Is(err, ErrStream) {
			t.Errorf("%v: altered stream read cleanly: %v", s, err)
		}
		if err := read(full, []byte("other")); !errors.Is(err, ErrStream) {
			t.Errorf("%v: stream opened with other aad: %v", s, err)
		}
	}
}

func TestSecretsAreZeroedOnDestroy(t *testing.T) {
	s := NewSecret(KeySize)
	b := s.Bytes()
	copy(b, bytes.Repeat([]byte{0xAA}, KeySize))
	if s.region == nil {
		t.Skip("protected memory is not available on this platform")
	}
	region := s.region
	s.Destroy()
	s.Destroy() // twice is fine
	if s.Bytes() != nil {
		t.Error("Bytes after Destroy is not nil")
	}
	_ = region // unmapped now; reading it would fault, which is the point
}

func TestSecretFromZeroesItsSource(t *testing.T) {
	src := []byte("hunter2hunter2")
	s := SecretFrom(src)
	defer s.Destroy()
	if !bytes.Equal(src, make([]byte, len(src))) {
		t.Error("source was not zeroed")
	}
	if string(s.Bytes()) != "hunter2hunter2" {
		t.Error("secret lost its contents")
	}
}
