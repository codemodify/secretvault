package svage

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The C2SP CCTV age vectors (testdata/cctv, see testdata/README.md): every
// file must decrypt, or fail, exactly as the vector says, releasing the
// same plaintext before any payload failure; and every valid armor,
// header and payload in them must re-encode to the same bytes.

type vector struct {
	name        string
	expect      string
	payloadHash *[32]byte
	fileKey     []byte
	identities  []Identity
	armored     bool
	file        []byte
}

func loadVectors(t testing.TB) []*vector {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "cctv", "*"))
	if err != nil || len(paths) == 0 {
		t.Fatalf("no vectors: %v", err)
	}
	var out []*vector
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, parseVector(t, filepath.Base(p), b))
	}
	return out
}

func parseVector(t testing.TB, name string, b []byte) *vector {
	v := &vector{name: name}
	compressed := false
	for {
		line, rest, ok := bytes.Cut(b, []byte("\n"))
		if !ok {
			t.Fatalf("%s: no payload", name)
		}
		b = rest
		if len(line) == 0 {
			break
		}
		key, value, _ := strings.Cut(string(line), ": ")
		switch key {
		case "expect":
			switch value {
			case "success", "HMAC failure", "header failure", "armor failure", "payload failure", "no match":
			default:
				t.Fatalf("%s: unknown expectation %q", name, value)
			}
			v.expect = value
		case "payload":
			h, err := hex.DecodeString(value)
			if err != nil || len(h) != 32 {
				t.Fatalf("%s: bad payload hash", name)
			}
			v.payloadHash = (*[32]byte)(h)
		case "file key":
			k, err := hex.DecodeString(value)
			if err != nil {
				t.Fatalf("%s: bad file key", name)
			}
			v.fileKey = k
		case "identity":
			id, err := ParseIdentity(value)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			v.identities = append(v.identities, id)
		case "passphrase":
			id, err := NewScryptIdentity([]byte(value))
			if err != nil {
				t.Fatal(err)
			}
			v.identities = append(v.identities, id)
		case "armored":
			v.armored = value == "yes"
		case "compressed":
			if value != "zlib" {
				t.Fatalf("%s: unknown compression %q", name, value)
			}
			compressed = true
		case "comment":
		default:
			t.Fatalf("%s: unknown key %q", name, key)
		}
	}
	if compressed {
		zr, err := zlib.NewReader(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		if b, err = io.ReadAll(zr); err != nil {
			t.Fatal(err)
		}
	}
	v.file = b
	return v
}

// outcome classifies an error the way the vectors name outcomes.
func outcome(err error) string {
	var ae *ArmorError
	var nm *NoIdentityMatchError
	switch {
	case err == nil:
		return "success"
	case errors.As(err, &ae):
		return "armor failure"
	case errors.Is(err, ErrHeaderMAC):
		return "HMAC failure"
	case errors.As(err, &nm):
		return "no match"
	case errors.Is(err, ErrPayload):
		return "payload failure"
	case errors.Is(err, ErrHeader):
		return "header failure"
	}
	return "unexpected error: " + err.Error()
}

func TestEveryCCTVVectorDecryptsAsExpected(t *testing.T) {
	vectors := loadVectors(t)
	passed := 0
	for _, v := range vectors {
		ok := t.Run(v.name, func(t *testing.T) {
			var in io.Reader = bytes.NewReader(v.file)
			if v.armored {
				in = NewArmorReader(in)
			}
			r, err := Decrypt(in, v.identities...)
			if err != nil {
				if got := outcome(err); got != v.expect {
					t.Fatalf("Decrypt: %s (%v), want %s", got, err, v.expect)
				}
				return
			}
			out, err := io.ReadAll(r)
			got := outcome(err)
			if got != v.expect {
				t.Fatalf("reading: %s (%v), want %s", got, err, v.expect)
			}
			if v.payloadHash != nil && sha256.Sum256(out) != *v.payloadHash {
				t.Fatalf("the %d bytes released do not match the payload hash", len(out))
			}
		})
		if ok {
			passed++
		}
	}
	t.Logf("%d of %d CCTV vectors pass", passed, len(vectors))
}

func TestCCTVVectorsDecryptAtRandom(t *testing.T) {
	for _, v := range loadVectors(t) {
		if v.armored {
			continue // armor is a stream, not a ReaderAt
		}
		t.Run(v.name, func(t *testing.T) {
			var want []byte
			if r, err := Decrypt(bytes.NewReader(v.file), v.identities...); err == nil {
				want, _ = io.ReadAll(r)
			}
			ra, size, err := DecryptReaderAt(bytes.NewReader(v.file), int64(len(v.file)), v.identities...)
			switch {
			case v.expect == "success" && err != nil:
				t.Fatalf("DecryptReaderAt: %v", err)
			case v.expect == "payload failure" && err != nil:
				return // some are caught up front, from the size or the final chunk
			case v.expect != "success" && v.expect != "payload failure":
				if got := outcome(err); got != v.expect {
					t.Fatalf("DecryptReaderAt: %s (%v), want %s", got, err, v.expect)
				}
				return
			}
			out, err := io.ReadAll(io.NewSectionReader(ra, 0, size))
			if v.expect == "success" {
				if err != nil || !bytes.Equal(out, want) || int64(len(out)) != size {
					t.Fatalf("read %d of %d bytes: %v", len(out), size, err)
				}
				return
			}
			if err == nil {
				t.Fatal("a damaged payload read in full")
			}
			if !bytes.HasPrefix(want, out) {
				t.Fatalf("the %d bytes read at random are not a prefix of the streamed plaintext", len(out))
			}
		})
	}
}

// Valid parts of the vectors re-encode to exactly the same bytes.
func TestCCTVVectorsReencodeIdentically(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.name, func(t *testing.T) {
			if v.armored {
				if v.expect == "armor failure" {
					return
				}
				payload, err := io.ReadAll(NewArmorReader(bytes.NewReader(v.file)))
				if err != nil {
					t.Fatal(err)
				}
				var buf bytes.Buffer
				w := NewArmorWriter(&buf)
				w.Write(payload)
				if err := w.Close(); err != nil {
					t.Fatal(err)
				}
				// CRLF and surrounding whitespace are allowed on input only.
				want := append(bytes.TrimSpace(bytes.ReplaceAll(v.file, []byte("\r\n"), []byte("\n"))), '\n')
				if !bytes.Equal(buf.Bytes(), want) {
					t.Fatalf("the armor re-encodes differently:\n%s\nwant:\n%s", buf.Bytes(), want)
				}
				return
			}
			if v.expect == "header failure" {
				return
			}
			br := bufio.NewReader(bytes.NewReader(v.file))
			hdr, err := parseHeader(br)
			if err != nil {
				t.Fatal(err)
			}
			payload, _ := io.ReadAll(br)
			again, err := marshalHeader(hdr.stanzas, func([]byte) []byte { return hdr.mac })
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(append(again, payload...), v.file) {
				t.Fatal("the header re-encodes differently")
			}
			if v.expect != "success" {
				return
			}
			// The payload re-encrypts to the same ciphertext.
			nonce, sealed := payload[:nonceSize], payload[nonceSize:]
			aead, err := payloadAEAD(v.fileKey, nonce)
			if err != nil {
				t.Fatal(err)
			}
			plain, err := io.ReadAll(newStreamReader(aead, bytes.NewReader(sealed)))
			if err != nil {
				t.Fatal(err)
			}
			var ct bytes.Buffer
			sw := newStreamWriter(aead, &ct)
			// Odd write sizes, to exercise chunk boundaries.
			for p := plain; len(p) > 0; {
				n := min(len(p), 1+len(p)%7919)
				sw.Write(p[:n])
				p = p[n:]
			}
			if err := sw.Close(); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(ct.Bytes(), sealed) {
				t.Fatal("the payload re-encrypts differently")
			}
		})
	}
}
