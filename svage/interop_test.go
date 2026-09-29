package svage

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Files the reference implementation (filippo.io/age v1.3.2) wrote, for
// the recipient types the CCTV vectors leave out (testdata/interop, and
// its generate.go.txt).

var interopPlaintext = bytes.Repeat([]byte("secretvault and age agree.\n"), 40)

func readInterop(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "interop", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestFilesAgeWroteToSSHKeysDecrypt(t *testing.T) {
	for _, c := range []struct{ key, file string }{
		{"ssh-ed25519.key", "ssh-ed25519.age"},
		{"ssh-ed25519.key", "ssh-ed25519-armored.age"},
		{"ssh-rsa.key", "ssh-rsa.age"},
	} {
		t.Run(c.file, func(t *testing.T) {
			id, err := ParseSSHIdentity(readInterop(t, c.key), nil)
			if err != nil {
				t.Fatal(err)
			}
			file := readInterop(t, c.file)
			got, err := decrypt(file, IsArmored(file), id)
			if err != nil || !bytes.Equal(got, interopPlaintext) {
				t.Fatalf("got %d bytes, %v", len(got), err)
			}
		})
	}
}

// The reference's tagged stanzas carry the tags this package computes,
// and open with the tokens' keys (derived here as the generator did).
func TestFilesAgeWroteToTagRecipientsCarryOurTags(t *testing.T) {
	var rcpts []string
	for _, l := range strings.Split(string(readInterop(t, "recipients.txt")), "\n") {
		if strings.HasPrefix(l, "age1") {
			rcpts = append(rcpts, l)
		}
	}
	for i, c := range []struct {
		file, seed string
		pq         bool
	}{
		{"p256tag.age", "svage interop p256tag", false},
		{"mlkem768p256tag.age", "svage interop mlkem768p256tag", true},
	} {
		t.Run(c.file, func(t *testing.T) {
			var priv hpke.PrivateKey
			var err error
			if c.pq {
				priv, err = hpke.MLKEM768P256().DeriveKeyPair([]byte(c.seed))
			} else {
				priv, err = hpke.DHKEM(ecdh.P256()).DeriveKeyPair([]byte(c.seed))
			}
			if err != nil {
				t.Fatal(err)
			}
			r, err := ParseTagRecipient(rcpts[i])
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(r.pub.Bytes(), priv.PublicKey().Bytes()) {
				t.Fatal("the recipient is not the derived key's")
			}
			point := r.encoded
			if c.pq {
				point = r.encoded[mlkem768EncapsSize:]
			}
			id := &tagIdentity{priv: priv, point: point, pq: c.pq}
			got, err := decrypt(readInterop(t, c.file), false, id)
			if err != nil || !bytes.Equal(got, interopPlaintext) {
				t.Fatalf("got %d bytes, %v", len(got), err)
			}
		})
	}
}

func TestIsArmoredLooksPastLeadingSpace(t *testing.T) {
	if !IsArmored([]byte("\n  \r\n"+armorBegin+"\n")) || IsArmored([]byte("age-encryption.org/v1\n")) {
		t.Error("IsArmored is wrong")
	}
	var b bytes.Buffer
	w := NewArmorWriter(&b)
	w.Close()
	if b.String() != armorBegin+"\n"+armorEnd+"\n" {
		t.Errorf("empty armor: %q", b.String())
	}
	if _, err := w.Write([]byte("x")); err == nil {
		t.Error("a write after Close")
	}
	if got, err := io.ReadAll(NewArmorReader(&b)); err != nil || len(got) != 0 {
		t.Errorf("reading empty armor: %q %v", got, err)
	}
}
