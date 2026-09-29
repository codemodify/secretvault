package svpgp

import (
	"bytes"
	"errors"
	"slices"
	"strings"
	"testing"
)

func TestEncryptedToNamesTheEncryptionSubkeys(t *testing.T) {
	v4 := generate(t, KeyOptions{Version: 4, UserIDs: []string{"Bob <bob@example.org>"}})
	v6 := generate(t, KeyOptions{Version: 6, UserIDs: []string{"Carol <carol@example.org>"}})
	sub := func(k *Key) SubkeyInfo {
		for _, s := range k.Subkeys() {
			if s.CanEncrypt {
				return s
			}
		}
		t.Fatalf("%v has no encryption subkey", k)
		return SubkeyInfo{}
	}

	// Version 3 session key packets name key IDs (v1 SEIPD).
	r, err := EncryptedTo(bytes.NewReader(encrypted(t, []*Key{v4.Public(), v6.Public()}, "hi", EncryptOptions{Armor: true, Passphrase: []byte("sesame")})))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(r.KeyIDs, []uint64{sub(v4).KeyID, sub(v6).KeyID}) || len(r.Fingerprints) != 0 || !r.Passphrase || r.Anonymous {
		t.Fatalf("v1 message: %+v", r)
	}

	// Version 6 ones name fingerprints (v2 SEIPD).
	r, err = EncryptedTo(bytes.NewReader(encrypted(t, []*Key{v6.Public()}, "hi", EncryptOptions{})))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Fingerprints) != 1 || !bytes.Equal(r.Fingerprints[0], sub(v6).Fingerprint) || len(r.KeyIDs) != 0 || r.Passphrase {
		t.Fatalf("v2 message: %+v", r)
	}

	// Signed and cleartext messages are not encrypted.
	for _, msg := range [][]byte{
		signed(t, v6, "hi", SignOptions{Mode: SignInline, Armor: true}),
		signed(t, v6, "hi", SignOptions{Mode: SignCleartext}),
		[]byte("not openpgp at all"),
	} {
		if _, err := EncryptedTo(bytes.NewReader(msg)); !errors.Is(err, ErrNotEncrypted) && !errors.Is(err, ErrMalformed) {
			t.Fatalf("%.30q: %v", msg, err)
		}
	}
	if _, err := EncryptedTo(strings.NewReader("")); err == nil {
		t.Fatal("an empty message named recipients")
	}
}
