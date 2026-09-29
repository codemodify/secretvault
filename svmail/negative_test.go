package svmail

import (
	"bytes"
	"crypto/x509"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svpgp"
)

func TestRevokedAndExpiredPGPKeys(t *testing.T) {
	k, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: 4, UserIDs: []string{"Alice <alice@example.org>"}})
	if err != nil {
		t.Fatal(err)
	}
	out, err := SignPGPMIME([]byte(testMessage), k, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := k.Revoke(svpgp.RevocationCompromised, "stolen", time.Time{}); err != nil {
		t.Fatal(err)
	}
	r := inspect(t, out, &LocalKeys{PGP: []*svpgp.Key{k.Public()}})
	if s := r.Layers[0].Signatures[0]; s.Status != StatusRevokedKey || !s.Verified {
		t.Fatalf("revoked\n%s", dump(r))
	}

	// A key that expired before the signature was made.
	created := time.Now().Add(-2 * time.Hour)
	e, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: 4, UserIDs: []string{"Alice <alice@example.org>"}, Created: created, Lifetime: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SignPGPMIME([]byte(testMessage), e, nil); err == nil {
		t.Fatal("signed with an expired key")
	}
	out, err = SignPGPMIME([]byte(testMessage), e, &ComposeOptions{Time: created.Add(30 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	// Made while the key was valid: still good.
	r = inspect(t, out, &LocalKeys{PGP: []*svpgp.Key{e.Public()}})
	if s := r.Layers[0].Signatures[0]; s.Status != StatusValid {
		t.Fatalf("signed while valid\n%s", dump(r))
	}
}

// refusingKeys stands for a daemon whose person said no, or whose vault
// is locked.
type refusingKeys struct {
	NoKeys
	err error
	req *PGPDecryptRequest
}

func (k *refusingKeys) DecryptPGP(req *PGPDecryptRequest) (*svpgp.Message, error) {
	k.req = req
	return nil, k.err
}

func (k *refusingKeys) SMIMEContentKey(*svcms.Recipient) ([]byte, error) { return nil, k.err }

func TestDecryptionRefused(t *testing.T) {
	alice := pgpKey(t, "Alice <alice@example.org>")
	bob := pgpKey(t, "Bob <bob@example.org>")
	out, err := EncryptPGPMIME([]byte(testMessage), []*svpgp.Key{bob.Public()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	refused := errors.New("the person declined")
	k := &refusingKeys{err: refused}
	r := inspect(t, out, k)
	e := r.Layers[0].Encryption
	if e.Decrypted || e.Error != refused.Error() || !hasWarning(r, WarnDecryption) {
		t.Fatalf("\n%s", dump(r))
	}
	// The request named the recipient, so the daemon could say whose key.
	if len(k.req.Recipients) != 1 || k.req.Recipients[0].KeyID == 0 {
		t.Fatalf("request %+v", k.req)
	}
	found := false
	for _, s := range bob.Subkeys() {
		if s.KeyID == k.req.Recipients[0].KeyID {
			found = true
		}
	}
	if !found {
		t.Fatal("the request names another key")
	}
	_ = alice

	p := getPKI(t)
	sb := p.user(t, "bob@example.org")
	out, err = EncryptSMIME([]byte(testMessage), []*x509.Certificate{sb.cert}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r = inspect(t, out, k)
	if r.Layers[0].Encryption.Decrypted || r.Layers[0].Encryption.Error != refused.Error() {
		t.Fatalf("\n%s", dump(r))
	}
}

func TestNoMDC(t *testing.T) {
	// An SKESK and an SED packet (tag 9): encryption from before 2001,
	// with nothing to detect changes. Only the packet headers matter
	// here; the refusal comes from svpgp.
	var bin []byte
	bin = append(bin, 0xC3, 4, 4, 9, 3, 0)            // SKESK v4, AES-256, simple S2K
	bin = append(bin, 0xC9, 16)                       // SED
	bin = append(bin, bytes.Repeat([]byte{7}, 16)...) // its "ciphertext"
	var armored bytes.Buffer
	w, _ := svpgp.ArmorWriter(&armored, svpgp.BlockMessage, true)
	w.Write(bin)
	w.Close()
	msg := "From: alice@example.org\r\nContent-Type: text/plain\r\n\r\n" + armored.String()
	r := inspect(t, []byte(msg), &LocalKeys{})
	l := r.Layers[0]
	if l.Kind != KindEncryption || l.Encryption.Integrity != "none" || !hasWarning(r, WarnNoIntegrity) || l.Encryption.Decrypted ||
		!l.Encryption.Recipients[0].Passphrase {
		t.Fatalf("\n%s", dump(r))
	}
}

func TestHeaderMismatchFrom(t *testing.T) {
	alice := pgpKey(t, "Alice <alice@example.org>")
	out, err := SignPGPMIME([]byte(testMessage), alice, &ComposeOptions{ProtectHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	// Only the outer From changes: the signature still covers the
	// protected one, and says so.
	bad := bytes.Replace(out, []byte("From: Alice <alice@example.org>\r\nTo"), []byte("From: Alice <alice@evil.example>\r\nTo"), 1)
	if bytes.Equal(bad, out) {
		t.Fatal("nothing replaced")
	}
	r := inspect(t, bad, &LocalKeys{PGP: []*svpgp.Key{alice.Public()}})
	s := r.Layers[0].Signatures[0]
	if s.Status != StatusValid || !hasWarning(r, WarnHeaderMismatch) {
		t.Fatalf("\n%s", dump(r))
	}
	// The sender compared is the protected one.
	if !s.SenderMatch || s.SenderAddress != "alice@example.org" {
		t.Fatalf("sender %s %v", s.SenderAddress, s.SenderMatch)
	}
	var d *HeaderDiff
	for i := range r.Protected.Differences {
		if r.Protected.Differences[i].Name == "From" {
			d = &r.Protected.Differences[i]
		}
	}
	if d == nil || d.Kind != DiffMismatch || !strings.Contains(d.Outer, "evil") {
		t.Fatalf("differences %+v", r.Protected.Differences)
	}
}
