package svcore

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"testing"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// token stands in for a FIDO2 key: credentials are random secrets it
// keeps, and hmac-secret is HMAC-SHA-256 of the salt under the one
// chosen by whether the PIN was used, as on a real key.
type token struct {
	name      string
	plugged   bool
	withPIN   bool                 // it has a PIN, and uses it by default
	creds     map[string][2][]byte // credential ID → CredRandom without, with UV
	enrolls   int
	evaluated []int // which credential answered, each time
	lie       bool  // answer with the wrong secret
}

var errNotHere = errors.New("test: no key holds any of those credentials")

func newToken(name string) *token {
	return &token{name: name, plugged: true, creds: map[string][2][]byte{}}
}

func (k *token) Enroll(rpID string, uv *bool, salt []byte, exclude []FIDO2Credential) (FIDO2Enrolment, error) {
	if !k.plugged {
		return FIDO2Enrolment{}, errors.New("test: no key plugged in")
	}
	for _, c := range exclude {
		if _, ok := k.creds[string(c.ID)]; ok {
			return FIDO2Enrolment{}, errors.New("test: already enrolled")
		}
	}
	if rpID != svformat.FIDO2RPID || len(salt) != 32 {
		return FIDO2Enrolment{}, errors.New("test: a bad request")
	}
	k.enrolls++
	id := svcrypto.RandomBytes(40)
	k.creds[string(id)] = [2][]byte{svcrypto.RandomKey(), svcrypto.RandomKey()}
	useUV := k.withPIN
	if uv != nil {
		useUV = *uv
	}
	return FIDO2Enrolment{ID: id, AAGUID: [16]byte{0xaa}, UV: useUV, Name: k.name, Output: k.hmac(id, useUV, salt)}, nil
}

func (k *token) hmac(id []byte, uv bool, salt []byte) []byte {
	r := k.creds[string(id)][0]
	if uv {
		r = k.creds[string(id)][1]
	}
	m := hmac.New(sha256.New, r)
	m.Write(salt)
	out := m.Sum(nil)
	if k.lie {
		out[0] ^= 1
	}
	return out
}

func (k *token) Evaluate(creds []FIDO2Credential) (int, []byte, error) {
	if !k.plugged {
		return 0, nil, errNotHere
	}
	for i, c := range creds {
		if _, ok := k.creds[string(c.ID)]; ok {
			k.evaluated = append(k.evaluated, i)
			return i, k.hmac(c.ID, c.UV, c.Salt), nil
		}
	}
	return 0, nil, errNotHere
}

// both is two keys plugged in at once.
type both [2]*token

func (b both) Enroll(string, *bool, []byte, []FIDO2Credential) (FIDO2Enrolment, error) {
	return FIDO2Enrolment{}, errors.New("test: not here")
}

func (b both) Evaluate(creds []FIDO2Credential) (int, []byte, error) {
	for _, k := range b {
		if i, out, err := k.Evaluate(creds); err == nil {
			return i, out, nil
		}
	}
	return 0, nil, errNotHere
}

func TestASecurityKeyOpensTheVault(t *testing.T) {
	for _, suite := range []svcrypto.Suite{svcrypto.Modern, svcrypto.NIST} {
		t.Run(suite.String(), func(t *testing.T) {
			store := svstore.NewMem()
			v := newVault(t, store, suite)
			if _, err := v.Put(login("github.com", "hunter2")); err != nil {
				t.Fatal(err)
			}
			key := newToken("YubiKey 5")
			info, err := v.AddSlot(NewSlot{Type: svformat.SlotFIDO2, SecurityKeys: key})
			if err != nil {
				t.Fatal(err)
			}
			if info.Label != "YubiKey 5" || info.FIDO2 == nil || info.FIDO2.RPID != "secretvault:" || info.FIDO2.UV ||
				len(info.FIDO2.Salt) != 32 || info.FIDO2.AAGUID[0] != 0xaa {
				t.Fatalf("slot %+v %+v", info, info.FIDO2)
			}
			v.Lock()

			w, err := Open(store, Options{})
			if err != nil {
				t.Fatal(err)
			}
			if err := w.Unlock(SecurityKey(key)); err != nil {
				t.Fatal(err)
			}
			if w.UnlockedBy() != info.ID {
				t.Fatal("the vault does not say the security key opened it")
			}
			if e, err := w.Get("github.com"); err != nil || secretOf(t, e) != "hunter2" {
				t.Fatalf("Get = %v", err)
			}
			if err := w.CheckKey(SecurityKey(key)); err != nil {
				t.Fatalf("CheckKey: %v", err)
			}
		})
	}
}

func TestTheWrongKeyOrAWrongAnswerDoesNotOpen(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, 0)
	key := newToken("mine")
	if _, err := v.AddSlot(NewSlot{Type: svformat.SlotFIDO2, SecurityKeys: key}); err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if err := v.Unlock(SecurityKey(newToken("theirs"))); !errors.Is(err, errNotHere) || !v.Locked() {
		t.Fatalf("another key: %v", err)
	}
	key.lie = true
	if err := v.Unlock(SecurityKey(key)); !errors.Is(err, ErrWrongKey) || !v.Locked() {
		t.Fatalf("a wrong answer: %v", err)
	}
	// A vault without fido2 slots says so.
	other := newVault(t, svstore.NewMem(), 0)
	other.Lock()
	if err := other.Unlock(SecurityKey(key)); !errors.Is(err, ErrWrongKey) {
		t.Fatalf("no fido2 slot: %v", err)
	}
}

// Each fido2 field is bound into the slot's AAD: a slot file changed to
// point elsewhere, or relabelled, no longer opens, even where the key's
// answer would be the same (the AAGUID, the label).
func TestATamperedFIDO2SlotDoesNotOpen(t *testing.T) {
	for name, change := range map[string]func(s *svformat.Slot){
		"label":  func(s *svformat.Slot) { s.Label = "evil" },
		"aaguid": func(s *svformat.Slot) { s.FIDO2.AAGUID[1] ^= 1 },
		"uv":     func(s *svformat.Slot) { s.FIDO2.UV = !s.FIDO2.UV },
		"rp":     func(s *svformat.Slot) { s.FIDO2.RPID = "evil:" },
		"salt":   func(s *svformat.Slot) { s.FIDO2.Salt[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			store := svstore.NewMem()
			v := newVault(t, store, 0)
			key := newToken("k")
			info, err := v.AddSlot(NewSlot{Type: svformat.SlotFIDO2, SecurityKeys: key})
			if err != nil {
				t.Fatal(err)
			}
			v.Lock()
			b, _ := store.Read(svformat.SlotName(info.ID))
			s, err := svformat.ParseSlot(b)
			if err != nil {
				t.Fatal(err)
			}
			change(s)
			b, _ = json.Marshal(s)
			store.Remove(svformat.SlotName(info.ID))
			if err := store.Create(svformat.SlotName(info.ID), b); err != nil {
				t.Fatal(err)
			}
			if err := v.Unlock(SecurityKey(key)); !errors.Is(err, ErrWrongKey) || !v.Locked() {
				t.Fatalf("a slot with its %s changed: %v", name, err)
			}
		})
	}
}

func TestOfTwoKeysEitherOpensTheVault(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, 0)
	a, b := newToken("A"), newToken("B")
	b.withPIN = true
	sa, err := v.AddSlot(NewSlot{Type: svformat.SlotFIDO2, SecurityKeys: a})
	if err != nil {
		t.Fatal(err)
	}
	sb, err := v.AddSlot(NewSlot{Type: svformat.SlotFIDO2, SecurityKeys: b, Label: "backup"})
	if err != nil {
		t.Fatal(err)
	}
	if !sb.FIDO2.UV || sb.Label != "backup" {
		t.Fatalf("B's slot %+v", sb.FIDO2)
	}
	creds, err := v.FIDO2Credentials()
	if err != nil || len(creds) != 2 || !bytes.Equal(creds[0].Salt, svformat.FIDO2Salt(sa.FIDO2.Salt)) || !creds[1].UV {
		t.Fatalf("FIDO2Credentials = %+v, %v", creds, err)
	}
	// Enrolling a key twice is refused: it is told the vault's credentials.
	if _, err := v.AddSlot(NewSlot{Type: svformat.SlotFIDO2, SecurityKeys: a}); err == nil {
		t.Fatal("the same key was enrolled twice")
	}
	for _, k := range []Key{SecurityKey(b), SecurityKey(both{a, b}), SecurityKey(a)} {
		v.Lock()
		if err := v.Unlock(k); err != nil {
			t.Fatal(err)
		}
	}
	if v.UnlockedBy() != sa.ID || len(b.evaluated) != 1 || b.evaluated[0] != 1 || len(a.evaluated) != 2 || a.evaluated[0] != 0 {
		t.Fatalf("A answered %v, B %v", a.evaluated, b.evaluated)
	}
}

func TestAddingASecurityKeyNeedsTheVaultOpen(t *testing.T) {
	v := newVault(t, svstore.NewMem(), 0)
	v.Lock()
	key := newToken("k")
	if _, err := v.AddSlot(NewSlot{Type: svformat.SlotFIDO2, SecurityKeys: key}); !errors.Is(err, ErrLocked) || key.enrolls != 0 {
		t.Fatalf("while locked: %v, %d enrolments", err, key.enrolls)
	}
	if err := v.Unlock(Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	if _, err := v.AddSlot(NewSlot{Type: svformat.SlotFIDO2}); err == nil {
		t.Fatal("a fido2 slot without a way to reach the key")
	}
}

// A rotation seals the new key for the security keys it is given, which
// takes their touch; the old key's fido2 slots go with the old key.
func TestARotationTakesSecurityKeysOnlyWhenGiven(t *testing.T) {
	store := svstore.NewMem()
	v := newVault(t, store, 0)
	a, b := newToken("A"), newToken("B")
	for _, k := range []*token{a, b} {
		if _, err := v.AddSlot(NewSlot{Type: svformat.SlotFIDO2, SecurityKeys: k}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := v.Rotate([]NewSlot{{Type: svformat.SlotPassphrase, Passphrase: pass}, {Type: svformat.SlotFIDO2, SecurityKeys: a}}, true, nil)
	if err != nil {
		t.Fatal(err)
	}
	v.Lock()
	if err := v.Unlock(SecurityKey(a)); err != nil {
		t.Fatalf("A after the rotation: %v", err)
	}
	v.Lock()
	if err := v.Unlock(SecurityKey(b)); err == nil {
		t.Fatal("B, not given to the rotation, still opens the vault")
	}
}
