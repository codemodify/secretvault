package svcore

import (
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
)

// fido2 keyslots: a FIDO2 security key's hmac-secret opens the vault.
//
// The key-encryption key is derived from the 32 bytes the key computes
// from the slot's salt, which only that key, holding that credential, can
// compute (docs/format.md, "fido2"):
//
//	kek = Derive(hmac-secret output, vault id, "sv1 fido2 kek", 32)
//
// svcore holds no device code. Whoever adds or opens a fido2 slot passes
// SecurityKeys, which reaches the keys and the person: svfido in the
// daemon, a stand-in in tests.

// SecurityKeys reaches FIDO2 security keys for svcore. Both methods may
// wait on the person, for a PIN or a touch.
type SecurityKeys interface {
	// Enroll makes a new credential with the hmac-secret extension for
	// rpID, on a key the person picks, and evaluates it at salt, with user
	// verification when uv says so (nil: when the key has a PIN). A key
	// already holding one of exclude is refused: it is a keyslot already.
	Enroll(rpID string, uv *bool, salt []byte, exclude []FIDO2Credential) (FIDO2Enrolment, error)

	// Evaluate finds a key plugged in that holds one of creds, and
	// evaluates that credential's hmac-secret at its salt. It returns
	// which of creds answered, and the output, which the caller wipes.
	Evaluate(creds []FIDO2Credential) (int, []byte, error)
}

// FIDO2Credential is a fido2 keyslot's credential, as a key is asked
// about it.
type FIDO2Credential struct {
	ID   []byte
	RPID string
	Salt []byte // what the key evaluates: svformat.FIDO2Salt of the slot's salt
	UV   bool   // with user verification
}

// FIDO2Enrolment is a new credential and its first output.
type FIDO2Enrolment struct {
	ID     []byte
	AAGUID [16]byte
	UV     bool   // whether the key verified the person, and so must again
	Name   string // the key's name: the slot's label when none is given
	Output []byte // hmac-secret at the salt asked for
}

// enrolled is a fido2 slot's credential, made before the slot is sealed.
type enrolled struct {
	params svformat.FIDO2
	output []byte
}

// enroll asks the key for a new credential, for a fido2 slot about to be
// added. It is called without v.mu: the person may take a while. With
// noTwins, a key that already holds one of the current key's fido2 slots
// is refused (a rotation enrols the same keys again, for the new key).
func (v *Vault) enroll(ns *NewSlot, noTwins bool) error {
	if ns.SecurityKeys == nil {
		return errors.New("svcore: a fido2 slot needs a way to reach the security key")
	}
	var exclude []FIDO2Credential
	if noTwins {
		var err error
		if exclude, err = v.FIDO2Credentials(); err != nil {
			return err
		}
	}
	salt := svcrypto.RandomBytes(32)
	e, err := ns.SecurityKeys.Enroll(svformat.FIDO2RPID, ns.FIDO2UV, svformat.FIDO2Salt(salt), exclude)
	if err != nil {
		return err
	}
	if len(e.Output) != 32 || len(e.ID) == 0 || len(e.ID) > 1023 {
		clear(e.Output)
		return errors.New("svcore: the security key's enrolment is incomplete")
	}
	ns.enrolled = &enrolled{
		params: svformat.FIDO2{RPID: svformat.FIDO2RPID, Credential: e.ID, Salt: salt, UV: e.UV, AAGUID: e.AAGUID[:]},
		output: e.Output,
	}
	if ns.Label == "" {
		ns.Label = e.Name
		for len(ns.Label) > 256 {
			_, n := utf8.DecodeLastRuneInString(ns.Label)
			ns.Label = ns.Label[:len(ns.Label)-n]
		}
	}
	return nil
}

func (e *enrolled) wipe() {
	if e != nil {
		clear(e.output)
	}
}

// fido2KEK derives a fido2 slot's key-encryption key.
func (v *Vault) fido2KEK(output []byte) []byte {
	return svcrypto.Derive(output, v.desc.ID[:], "sv1 fido2 kek", svcrypto.KeySize)
}

// FIDO2Credentials lists the credentials of the vault's fido2 keyslots
// for the current key, or a newer one (a rotation made elsewhere, which a
// locked handle learns of only as it unlocks), as a key is asked about
// them. It works while locked, so a caller can look for a key before
// asking anyone anything.
func (v *Vault) FIDO2Credentials() ([]FIDO2Credential, error) {
	slots, err := v.slots()
	if err != nil {
		return nil, err
	}
	epoch := v.Epoch()
	var out []FIDO2Credential
	for _, s := range slots {
		if s.Type == svformat.SlotFIDO2 && s.Epoch >= epoch {
			out = append(out, credentialOf(s))
		}
	}
	return out, nil
}

func credentialOf(s *svformat.Slot) FIDO2Credential {
	return FIDO2Credential{ID: s.FIDO2.Credential, RPID: s.FIDO2.RPID, Salt: svformat.FIDO2Salt(s.FIDO2.Salt), UV: s.FIDO2.UV}
}

type securityKey struct{ keys SecurityKeys }

// SecurityKey is a key for fido2 slots: whichever of the vault's security
// keys is plugged in. The keys are asked once, for all the vault's fido2
// slots together, so one touch opens the vault whichever key it is.
func SecurityKey(keys SecurityKeys) Key { return securityKey{keys} }

func (securityKey) slotType() string { return svformat.SlotFIDO2 }

func (k securityKey) open(v *Vault, s *svformat.Slot) ([]byte, error) {
	_, master, err := k.pick(v, []*svformat.Slot{s})
	return master, err
}

// pick has the keys evaluate whichever of slots one of them holds, and
// opens that slot.
func (k securityKey) pick(v *Vault, slots []*svformat.Slot) (*svformat.Slot, []byte, error) {
	creds := make([]FIDO2Credential, len(slots))
	for i, s := range slots {
		creds[i] = credentialOf(s)
	}
	i, output, err := k.keys.Evaluate(creds)
	if err != nil {
		return nil, nil, err
	}
	defer clear(output)
	if i < 0 || i >= len(slots) {
		return nil, nil, fmt.Errorf("svcore: the security key answered for credential %d of %d", i, len(slots))
	}
	s := slots[i]
	kek := v.fido2KEK(output)
	defer clear(kek)
	master, err := v.suite.Open(kek, s.Wrapped, s.AAD())
	if err != nil {
		return nil, nil, ErrWrongKey
	}
	return s, master, nil
}

// slotPicker is a Key that answers for one of several slots at once.
type slotPicker interface {
	pick(v *Vault, slots []*svformat.Slot) (*svformat.Slot, []byte, error)
}
