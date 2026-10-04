// Package webauthntest is a WebAuthn relying party for tests: it checks
// registrations and assertions as a server does (WebAuthn Level 3, §7.1
// and §7.2), from the specification's text, apart from svext's encoder,
// so that each checks the other. It speaks the standard library only
// (and the module's CBOR reader), and serves a page that registers and
// signs in with navigator.credentials (Handler).
package webauthntest

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/codemodify/secretvault/internal/cbor"
)

// Flags of authenticatorData.
const (
	UP = 0x01
	UV = 0x04
	BE = 0x08
	BS = 0x10
	AT = 0x40
	ED = 0x80
)

// Credential is a registered credential.
type Credential struct {
	ID        []byte
	Alg       int64
	PublicKey any // *ecdsa.PublicKey or ed25519.PublicKey
	AAGUID    []byte
	Flags     byte
	Count     uint32
}

// AuthData is authenticatorData taken apart.
type AuthData struct {
	RPIDHash []byte
	Flags    byte
	Count    uint32
	AAGUID   []byte
	CredID   []byte
	COSE     cbor.Map
}

var b64 = base64.RawURLEncoding

// ParseAuthData reads authenticatorData.
func ParseAuthData(b []byte) (*AuthData, error) {
	if len(b) < 37 {
		return nil, errors.New("authenticatorData: shorter than 37 bytes")
	}
	a := &AuthData{RPIDHash: b[:32], Flags: b[32], Count: binary.BigEndian.Uint32(b[33:37])}
	rest := b[37:]
	if a.Flags&AT != 0 {
		if len(rest) < 18 {
			return nil, errors.New("authenticatorData: attested credential data cut short")
		}
		a.AAGUID = rest[:16]
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		if n > 1023 || len(rest) < 18+n {
			return nil, errors.New("authenticatorData: a bad credential ID length")
		}
		a.CredID = rest[18 : 18+n]
		v, after, err := cbor.UnmarshalFirst(rest[18+n:])
		if err != nil {
			return nil, fmt.Errorf("authenticatorData: the public key: %w", err)
		}
		m, ok := v.(cbor.Map)
		if !ok {
			return nil, errors.New("authenticatorData: the public key is not a map")
		}
		a.COSE = m
		rest = after
	}
	if a.Flags&ED == 0 && len(rest) != 0 {
		return nil, errors.New("authenticatorData: bytes after it")
	}
	return a, nil
}

// PublicKey reads a COSE_Key: EC2 on P-256 with ES256, or OKP Ed25519
// with EdDSA.
func PublicKey(m cbor.Map) (int64, any, error) {
	kty, _ := m[int64(1)].(int64)
	alg, _ := m[int64(3)].(int64)
	crv, _ := m[int64(-1)].(int64)
	x, _ := m[int64(-2)].([]byte)
	switch {
	case kty == 2 && alg == -7 && crv == 1:
		y, _ := m[int64(-3)].([]byte)
		if len(x) != 32 || len(y) != 32 {
			return 0, nil, errors.New("COSE: an EC2 point of the wrong size")
		}
		pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
			return 0, nil, errors.New("COSE: the point is not on P-256")
		}
		return alg, pub, nil
	case kty == 1 && alg == -8 && crv == 6:
		if len(x) != ed25519.PublicKeySize {
			return 0, nil, errors.New("COSE: an Ed25519 key of the wrong size")
		}
		return alg, ed25519.PublicKey(x), nil
	}
	return 0, nil, fmt.Errorf("COSE: kty %d alg %d crv %d is not one this RP takes", kty, alg, crv)
}

// clientData checks clientDataJSON (§7.1 steps 7-10, §7.2 steps 11-14).
func clientData(raw []byte, typ, origin string, challenge []byte) error {
	var c struct {
		Type        string `json:"type"`
		Challenge   string `json:"challenge"`
		Origin      string `json:"origin"`
		CrossOrigin bool   `json:"crossOrigin"`
	}
	if err := json.Unmarshal(raw, &c); err != nil {
		return fmt.Errorf("clientDataJSON: %w", err)
	}
	if c.Type != typ {
		return fmt.Errorf("clientDataJSON: type %q", c.Type)
	}
	if c.Challenge != b64.EncodeToString(challenge) {
		return errors.New("clientDataJSON: another challenge")
	}
	if c.Origin != origin {
		return fmt.Errorf("clientDataJSON: origin %q, not %q", c.Origin, origin)
	}
	return nil
}

// RP is a relying party.
type RP struct {
	ID     string // its rpId
	Origin string // the origin its pages are on
}

func (rp *RP) checkAuthData(a *AuthData, requireUV bool) error {
	want := sha256.Sum256([]byte(rp.ID))
	if !bytes.Equal(a.RPIDHash, want[:]) {
		return errors.New("authenticatorData: rpIdHash is not this RP's")
	}
	if a.Flags&UP == 0 {
		return errors.New("authenticatorData: the user was not present")
	}
	if requireUV && a.Flags&UV == 0 {
		return errors.New("authenticatorData: the user was not verified")
	}
	if a.Flags&BS != 0 && a.Flags&BE == 0 {
		return errors.New("authenticatorData: backed up but not backup eligible")
	}
	return nil
}

// Challenge is a new challenge of 32 bytes.
func Challenge() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

// VerifyRegistration checks a registration (§7.1) with attestation
// "none", and returns the credential.
func (rp *RP) VerifyRegistration(clientDataJSON, attestationObject, challenge []byte, requireUV bool) (*Credential, error) {
	if err := clientData(clientDataJSON, "webauthn.create", rp.Origin, challenge); err != nil {
		return nil, err
	}
	v, err := cbor.Unmarshal(attestationObject)
	if err != nil {
		return nil, fmt.Errorf("attestationObject: %w", err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, errors.New("attestationObject: not a map")
	}
	if f, _ := m["fmt"].(string); f != "none" {
		return nil, fmt.Errorf("attestationObject: fmt %q", m["fmt"])
	}
	if st, ok := m["attStmt"].(cbor.Map); !ok || len(st) != 0 {
		return nil, errors.New("attestationObject: attStmt is not empty")
	}
	raw, _ := m["authData"].([]byte)
	a, err := ParseAuthData(raw)
	if err != nil {
		return nil, err
	}
	if err := rp.checkAuthData(a, requireUV); err != nil {
		return nil, err
	}
	if a.Flags&AT == 0 {
		return nil, errors.New("authenticatorData: no attested credential data")
	}
	alg, pub, err := PublicKey(a.COSE)
	if err != nil {
		return nil, err
	}
	return &Credential{ID: bytes.Clone(a.CredID), Alg: alg, PublicKey: pub, AAGUID: bytes.Clone(a.AAGUID), Flags: a.Flags, Count: a.Count}, nil
}

// VerifyAssertion checks an assertion (§7.2) by c.
func (rp *RP) VerifyAssertion(c *Credential, clientDataJSON, authData, signature, challenge []byte, requireUV bool) error {
	if err := clientData(clientDataJSON, "webauthn.get", rp.Origin, challenge); err != nil {
		return err
	}
	a, err := ParseAuthData(authData)
	if err != nil {
		return err
	}
	if err := rp.checkAuthData(a, requireUV); err != nil {
		return err
	}
	h := sha256.Sum256(clientDataJSON)
	msg := append(bytes.Clone(authData), h[:]...)
	switch pub := c.PublicKey.(type) {
	case *ecdsa.PublicKey:
		d := sha256.Sum256(msg)
		if !ecdsa.VerifyASN1(pub, d[:], signature) {
			return errors.New("the ES256 signature does not verify")
		}
	case ed25519.PublicKey:
		if !ed25519.Verify(pub, msg, signature) {
			return errors.New("the EdDSA signature does not verify")
		}
	default:
		return errors.New("no public key")
	}
	if (a.Count != 0 || c.Count != 0) && a.Count <= c.Count {
		return errors.New("the signature count did not grow")
	}
	return nil
}
