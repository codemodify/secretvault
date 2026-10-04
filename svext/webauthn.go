package svext

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/codemodify/secretvault/internal/cbor"
)

// Passkeys: secretvault as a WebAuthn authenticator, through its
// extension (docs/browser.md, "Passkeys"). The extension intercepts a
// page's navigator.credentials.create and get, builds clientDataJSON
// from the origin the browser gives it, and asks the daemon; the daemon
// checks the request again here, keeps the private key, and signs. The
// key never leaves the daemon to sign in: only the public key and
// signatures do.
//
// What the daemon makes is what WebAuthn Level 3 (§6.1, §6.5) and CTAP
// 2.1 define:
//
//	authenticatorData   rpIdHash (32) | flags (1) | signCount (4, big-endian)
//	                    [ | AAGUID (16) | credIdLen (2) | credId | COSE key ]
//	attestationObject   {"fmt": "none", "attStmt": {}, "authData": ...} (CTAP2 canonical CBOR)
//	assertion signature over authenticatorData | SHA-256(clientDataJSON):
//	                    ES256 as ASN.1 DER, EdDSA (Ed25519) as 64 bytes
//
// The credential is "backup eligible" and "backed up" (BE, BS): it lives
// in a vault, which may be synced to other devices. Its signature count is
// always 0, as a synced credential's must be (no one device can keep a
// counter that only grows). UP is set: the person chose the passkey in
// secretvault's own window. UV is set only when secretvault verified the
// person for this request (they typed the vault's passphrase).

// AAGUID identifies secretvault as an authenticator model, the same for
// every installation: 147e5391-634b-4919-8f0a-d0c353e3a97f. It was made
// once, at random, and must not change.
var AAGUID = [16]byte{0x14, 0x7e, 0x53, 0x91, 0x63, 0x4b, 0x49, 0x19, 0x8f, 0x0a, 0xd0, 0xc3, 0x53, 0xe3, 0xa9, 0x7f}

// authenticatorData flags (WebAuthn §6.1).
const (
	FlagUP byte = 0x01 // user present
	FlagUV byte = 0x04 // user verified
	FlagBE byte = 0x08 // backup eligible
	FlagBS byte = 0x10 // backed up
	FlagAT byte = 0x40 // attested credential data included
	FlagED byte = 0x80 // extension data included
)

// COSE algorithms secretvault makes passkeys with.
const (
	AlgES256 = -7 // ECDSA with P-256 and SHA-256
	AlgEdDSA = -8 // Ed25519
)

// AlgName names an algorithm as items keep it.
func AlgName(alg int) string {
	switch alg {
	case AlgES256:
		return "ES256"
	case AlgEdDSA:
		return "EdDSA"
	}
	return ""
}

// AlgOf reads an algorithm's name back.
func AlgOf(name string) (int, bool) {
	switch name {
	case "ES256":
		return AlgES256, true
	case "EdDSA":
		return AlgEdDSA, true
	}
	return 0, false
}

// ChooseAlgorithm is the first algorithm of the RP's list (in its order
// of preference) that secretvault can make; ok is false when there is
// none. An empty list means ES256 and RS256 (WebAuthn §5.4.3's default).
func ChooseAlgorithm(rp []int) (int, bool) {
	if len(rp) == 0 {
		return AlgES256, true
	}
	for _, a := range rp {
		if a == AlgES256 || a == AlgEdDSA {
			return a, true
		}
	}
	return 0, false
}

// Limits of what a passkey request carries.
const (
	MaxRPID          = 253
	MaxCredentialID  = 1023 // WebAuthn §4: at most 1023 bytes
	MaxUserHandle    = 64   // §5.4.3: at most 64 bytes
	MaxClientData    = 8192
	MaxCredentialIDs = 64 // in an allow or exclude list
	MaxAlgorithms    = 16
	MinChallenge     = 16 // §13.4.3: at least 16 random bytes
	CredentialIDLen  = 16 // what secretvault makes
)

// ErrRPID is an rpId the origin may not use.
var ErrRPID = errors.New("the relying party ID does not fit the page's origin")

// ErrInsecure is an origin WebAuthn does not run in: neither https, nor
// http on localhost.
var ErrInsecure = errors.New("passkeys need a secure page (https, or http on localhost)")

// SecureOrigin reports whether o is a secure context WebAuthn runs in,
// with a domain (not an address) for its host: https, or http on
// localhost or a name under .localhost.
func SecureOrigin(o Origin) bool {
	if net.ParseIP(o.Host) != nil || o.Host == "" {
		return false
	}
	switch o.Scheme {
	case "https":
		return true
	case "http":
		return o.Host == "localhost" || strings.HasSuffix(o.Host, ".localhost")
	}
	return false
}

// CheckRPID checks that rpID may be used by a page at origin o, by
// WebAuthn's rules (§5.1.3, §5.1.4: the HTML standard's "is a registrable
// domain suffix of or is equal to"), with the bundled Public Suffix List:
//
//   - the page must be a secure context, its host a domain;
//   - rpID must be written as browsers write hosts (ASCII, lower case);
//   - it is the page's host itself; or the page's host ends with "." and
//     rpID, and rpID is neither a public suffix nor a suffix of the
//     host's public suffix (so "github.io" is no one's rpID, nor "co.uk").
func CheckRPID(l *SuffixList, rpID string, o Origin) error {
	if !SecureOrigin(o) {
		return ErrInsecure
	}
	if rpID == "" || len(rpID) > MaxRPID || net.ParseIP(rpID) != nil {
		return ErrRPID
	}
	if a, ok := asciiHost(rpID); !ok || a != rpID || strings.HasSuffix(rpID, ".") {
		return ErrRPID
	}
	host := o.Host
	if rpID == host {
		return nil
	}
	if !strings.HasSuffix(host, "."+rpID) {
		return ErrRPID
	}
	ps := l.PublicSuffix(host)
	if rpID == l.PublicSuffix(rpID) || ps == rpID || strings.HasSuffix(ps, "."+rpID) {
		return ErrRPID
	}
	return nil
}

// ClientData is what the daemon reads of clientDataJSON (WebAuthn
// §5.8.1), which the extension builds from the browser's word for the
// page's origin.
type ClientData struct {
	Type        string `json:"type"`
	Challenge   string `json:"challenge"`
	Origin      string `json:"origin"`
	CrossOrigin bool   `json:"crossOrigin"`
	TopOrigin   string `json:"topOrigin,omitempty"`
}

// Client data types.
const (
	ClientCreate = "webauthn.create"
	ClientGet    = "webauthn.get"
)

// CheckClientData reads clientDataJSON and checks it says what the
// request says: its type, the page's origin, a challenge of at least 16
// bytes, and, for a frame of another origin than its page, that page's
// origin. It returns SHA-256 of the bytes, which is what is signed.
func CheckClientData(raw []byte, typ string, o Origin) ([32]byte, error) {
	var zero [32]byte
	if len(raw) == 0 || len(raw) > MaxClientData {
		return zero, Errorf(CodeBadRequest, "clientData: 1 to %d bytes", MaxClientData)
	}
	var c ClientData
	if err := json.Unmarshal(raw, &c); err != nil {
		return zero, Errorf(CodeBadRequest, "clientData: not JSON")
	}
	if c.Type != typ {
		return zero, Errorf(CodeBadRequest, "clientData: of type %q, not %q", c.Type, typ)
	}
	if c.Origin != o.String() {
		return zero, Errorf(CodeBadRequest, "clientData: for %q, not the request's origin", c.Origin)
	}
	ch, err := base64.RawURLEncoding.DecodeString(c.Challenge)
	if err != nil || len(ch) < MinChallenge {
		return zero, Errorf(CodeBadRequest, "clientData: a challenge of at least %d bytes, base64url", MinChallenge)
	}
	if c.CrossOrigin {
		if _, err := ParseOrigin(c.TopOrigin); err != nil {
			return zero, Errorf(CodeBadRequest, "clientData: a cross-origin frame names its page's origin")
		}
	} else if c.TopOrigin != "" {
		return zero, Errorf(CodeBadRequest, "clientData: topOrigin only for a cross-origin frame")
	}
	// And it is exactly what the extension writes (lib/webauthn.js), member
	// for member and byte for byte: no member twice, in another case, or
	// more, which a relying party might read otherwise than this does.
	if !bytes.Equal(raw, clientDataJSON(c)) {
		return zero, Errorf(CodeBadRequest, "clientData: not as the extension writes it")
	}
	return sha256.Sum256(raw), nil
}

// clientDataJSON writes clientDataJSON as WebAuthn's §5.8.1.1 orders it,
// as the extension does.
func clientDataJSON(c ClientData) []byte {
	q := func(s string) string {
		b, _ := json.Marshal(s)
		return string(b)
	}
	s := `{"type":` + q(c.Type) + `,"challenge":` + q(c.Challenge) + `,"origin":` + q(c.Origin) + `,"crossOrigin":`
	if c.CrossOrigin {
		s += `true,"topOrigin":` + q(c.TopOrigin)
	} else {
		s += "false"
	}
	return []byte(s + "}")
}

// AuthenticatorData is authenticatorData for rpID, with flags and the
// signature count; attested (AttestedCredentialData) is added, with the
// AT flag, when it is not nil.
func AuthenticatorData(rpID string, flags byte, count uint32, attested []byte) []byte {
	h := sha256.Sum256([]byte(rpID))
	out := make([]byte, 0, 37+len(attested))
	out = append(out, h[:]...)
	if attested != nil {
		flags |= FlagAT
	}
	out = append(out, flags)
	out = binary.BigEndian.AppendUint32(out, count)
	return append(out, attested...)
}

// AttestedCredentialData is AAGUID | credIdLen | credId | the COSE key.
func AttestedCredentialData(credID, coseKey []byte) []byte {
	out := make([]byte, 0, 18+len(credID)+len(coseKey))
	out = append(out, AAGUID[:]...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(credID)))
	out = append(out, credID...)
	return append(out, coseKey...)
}

// AttestationObject is the attestation object of format "none" for
// authData.
func AttestationObject(authData []byte) []byte {
	b, err := cbor.Marshal(cbor.Map{"fmt": "none", "attStmt": cbor.Map{}, "authData": authData})
	if err != nil {
		panic(err) // nothing in it can fail to encode
	}
	return b
}

// KeyPair is a passkey's key pair as the daemon makes and keeps it.
type KeyPair struct {
	Alg     int
	Private []byte // PKCS #8, DER: the caller wipes it
	COSE    []byte // the public key, a COSE_Key
	SPKI    []byte // the public key, SubjectPublicKeyInfo DER (getPublicKey())
}

// NewKeyPair makes a key pair for alg.
func NewKeyPair(alg int) (*KeyPair, error) {
	var priv any
	switch alg {
	case AlgES256:
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		priv = k
	case AlgEdDSA:
		_, k, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		priv = k
	default:
		return nil, fmt.Errorf("no passkey algorithm %d", alg)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pk, err := PublicOf(der)
	if err != nil {
		clear(der)
		return nil, err
	}
	pk.Private = der
	return pk, nil
}

// PublicOf is the public half of a PKCS #8 private key, with its
// algorithm; Private is left empty.
func PublicOf(pkcs8 []byte) (*KeyPair, error) {
	k, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("a passkey's private key: %w", err)
	}
	pk := &KeyPair{}
	var pub any
	switch k := k.(type) {
	case *ecdsa.PrivateKey:
		if k.Curve != elliptic.P256() {
			return nil, errors.New("a passkey's private key: an EC key not on P-256")
		}
		e, err := k.PublicKey.ECDH()
		if err != nil {
			return nil, err
		}
		pt := e.Bytes() // 04 | X | Y
		pk.Alg = AlgES256
		pk.COSE, _ = cbor.Marshal(cbor.Map{1: 2, 3: AlgES256, -1: 1, -2: bytes.Clone(pt[1:33]), -3: bytes.Clone(pt[33:65])})
		pub = &k.PublicKey
	case ed25519.PrivateKey:
		p := k.Public().(ed25519.PublicKey)
		pk.Alg = AlgEdDSA
		pk.COSE, _ = cbor.Marshal(cbor.Map{1: 1, 3: AlgEdDSA, -1: 6, -2: []byte(p)})
		pub = p
	default:
		return nil, fmt.Errorf("a passkey's private key: a %T, not P-256 or Ed25519", k)
	}
	if pk.SPKI, err = x509.MarshalPKIXPublicKey(pub); err != nil {
		return nil, err
	}
	return pk, nil
}

// SignAssertion signs authData | clientDataHash with a PKCS #8 key, as
// WebAuthn's assertion signature (§6.3.3 step 11): ES256 as ASN.1 DER,
// Ed25519 as its 64 bytes.
func SignAssertion(pkcs8, authData []byte, clientDataHash [32]byte) ([]byte, error) {
	k, err := x509.ParsePKCS8PrivateKey(pkcs8)
	if err != nil {
		return nil, fmt.Errorf("a passkey's private key: %w", err)
	}
	msg := make([]byte, 0, len(authData)+32)
	msg = append(append(msg, authData...), clientDataHash[:]...)
	switch k := k.(type) {
	case *ecdsa.PrivateKey:
		h := sha256.Sum256(msg)
		return ecdsa.SignASN1(rand.Reader, k, h[:])
	case ed25519.PrivateKey:
		defer clear(k)
		return ed25519.Sign(k, msg), nil
	}
	return nil, fmt.Errorf("a passkey's private key: a %T", k)
}

// NewCredentialID is a new credential's ID: 16 random bytes.
func NewCredentialID() []byte {
	b := make([]byte, CredentialIDLen)
	rand.Read(b)
	return b
}

// B64 is base64url without padding, as WebAuthn's JSON and CXF write
// binary.
var B64 = base64.RawURLEncoding

// UnB64 reads base64url, with or without padding.
func UnB64(s string) ([]byte, error) {
	return B64.DecodeString(strings.TrimRight(s, "="))
}
