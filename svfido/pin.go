package svfido

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"unicode/utf8"

	"github.com/codemodify/secretvault/internal/cbor"
)

// PIN/UV auth protocols (CTAP 2.1 §6.5). Both start from an ECDH
// agreement on P-256 between an ephemeral key of ours and the device's
// key-agreement key; Z is the x-coordinate of the shared point.
//
//	protocol 1   shared secret = SHA-256(Z)
//	             encrypt = AES-256-CBC, IV of zeros; authenticate = first
//	             16 bytes of HMAC-SHA-256
//	protocol 2   shared secret = HKDF-SHA-256(salt 32 zeros, Z, "CTAP2 HMAC key", 32)
//	                          || HKDF-SHA-256(salt 32 zeros, Z, "CTAP2 AES key", 32)
//	             encrypt = random IV || AES-256-CBC under the AES half;
//	             authenticate = HMAC-SHA-256 under the HMAC half (or the
//	             whole of a PIN token), all 32 bytes
//
// The same shared secret protects PINs on their way in, PIN tokens on
// their way out, and hmac-secret salts and outputs.

type pinProtocol int

var zeroSalt = make([]byte, 32)

// kdf turns Z into the shared secret.
func (p pinProtocol) kdf(z []byte) []byte {
	if p == 1 {
		s := sha256.Sum256(z)
		return s[:]
	}
	hmacKey, err1 := hkdf.Key(sha256.New, z, zeroSalt, "CTAP2 HMAC key", 32)
	aesKey, err2 := hkdf.Key(sha256.New, z, zeroSalt, "CTAP2 AES key", 32)
	if err1 != nil || err2 != nil {
		panic("svfido: HKDF of 32 bytes failed") // impossible for these lengths
	}
	return append(hmacKey, aesKey...)
}

// aesKey is the part of a shared secret that encrypts.
func (p pinProtocol) aesKey(key []byte) []byte {
	if p == 2 {
		return key[32:]
	}
	return key
}

func (p pinProtocol) encrypt(key, plaintext []byte) ([]byte, error) {
	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("svfido: plaintext is not a whole number of blocks")
	}
	block, err := aes.NewCipher(p.aesKey(key))
	if err != nil {
		return nil, err
	}
	iv := make([]byte, aes.BlockSize)
	if p == 2 {
		rand.Read(iv)
	}
	out := make([]byte, len(plaintext))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, plaintext)
	if p == 2 {
		return append(iv, out...), nil
	}
	return out, nil
}

func (p pinProtocol) decrypt(key, ciphertext []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if p == 2 {
		if len(ciphertext) < aes.BlockSize {
			return nil, malformed("a ciphertext shorter than its IV")
		}
		iv, ciphertext = ciphertext[:aes.BlockSize], ciphertext[aes.BlockSize:]
	}
	if len(ciphertext) == 0 || len(ciphertext)%aes.BlockSize != 0 {
		return nil, malformed("a ciphertext of %d bytes", len(ciphertext))
	}
	block, err := aes.NewCipher(p.aesKey(key))
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(ciphertext))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(out, ciphertext)
	return out, nil
}

// authenticate MACs message under a shared secret or a PIN token.
func (p pinProtocol) authenticate(key, message []byte) []byte {
	if p == 2 && len(key) == 64 {
		key = key[:32]
	}
	m := hmac.New(sha256.New, key)
	m.Write(message)
	sum := m.Sum(nil)
	if p == 1 {
		return sum[:16]
	}
	return sum
}

// coseKey is a P-256 public key as CTAP sends key-agreement keys: a
// COSE_Key with alg -25 (ECDH-ES+HKDF-256, which the spec names for form's
// sake whatever the protocol).
func coseKey(pub *ecdh.PublicKey) cbor.Map {
	b := pub.Bytes() // 0x04 || x || y
	return cbor.Map{
		int64(1):  int64(2),   // kty: EC2
		int64(3):  int64(-25), // alg
		int64(-1): int64(1),   // crv: P-256
		int64(-2): b[1:33],
		int64(-3): b[33:65],
	}
}

// parseCOSEKey reads a device's key-agreement key, which must be a point
// on P-256.
func parseCOSEKey(v any) (*ecdh.PublicKey, error) {
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, malformed("a key-agreement key that is not a map")
	}
	kty, _ := m[int64(1)].(int64)
	crv, _ := m[int64(-1)].(int64)
	x, _ := m[int64(-2)].([]byte)
	y, _ := m[int64(-3)].([]byte)
	if kty != 2 || crv != 1 || len(x) != 32 || len(y) != 32 {
		return nil, malformed("a key-agreement key that is not P-256")
	}
	pub, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, malformed("a key-agreement key off the curve")
	}
	return pub, nil
}

// shared is one key agreement with a device.
type shared struct {
	proto  pinProtocol
	ours   cbor.Map // our ephemeral public key, as sent
	secret []byte
}

func (s *shared) wipe() { clear(s.secret) }

// ClientPIN subcommands and parameters (CTAP 2.1 §6.5.5).
const (
	cmdClientPIN = 0x06

	pinGetRetries        = 0x01
	pinGetKeyAgreement   = 0x02
	pinGetPINToken       = 0x05
	pinGetTokenWithPerms = 0x09

	pinParamProtocol     = 0x01
	pinParamSubCommand   = 0x02
	pinParamKeyAgreement = 0x03
	pinParamPINHashEnc   = 0x06
	pinParamPermissions  = 0x09
	pinParamRPID         = 0x0A
)

// agree makes a key agreement with the device, in its preferred protocol.
func (d *Device) agree(ctx context.Context) (*shared, error) {
	proto := d.protocol()
	resp, err := d.command(ctx, cmdClientPIN, cbor.Map{
		pinParamProtocol:   int64(proto),
		pinParamSubCommand: int64(pinGetKeyAgreement),
	}, nil)
	if err != nil {
		return nil, err
	}
	theirs, err := parseCOSEKey(resp[int64(1)])
	if err != nil {
		return nil, err
	}
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	z, err := priv.ECDH(theirs)
	if err != nil {
		return nil, malformed("key agreement failed: %v", err)
	}
	defer clear(z)
	return &shared{proto: proto, ours: coseKey(priv.PublicKey()), secret: proto.kdf(z)}, nil
}

// PINRetries is how many wrong PINs the device still takes before it
// blocks its PIN for good.
func (d *Device) PINRetries(ctx context.Context) (int, error) {
	resp, err := d.command(ctx, cmdClientPIN, cbor.Map{
		pinParamProtocol:   int64(d.protocol()),
		pinParamSubCommand: int64(pinGetRetries),
	}, nil)
	if err != nil {
		return 0, err
	}
	n, ok := resp[int64(3)].(int64)
	if !ok || n < 0 || n > 255 {
		return 0, malformed("getRetries without a count")
	}
	return int(n), nil
}

// Permission is what a CTAP 2.1 PIN token may be used for.
type Permission byte

const (
	PermMakeCredential Permission = 0x01
	PermGetAssertion   Permission = 0x02
)

// PINLengthError is a PIN refused before it is sent, so it costs none of
// the device's retries.
type PINLengthError struct {
	Min int // characters
	Max int // bytes
}

func (e *PINLengthError) Error() string {
	return fmt.Sprintf("a PIN for this security key is %d characters or more, and at most %d bytes", e.Min, e.Max)
}

// PINToken is proof, for a while, that the PIN was given to one device.
// It is bound to that device, and to the permissions and site it was
// asked for; a CTAP 2.1 token is good for one command.
type PINToken struct {
	dev    *Device
	proto  pinProtocol
	token  []byte
	perms  Permission
	rpID   string
	scoped bool // a CTAP 2.1 token, whose permissions the device clears after one use
	used   bool
}

// Wipe forgets the token.
func (t *PINToken) Wipe() {
	if t != nil {
		clear(t.token)
		t.used = true
	}
}

// param computes pinUvAuthParam over clientDataHash for one command,
// refusing any use the token was not issued for.
func (t *PINToken) param(dev *Device, perm Permission, rpID string, clientDataHash []byte) ([]byte, error) {
	switch {
	case t.dev != dev:
		return nil, fmt.Errorf("%w: it was issued by another security key", ErrTokenMisuse)
	case t.used:
		return nil, fmt.Errorf("%w: it has been used up", ErrTokenMisuse)
	case t.scoped && t.perms&perm == 0:
		return nil, fmt.Errorf("%w: it was not issued for this command", ErrTokenMisuse)
	case t.scoped && t.rpID != "" && t.rpID != rpID:
		return nil, fmt.Errorf("%w: it was issued for %q", ErrTokenMisuse, t.rpID)
	case len(clientDataHash) != 32:
		return nil, fmt.Errorf("%w: the client data hash is %d bytes", ErrTokenMisuse, len(clientDataHash))
	}
	if t.scoped {
		t.used = true
	}
	return t.proto.authenticate(t.token, clientDataHash), nil
}

// PINToken gives the PIN to the device and returns a token for perms on
// rpID. A wrong PIN costs one of the device's retries (StatusPINInvalid);
// three in a row need the device to be plugged in again
// (StatusPINAuthBlocked); the last one blocks the PIN (StatusPINBlocked).
// A PIN that cannot be right by its length is refused without asking the
// device. The caller wipes pin.
func (d *Device) PINToken(ctx context.Context, pin []byte, perms Permission, rpID string) (*PINToken, error) {
	info := d.Info()
	if !info.PINSet() {
		return nil, StatusPINNotSet
	}
	minLen := max(4, info.MinPINLength)
	if len(pin) > 63 || !utf8.Valid(pin) || utf8.RuneCount(pin) < minLen {
		return nil, &PINLengthError{Min: minLen, Max: 63}
	}
	sh, err := d.agree(ctx)
	if err != nil {
		return nil, err
	}
	defer sh.wipe()
	sum := sha256.Sum256(pin)
	pinHashEnc, err := sh.proto.encrypt(sh.secret, sum[:16])
	clear(sum[:])
	if err != nil {
		return nil, err
	}
	params := cbor.Map{
		pinParamProtocol:     int64(sh.proto),
		pinParamKeyAgreement: sh.ours,
		pinParamPINHashEnc:   pinHashEnc,
	}
	scoped := info.Options["pinUvAuthToken"]
	if scoped {
		params[pinParamSubCommand] = int64(pinGetTokenWithPerms)
		params[pinParamPermissions] = int64(perms)
		if rpID != "" {
			params[pinParamRPID] = rpID
		}
	} else {
		params[pinParamSubCommand] = int64(pinGetPINToken)
	}
	resp, err := d.command(ctx, cmdClientPIN, params, nil)
	if err != nil {
		return nil, err
	}
	enc, ok := resp[int64(2)].([]byte)
	if !ok {
		return nil, malformed("a PIN token answer without a token")
	}
	token, err := sh.proto.decrypt(sh.secret, enc)
	if err != nil {
		return nil, err
	}
	if (sh.proto == 2 && len(token) != 32) || (sh.proto == 1 && len(token) != 16 && len(token) != 32) {
		clear(token)
		return nil, malformed("a %d-byte PIN token", len(token))
	}
	t := &PINToken{dev: d, proto: sh.proto, token: token, perms: perms, scoped: scoped}
	if scoped {
		t.rpID = rpID
	}
	return t, nil
}
