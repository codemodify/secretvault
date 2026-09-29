package svfido

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/codemodify/secretvault/internal/cbor"
)

// CTAP2 commands (CTAP 2.1 §6).
const (
	cmdMakeCredential = 0x01
	cmdGetAssertion   = 0x02
	cmdGetInfo        = 0x04
	cmdSelection      = 0x0B
)

// Device is one FIDO2 security key, spoken to on a CTAPHID channel of its
// own. Its methods may be called from any goroutine; they take turns.
type Device struct {
	name string
	path string

	mu   sync.Mutex
	hid  *hidConn
	info *Info
}

// NewDevice opens a CTAPHID channel on t and asks the device what it is.
// name is how people are told about it.
func NewDevice(ctx context.Context, t Transport, name string) (*Device, error) {
	d := &Device{name: name, hid: &hidConn{t: t}}
	if err := d.hid.open(ctx); err != nil {
		return nil, err
	}
	info, err := d.GetInfo(ctx)
	if err != nil {
		return nil, err
	}
	d.info = info
	return d, nil
}

// Open opens a device found by Devices.
func Open(ctx context.Context, info DeviceInfo) (*Device, error) {
	t, err := openTransport(info)
	if err != nil {
		return nil, err
	}
	d, err := NewDevice(ctx, t, info.String())
	if err != nil {
		t.Close()
		return nil, fmt.Errorf("%s: %w", info, err)
	}
	d.path = info.Path
	return d, nil
}

// OpenAll opens every security key plugged in. With none it returns
// ErrNoDevice; with none that could be opened, the first reason (usually
// a PermissionError).
func OpenAll(ctx context.Context) ([]*Device, error) {
	infos, err := Devices()
	if err != nil {
		return nil, err
	}
	var out []*Device
	var first error
	for _, info := range infos {
		d, err := Open(ctx, info)
		if err != nil {
			if first == nil {
				first = err
			}
			continue
		}
		out = append(out, d)
	}
	switch {
	case len(out) > 0:
		return out, nil
	case first != nil:
		return nil, first
	}
	return nil, ErrNoDevice
}

// Name is how the device is named to people.
func (d *Device) Name() string {
	if d.name == "" {
		return "security key"
	}
	return d.name
}

// Path is the device node, when it has one.
func (d *Device) Path() string { return d.path }

// Info is what the device said about itself when it was opened.
func (d *Device) Info() *Info { return d.info }

// SetTimeout sets how long the device may go without a word in the
// middle of a request before it is taken to have hung.
func (d *Device) SetTimeout(silence time.Duration) {
	d.mu.Lock()
	d.hid.silence = silence
	d.mu.Unlock()
}

// Close closes the device.
func (d *Device) Close() error { return d.hid.t.Close() }

// command runs one CTAP2 command and returns its answer, which must be a
// map (or nothing). onUP is told when the device waits for a touch.
func (d *Device) command(ctx context.Context, cmd byte, params cbor.Map, onUP func()) (cbor.Map, error) {
	req := []byte{cmd}
	if params != nil {
		b, err := cbor.Marshal(params)
		if err != nil {
			return nil, err
		}
		req = append(req, b...)
	}
	limit := 1024 // what every CTAP2 device takes
	if d.info != nil && d.info.MaxMsgSize > limit {
		limit = d.info.MaxMsgSize
	}
	if len(req) > min(limit, maxMessage) {
		return nil, StatusRequestTooLarge
	}
	d.mu.Lock()
	resp, err := d.hid.transact(ctx, cmdCBOR, req, onUP)
	d.mu.Unlock()
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 {
		return nil, malformed("an empty answer")
	}
	if resp[0] != 0 {
		return nil, Status(resp[0])
	}
	if len(resp) == 1 {
		return cbor.Map{}, nil
	}
	v, err := cbor.Unmarshal(resp[1:])
	if err != nil {
		return nil, malformed("%v", err)
	}
	m, ok := v.(cbor.Map)
	if !ok {
		return nil, malformed("an answer that is not a map")
	}
	return m, nil
}

// Info is authenticatorGetInfo's answer (CTAP 2.1 §6.4).
type Info struct {
	Versions                 []string        // FIDO_2_0, FIDO_2_1, ...
	Extensions               []string        // hmac-secret, credProtect, ...
	AAGUID                   [16]byte        // the model
	Options                  map[string]bool // clientPin, pinUvAuthToken, makeCredUvNotRqd, alwaysUv, ...
	MaxMsgSize               int
	PINProtocols             []int // in the device's order of preference
	MaxCredentialCountInList int
	MaxCredentialIDLength    int
	MinPINLength             int
	FirmwareVersion          int
}

// HasVersion reports whether the device speaks a CTAP version.
func (i *Info) HasVersion(v string) bool { return slices.Contains(i.Versions, v) }

// HMACSecret reports whether the device has the hmac-secret extension.
func (i *Info) HMACSecret() bool { return slices.Contains(i.Extensions, "hmac-secret") }

// PINSet reports whether the device has a PIN.
func (i *Info) PINSet() bool { return i.Options["clientPin"] }

// PINSupported reports whether the device can have a PIN at all.
func (i *Info) PINSupported() bool {
	_, ok := i.Options["clientPin"]
	return ok
}

// AlwaysUV reports whether the device verifies the person on every use.
func (i *Info) AlwaysUV() bool { return i.Options["alwaysUv"] }

// GetInfo asks the device what it is.
func (d *Device) GetInfo(ctx context.Context) (*Info, error) {
	m, err := d.command(ctx, cmdGetInfo, nil, nil)
	if err != nil {
		return nil, err
	}
	return parseInfo(m)
}

func parseInfo(m cbor.Map) (*Info, error) {
	info := &Info{Options: map[string]bool{}}
	var err error
	if info.Versions, err = stringList(m, 1, true); err != nil {
		return nil, err
	}
	if info.Extensions, err = stringList(m, 2, false); err != nil {
		return nil, err
	}
	aaguid, ok := m[int64(3)].([]byte)
	if !ok || len(aaguid) != 16 {
		return nil, malformed("getInfo without a 16-byte AAGUID")
	}
	copy(info.AAGUID[:], aaguid)
	if v, ok := m[int64(4)]; ok {
		opts, ok := v.(cbor.Map)
		if !ok {
			return nil, malformed("getInfo options are not a map")
		}
		for k, v := range opts {
			name, ok1 := k.(string)
			on, ok2 := v.(bool)
			if !ok1 || !ok2 {
				return nil, malformed("getInfo option %v is not a named boolean", k)
			}
			info.Options[name] = on
		}
	}
	ints := []struct {
		key int64
		to  *int
	}{
		{5, &info.MaxMsgSize}, {7, &info.MaxCredentialCountInList}, {8, &info.MaxCredentialIDLength},
		{0x0D, &info.MinPINLength}, {0x0E, &info.FirmwareVersion},
	}
	for _, f := range ints {
		if v, ok := m[f.key]; ok {
			n, ok := v.(int64)
			if !ok || n < 0 || n > 1<<31 {
				return nil, malformed("getInfo field %d is not a count", f.key)
			}
			*f.to = int(n)
		}
	}
	if v, ok := m[int64(6)]; ok {
		list, ok := v.([]any)
		if !ok {
			return nil, malformed("getInfo PIN protocols are not a list")
		}
		for _, e := range list {
			n, ok := e.(int64)
			if !ok || n < 1 || n > 255 {
				return nil, malformed("getInfo PIN protocol %v", e)
			}
			info.PINProtocols = append(info.PINProtocols, int(n))
		}
	}
	if len(info.Versions) == 0 {
		return nil, malformed("getInfo without versions")
	}
	return info, nil
}

func stringList(m cbor.Map, key int64, required bool) ([]string, error) {
	v, ok := m[key]
	if !ok {
		if required {
			return nil, malformed("getInfo without field %d", key)
		}
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, malformed("getInfo field %d is not a list", key)
	}
	out := make([]string, 0, len(list))
	for _, e := range list {
		s, ok := e.(string)
		if !ok {
			return nil, malformed("getInfo field %d holds a %T", key, e)
		}
		out = append(out, s)
	}
	return out, nil
}

// protocol is the PIN/UV auth protocol to use with the device: 2 if it
// offers it, else 1.
func (d *Device) protocol() pinProtocol {
	if d.info != nil && slices.Contains(d.info.PINProtocols, 2) {
		return 2
	}
	return 1
}

// Authenticator data flags (CTAP 2.1 §6.1, WebAuthn §6.1).
const (
	FlagUP = 0x01 // the person touched the key
	FlagUV = 0x04 // the device verified the person (PIN or built-in)
	FlagAT = 0x40 // attested credential data follows
	FlagED = 0x80 // extensions follow
)

// AuthData is authenticator data: what a device signs about an
// operation.
type AuthData struct {
	RPIDHash     [32]byte
	Flags        byte
	SignCount    uint32
	AAGUID       [16]byte // with attested credential data
	CredentialID []byte   // with attested credential data
	Extensions   cbor.Map // with FlagED
}

func parseAuthData(b []byte) (*AuthData, error) {
	if len(b) < 37 {
		return nil, malformed("%d bytes of authenticator data", len(b))
	}
	a := &AuthData{Flags: b[32], SignCount: binary.BigEndian.Uint32(b[33:37])}
	copy(a.RPIDHash[:], b[:32])
	rest := b[37:]
	if a.Flags&FlagAT != 0 {
		if len(rest) < 18 {
			return nil, malformed("truncated attested credential data")
		}
		copy(a.AAGUID[:], rest[:16])
		n := int(binary.BigEndian.Uint16(rest[16:18]))
		rest = rest[18:]
		if n == 0 || n > 1023 || len(rest) < n {
			return nil, malformed("a %d-byte credential ID", n)
		}
		a.CredentialID = bytes.Clone(rest[:n])
		rest = rest[n:]
		pub, after, err := cbor.UnmarshalFirst(rest)
		if err != nil {
			return nil, malformed("the credential's public key: %v", err)
		}
		if _, ok := pub.(cbor.Map); !ok {
			return nil, malformed("a credential public key that is not a map")
		}
		rest = after
	}
	if a.Flags&FlagED != 0 {
		v, err := cbor.Unmarshal(rest)
		if err != nil {
			return nil, malformed("the extensions: %v", err)
		}
		ext, ok := v.(cbor.Map)
		if !ok {
			return nil, malformed("extensions that are not a map")
		}
		a.Extensions, rest = ext, nil
	}
	if len(rest) != 0 {
		return nil, malformed("%d bytes after the authenticator data", len(rest))
	}
	return a, nil
}

// MakeCredentialRequest asks a device for a new credential. secretvault
// makes only non-discoverable credentials: the device keeps nothing, and
// the credential ID (which the device can read back) is the credential.
type MakeCredentialRequest struct {
	ClientDataHash []byte // 32 bytes
	RPID           string
	RPName         string
	UserID         []byte // at most 64 bytes
	UserName       string
	HMACSecret     bool      // ask for the hmac-secret extension
	PIN            *PINToken // with PermMakeCredential; nil without user verification
	OnTouch        func()    // told when the device waits for a touch
}

// Attestation is a new credential.
type Attestation struct {
	Format   string
	AuthData *AuthData
}

// MakeCredential makes a credential. The device waits for a touch.
func (d *Device) MakeCredential(ctx context.Context, r *MakeCredentialRequest) (*Attestation, error) {
	if len(r.ClientDataHash) != 32 || r.RPID == "" || len(r.UserID) == 0 || len(r.UserID) > 64 {
		return nil, errors.New("svfido: an incomplete credential request")
	}
	params := cbor.Map{
		1: r.ClientDataHash,
		2: cbor.Map{"id": r.RPID, "name": cmp.Or(r.RPName, r.RPID)},
		3: cbor.Map{"id": r.UserID, "name": cmp.Or(r.UserName, "secretvault"), "displayName": cmp.Or(r.UserName, "secretvault")},
		4: []any{cbor.Map{"alg": int64(-7), "type": "public-key"}}, // ES256, which every key has
	}
	if r.HMACSecret {
		params[6] = cbor.Map{"hmac-secret": true}
	}
	if r.PIN != nil {
		p, err := r.PIN.param(d, PermMakeCredential, r.RPID, r.ClientDataHash)
		if err != nil {
			return nil, err
		}
		params[8], params[9] = p, int64(r.PIN.proto)
	}
	m, err := d.command(ctx, cmdMakeCredential, params, r.OnTouch)
	if err != nil {
		return nil, err
	}
	format, ok1 := m[int64(1)].(string)
	raw, ok2 := m[int64(2)].([]byte)
	_, ok3 := m[int64(3)].(cbor.Map)
	if !ok1 || !ok2 || !ok3 {
		return nil, malformed("makeCredential's answer lacks its format, data or statement")
	}
	ad, err := parseAuthData(raw)
	if err != nil {
		return nil, err
	}
	if ad.RPIDHash != sha256.Sum256([]byte(r.RPID)) {
		return nil, malformed("a credential for another site")
	}
	if ad.Flags&FlagAT == 0 || ad.Flags&FlagUP == 0 {
		return nil, malformed("a credential without attested data, or made without a touch")
	}
	if r.PIN != nil && ad.Flags&FlagUV == 0 {
		return nil, malformed("a credential made with the PIN but not marked verified")
	}
	if r.HMACSecret {
		if on, _ := ad.Extensions["hmac-secret"].(bool); !on {
			return nil, ErrNoHMACSecret
		}
	}
	return &Attestation{Format: format, AuthData: ad}, nil
}

// AssertionRequest asks a device to use a credential.
type AssertionRequest struct {
	ClientDataHash []byte // 32 bytes
	RPID           string
	Allow          [][]byte  // credential IDs; secretvault always names them
	NoTouch        bool      // up=false: answer without a touch (a silent probe)
	Salts          [][]byte  // hmac-secret: one or two 32-byte salts
	PIN            *PINToken // with PermGetAssertion; nil without user verification
	OnTouch        func()    // told when the device waits for a touch
}

// Assertion is a device's answer.
type Assertion struct {
	CredentialID []byte
	AuthData     *AuthData
	HMACSecret   [][]byte // one 32-byte output per salt
}

// GetAssertion uses one of r.Allow. A device that holds none of them
// answers StatusNoCredentials.
func (d *Device) GetAssertion(ctx context.Context, r *AssertionRequest) (*Assertion, error) {
	if len(r.ClientDataHash) != 32 || r.RPID == "" || len(r.Allow) == 0 || len(r.Salts) > 2 {
		return nil, errors.New("svfido: an incomplete assertion request")
	}
	allow := make([]any, len(r.Allow))
	for i, id := range r.Allow {
		allow[i] = cbor.Map{"id": id, "type": "public-key"}
	}
	params := cbor.Map{1: r.RPID, 2: r.ClientDataHash, 3: allow}
	var sh *shared
	if len(r.Salts) > 0 {
		var salts []byte
		for _, s := range r.Salts {
			if len(s) != 32 {
				return nil, errors.New("svfido: an hmac-secret salt is 32 bytes")
			}
			salts = append(salts, s...)
		}
		var err error
		if sh, err = d.agree(ctx); err != nil {
			return nil, err
		}
		defer sh.wipe()
		saltEnc, err := sh.proto.encrypt(sh.secret, salts)
		if err != nil {
			return nil, err
		}
		in := cbor.Map{1: sh.ours, 2: saltEnc, 3: sh.proto.authenticate(sh.secret, saltEnc)}
		if sh.proto != 1 {
			in[4] = int64(sh.proto) // absent means 1, which CTAP 2.0 devices expect
		}
		params[4] = cbor.Map{"hmac-secret": in}
	}
	if r.NoTouch {
		params[5] = cbor.Map{"up": false}
	}
	if r.PIN != nil {
		p, err := r.PIN.param(d, PermGetAssertion, r.RPID, r.ClientDataHash)
		if err != nil {
			return nil, err
		}
		params[6], params[7] = p, int64(r.PIN.proto)
	}
	onTouch := r.OnTouch
	if r.NoTouch {
		onTouch = nil
	}
	m, err := d.command(ctx, cmdGetAssertion, params, onTouch)
	if err != nil {
		return nil, err
	}
	raw, ok := m[int64(2)].([]byte)
	if _, sig := m[int64(3)].([]byte); !ok || !sig {
		return nil, malformed("getAssertion's answer lacks its data or signature")
	}
	ad, err := parseAuthData(raw)
	if err != nil {
		return nil, err
	}
	if ad.RPIDHash != sha256.Sum256([]byte(r.RPID)) {
		return nil, malformed("an assertion for another site")
	}
	if !r.NoTouch && ad.Flags&FlagUP == 0 {
		return nil, malformed("an assertion without the touch it asked for")
	}
	if r.PIN != nil && ad.Flags&FlagUV == 0 {
		return nil, malformed("an assertion with the PIN but not marked verified")
	}
	a := &Assertion{AuthData: ad}
	switch cred := m[int64(1)].(type) {
	case nil:
		if len(r.Allow) != 1 {
			return nil, malformed("an assertion that does not say which credential answered")
		}
		a.CredentialID = bytes.Clone(r.Allow[0])
	case cbor.Map:
		id, _ := cred["id"].([]byte)
		if !slices.ContainsFunc(r.Allow, func(a []byte) bool { return bytes.Equal(a, id) }) {
			return nil, malformed("an assertion by a credential that was not asked for")
		}
		a.CredentialID = id
	default:
		return nil, malformed("an assertion's credential that is not a map")
	}
	if sh != nil {
		enc, ok := ad.Extensions["hmac-secret"].([]byte)
		if !ok {
			return nil, ErrNoHMACSecret
		}
		out, err := sh.proto.decrypt(sh.secret, enc)
		if err != nil {
			return nil, err
		}
		if len(out) != 32*len(r.Salts) {
			clear(out)
			return nil, malformed("%d bytes of hmac-secret output for %d salts", len(out), len(r.Salts))
		}
		for i := range r.Salts {
			a.HMACSecret = append(a.HMACSecret, out[32*i:32*i+32])
		}
	}
	return a, nil
}

// Select waits for the person to touch this device: how one of several
// keys plugged in is picked. CTAP 2.1 devices have a command for it; on
// CTAP 2.0 devices it is a credential request with an empty PIN
// parameter, which such devices answer, after a touch, with a PIN error.
func (d *Device) Select(ctx context.Context, onTouch func()) error {
	if d.info.HasVersion("FIDO_2_1") {
		_, err := d.command(ctx, cmdSelection, nil, onTouch)
		return err
	}
	_, err := d.command(ctx, cmdMakeCredential, cbor.Map{
		1: make([]byte, 32),
		2: cbor.Map{"id": ".dummy"},
		3: cbor.Map{"id": []byte{0}, "name": "dummy"},
		4: []any{cbor.Map{"alg": int64(-7), "type": "public-key"}},
		8: []byte{},
		9: int64(1),
	}, onTouch)
	if err == nil || errors.Is(err, StatusPINInvalid) || errors.Is(err, StatusPINNotSet) {
		return nil // touched (a device without PINs made the dummy credential, which it keeps nowhere)
	}
	return err
}
