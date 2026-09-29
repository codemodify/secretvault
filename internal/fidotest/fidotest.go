// Package fidotest is a software FIDO2 security key for tests.
//
// It speaks CTAPHID over in-memory reports (a Port stands where a
// /dev/hidraw node would), and CTAP 2.1 or 2.0: getInfo, makeCredential
// and getAssertion with non-discoverable credentials and the hmac-secret
// extension, selection, and clientPIN with PIN/UV auth protocols 1 and 2,
// PIN retries and blocking. The touch is simulated by Options.Touch.
//
// Its cryptography is written here from the specification's text, apart
// from svfido's, so each checks the other; svfido's is also checked
// against Python's cryptography package. It reads requests strictly: they
// must be CTAP2 canonical CBOR, and a PIN token is honoured only for what
// it was issued for, as a CTAP 2.1 key does.
package fidotest

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/codemodify/secretvault/internal/cbor"
)

// Options describe the key.
type Options struct {
	Name      string
	AAGUID    [16]byte
	CTAP20    bool   // a CTAP 2.0 key: getPinToken, protocol 1 only, no selection
	PIN       string // "" for a key with no PIN set
	Protocols []int  // PIN/UV auth protocols offered: [2 1] by default, [1] for CTAP 2.0
	AlwaysUV  bool   // verify on every use (CTAP 2.1 alwaysUv)
	NoHMAC    bool   // no hmac-secret extension

	// Touch is called whenever the key waits for a touch: it returns nil
	// for a touch, ErrDenied, ErrNoTouch, or ctx's error when the host
	// cancels. nil touches at once.
	Touch func(ctx context.Context) error

	// Keepalive is how often the key says it is busy (20 ms when 0).
	Keepalive time.Duration
}

var (
	// ErrDenied is a person declining (a key with a "no" button).
	ErrDenied = errors.New("fidotest: declined")
	// ErrNoTouch is nobody touching in time.
	ErrNoTouch = errors.New("fidotest: nobody touched")
)

// CTAP statuses the key answers with.
const (
	okStatus            = 0x00
	errInvalidCommand   = 0x01
	errInvalidParameter = 0x02
	errInvalidLength    = 0x03
	errInvalidSeq       = 0x04
	errMsgTimeout       = 0x05
	errChannelBusy      = 0x06
	errInvalidChannel   = 0x0B
	errUnexpectedType   = 0x11
	errInvalidCBOR      = 0x12
	errMissingParameter = 0x14
	errUnsupportedAlg   = 0x26
	errOperationDenied  = 0x27
	errUnsupportedOpt   = 0x2B
	errInvalidOption    = 0x2C
	errKeepaliveCancel  = 0x2D
	errNoCredentials    = 0x2E
	errActionTimeout    = 0x2F
	errPINInvalid       = 0x31
	errPINBlocked       = 0x32
	errPINAuthInvalid   = 0x33
	errPINAuthBlocked   = 0x34
	errPINNotSet        = 0x35
	errPUATRequired     = 0x36
	errInvalidSubcmd    = 0x3E
)

const (
	reportSize = 64
	maxMessage = 57 + 128*59
	broadcast  = 0xffffffff
	maxRetries = 8
)

// Authenticator is one software security key.
type Authenticator struct {
	opts Options

	fromHost chan []byte
	quit     chan struct{}
	stopped  chan struct{}

	portsMu sync.Mutex
	ports   map[*Port]bool
	gone    bool

	mu          sync.Mutex
	master      []byte // seals credential IDs
	ka          *ecdh.PrivateKey
	pinHash     []byte // LEFT(SHA-256(PIN), 16), or nil
	retries     int
	consecutive int
	token       []byte
	tokenPerms  byte
	tokenRPID   string
	signCount   uint32
	touches     int
	counts      map[string]int
	upNeeded    bool
}

// New starts a key.
func New(o Options) *Authenticator {
	if len(o.Protocols) == 0 {
		o.Protocols = []int{2, 1}
		if o.CTAP20 {
			o.Protocols = []int{1}
		}
	}
	if o.Keepalive == 0 {
		o.Keepalive = 20 * time.Millisecond
	}
	if o.Name == "" {
		o.Name = "Software Key"
	}
	a := &Authenticator{
		opts:     o,
		fromHost: make(chan []byte, 256),
		quit:     make(chan struct{}),
		stopped:  make(chan struct{}),
		ports:    map[*Port]bool{},
		master:   random(32),
		retries:  maxRetries,
		counts:   map[string]int{},
	}
	a.ka, _ = ecdh.P256().GenerateKey(rand.Reader)
	if o.PIN != "" {
		h := sha256.Sum256([]byte(o.PIN))
		a.pinHash = h[:16]
	}
	go a.run()
	return a
}

// Name is the key's name.
func (a *Authenticator) Name() string { return a.opts.Name }

// Stop turns the key off for good.
func (a *Authenticator) Stop() {
	select {
	case <-a.quit:
	default:
		close(a.quit)
	}
	<-a.stopped
	a.Unplug()
}

// Unplug makes every open port fail, as pulling the key out does.
func (a *Authenticator) Unplug() {
	a.portsMu.Lock()
	a.gone = true
	for p := range a.ports {
		p.shut()
	}
	a.ports = map[*Port]bool{}
	a.portsMu.Unlock()
}

// PowerCycle is unplugging the key and plugging it in again: a new key
// agreement key, and the three-wrong-PINs lock lifted.
func (a *Authenticator) PowerCycle() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.ka, _ = ecdh.P256().GenerateKey(rand.Reader)
	a.consecutive = 0
	a.token = nil
	a.portsMu.Lock()
	a.gone = false
	a.portsMu.Unlock()
}

// Retries is how many wrong PINs the key still takes.
func (a *Authenticator) Retries() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.retries
}

// Touches is how many touches the key has taken.
func (a *Authenticator) Touches() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.touches
}

// Count is how many times a command ran: "getInfo", "makeCredential",
// "getAssertion" (with a touch), "probe" (getAssertion without one),
// "clientPIN", "selection", "cancel".
func (a *Authenticator) Count(what string) int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.counts[what]
}

// Port is one open handle on the key, like an open /dev/hidraw node: it
// sees every report the key sends.
type Port struct {
	a      *Authenticator
	in     chan []byte
	closed chan struct{}
	once   sync.Once
}

// Transport opens a new handle on the key.
func (a *Authenticator) Transport() *Port {
	p := &Port{a: a, in: make(chan []byte, 4096), closed: make(chan struct{})}
	a.portsMu.Lock()
	if a.gone {
		p.shut()
	} else {
		a.ports[p] = true
	}
	a.portsMu.Unlock()
	return p
}

var errGone = errors.New("fidotest: the key is unplugged")

// WriteReport sends a report to the key.
func (p *Port) WriteReport(r []byte) error {
	if len(r) != reportSize {
		return errors.New("fidotest: a report is 64 bytes")
	}
	select {
	case <-p.closed:
		return errGone
	case p.a.fromHost <- bytes.Clone(r):
		return nil
	}
}

// ReadReport waits for a report from the key.
func (p *Port) ReadReport(r []byte, deadline time.Time) (int, error) {
	t := time.NewTimer(time.Until(deadline))
	defer t.Stop()
	select {
	case rep := <-p.in:
		return copy(r, rep), nil
	case <-p.closed:
		return 0, errGone
	case <-t.C:
		return 0, os.ErrDeadlineExceeded
	}
}

// Close closes the handle.
func (p *Port) Close() error {
	p.a.portsMu.Lock()
	delete(p.a.ports, p)
	p.a.portsMu.Unlock()
	p.shut()
	return nil
}

func (p *Port) shut() { p.once.Do(func() { close(p.closed) }) }

// send writes a message to every port, cut into reports.
func (a *Authenticator) send(cid uint32, cmd byte, data []byte) {
	var reps [][]byte
	r := make([]byte, reportSize)
	binary.BigEndian.PutUint32(r, cid)
	r[4] = cmd
	binary.BigEndian.PutUint16(r[5:], uint16(len(data)))
	n := copy(r[7:], data)
	reps = append(reps, r)
	data = data[n:]
	for seq := byte(0); len(data) > 0; seq++ {
		r = make([]byte, reportSize)
		binary.BigEndian.PutUint32(r, cid)
		r[4] = seq
		n = copy(r[5:], data)
		reps = append(reps, r)
		data = data[n:]
	}
	a.portsMu.Lock()
	defer a.portsMu.Unlock()
	for p := range a.ports {
		for _, r := range reps {
			select {
			case p.in <- r:
			default: // a port nobody reads loses reports, as a real one would
			}
		}
	}
}

func (a *Authenticator) sendError(cid uint32, code byte) { a.send(cid, 0xbf, []byte{code}) }

type result struct {
	cid  uint32
	resp []byte
}

// run is the key's CTAPHID loop: it assembles messages, answers INIT,
// PING and WINK itself, hands CBOR requests to a worker so it can keep
// sending keepalives and hear CANCEL meanwhile, and refuses anything out
// of order.
func (a *Authenticator) run() {
	defer close(a.stopped)
	nextCID := uint32(0x01020304)
	channels := map[uint32]bool{}

	var asm struct {
		on    bool
		cid   uint32
		cmd   byte
		total int
		data  []byte
		seq   byte
		timer <-chan time.Time
	}
	var busy struct {
		on     bool
		cid    uint32
		cancel context.CancelFunc
	}
	done := make(chan result, 1)
	tick := time.NewTicker(a.opts.Keepalive)
	defer tick.Stop()

	for {
		select {
		case <-a.quit:
			if busy.on {
				busy.cancel()
				<-done
			}
			return
		case <-asm.timer:
			a.sendError(asm.cid, errMsgTimeout)
			asm.on, asm.timer = false, nil
		case r := <-done:
			busy.on = false
			a.send(r.cid, 0x90, r.resp)
		case <-tick.C:
			if busy.on {
				a.mu.Lock()
				status := byte(1)
				if a.upNeeded {
					status = 2
				}
				a.mu.Unlock()
				a.send(busy.cid, 0xbb, []byte{status})
			}
		case rep := <-a.fromHost:
			cid := binary.BigEndian.Uint32(rep)
			b := rep[4]
			if b&0x80 == 0 { // continuation
				if !asm.on || cid != asm.cid {
					continue
				}
				if b != asm.seq {
					a.sendError(cid, errInvalidSeq)
					asm.on, asm.timer = false, nil
					continue
				}
				asm.seq++
				asm.data = append(asm.data, rep[5:min(reportSize, 5+asm.total-len(asm.data))]...)
			} else {
				bcnt := int(binary.BigEndian.Uint16(rep[5:7]))
				switch {
				case cid == 0 || (cid != broadcast && !channels[cid]):
					a.sendError(cid, errInvalidChannel)
					continue
				case b == 0x91: // CANCEL
					if busy.on && busy.cid == cid {
						a.mu.Lock()
						a.counts["cancel"]++
						a.mu.Unlock()
						busy.cancel()
					}
					continue
				case b == 0x86 && cid == broadcast:
					// INIT is answered even mid-transaction.
				case (busy.on && busy.cid != cid) || (asm.on && asm.cid != cid):
					a.sendError(cid, errChannelBusy)
					continue
				case busy.on || asm.on:
					a.sendError(cid, errInvalidSeq)
					continue
				case cid == broadcast:
					a.sendError(cid, errInvalidChannel)
					continue
				case bcnt > maxMessage:
					a.sendError(cid, errInvalidLength)
					continue
				}
				if b == 0x86 && cid == broadcast {
					if bcnt != 8 {
						a.sendError(cid, errInvalidLength)
						continue
					}
					nextCID++
					channels[nextCID] = true
					resp := append(bytes.Clone(rep[7:15]), 0, 0, 0, 0, 2, 1, 0, 0, 0x0D) // WINK | CBOR | NMSG
					binary.BigEndian.PutUint32(resp[8:12], nextCID)
					a.send(cid, 0x86, resp)
					continue
				}
				asm.on, asm.cid, asm.cmd, asm.total, asm.seq = true, cid, b, bcnt, 0
				asm.data = append([]byte(nil), rep[7:min(reportSize, 7+bcnt)]...)
				asm.timer = time.After(500 * time.Millisecond)
			}
			if len(asm.data) < asm.total {
				continue
			}
			asm.on, asm.timer = false, nil
			switch asm.cmd {
			case 0x81: // PING
				a.send(asm.cid, 0x81, asm.data)
			case 0x88: // WINK
				a.send(asm.cid, 0x88, nil)
			case 0x90: // CBOR
				if len(asm.data) == 0 {
					a.sendError(asm.cid, errInvalidLength)
					continue
				}
				ctx, cancel := context.WithCancel(context.Background())
				busy.on, busy.cid, busy.cancel = true, asm.cid, cancel
				req, cid := asm.data, asm.cid
				go func() {
					resp := a.process(ctx, req)
					cancel()
					done <- result{cid: cid, resp: resp}
				}()
			default:
				a.sendError(asm.cid, errInvalidCommand)
			}
		}
	}
}

// process answers one CTAP2 request: a status byte, then CBOR.
func (a *Authenticator) process(ctx context.Context, req []byte) []byte {
	a.mu.Lock()
	defer a.mu.Unlock()
	var params cbor.Map
	if len(req) > 1 {
		v, err := cbor.UnmarshalCanonical(req[1:])
		if err != nil {
			return []byte{errInvalidCBOR}
		}
		m, ok := v.(cbor.Map)
		if !ok {
			return []byte{errUnexpectedType}
		}
		params = m
	}
	var resp cbor.Map
	var status byte
	switch req[0] {
	case 0x04:
		a.counts["getInfo"]++
		resp = a.getInfo()
	case 0x01:
		a.counts["makeCredential"]++
		resp, status = a.makeCredential(ctx, params)
	case 0x02:
		resp, status = a.getAssertion(ctx, params)
	case 0x06:
		a.counts["clientPIN"]++
		resp, status = a.clientPIN(params)
	case 0x0B:
		if a.opts.CTAP20 {
			return []byte{errInvalidCommand}
		}
		a.counts["selection"]++
		status = a.waitTouch(ctx)
	default:
		return []byte{errInvalidCommand}
	}
	if status != okStatus {
		return []byte{status}
	}
	if resp == nil {
		return []byte{okStatus}
	}
	b, err := cbor.Marshal(resp)
	if err != nil {
		panic(err)
	}
	return append([]byte{okStatus}, b...)
}

// waitTouch waits for the simulated touch, with a.mu released.
func (a *Authenticator) waitTouch(ctx context.Context) byte {
	a.upNeeded = true
	a.mu.Unlock()
	var err error
	if a.opts.Touch != nil {
		err = a.opts.Touch(ctx)
	}
	if err == nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	a.mu.Lock()
	a.upNeeded = false
	switch {
	case err == nil:
		a.touches++
		return okStatus
	case errors.Is(err, ErrDenied):
		return errOperationDenied
	case errors.Is(err, ErrNoTouch):
		return errActionTimeout
	}
	return errKeepaliveCancel
}

func (a *Authenticator) getInfo() cbor.Map {
	versions := []any{"FIDO_2_0", "FIDO_2_1"}
	opts := cbor.Map{"rk": false, "up": true, "plat": false, "clientPin": a.pinHash != nil}
	if a.opts.CTAP20 {
		versions = []any{"U2F_V2", "FIDO_2_0"}
	} else {
		opts["pinUvAuthToken"] = true
		opts["makeCredUvNotRqd"] = true
		opts["alwaysUv"] = a.opts.AlwaysUV
	}
	var protos []any
	for _, p := range a.opts.Protocols {
		protos = append(protos, int64(p))
	}
	m := cbor.Map{1: versions, 3: a.opts.AAGUID[:], 4: opts, 5: int64(1200), 6: protos, 7: int64(8), 8: int64(128)}
	if !a.opts.NoHMAC {
		m[2] = []any{"hmac-secret"}
	}
	if !a.opts.CTAP20 {
		m[0x0D] = int64(4)
	}
	return m
}

// The credential ID is the credential, sealed under the key's master key
// and bound to the site: nonce (12) || AES-256-GCM(private scalar (32) ||
// CredRandomWithUV (32) || CredRandomWithoutUV (32) || hmac-secret (1)).
type credential struct {
	priv          *ecdsa.PrivateKey
	withUV, noUV  []byte
	hmac          bool
	id            []byte
	rpIDHash      [32]byte
	publicKeyCOSE cbor.Map
}

func (a *Authenticator) gcm() cipher.AEAD {
	b, _ := aes.NewCipher(a.master)
	g, _ := cipher.NewGCM(b)
	return g
}

func (a *Authenticator) newCredential(rpID string, hmacSecret bool) *credential {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := &credential{priv: priv, withUV: random(32), noUV: random(32), hmac: hmacSecret, rpIDHash: sha256.Sum256([]byte(rpID))}
	pt := append(priv.D.FillBytes(make([]byte, 32)), c.withUV...)
	pt = append(append(pt, c.noUV...), boolByte(hmacSecret))
	nonce := random(12)
	c.id = a.gcm().Seal(nonce, nonce, pt, c.rpIDHash[:])
	c.publicKeyCOSE = cbor.Map{1: int64(2), 3: int64(-7), -1: int64(1),
		-2: priv.X.FillBytes(make([]byte, 32)), -3: priv.Y.FillBytes(make([]byte, 32))}
	return c
}

func (a *Authenticator) openCredential(id []byte, rpID string) *credential {
	if len(id) < 12+16 {
		return nil
	}
	h := sha256.Sum256([]byte(rpID))
	pt, err := a.gcm().Open(nil, id[:12], id[12:], h[:])
	if err != nil || len(pt) != 97 {
		return nil
	}
	priv := new(ecdsa.PrivateKey)
	priv.Curve = elliptic.P256()
	priv.D = new(big.Int).SetBytes(pt[:32])
	priv.X, priv.Y = elliptic.P256().ScalarBaseMult(pt[:32])
	return &credential{priv: priv, withUV: pt[32:64], noUV: pt[64:96], hmac: pt[96] == 1, id: id, rpIDHash: h}
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

// checkToken verifies pinUvAuthParam over clientDataHash, for a command
// needing perm on rpID. It returns the status to answer, and whether the
// person was verified.
func (a *Authenticator) checkToken(params cbor.Map, paramKey, protoKey int64, perm byte, rpID string, cdh []byte) (bool, byte) {
	v, present := params[paramKey]
	if !present {
		if a.opts.AlwaysUV {
			return false, errPUATRequired
		}
		return false, okStatus
	}
	p, ok := v.([]byte)
	if !ok {
		return false, errUnexpectedType
	}
	proto, ok := params[protoKey].(int64)
	if !ok {
		return false, errMissingParameter
	}
	if !slices.Contains(a.opts.Protocols, int(proto)) {
		return false, errInvalidParameter
	}
	if a.pinHash == nil {
		return false, errPINNotSet
	}
	if a.token == nil || !verify(int(proto), a.token, cdh, p) {
		return false, errPINAuthInvalid
	}
	if !a.opts.CTAP20 {
		// CTAP 2.1: a token is honoured only for the permissions and the
		// site it was issued for, and only once for these.
		if a.tokenPerms&perm == 0 {
			return false, errPINAuthInvalid
		}
		if a.tokenRPID != "" && a.tokenRPID != rpID {
			return false, errPINAuthInvalid
		}
		a.tokenRPID = rpID
	}
	return true, okStatus
}

// spent clears a CTAP 2.1 token's permissions after it was used.
func (a *Authenticator) spent() {
	if !a.opts.CTAP20 {
		a.tokenPerms = 0
	}
}

func (a *Authenticator) makeCredential(ctx context.Context, params cbor.Map) (cbor.Map, byte) {
	cdh, ok1 := params[int64(1)].([]byte)
	rp, ok2 := params[int64(2)].(cbor.Map)
	user, ok3 := params[int64(3)].(cbor.Map)
	algs, ok4 := params[int64(4)].([]any)
	if !ok1 || !ok2 || !ok3 || !ok4 {
		return nil, errMissingParameter
	}
	rpID, _ := rp["id"].(string)
	uid, _ := user["id"].([]byte)
	if rpID == "" || len(uid) == 0 || len(uid) > 64 || len(cdh) != 32 {
		return nil, errInvalidParameter
	}
	if p, ok := params[int64(8)].([]byte); ok && len(p) == 0 {
		// An empty PIN parameter: "touch me to be chosen".
		if st := a.waitTouch(ctx); st != okStatus {
			return nil, st
		}
		if a.pinHash != nil {
			return nil, errPINInvalid
		}
		return nil, errPINNotSet
	}
	es256 := false
	for _, e := range algs {
		m, _ := e.(cbor.Map)
		if alg, _ := m["alg"].(int64); alg == -7 && m["type"] == "public-key" {
			es256 = true
		}
	}
	if !es256 {
		return nil, errUnsupportedAlg
	}
	if opts, ok := params[int64(7)].(cbor.Map); ok {
		if rk, _ := opts["rk"].(bool); rk {
			return nil, errUnsupportedOpt
		}
		if _, up := opts["up"]; up {
			return nil, errInvalidOption
		}
		if uv, _ := opts["uv"].(bool); uv {
			return nil, errInvalidOption
		}
	}
	uv, st := a.checkToken(params, 8, 9, 0x01, rpID, cdh)
	if st != okStatus {
		return nil, st
	}
	if !uv && a.pinHash != nil && a.opts.CTAP20 {
		return nil, errPUATRequired // CTAP 2.0 PIN_REQUIRED
	}
	hmacSecret := false
	if ext, ok := params[int64(6)].(cbor.Map); ok {
		hmacSecret, _ = ext["hmac-secret"].(bool)
		hmacSecret = hmacSecret && !a.opts.NoHMAC
	}
	if ex, ok := params[int64(5)].([]any); ok {
		for _, e := range ex {
			m, _ := e.(cbor.Map)
			id, _ := m["id"].([]byte)
			if a.openCredential(id, rpID) != nil {
				if st := a.waitTouch(ctx); st != okStatus {
					return nil, st
				}
				return nil, 0x19 // CREDENTIAL_EXCLUDED
			}
		}
	}
	if st := a.waitTouch(ctx); st != okStatus {
		return nil, st
	}
	a.spent()
	c := a.newCredential(rpID, hmacSecret)
	flags := byte(0x01 | 0x40)
	if uv {
		flags |= 0x04
	}
	ad := append(c.rpIDHash[:], flags)
	a.signCount++
	ad = binary.BigEndian.AppendUint32(ad, a.signCount)
	ad = append(ad, a.opts.AAGUID[:]...)
	ad = binary.BigEndian.AppendUint16(ad, uint16(len(c.id)))
	ad = append(ad, c.id...)
	pk, _ := cbor.Marshal(c.publicKeyCOSE)
	ad = append(ad, pk...)
	if hmacSecret {
		ad[32] |= 0x80
		ext, _ := cbor.Marshal(cbor.Map{"hmac-secret": true})
		ad = append(ad, ext...)
	}
	return cbor.Map{1: "none", 2: ad, 3: cbor.Map{}}, okStatus
}

func (a *Authenticator) getAssertion(ctx context.Context, params cbor.Map) (cbor.Map, byte) {
	rpID, ok1 := params[int64(1)].(string)
	cdh, ok2 := params[int64(2)].([]byte)
	if !ok1 || !ok2 {
		return nil, errMissingParameter
	}
	if len(cdh) != 32 {
		return nil, errInvalidParameter
	}
	up := true
	if opts, ok := params[int64(5)].(cbor.Map); ok {
		if v, ok := opts["up"]; ok {
			b, isBool := v.(bool)
			if !isBool {
				return nil, errUnexpectedType
			}
			up = b
		}
		if uv, _ := opts["uv"].(bool); uv {
			return nil, errInvalidOption
		}
		if _, rk := opts["rk"]; rk {
			return nil, errUnsupportedOpt
		}
	}
	if up {
		a.counts["getAssertion"]++
	} else {
		a.counts["probe"]++
	}
	if p, ok := params[int64(6)].([]byte); ok && len(p) == 0 {
		if st := a.waitTouch(ctx); st != okStatus {
			return nil, st
		}
		if a.pinHash != nil {
			return nil, errPINInvalid
		}
		return nil, errPINNotSet
	}
	uv, st := a.checkToken(params, 6, 7, 0x02, rpID, cdh)
	if st != okStatus {
		return nil, st
	}
	var c *credential
	if list, ok := params[int64(3)].([]any); ok {
		for _, e := range list {
			m, _ := e.(cbor.Map)
			id, _ := m["id"].([]byte)
			if m["type"] != "public-key" {
				continue
			}
			if c = a.openCredential(id, rpID); c != nil {
				break
			}
		}
	}
	if c == nil {
		// A CTAP 2.1 key asks for the touch before saying it has nothing,
		// so nothing is learnt without one.
		if up && !a.opts.CTAP20 {
			if st := a.waitTouch(ctx); st != okStatus {
				return nil, st
			}
		}
		return nil, errNoCredentials
	}
	var output []byte
	if ext, ok := params[int64(4)].(cbor.Map); ok && c.hmac {
		if in, ok := ext["hmac-secret"].(cbor.Map); ok {
			var st byte
			if output, st = a.hmacSecret(in, uv, c); st != okStatus {
				return nil, st
			}
		}
	}
	if up {
		if st := a.waitTouch(ctx); st != okStatus {
			return nil, st
		}
	}
	if uv {
		a.spent()
	}
	flags := byte(0)
	if up {
		flags |= 0x01
	}
	if uv {
		flags |= 0x04
	}
	ad := append(c.rpIDHash[:], flags)
	a.signCount++
	ad = binary.BigEndian.AppendUint32(ad, a.signCount)
	if output != nil {
		ad[32] |= 0x80
		ext, _ := cbor.Marshal(cbor.Map{"hmac-secret": output})
		ad = append(ad, ext...)
	}
	digest := sha256.Sum256(append(bytes.Clone(ad), cdh...))
	sig, _ := ecdsa.SignASN1(rand.Reader, c.priv, digest[:])
	return cbor.Map{1: cbor.Map{"id": c.id, "type": "public-key"}, 2: ad, 3: sig}, okStatus
}

// hmacSecret is the extension (CTAP 2.1 §12.5): the salts arrive
// encrypted under a fresh key agreement; each output is
// HMAC-SHA-256(CredRandom, salt), with CredRandom chosen by whether the
// person was verified, and goes back encrypted the same way.
func (a *Authenticator) hmacSecret(in cbor.Map, uv bool, c *credential) ([]byte, byte) {
	proto := int64(1)
	if v, ok := in[int64(4)]; ok {
		if a.opts.CTAP20 {
			return nil, errInvalidCBOR // CTAP 2.0 knows keys 1 to 3 only
		}
		p, ok := v.(int64)
		if !ok {
			return nil, errUnexpectedType
		}
		proto = p
	}
	if !slices.Contains(a.opts.Protocols, int(proto)) {
		return nil, errInvalidParameter
	}
	peer, ok1 := in[int64(1)].(cbor.Map)
	saltEnc, ok2 := in[int64(2)].([]byte)
	saltAuth, ok3 := in[int64(3)].([]byte)
	if !ok1 || !ok2 || !ok3 {
		return nil, errMissingParameter
	}
	secret, st := a.agree(int(proto), peer)
	if st != okStatus {
		return nil, st
	}
	if !verify(int(proto), secret, saltEnc, saltAuth) {
		return nil, errPINAuthInvalid
	}
	salts, err := decrypt(int(proto), secret, saltEnc)
	if err != nil || (len(salts) != 32 && len(salts) != 64) {
		return nil, errInvalidLength
	}
	credRandom := c.noUV
	if uv {
		credRandom = c.withUV
	}
	var out []byte
	for i := 0; i < len(salts); i += 32 {
		m := hmac.New(sha256.New, credRandom)
		m.Write(salts[i : i+32])
		out = m.Sum(out)
	}
	return encrypt(int(proto), secret, out), okStatus
}

// agree is the key's side of ECDH with a platform key.
func (a *Authenticator) agree(proto int, peer cbor.Map) ([]byte, byte) {
	x, _ := peer[int64(-2)].([]byte)
	y, _ := peer[int64(-3)].([]byte)
	if kty, _ := peer[int64(1)].(int64); kty != 2 || len(x) != 32 || len(y) != 32 {
		return nil, errInvalidParameter
	}
	if crv, _ := peer[int64(-1)].(int64); crv != 1 {
		return nil, errInvalidParameter
	}
	pub, err := ecdh.P256().NewPublicKey(append(append([]byte{4}, x...), y...))
	if err != nil {
		return nil, errInvalidParameter
	}
	z, err := a.ka.ECDH(pub)
	if err != nil {
		return nil, errInvalidParameter
	}
	return kdf(proto, z), okStatus
}

func (a *Authenticator) clientPIN(params cbor.Map) (cbor.Map, byte) {
	sub, ok := params[int64(2)].(int64)
	if !ok {
		return nil, errMissingParameter
	}
	proto, hasProto := params[int64(1)].(int64)
	if hasProto && !slices.Contains(a.opts.Protocols, int(proto)) {
		return nil, errInvalidParameter
	}
	switch sub {
	case 0x01: // getPINRetries
		m := cbor.Map{3: int64(a.retries)}
		if !a.opts.CTAP20 {
			m[4] = false
		}
		return m, okStatus
	case 0x02: // getKeyAgreement
		if !hasProto {
			return nil, errMissingParameter
		}
		b := a.ka.PublicKey().Bytes()
		return cbor.Map{1: cbor.Map{1: int64(2), 3: int64(-25), -1: int64(1), -2: b[1:33], -3: b[33:65]}}, okStatus
	case 0x05, 0x09: // getPINToken, getPinUvAuthTokenUsingPinWithPermissions
		if !hasProto {
			return nil, errMissingParameter
		}
		perms := byte(0x03) // getPINToken: makeCredential and getAssertion
		rpID := ""
		if sub == 0x09 {
			if a.opts.CTAP20 {
				return nil, errInvalidSubcmd
			}
			p, ok := params[int64(9)].(int64)
			if !ok {
				return nil, errMissingParameter
			}
			if p == 0 || p > 0xff {
				return nil, errInvalidParameter
			}
			perms = byte(p)
			if r, ok := params[int64(0x0A)]; ok {
				if rpID, ok = r.(string); !ok {
					return nil, errUnexpectedType
				}
			}
		}
		peer, ok1 := params[int64(3)].(cbor.Map)
		pinHashEnc, ok2 := params[int64(6)].([]byte)
		if !ok1 || !ok2 {
			return nil, errMissingParameter
		}
		if a.pinHash == nil {
			return nil, errPINNotSet
		}
		if a.retries == 0 {
			return nil, errPINBlocked
		}
		if a.consecutive >= 3 {
			return nil, errPINAuthBlocked
		}
		secret, st := a.agree(int(proto), peer)
		if st != okStatus {
			return nil, st
		}
		a.retries--
		got, err := decrypt(int(proto), secret, pinHashEnc)
		if err != nil || len(got) != 16 || subtle.ConstantTimeCompare(got, a.pinHash) != 1 {
			a.ka, _ = ecdh.P256().GenerateKey(rand.Reader)
			a.consecutive++
			switch {
			case a.retries == 0:
				return nil, errPINBlocked
			case a.consecutive >= 3:
				return nil, errPINAuthBlocked
			}
			return nil, errPINInvalid
		}
		a.retries, a.consecutive = maxRetries, 0
		a.token, a.tokenPerms, a.tokenRPID = random(32), perms, rpID
		return cbor.Map{2: encrypt(int(proto), secret, a.token)}, okStatus
	}
	return nil, errInvalidSubcmd
}

// The PIN/UV auth protocols, from CTAP 2.1 §6.5.6 (one) and §6.5.7 (two).

func kdf(proto int, z []byte) []byte {
	if proto == 1 {
		h := sha256.Sum256(z)
		return h[:]
	}
	salt := make([]byte, 32)
	h, _ := hkdf.Key(sha256.New, z, salt, "CTAP2 HMAC key", 32)
	k, _ := hkdf.Key(sha256.New, z, salt, "CTAP2 AES key", 32)
	return append(h, k...)
}

func encrypt(proto int, key, pt []byte) []byte {
	iv := make([]byte, 16)
	if proto == 2 {
		key = key[32:]
		rand.Read(iv)
	}
	b, _ := aes.NewCipher(key)
	out := make([]byte, len(pt))
	cipher.NewCBCEncrypter(b, iv).CryptBlocks(out, pt)
	if proto == 2 {
		return append(iv, out...)
	}
	return out
}

func decrypt(proto int, key, ct []byte) ([]byte, error) {
	iv := make([]byte, 16)
	if proto == 2 {
		key = key[32:]
		if len(ct) < 16 {
			return nil, errors.New("short")
		}
		iv, ct = ct[:16], ct[16:]
	}
	if len(ct) == 0 || len(ct)%16 != 0 {
		return nil, errors.New("not blocks")
	}
	b, _ := aes.NewCipher(key)
	out := make([]byte, len(ct))
	cipher.NewCBCDecrypter(b, iv).CryptBlocks(out, ct)
	return out, nil
}

func verify(proto int, key, msg, sig []byte) bool {
	if proto == 2 && len(key) == 64 {
		key = key[:32]
	}
	m := hmac.New(sha256.New, key)
	m.Write(msg)
	want := m.Sum(nil)
	if proto == 1 {
		want = want[:16]
	}
	return hmac.Equal(want, sig)
}

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}
