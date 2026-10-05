package svd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svgpgagent"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

// The gpg-agent face: secretvaultd as GnuPG's agent (svgpgagent), on its
// own socket, so that gpg signs and decrypts with the OpenPGP keys in the
// vaults (pgp.go) without the keys leaving the daemon. gpg holds only the
// public keys; it names each (sub)key by its keygrip.
//
//   - Every unlocked vault's keys are offered: each part (primary key or
//     subkey) whose secret key material the item holds. When gpg asks for
//     a key that is not there and the default vault is locked, its
//     passphrase is asked for, once per connection.
//   - Signing (PKSIGN) is OpSign on the key's item and decrypting
//     (PKDECRYPT) OpDecrypt, decided as for any program: the program on
//     the socket (gpg) is identified and, unless a decision covers it,
//     the person is asked. An item with the attribute confirm=always is
//     asked about on every use.
//   - Nothing on this socket reads a key out, writes one in, or deletes
//     one: keys are made and imported with 'secretvault pgp'.
//
// gpg finds its agent by the socket in its socket directory (gpgconf
// --list-dirs agent-socket); gnupg.link makes that a link to this face's
// socket, and the daemon makes the links again each time it starts
// (gpgagent_link.go).

// gpgAgentVersion answers GETINFO version. gpg warns when its agent is
// older than itself, which would only mislead here: this is no gpg-agent
// left running from before an upgrade. So the version is above any
// GnuPG 2, and says whose it is.
const gpgAgentVersion = "2.99.0-secretvault"

// GPGAgentEnabled reports whether the config wants the gpg-agent socket.
// The host daemon never serves one, nor does Windows, where gpg reaches
// its agent through a TCP socket emulation this face does not speak.
func (d *Daemon) GPGAgentEnabled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.cfg.NoGPGAgent && d.host == nil && runtime.GOOS != "windows"
}

// ServeGPGAgent answers gpg-agent's protocol on ln, from a goroutine of
// its own, until ctx ends. By the time it returns, the GnuPG homes
// pointed at the daemon are linked to ln's socket, and gnupg.link knows
// it: call it before the daemon's own socket is served, which gpg's
// agent-program may be waiting on.
func (d *Daemon) ServeGPGAgent(ctx context.Context, ln net.Listener) {
	sock := ln.Addr().String()
	d.mu.Lock()
	d.gpgSock = sock
	d.mu.Unlock()
	d.relinkGnuPG(false)
	go d.acceptGPGAgent(ctx, ln, sock)
}

func (d *Daemon) acceptGPGAgent(ctx context.Context, ln net.Listener, sock string) {
	defer func() {
		d.mu.Lock()
		d.gpgSock = ""
		d.mu.Unlock()
	}()
	go func() { <-ctx.Done(); ln.Close() }()
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			proc, err := d.opts.Peer(conn)
			if err != nil {
				d.opts.Log("gpg-agent face refused a connection: " + err.Error())
				return
			}
			a := &gpgAgent{d: d, ctx: ctx, cl: &client{proc: proc}}
			d.mu.Lock()
			ssh := d.sshSock
			d.mu.Unlock()
			svgpgagent.Serve(conn, a, svgpgagent.Config{Version: gpgAgentVersion, PID: os.Getpid(), Socket: sock, SSHSocket: ssh})
			d.broker.DropConn(a.cl)
		}()
	}
}

// gpgAgent is one connection: the program on it, and whether it has
// been through an unlock already.
type gpgAgent struct {
	d      *Daemon
	ctx    context.Context
	cl     *client
	unlock bool // the default vault's passphrase was asked for

	// The keys found a moment ago. gpg -K asks about every key in its
	// keyring, one KEYINFO each; this spares a scan of the vaults for
	// each. It holds nothing secret, and signing and decrypting read the
	// item again.
	keys    []gpgKey
	keysAge time.Time
}

// gpgKeysFresh is how long a connection's scan stands.
const gpgKeysFresh = 2 * time.Second

// scan is the keys of the unlocked vaults, as found at most a moment ago.
func (a *gpgAgent) scan() []gpgKey {
	if a.keys == nil || time.Since(a.keysAge) > gpgKeysFresh {
		a.keys, a.keysAge = a.d.gpgKeys(), time.Now()
	}
	return a.keys
}

// gpgKey is a part of an OpenPGP key in an unlocked vault, as gpg names
// it.
type gpgKey struct {
	svgpgagent.Key
	mv   *managedVault
	id   string // the item's object ID
	name string
	fp   []byte // the part's fingerprint
}

// gpgKeys lists the parts with secret key material of every OpenPGP key
// in the unlocked vaults.
func (d *Daemon) gpgKeys() []gpgKey {
	d.mu.Lock()
	var vaults []*managedVault
	for _, mv := range d.vaults {
		if mv.v != nil && !mv.v.Locked() {
			vaults = append(vaults, mv)
		}
	}
	d.mu.Unlock()
	var out []gpgKey
	for _, mv := range vaults {
		items, err := pgpItems(mv)
		if err != nil {
			continue
		}
		for _, it := range items {
			out = append(out, partsOf(mv, it)...)
			it.e.Item.Wipe()
		}
	}
	return out
}

// partsOf lists an item's parts that have secret key material and a
// keygrip.
func partsOf(mv *managedVault, it pgpItem) []gpgKey {
	f, ok := it.e.Item.Field(svrpc.PGPSecretField)
	if !ok {
		return nil
	}
	k, err := svpgp.ReadKey(bytes.NewReader(f.Value))
	if err != nil {
		return nil
	}
	defer k.Close()
	var out []gpgKey
	for _, p := range k.Parts() {
		if !p.HasSecret {
			continue // a GnuPG stub: the secret is elsewhere
		}
		grip, err := svgpgagent.Keygrip(p.Algorithm, p.Public)
		if err != nil {
			continue
		}
		out = append(out, gpgKey{
			Key: svgpgagent.Key{Keygrip: grip, Algorithm: p.Algorithm, Public: p.Public,
				Confirm: it.e.Item.Attrs["confirm"] == "always"},
			mv: mv, id: it.e.ID.String(), name: it.e.Item.Name, fp: p.Fingerprint,
		})
	}
	return out
}

// unlockDefault asks for the default vault's passphrase when the vault
// is locked, once per connection: gpg is looking for a key, and it may be
// there. It reports whether the vault was unlocked.
func (a *gpgAgent) unlockDefault() bool {
	if a.unlock {
		return false
	}
	mv, err := a.d.vault("")
	if err != nil || !mv.v.Locked() {
		return false
	}
	a.unlock = true
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	defer cancel()
	why := a.cl.display() + " wants to use your OpenPGP keys."
	if _, _, err = a.d.ensureUnlocked(ctx, a.cl, mv, why); err != nil {
		return false
	}
	a.keys = nil // scan again
	return true
}

// find is the key with a keygrip.
func (a *gpgAgent) find(grip []byte) (gpgKey, error) {
	for range 2 {
		for _, k := range a.scan() {
			if bytes.Equal(k.Keygrip, grip) {
				return k, nil
			}
		}
		if !a.unlockDefault() {
			break
		}
	}
	return gpgKey{}, svgpgagent.ErrNoKey
}

// Keys lists what can be used; with nothing unlocked, it asks for the
// default vault's passphrase first.
func (a *gpgAgent) Keys() ([]svgpgagent.Key, error) {
	keys := a.scan()
	if len(keys) == 0 && a.unlockDefault() {
		keys = a.scan()
	}
	out := make([]svgpgagent.Key, len(keys))
	for i, k := range keys {
		out[i] = k.Key
	}
	return out, nil
}

func (a *gpgAgent) Key(grip []byte) (svgpgagent.Key, error) {
	k, err := a.find(grip)
	return k.Key, err
}

// Sign signs with the key, after consent.
func (a *gpgAgent) Sign(grip []byte, h svpgp.HashAlgorithm, digest []byte) ([][]byte, error) {
	k, err := a.find(grip)
	if err != nil {
		return nil, err
	}
	var sig [][]byte
	err = a.use(k, svbroker.OpSign, func(key *svpgp.Key) (err error) {
		sig, err = key.SignDigest(k.fp, h, digest)
		return err
	})
	return sig, err
}

// Decrypt decrypts with the key, after consent: RSA's session key, or
// ECDH's shared point.
func (a *gpgAgent) Decrypt(grip []byte, data []byte) ([]byte, error) {
	k, err := a.find(grip)
	if err != nil {
		return nil, err
	}
	var out []byte
	err = a.use(k, svbroker.OpDecrypt, func(key *svpgp.Key) (err error) {
		switch k.Algorithm {
		case svpgp.RSA, svpgp.RSAEncryptOnly:
			out, err = key.DecryptPKCS1(k.fp, data)
		default:
			out, err = key.SharedPoint(k.fp, data)
		}
		return err
	})
	return out, err
}

// use authorizes op on the key's item, as pgp.sign and pgp.decrypt do
// (confirm=always asks every time), and runs f with the secret key.
func (a *gpgAgent) use(k gpgKey, op svbroker.Op, f func(*svpgp.Key) error) error {
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	defer cancel()
	_, it, err := a.d.pgpKey(ctx, a.cl, k.mv.cfg.Name, op, withID(k.id))
	if err != nil {
		return gpgError(err)
	}
	defer it.e.Item.Wipe()
	key, err := pgpSecretOf(&it.e.Item)
	if err != nil {
		return err
	}
	defer key.Close()
	return f(key)
}

// withID picks the item with an object ID.
func withID(id string) func(*managedVault, []pgpItem) ([]pgpItem, error) {
	return func(mv *managedVault, items []pgpItem) ([]pgpItem, error) {
		for _, it := range items {
			if it.e.ID.String() == id {
				return []pgpItem{it}, nil
			}
		}
		return nil, svrpc.Errorf(svrpc.CodeNotFound, "the key is no longer in vault %q", mv.cfg.Name)
	}
}

// gpgError gives the daemon's refusals GnuPG's codes, so gpg says what
// happened: "Operation cancelled" when the person said no, "No pinentry"
// when nobody could be asked.
func gpgError(err error) error {
	code := svgpgagent.CodeInvalidValue
	switch {
	case errors.Is(err, svrpc.ErrDenied), errors.Is(err, svrpc.ErrCanceled):
		code = svgpgagent.CodeCanceled
	case errors.Is(err, svrpc.ErrNoPrompter):
		code = svgpgagent.CodeNoPinentry
	case errors.Is(err, svrpc.ErrLocked), errors.Is(err, svrpc.ErrNotFound), errors.Is(err, svrpc.ErrNoVault):
		// GnuPG has no word for a missing vault: to gpg, the key is not
		// there. The message says which.
		code = svgpgagent.CodeNoSecretKey
	case errors.Is(err, svrpc.ErrWrongKey):
		code = svgpgagent.CodeBadPassphrase
	case errors.Is(err, context.DeadlineExceeded):
		code = svgpgagent.CodeTimeout
	}
	return svgpgagent.Errorf(code, "%s", fmt.Sprint(err))
}
