package svd

import (
	"bytes"
	"context"
	"crypto"
	"encoding/pem"
	"errors"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
)

// The SSH agent face: secretvaultd as ssh-agent (the protocol of
// draft-ietf-sshm-ssh-agent), on its own socket. Keys are vault items of
// kind "ssh-key" (fields private_key, and passphrase if the key has one);
// every unlocked vault's keys are offered.
//
//   - Listing keys (public keys only) needs the vault unlocked, and asks for
//     its passphrase if every vault is locked.
//   - Signing is an access like any other: the program asking (ssh, git,
//     or the local ssh of a session whose agent is forwarded) is identified
//     and, unless a decision covers it, the person is asked. An item with
//     the attribute confirm=always is asked about on every use.
//   - ssh-add stores a new key in the default vault, with consent.
//   - ssh-add -d and -D do not delete anything: keys live in vaults, and are
//     removed there. ssh-add -x / -X lock and unlock the default vault.

// OpSign is signing with a key held in a vault.
const OpSign = svbroker.OpSign

// ServeSSHAgent answers the SSH agent protocol on ln, from a goroutine of
// its own, until ctx ends. By the time it returns, the SSH agent sockets
// of the GnuPG homes pointed at the daemon are linked to ln's
// (gpgagent_link.go).
func (d *Daemon) ServeSSHAgent(ctx context.Context, ln net.Listener) {
	d.mu.Lock()
	d.sshSock = ln.Addr().String()
	d.mu.Unlock()
	d.relinkGnuPG(true)
	go d.acceptSSHAgent(ctx, ln)
}

func (d *Daemon) acceptSSHAgent(ctx context.Context, ln net.Listener) {
	defer func() {
		d.mu.Lock()
		d.sshSock = ""
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
				d.opts.Log("ssh agent refused a connection: " + err.Error())
				return
			}
			a := &sshAgent{d: d, ctx: ctx, cl: &client{proc: proc}}
			agent.ServeAgent(a, conn)
			d.broker.DropConn(a.cl)
		}()
	}
}

type sshAgent struct {
	d   *Daemon
	ctx context.Context
	cl  *client
}

// sshKey is a key found in a vault.
type sshKey struct {
	mv   *managedVault
	e    svcore.Entry
	pub  ssh.PublicKey
	name string
}

// keys returns every SSH key of the unlocked vaults. Each entry's fields
// must be wiped by the caller.
func (a *sshAgent) keys() []sshKey {
	a.d.mu.Lock()
	var vaults []*managedVault
	for _, mv := range a.d.vaults {
		if mv.v != nil && !mv.v.Locked() {
			vaults = append(vaults, mv)
		}
	}
	a.d.mu.Unlock()
	var out []sshKey
	for _, mv := range vaults {
		entries, err := mv.v.List("")
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.Item.Kind != "ssh-key" {
				e.Item.Wipe()
				continue
			}
			pub := publicKeyOf(&e.Item)
			if pub == nil {
				e.Item.Wipe()
				continue
			}
			out = append(out, sshKey{mv: mv, e: e, pub: pub, name: e.Item.Name})
		}
	}
	return out
}

// publicKeyOf reads an item's public key: the public_key field, else the
// private key's public half.
func publicKeyOf(it *svcore.Item) ssh.PublicKey {
	if f, ok := it.Field("public_key"); ok {
		if pub, _, _, _, err := ssh.ParseAuthorizedKey(f.Value); err == nil {
			return pub
		}
	}
	signer, err := signerOf(it)
	if err != nil {
		return nil
	}
	return signer.PublicKey()
}

// signerOf parses an item's private key, with its passphrase field if it
// has one.
func signerOf(it *svcore.Item) (ssh.Signer, error) {
	f, ok := it.Field("private_key")
	if !ok {
		return nil, errors.New("the item has no private_key field")
	}
	if p, ok := it.Field("passphrase"); ok && len(p.Value) > 0 {
		return ssh.ParsePrivateKeyWithPassphrase(f.Value, p.Value)
	}
	return ssh.ParsePrivateKey(f.Value)
}

func wipeKeys(ks []sshKey) {
	for i := range ks {
		ks[i].e.Item.Wipe()
	}
}

// List offers the public keys of every unlocked vault. With every vault
// locked it asks for the default vault's passphrase first.
func (a *sshAgent) List() ([]*agent.Key, error) {
	ks := a.keys()
	if len(ks) == 0 {
		if mv, err := a.d.vault(""); err == nil && mv.v.Locked() {
			ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
			defer cancel()
			why := a.cl.display() + " wants to use your SSH keys."
			if _, _, err := a.d.ensureUnlocked(ctx, a.cl, mv, why); err == nil {
				ks = a.keys()
			}
		}
	}
	defer wipeKeys(ks)
	var out []*agent.Key
	for _, k := range ks {
		comment := k.e.Item.Label
		if comment == "" {
			comment = k.name
		}
		out = append(out, &agent.Key{Format: k.pub.Type(), Blob: k.pub.Marshal(), Comment: comment})
	}
	return out, nil
}

func (a *sshAgent) Sign(key ssh.PublicKey, data []byte) (*ssh.Signature, error) {
	return a.SignWithFlags(key, data, 0)
}

// SignWithFlags signs with a vault key, after consent.
func (a *sshAgent) SignWithFlags(key ssh.PublicKey, data []byte, flags agent.SignatureFlags) (*ssh.Signature, error) {
	ks := a.keys()
	defer wipeKeys(ks)
	want := key.Marshal()
	for _, k := range ks {
		if !bytes.Equal(k.pub.Marshal(), want) {
			continue
		}
		ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
		defer cancel()
		authorize := a.d.authorize
		if k.e.Item.Attrs["confirm"] == "always" {
			authorize = a.d.authorizeEveryTime
		}
		if err := authorize(ctx, a.cl, k.mv, k.e.ID.String(), k.name, OpSign); err != nil {
			return nil, err
		}
		signer, err := signerOf(&k.e.Item)
		if err != nil {
			return nil, err
		}
		if as, ok := signer.(ssh.AlgorithmSigner); ok && flags != 0 {
			alg := ssh.KeyAlgoRSA
			switch {
			case flags&agent.SignatureFlagRsaSha512 != 0:
				alg = ssh.KeyAlgoRSASHA512
			case flags&agent.SignatureFlagRsaSha256 != 0:
				alg = ssh.KeyAlgoRSASHA256
			}
			return as.SignWithAlgorithm(nil, data, alg)
		}
		return signer.Sign(nil, data)
	}
	return nil, errors.New("that key is not in any unlocked vault")
}

// Add stores a key ssh-add gives into the default vault.
func (a *sshAgent) Add(key agent.AddedKey) error {
	mv, err := a.d.vault("")
	if err != nil {
		return err
	}
	signer, err := ssh.NewSignerFromKey(key.PrivateKey)
	if err != nil {
		return err
	}
	pub := signer.PublicKey()
	comment := key.Comment
	if comment == "" {
		comment = ssh.FingerprintSHA256(pub)
	}
	name := "ssh/" + strings.NewReplacer("/", "∕", "\n", " ").Replace(comment)
	ctx, cancel := context.WithTimeout(a.ctx, 2*time.Minute)
	defer cancel()
	if err := a.d.authorize(ctx, a.cl, mv, "", name, svbroker.OpWrite); err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(key.PrivateKey.(crypto.PrivateKey), comment)
	if err != nil {
		return err
	}
	var buf bytes.Buffer
	pem.Encode(&buf, block)
	clear(block.Bytes)
	attrs := map[string]string{"fingerprint": ssh.FingerprintSHA256(pub)}
	if key.ConfirmBeforeUse {
		attrs["confirm"] = "always"
	}
	it := svcore.Item{Kind: "ssh-key", Name: name, Label: comment, Attrs: attrs, Fields: []svcore.Field{
		{Name: "private_key", Type: svcore.FieldKey, Value: buf.Bytes()},
		{Name: "public_key", Type: svcore.FieldText, Value: ssh.MarshalAuthorizedKey(pub)},
	}}
	_, err = mv.v.Put(it)
	it.Wipe()
	return err
}

var errKeysLiveInVaults = errors.New("keys live in vaults: remove them with 'secretvault rm'")

func (a *sshAgent) Remove(ssh.PublicKey) error { return errKeysLiveInVaults }
func (a *sshAgent) RemoveAll() error           { return errKeysLiveInVaults }

// Lock (ssh-add -x) locks the default vault; Unlock (ssh-add -X) unlocks
// it with the passphrase given.
func (a *sshAgent) Lock([]byte) error {
	mv, err := a.d.vault("")
	if err != nil {
		return err
	}
	a.d.lock(mv, "ssh-add -x by "+a.cl.display())
	return nil
}

func (a *sshAgent) Unlock(passphrase []byte) error {
	mv, err := a.d.vault("")
	if err != nil {
		return err
	}
	if !mv.v.Locked() {
		return mv.v.CheckKey(svcore.Passphrase(passphrase))
	}
	return a.d.unlockWith(mv, svcore.Passphrase(passphrase))
}

func (a *sshAgent) Signers() ([]ssh.Signer, error) { return nil, errors.New("not supported") }

func (a *sshAgent) Extension(string, []byte) ([]byte, error) {
	return nil, agent.ErrExtensionUnsupported
}
