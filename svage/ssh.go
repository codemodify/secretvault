package svage

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/ssh"
)

// SSH keys as recipients and identities, as age supports them for people
// who already have one (they are not in the C2SP spec; this follows age's
// agessh package).
//
//	-> ssh-ed25519 <tag> <ephemeral share>   X25519 with the key mapped to
//	                                         Curve25519, the shared secret
//	                                         tweaked by the SSH public key
//	-> ssh-rsa <tag>                         RSA-OAEP-SHA256
//
// The tag is the first four bytes of SHA-256 of the SSH public key, so an
// identity knows which stanzas are its own (and a file says which SSH key
// can open it).

const (
	sshEd25519Label = "age-encryption.org/v1/ssh-ed25519"
	sshRSALabel     = "age-encryption.org/v1/ssh-rsa"
)

func sshTag(pk ssh.PublicKey) string {
	h := sha256.Sum256(pk.Marshal())
	return encodeB64(h[:4])
}

// ParseSSHRecipient reads an OpenSSH public key line, as in
// authorized_keys: "ssh-ed25519 AAAA... comment" or "ssh-rsa AAAA...".
func ParseSSHRecipient(line string) (Recipient, error) {
	pk, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return nil, fmt.Errorf("svage: malformed SSH public key: %v", err)
	}
	return NewSSHRecipient(pk)
}

// NewSSHRecipient makes a recipient of an ssh-ed25519 or ssh-rsa key.
func NewSSHRecipient(pk ssh.PublicKey) (Recipient, error) {
	cpk, ok := pk.(ssh.CryptoPublicKey)
	if !ok {
		return nil, errors.New("svage: unsupported SSH key")
	}
	switch k := cpk.CryptoPublicKey().(type) {
	case ed25519.PublicKey:
		u, err := ed25519ToX25519(k)
		if err != nil {
			return nil, err
		}
		pub, err := ecdh.X25519().NewPublicKey(u)
		if err != nil {
			return nil, err
		}
		return &SSHEd25519Recipient{ssh: pk, pub: pub}, nil
	case *rsa.PublicKey:
		if k.N.BitLen() < 2048 {
			return nil, errors.New("svage: RSA keys shorter than 2048 bits are refused")
		}
		return &SSHRSARecipient{ssh: pk, pub: k}, nil
	}
	return nil, fmt.Errorf("svage: SSH keys of type %s are not supported (use ssh-ed25519 or ssh-rsa)", pk.Type())
}

// SSHEd25519Recipient is an ssh-ed25519 public key.
type SSHEd25519Recipient struct {
	ssh ssh.PublicKey
	pub *ecdh.PublicKey // the key on Curve25519
}

// String is the key's authorized_keys form.
func (r *SSHEd25519Recipient) String() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(r.ssh)))
}

// Wrap implements Recipient.
func (r *SSHEd25519Recipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	eph, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	shared, err := eph.ECDH(r.pub)
	if err != nil {
		return nil, fmt.Errorf("svage: unusable ssh-ed25519 recipient: %v", err)
	}
	defer clear(shared)
	share := eph.PublicKey().Bytes()
	key, err := sshEd25519Key(r.ssh, shared, share, r.pub.Bytes())
	if err != nil {
		return nil, err
	}
	defer clear(key)
	body, err := sealKey(key, fileKey)
	if err != nil {
		return nil, err
	}
	return []*Stanza{{Type: "ssh-ed25519", Args: []string{sshTag(r.ssh), encodeB64(share)}, Body: body}}, nil
}

// sshEd25519Key derives the wrap key from the X25519 shared secret,
// first tweaking it with a scalar derived from the SSH public key.
func sshEd25519Key(pk ssh.PublicKey, shared, share, recipient []byte) ([]byte, error) {
	tweak, err := hkdf.Key(sha256.New, nil, pk.Marshal(), sshEd25519Label, 32)
	if err != nil {
		return nil, err
	}
	defer clear(tweak)
	tk, err := ecdh.X25519().NewPrivateKey(tweak)
	if err != nil {
		return nil, err
	}
	sp, err := ecdh.X25519().NewPublicKey(shared)
	if err != nil {
		return nil, err
	}
	tweaked, err := tk.ECDH(sp)
	if err != nil {
		return nil, err
	}
	defer clear(tweaked)
	salt := append(append([]byte(nil), share...), recipient...)
	return hkdf.Key(sha256.New, tweaked, salt, sshEd25519Label, chacha20poly1305.KeySize)
}

// SSHRSARecipient is an ssh-rsa public key.
type SSHRSARecipient struct {
	ssh ssh.PublicKey
	pub *rsa.PublicKey
}

// String is the key's authorized_keys form.
func (r *SSHRSARecipient) String() string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(r.ssh)))
}

// Wrap implements Recipient.
func (r *SSHRSARecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	body, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, r.pub, fileKey, []byte(sshRSALabel))
	if err != nil {
		return nil, err
	}
	return []*Stanza{{Type: "ssh-rsa", Args: []string{sshTag(r.ssh)}, Body: body}}, nil
}

// ParseSSHIdentity reads an SSH private key (OpenSSH or PEM format,
// ssh-ed25519 or ssh-rsa). For a key protected by a passphrase it calls
// passphrase, but only once a stanza for that key turns up, and wipes
// what it returns; with a nil passphrase such keys are an error.
func ParseSSHIdentity(pemBytes []byte, passphrase func() ([]byte, error)) (Identity, error) {
	k, err := ssh.ParseRawPrivateKey(pemBytes)
	var missing *ssh.PassphraseMissingError
	if errors.As(err, &missing) {
		if passphrase == nil {
			return nil, errors.New("svage: the SSH key is protected by a passphrase")
		}
		return &sshEncryptedIdentity{pem: append([]byte(nil), pemBytes...), pub: missing.PublicKey, passphrase: passphrase}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("svage: malformed SSH private key: %v", err)
	}
	return newSSHIdentity(k)
}

func newSSHIdentity(k any) (Identity, error) {
	switch k := k.(type) {
	case *ed25519.PrivateKey:
		return NewSSHEd25519Identity(*k)
	case ed25519.PrivateKey:
		return NewSSHEd25519Identity(k)
	case *rsa.PrivateKey:
		return NewSSHRSAIdentity(k)
	}
	return nil, fmt.Errorf("svage: SSH keys of type %T are not supported (use ssh-ed25519 or ssh-rsa)", k)
}

// SSHEd25519Identity is an ssh-ed25519 private key.
type SSHEd25519Identity struct {
	ssh  ssh.PublicKey
	priv *ecdh.PrivateKey // the key on Curve25519
}

func (*SSHEd25519Identity) native() {}

// NewSSHEd25519Identity makes an identity of an Ed25519 private key.
func NewSSHEd25519Identity(k ed25519.PrivateKey) (*SSHEd25519Identity, error) {
	pk, err := ssh.NewPublicKey(k.Public())
	if err != nil {
		return nil, err
	}
	h := sha512.Sum512(k.Seed())
	defer clear(h[:])
	priv, err := ecdh.X25519().NewPrivateKey(h[:32])
	if err != nil {
		return nil, err
	}
	return &SSHEd25519Identity{ssh: pk, priv: priv}, nil
}

// Recipient is the identity's public half.
func (id *SSHEd25519Identity) Recipient() Recipient {
	return &SSHEd25519Recipient{ssh: id.ssh, pub: id.priv.PublicKey()}
}

// Unwrap implements Identity.
func (id *SSHEd25519Identity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(id.unwrap, stanzas)
}

func (id *SSHEd25519Identity) unwrap(s *Stanza) ([]byte, error) {
	if s.Type != "ssh-ed25519" {
		return nil, ErrIncorrectIdentity
	}
	if len(s.Args) != 2 {
		return nil, errors.New("an ssh-ed25519 stanza has two arguments")
	}
	share, err := decodeB64(s.Args[1])
	if err != nil || len(share) != 32 {
		return nil, errors.New("the ephemeral share is not 32 bytes of canonical base64")
	}
	if s.Args[0] != sshTag(id.ssh) {
		return nil, ErrIncorrectIdentity
	}
	if len(s.Body) != FileKeySize+chacha20poly1305.Overhead {
		return nil, errBodySize
	}
	pk, err := ecdh.X25519().NewPublicKey(share)
	if err != nil {
		return nil, err
	}
	shared, err := id.priv.ECDH(pk)
	if err != nil {
		return nil, errors.New("the ephemeral share is a low-order point")
	}
	defer clear(shared)
	key, err := sshEd25519Key(id.ssh, shared, share, id.priv.PublicKey().Bytes())
	if err != nil {
		return nil, err
	}
	defer clear(key)
	fileKey, err := openKey(key, s.Body)
	if err != nil {
		return nil, ErrIncorrectIdentity
	}
	return fileKey, nil
}

// SSHRSAIdentity is an ssh-rsa private key.
type SSHRSAIdentity struct {
	ssh  ssh.PublicKey
	priv *rsa.PrivateKey
}

func (*SSHRSAIdentity) native() {}

// NewSSHRSAIdentity makes an identity of an RSA private key.
func NewSSHRSAIdentity(k *rsa.PrivateKey) (*SSHRSAIdentity, error) {
	pk, err := ssh.NewPublicKey(&k.PublicKey)
	if err != nil {
		return nil, err
	}
	return &SSHRSAIdentity{ssh: pk, priv: k}, nil
}

// Recipient is the identity's public half.
func (id *SSHRSAIdentity) Recipient() Recipient {
	return &SSHRSARecipient{ssh: id.ssh, pub: &id.priv.PublicKey}
}

// Unwrap implements Identity.
func (id *SSHRSAIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	return multiUnwrap(id.unwrap, stanzas)
}

func (id *SSHRSAIdentity) unwrap(s *Stanza) ([]byte, error) {
	if s.Type != "ssh-rsa" {
		return nil, ErrIncorrectIdentity
	}
	if len(s.Args) != 1 {
		return nil, errors.New("an ssh-rsa stanza has one argument")
	}
	if s.Args[0] != sshTag(id.ssh) {
		return nil, ErrIncorrectIdentity
	}
	fileKey, err := rsa.DecryptOAEP(sha256.New(), nil, id.priv, s.Body, []byte(sshRSALabel))
	if err != nil {
		return nil, ErrIncorrectIdentity
	}
	if len(fileKey) != FileKeySize {
		clear(fileKey)
		return nil, errBodySize
	}
	return fileKey, nil
}

// sshEncryptedIdentity is a passphrase-protected SSH key, opened the first
// time a stanza for it turns up.
type sshEncryptedIdentity struct {
	pem        []byte
	pub        ssh.PublicKey // nil for old PEM keys, which hide it too
	passphrase func() ([]byte, error)

	mu sync.Mutex
	id Identity
}

func (e *sshEncryptedIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	if !e.mayMatch(stanzas) {
		return nil, ErrIncorrectIdentity
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.id == nil {
		pass, err := e.passphrase()
		if err != nil {
			return nil, fmt.Errorf("svage: the SSH key's passphrase: %w", err)
		}
		k, err := ssh.ParseRawPrivateKeyWithPassphrase(e.pem, pass)
		clear(pass)
		if err != nil {
			return nil, fmt.Errorf("svage: opening the SSH key: %v", err)
		}
		if e.id, err = newSSHIdentity(k); err != nil {
			return nil, err
		}
		clear(e.pem)
	}
	return e.id.Unwrap(stanzas)
}

// mayMatch reports whether any stanza could be for this key.
func (e *sshEncryptedIdentity) mayMatch(stanzas []*Stanza) bool {
	for _, s := range stanzas {
		if s.Type != "ssh-ed25519" && s.Type != "ssh-rsa" {
			continue
		}
		if e.pub == nil {
			return true
		}
		if s.Type == e.pub.Type() && len(s.Args) > 0 && s.Args[0] == sshTag(e.pub) {
			return true
		}
	}
	return false
}

// Ed25519 to X25519. An Edwards point (x, y) maps to the Montgomery u =
// (1 + y) / (1 - y). The key is public, so plain big-integer arithmetic
// does; it also checks that y is on the curve, as decoding the point
// would, accepting the same non-canonical encodings Go's and age's
// Edwards decoders do (y not reduced, and a sign bit on x = 0).

var (
	p25519 = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	// d = -121665 / 121666
	d25519 = new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), new(big.Int).ModInverse(big.NewInt(121666), p25519)), p25519)
)

func ed25519ToX25519(pk ed25519.PublicKey) ([]byte, error) {
	if len(pk) != ed25519.PublicKeySize {
		return nil, errors.New("svage: an Ed25519 key must be 32 bytes")
	}
	le := make([]byte, 32)
	for i := range 32 {
		le[31-i] = pk[i]
	}
	le[0] &= 0x7f // the sign of x
	p := p25519
	y := new(big.Int).SetBytes(le)
	y.Mod(y, p)
	// x^2 = (y^2 - 1) / (d y^2 + 1) must be a square.
	y2 := new(big.Int).Mul(y, y)
	num := new(big.Int).Sub(y2, big.NewInt(1))
	den := new(big.Int).Mul(d25519, y2)
	den.Add(den, big.NewInt(1)).Mod(den, p)
	x2 := num.Mul(num, new(big.Int).ModInverse(den, p))
	x2.Mod(x2, p)
	if x2.Sign() != 0 && new(big.Int).Exp(x2, new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1), p).Cmp(big.NewInt(1)) != 0 {
		return nil, errors.New("svage: the Ed25519 key is not a point on the curve")
	}
	oneMinusY := new(big.Int).Sub(big.NewInt(1), y)
	oneMinusY.Mod(oneMinusY, p)
	if oneMinusY.Sign() == 0 {
		return nil, errors.New("svage: the Ed25519 key is the identity point")
	}
	u := new(big.Int).Add(big.NewInt(1), y)
	u.Mul(u, new(big.Int).ModInverse(oneMinusY, p)).Mod(u, p)
	out := make([]byte, 32)
	u.FillBytes(out)
	for i := range 16 {
		out[i], out[31-i] = out[31-i], out[i]
	}
	return out, nil
}
