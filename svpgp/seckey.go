package svpgp

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"math/big"
	"slices"

	"github.com/codemodify/secretvault/svcrypto"
)

// Secret key packets (RFC 9580, section 5.5.3) and their protection
// (section 3.7.2.1).
//
// Decrypted secret key material is kept in an svcrypto.Secret: locked
// memory, zeroed when the key is locked or closed. The standard library's
// key types are built from it for each operation and wiped afterwards as
// far as Go allows; see the package documentation for the limits.

// S2K usage octets.
const (
	usageNone      = 0
	usageAEAD      = 253
	usageCFB       = 254
	usageMalleable = 255
)

type secretKey struct {
	pub  *publicKey
	tag  packetType // ptSecretKey or ptSecretSubkey
	raw  []byte     // the packet body, for a protected or stub key
	prot keyProtection

	secret *svcrypto.Secret // the cleartext secret material, when unlocked

	// unavailable says why there is no secret material to unlock: a
	// GnuPG stub (the key is elsewhere, or on a card), or a protection
	// this package refuses.
	unavailable error
}

type keyProtection struct {
	usage  byte
	cipher CipherAlgorithm
	aead   AEADAlgorithm
	s2k    *s2k
	iv     []byte // the CFB IV or the AEAD nonce
	data   []byte // the encrypted material with its check value or tag
}

// parseSecretKey reads a secret key or secret subkey packet.
func parseSecretKey(body []byte, tag packetType) (*secretKey, error) {
	pub, rest, err := parsePublicKey(body, true)
	if err != nil {
		return nil, err
	}
	sk := &secretKey{pub: pub, tag: tag}
	p := newParser(rest)
	sk.prot.usage = p.u8()
	if p.err != nil {
		return nil, p.err
	}
	v6 := pub.version == 6
	if sk.prot.usage == usageNone {
		material := p.rest()
		if !v6 {
			if len(material) < 2 {
				return nil, malformed("secret key without its checksum")
			}
			sum := binary.BigEndian.Uint16(material[len(material)-2:])
			material = material[:len(material)-2]
			if checksum16(material) != sum {
				return nil, malformed("secret key checksum mismatch")
			}
		}
		if pub.unusable != nil {
			// The material cannot be checked; keep the packet as it is.
			sk.raw = body
			sk.unavailable = pub.unusable
			return sk, nil
		}
		// The cleartext now lives in protected memory; wipe the packet's
		// copy whether or not it was good.
		err := sk.setMaterial(material)
		clear(material)
		if err != nil {
			return nil, err
		}
		return sk, nil
	}
	sk.raw = body
	params := p
	if v6 {
		if sk.prot.usage == usageMalleable {
			return nil, malformed("version 6 secret key with S2K usage 255")
		}
		n := int(p.u8())
		params = newParser(p.bytes(n))
		if p.err != nil {
			return nil, p.err
		}
	}
	switch sk.prot.usage {
	case usageAEAD, usageCFB, usageMalleable:
		sk.prot.cipher = CipherAlgorithm(params.u8())
		if sk.prot.usage == usageAEAD {
			sk.prot.aead = AEADAlgorithm(params.u8())
		}
		s2kParser := params
		if v6 {
			n := int(params.u8())
			s2kParser = newParser(params.bytes(n))
		}
		if params.err != nil {
			return nil, params.err
		}
		spec, err := parseS2K(s2kParser)
		if err != nil {
			if errors.Is(err, ErrUnsupported) {
				sk.unavailable = err
				return sk, nil
			}
			return nil, err
		}
		if v6 {
			s2kParser.done()
			if s2kParser.err != nil {
				return nil, s2kParser.err
			}
		}
		sk.prot.s2k = spec
		if spec.typ == s2kGNU {
			if v6 {
				return nil, malformed("GnuPG S2K extension in a version 6 key")
			}
			sk.unavailable = ErrKeyLocked
			if spec.gnuMode == 1 {
				sk.unavailable = errors.Join(ErrKeyLocked, errors.New("svpgp: the secret key is not in this copy (GnuPG stub)"))
			} else {
				sk.unavailable = errors.Join(ErrKeyLocked, errors.New("svpgp: the secret key is on a smartcard"))
			}
			return sk, nil
		}
		if spec.typ == s2kArgon2 && sk.prot.usage != usageAEAD {
			return nil, malformed("Argon2 S2K without AEAD protection")
		}
		if v6 && spec.typ == s2kSimple {
			return nil, malformed("simple S2K in a version 6 key")
		}
		var ivLen int
		if sk.prot.usage == usageAEAD {
			ivLen = sk.prot.aead.nonceSize()
			if ivLen == 0 {
				sk.unavailable = unsupported("secret key protected with %v", sk.prot.aead)
				return sk, nil
			}
		} else {
			ivLen = sk.prot.cipher.BlockSize()
			if ivLen == 0 {
				sk.unavailable = unsupported("secret key protected with %v", sk.prot.cipher)
				return sk, nil
			}
		}
		sk.prot.iv = params.bytes(ivLen)
	default:
		// A bare cipher ID: the passphrase is hashed with MD5.
		if v6 {
			return nil, malformed("version 6 secret key with S2K usage %d", sk.prot.usage)
		}
		sk.unavailable = unsupported("secret key protected with an MD5-derived key (S2K usage %d)", sk.prot.usage)
		return sk, nil
	}
	if v6 {
		params.done()
		if params.err != nil {
			return nil, params.err
		}
	}
	if p.err != nil {
		return nil, p.err
	}
	sk.prot.data = p.rest()
	if pub.unusable != nil {
		sk.unavailable = pub.unusable
	}
	return sk, nil
}

// locked reports whether the key has secret material that needs a
// passphrase first.
func (sk *secretKey) locked() bool { return sk.secret == nil }

// usable says whether the secret material can be used right now.
func (sk *secretKey) usable() error {
	if sk.unavailable != nil {
		return sk.unavailable
	}
	if sk.secret == nil {
		return ErrKeyLocked
	}
	return nil
}

// setMaterial checks cleartext secret material against the public key and
// keeps a copy in protected memory.
func (sk *secretKey) setMaterial(material []byte) error {
	parts, err := sk.decode(material)
	if err != nil {
		return err
	}
	parts.wipe()
	sk.secret.Destroy()
	sk.secret = svcrypto.NewSecret(len(material))
	copy(sk.secret.Bytes(), material)
	return nil
}

// unlock decrypts the secret material with a passphrase.
func (sk *secretKey) unlock(passphrase []byte, lim Limits) error {
	if sk.unavailable != nil {
		return sk.unavailable
	}
	if sk.secret != nil {
		return nil
	}
	pr := sk.prot
	v6 := sk.pub.version == 6
	key, err := pr.s2k.derive(passphrase, pr.cipher.KeySize(), v6, lim)
	if err != nil {
		return err
	}
	defer clear(key)
	var material []byte
	switch pr.usage {
	case usageAEAD:
		kek, err := hkdf.Key(sha256.New, key, nil, string([]byte{0xC0 | byte(sk.tag), byte(sk.pub.version), byte(pr.cipher), byte(pr.aead)}), pr.cipher.KeySize())
		if err != nil {
			return err
		}
		defer clear(kek)
		aead, err := pr.aead.newAEAD(pr.cipher, kek)
		if err != nil {
			return err
		}
		ad := append([]byte{0xC0 | byte(sk.tag)}, sk.pub.body...)
		if material, err = aead.Open(nil, pr.iv, pr.data, ad); err != nil {
			return ErrPassphrase
		}
	case usageCFB, usageMalleable:
		block, err := pr.cipher.newBlock(key)
		if err != nil {
			return err
		}
		plain := make([]byte, len(pr.data))
		newCFB(block, pr.iv, true).XORKeyStream(plain, pr.data)
		if pr.usage == usageCFB {
			if len(plain) < sha1.Size {
				clear(plain)
				return ErrPassphrase
			}
			material = plain[:len(plain)-sha1.Size]
			sum := sha1.Sum(material)
			if subtle.ConstantTimeCompare(sum[:], plain[len(material):]) != 1 {
				clear(plain)
				return ErrPassphrase
			}
		} else {
			if len(plain) < 2 {
				clear(plain)
				return ErrPassphrase
			}
			material = plain[:len(plain)-2]
			if checksum16(material) != binary.BigEndian.Uint16(plain[len(material):]) {
				clear(plain)
				return ErrPassphrase
			}
		}
		defer clear(plain)
	default:
		return unsupported("S2K usage %d", pr.usage)
	}
	defer clear(material)
	if err := sk.setMaterial(material); err != nil {
		// The integrity check passed, so this is not a wrong passphrase:
		// the key itself is bad.
		return err
	}
	return nil
}

// lock forgets the cleartext material of a protected key. An unprotected
// key keeps it: there would be no way back.
func (sk *secretKey) lock() {
	if sk.prot.usage != usageNone {
		sk.secret.Destroy()
		sk.secret = nil
	}
}

// destroy forgets the cleartext material whatever the protection.
func (sk *secretKey) destroy() {
	sk.secret.Destroy()
	sk.secret = nil
}

// protect encrypts the (unlocked) secret material under a passphrase:
// AEAD (usage 253) or CFB with a SHA-1 check (usage 254), with AES-256.
func (sk *secretKey) protect(passphrase []byte, spec *s2k, aeadMode AEADAlgorithm, lim Limits) error {
	if err := sk.usable(); err != nil {
		return err
	}
	material := sk.secret.Bytes()
	pr := keyProtection{cipher: AES256, s2k: spec}
	v6 := sk.pub.version == 6
	key, err := spec.derive(passphrase, pr.cipher.KeySize(), v6, lim)
	if err != nil {
		return err
	}
	defer clear(key)
	if aeadMode != 0 {
		pr.usage, pr.aead = usageAEAD, aeadMode
		kek, err := hkdf.Key(sha256.New, key, nil, string([]byte{0xC0 | byte(sk.tag), byte(sk.pub.version), byte(pr.cipher), byte(pr.aead)}), pr.cipher.KeySize())
		if err != nil {
			return err
		}
		defer clear(kek)
		aead, err := pr.aead.newAEAD(pr.cipher, kek)
		if err != nil {
			return err
		}
		pr.iv = make([]byte, aeadMode.nonceSize())
		rand.Read(pr.iv)
		ad := append([]byte{0xC0 | byte(sk.tag)}, sk.pub.body...)
		pr.data = aead.Seal(nil, pr.iv, material, ad)
	} else {
		if spec.typ == s2kArgon2 {
			return errors.New("svpgp: Argon2 is only used with AEAD key protection")
		}
		pr.usage = usageCFB
		block, err := pr.cipher.newBlock(key)
		if err != nil {
			return err
		}
		pr.iv = make([]byte, block.BlockSize())
		rand.Read(pr.iv)
		sum := sha1.Sum(material)
		plain := append(slices.Clone(material), sum[:]...)
		pr.data = make([]byte, len(plain))
		newCFB(block, pr.iv, false).XORKeyStream(pr.data, plain)
		clear(plain)
	}
	sk.prot = pr
	sk.raw = sk.protectedBody()
	return nil
}

// protectedBody encodes the packet body of a protected key.
func (sk *secretKey) protectedBody() []byte {
	pr := sk.prot
	v6 := sk.pub.version == 6
	body := append([]byte{}, sk.pub.body...)
	body = append(body, pr.usage)
	var params []byte
	params = append(params, byte(pr.cipher))
	if pr.usage == usageAEAD {
		params = append(params, byte(pr.aead))
	}
	spec := pr.s2k.bytes()
	if v6 {
		params = append(params, byte(len(spec)))
	}
	params = append(params, spec...)
	params = append(params, pr.iv...)
	if v6 {
		body = append(body, byte(len(params)))
	}
	body = append(body, params...)
	return append(body, pr.data...)
}

// body encodes the packet body: as read (or as last protected) for a
// protected key, and from the cleartext for an unprotected one.
func (sk *secretKey) body() ([]byte, error) {
	if sk.prot.usage != usageNone || sk.raw != nil {
		return sk.raw, nil
	}
	if sk.secret == nil {
		return nil, ErrKeyLocked
	}
	material := sk.secret.Bytes()
	body := append([]byte{}, sk.pub.body...)
	body = append(body, usageNone)
	body = append(body, material...)
	if sk.pub.version != 6 {
		body = binary.BigEndian.AppendUint16(body, checksum16(material))
	}
	return body, nil
}

// secretParts is secret key material decoded into the standard library's
// types for one operation.
type secretParts struct {
	rsa     *rsa.PrivateKey
	ecdsa   *ecdsa.PrivateKey
	ed      ed25519.PrivateKey
	ecdh    *ecdh.PrivateKey
	elgX    *big.Int
	scratch [][]byte // buffers to zero afterwards
}

// wipe zeroes what Go lets us reach. The standard library's own copies
// (the FIPS module's RSA key, ecdh.PrivateKey) cannot be reached.
func (sp *secretParts) wipe() {
	if sp == nil {
		return
	}
	if sp.rsa != nil {
		clearBig(sp.rsa.D)
		for _, p := range sp.rsa.Primes {
			clearBig(p)
		}
		clearBig(sp.rsa.Precomputed.Dp)
		clearBig(sp.rsa.Precomputed.Dq)
		clearBig(sp.rsa.Precomputed.Qinv)
	}
	if sp.ecdsa != nil {
		clearBig(sp.ecdsa.D)
	}
	clear(sp.ed)
	clearBig(sp.elgX)
	for _, b := range sp.scratch {
		clear(b)
	}
}

func clearBig(x *big.Int) {
	if x != nil {
		clear(x.Bits())
		x.SetInt64(0)
	}
}

// decode parses cleartext secret material and checks that it belongs to
// the public key. The material must be used up exactly.
func (sk *secretKey) decode(material []byte) (*secretParts, error) {
	pk := sk.pub
	strict := pk.version == 6
	p := newParser(material)
	sp := &secretParts{}
	fail := func(err error) (*secretParts, error) {
		sp.wipe()
		return nil, err
	}
	mismatch := malformed("the secret key does not match its public key")
	switch pk.alg {
	case RSA, RSAEncryptOnly, RSASignOnly:
		d, pp, q, _ := p.mpi(strict), p.mpi(strict), p.mpi(strict), p.mpi(strict)
		p.done()
		if p.err != nil {
			return fail(p.err)
		}
		priv := &rsa.PrivateKey{
			PublicKey: rsa.PublicKey{N: new(big.Int).Set(pk.rsa.N), E: pk.rsa.E},
			D:         new(big.Int).SetBytes(d),
			Primes:    []*big.Int{new(big.Int).SetBytes(pp), new(big.Int).SetBytes(q)},
		}
		sp.rsa = priv
		if err := priv.Validate(); err != nil {
			return fail(mismatch)
		}
		priv.Precompute()
	case ECDSA:
		x := p.mpi(strict)
		p.done()
		if p.err != nil {
			return fail(p.err)
		}
		b, ok := fixedOctets(x, pk.curve.fsize)
		if !ok {
			return fail(mismatch)
		}
		sp.scratch = append(sp.scratch, b)
		priv, err := ecdsa.ParseRawPrivateKey(pk.curve.ecdsa, b)
		if err != nil || !priv.PublicKey.Equal(pk.ecdsa) {
			return fail(mismatch)
		}
		sp.ecdsa = priv
	case EdDSALegacy:
		x := p.mpi(strict)
		p.done()
		if p.err != nil {
			return fail(p.err)
		}
		seed, ok := fixedOctets(x, 32)
		if !ok {
			return fail(mismatch)
		}
		sp.scratch = append(sp.scratch, seed)
		sp.ed = ed25519.NewKeyFromSeed(seed)
		if subtle.ConstantTimeCompare(sp.ed[32:], pk.ed) != 1 {
			return fail(mismatch)
		}
	case Ed25519:
		seed := p.bytes(32)
		p.done()
		if p.err != nil {
			return fail(p.err)
		}
		sp.ed = ed25519.NewKeyFromSeed(seed)
		if subtle.ConstantTimeCompare(sp.ed[32:], pk.ed) != 1 {
			return fail(mismatch)
		}
	case ECDH:
		x := p.mpi(strict)
		p.done()
		if p.err != nil {
			return fail(p.err)
		}
		b, ok := fixedOctets(x, pk.curve.fsize)
		if !ok {
			return fail(mismatch)
		}
		sp.scratch = append(sp.scratch, b)
		if pk.curve == curveCurve25519Legacy {
			// Big-endian on the wire, little-endian natively.
			slices.Reverse(b)
		}
		priv, err := pk.curve.ecdh.NewPrivateKey(b)
		if err != nil || !priv.PublicKey().Equal(pk.ecdh) {
			return fail(mismatch)
		}
		sp.ecdh = priv
	case X25519:
		b := p.bytes(32)
		p.done()
		if p.err != nil {
			return fail(p.err)
		}
		priv, err := ecdh.X25519().NewPrivateKey(b)
		if err != nil || !priv.PublicKey().Equal(pk.ecdh) {
			return fail(mismatch)
		}
		sp.ecdh = priv
	case ElGamal:
		x := p.mpi(strict)
		p.done()
		if p.err != nil {
			return fail(p.err)
		}
		sp.elgX = new(big.Int).SetBytes(x)
		k := pk.elg
		pm1 := new(big.Int).Sub(k.p, big.NewInt(1))
		if sp.elgX.Sign() <= 0 || sp.elgX.Cmp(pm1) >= 0 || new(big.Int).Exp(k.g, sp.elgX, k.p).Cmp(k.y) != 0 {
			return fail(mismatch)
		}
	case DSA:
		x := p.mpi(strict)
		p.done()
		if p.err != nil {
			return fail(p.err)
		}
		// DSA keys are only ever used to verify; the secret is kept, not
		// used.
		if new(big.Int).SetBytes(x).Sign() <= 0 {
			return fail(mismatch)
		}
	default:
		return fail(unsupported("%v secret keys", pk.alg))
	}
	return sp, nil
}

// parts decodes the unlocked material for one operation. The caller must
// wipe the result.
func (sk *secretKey) parts() (*secretParts, error) {
	if err := sk.usable(); err != nil {
		return nil, err
	}
	return sk.decode(sk.secret.Bytes())
}

// sign makes the algorithm-specific fields of a signature over a digest.
func (sk *secretKey) sign(h HashAlgorithm, digest []byte) ([]byte, error) {
	pk := sk.pub
	if pk.unusable != nil {
		return nil, pk.unusable
	}
	if err := pk.signingHashOK(h); err != nil {
		return nil, err
	}
	sp, err := sk.parts()
	if err != nil {
		return nil, err
	}
	defer sp.wipe()
	switch pk.alg {
	case RSA, RSASignOnly:
		ch, _ := h.cryptoHash()
		sig, err := rsa.SignPKCS1v15(nil, sp.rsa, ch, digest)
		if err != nil {
			return nil, err
		}
		return appendMPI(nil, sig), nil
	case ECDSA:
		der, err := ecdsa.SignASN1(rand.Reader, sp.ecdsa, digest)
		if err != nil {
			return nil, err
		}
		r, s, err := parseASN1Signature(der)
		if err != nil {
			return nil, err
		}
		return appendMPI(appendMPI(nil, r), s), nil
	case EdDSALegacy:
		sig := ed25519.Sign(sp.ed, digest)
		return appendMPI(appendMPI(nil, sig[:32]), sig[32:]), nil
	case Ed25519:
		return ed25519.Sign(sp.ed, digest), nil
	}
	return nil, unsupported("signing with %v keys", pk.alg)
}
