package svpgp

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"slices"
	"time"
)

// KeyOptions choose what GenerateKey makes.
type KeyOptions struct {
	// Version is 6 (the default): an Ed25519 primary key and an X25519
	// encryption subkey, RFC 9580's native algorithms. Or 4: EdDSALegacy
	// and ECDH over Curve25519, which GnuPG 2.4 and every other v4
	// implementation read.
	Version int
	// UserIDs are bound to the key, the first as primary. A version 4 key
	// needs at least one; a version 6 key may have none.
	UserIDs []string
	// Created is the keys' creation time; zero means now.
	Created time.Time
	// Lifetime is how long the key is valid for; zero means it does not
	// expire.
	Lifetime time.Duration
	// Passphrase, if set, protects the secret key material (AEAD with
	// Argon2 for version 6; CFB with iterated SHA-256 for version 4, which
	// GnuPG reads). The key comes back unlocked, ready to use; Serialize
	// writes the protected form.
	Passphrase []byte
}

// GenerateKey makes a new key: a primary key that certifies and signs, and
// a subkey that encrypts, bound by self-signatures that carry the key
// flags, expiry, algorithm preferences and features.
func GenerateKey(opts KeyOptions) (*Key, error) {
	version := opts.Version
	if version == 0 {
		version = 6
	}
	if version != 4 && version != 6 {
		return nil, fmt.Errorf("svpgp: cannot generate version %d keys", version)
	}
	if version == 4 && len(opts.UserIDs) == 0 {
		return nil, errors.New("svpgp: a version 4 key needs a user ID (other implementations will not use one without)")
	}
	created := opts.Created
	if created.IsZero() {
		created = time.Now()
	}
	created = created.Truncate(time.Second)
	var lifetime uint32
	if opts.Lifetime != 0 {
		secs := int64(opts.Lifetime / time.Second)
		if secs <= 0 || secs > 0xFFFFFFFF {
			return nil, errors.New("svpgp: key lifetime out of range")
		}
		lifetime = uint32(secs)
	}

	primary, err := generateSigningKey(version, created)
	if err != nil {
		return nil, err
	}
	sub, err := generateEncryptionKey(version, created)
	if err != nil {
		primary.sec.destroy()
		return nil, err
	}
	k := &Key{primary: primary, subkeys: []*subkey{{keyComponent: *sub}}}
	fail := func(err error) (*Key, error) {
		k.Close()
		return nil, err
	}

	prefs := func(b *subpacketBuilder) {
		b.add(spKeyFlags, true, flagCertify|flagSign)
		if lifetime != 0 {
			b.addTime(spKeyExpiration, true, lifetime)
		}
		if version == 6 {
			b.add(spPrefSymmetric, false, byte(AES256), byte(AES128))
			b.add(spPrefAEAD, false, byte(AES256), byte(OCB), byte(AES128), byte(OCB), byte(AES256), byte(GCM), byte(AES128), byte(GCM))
			b.add(spPrefHash, false, byte(SHA512), byte(SHA3_512), byte(SHA256), byte(SHA3_256))
			b.add(spFeatures, false, featureSEIPDv1|featureSEIPDv2)
		} else {
			b.add(spPrefSymmetric, false, byte(AES256), byte(AES192), byte(AES128))
			b.add(spPrefHash, false, byte(SHA512), byte(SHA384), byte(SHA256), byte(SHA224))
			b.add(spFeatures, false, featureSEIPDv1)
		}
		b.add(spPrefCompression, false, byte(Uncompressed), byte(ZLIB), byte(ZIP))
	}
	pk := primary.pub
	if version == 6 {
		dks, err := selfSignature(primary, SigDirectKey, created, prefs, pk, nil, nil)
		if err != nil {
			return fail(err)
		}
		k.sigs = append(k.sigs, dks)
	}
	for i, uid := range opts.UserIDs {
		if uid == "" {
			return fail(errors.New("svpgp: empty user ID"))
		}
		first := i == 0
		cert, err := selfSignature(primary, SigPositiveCert, created, func(b *subpacketBuilder) {
			if first {
				b.add(spPrimaryUserID, false, 1)
			}
			if version == 4 {
				prefs(b)
			}
		}, pk, nil, []byte(uid))
		if err != nil {
			return fail(err)
		}
		k.identities = append(k.identities, &identity{raw: []byte(uid), sigs: []*signature{cert}})
	}
	binding, err := selfSignature(primary, SigSubkeyBinding, created, func(b *subpacketBuilder) {
		b.add(spKeyFlags, true, flagEncryptComms|flagEncryptStorage)
		if lifetime != 0 {
			b.addTime(spKeyExpiration, true, lifetime)
		}
	}, pk, sub.pub, nil)
	if err != nil {
		return fail(err)
	}
	k.subkeys[0].sigs = []*signature{binding}
	k.checkSelfSignatures()
	if err := k.Valid(created); err != nil {
		return fail(fmt.Errorf("svpgp: the new key does not validate: %w", err))
	}
	if opts.Passphrase != nil {
		if len(opts.Passphrase) == 0 {
			return fail(errors.New("svpgp: an empty passphrase protects nothing"))
		}
		for _, c := range k.components() {
			spec, mode := newIteratedS2K(), AEADAlgorithm(0)
			if version == 6 {
				spec, mode = newArgon2S2K(), OCB
			}
			if err := c.sec.protect(opts.Passphrase, spec, mode, DefaultLimits); err != nil {
				return fail(err)
			}
		}
	}
	return k, nil
}

// generateSigningKey makes an Ed25519 primary key: the native algorithm in
// version 6, EdDSALegacy in version 4.
func generateSigningKey(version int, created time.Time) (*keyComponent, error) {
	seed := make([]byte, ed25519.SeedSize)
	rand.Read(seed)
	defer clear(seed)
	priv := ed25519.NewKeyFromSeed(seed)
	defer clear(priv)
	pub := priv[32:]
	var alg PublicKeyAlgorithm
	var material, secret []byte
	if version == 6 {
		alg, material, secret = Ed25519, slices.Clone(pub), slices.Clone(seed)
	} else {
		alg = EdDSALegacy
		material = appendMPI(curveEd25519Legacy.appendOID(nil), append([]byte{0x40}, pub...))
		secret = appendMPI(nil, seed)
	}
	defer clear(secret)
	return newComponent(version, created, alg, material, secret, ptSecretKey)
}

// generateEncryptionKey makes an X25519 subkey: the native algorithm in
// version 6, ECDH over Curve25519Legacy in version 4.
func generateEncryptionKey(version int, created time.Time) (*keyComponent, error) {
	native := make([]byte, 32)
	rand.Read(native)
	defer clear(native)
	var alg PublicKeyAlgorithm
	var material, secret []byte
	if version == 6 {
		priv, err := ecdh.X25519().NewPrivateKey(native)
		if err != nil {
			return nil, err
		}
		alg, material, secret = X25519, priv.PublicKey().Bytes(), slices.Clone(native)
	} else {
		// Curve25519Legacy stores the clamped scalar, big-endian (RFC 9580,
		// section 5.5.5.6.1.1).
		native[0] &= 248
		native[31] &= 127
		native[31] |= 64
		priv, err := ecdh.X25519().NewPrivateKey(native)
		if err != nil {
			return nil, err
		}
		alg = ECDH
		material = appendMPI(curveCurve25519Legacy.appendOID(nil), append([]byte{0x40}, priv.PublicKey().Bytes()...))
		material = append(material, 3, 1, byte(curveCurve25519Legacy.kdfHash), byte(curveCurve25519Legacy.kek))
		reversed := slices.Clone(native)
		slices.Reverse(reversed)
		secret = appendMPI(nil, reversed)
		clear(reversed)
	}
	defer clear(secret)
	return newComponent(version, created, alg, material, secret, ptSecretSubkey)
}

func newComponent(version int, created time.Time, alg PublicKeyAlgorithm, material, secret []byte, tag packetType) (*keyComponent, error) {
	pk, err := newPublicKey(version, created, alg, material)
	if err != nil {
		return nil, err
	}
	sk := &secretKey{pub: pk, tag: tag}
	if err := sk.setMaterial(secret); err != nil {
		return nil, err
	}
	return &keyComponent{pub: pk, sec: sk}, nil
}

// selfSignature makes a signature by the primary key over (parts of) its
// own key.
func selfSignature(signer *keyComponent, typ SignatureType, created time.Time, extra func(*subpacketBuilder), primary, sub *publicKey, uid []byte) (*signature, error) {
	tmpl, err := newSignatureTemplate(signer, typ, SHA512, created, extra)
	if err != nil {
		return nil, err
	}
	h, err := tmpl.newHash()
	if err != nil {
		return nil, err
	}
	h.Write(primary.appendForHash(nil, tmpl.version))
	switch {
	case uid != nil:
		h.Write(appendU32([]byte{0xB4}, uint32(len(uid))))
		h.Write(uid)
	case sub != nil:
		h.Write(sub.appendForHash(nil, tmpl.version))
	}
	return tmpl.sign(signer, h)
}

// Revoke adds a revocation signature to the key, made at time at (zero
// means now) by its primary key, whose secret must be unlocked. Publish the
// key afterwards so others learn of it.
func (k *Key) Revoke(reason RevocationReason, text string, at time.Time) error {
	if k.primary.sec == nil {
		return ErrKeyLocked
	}
	if err := k.primary.sec.usable(); err != nil {
		return err
	}
	if at.IsZero() {
		at = time.Now()
	}
	sig, err := selfSignature(k.primary, SigKeyRevocation, at, func(b *subpacketBuilder) {
		b.add(spRevocationReason, false, append([]byte{byte(reason)}, text...)...)
	}, k.primary.pub, nil, nil)
	if err != nil {
		return err
	}
	verifyKeySignature(sig, k.primary.pub, k.primary.pub, nil, nil, false)
	k.sigs = append(slices.Clip(k.sigs), sig)
	return nil
}
