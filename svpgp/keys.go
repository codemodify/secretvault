package svpgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// Key is an OpenPGP key, also called a certificate (RFC 9580, section 10.1):
// a primary key with its user IDs, subkeys and the signatures that bind
// them, and the secret key material when it is a secret key.
//
// Reading a key checks every self-signature once. Which parts are valid at
// a given time (bound, not expired, not revoked, allowed to sign or
// encrypt) is worked out from those when asked. A Key is not safe for
// concurrent use while it is being unlocked, locked, closed or revoked.
type Key struct {
	primary    *keyComponent
	sigs       []*signature // on the primary key: direct key signatures and revocations
	identities []*identity
	attributes []*attribute
	subkeys    []*subkey
}

type keyComponent struct {
	pub *publicKey
	sec *secretKey // nil when there is no secret key packet
}

type identity struct {
	raw  []byte // the user ID packet body
	sigs []*signature
}

type attribute struct {
	raw  []byte // the user attribute packet body, kept but not interpreted
	sigs []*signature
}

type subkey struct {
	keyComponent
	sigs []*signature
}

// RevocationReason says why a key was revoked (RFC 9580, section
// 5.2.3.31). Superseded and retired keys stay good for what they signed
// before they were revoked; compromised keys, and keys revoked without a
// reason, do not.
type RevocationReason byte

// Revocation reasons.
const (
	RevocationNoReason    RevocationReason = 0
	RevocationSuperseded  RevocationReason = 1
	RevocationCompromised RevocationReason = 2
	RevocationRetired     RevocationReason = 3
)

// ReadKeys reads one or more keys, public or secret, binary or armored
// (several armor blocks may follow each other). Keys that cannot be read at
// all (versions 2, 3 and 5, or a version 4 secret key of an unknown
// algorithm) are skipped, as are subkeys of that kind; keys that read but
// use an algorithm this package does not implement are returned, and every
// use of them fails with ErrUnsupported. ReadKeys fails if the input is
// malformed or holds no key it can read.
func ReadKeys(r io.Reader) ([]*Key, error) {
	br, typ, err := openInput(r)
	if err != nil {
		return nil, err
	}
	if typ == "" {
		return readKeys(br)
	}
	var keys []*Key
	var skipped error
	for {
		if typ != BlockPublicKey && typ != BlockPrivateKey {
			return nil, malformed("armor of type %q holds no key", typ)
		}
		block, err := armorBody(br, typ)
		if err != nil {
			return nil, err
		}
		got, err := readKeys(block.Body)
		if errors.Is(err, ErrUnsupported) {
			skipped = err
		} else if err != nil {
			return nil, err
		}
		keys = append(keys, got...)
		if typ, err = findArmor(br); err != nil {
			if errors.Is(err, ErrMalformed) && len(keys)+boolInt(skipped != nil) > 0 {
				break // no further block
			}
			return nil, err
		}
	}
	if len(keys) == 0 {
		return nil, skipped
	}
	return keys, nil
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// ReadKey reads exactly one key.
func ReadKey(r io.Reader) (*Key, error) {
	keys, err := ReadKeys(r)
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 {
		return nil, fmt.Errorf("svpgp: %d keys where one was expected", len(keys))
	}
	return keys[0], nil
}

// readKeys reads keys from binary packets.
func readKeys(r io.Reader) ([]*Key, error) {
	pr := newPacketReader(r)
	var (
		keys     []*Key
		cur      *Key
		target   *[]*signature // where the next signature belongs
		skipping bool          // inside a key that is not supported
		skipped  error
		count    int
	)
	for {
		tag, body, err := pr.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if tag == ptPublicKey || tag == ptSecretKey {
			count = 0
		}
		if count++; count > maxPacketsPerKey {
			return nil, limit("a key of more than %d packets", maxPacketsPerKey)
		}
		switch tag {
		case ptPublicKey, ptSecretKey:
			data, err := body.readAll(maxPacketSize)
			if err != nil {
				return nil, err
			}
			comp, err := parseComponent(data, tag)
			if errors.Is(err, ErrUnsupported) {
				skipping, skipped, cur, target = true, err, nil, nil
				continue
			}
			if err != nil {
				return nil, err
			}
			if !comp.pub.alg.canSign() {
				skipping, skipped, cur, target = true, unsupported("a %v primary key, which cannot certify", comp.pub.alg), nil, nil
				continue
			}
			skipping = false
			cur = &Key{primary: comp}
			keys = append(keys, cur)
			target = &cur.sigs
		case ptPublicSubkey, ptSecretSubkey:
			if skipping {
				continue
			}
			if cur == nil {
				return nil, malformed("a subkey before any primary key")
			}
			data, err := body.readAll(maxPacketSize)
			if err != nil {
				return nil, err
			}
			comp, err := parseComponent(data, tag)
			if errors.Is(err, ErrUnsupported) || err == nil && comp.pub.version != cur.primary.pub.version {
				target = nil // drop the subkey and its signatures
				continue
			}
			if err != nil {
				return nil, err
			}
			sub := &subkey{keyComponent: *comp}
			cur.subkeys = append(cur.subkeys, sub)
			target = &sub.sigs
		case ptUserID, ptUserAttribute:
			if skipping {
				continue
			}
			if cur == nil {
				return nil, malformed("a %v before any key", tag)
			}
			data, err := body.readAll(maxPacketSize)
			if err != nil {
				return nil, err
			}
			if tag == ptUserID {
				id := &identity{raw: data}
				cur.identities = append(cur.identities, id)
				target = &id.sigs
			} else {
				a := &attribute{raw: data}
				cur.attributes = append(cur.attributes, a)
				target = &a.sigs
			}
		case ptSignature:
			if skipping {
				continue
			}
			if cur == nil {
				return nil, malformed("a signature before any key")
			}
			data, err := body.readAll(maxPacketSize)
			if err != nil {
				return nil, err
			}
			sig, err := parseSignature(data, 0)
			if err != nil || target == nil {
				continue // a signature that cannot be read cannot count
			}
			*target = append(*target, sig)
		case ptTrust, ptMarker, ptPadding:
		default:
			if tag.critical() {
				return nil, malformed("a %v packet in a key", tag)
			}
		}
	}
	for _, k := range keys {
		k.checkSelfSignatures()
	}
	if len(keys) == 0 {
		if skipped != nil {
			return nil, skipped
		}
		return nil, malformed("no key found")
	}
	return keys, nil
}

func parseComponent(data []byte, tag packetType) (*keyComponent, error) {
	if tag == ptSecretKey || tag == ptSecretSubkey {
		sk, err := parseSecretKey(data, tag)
		if err != nil {
			return nil, err
		}
		return &keyComponent{pub: sk.pub, sec: sk}, nil
	}
	pk, _, err := parsePublicKey(data, false)
	if err != nil {
		return nil, err
	}
	return &keyComponent{pub: pk}, nil
}

// issuedBy reports whether a signature claims to be by the key, or makes no
// claim at all (and so might be).
func (s *signature) issuedBy(pk *publicKey) bool {
	if s.issuerFP != nil {
		return bytes.Equal(s.issuerFP, pk.fp)
	}
	if s.hasIssuerKeyID {
		return s.issuerKeyID == pk.keyID
	}
	return true
}

// keySignatureDigest hashes a signature over key material: the primary
// key, then a user ID or attribute, or a subkey (RFC 9580, section 5.2.4).
func keySignatureDigest(s *signature, primary, sub *publicKey, uid []byte, isAttribute bool) ([]byte, error) {
	h, err := s.newHash()
	if err != nil {
		return nil, err
	}
	h.Write(primary.appendForHash(nil, s.version))
	switch {
	case uid != nil:
		if s.version == 3 {
			h.Write(uid)
		} else {
			prefix := byte(0xB4)
			if isAttribute {
				prefix = 0xD1
			}
			h.Write(appendU32([]byte{prefix}, uint32(len(uid))))
			h.Write(uid)
		}
	case sub != nil:
		h.Write(sub.appendForHash(nil, s.version))
	}
	s.writeTrailer(h)
	return h.Sum(nil), nil
}

// verifyKeySignature checks a signature over key material with the key
// that should have made it, and records the result in the signature.
func verifyKeySignature(s *signature, signer, primary, sub *publicKey, uid []byte, isAttribute bool) {
	s.checked = true
	if s.invalid != nil {
		s.checkErr = s.invalid
		return
	}
	digest, err := keySignatureDigest(s, primary, sub, uid, isAttribute)
	if err != nil {
		s.checkErr = err
		return
	}
	s.checkErr = s.verifyDigest(signer, digest)
}

// checkSelfSignatures verifies, once, every signature that claims to be by
// the primary key over its own parts, and the back-signatures of signing
// subkeys. Third-party signatures are kept but not verified.
func (k *Key) checkSelfSignatures() {
	pk := k.primary.pub
	budget := maxSelfSigChecks
	take := func(s *signature) bool {
		if !s.issuedBy(pk) || budget == 0 {
			return false
		}
		budget--
		return true
	}
	for _, s := range k.sigs {
		if (s.typ == SigDirectKey || s.typ == SigKeyRevocation) && take(s) {
			verifyKeySignature(s, pk, pk, nil, nil, false)
		}
	}
	for _, id := range k.identities {
		for _, s := range id.sigs {
			if (s.typ.isCertification() || s.typ == SigCertRevocation) && take(s) {
				verifyKeySignature(s, pk, pk, nil, id.raw, false)
			}
		}
	}
	for _, a := range k.attributes {
		for _, s := range a.sigs {
			if (s.typ.isCertification() || s.typ == SigCertRevocation) && take(s) {
				verifyKeySignature(s, pk, pk, nil, a.raw, true)
			}
		}
	}
	for _, sub := range k.subkeys {
		for _, s := range sub.sigs {
			if (s.typ != SigSubkeyBinding && s.typ != SigSubkeyRevocation) || !take(s) {
				continue
			}
			verifyKeySignature(s, pk, pk, sub.pub, nil, false)
			if s.typ == SigSubkeyBinding && s.checkErr == nil && s.embedded != nil && s.embedded.typ == SigPrimaryKeyBinding && budget > 0 {
				budget--
				verifyKeySignature(s.embedded, sub.pub, pk, sub.pub, nil, false)
			}
		}
	}
}

// goodAt reports whether a checked self-signature counts at time t: it
// verified, its hash is accepted, it existed at t and had not expired.
func (s *signature) goodAt(t time.Time) bool {
	return s.checked && s.checkErr == nil && s.invalid == nil && s.hashPolicy() == nil &&
		!s.created.After(t) && !s.expiredAt(t)
}

// backsigOK reports whether a subkey binding carries a valid primary key
// binding signature made by the subkey, which a signing subkey needs.
func (s *signature) backsigOK() bool {
	e := s.embedded
	return e != nil && e.typ == SigPrimaryKeyBinding && e.checked && e.checkErr == nil &&
		e.invalid == nil && e.hashPolicy() == nil
}

// latestGood returns the most recent signature of the given types that is
// good at t.
func latestGood(sigs []*signature, t time.Time, types ...SignatureType) *signature {
	var best *signature
	for _, s := range sigs {
		if !slices.Contains(types, s.typ) || !s.goodAt(t) {
			continue
		}
		if best == nil || !s.created.Before(best.created) {
			best = s
		}
	}
	return best
}

// revocationAt returns a valid revocation that applies at time t, as seen
// from now: a hard revocation made by now applies at any time, a soft one
// only from when it was made. Revocations fail closed: they count whatever
// hash they use, since ignoring a real one is worse than honouring a
// forged one.
func revocationAt(sigs []*signature, typ SignatureType, t, now time.Time) *signature {
	for _, s := range sigs {
		if s.typ != typ || !s.checked || s.checkErr != nil || s.invalid != nil || s.created.After(now) {
			continue
		}
		if s.hardRevocation() || !s.created.After(t) {
			return s
		}
	}
	return nil
}

func revokedError(s *signature) error {
	switch {
	case !s.hasRevReason:
		return fmt.Errorf("%w (no reason given)", ErrKeyRevoked)
	case s.revText != "":
		return fmt.Errorf("%w (reason %d: %q)", ErrKeyRevoked, s.revReason, s.revText)
	}
	return fmt.Errorf("%w (reason %d)", ErrKeyRevoked, s.revReason)
}

// keyExpiry is when a binding signature says a key expires, or zero.
func keyExpiry(pk *publicKey, binding *signature) time.Time {
	if binding == nil || binding.keyExpiry == 0 {
		return time.Time{}
	}
	return pk.created.Add(time.Duration(binding.keyExpiry) * time.Second)
}

func expiredBy(exp, t time.Time) bool { return !exp.IsZero() && !t.Before(exp) }

// identityAt returns the user ID's latest self-certification at t, or nil
// if it had none then or had been revoked since it was made. A user ID
// revoked later was still the key's at t.
func (k *Key) identityAt(id *identity, t, now time.Time) *signature {
	cert := latestGood(id.sigs, t, SigGenericCert, SigPersonaCert, SigCasualCert, SigPositiveCert)
	if cert == nil {
		return nil
	}
	for _, s := range id.sigs {
		if s.typ == SigCertRevocation && s.checked && s.checkErr == nil && s.invalid == nil &&
			!s.created.After(t) && !s.created.After(now) && !s.created.Before(cert.created) {
			return nil
		}
	}
	return cert
}

// primaryIdentity returns the primary user ID at t and its certification:
// one marked primary if any, the most recently certified otherwise.
func (k *Key) primaryIdentity(t, now time.Time) (*identity, *signature) {
	var best *identity
	var bestCert *signature
	for _, id := range k.identities {
		cert := k.identityAt(id, t, now)
		if cert == nil {
			continue
		}
		if best == nil || cert.primaryUserID && !bestCert.primaryUserID ||
			cert.primaryUserID == bestCert.primaryUserID && cert.created.After(bestCert.created) {
			best, bestCert = id, cert
		}
	}
	return best, bestCert
}

// primaryBindings finds the self-signatures that describe the primary key
// at t: the direct key signature, and (for version 4 keys) the primary user
// ID's certification, which by convention carries the key's properties.
// binding is the one to take properties from.
func (k *Key) primaryBindings(t, now time.Time) (binding, dks *signature) {
	dks = latestGood(k.sigs, t, SigDirectKey)
	binding = dks
	if k.primary.pub.version == 4 {
		if _, cert := k.primaryIdentity(t, now); cert != nil {
			binding = cert
		}
	}
	return binding, dks
}

// primaryState checks that the primary key is valid at t, as seen from now,
// and returns the self-signature that describes it.
func (k *Key) primaryState(t, now time.Time) (*signature, error) {
	pk := k.primary.pub
	if pk.unusable != nil {
		return nil, pk.unusable
	}
	if pk.created.After(t) {
		return nil, fmt.Errorf("%w: the key was created after %v", ErrKeyInvalid, t.UTC().Format(time.RFC3339))
	}
	if rev := revocationAt(k.sigs, SigKeyRevocation, t, now); rev != nil {
		return nil, revokedError(rev)
	}
	binding, dks := k.primaryBindings(t, now)
	if pk.version == 6 && dks == nil {
		return nil, fmt.Errorf("%w: no valid direct key self-signature", ErrKeyInvalid)
	}
	if binding == nil {
		return nil, fmt.Errorf("%w: no valid self-signature", ErrKeyInvalid)
	}
	if expiredBy(keyExpiry(pk, binding), t) || expiredBy(keyExpiry(pk, dks), t) {
		return nil, ErrKeyExpired
	}
	return binding, nil
}

// primaryFlags returns the primary key's key flags from its binding, the
// direct key signature, or (for keys that predate key flags) inferred from
// its algorithm.
func (k *Key) primaryFlags(binding *signature, t, now time.Time) byte {
	if binding.hasKeyFlags {
		return binding.flags()
	}
	if _, dks := k.primaryBindings(t, now); dks != nil && dks.hasKeyFlags {
		return dks.flags()
	}
	return inferredFlags(k.primary.pub.alg)
}

func inferredFlags(alg PublicKeyAlgorithm) byte {
	var f byte
	if alg.canSign() {
		f |= flagCertify | flagSign
	}
	if alg.canEncrypt() {
		f |= flagEncryptComms | flagEncryptStorage
	}
	return f
}

// subkeyState checks that a subkey is valid at t, as seen from now, and
// returns its binding signature.
func (k *Key) subkeyState(sub *subkey, t, now time.Time) (*signature, error) {
	if sub.pub.unusable != nil {
		return nil, sub.pub.unusable
	}
	if sub.pub.created.After(t) {
		return nil, fmt.Errorf("%w: the subkey was created after %v", ErrKeyInvalid, t.UTC().Format(time.RFC3339))
	}
	if _, err := k.primaryState(t, now); err != nil {
		return nil, err
	}
	if rev := revocationAt(sub.sigs, SigSubkeyRevocation, t, now); rev != nil {
		return nil, revokedError(rev)
	}
	binding := latestGood(sub.sigs, t, SigSubkeyBinding)
	if binding == nil {
		return nil, fmt.Errorf("%w: the subkey has no valid binding signature", ErrKeyInvalid)
	}
	if expiredBy(keyExpiry(sub.pub, binding), t) {
		return nil, ErrKeyExpired
	}
	return binding, nil
}

func subkeyFlags(sub *subkey, binding *signature) byte {
	if binding.hasKeyFlags {
		return binding.flags()
	}
	return inferredFlags(sub.pub.alg)
}

// signerAt checks that a component may make data signatures at t, as seen
// from now.
func (k *Key) signerAt(c *keyComponent, t, now time.Time) error {
	if c == k.primary {
		binding, err := k.primaryState(t, now)
		if err != nil {
			return err
		}
		if k.primaryFlags(binding, t, now)&flagSign == 0 || !c.pub.alg.canSign() {
			return fmt.Errorf("%w: the primary key is not allowed to sign data", ErrKeyInvalid)
		}
		return nil
	}
	for _, sub := range k.subkeys {
		if &sub.keyComponent != c {
			continue
		}
		binding, err := k.subkeyState(sub, t, now)
		if err != nil {
			return err
		}
		if subkeyFlags(sub, binding)&flagSign == 0 || !c.pub.alg.canSign() {
			return fmt.Errorf("%w: the subkey is not allowed to sign data", ErrKeyInvalid)
		}
		if !binding.backsigOK() {
			return fmt.Errorf("%w: the signing subkey has no valid primary key binding signature", ErrKeyInvalid)
		}
		return nil
	}
	return ErrKeyInvalid
}

// signingKey picks the component to sign with at t: the most recently
// created valid signing subkey whose secret is available, or the primary
// key.
func (k *Key) signingKey(t time.Time) (*keyComponent, error) {
	var best *keyComponent
	var firstErr error
	for _, sub := range k.subkeys {
		c := &sub.keyComponent
		if err := k.signerAt(c, t, t); err != nil {
			continue
		}
		if c.sec == nil || c.sec.usable() != nil {
			if firstErr == nil && c.sec != nil {
				firstErr = c.sec.usable()
			}
			continue
		}
		if best == nil || c.pub.created.After(best.pub.created) {
			best = c
		}
	}
	if best != nil {
		return best, nil
	}
	if err := k.signerAt(k.primary, t, t); err == nil {
		if k.primary.sec == nil {
			return nil, ErrKeyLocked
		}
		if err := k.primary.sec.usable(); err != nil {
			return nil, err
		}
		return k.primary, nil
	} else if firstErr == nil && !errors.Is(err, ErrKeyInvalid) {
		firstErr = err
	}
	if firstErr != nil {
		return nil, firstErr
	}
	return nil, fmt.Errorf("%w: signing", ErrNoUsableKey)
}

// encryptionKeys returns the components to encrypt to at t: every valid
// subkey flagged for encryption, or the primary key if it is the only one.
func (k *Key) encryptionKeys(t time.Time) ([]*keyComponent, error) {
	var out []*keyComponent
	for _, sub := range k.subkeys {
		binding, err := k.subkeyState(sub, t, t)
		if err != nil || !sub.pub.alg.canEncrypt() {
			continue
		}
		if subkeyFlags(sub, binding)&(flagEncryptComms|flagEncryptStorage) != 0 {
			out = append(out, &sub.keyComponent)
		}
	}
	if len(out) > 0 {
		return out, nil
	}
	binding, err := k.primaryState(t, t)
	if err != nil {
		return nil, err
	}
	if k.primaryFlags(binding, t, t)&(flagEncryptComms|flagEncryptStorage) != 0 && k.primary.pub.alg.canEncrypt() && k.primary.pub.unusable == nil {
		return []*keyComponent{k.primary}, nil
	}
	return nil, fmt.Errorf("%w: encryption", ErrNoUsableKey)
}

// components lists the primary key and the subkeys.
func (k *Key) components() []*keyComponent {
	out := []*keyComponent{k.primary}
	for _, sub := range k.subkeys {
		out = append(out, &sub.keyComponent)
	}
	return out
}

// findComponent looks a (sub)key up by fingerprint, or by key ID when fp is
// nil.
func (k *Key) findComponent(fp []byte, keyID uint64) []*keyComponent {
	var out []*keyComponent
	for _, c := range k.components() {
		if fp != nil && bytes.Equal(c.pub.fp, fp) || fp == nil && c.pub.keyID == keyID {
			out = append(out, c)
		}
	}
	return out
}

// Fingerprint is the primary key's fingerprint: 20 bytes for a version 4
// key, 32 for a version 6 key.
func (k *Key) Fingerprint() []byte { return slices.Clone(k.primary.pub.fp) }

// KeyID is the primary key's 64-bit key ID.
func (k *Key) KeyID() uint64 { return k.primary.pub.keyID }

// Version is the key's version: 4 or 6.
func (k *Key) Version() int { return k.primary.pub.version }

// CreatedAt is when the primary key was made.
func (k *Key) CreatedAt() time.Time { return k.primary.pub.created }

// Algorithm is the primary key's algorithm.
func (k *Key) Algorithm() PublicKeyAlgorithm { return k.primary.pub.alg }

// UserIDs are the user IDs bound to the key by a valid self-certification
// and not revoked, now. User IDs that others added without the key's
// signature are not included: nothing says they belong to the key.
func (k *Key) UserIDs() []string {
	now := time.Now()
	var out []string
	for _, id := range k.identities {
		if k.identityAt(id, now, now) != nil {
			out = append(out, string(id.raw))
		}
	}
	return out
}

// PrimaryUserID is the key's primary user ID now, or "" if it has none.
func (k *Key) PrimaryUserID() string {
	now := time.Now()
	if id, _ := k.primaryIdentity(now, now); id != nil {
		return string(id.raw)
	}
	return ""
}

// Revoked reports whether the key carries a valid revocation signature
// made by itself.
func (k *Key) Revoked() bool {
	now := time.Now()
	return revocationAt(k.sigs, SigKeyRevocation, now, now) != nil
}

// ExpiresAt is when the primary key expires according to its current
// self-signatures, or the zero time if it does not.
func (k *Key) ExpiresAt() time.Time {
	now := time.Now()
	binding, dks := k.primaryBindings(now, now)
	exp := keyExpiry(k.primary.pub, binding)
	if e := keyExpiry(k.primary.pub, dks); !e.IsZero() && (exp.IsZero() || e.Before(exp)) {
		exp = e
	}
	return exp
}

// Valid reports whether the primary key is valid at t: made by then,
// bound by a valid self-signature, not expired and not revoked. It
// returns nil when it is, and the reason otherwise.
func (k *Key) Valid(t time.Time) error {
	_, err := k.primaryState(t, t)
	return err
}

// HasSecret reports whether the key holds secret key material for at least
// one of its (sub)keys, locked or not.
func (k *Key) HasSecret() bool {
	for _, c := range k.components() {
		if c.sec != nil && c.sec.unavailable == nil {
			return true
		}
	}
	return false
}

// Locked reports whether some secret key material needs Unlock before use.
func (k *Key) Locked() bool {
	for _, c := range k.components() {
		if c.sec != nil && c.sec.unavailable == nil && c.sec.secret == nil {
			return true
		}
	}
	return false
}

// SubkeyInfo describes a subkey.
type SubkeyInfo struct {
	Fingerprint []byte
	KeyID       uint64
	Algorithm   PublicKeyAlgorithm
	Created     time.Time
	Expires     time.Time // zero if it does not expire
	CanSign     bool      // valid now, and allowed to sign data
	CanEncrypt  bool      // valid now, and allowed to encrypt
	HasSecret   bool
	Err         error // why the subkey is not valid now, or nil
}

// Subkeys describes the key's subkeys, as they stand now.
func (k *Key) Subkeys() []SubkeyInfo {
	now := time.Now()
	var out []SubkeyInfo
	for _, sub := range k.subkeys {
		info := SubkeyInfo{
			Fingerprint: slices.Clone(sub.pub.fp),
			KeyID:       sub.pub.keyID,
			Algorithm:   sub.pub.alg,
			Created:     sub.pub.created,
			HasSecret:   sub.sec != nil && sub.sec.unavailable == nil,
		}
		binding, err := k.subkeyState(sub, now, now)
		info.Err = err
		if b := latestGood(sub.sigs, now, SigSubkeyBinding); b != nil {
			info.Expires = keyExpiry(sub.pub, b)
		}
		if err == nil {
			flags := subkeyFlags(sub, binding)
			info.CanSign = flags&flagSign != 0 && sub.pub.alg.canSign() && binding.backsigOK()
			info.CanEncrypt = flags&(flagEncryptComms|flagEncryptStorage) != 0 && sub.pub.alg.canEncrypt()
		}
		out = append(out, info)
	}
	return out
}

// Public returns the key without its secret key material. The two share
// no secret state: closing one does not affect the other.
func (k *Key) Public() *Key {
	out := &Key{
		primary:    &keyComponent{pub: k.primary.pub},
		sigs:       k.sigs,
		identities: k.identities,
		attributes: k.attributes,
	}
	for _, sub := range k.subkeys {
		out.subkeys = append(out.subkeys, &subkey{keyComponent: keyComponent{pub: sub.pub}, sigs: sub.sigs})
	}
	return out
}

// Serialize writes the key as binary packets: the public key, or with
// secret set the secret key (protected as it stands; unlocking does not
// change what is written). Local (non-exportable) certifications are left
// out.
func (k *Key) Serialize(w io.Writer, secret bool) error {
	if secret && k.primary.sec == nil {
		return fmt.Errorf("%w: the key has no secret key packet", ErrKeyLocked)
	}
	writeComponent := func(c *keyComponent, pubTag, secTag packetType) error {
		if secret && c.sec != nil {
			body, err := c.sec.body()
			if err != nil {
				return err
			}
			return writePacket(w, secTag, body)
		}
		return writePacket(w, pubTag, c.pub.body)
	}
	writeSigs := func(sigs []*signature) error {
		for _, s := range sigs {
			if !s.exportable {
				continue
			}
			if err := writePacket(w, ptSignature, s.body); err != nil {
				return err
			}
		}
		return nil
	}
	if err := writeComponent(k.primary, ptPublicKey, ptSecretKey); err != nil {
		return err
	}
	if err := writeSigs(k.sigs); err != nil {
		return err
	}
	for _, id := range k.identities {
		if err := writePacket(w, ptUserID, id.raw); err != nil {
			return err
		}
		if err := writeSigs(id.sigs); err != nil {
			return err
		}
	}
	for _, a := range k.attributes {
		if err := writePacket(w, ptUserAttribute, a.raw); err != nil {
			return err
		}
		if err := writeSigs(a.sigs); err != nil {
			return err
		}
	}
	for _, sub := range k.subkeys {
		if err := writeComponent(&sub.keyComponent, ptPublicSubkey, ptSecretSubkey); err != nil {
			return err
		}
		if err := writeSigs(sub.sigs); err != nil {
			return err
		}
	}
	return nil
}

// Armor returns the key armored: a public key block, or with secret set a
// private key block. The CRC24 line is written for version 4 keys only.
func (k *Key) Armor(secret bool) ([]byte, error) {
	var bin bytes.Buffer
	if err := k.Serialize(&bin, secret); err != nil {
		return nil, err
	}
	typ := BlockPublicKey
	if secret {
		typ = BlockPrivateKey
	}
	return armorBytes(typ, bin.Bytes(), k.Version() == 4), nil
}

// Unlock decrypts the key's protected secret key material with a
// passphrase and keeps it in locked memory until Lock or Close. Either
// every protected part unlocks or none does. Parts whose secret is not in
// this copy (GnuPG stubs, smartcards) are left as they are.
func (k *Key) Unlock(passphrase []byte) error {
	var done []*secretKey
	usable := 0
	var lastErr error
	for _, c := range k.components() {
		sk := c.sec
		if sk == nil {
			continue
		}
		if sk.unavailable != nil {
			lastErr = sk.unavailable
			continue
		}
		if sk.secret != nil {
			usable++
			continue
		}
		if err := sk.unlock(passphrase, DefaultLimits); err != nil {
			for _, d := range done {
				d.lock()
			}
			return err
		}
		done = append(done, sk)
		usable++
	}
	if usable == 0 {
		if lastErr != nil {
			return lastErr
		}
		return fmt.Errorf("%w: the key has no secret key material", ErrKeyLocked)
	}
	return nil
}

// LockOptions choose how Lock protects secret key material.
type LockOptions struct {
	// AEAD protects a version 4 key with AES-256-OCB and Argon2 (S2K usage
	// 253) instead of AES-256-CFB with iterated SHA-256 (usage 254), which
	// is what GnuPG 2.4 can read. Version 6 keys always use AEAD.
	AEAD bool
}

// Lock forgets the cleartext secret key material. With a passphrase it
// first (re)protects every secret part under that passphrase, so that
// Serialize writes the newly protected form; the key must be unlocked for
// that. Without one it only forgets, which needs every part to be
// protected already.
func (k *Key) Lock(passphrase []byte, opts *LockOptions) error {
	var secrets []*secretKey
	for _, c := range k.components() {
		if c.sec != nil && c.sec.unavailable == nil {
			secrets = append(secrets, c.sec)
		}
	}
	if len(secrets) == 0 {
		return fmt.Errorf("%w: the key has no secret key material", ErrKeyLocked)
	}
	if passphrase == nil {
		for _, sk := range secrets {
			if sk.prot.usage == usageNone {
				return errors.New("svpgp: an unprotected key cannot be locked without a passphrase")
			}
		}
		for _, sk := range secrets {
			sk.lock()
		}
		return nil
	}
	if len(passphrase) == 0 {
		return errors.New("svpgp: an empty passphrase protects nothing")
	}
	for _, sk := range secrets {
		if err := sk.usable(); err != nil {
			return fmt.Errorf("svpgp: unlock the key before protecting it again: %w", err)
		}
	}
	for _, sk := range secrets {
		spec, mode := newIteratedS2K(), AEADAlgorithm(0)
		if sk.pub.version == 6 || opts != nil && opts.AEAD {
			spec, mode = newArgon2S2K(), OCB
		}
		if err := sk.protect(passphrase, spec, mode, DefaultLimits); err != nil {
			return err
		}
	}
	for _, sk := range secrets {
		sk.lock()
	}
	return nil
}

// Close wipes all cleartext secret key material from memory. A protected
// key can be unlocked again; an unprotected one loses its secret parts for
// good (serialize it first if it is needed).
func (k *Key) Close() {
	for _, c := range k.components() {
		if c.sec == nil || c.sec.unavailable != nil {
			continue
		}
		if c.sec.prot.usage == usageNone {
			c.sec.unavailable = fmt.Errorf("%w: the key was closed", ErrKeyLocked)
		}
		c.sec.destroy()
	}
}

// String describes the key briefly, for logs and errors.
func (k *Key) String() string {
	s := fmt.Sprintf("v%d %v key %X", k.Version(), k.Algorithm(), k.primary.pub.fp)
	if uid := k.PrimaryUserID(); uid != "" {
		s += " " + fmt.Sprintf("%q", uid)
	}
	return s
}
