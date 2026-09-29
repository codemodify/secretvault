package svpgp

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"io"
	"slices"
	"time"
)

// SignatureResult is the verdict on one signature.
type SignatureResult struct {
	// Valid is true when the signature verifies, was made by a key in the
	// keyring that was valid and allowed to sign at the time, and passes
	// the policy (hash strength, expiry). Only then.
	Valid bool
	// Err says why the signature is not valid; nil when it is. It wraps
	// one of ErrUnknownSigner, ErrBadSignature, ErrWeakAlgorithm,
	// ErrKeyExpired, ErrKeyRevoked, ErrKeyInvalid, ErrSignatureExpired,
	// ErrSignatureFuture, ErrSignatureMalformed, ErrNotIntendedRecipient
	// or ErrUnsupported.
	Err error

	Type      SignatureType
	Version   int
	Hash      HashAlgorithm
	Algorithm PublicKeyAlgorithm
	CreatedAt time.Time
	// IssuerFingerprint and IssuerKeyID are what the signature says about
	// its issuer; nothing proves that unless Key is set.
	IssuerFingerprint []byte
	IssuerKeyID       uint64

	// Key is the key whose (sub)key the signature verifies with, and
	// SigningKey the fingerprint of that (sub)key. Both are set whenever
	// the signature verifies cryptographically, even if it is not Valid
	// (an expired or revoked key, say).
	Key        *Key
	SigningKey []byte
}

// verifyContext is what a signature is checked against.
type verifyContext struct {
	keyring []*Key
	now     time.Time
	// recipients are the primary keys the enclosing message was decrypted
	// with, or nil outside an encrypted message.
	recipients []*publicKey
}

func newResult(s *signature) SignatureResult {
	r := SignatureResult{Type: s.typ, Version: s.version, Hash: s.hash, Algorithm: s.alg, CreatedAt: s.created}
	if s.issuerFP != nil {
		r.IssuerFingerprint = slices.Clone(s.issuerFP)
		if s.version == 4 {
			r.IssuerKeyID = uint64FromBytes(s.issuerFP[12:])
		} else {
			r.IssuerKeyID = uint64FromBytes(s.issuerFP[:8])
		}
	} else if s.hasIssuerKeyID {
		r.IssuerKeyID = s.issuerKeyID
	}
	return r
}

func uint64FromBytes(b []byte) uint64 {
	var v uint64
	for _, c := range b[:8] {
		v = v<<8 | uint64(c)
	}
	return v
}

func malformedResult(err error) SignatureResult {
	return SignatureResult{Err: fmt.Errorf("%w: %w", ErrSignatureMalformed, err)}
}

// sigChecker hashes data for one signature being verified.
type sigChecker struct {
	s   *signature
	h   hash.Hash
	w   io.Writer
	err error // the signature cannot be checked
}

func newSigChecker(s *signature) *sigChecker {
	c := &sigChecker{s: s, w: io.Discard}
	if s.typ != SigBinary && s.typ != SigText {
		c.err = fmt.Errorf("%w: a %v signature is not a signature over data", ErrSignatureMalformed, s.typ)
		return c
	}
	h, err := s.newHash()
	if err != nil {
		c.err = fmt.Errorf("%w: %w", ErrWeakAlgorithm, err)
		return c
	}
	c.h, c.w = h, h
	if s.typ == SigText {
		c.w = &canonicalWriter{w: h}
	}
	return c
}

func (c *sigChecker) Write(p []byte) (int, error) { return c.w.Write(p) }

// result finishes the hash and checks the signature.
func (c *sigChecker) result(ctx *verifyContext) SignatureResult {
	if c.err != nil {
		r := newResult(c.s)
		r.Err = c.err
		return r
	}
	c.s.writeTrailer(c.h)
	return checkSignature(c.s, c.h.Sum(nil), ctx)
}

// checkSignature decides on a data signature whose digest has been
// computed: find the key, verify, then check the policy and that the key
// was valid for signing when the signature was made.
func checkSignature(s *signature, digest []byte, ctx *verifyContext) SignatureResult {
	r := newResult(s)
	if s.invalid != nil {
		r.Err = fmt.Errorf("%w: %w", ErrSignatureMalformed, s.invalid)
		return r
	}
	type candidate struct {
		key  *Key
		comp *keyComponent
	}
	var candidates []candidate
	for _, k := range ctx.keyring {
		var comps []*keyComponent
		switch {
		case s.issuerFP != nil:
			comps = k.findComponent(s.issuerFP, 0)
		case s.hasIssuerKeyID:
			comps = k.findComponent(nil, s.issuerKeyID)
		default:
			comps = k.components()
		}
		for _, c := range comps {
			candidates = append(candidates, candidate{k, c})
		}
	}
	if len(candidates) == 0 {
		r.Err = ErrUnknownSigner
		return r
	}
	var lastErr error
	for _, cand := range candidates {
		if err := s.verifyDigest(cand.comp.pub, digest); err != nil {
			lastErr = err
			continue
		}
		r.Key, r.SigningKey = cand.key, slices.Clone(cand.comp.pub.fp)
		r.Err = policyCheck(s, cand.key, cand.comp, ctx)
		r.Valid = r.Err == nil
		return r
	}
	if errors.Is(lastErr, ErrUnsupported) {
		r.Err = lastErr
	} else {
		r.Err = ErrBadSignature
	}
	return r
}

// policyCheck is everything about a cryptographically valid signature
// that can still make it invalid.
func policyCheck(s *signature, k *Key, c *keyComponent, ctx *verifyContext) error {
	if err := s.hashPolicy(); err != nil {
		return fmt.Errorf("%w: %v in a signature made %v", err, s.hash, s.created.Format(time.DateOnly))
	}
	if s.created.After(ctx.now) {
		return ErrSignatureFuture
	}
	if s.expiredAt(ctx.now) {
		return ErrSignatureExpired
	}
	if err := k.signerAt(c, s.created, ctx.now); err != nil {
		return err
	}
	if len(s.recipients) > 0 {
		ok := false
		for _, want := range s.recipients {
			for _, got := range ctx.recipients {
				if int(want[0]) == got.version && bytes.Equal(want[1:], got.fp) {
					ok = true
				}
			}
		}
		if !ok {
			return ErrNotIntendedRecipient
		}
	}
	return nil
}

// Verify checks a detached signature (binary or armored, holding one or
// more signatures) over a message against a keyring, at time at (zero
// means now). It returns a result for every signature. The error is only
// for input that cannot be read or holds no signature; a nil error does
// not mean any signature is valid.
func Verify(message, signature io.Reader, keyring []*Key, at time.Time) ([]SignatureResult, error) {
	if at.IsZero() {
		at = time.Now()
	}
	br, typ, err := openInput(signature)
	if err != nil {
		return nil, err
	}
	var src io.Reader = br
	if typ != "" {
		if typ != BlockSignature {
			return nil, malformed("armor of type %q is not a signature", typ)
		}
		block, err := armorBody(br, typ)
		if err != nil {
			return nil, err
		}
		src = block.Body
	}
	var checkers []*sigChecker
	var results []SignatureResult
	pr := newPacketReader(src)
	for {
		tag, body, err := pr.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		switch tag {
		case ptSignature:
			if len(checkers)+len(results) >= maxDetachedSigs {
				return nil, limit("more than %d signatures", maxDetachedSigs)
			}
			data, err := body.readAll(maxPacketSize)
			if err != nil {
				return nil, err
			}
			s, err := parseSignature(data, 0)
			if err != nil {
				results = append(results, malformedResult(err))
				continue
			}
			checkers = append(checkers, newSigChecker(s))
		case ptMarker, ptPadding:
		default:
			if tag.critical() {
				return nil, malformed("a %v packet in a detached signature", tag)
			}
		}
	}
	if len(checkers)+len(results) == 0 {
		return nil, ErrNoSignature
	}
	writers := make([]io.Writer, len(checkers))
	for i, c := range checkers {
		writers[i] = c
	}
	if _, err := io.Copy(io.MultiWriter(writers...), message); err != nil {
		return nil, err
	}
	ctx := &verifyContext{keyring: keyring, now: at}
	for _, c := range checkers {
		results = append(results, c.result(ctx))
	}
	return results, nil
}
