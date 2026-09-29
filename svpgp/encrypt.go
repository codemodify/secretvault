package svpgp

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"slices"
	"time"
)

// EncryptFormat chooses the encryption container.
type EncryptFormat int

const (
	// FormatAuto uses v2 SEIPD (AEAD) when every recipient key says it
	// supports it (version 6 keys, and version 4 keys with the feature
	// flag), and v1 SEIPD otherwise. A passphrase-only message uses v2.
	FormatAuto EncryptFormat = iota
	// FormatV1 uses v1 SEIPD (CFB with a modification detection code),
	// with v3 PKESK and v4 SKESK packets: what GnuPG 2.4 reads.
	FormatV1
	// FormatV2 uses v2 SEIPD, with v6 PKESK and SKESK packets, and fails
	// if a recipient does not support it.
	FormatV2
)

// EncryptOptions choose how Encrypt encrypts.
type EncryptOptions struct {
	// Passphrase also lets the message be decrypted with this passphrase,
	// or, with no recipients, is the only way to decrypt it.
	Passphrase []byte
	// Signer, if set, signs the message inside the encryption, with intended
	// recipient subpackets naming the recipients. Its signing key must be
	// unlocked.
	Signer *Key
	// Armor armors the output.
	Armor bool
	// Format chooses the container; see EncryptFormat.
	Format EncryptFormat
	// Compression compresses the message with ZIP or ZLIB, if every
	// recipient's preferences allow it (it is silently left out if not).
	// The default is none: compression before encryption can leak what
	// the data is.
	Compression CompressionAlgorithm
	// Text marks the literal data as UTF-8 text, stored with CR LF line
	// endings as RFC 9580 requires, and makes the signature, if any, a text
	// signature.
	Text bool
	// FileName goes into the literal data packet; nothing protects it from
	// the recipients.
	FileName string
	// Time is when recipient keys must be valid and when the signature is
	// made; zero means now.
	Time time.Time
	// Hash is the signature's hash; zero means SHA2-512.
	Hash HashAlgorithm
}

// Encrypt returns a writer that encrypts what is written to it to the
// recipients' valid encryption subkeys (every one each key has) and to the
// passphrase, if one is given. Close finishes the message; it does not
// close w. The choice of cipher follows the recipients' preferences, among
// AES-256, AES-192 and AES-128 (and OCB, GCM, EAX for v2).
func Encrypt(w io.Writer, recipients []*Key, opts EncryptOptions) (io.WriteCloser, error) {
	t := opts.Time
	if t.IsZero() {
		t = time.Now()
	}
	if len(recipients) == 0 && len(opts.Passphrase) == 0 {
		return nil, errors.New("svpgp: no recipients and no passphrase")
	}
	var targets []*keyComponent
	var prefs []*signature // each recipient's primary binding, for its preferences
	var primaries []*publicKey
	for _, r := range recipients {
		comps, err := r.encryptionKeys(t)
		if err != nil {
			return nil, fmt.Errorf("svpgp: cannot encrypt to %v: %w", r, err)
		}
		binding, err := r.primaryState(t, t)
		if err != nil {
			return nil, fmt.Errorf("svpgp: cannot encrypt to %v: %w", r, err)
		}
		targets = append(targets, comps...)
		prefs = append(prefs, r.preferenceSignature(binding, t))
		primaries = append(primaries, r.primary.pub)
	}
	v2 := true
	for i, r := range recipients {
		if !supportsV2(r, prefs[i]) {
			v2 = false
		}
	}
	switch opts.Format {
	case FormatV1:
		v2 = false
	case FormatV2:
		if !v2 {
			return nil, errors.New("svpgp: a recipient does not support v2 SEIPD (AEAD) encryption")
		}
	}
	var signer *keyComponent
	if opts.Signer != nil {
		var err error
		if signer, err = opts.Signer.signingKey(t); err != nil {
			return nil, fmt.Errorf("svpgp: cannot sign: %w", err)
		}
	}

	e := &encryptWriter{}
	var cipherAlg CipherAlgorithm
	var aeadMode AEADAlgorithm
	if v2 {
		cipherAlg, aeadMode = chooseAEAD(prefs)
	} else {
		cipherAlg = chooseCipher(prefs)
	}
	sessionKey := make([]byte, cipherAlg.KeySize())
	rand.Read(sessionKey)
	defer clear(sessionKey)

	out := w
	if opts.Armor {
		armor, err := ArmorWriter(w, BlockMessage, !v2)
		if err != nil {
			return nil, err
		}
		e.closers = append(e.closers, armor)
		out = armor
	}
	for _, c := range targets {
		version := 3
		if v2 {
			version = 6
		}
		body, err := encryptSessionKey(version, c.pub, cipherAlg, sessionKey)
		if err != nil {
			return nil, err
		}
		if err := writePacket(out, ptPKESK, body); err != nil {
			return nil, err
		}
	}
	if len(opts.Passphrase) > 0 {
		version := 4
		if v2 {
			version = 6
		}
		body, err := newSKESK(version, opts.Passphrase, cipherAlg, sessionKey, aeadMode)
		if err != nil {
			return nil, err
		}
		if err := writePacket(out, ptSKESK, body); err != nil {
			return nil, err
		}
	}
	var sealed io.WriteCloser
	var err error
	if v2 {
		sealed, err = newSEIPDv2Writer(out, cipherAlg, aeadMode, sessionKey)
	} else {
		sealed, err = newSEIPDv1Writer(out, cipherAlg, sessionKey)
	}
	if err != nil {
		return nil, err
	}
	counted := &countingWriter{w: sealed}
	e.closers = append(e.closers, sealed)
	if v2 {
		// Padding hides the exact length (RFC 9580, section 5.14).
		e.closers = append(e.closers, closerFunc(func() error { return writePadding(counted) }))
	}
	inner := io.Writer(counted)
	if opts.Compression != Uncompressed && acceptsCompression(prefs, opts.Compression) {
		cw, err := compressor(inner, opts.Compression)
		if err != nil {
			return nil, err
		}
		e.closers = append(e.closers, cw)
		inner = cw
	}
	if signer != nil {
		typ := SigBinary
		if opts.Text {
			typ = SigText
		}
		b, err := newSigBuilder(signer, typ, opts.Hash, t, primaries)
		if err != nil {
			return nil, err
		}
		if err := writePacket(inner, ptOnePass, b.onePass(true)); err != nil {
			return nil, err
		}
		dst := inner
		e.closers = append(e.closers, closerFunc(func() error {
			sig, err := b.finish()
			if err != nil {
				return err
			}
			return writePacket(dst, ptSignature, sig.body)
		}))
		e.hash = b
	}
	lit, err := newLiteralWriter(inner, opts.Text, opts.FileName)
	if err != nil {
		return nil, err
	}
	e.closers = append(e.closers, lit)
	e.lit = lit
	return e, nil
}

// encryptWriter is what Encrypt returns: plaintext goes into the literal
// data packet (and the signature hash), and Close finishes each layer from
// the inside out.
type encryptWriter struct {
	lit     io.Writer
	hash    io.Writer
	closers []io.Closer // outermost first
	closed  bool
	err     error
}

func (e *encryptWriter) Write(p []byte) (int, error) {
	if e.closed {
		return 0, errors.New("svpgp: write after close")
	}
	if e.err != nil {
		return 0, e.err
	}
	if e.hash != nil {
		e.hash.Write(p)
	}
	n, err := e.lit.Write(p)
	if err != nil {
		e.err = err
	}
	return n, err
}

func (e *encryptWriter) Close() error {
	if e.closed {
		return e.err
	}
	e.closed = true
	for i := len(e.closers) - 1; i >= 0; i-- {
		if err := e.closers[i].Close(); err != nil && e.err == nil {
			e.err = err
		}
	}
	return e.err
}

type closerFunc func() error

func (f closerFunc) Close() error { return f() }

type countingWriter struct {
	w io.Writer
	n int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}

// padme rounds a length up so that it leaks at most O(log log n) bits
// (Padmé, from "Reducing Metadata Leakage from Encrypted Files and
// Communication with PURBs").
func padme(n int64) int64 {
	if n < 2 {
		return n
	}
	e := bits.Len64(uint64(n)) - 1
	s := bits.Len64(uint64(e))
	mask := int64(1)<<(e-s) - 1
	return (n + mask) &^ mask
}

// writePadding ends a v2 SEIPD plaintext with a padding packet of random
// bytes that brings its length up to a Padmé size.
func writePadding(c *countingWriter) error {
	n := padme(c.n+2) - c.n - 2
	body := make([]byte, n)
	rand.Read(body)
	return writePacket(c, ptPadding, body)
}

// preferenceSignature is the self-signature whose algorithm preferences
// apply: the primary binding, or the direct key signature when the binding
// has none.
func (k *Key) preferenceSignature(binding *signature, t time.Time) *signature {
	if binding.prefSymmetric != nil || binding.prefAEAD != nil || binding.hasFeatures {
		return binding
	}
	if _, dks := k.primaryBindings(t, t); dks != nil {
		return dks
	}
	return binding
}

// supportsV2 reports whether a recipient can read v2 SEIPD: its features
// say so, or it is a version 6 key without a features subpacket (RFC 9580,
// section 13.7).
func supportsV2(k *Key, pref *signature) bool {
	if pref.hasFeatures {
		return len(pref.features) > 0 && pref.features[0]&featureSEIPDv2 != 0
	}
	return k.Version() == 6
}

// chooseCipher picks the v1 SEIPD cipher: the first of AES-256, AES-192 and
// AES-128 that every recipient lists. AES-128 is implied for everyone.
func chooseCipher(prefs []*signature) CipherAlgorithm {
	for _, c := range []CipherAlgorithm{AES256, AES192, AES128} {
		ok := true
		for _, p := range prefs {
			if c != AES128 && !slices.Contains(p.prefSymmetric, byte(c)) {
				ok = false
			}
		}
		if ok {
			return c
		}
	}
	return AES128
}

// chooseAEAD picks the v2 SEIPD cipher and mode that every recipient lists,
// preferring OCB, then GCM, then EAX, and AES-256 over AES-128. AES-128 with
// OCB is implied for everyone.
func chooseAEAD(prefs []*signature) (CipherAlgorithm, AEADAlgorithm) {
	for _, mode := range []AEADAlgorithm{OCB, GCM, EAX} {
		for _, c := range []CipherAlgorithm{AES256, AES128} {
			ok := true
			for _, p := range prefs {
				if c == AES128 && mode == OCB {
					continue
				}
				found := false
				for i := 0; i+1 < len(p.prefAEAD); i += 2 {
					if p.prefAEAD[i] == byte(c) && p.prefAEAD[i+1] == byte(mode) {
						found = true
					}
				}
				if !found {
					ok = false
				}
			}
			if ok {
				return c, mode
			}
		}
	}
	return AES128, OCB
}

// acceptsCompression reports whether every recipient lists the algorithm.
func acceptsCompression(prefs []*signature, alg CompressionAlgorithm) bool {
	for _, p := range prefs {
		if !slices.Contains(p.prefCompress, byte(alg)) {
			return false
		}
	}
	return true
}
