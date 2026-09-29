package svpgp

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"
	"time"
)

// SignMode is the form of a signed message.
type SignMode int

const (
	// SignDetached writes only the signature; the message travels
	// separately (RFC 9580, section 10.4).
	SignDetached SignMode = iota
	// SignInline writes a signed message: a one-pass signature packet, the
	// message in a literal data packet, and the signature (section 10.3).
	SignInline
	// SignCleartext writes the message as readable text followed by an
	// armored signature (the cleartext signature framework, section 7).
	// It always makes a text signature, which ignores trailing whitespace
	// and line ending differences, and is always armored.
	SignCleartext
)

// SignOptions choose how Sign signs.
type SignOptions struct {
	Mode SignMode
	// Text makes a text signature (type 0x01): line endings are
	// canonicalised to CR LF before hashing, so the signature survives
	// conversion between them. The literal data of an inline signed
	// message is marked as UTF-8 text and stored with CR LF line endings,
	// as RFC 9580 requires.
	Text bool
	// Armor armors the output. Cleartext signed messages always are.
	Armor bool
	// Hash is the hash to sign with; zero means SHA2-512.
	Hash HashAlgorithm
	// Time is the signature's creation time, and the time at which the key
	// must be valid; zero means now.
	Time time.Time
	// FileName goes into the literal data packet of an inline signed
	// message. Nothing signs it.
	FileName string
}

// Sign signs a message with the key's signing (sub)key valid at the
// signing time, whose secret must be unlocked.
func Sign(w io.Writer, message io.Reader, signer *Key, opts SignOptions) error {
	t := opts.Time
	if t.IsZero() {
		t = time.Now()
	}
	comp, err := signer.signingKey(t)
	if err != nil {
		return err
	}
	typ := SigBinary
	if opts.Text || opts.Mode == SignCleartext {
		typ = SigText
	}
	switch opts.Mode {
	case SignDetached:
		b, err := newSigBuilder(comp, typ, opts.Hash, t, nil)
		if err != nil {
			return err
		}
		if _, err := io.Copy(b, message); err != nil {
			return err
		}
		sig, err := b.finish()
		if err != nil {
			return err
		}
		pkt := packetBytes(ptSignature, sig.body)
		if opts.Armor {
			pkt = armorBytes(BlockSignature, pkt, sig.version != 6)
		}
		_, err = w.Write(pkt)
		return err
	case SignInline:
		out := w
		var armor io.WriteCloser
		if opts.Armor {
			if armor, err = ArmorWriter(w, BlockMessage, comp.pub.version != 6); err != nil {
				return err
			}
			out = armor
		}
		b, err := newSigBuilder(comp, typ, opts.Hash, t, nil)
		if err != nil {
			return err
		}
		if err := writePacket(out, ptOnePass, b.onePass(true)); err != nil {
			return err
		}
		if err := writeLiteral(out, opts.Text, opts.FileName, io.TeeReader(message, b)); err != nil {
			return err
		}
		sig, err := b.finish()
		if err != nil {
			return err
		}
		if err := writePacket(out, ptSignature, sig.body); err != nil {
			return err
		}
		if armor != nil {
			return armor.Close()
		}
		return nil
	case SignCleartext:
		text, err := io.ReadAll(message)
		if err != nil {
			return err
		}
		lines := cleartextLines(text)
		b, err := newSigBuilder(comp, SigText, opts.Hash, t, nil)
		if err != nil {
			return err
		}
		b.w = b.h // the lines are already canonical
		var out bytes.Buffer
		out.WriteString("-----BEGIN " + BlockSignedMessage + "-----\n")
		if comp.pub.version == 4 {
			// For readers that still expect it (RFC 9580, section 6.2.2.3).
			out.WriteString("Hash: " + b.tmpl.hash.String() + "\n")
		}
		out.WriteString("\n")
		for i, l := range lines {
			if i > 0 {
				b.Write([]byte("\r\n"))
			}
			b.Write(l)
			if bytes.HasPrefix(l, []byte("-")) || bytes.HasPrefix(l, []byte("From ")) {
				out.WriteString("- ")
			}
			out.Write(l)
			out.WriteString("\n")
		}
		sig, err := b.finish()
		if err != nil {
			return err
		}
		out.Write(armorBytes(BlockSignature, packetBytes(ptSignature, sig.body), sig.version != 6))
		_, err = w.Write(out.Bytes())
		return err
	}
	return fmt.Errorf("svpgp: unknown sign mode %d", opts.Mode)
}

// writeLiteral writes a literal data packet, streaming the data with
// partial body lengths. Text is marked as UTF-8 ('u') and stored with CR LF
// line endings, as RFC 9580 section 5.9 requires.
func writeLiteral(w io.Writer, text bool, name string, data io.Reader) error {
	lw, err := newLiteralWriter(w, text, name)
	if err != nil {
		return err
	}
	if _, err := io.Copy(lw, bufio.NewReaderSize(data, 64<<10)); err != nil {
		return err
	}
	return lw.Close()
}

// newLiteralWriter starts a literal data packet; see writeLiteral.
func newLiteralWriter(w io.Writer, text bool, name string) (io.WriteCloser, error) {
	pw, err := newPartialWriter(w, ptLiteral)
	if err != nil {
		return nil, err
	}
	format := byte('b')
	if text {
		format = 'u'
	}
	if _, err := pw.Write(literalHeader(format, name, time.Time{})); err != nil {
		return nil, err
	}
	if !text {
		return pw, nil
	}
	return struct {
		io.Writer
		io.Closer
	}{&canonicalWriter{w: pw}, pw}, nil
}

// sigBuilder hashes the data for one new signature as it streams past, and
// signs it at the end.
type sigBuilder struct {
	tmpl   *signature // everything but the signature value
	h      hash.Hash
	w      io.Writer // h, or a canonicalising writer over it
	signer *keyComponent
}

// newSigBuilder prepares a data signature. recipients are the primary key
// fingerprints of the people it is encrypted to, for the intended recipient
// subpackets of a signed and encrypted message.
func newSigBuilder(signer *keyComponent, typ SignatureType, h HashAlgorithm, created time.Time, recipients []*publicKey) (*sigBuilder, error) {
	extra := func(b *subpacketBuilder) {
		for _, r := range recipients {
			b.add(spIntendedRecipient, signer.pub.version == 6, append([]byte{byte(r.version)}, r.fp...)...)
		}
	}
	tmpl, err := newSignatureTemplate(signer, typ, h, created, extra)
	if err != nil {
		return nil, err
	}
	hh, err := tmpl.newHash()
	if err != nil {
		return nil, err
	}
	b := &sigBuilder{tmpl: tmpl, h: hh, w: hh, signer: signer}
	if typ == SigText {
		b.w = &canonicalWriter{w: hh}
	}
	return b, nil
}

func (b *sigBuilder) Write(p []byte) (int, error) { return b.w.Write(p) }

// onePass encodes the one-pass signature packet for this signature (RFC
// 9580, section 5.4): version 3 for a version 4 key, 6 for version 6.
func (b *sigBuilder) onePass(last bool) []byte {
	s := b.tmpl
	nested := byte(0)
	if last {
		nested = 1
	}
	if s.version == 6 {
		out := []byte{6, byte(s.typ), byte(s.hash), byte(s.alg), byte(len(s.salt))}
		out = append(out, s.salt...)
		out = append(out, b.signer.pub.fp...)
		return append(out, nested)
	}
	out := []byte{3, byte(s.typ), byte(s.hash), byte(s.alg)}
	out = appendU32(out, uint32(b.signer.pub.keyID>>32))
	out = appendU32(out, uint32(b.signer.pub.keyID))
	return append(out, nested)
}

// finish signs what has been hashed.
func (b *sigBuilder) finish() (*signature, error) {
	return b.tmpl.sign(b.signer, b.h)
}

// newSignatureTemplate sets up a version 4 or 6 signature by a key, with
// the subpackets every signature gets (creation time, issuer) and any the
// caller adds.
func newSignatureTemplate(signer *keyComponent, typ SignatureType, h HashAlgorithm, created time.Time, extra func(*subpacketBuilder)) (*signature, error) {
	pk := signer.pub
	if pk.unusable != nil {
		return nil, pk.unusable
	}
	if !pk.alg.canSign() {
		return nil, fmt.Errorf("%w: a %v key cannot sign", ErrUnsupported, pk.alg)
	}
	if h == 0 {
		h = SHA512
	}
	switch h {
	case SHA256, SHA384, SHA512, SHA224, SHA3_256, SHA3_512:
	default:
		return nil, unsupported("signing with %v", h)
	}
	if err := pk.signingHashOK(h); err != nil {
		return nil, err
	}
	s := &signature{version: pk.version, typ: typ, alg: pk.alg, hash: h, created: created, hasCreated: true}
	var hashed subpacketBuilder
	hashed.addTime(spCreationTime, true, timeField(created))
	hashed.add(spIssuerFingerprint, false, append([]byte{byte(pk.version)}, pk.fp...)...)
	if extra != nil {
		extra(&hashed)
	}
	s.hashed = hashed
	if pk.version == 4 {
		var unhashed subpacketBuilder
		id := pk.keyID
		unhashed.add(spIssuerKeyID, false, byte(id>>56), byte(id>>48), byte(id>>40), byte(id>>32), byte(id>>24), byte(id>>16), byte(id>>8), byte(id))
		s.unhashed = unhashed
	} else {
		s.salt = make([]byte, h.saltSize())
		rand.Read(s.salt)
	}
	return s, nil
}

// sign finishes a template over a hash that holds the signed data: it
// hashes the trailer, signs, and checks the result before returning it.
func (s *signature) sign(signer *keyComponent, h hash.Hash) (*signature, error) {
	if signer.sec == nil {
		return nil, ErrKeyLocked
	}
	s.writeTrailer(h)
	digest := h.Sum(nil)
	material, err := signer.sec.sign(s.hash, digest)
	if err != nil {
		return nil, err
	}
	sig, err := assembleSignature(s.version, s.typ, s.alg, s.hash, s.hashed, s.unhashed, s.salt, digest[:2], material)
	if err != nil {
		return nil, err
	}
	// A fault while signing can leak the key; never let a bad signature
	// out.
	if err := sig.verifyDigest(signer.pub, digest); err != nil {
		return nil, errors.Join(errors.New("svpgp: the new signature does not verify"), err)
	}
	return sig, nil
}
