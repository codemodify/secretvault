package svpgp

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"time"
)

// Message is an OpenPGP message that has been read: its content, how it
// was protected, and the verdict on each signature in it.
type Message struct {
	// Body is the message itself: the literal data, or for a cleartext
	// signed message exactly the text that was signed, with its lines
	// separated by LF instead of CR LF (trailing whitespace is not part of
	// it, and neither is the line ending before the signature).
	Body []byte

	// Format ('b' binary, 'u' UTF-8 text, 't' text), FileName and Date
	// come from the literal data packet. No signature covers them (RFC
	// 9580, section 5.9); do not act on them as if one did.
	Format   byte
	FileName string
	Date     time.Time

	// Encrypted says whether the message was encrypted. When it was,
	// IntegrityProtected says whether its integrity was checked, which is
	// always true unless ReadOptions.AllowUnprotected let an old SED packet
	// through; SEIPDVersion is 1 (CFB with an MDC) or 2 (AEAD), Cipher the
	// session key's cipher and AEAD the mode for version 2.
	Encrypted          bool
	IntegrityProtected bool
	SEIPDVersion       int
	Cipher             CipherAlgorithm
	AEAD               AEADAlgorithm

	// DecryptedWith is the key whose secret (sub)key decrypted the message,
	// and DecryptionKey that (sub)key's fingerprint. Both are nil when a
	// passphrase did.
	DecryptedWith *Key
	DecryptionKey []byte

	// Compressed says whether the message was compressed.
	Compressed bool

	// Cleartext says whether this was a cleartext signed message.
	Cleartext bool

	// Signatures holds a verdict for every signature in the message.
	Signatures []SignatureResult

	// Warnings are things the caller should tell the person: an
	// unprotected or weakly encrypted message, a deprecated key type.
	Warnings []string
}

// ReadOptions configure ReadMessage.
type ReadOptions struct {
	// Keyring holds the secret keys to decrypt with (they must be
	// unlocked) and the public keys to verify signatures with.
	Keyring []*Key
	// Passphrase is called, at most once, when the message can be
	// decrypted with a passphrase and no key in the keyring decrypts it.
	// The package does not keep or wipe the slice it returns.
	Passphrase func() ([]byte, error)
	// Time is when signatures are judged; zero means now.
	Time time.Time
	// AllowUnprotected lets a message encrypted without integrity
	// protection (an SED packet, from before 2001) be decrypted. The
	// result has IntegrityProtected false and a warning. Anyone could have
	// changed such a message.
	AllowUnprotected bool
	// Limits bound the resources the message may use; nil means
	// DefaultLimits.
	Limits *Limits
}

// ReadMessage reads any OpenPGP message: encrypted, signed, compressed or
// literal, binary or armored, or a cleartext signed message. It decrypts
// with the keyring or a passphrase and verifies signatures against the
// keyring. Integrity is checked before anything inside an encrypted packet
// is parsed, and nothing is returned from a message that fails it.
func ReadMessage(r io.Reader, opts ReadOptions) (*Message, error) {
	br, typ, err := openInput(r)
	if err != nil {
		return nil, err
	}
	m := newMsgReader(opts)
	var src io.Reader = br
	switch typ {
	case "":
	case BlockMessage:
		block, err := armorBody(br, typ)
		if err != nil {
			return nil, err
		}
		src = block.Body
	case BlockSignedMessage:
		return m.readCleartext(br)
	default:
		return nil, malformed("armor of type %q is not a message", typ)
	}
	if err := m.parse(newPacketReader(src), 0); err != nil {
		clear(m.msg.Body)
		return nil, err
	}
	m.checkSignatures()
	return m.msg, nil
}

// Decrypt reads an encrypted message (binary or armored) with the secret
// keys in the keyring, which must be unlocked, or with a passphrase, and
// verifies any signatures inside against the keyring now. A message that
// is not encrypted is refused with ErrNotEncrypted.
func Decrypt(r io.Reader, keyring []*Key, passphrase func() ([]byte, error)) (*Message, error) {
	msg, err := ReadMessage(r, ReadOptions{Keyring: keyring, Passphrase: passphrase})
	if err != nil {
		return nil, err
	}
	if !msg.Encrypted {
		clear(msg.Body)
		return nil, ErrNotEncrypted
	}
	return msg, nil
}

// VerifyInline reads a signed message, inline (binary or armored) or
// cleartext, and verifies its signatures against the keyring at time at
// (zero means now). It fails with ErrNoSignature if the message is not
// signed. As with Verify, a nil error does not mean a signature is valid:
// check Message.Signatures.
func VerifyInline(r io.Reader, keyring []*Key, at time.Time) (*Message, error) {
	msg, err := ReadMessage(r, ReadOptions{Keyring: keyring, Time: at})
	if err != nil {
		return nil, err
	}
	if len(msg.Signatures) == 0 {
		return nil, ErrNoSignature
	}
	return msg, nil
}

type msgReader struct {
	opts       ReadOptions
	lim        Limits
	now        time.Time
	msg        *Message
	budget     int64 // plaintext bytes still allowed
	jobs       []sigJob
	literal    bool         // the literal data has been read
	recipients []*publicKey // primary keys the message was decrypted with
}

// sigJob is a signature over the literal data waiting to be checked, with
// the one-pass signature packet it answers, if any.
type sigJob struct {
	sig *signature
	ops *onePass
	err error // the signature packet could not be read
}

func newMsgReader(opts ReadOptions) *msgReader {
	lim := opts.Limits.withDefaults()
	now := opts.Time
	if now.IsZero() {
		now = time.Now()
	}
	return &msgReader{opts: opts, lim: lim, now: now, msg: &Message{}, budget: lim.MaxMessageSize}
}

// parse reads one level of a message: the packets of an OpenPGP message
// (RFC 9580, section 10.3), recursing into compressed and encrypted data.
func (m *msgReader) parse(pr *packetReader, depth int) error {
	if depth > m.lim.MaxNesting {
		return limit("messages nested more than %d deep", m.lim.MaxNesting)
	}
	var (
		ops       []*onePass // one-pass signatures still waiting for their signature
		esks      []any      // session key packets before the encrypted data
		haveData  bool       // this level's message (literal, compressed or encrypted) has been read
		encrypted bool       // it was encrypted data: nothing may follow
	)
	for {
		tag, body, err := pr.next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if tag == ptMarker || tag == ptPadding {
			continue
		}
		if encrypted && tag.critical() {
			return malformed("a %v packet after the encrypted data", tag)
		}
		switch tag {
		case ptPKESK, ptSKESK, ptSEIPD, ptSED:
			if depth != 0 || haveData || len(ops) > 0 || len(m.jobs) > 0 {
				return malformed("encrypted data where the message grammar allows none (nested or signed encryption is refused)")
			}
			if tag == ptPKESK || tag == ptSKESK {
				if len(esks) >= maxESKPackets {
					return limit("more than %d session key packets", maxESKPackets)
				}
				data, err := body.readAll(maxPacketSize)
				if err != nil {
					return err
				}
				var esk any
				if tag == ptPKESK {
					esk, err = parsePKESK(data)
				} else {
					esk, err = parseSKESK(data)
				}
				if errors.Is(err, ErrUnsupported) {
					continue // a version or algorithm this reader cannot use
				}
				if err != nil {
					return err
				}
				esks = append(esks, esk)
				continue
			}
			if err := m.decrypt(tag, body, esks, depth); err != nil {
				return err
			}
			haveData, encrypted = true, true
		case ptOnePass:
			if haveData {
				return malformed("a one-pass signature after the signed data")
			}
			if len(ops)+len(m.jobs) >= maxOnePass {
				return limit("more than %d signatures on a message", maxOnePass)
			}
			data, err := body.readAll(maxPacketSize)
			if err != nil {
				return err
			}
			op, err := parseOnePass(data)
			if err != nil {
				op = &onePass{err: err}
			}
			ops = append(ops, op)
		case ptSignature:
			data, err := body.readAll(maxPacketSize)
			if err != nil {
				return err
			}
			sig, perr := parseSignature(data, 0)
			if !haveData {
				if len(ops)+len(m.jobs) >= maxOnePass {
					return limit("more than %d signatures on a message", maxOnePass)
				}
				m.jobs = append(m.jobs, sigJob{sig: sig, err: perr})
				continue
			}
			if len(ops) == 0 {
				return malformed("a signature after the data with no one-pass signature for it")
			}
			op := ops[len(ops)-1]
			ops = ops[:len(ops)-1]
			m.jobs = append(m.jobs, sigJob{sig: sig, ops: op, err: perr})
		case ptLiteral:
			if haveData || m.literal {
				return malformed("more than one literal data packet")
			}
			if err := m.readLiteral(body); err != nil {
				return err
			}
			haveData = true
		case ptCompressed:
			if haveData {
				return malformed("compressed data after the message data")
			}
			r, _, err := decompressor(body, m.lim, m.budget)
			if err != nil {
				return err
			}
			m.msg.Compressed = true
			if err := m.parse(newPacketReader(r), depth+1); err != nil {
				return err
			}
			haveData = true
		case 20:
			return unsupported("LibrePGP's AEAD encrypted data packet (type 20)")
		default:
			if tag.critical() {
				return malformed("a %v packet in a message", tag)
			}
		}
	}
	if len(esks) > 0 && !encrypted {
		return malformed("session key packets without encrypted data")
	}
	if !haveData {
		if depth == 0 && len(m.jobs) > 0 && len(ops) == 0 {
			return malformed("signatures without a message (a detached signature? use Verify)")
		}
		return malformed("no message data")
	}
	if len(ops) > 0 {
		return malformed("a one-pass signature without its signature: the message is cut short")
	}
	return nil
}

func (m *msgReader) readLiteral(body io.Reader) error {
	format, name, date, err := readLiteralHeader(body)
	if err != nil {
		return err
	}
	data, err := io.ReadAll(io.LimitReader(body, m.budget+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > m.budget {
		clear(data)
		return limit("a message over %d bytes", m.lim.MaxMessageSize)
	}
	m.budget -= int64(len(data))
	m.literal = true
	m.msg.Body, m.msg.Format, m.msg.FileName, m.msg.Date = data, format, name, date
	return nil
}

// candidate is a session key to try.
type candidate struct {
	alg  CipherAlgorithm
	key  []byte
	from *Key
	comp *keyComponent
}

// decrypt obtains the session key from the session key packets and
// decrypts the encrypted data, checking its integrity before parsing
// anything inside it.
func (m *msgReader) decrypt(tag packetType, body *bodyReader, esks []any, depth int) error {
	m.msg.Encrypted = true
	if tag == ptSED && !m.opts.AllowUnprotected {
		return ErrUnprotected
	}
	ed, err := readEncryptedData(tag, body, m.lim.MaxMessageSize+m.lim.MaxMessageSize/2+1<<20)
	if err != nil {
		return err
	}
	if tag == ptSED {
		m.warn("the message is not integrity protected: anyone could have changed it")
	} else {
		m.msg.IntegrityProtected = true
		m.msg.SEIPDVersion = ed.version
	}
	pkeskVersion, skeskVersion := 3, 4
	if ed.version == 2 {
		pkeskVersion, skeskVersion = 6, 6
	}
	var cands []candidate
	defer func() {
		for _, c := range cands {
			clear(c.key)
		}
	}()
	// The first PKESK that gives a session key wins: the checksum or the
	// key wrap has authenticated it, so there is no need to go on.
	var keyErr error
	tries := 0
pkesks:
	for _, e := range esks {
		p, ok := e.(*pkesk)
		if !ok || p.version != pkeskVersion {
			continue
		}
		for _, k := range m.opts.Keyring {
			for _, c := range k.components() {
				if c.sec == nil || !c.pub.alg.canEncrypt() || !(p.matches(c.pub) || p.anonymous()) {
					continue
				}
				if p.anonymous() {
					if tries++; tries > maxRecipientTries {
						continue pkesks
					}
				}
				if err := c.sec.usable(); err != nil {
					keyErr = err
					continue
				}
				alg, key, err := p.decrypt(c.sec, ed.cipher)
				if err != nil {
					continue
				}
				cands = append(cands, candidate{alg: alg, key: key, from: k, comp: c})
				break pkesks
			}
		}
	}
	var passErr error
	if len(cands) == 0 {
		var skesks []*skesk
		for _, e := range esks {
			if s, ok := e.(*skesk); ok && s.version == skeskVersion {
				skesks = append(skesks, s)
			}
		}
		if len(skesks) == 0 && len(esks) == 0 && m.opts.Passphrase != nil {
			// No session key packets at all: very old data, where the
			// passphrase hashed with MD5 is the IDEA key.
			return unsupported("encrypted data without session key packets")
		}
		if len(skesks) > 0 && m.opts.Passphrase != nil {
			pass, err := m.opts.Passphrase()
			if err != nil {
				return err
			}
			if len(skesks) > maxPassphraseTries {
				skesks = skesks[:maxPassphraseTries]
			}
			for _, s := range skesks {
				alg, key, err := s.decrypt(pass, ed.cipher, m.lim)
				if err != nil {
					passErr = err
					continue
				}
				cands = append(cands, candidate{alg: alg, key: key})
			}
		}
	}
	if len(cands) == 0 {
		switch {
		case passErr != nil:
			return passErr
		case keyErr != nil:
			return keyErr
		}
		return ErrNoKey
	}
	try := cands
	if ed.version != 2 && len(cands) > 1 {
		try = nil
		for _, c := range cands {
			if ed.quickCheck(c.alg, c.key) {
				try = append(try, c)
			}
		}
	}
	var plain []byte
	var used *candidate
	for i := range try {
		if plain, err = ed.decrypt(try[i].alg, try[i].key); err == nil {
			used = &try[i]
			break
		}
	}
	if used == nil {
		return ErrDecryption
	}
	defer clear(plain)
	if ed.version == 2 {
		m.msg.Cipher, m.msg.AEAD = ed.cipher, ed.aead
	} else {
		m.msg.Cipher = used.alg
	}
	if used.alg.legacy() {
		m.warn(fmt.Sprintf("the message is encrypted with %v, which is obsolete: its confidentiality is suspect", used.alg))
	}
	if used.from != nil {
		m.msg.DecryptedWith = used.from
		m.msg.DecryptionKey = slices.Clone(used.comp.pub.fp)
		m.recipients = append(m.recipients, used.from.primary.pub)
		switch pk := used.comp.pub; {
		case pk.alg == ElGamal:
			m.warn("the message was decrypted with an ElGamal key, which is too weak for modern use")
		case pk.rsa != nil && pk.rsa.N.BitLen() < 3072:
			m.warn(fmt.Sprintf("the message was decrypted with a %d-bit RSA key, which is too weak for modern use", pk.rsa.N.BitLen()))
		}
	}
	return m.parse(newPacketReader(bytes.NewReader(plain)), depth+1)
}

func (m *msgReader) warn(s string) {
	if !slices.Contains(m.msg.Warnings, s) {
		m.msg.Warnings = append(m.msg.Warnings, s)
	}
}

// checkSignatures verifies every signature over the literal data.
func (m *msgReader) checkSignatures() {
	ctx := &verifyContext{keyring: m.opts.Keyring, now: m.now, recipients: m.recipients}
	for _, job := range m.jobs {
		switch {
		case job.err != nil:
			m.msg.Signatures = append(m.msg.Signatures, malformedResult(job.err))
		case job.ops != nil && job.ops.err != nil:
			m.msg.Signatures = append(m.msg.Signatures, malformedResult(job.ops.err))
		case job.ops != nil && !job.ops.matches(job.sig):
			r := newResult(job.sig)
			r.Err = fmt.Errorf("%w: the signature does not match its one-pass signature packet", ErrSignatureMalformed)
			m.msg.Signatures = append(m.msg.Signatures, r)
		default:
			c := newSigChecker(job.sig)
			c.Write(m.msg.Body)
			m.msg.Signatures = append(m.msg.Signatures, c.result(ctx))
		}
	}
}

// onePass is a one-pass signature packet (RFC 9580, section 5.4).
type onePass struct {
	version int
	typ     SignatureType
	hash    HashAlgorithm
	alg     PublicKeyAlgorithm
	keyID   uint64 // version 3
	fp      []byte // version 6
	salt    []byte // version 6
	err     error  // the packet could not be read
}

func parseOnePass(body []byte) (*onePass, error) {
	p := newParser(body)
	op := &onePass{version: int(p.u8())}
	if p.err == nil && op.version != 3 && op.version != 6 {
		return nil, unsupported("version %d one-pass signatures", op.version)
	}
	op.typ = SignatureType(p.u8())
	op.hash = HashAlgorithm(p.u8())
	op.alg = PublicKeyAlgorithm(p.u8())
	if op.version == 6 {
		op.salt = p.bytes(int(p.u8()))
		op.fp = p.bytes(32)
	} else if id := p.bytes(8); p.err == nil {
		op.keyID = uint64FromBytes(id)
	}
	p.u8() // the nested flag: every signature here covers the literal data
	p.done()
	if p.err != nil {
		return nil, p.err
	}
	return op, nil
}

// matches reports whether a signature is the one a one-pass packet
// announced (RFC 9580, section 10.3.2.2).
func (op *onePass) matches(s *signature) bool {
	if op.typ != s.typ || op.hash != s.hash || op.alg != s.alg {
		return false
	}
	if op.version == 6 {
		return s.version == 6 && bytes.Equal(op.salt, s.salt) && bytes.Equal(op.fp, s.issuerFP)
	}
	if s.version != 3 && s.version != 4 {
		return false
	}
	if s.issuerFP != nil {
		return uint64FromBytes(s.issuerFP[12:]) == op.keyID
	}
	return s.hasIssuerKeyID && s.issuerKeyID == op.keyID
}
