package svmail

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/codemodify/secretvault/svpgp"
)

// OpenPGP in mail: PGP/MIME (RFC 3156) and inline blocks.

// pgpScan is what the packets in front of an OpenPGP message say.
type pgpScan struct {
	encrypted   bool
	unprotected bool // an SED packet: no integrity protection
	recipients  []PGPRecipient
	// A version 2 SEIPD packet names its cipher and AEAD mode in the
	// clear; version 1 hides the cipher in the session key.
	seipd  int
	cipher svpgp.CipherAlgorithm
	aead   svpgp.AEADAlgorithm
}

// scanPGP reads the packet headers at the start of an OpenPGP message,
// armored or binary, to learn whether it is encrypted and to whom,
// without decrypting or verifying anything. It reads at most maxPGPScan
// bytes.
func scanPGP(data []byte) (*pgpScan, error) {
	var bin []byte
	if i := bytes.Index(data, []byte("-----BEGIN PGP ")); i >= 0 {
		block, err := svpgp.Dearmor(bytes.NewReader(data[i:]))
		if err != nil {
			return nil, err
		}
		bin, err = io.ReadAll(io.LimitReader(block.Body, maxPGPScan))
		if err != nil && len(bin) == 0 {
			return nil, err
		}
	} else {
		bin = data[:min(len(data), maxPGPScan)]
	}
	out := &pgpScan{}
	for n := 0; len(bin) > 0 && n < 256; n++ {
		tag, body, rest, ok := pgpPacket(bin)
		if !ok {
			break
		}
		bin = rest
		switch tag {
		case 1: // PKESK
			if r, ok := parsePKESKHeader(body); ok {
				out.recipients = append(out.recipients, r)
			}
		case 3: // SKESK
			out.recipients = append(out.recipients, PGPRecipient{Passphrase: true})
		case 18: // SEIPD
			out.encrypted = true
			if len(body) >= 1 {
				out.seipd = int(body[0])
			}
			if out.seipd == 2 && len(body) >= 3 {
				out.cipher, out.aead = svpgp.CipherAlgorithm(body[1]), svpgp.AEADAlgorithm(body[2])
			}
			return out, nil
		case 9: // SED
			out.encrypted, out.unprotected = true, true
			return out, nil
		case 10, 21: // marker, padding
		default:
			return out, nil
		}
	}
	out.encrypted = out.encrypted || len(out.recipients) > 0
	return out, nil
}

// pgpPacket splits one packet off b. Only packets with a known length
// are split: a partial or indeterminate length ends the scan, which is
// fine, since only data packets have them.
func pgpPacket(b []byte) (tag byte, body, rest []byte, ok bool) {
	if len(b) < 2 || b[0]&0x80 == 0 {
		return 0, nil, nil, false
	}
	var n, hdr int
	if b[0]&0x40 != 0 {
		tag = b[0] & 0x3f
		switch l := int(b[1]); {
		case l < 192:
			n, hdr = l, 2
		case l < 224:
			if len(b) < 3 {
				return 0, nil, nil, false
			}
			n, hdr = (l-192)<<8+int(b[2])+192, 3
		case l == 255:
			if len(b) < 6 {
				return 0, nil, nil, false
			}
			n, hdr = int(b[2])<<24|int(b[3])<<16|int(b[4])<<8|int(b[5]), 6
		default:
			// A partial length: the packet is data, and the scan ends
			// here, with the tag and the first chunk known.
			n = 1 << (l & 0x1f)
			return tag, b[2:min(len(b), 2+n)], nil, true
		}
	} else {
		tag = (b[0] >> 2) & 0x0f
		switch b[0] & 3 {
		case 0:
			n, hdr = int(b[1]), 2
		case 1:
			if len(b) < 3 {
				return 0, nil, nil, false
			}
			n, hdr = int(b[1])<<8|int(b[2]), 3
		case 2:
			if len(b) < 5 {
				return 0, nil, nil, false
			}
			n, hdr = int(b[1])<<24|int(b[2])<<16|int(b[3])<<8|int(b[4]), 5
		default:
			return tag, nil, nil, true
		}
	}
	if n < 0 || hdr+n > len(b) {
		// Cut short by the scan limit: the tag and what there is of the
		// body are still known.
		return tag, b[min(hdr, len(b)):], nil, true
	}
	return tag, b[hdr : hdr+n], b[hdr+n:], true
}

func parsePKESKHeader(b []byte) (PGPRecipient, bool) {
	var r PGPRecipient
	switch {
	case len(b) >= 10 && b[0] == 3:
		for _, c := range b[1:9] {
			r.KeyID = r.KeyID<<8 | uint64(c)
		}
		r.Algorithm = svpgp.PublicKeyAlgorithm(b[9])
		return r, true
	case len(b) >= 3 && b[0] == 6:
		n := int(b[1])
		if len(b) < 2+n+1 {
			return r, false
		}
		if n > 0 {
			r.Fingerprint = slices.Clone(b[3 : 2+n])
			switch {
			case b[2] == 4 && len(r.Fingerprint) == 20:
				for _, c := range r.Fingerprint[12:] {
					r.KeyID = r.KeyID<<8 | uint64(c)
				}
			case b[2] == 6 && len(r.Fingerprint) == 32:
				for _, c := range r.Fingerprint[:8] {
					r.KeyID = r.KeyID<<8 | uint64(c)
				}
			}
		}
		r.Algorithm = svpgp.PublicKeyAlgorithm(b[2+n])
		return r, true
	}
	return r, false
}

// lookupIssuers finds known keys for the signatures made by keys that
// were not given, leaving out those already in have.
func (in *inspector) lookupIssuers(results []svpgp.SignatureResult, have []*svpgp.Key, layer int) []*svpgp.Key {
	var out []*svpgp.Key
	seen := map[string]bool{}
	for _, k := range have {
		seen[string(k.Fingerprint())] = true
	}
	for _, r := range results {
		if !errors.Is(r.Err, svpgp.ErrUnknownSigner) {
			continue
		}
		var keys []*svpgp.Key
		var err error
		switch {
		case r.IssuerFingerprint != nil:
			keys, err = in.keys.PGPKeysByFingerprint(r.IssuerFingerprint)
		case r.IssuerKeyID != 0:
			keys, err = in.keys.PGPKeysByKeyID(r.IssuerKeyID)
		}
		if err != nil {
			in.warn(WarnKeys, "looking up an OpenPGP key: "+err.Error(), layer)
		}
		for _, k := range keys {
			if fp := string(k.Fingerprint()); !seen[fp] {
				seen[fp] = true
				out = append(out, k)
			}
		}
	}
	return out
}

// senderKeys are the known keys for the sender, to check signatures inside
// an encrypted message with.
func (in *inspector) senderKeys(l *Layer) []*svpgp.Key {
	if in.from == "" {
		return nil
	}
	keys, err := in.keys.PGPKeysByEmail(in.from)
	if err != nil {
		in.warn(WarnKeys, "looking up the sender's OpenPGP keys: "+err.Error(), l.ID)
	}
	return keys
}

func (in *inspector) verifyPGPDetached(l *Layer, data, sig []byte) {
	res, err := svpgp.Verify(bytes.NewReader(data), bytes.NewReader(sig), nil, in.now)
	if err != nil {
		l.Error = "the signature does not parse: " + err.Error()
		in.warn(WarnVerification, fmt.Sprintf("the signature in layer %d could not be read", l.ID), l.ID)
		return
	}
	if keys := in.lookupIssuers(res, nil, l.ID); len(keys) > 0 {
		if again, err := svpgp.Verify(bytes.NewReader(data), bytes.NewReader(sig), keys, in.now); err == nil {
			res = again
		}
	}
	for _, r := range res {
		in.addPGPSignature(l, r)
	}
}

// readPGP reads an OpenPGP message that is not encrypted (signed, or
// just literal), checking its signatures against the keys that made them.
func (in *inspector) readPGP(data []byte) (*svpgp.Message, error) {
	opts := svpgp.ReadOptions{Time: in.now, Limits: in.lim.pgp()}
	msg, err := svpgp.ReadMessage(bytes.NewReader(data), opts)
	if err != nil {
		return nil, err
	}
	if keys := in.lookupIssuers(msg.Signatures, nil, 0); len(keys) > 0 {
		opts.Keyring = keys
		if again, err := svpgp.ReadMessage(bytes.NewReader(data), opts); err == nil {
			msg = again
		}
	}
	return msg, nil
}

// decryptPGP decrypts an OpenPGP message through Keys, filling in the
// encryption layer, and returns the message and, if it was signed inside,
// the signature layer made for that.
func (in *inspector) decryptPGP(l *Layer, data []byte, c walkCtx) (*svpgp.Message, *Layer) {
	scan, err := scanPGP(data)
	if err != nil {
		l.Error = "the encrypted part is not OpenPGP: " + err.Error()
		in.warn(WarnDecryption, fmt.Sprintf("layer %d could not be read", l.ID), l.ID)
		return nil, nil
	}
	if !scan.encrypted {
		l.Error = "the encrypted part holds an OpenPGP message that is not encrypted"
		in.warn(WarnDecryption, fmt.Sprintf("layer %d is not encrypted", l.ID), l.ID)
		return nil, nil
	}
	for _, r := range scan.recipients {
		rr := &Recipient{Passphrase: r.Passphrase, Algorithm: r.Algorithm.String()}
		if r.Passphrase {
			rr.Algorithm = ""
		}
		if r.KeyID != 0 {
			rr.KeyID = fmt.Sprintf("%016X", r.KeyID)
		}
		if r.Fingerprint != nil {
			rr.Fingerprint = hexUpper(r.Fingerprint)
		}
		l.Encryption.Recipients = append(l.Encryption.Recipients, rr)
	}
	switch scan.seipd {
	case 1:
		l.Encryption.Integrity = "mdc"
	case 2:
		l.Encryption.Integrity = "aead"
		l.Encryption.Cipher = scan.cipher.String() + " " + scan.aead.String()
	}
	if scan.unprotected {
		// A Symmetrically Encrypted Data packet, from before 2001: no
		// modification detection code. svpgp refuses to decrypt it
		// unless asked.
		l.Encryption.Integrity = "none"
		in.warn(WarnNoIntegrity, fmt.Sprintf("layer %d is encrypted without integrity protection (no MDC): anyone could have changed it", l.ID), l.ID)
	}
	verify := in.senderKeys(l)
	req := &PGPDecryptRequest{Message: data, Recipients: scan.recipients, Verify: verify, Time: in.now}
	msg, err := in.keys.DecryptPGP(req)
	if err == nil && !msg.Encrypted {
		clear(msg.Body)
		err = svpgp.ErrNotEncrypted
	}
	if err != nil {
		l.Encryption.Error = err.Error()
		in.warn(WarnDecryption, fmt.Sprintf("layer %d was not decrypted: %v", l.ID, err), l.ID)
		return nil, nil
	}
	// A signature by a key the lookup knows but that was not given: ask
	// once more, with it.
	if extra := in.lookupIssuers(msg.Signatures, verify, l.ID); len(extra) > 0 {
		req.Verify = append(slices.Clone(verify), extra...)
		if again, err := in.keys.DecryptPGP(req); err == nil && again.Encrypted {
			clear(msg.Body)
			msg = again
		}
	}
	e := l.Encryption
	e.Decrypted = true
	if msg.DecryptionKey != nil {
		e.DecryptedWith = hexUpper(msg.DecryptionKey)
	} else {
		e.DecryptedWith = "passphrase"
	}
	e.Cipher = msg.Cipher.String()
	switch {
	case msg.SEIPDVersion == 2:
		e.Cipher += " " + msg.AEAD.String()
		e.Integrity = "aead"
	case msg.IntegrityProtected:
		e.Integrity = "mdc"
	default:
		e.Integrity = "none"
		in.warn(WarnNoIntegrity, fmt.Sprintf("layer %d is encrypted without integrity protection: anyone could have changed it", l.ID), l.ID)
	}
	for _, w := range msg.Warnings {
		code := WarnWeakCipher
		if strings.Contains(w, "integrity") {
			code = WarnNoIntegrity
		}
		in.warn(code, fmt.Sprintf("layer %d: %s", l.ID, w), l.ID)
	}
	var sigLayer *Layer
	if len(msg.Signatures) > 0 {
		sigLayer = in.newLayer(KindSignature, l.Format, c)
		if sigLayer != nil {
			sigLayer.Parent = l.ID
			for _, r := range msg.Signatures {
				in.addPGPSignature(sigLayer, r)
			}
		}
	}
	return msg, sigLayer
}

func (in *inspector) addPGPSignature(l *Layer, r svpgp.SignatureResult) {
	s := &Signature{Status: pgpStatus(r.Err), Verified: r.Key != nil}
	if r.Err != nil {
		s.Error = r.Err.Error()
		s.Problems = []string{s.Status}
	}
	if !r.CreatedAt.IsZero() {
		t := r.CreatedAt
		s.SignedAt = &t
	}
	if r.Hash != 0 {
		s.Hash = r.Hash.String()
	}
	if r.Algorithm != 0 {
		s.Algorithm = r.Algorithm.String()
	}
	switch {
	case r.IssuerFingerprint != nil:
		s.Issuer = hexUpper(r.IssuerFingerprint)
	case r.IssuerKeyID != 0:
		s.Issuer = fmt.Sprintf("%016X", r.IssuerKeyID)
	}
	key := r.Key
	if key != nil {
		s.Fingerprint = hexUpper(key.Fingerprint())
		s.SigningKey = hexUpper(r.SigningKey)
		s.UserIDs = key.UserIDs()
	}
	l.Signatures = append(l.Signatures, s)
	in.sigs = append(in.sigs, sigCheck{layer: l, sig: s, match: func(addr string) bool {
		return key != nil && keyHasAddress(key, addr)
	}})
	if s.Status != StatusValid {
		in.warn(WarnVerification, fmt.Sprintf("a signature in layer %d is not valid: %s", l.ID, s.Status), l.ID)
	}
}

func pgpStatus(err error) string {
	switch {
	case err == nil:
		return StatusValid
	case errors.Is(err, svpgp.ErrUnknownSigner):
		return StatusUnknownKey
	case errors.Is(err, svpgp.ErrBadSignature):
		return StatusBad
	case errors.Is(err, svpgp.ErrKeyExpired):
		return StatusExpiredKey
	case errors.Is(err, svpgp.ErrKeyRevoked):
		return StatusRevokedKey
	case errors.Is(err, svpgp.ErrKeyInvalid):
		return StatusInvalidKey
	case errors.Is(err, svpgp.ErrWeakAlgorithm):
		return StatusWeakAlgorithm
	case errors.Is(err, svpgp.ErrSignatureExpired):
		return StatusExpiredSignature
	case errors.Is(err, svpgp.ErrSignatureFuture):
		return StatusFutureSignature
	case errors.Is(err, svpgp.ErrNotIntendedRecipient):
		return StatusNotIntendedRecipient
	case errors.Is(err, svpgp.ErrSignatureMalformed), errors.Is(err, svpgp.ErrMalformed):
		return StatusMalformed
	case errors.Is(err, svpgp.ErrUnsupported):
		return StatusUnsupported
	}
	return StatusError
}

// armorBlock is an inline OpenPGP block in text.
type armorBlock struct {
	start, end int // its bytes in the text, BEGIN line to END line
	signed     bool
}

// findArmorBlocks finds BEGIN PGP MESSAGE and BEGIN PGP SIGNED MESSAGE
// blocks that start at the beginning of a line.
func findArmorBlocks(text []byte) []armorBlock {
	var out []armorBlock
	for i := 0; i < len(text) && len(out) < maxInlineBlocks; {
		line, next, _ := nextLine(text, i)
		trimmed := bytes.TrimRight(line, " \t")
		var endMarker string
		signed := false
		switch string(trimmed) {
		case "-----BEGIN PGP MESSAGE-----":
			endMarker = "-----END PGP MESSAGE-----"
		case "-----BEGIN PGP SIGNED MESSAGE-----":
			endMarker, signed = "-----END PGP SIGNATURE-----", true
		}
		if endMarker == "" {
			i = next
			continue
		}
		start := i
		j := next
		found := false
		for j < len(text) {
			l, nx, _ := nextLine(text, j)
			if string(bytes.TrimRight(l, " \t")) == endMarker {
				out = append(out, armorBlock{start: start, end: j + len(l), signed: signed})
				found = true
				j = nx
				break
			}
			j = nx
		}
		if !found {
			break
		}
		i = j
	}
	return out
}

// inlinePGP reads the inline OpenPGP blocks in a text part.
func (in *inspector) inlinePGP(p *Part, body []byte, info *PartInfo, c walkCtx) {
	blocks := findArmorBlocks(body)
	if len(blocks) == 0 {
		return
	}
	outside := len(blocks) > 1
	prev := 0
	for _, b := range blocks {
		if len(bytes.TrimSpace(body[prev:b.start])) > 0 {
			outside = true
		}
		prev = b.end
	}
	if len(bytes.TrimSpace(body[prev:])) > 0 {
		outside = true
	}
	if outside {
		in.warn(WarnUnprotectedText, where(c)+" has text outside its OpenPGP block, which the block does not protect", 0)
	} else {
		info.container = true
	}
	bc := c
	bc.whole = c.whole && !outside
	charset := p.Params["charset"]
	for _, b := range blocks {
		block := body[b.start:b.end]
		var scan *pgpScan
		if !b.signed {
			var err error
			if scan, err = scanPGP(block); err != nil {
				in.warn(WarnStructure, where(c)+": an OpenPGP block that does not parse: "+err.Error(), 0)
				continue
			}
		}
		if b.signed || !scan.encrypted {
			msg, err := in.readPGP(block)
			if err == nil && len(msg.Signatures) == 0 {
				// Armored, but neither signed nor encrypted: plain text
				// as far as anyone can tell.
				in.warn(WarnUnprotectedText, where(c)+" holds an OpenPGP block that is neither signed nor encrypted", 0)
				info.container = false
				continue
			}
			l := in.newLayer(KindSignature, FormatPGPInline, bc)
			if l == nil {
				return
			}
			if err != nil {
				l.Error = "the OpenPGP message does not parse: " + err.Error()
				in.warn(WarnVerification, fmt.Sprintf("the signature in layer %d could not be read", l.ID), l.ID)
				info.container = false
				continue
			}
			for _, r := range msg.Signatures {
				in.addPGPSignature(l, r)
			}
			in.inlineContent(l, bc.inside(l, true), msg.Body, charset)
			continue
		}
		l := in.newLayer(KindEncryption, FormatPGPInline, bc)
		if l == nil {
			return
		}
		l.Encryption = &Encryption{Recipients: []*Recipient{}}
		msg, sigLayer := in.decryptPGP(l, block, bc)
		if msg == nil {
			continue
		}
		ic := bc.inside(l, false)
		if sigLayer != nil {
			ic.signedBy = append(slices.Clone(ic.signedBy), sigLayer.ID)
		}
		in.inlineContent(l, ic, msg.Body, charset)
		clear(msg.Body)
	}
}

// inlineContent records the plain text an inline block held, as a part
// of the layer's content.
func (in *inspector) inlineContent(l *Layer, c walkCtx, body []byte, charset string) {
	raw := slices.Clone(body)
	in.setContent(l, c, raw)
	info := &PartInfo{Tree: c.tree, Part: "", ContentType: "text/plain", Charset: charset, Size: len(raw), SignedBy: c.signedBy, EncryptedBy: c.encryptedBy}
	text, ok, problem := decodeText(charset, raw)
	if problem != "" {
		info.Problems = append(info.Problems, problem)
	}
	if ok {
		info.Text = normalizeNewlines(text)
	}
	in.r.Parts = append(in.r.Parts, info)
}
