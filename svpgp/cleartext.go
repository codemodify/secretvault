package svpgp

import (
	"bufio"
	"fmt"
	"io"
	"strings"
)

// The cleartext signature framework (RFC 9580, section 7): readable text
// followed by an armored signature.

// readCleartext reads a cleartext signed message after its BEGIN line and
// verifies its signatures.
func (m *msgReader) readCleartext(br *bufio.Reader) (*Message, error) {
	// Only well-formed Hash headers may come before the text; anything
	// else could make people believe unsigned text was signed.
	for {
		line, err := readArmorLine(br)
		if err != nil {
			return nil, truncatedArmor(err)
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		key, value, ok := strings.Cut(line, ": ")
		if !ok || key != "Hash" {
			return nil, malformed("cleartext signed message with the header %q (only Hash is allowed)", line)
		}
		for _, name := range strings.Split(value, ",") {
			if _, ok := hashByName(strings.TrimSpace(name)); !ok {
				return nil, malformed("cleartext signed message with a malformed Hash header %q", line)
			}
		}
	}
	var lines []string
	size := int64(0)
	for {
		line, err := readArmorLine(br)
		if err == io.EOF {
			return nil, malformed("cleartext signed message without its signature")
		}
		if err != nil {
			return nil, err
		}
		if strings.HasPrefix(line, "-") {
			if typ, ok := armorLine(line, "BEGIN"); ok {
				if typ != BlockSignature {
					return nil, malformed("cleartext signed message followed by %q", typ)
				}
				break
			}
			if !strings.HasPrefix(line, "- ") {
				return nil, malformed("cleartext line starting with an unescaped dash: %q", line)
			}
			line = line[2:]
		}
		line = strings.TrimRight(line, " \t\r")
		if size += int64(len(line)) + 2; size > m.lim.MaxMessageSize {
			return nil, limit("a message over %d bytes", m.lim.MaxMessageSize)
		}
		lines = append(lines, line)
	}
	block, err := armorBody(br, BlockSignature)
	if err != nil {
		return nil, err
	}
	var sigs []*signature
	var bad []SignatureResult
	pr := newPacketReader(block.Body)
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
			if len(sigs)+len(bad) >= maxDetachedSigs {
				return nil, limit("more than %d signatures", maxDetachedSigs)
			}
			data, err := body.readAll(maxPacketSize)
			if err != nil {
				return nil, err
			}
			s, err := parseSignature(data, 0)
			if err != nil {
				bad = append(bad, malformedResult(err))
				continue
			}
			sigs = append(sigs, s)
		case ptMarker, ptPadding:
		default:
			if tag.critical() {
				return nil, malformed("a %v packet in a cleartext signature", tag)
			}
		}
	}
	if len(sigs)+len(bad) == 0 {
		return nil, ErrNoSignature
	}
	signed := []byte(strings.Join(lines, "\r\n"))
	msg := m.msg
	msg.Cleartext = true
	msg.Format = 't'
	msg.Body = []byte(strings.Join(lines, "\n"))
	ctx := &verifyContext{keyring: m.opts.Keyring, now: m.now}
	for _, s := range sigs {
		if s.typ != SigText {
			r := newResult(s)
			r.Err = fmt.Errorf("%w: a %v signature in a cleartext signed message", ErrSignatureMalformed, s.typ)
			msg.Signatures = append(msg.Signatures, r)
			continue
		}
		c := newSigChecker(s)
		c.Write(signed)
		msg.Signatures = append(msg.Signatures, c.result(ctx))
	}
	msg.Signatures = append(msg.Signatures, bad...)
	return msg, nil
}
