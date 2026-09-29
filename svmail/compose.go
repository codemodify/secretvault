package svmail

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"mime"
	"slices"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svpgp"
)

// Building outgoing messages: PGP/MIME (RFC 3156) and S/MIME (RFC 8551),
// signed, encrypted or both, with protected header fields (RFC 9788) when
// asked. Each function takes a whole message as a mail client composes it
// (header fields, then a MIME body) and returns one ready to send, with
// CR LF line endings. The protected part is first made 7-bit safe, since
// a signature must survive transport byte for byte; header fields are
// copied as they are, so 8-bit ones (RFC 6532) need an 8-bit clean
// transport. Bcc and Resent-Bcc are removed: give those recipients to the
// transport. An encrypted message names every recipient's key, so
// encrypting to a Bcc recipient tells the others: send them a copy of
// their own.

// ComposeOptions choose how outgoing messages are built. The zero value
// is fine.
type ComposeOptions struct {
	// ProtectHeaders copies the message's header fields into the signed
	// or encrypted part (RFC 9788), so the signature covers them or the
	// encryption hides them. An encrypted message's outer Subject becomes
	// "[...]", and HP-Outer fields inside record what is outside. Bcc is
	// never copied inside.
	ProtectHeaders bool

	// Time is the signatures' creation time; zero means now.
	Time time.Time

	// PGPHash is the OpenPGP signature hash; zero means svpgp's default.
	PGPHash svpgp.HashAlgorithm

	// SMIMEHash and SMIMEPSS choose the S/MIME signature: zero means
	// SHA-256 (or the curve's hash, or SHA-512 for Ed25519), and PSS
	// signs RSA keys with RSA-PSS.
	SMIMEHash crypto.Hash
	SMIMEPSS  bool

	// SMIMELegacy encrypts S/MIME as EnvelopedData with AES-256-CBC, for
	// clients that do not read AuthEnvelopedData. It has no integrity
	// protection.
	SMIMELegacy bool
}

func (o *ComposeOptions) orZero() ComposeOptions {
	if o == nil {
		return ComposeOptions{}
	}
	return *o
}

// outgoing is a message split for protecting: the fields that stay
// outside, and the MIME entity to sign or encrypt.
type outgoing struct {
	outer []Field
	inner []byte
}

// Fields never copied into a protected part: they are added in transit.
var neverProtect = []string{"received", "return-path", "dkim-signature", "arc-seal", "arc-message-signature",
	"arc-authentication-results", "authentication-results", "delivered-to", "x-original-to"}

// Fields dropped altogether: Bcc tells every recipient who else got the
// message. Give Bcc recipients to the transport instead.
var dropped = []string{"bcc", "resent-bcc"}

// prepare splits a message and builds the entity to protect. hp is
// "clear" for signing and "cipher" for encrypting.
func prepare(msg []byte, protect bool, hp string) (*outgoing, error) {
	root, err := ParseMessage(msg, nil)
	if err != nil {
		return nil, err
	}
	if len(root.Header) == 0 {
		return nil, malformed("no header")
	}
	var outer, content []Field
	for _, f := range root.Header {
		switch n := strings.ToLower(f.Name); {
		case strings.HasPrefix(n, "content-"):
			content = append(content, f)
		case n == "mime-version", slices.Contains(dropped, n):
		default:
			outer = append(outer, f)
		}
	}
	root.Header = content
	var entity bytes.Buffer
	if err := writeEntity(&entity, root, func(ct string) string {
		if !protect {
			return ct
		}
		return withParam(ct, "hp", hp)
	}); err != nil {
		return nil, err
	}
	out := &outgoing{outer: outer}
	if protect {
		var hdr bytes.Buffer
		for _, f := range outer {
			if isNeverProtected(f.Name) {
				continue
			}
			hdr.Write(trimLines(canonical(ensureEOL(f.Raw))))
		}
		if hp == "cipher" {
			for i, f := range outer {
				if strings.EqualFold(f.Name, "Subject") {
					outer[i] = newField("Subject", "[...]")
				}
			}
			for _, f := range outer {
				if isNeverProtected(f.Name) {
					continue
				}
				hdr.Write(newField("HP-Outer", f.Name+": "+f.Value).Raw)
			}
		}
		out.inner = append(hdr.Bytes(), entity.Bytes()...)
	} else {
		out.inner = entity.Bytes()
	}
	return out, nil
}

func isNeverProtected(name string) bool {
	n := strings.ToLower(name)
	for _, x := range neverProtect {
		if n == x || strings.HasPrefix(n, "list-") {
			return true
		}
	}
	return false
}

func ensureEOL(b []byte) []byte {
	if len(b) > 0 && b[len(b)-1] == '\n' {
		return b
	}
	return append(append([]byte{}, b...), '\r', '\n')
}

// newField makes a header field, folding nothing: values here are short.
func newField(name, value string) Field {
	return Field{Name: name, Value: value, Raw: []byte(name + ": " + value + "\r\n")}
}

// withParam adds a parameter to a Content-Type value.
func withParam(ct, name, value string) string {
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		mt, params = "text/plain", map[string]string{"charset": "us-ascii"}
	}
	params[name] = value
	return mime.FormatMediaType(mt, params)
}

// writeEntity writes a part as a 7-bit safe entity with CR LF line
// endings. Leaves whose bodies are 8-bit, have long lines, trailing white
// space or lines starting "From " are re-encoded (quoted-printable for
// text, base64 otherwise); a multipart holding such a leaf is rewritten
// part by part; everything else is copied as it is. Signed and encrypted
// entities are never changed inside, since that would break them. ctype,
// for the top entity, may rewrite its Content-Type value; its header
// fields are written from p.Header, whose Raw bytes may not be all of the
// entity's header.
func writeEntity(w *bytes.Buffer, p *Part, ctype func(string) string) error {
	if ctype == nil && !needsChange(p) {
		w.Write(canonical(p.Raw))
		return nil
	}
	ct := p.Header.Get("Content-Type")
	if ct == "" {
		ct = "text/plain; charset=us-ascii"
		if !isASCII(p.Body) {
			ct = "text/plain; charset=utf-8"
		}
	}
	if ctype != nil {
		ct = ctype(ct)
	}
	rewrite := strings.HasPrefix(p.MediaType, "multipart/") && len(p.Parts) > 0 && !sealed(p) && needsChange(p)
	body, newCTE := p.Body, ""
	if !strings.HasPrefix(p.MediaType, "multipart/") && !sealed(p) && needsEncoding(p.Body) {
		if p.MediaType == "message/rfc822" {
			return errors.New("svmail: an attached message with 8-bit content cannot be protected; attach it as a file")
		}
		decoded, err := p.Decoded()
		if err != nil {
			return fmt.Errorf("svmail: a part cannot be re-encoded: %w", err)
		}
		if strings.HasPrefix(p.MediaType, "text/") {
			body, newCTE = encodeQP(decoded), "quoted-printable"
		} else {
			body, newCTE = encodeBase64Lines(decoded), "base64"
		}
	}
	wroteCT := false
	for _, f := range p.Header {
		switch {
		case strings.EqualFold(f.Name, "Content-Type"):
			if !wroteCT {
				w.WriteString("Content-Type: " + ct + "\r\n")
				wroteCT = true
			}
		case strings.EqualFold(f.Name, "Content-Transfer-Encoding") && newCTE != "":
			w.WriteString("Content-Transfer-Encoding: " + newCTE + "\r\n")
			newCTE = ""
		case strings.EqualFold(f.Name, "MIME-Version"):
		default:
			w.Write(trimLines(canonical(ensureEOL(f.Raw))))
		}
	}
	if !wroteCT {
		w.WriteString("Content-Type: " + ct + "\r\n")
	}
	if newCTE != "" {
		w.WriteString("Content-Transfer-Encoding: " + newCTE + "\r\n")
	}
	w.WriteString("\r\n")
	if !rewrite {
		w.Write(canonical(body))
		return nil
	}
	boundary := p.Params["boundary"]
	for _, child := range p.Parts {
		w.WriteString("--" + boundary + "\r\n")
		if err := writeEntity(w, child, nil); err != nil {
			return err
		}
		w.WriteString("\r\n")
	}
	w.WriteString("--" + boundary + "--\r\n")
	return nil
}

// sealed says whether an entity is signed or encrypted as a whole, and so
// must travel exactly as it is.
func sealed(p *Part) bool {
	switch p.MediaType {
	case "multipart/signed", "multipart/encrypted", "application/pkcs7-mime", "application/x-pkcs7-mime":
		return true
	}
	return false
}

// needsChange says whether writeEntity has to change something in the
// entity: a body (or, in a multipart, a preamble or epilogue) or a header
// line that would not survive transport.
func needsChange(p *Part) bool {
	if sealed(p) {
		return false
	}
	for _, f := range p.Header {
		if headerNeedsChange(f.Raw) {
			return true
		}
	}
	if strings.HasPrefix(p.MediaType, "multipart/") && len(p.Parts) > 0 {
		for _, c := range p.Parts {
			if needsChange(c) {
				return true
			}
		}
	}
	return needsEncoding(p.Body)
}

// headerNeedsChange says whether a header field has a line with trailing
// white space, which transports may strip. 8-bit header fields (RFC 6532)
// are left as they are: they need an 8-bit clean transport.
func headerNeedsChange(raw []byte) bool {
	for i := 0; i < len(raw); {
		line, next, _ := nextLine(raw, i)
		if n := len(line); n > 0 && (line[n-1] == ' ' || line[n-1] == '\t') {
			return true
		}
		i = next
	}
	return false
}

// trimLines removes white space at the ends of lines.
func trimLines(b []byte) []byte {
	var out []byte
	for i := 0; i < len(b); {
		line, next, eol := nextLine(b, i)
		out = append(out, bytes.TrimRight(line, " \t")...)
		if eol > 0 {
			out = append(out, '\r', '\n')
		}
		i = next
	}
	return out
}

func isASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return false
		}
	}
	return true
}

// needsEncoding says whether a body would not survive transport as it is:
// 8-bit bytes, NULs, bare CRs, lines over 998 bytes, trailing white space
// (which some transports strip), or lines starting "From " (which mbox
// mangles).
func needsEncoding(b []byte) bool {
	for i := 0; i < len(b); {
		line, next, _ := nextLine(b, i)
		if len(line) > 998 || bytes.HasPrefix(line, []byte("From ")) {
			return true
		}
		if n := len(line); n > 0 && (line[n-1] == ' ' || line[n-1] == '\t') {
			return true
		}
		for _, c := range line {
			if c >= 0x80 || c == 0 || c == '\r' {
				return true
			}
		}
		i = next
	}
	return false
}

// encodeQP encodes text as quoted-printable (RFC 2045, section 6.7), line
// by line, with CR LF line endings.
func encodeQP(b []byte) []byte {
	var out bytes.Buffer
	for i := 0; i < len(b); {
		line, next, eol := nextLine(b, i)
		i = next
		var enc []byte
		for j, c := range line {
			switch {
			case c == '=' || c >= 0x7f || (c < ' ' && c != '\t'),
				(c == ' ' || c == '\t') && j == len(line)-1,
				j == 0 && c == 'F' && bytes.HasPrefix(line, []byte("From ")),
				j == 0 && c == '.' && len(line) == 1:
				enc = fmt.Appendf(enc, "=%02X", c)
			default:
				enc = append(enc, c)
			}
		}
		// Soft line breaks keep lines to 76 characters, never splitting
		// an =XX.
		for len(enc) > 76 {
			cut := 75
			if enc[cut-1] == '=' {
				cut--
			} else if enc[cut-2] == '=' {
				cut -= 2
			}
			out.Write(enc[:cut])
			out.WriteString("=\r\n")
			enc = enc[cut:]
		}
		out.Write(enc)
		if eol > 0 {
			out.WriteString("\r\n")
		}
	}
	return out.Bytes()
}

// encodeBase64Lines encodes data as base64 in lines of 76 characters.
func encodeBase64Lines(b []byte) []byte {
	enc := base64.StdEncoding.EncodeToString(b)
	var out bytes.Buffer
	for len(enc) > 76 {
		out.WriteString(enc[:76] + "\r\n")
		enc = enc[76:]
	}
	if enc != "" {
		out.WriteString(enc + "\r\n")
	}
	return out.Bytes()
}

func newBoundary() string {
	b := make([]byte, 16)
	rand.Read(b)
	return "sv-" + hex.EncodeToString(b)
}

// assemble writes the outer header fields, the MIME fields and the body.
func assemble(outer []Field, contentFields []string, body []byte) []byte {
	var out bytes.Buffer
	for _, f := range outer {
		out.Write(canonical(ensureEOL(f.Raw)))
	}
	out.WriteString("MIME-Version: 1.0\r\n")
	for _, f := range contentFields {
		out.WriteString(f + "\r\n")
	}
	out.WriteString("\r\n")
	out.Write(body)
	return out.Bytes()
}

// multipartSignedBody is the body of a multipart/signed: the signed
// entity exactly, then the signature part.
func multipartSignedBody(boundary string, inner []byte, sigFields []string, sig []byte) []byte {
	var b bytes.Buffer
	b.WriteString("--" + boundary + "\r\n")
	b.Write(inner)
	// The line break before the boundary belongs to the boundary: the
	// signed bytes are inner exactly.
	b.WriteString("\r\n--" + boundary + "\r\n")
	for _, f := range sigFields {
		b.WriteString(f + "\r\n")
	}
	b.WriteString("\r\n")
	b.Write(sig)
	if len(sig) > 0 && sig[len(sig)-1] != '\n' {
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n--" + boundary + "--\r\n")
	return b.Bytes()
}

// signPGPEntity signs inner and returns the multipart/signed entity's
// Content-Type and body.
func signPGPEntity(inner []byte, signer *svpgp.Key, o ComposeOptions) (string, []byte, error) {
	var sig bytes.Buffer
	if err := svpgp.Sign(&sig, bytes.NewReader(inner), signer, svpgp.SignOptions{Mode: svpgp.SignDetached, Armor: true, Hash: o.PGPHash, Time: o.Time}); err != nil {
		return "", nil, err
	}
	// Check the signature before sending it, and learn its hash for the
	// micalg parameter.
	at := o.Time
	if at.IsZero() {
		at = time.Now()
	}
	res, err := svpgp.Verify(bytes.NewReader(inner), bytes.NewReader(sig.Bytes()), []*svpgp.Key{signer.Public()}, at)
	if err != nil || len(res) != 1 || !res[0].Valid {
		return "", nil, fmt.Errorf("svmail: the new signature does not verify: %v", errors.Join(err, firstErr(res)))
	}
	boundary := newBoundary()
	ct := mime.FormatMediaType("multipart/signed", map[string]string{
		"micalg":   "pgp-" + strings.ToLower(res[0].Hash.String()),
		"protocol": "application/pgp-signature",
		"boundary": boundary,
	})
	body := multipartSignedBody(boundary, inner, []string{
		`Content-Type: application/pgp-signature; name="OpenPGP_signature.asc"`,
		"Content-Description: OpenPGP digital signature",
		`Content-Disposition: attachment; filename="OpenPGP_signature.asc"`,
	}, canonical(sig.Bytes()))
	return ct, body, nil
}

func firstErr(res []svpgp.SignatureResult) error {
	for _, r := range res {
		if r.Err != nil {
			return r.Err
		}
	}
	return nil
}

// SignPGPMIME signs a message as PGP/MIME (RFC 3156): multipart/signed
// with a detached OpenPGP signature over its body (and, with
// ProtectHeaders, its header fields).
func SignPGPMIME(msg []byte, signer *svpgp.Key, opts *ComposeOptions) ([]byte, error) {
	o := opts.orZero()
	out, err := prepare(msg, o.ProtectHeaders, "clear")
	if err != nil {
		return nil, err
	}
	ct, body, err := signPGPEntity(out.inner, signer, o)
	if err != nil {
		return nil, err
	}
	return assemble(out.outer, []string{"Content-Type: " + ct}, body), nil
}

// EncryptPGPMIME encrypts a message as PGP/MIME (RFC 3156):
// multipart/encrypted holding an OpenPGP message to the recipients'
// keys. With a signer it is signed too, inside the encryption (RFC 3156,
// section 6.2). Include the sender's own key among the recipients to be
// able to read it later.
func EncryptPGPMIME(msg []byte, recipients []*svpgp.Key, signer *svpgp.Key, opts *ComposeOptions) ([]byte, error) {
	o := opts.orZero()
	out, err := prepare(msg, o.ProtectHeaders, "cipher")
	if err != nil {
		return nil, err
	}
	var ct bytes.Buffer
	w, err := svpgp.Encrypt(&ct, recipients, svpgp.EncryptOptions{Signer: signer, Armor: true, Time: o.Time, Hash: o.PGPHash})
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(out.inner); err != nil {
		return nil, err
	}
	if err := w.Close(); err != nil {
		return nil, err
	}
	boundary := newBoundary()
	var body bytes.Buffer
	body.WriteString("This is an OpenPGP/MIME encrypted message (RFC 4880 and 3156)\r\n")
	body.WriteString("--" + boundary + "\r\n")
	body.WriteString("Content-Type: application/pgp-encrypted\r\nContent-Description: PGP/MIME version identification\r\n\r\nVersion: 1\r\n\r\n")
	body.WriteString("--" + boundary + "\r\n")
	body.WriteString("Content-Type: application/octet-stream; name=\"encrypted.asc\"\r\nContent-Description: OpenPGP encrypted message\r\nContent-Disposition: inline; filename=\"encrypted.asc\"\r\n\r\n")
	body.Write(canonical(ct.Bytes()))
	body.WriteString("\r\n--" + boundary + "--\r\n")
	ctype := mime.FormatMediaType("multipart/encrypted", map[string]string{"protocol": "application/pgp-encrypted", "boundary": boundary})
	return assemble(out.outer, []string{"Content-Type: " + ctype}, body.Bytes()), nil
}

// smimeMicalg names a hash as S/MIME's micalg parameter does (RFC 8551,
// section 3.5.3.2).
func smimeMicalg(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "sha-256"
	case crypto.SHA384:
		return "sha-384"
	case crypto.SHA512:
		return "sha-512"
	case crypto.SHA224:
		return "sha-224"
	}
	return "unknown"
}

func signSMIMEEntity(inner []byte, key crypto.Signer, chain []*x509.Certificate, o ComposeOptions) (string, []byte, error) {
	der, err := svcms.Sign(inner, key, chain, svcms.SignOptions{Hash: o.SMIMEHash, PSS: o.SMIMEPSS, Time: o.Time})
	if err != nil {
		return "", nil, err
	}
	sd, err := svcms.ParseSignedData(der, nil)
	if err != nil {
		return "", nil, err
	}
	res, err := sd.Verify(svcms.VerifyOptions{Content: inner})
	if err != nil || len(res) != 1 || res[0].SignatureErr != nil {
		return "", nil, fmt.Errorf("svmail: the new signature does not verify: %v", err)
	}
	boundary := newBoundary()
	ct := mime.FormatMediaType("multipart/signed", map[string]string{
		"protocol": "application/pkcs7-signature",
		"micalg":   smimeMicalg(res[0].Hash),
		"boundary": boundary,
	})
	body := multipartSignedBody(boundary, inner, []string{
		`Content-Type: application/pkcs7-signature; name="smime.p7s"`,
		"Content-Transfer-Encoding: base64",
		`Content-Disposition: attachment; filename="smime.p7s"`,
		"Content-Description: S/MIME Cryptographic Signature",
	}, encodeBase64Lines(der))
	return ct, body, nil
}

// SignSMIME signs a message as S/MIME (RFC 8551): multipart/signed with a
// detached CMS signature by key, whose certificate is chain[0]; the rest
// of the chain goes in the signature. The key may live elsewhere.
func SignSMIME(msg []byte, key crypto.Signer, chain []*x509.Certificate, opts *ComposeOptions) ([]byte, error) {
	o := opts.orZero()
	out, err := prepare(msg, o.ProtectHeaders, "clear")
	if err != nil {
		return nil, err
	}
	ct, body, err := signSMIMEEntity(out.inner, key, chain, o)
	if err != nil {
		return nil, err
	}
	return assemble(out.outer, []string{"Content-Type: " + ct}, body), nil
}

// EncryptSMIME encrypts a message as S/MIME (RFC 8551):
// application/pkcs7-mime holding AuthEnvelopedData (AES-256-GCM), or with
// SMIMELegacy EnvelopedData (AES-256-CBC), to the recipients'
// certificates. With a key it is signed first, as multipart/signed inside
// the encryption. Include the sender's own certificate among the
// recipients to be able to read it later.
func EncryptSMIME(msg []byte, recipients []*x509.Certificate, key crypto.Signer, chain []*x509.Certificate, opts *ComposeOptions) ([]byte, error) {
	o := opts.orZero()
	out, err := prepare(msg, o.ProtectHeaders, "cipher")
	if err != nil {
		return nil, err
	}
	content := out.inner
	if key != nil {
		ct, body, err := signSMIMEEntity(out.inner, key, chain, o)
		if err != nil {
			return nil, err
		}
		content = append([]byte("Content-Type: "+ct+"\r\n\r\n"), body...)
	}
	der, err := svcms.Encrypt(content, recipients, svcms.EncryptOptions{Legacy: o.SMIMELegacy})
	if err != nil {
		return nil, err
	}
	typ := "authEnveloped-data"
	if o.SMIMELegacy {
		typ = "enveloped-data"
	}
	return assemble(out.outer, []string{
		"Content-Type: " + mime.FormatMediaType("application/pkcs7-mime", map[string]string{"smime-type": typ, "name": "smime.p7m"}),
		"Content-Transfer-Encoding: base64",
		`Content-Disposition: attachment; filename="smime.p7m"`,
		"Content-Description: S/MIME Encrypted Message",
	}, encodeBase64Lines(der)), nil
}
