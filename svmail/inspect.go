package svmail

import (
	"fmt"
	"mime"
	"net/mail"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Options configure InspectWith.
type Options struct {
	// Time is when signatures and certificates are judged; zero means
	// now.
	Time time.Time
	// Limits bound what the message may use; nil means DefaultLimits.
	Limits *Limits
}

// Inspect takes a raw message apart: it recognises PGP/MIME (RFC 3156),
// inline OpenPGP and S/MIME (RFC 8551: detached, opaque, enveloped and
// auth-enveloped), however they nest, verifies every signature and
// decrypts every encrypted part it has a key for, reads protected header
// fields (RFC 9788 and Memory Hole) and Autocrypt headers, and reports it
// all. The error is only for input that cannot be read as a message.
func Inspect(raw []byte, keys Keys) (*Report, error) {
	return InspectWith(raw, keys, Options{})
}

// InspectWith is Inspect with options.
func InspectWith(raw []byte, keys Keys, opts Options) (*Report, error) {
	lim := opts.Limits.withDefaults()
	if len(raw) > lim.MaxSize {
		return nil, limit("a message of %d bytes (the limit is %d)", len(raw), lim.MaxSize)
	}
	if keys == nil {
		keys = NoKeys{}
	}
	now := opts.Time
	if now.IsZero() {
		now = time.Now()
	}
	in := &inspector{keys: keys, now: now, lim: lim, p: &parser{lim: lim}, r: &Report{Parts: []*PartInfo{}}}
	root, err := in.p.entity(raw, 0, "text/plain")
	if err != nil {
		return nil, err
	}
	if len(root.Header) == 0 {
		return nil, malformed("no header")
	}
	in.outer = root.Header
	in.r.Headers = decodeHeaders(root.Header)
	in.from = in.r.Headers.FromAddress
	in.autocrypt(root.Header)
	in.walk(root, walkCtx{whole: true})
	in.finish()
	return in.r, nil
}

type inspector struct {
	keys  Keys
	now   time.Time
	lim   Limits
	p     *parser
	r     *Report
	outer Header
	from  string // the outer From address

	// The cryptographic payload: the first part below the layers that
	// cover the whole message, where protected header fields live.
	payload    *Part
	payloadCtx walkCtx

	sigs []sigCheck // signatures to compare with the sender
}

// sigCheck is a signature and how to tell whether its signer is an
// address.
type sigCheck struct {
	layer *Layer
	sig   *Signature
	match func(addr string) bool
}

// walkCtx is where a part sits.
type walkCtx struct {
	tree        int    // 0, or the layer whose content holds this part
	path        string // the part's path in its tree
	whole       bool   // the part is all of the message's content
	parent      int    // the innermost layer holding this part
	signedBy    []int
	encryptedBy []int
	depth       int
}

func (c walkCtx) child(i int, whole bool) walkCtx {
	n := strconv.Itoa(i + 1)
	if c.path != "" {
		n = c.path + "." + n
	}
	c.path, c.whole, c.depth = n, whole, c.depth+1
	return c
}

// inside is the context of a layer's content: a new tree.
func (c walkCtx) inside(l *Layer, signed bool) walkCtx {
	out := c
	out.tree, out.path, out.parent, out.depth = l.ID, "", l.ID, c.depth+1
	if signed {
		out.signedBy = append(slices.Clone(c.signedBy), l.ID)
	} else {
		out.encryptedBy = append(slices.Clone(c.encryptedBy), l.ID)
	}
	return out
}

func (in *inspector) warn(code, msg string, layer int) {
	for _, w := range in.r.Warnings {
		if w.Code == code && w.Message == msg && w.Layer == layer {
			return
		}
	}
	in.r.Warnings = append(in.r.Warnings, Warning{Code: code, Message: msg, Layer: layer})
}

func where(c walkCtx) string {
	p := c.path
	if p == "" {
		p = "the whole message"
	} else {
		p = "part " + p
	}
	if c.tree != 0 {
		p += fmt.Sprintf(" of layer %d's content", c.tree)
	}
	return p
}

// newLayer adds a layer, or returns nil past MaxLayers.
func (in *inspector) newLayer(kind, format string, c walkCtx) *Layer {
	if len(in.r.Layers) >= in.lim.MaxLayers {
		in.warn(WarnStructure, fmt.Sprintf("more than %d signature and encryption layers: %s was not checked", in.lim.MaxLayers, where(c)), 0)
		return nil
	}
	l := &Layer{ID: len(in.r.Layers) + 1, Parent: c.parent, Kind: kind, Format: format, Part: c.path, Covers: "part"}
	if c.whole {
		l.Covers = "message"
	}
	in.r.Layers = append(in.r.Layers, l)
	return l
}

func (in *inspector) layer(id int) *Layer { return in.r.Layers[id-1] }

// setContent records a layer's content, when the layer covers the whole
// message; the innermost such layer wins, as it comes last.
func (in *inspector) setContent(l *Layer, c walkCtx, raw []byte) {
	if c.whole {
		in.r.Content = &Content{Layer: l.ID, Raw: raw}
	}
}

func (in *inspector) walk(p *Part, c walkCtx) {
	if c.depth > in.lim.MaxDepth {
		in.warn(WarnStructure, fmt.Sprintf("parts nested more than %d deep were not read", in.lim.MaxDepth), 0)
		return
	}
	wrapper := in.isWrapper(p)
	if c.whole && len(c.signedBy)+len(c.encryptedBy) > 0 && in.payload == nil && !wrapper {
		in.payload, in.payloadCtx = p, c
	}
	switch {
	case wrapper && p.MediaType == "multipart/signed":
		in.multipartSigned(p, c)
	case wrapper && p.MediaType == "multipart/encrypted":
		in.multipartEncrypted(p, c)
	case wrapper:
		in.pkcs7Mime(p, c)
	case strings.HasPrefix(p.MediaType, "multipart/"):
		for _, prob := range p.Problems {
			in.warn(WarnStructure, where(c)+": "+prob, 0)
		}
		for i, child := range p.Parts {
			// A multipart of one part adds nothing around it.
			in.walk(child, c.child(i, c.whole && len(p.Parts) == 1))
		}
	default:
		in.leaf(p, c)
	}
}

// isWrapper says whether a part is a cryptographic layer this package
// reads.
func (in *inspector) isWrapper(p *Part) bool {
	switch p.MediaType {
	case "multipart/signed":
		return len(p.Parts) == 2 && signedProtocol(p) != ""
	case "multipart/encrypted":
		return len(p.Parts) == 2 && strings.EqualFold(p.Params["protocol"], "application/pgp-encrypted")
	case "application/pkcs7-mime", "application/x-pkcs7-mime":
		return true
	case "application/octet-stream":
		return strings.HasSuffix(strings.ToLower(filename(p)), ".p7m")
	}
	return false
}

// signedProtocol is the kind of a multipart/signed: "pgp", "smime" or ""
// for one this package does not read. The protocol parameter decides;
// without one, the second part's type does.
func signedProtocol(p *Part) string {
	proto := strings.ToLower(p.Params["protocol"])
	if proto == "" && len(p.Parts) == 2 {
		proto = p.Parts[1].MediaType
	}
	switch proto {
	case "application/pgp-signature":
		return "pgp"
	case "application/pkcs7-signature", "application/x-pkcs7-signature":
		return "smime"
	}
	return ""
}

func (in *inspector) multipartSigned(p *Part, c walkCtx) {
	kind := signedProtocol(p)
	format := FormatPGPMIME
	if kind == "smime" {
		format = FormatSMIMEDetached
	}
	l := in.newLayer(KindSignature, format, c)
	signed, sigPart := p.Parts[0], p.Parts[1]
	if l != nil {
		wantType := map[string][]string{"pgp": {"application/pgp-signature"}, "smime": {"application/pkcs7-signature", "application/x-pkcs7-signature"}}[kind]
		if !slices.Contains(wantType, sigPart.MediaType) {
			in.warn(WarnStructure, fmt.Sprintf("the signature part of %s is %s", where(c), sigPart.MediaType), l.ID)
		}
		sig, err := sigPart.Decoded()
		if err != nil {
			l.Error = "the signature part does not decode: " + err.Error()
			in.warn(WarnVerification, fmt.Sprintf("the signature in layer %d could not be read", l.ID), l.ID)
		} else {
			data := canonical(signed.Raw)
			if kind == "pgp" {
				in.verifyPGPDetached(l, data, sig)
			} else {
				in.verifySMIMEDetached(l, data, sig)
			}
		}
		in.setContent(l, c, signed.Raw)
	}
	inner := c.child(0, c.whole)
	if l != nil && len(l.Signatures) > 0 {
		// A layer with no signature it could read signs nothing.
		inner.signedBy = append(slices.Clone(c.signedBy), l.ID)
	}
	in.walk(signed, inner)
}

func (in *inspector) multipartEncrypted(p *Part, c walkCtx) {
	l := in.newLayer(KindEncryption, FormatPGPMIME, c)
	if l == nil {
		return
	}
	l.Encryption = &Encryption{Recipients: []*Recipient{}}
	control, _ := p.Parts[0].Decoded()
	if p.Parts[0].MediaType != "application/pgp-encrypted" || !strings.Contains(string(control), "Version: 1") {
		in.warn(WarnStructure, "the PGP/MIME version part is missing or not version 1", l.ID)
	}
	data, err := p.Parts[1].Decoded()
	if err != nil {
		l.Error = "the encrypted part does not decode: " + err.Error()
		return
	}
	msg, sigLayer := in.decryptPGP(l, data, c)
	if msg == nil {
		return
	}
	defer clear(msg.Body)
	ic := c.inside(l, false)
	if sigLayer != nil {
		ic.signedBy = append(slices.Clone(ic.signedBy), sigLayer.ID)
	}
	in.readInner(l, ic, slices.Clone(msg.Body))
}

func (in *inspector) leaf(p *Part, c walkCtx) {
	info := &PartInfo{
		Tree:        c.tree,
		Part:        c.path,
		ContentType: p.MediaType,
		Charset:     p.Params["charset"],
		Filename:    filename(p),
		SignedBy:    c.signedBy,
		EncryptedBy: c.encryptedBy,
		Problems:    p.Problems,
	}
	if d := p.Header.Get("Content-Disposition"); d != "" {
		if disp, _, err := mime.ParseMediaType(d); err == nil {
			info.Disposition = strings.ToLower(disp)
		}
	}
	info.LegacyDisplay = p.Params["hp-legacy-display"] == "1" ||
		(p.MediaType == "text/rfc822-headers" && strings.EqualFold(p.Params["protected-headers"], "v1"))
	in.r.Parts = append(in.r.Parts, info)
	body, err := p.Decoded()
	if err != nil {
		info.Problems = append(info.Problems, err.Error())
	}
	info.Size = len(body)
	if !strings.HasPrefix(p.MediaType, "text/") {
		return
	}
	text, ok, problem := decodeText(p.Params["charset"], body)
	if problem != "" {
		info.Problems = append(info.Problems, problem)
		in.warn(WarnCharset, where(c)+": "+problem, 0)
	}
	if ok {
		info.Text = normalizeNewlines(text)
	}
	if p.MediaType == "text/plain" {
		in.inlinePGP(p, body, info, c)
	}
}

func filename(p *Part) string {
	if d := p.Header.Get("Content-Disposition"); d != "" {
		if _, params, err := mime.ParseMediaType(d); err == nil && params["filename"] != "" {
			return DecodeHeader(params["filename"])
		}
	}
	return DecodeHeader(p.Params["name"])
}

func decodeHeaders(h Header) Headers {
	out := Headers{
		From:      DecodeHeader(h.Get("From")),
		Sender:    DecodeHeader(h.Get("Sender")),
		ReplyTo:   DecodeHeader(h.Get("Reply-To")),
		To:        DecodeHeader(strings.Join(h.Values("To"), ", ")),
		Cc:        DecodeHeader(strings.Join(h.Values("Cc"), ", ")),
		Subject:   DecodeHeader(h.Get("Subject")),
		Date:      h.Get("Date"),
		MessageID: h.Get("Message-ID"),
	}
	out.FromAddress = addressOf(h.Get("From"))
	return out
}

var addressParser = &mail.AddressParser{WordDecoder: wordDecoder}

// addressOf is the bare address of a field naming exactly one address,
// "" otherwise: a guess could match a signer to an address the person
// does not see.
func addressOf(v string) string {
	if v == "" {
		return ""
	}
	if list, err := addressParser.ParseList(v); err == nil && len(list) == 1 {
		return list[0].Address
	}
	return ""
}

// finish works out what needs the whole message: coverage, warnings about
// mixed parts, who the sender is, and protected header fields.
func (in *inspector) finish() {
	r := in.r
	r.Signed, r.Encrypted = CoverNone, CoverNone
	for _, l := range r.Layers {
		if l.Kind == KindSignature && len(l.Signatures) == 0 {
			continue // it signs nothing: see its Error
		}
		cov := &r.Signed
		if l.Kind == KindEncryption {
			cov = &r.Encrypted
		}
		if l.Covers == "message" {
			*cov = CoverFull
		} else if *cov == CoverNone {
			*cov = CoverPartial
		}
		if l.Covers == "part" {
			if l.Kind == KindSignature {
				in.warn(WarnPartialSignature, fmt.Sprintf("the signature in layer %d covers only part of the message%s", l.ID, partName(l)), l.ID)
			} else {
				in.warn(WarnPartialEncryption, fmt.Sprintf("the encryption in layer %d covers only part of the message%s", l.ID, partName(l)), l.ID)
			}
		}
	}
	var signed, unsigned, encrypted, plain []string
	for _, p := range r.Parts {
		if p.LegacyDisplay || p.container || (p.Size == 0 && strings.TrimSpace(p.Text) == "") {
			continue
		}
		name := p.Part
		if name == "" {
			name = "the body"
		}
		if p.Tree != 0 {
			name = fmt.Sprintf("%s of layer %d", name, p.Tree)
		}
		if len(p.SignedBy) > 0 {
			signed = append(signed, name)
		} else {
			unsigned = append(unsigned, name)
		}
		if len(p.EncryptedBy) > 0 {
			encrypted = append(encrypted, name)
		} else {
			plain = append(plain, name)
		}
	}
	if len(signed) > 0 && len(unsigned) > 0 {
		in.warn(WarnUnsignedPart, "parts "+strings.Join(unsigned, ", ")+" are not signed, while "+strings.Join(signed, ", ")+" are", 0)
	}
	if len(encrypted) > 0 && len(plain) > 0 {
		in.warn(WarnUnencryptedPart, "parts "+strings.Join(plain, ", ")+" were sent unencrypted, alongside encrypted ones", 0)
	}
	in.protectedHeaders()
	addr := in.from
	if ph := r.Protected; ph != nil && ph.FromAddress != "" && (ph.Signed || ph.Encrypted) {
		addr = ph.FromAddress
	}
	for _, s := range in.sigs {
		s.sig.SenderAddress = addr
		s.sig.SenderMatch = addr != "" && s.match(addr)
		if s.sig.Verified && !s.sig.SenderMatch && addr != "" {
			who := s.sig.Fingerprint
			if s.sig.Certificate != nil {
				who = s.sig.Certificate.Subject
			}
			in.warn(WarnSenderMismatch, fmt.Sprintf("the signature in layer %d was made by %s, which is not for the sender %s", s.layer.ID, who, addr), s.layer.ID)
		}
	}
}

func partName(l *Layer) string {
	if l.Part == "" {
		return ""
	}
	return " (part " + l.Part + ")"
}
