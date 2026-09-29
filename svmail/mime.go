package svmail

import (
	"bytes"
	"mime"
	"strconv"
	"strings"
)

// Reading RFC 5322 messages and MIME (RFC 2045, 2046), keeping the exact
// bytes of every part. Checking a multipart/signed signature needs the
// signed part byte for byte as it was sent, which mime/multipart does not
// give, so boundaries are found here.

// Part is one MIME entity: a whole message, or a part of one.
type Part struct {
	// Header holds the entity's header fields, in order.
	Header Header

	// Raw is the entity exactly as it appears in the input: its header,
	// the empty line, and its body. For a part of a multipart it runs
	// from after the boundary line to before the line break that
	// precedes the next boundary, which is what a multipart/signed
	// signature covers.
	Raw []byte

	// Body is the body exactly as it appears, before any transfer
	// decoding.
	Body []byte

	// MediaType is the Content-Type's type/subtype in lower case,
	// text/plain when there is none; Params are its parameters, with
	// lower-case names.
	MediaType string
	Params    map[string]string

	// Parts are the parts of a multipart, in order.
	Parts []*Part

	// Problems are things wrong with the entity that did not stop it
	// being read: a missing close boundary, a malformed header line.
	Problems []string
}

// Header is a list of header fields.
type Header []Field

// Field is one header field.
type Field struct {
	// Name is the field name as written.
	Name string
	// Value is the unfolded value, with surrounding white space removed.
	// It is not decoded: see DecodeHeader.
	Value string
	// Raw is the field exactly as written, folding and line ending
	// included.
	Raw []byte
}

// Get returns the first value of the named field ("" if there is none),
// ignoring case in the name.
func (h Header) Get(name string) string {
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			return f.Value
		}
	}
	return ""
}

// Values returns every value of the named field, in order.
func (h Header) Values(name string) []string {
	var out []string
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			out = append(out, f.Value)
		}
	}
	return out
}

// Has says whether the header has the named field.
func (h Header) Has(name string) bool {
	for _, f := range h {
		if strings.EqualFold(f.Name, name) {
			return true
		}
	}
	return false
}

// ParseMessage reads a message (or any MIME entity), CR LF or LF line
// endings alike, into its tree of parts.
func ParseMessage(raw []byte, lim *Limits) (*Part, error) {
	l := lim.withDefaults()
	if len(raw) > l.MaxSize {
		return nil, limit("a message of %d bytes (the limit is %d)", len(raw), l.MaxSize)
	}
	p := &parser{lim: l}
	return p.entity(raw, 0, "text/plain")
}

type parser struct {
	lim   Limits
	parts int
}

// entity reads one entity from raw, which is all of it.
func (p *parser) entity(raw []byte, depth int, defaultType string) (*Part, error) {
	if depth > p.lim.MaxDepth {
		return nil, limit("MIME parts nested more than %d deep", p.lim.MaxDepth)
	}
	if p.parts++; p.parts > p.lim.MaxParts {
		return nil, limit("more than %d MIME parts", p.lim.MaxParts)
	}
	part := &Part{Raw: raw}
	hdr, body, problems, err := parseHeader(raw, p.lim)
	if err != nil {
		return nil, err
	}
	part.Header, part.Body, part.Problems = hdr, body, problems
	part.MediaType, part.Params = defaultType, map[string]string{}
	if defaultType == "text/plain" {
		part.Params["charset"] = "us-ascii"
	}
	if ct := hdr.Get("Content-Type"); ct != "" {
		mt, params, err := mime.ParseMediaType(ct)
		switch {
		case err == nil:
			part.MediaType, part.Params = strings.ToLower(mt), params
		case mt != "":
			// A parameter that does not parse: keep the type, drop the
			// parameters, and say so.
			part.MediaType = strings.ToLower(mt)
			part.Params = lenientParams(ct)
			part.Problems = append(part.Problems, "Content-Type parameters do not parse: "+err.Error())
		default:
			part.Problems = append(part.Problems, "Content-Type does not parse; read as "+defaultType)
		}
	}
	if !strings.HasPrefix(part.MediaType, "multipart/") {
		return part, nil
	}
	boundary := part.Params["boundary"]
	if boundary == "" || len(boundary) > 200 {
		part.Problems = append(part.Problems, "a multipart without a usable boundary, read as a single part")
		return part, nil
	}
	childType := "text/plain"
	if part.MediaType == "multipart/digest" {
		childType = "message/rfc822"
	}
	pieces, closed := splitMultipart(body, boundary)
	if !closed {
		part.Problems = append(part.Problems, "the multipart has no closing boundary")
	}
	for _, piece := range pieces {
		child, err := p.entity(piece, depth+1, childType)
		if err != nil {
			return nil, err
		}
		part.Parts = append(part.Parts, child)
	}
	if len(part.Parts) == 0 {
		part.Problems = append(part.Problems, "the multipart has no parts")
	}
	return part, nil
}

// lenientParams reads what it can of a Content-Type's parameters when
// mime.ParseMediaType refuses them (a duplicate, a stray character),
// taking the first value of each name.
func lenientParams(ct string) map[string]string {
	out := map[string]string{}
	_, rest, _ := strings.Cut(ct, ";")
	for _, kv := range strings.Split(rest, ";") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		if uq, err := strconv.Unquote(v); err == nil && strings.HasPrefix(v, `"`) {
			v = uq
		} else {
			v = strings.Trim(v, `"`)
		}
		if _, dup := out[k]; !dup && k != "" {
			out[k] = v
		}
	}
	return out
}

// nextLine returns the line starting at i (without its line ending), the
// index after its line ending, and the length of that line ending.
func nextLine(b []byte, i int) (line []byte, next, eol int) {
	j := bytes.IndexByte(b[i:], '\n')
	if j < 0 {
		return b[i:], len(b), 0
	}
	end := i + j
	eol = 1
	if end > i && b[end-1] == '\r' {
		end--
		eol = 2
	}
	return b[i:end], i + j + 1, eol
}

// parseHeader splits an entity into its header fields and its body. An
// entity whose first line is not a header field has no header: all of it
// is body.
func parseHeader(raw []byte, lim Limits) (Header, []byte, []string, error) {
	var h Header
	var problems []string
	// The field being read: where it starts, and its value's pieces,
	// joined once it ends (joining at every continuation line would take
	// quadratic time).
	start, open := 0, false
	var pieces []string
	finish := func(end int) {
		if open {
			f := &h[len(h)-1]
			f.Raw = raw[start:end]
			f.Value = strings.Join(pieces, " ")
		}
		open, pieces = false, pieces[:0]
	}
	i := 0
	for i < len(raw) {
		line, next, _ := nextLine(raw, i)
		if len(line) == 0 {
			finish(i)
			return h, raw[next:], problems, nil
		}
		if next > lim.MaxHeaderSize {
			return nil, nil, nil, limit("a header over %d bytes", lim.MaxHeaderSize)
		}
		if line[0] == ' ' || line[0] == '\t' {
			if !open {
				// Continuing nothing, or a line that was not a field.
				if len(h) == 0 {
					problems = append(problems, "a header that starts with a continuation line")
				}
				i = next
				continue
			}
			if v := strings.TrimSpace(string(line)); v != "" {
				pieces = append(pieces, v)
			}
			i = next
			continue
		}
		finish(i)
		if i == 0 && bytes.HasPrefix(line, []byte("From ")) {
			i = next // an mbox separator
			continue
		}
		name, value, ok := bytes.Cut(line, []byte(":"))
		if !ok || !validFieldName(name) {
			if len(h) == 0 && len(problems) == 0 && (i == 0 || bytes.HasPrefix(raw, []byte("From "))) {
				// Not a header at all: the entity is all body.
				return nil, raw[i:], nil, nil
			}
			problems = append(problems, "a header line that is not a field: "+truncate(string(line), 60))
			i = next
			continue
		}
		if len(h) >= lim.MaxHeaderFields {
			return nil, nil, nil, limit("more than %d header fields", lim.MaxHeaderFields)
		}
		h = append(h, Field{Name: string(name)})
		start, open = i, true
		if v := strings.TrimSpace(string(value)); v != "" {
			pieces = append(pieces, v)
		}
		i = next
	}
	finish(len(raw))
	return h, raw[len(raw):], problems, nil
}

func validFieldName(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, c := range b {
		if c <= ' ' || c >= 0x7f {
			return false
		}
	}
	return true
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// splitMultipart finds the parts of a multipart body (RFC 2046, section
// 5.1.1). A delimiter is "--" and the boundary at the start of a line,
// followed only by white space; the close delimiter adds "--". The line
// break before a delimiter belongs to the delimiter, not to the part
// before it.
func splitMultipart(body []byte, boundary string) (parts [][]byte, closed bool) {
	dash := []byte("--" + boundary)
	start := -1 // where the current part began, or -1 in the preamble
	for i := 0; i < len(body); {
		line, next, _ := nextLine(body, i)
		if bytes.HasPrefix(line, dash) {
			rest := line[len(dash):]
			isClose := bytes.HasPrefix(rest, []byte("--"))
			if isClose {
				rest = rest[2:]
			}
			if len(bytes.TrimRight(rest, " \t")) == 0 {
				if start >= 0 {
					end := i
					// The line break before the delimiter is part of it.
					if end > start && body[end-1] == '\n' {
						end--
						if end > start && body[end-1] == '\r' {
							end--
						}
					}
					parts = append(parts, body[start:end])
				}
				if isClose {
					return parts, true
				}
				start = next
			}
		}
		i = next
	}
	if start >= 0 {
		parts = append(parts, body[start:])
	}
	return parts, false
}

// canonical returns b with every line ending CR LF, as signatures over
// MIME entities are computed (RFC 3156, section 5; RFC 8551, section
// 3.1.1). It returns b itself when nothing needs to change.
func canonical(b []byte) []byte {
	bare := 0
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			bare++
		}
	}
	if bare == 0 {
		return b
	}
	out := make([]byte, 0, len(b)+bare)
	for i, c := range b {
		if c == '\n' && (i == 0 || b[i-1] != '\r') {
			out = append(out, '\r')
		}
		out = append(out, c)
	}
	return out
}
