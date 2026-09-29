package svcms

// BER to DER. CMS may be encoded in BER (RFC 5652, section 1.2): streaming
// encoders, OpenSSL's among them, write indefinite lengths and break long
// OCTET STRINGs into constructed chunks, and PKCS#12 files from Windows do
// the same. The parsers here read DER only (with cryptobyte), so input is
// first rewritten into definite, minimal lengths with constructed strings
// joined. Elements that are already in that form are kept byte for byte,
// which matters for what signatures cover: a DER message comes out
// unchanged.
//
// This is not a full DER canonicaliser: SET OF elements are not sorted and
// BOOLEAN or INTEGER encodings are left alone. Only the framing changes.

// berNode is one element being rewritten.
type berNode struct {
	raw   []byte     // the whole element as read, when it needs no change
	ident []byte     // identifier octets, as they will be written
	segs  [][]byte   // contents of a primitive element, in pieces
	kids  []*berNode // contents of a constructed element
	size  int        // length of the contents as written
}

func (n *berNode) totalLen() int {
	if n.raw != nil {
		return len(n.raw)
	}
	return len(n.ident) + lengthLen(n.size) + n.size
}

func lengthLen(n int) int {
	switch {
	case n < 0x80:
		return 1
	case n < 1<<8:
		return 2
	case n < 1<<16:
		return 3
	case n < 1<<24:
		return 4
	}
	return 5
}

func appendLength(out []byte, n int) []byte {
	switch {
	case n < 0x80:
		return append(out, byte(n))
	case n < 1<<8:
		return append(out, 0x81, byte(n))
	case n < 1<<16:
		return append(out, 0x82, byte(n>>8), byte(n))
	case n < 1<<24:
		return append(out, 0x83, byte(n>>16), byte(n>>8), byte(n))
	}
	return append(out, 0x84, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

func (n *berNode) write(out []byte) []byte {
	if n.raw != nil {
		return append(out, n.raw...)
	}
	out = append(out, n.ident...)
	out = appendLength(out, n.size)
	for _, s := range n.segs {
		out = append(out, s...)
	}
	for _, k := range n.kids {
		out = k.write(out)
	}
	return out
}

type berReader struct {
	maxDepth int
	elements int
}

// toDER rewrites one BER element, which must be all of in, as DER framing.
// Input already in that form is returned as is, not copied.
func toDER(in []byte, lim Limits) ([]byte, error) {
	if len(in) > lim.MaxSize {
		return nil, limit("input of %d bytes (the limit is %d)", len(in), lim.MaxSize)
	}
	r := &berReader{maxDepth: lim.MaxDepth}
	n, rest, err := r.element(in, 0)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, malformed("%d bytes of trailing data", len(rest))
	}
	if n.raw != nil {
		return n.raw, nil
	}
	return n.write(make([]byte, 0, n.totalLen())), nil
}

// Universal string types whose constructed (chunked) BER form DER does not
// allow; their chunks are joined.
func joinableString(tag uint32) bool {
	switch tag {
	case 4, 12, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 30:
		return true
	}
	return false
}

// header reads an element's identifier and length octets. length is -1 for
// the indefinite form; canonical says whether the length was minimal.
func readBERHeader(in []byte) (ident []byte, class byte, constructed bool, tag uint32, length int, hdr int, canonical bool, err error) {
	if len(in) < 2 {
		return nil, 0, false, 0, 0, 0, false, malformed("truncated element")
	}
	b := in[0]
	class, constructed, tag = b>>6, b&0x20 != 0, uint32(b&0x1f)
	i := 1
	canonical = true
	if tag == 0x1f {
		tag = 0
		for n := 0; ; n++ {
			if i >= len(in) || n == 4 {
				return nil, 0, false, 0, 0, 0, false, malformed("bad high tag number")
			}
			c := in[i]
			i++
			if n == 0 && c == 0x80 {
				return nil, 0, false, 0, 0, 0, false, malformed("non-minimal tag number")
			}
			tag = tag<<7 | uint32(c&0x7f)
			if c&0x80 == 0 {
				break
			}
		}
		if tag < 0x1f {
			return nil, 0, false, 0, 0, 0, false, malformed("non-minimal tag number")
		}
	}
	ident = in[:i]
	if i >= len(in) {
		return nil, 0, false, 0, 0, 0, false, malformed("truncated element")
	}
	l := in[i]
	i++
	switch {
	case l < 0x80:
		length = int(l)
	case l == 0x80:
		if !constructed {
			return nil, 0, false, 0, 0, 0, false, malformed("indefinite length on a primitive element")
		}
		length, canonical = -1, false
	case l == 0xff:
		return nil, 0, false, 0, 0, 0, false, malformed("reserved length octet")
	default:
		k := int(l & 0x7f)
		if k > 4 {
			return nil, 0, false, 0, 0, 0, false, limit("an element over 4 GiB")
		}
		if i+k > len(in) {
			return nil, 0, false, 0, 0, 0, false, malformed("truncated length")
		}
		v := 0
		for _, c := range in[i : i+k] {
			v = v<<8 | int(c)
		}
		i += k
		if v < 0 || v > len(in) {
			return nil, 0, false, 0, 0, 0, false, malformed("length past the end of the data")
		}
		length = v
		if v < 0x80 || in[i-k] == 0 {
			canonical = false
		}
	}
	if length > len(in)-i {
		return nil, 0, false, 0, 0, 0, false, malformed("length past the end of the data")
	}
	return ident, class, constructed, tag, length, i, canonical, nil
}

// element reads one element from the front of in.
func (r *berReader) element(in []byte, depth int) (*berNode, []byte, error) {
	if depth > r.maxDepth {
		return nil, nil, limit("ASN.1 nested more than %d deep", r.maxDepth)
	}
	if r.elements++; r.elements > maxElements {
		return nil, nil, limit("more than %d ASN.1 elements", maxElements)
	}
	ident, class, constructed, tag, length, hdr, canonical, err := readBERHeader(in)
	if err != nil {
		return nil, nil, err
	}
	if class == 0 && tag == 0 {
		return nil, nil, malformed("unexpected end-of-contents")
	}
	if !constructed {
		if class == 0 && tag == 3 && length == 0 {
			return nil, nil, malformed("empty BIT STRING")
		}
		end := hdr + length
		n := &berNode{size: length}
		if canonical {
			n.raw = in[:end]
		} else {
			n.ident, n.segs = ident, [][]byte{in[hdr:end]}
		}
		return n, in[end:], nil
	}
	if class == 0 && tag == 3 {
		return nil, nil, unsupported("constructed BIT STRING")
	}
	join := class == 0 && joinableString(tag)
	var body, rest []byte
	if length >= 0 {
		body, rest = in[hdr:hdr+length], in[hdr+length:]
	} else {
		body = in[hdr:]
	}
	n := &berNode{}
	allRaw := canonical && !join
	for {
		if length < 0 {
			if len(body) < 2 {
				return nil, nil, malformed("indefinite-length element without end-of-contents")
			}
			if body[0] == 0 && body[1] == 0 {
				rest = body[2:]
				break
			}
		} else if len(body) == 0 {
			break
		}
		kid, after, err := r.element(body, depth+1)
		if err != nil {
			return nil, nil, err
		}
		body = after
		if join {
			if err := joinChunk(n, kid, tag, in[0]&^0x20); err != nil {
				return nil, nil, err
			}
			continue
		}
		if kid.raw == nil {
			allRaw = false
		}
		n.kids = append(n.kids, kid)
		n.size += kid.totalLen()
	}
	if allRaw {
		return &berNode{raw: in[:len(in)-len(rest)]}, rest, nil
	}
	if join {
		n.ident = []byte{in[0] &^ 0x20} // primitive form of the same tag
		return n, rest, nil
	}
	n.ident = ident
	return n, rest, nil
}

// joinChunk adds a chunk of a constructed string to its primitive result.
// Each chunk must be the same universal type.
func joinChunk(n, kid *berNode, tag uint32, primIdent byte) error {
	var ident byte
	if kid.raw != nil {
		ident = kid.raw[0]
	} else {
		ident = kid.ident[0]
	}
	if ident != primIdent {
		return malformed("a chunk of a constructed string of type %d has another type", tag)
	}
	if kid.raw != nil {
		_, _, _, _, length, hdr, _, err := readBERHeader(kid.raw)
		if err != nil {
			return err
		}
		n.segs = append(n.segs, kid.raw[hdr:hdr+length])
		n.size += length
		return nil
	}
	n.segs = append(n.segs, kid.segs...)
	n.size += kid.size
	return nil
}
