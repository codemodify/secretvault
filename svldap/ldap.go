// Package svldap asks an organisation's LDAP directory (OpenLDAP, Active
// Directory) for its people's keys: their S/MIME certificates
// (userCertificate) and OpenPGP keys (pgpKey). It is a small LDAPv3 client
// of our own (RFC 4511), with only what that takes: a simple bind, one
// search, StartTLS.
//
// It never builds a filter from text: the search is equality on the mail
// attributes for the address asked about, so nothing in an address can
// widen it. The connection is TLS (ldaps://, or ldap:// with StartTLS),
// except to this machine.
package svldap

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Errors.
var (
	ErrURL      = errors.New("svldap: not an LDAP URL (ldaps://host, or ldap://host with StartTLS)")
	ErrProtocol = errors.New("svldap: the server's answer is not LDAP")
	ErrTooLarge = errors.New("svldap: the server's answer is too large")
)

// ResultError is an LDAP result other than success.
type ResultError struct {
	Code    int
	Message string
}

func (e *ResultError) Error() string {
	if e.Message != "" {
		return fmt.Sprintf("svldap: the directory said %d: %s", e.Code, e.Message)
	}
	return fmt.Sprintf("svldap: the directory said %d", e.Code)
}

// Limits on what a server may send.
const (
	maxMessage = 4 << 20
	maxEntries = 64
)

// Conn is a connection to a directory.
type Conn struct {
	conn net.Conn
	r    *bufio.Reader
	id   int
}

// Dial connects to rawURL: ldaps://host[:636], or ldap://host[:389], which
// is upgraded with StartTLS unless the host is this machine. tlsConfig
// may be nil (the system's roots); its ServerName is filled in.
func Dial(ctx context.Context, rawURL string, tlsConfig *tls.Config) (*Conn, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || (u.Scheme != "ldap" && u.Scheme != "ldaps") {
		return nil, ErrURL
	}
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		port = map[string]string{"ldap": "389", "ldaps": "636"}[u.Scheme]
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if tlsConfig != nil {
		cfg = tlsConfig.Clone()
	}
	if cfg.ServerName == "" {
		cfg.ServerName = host
	}
	var d net.Dialer
	raw, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		raw.SetDeadline(dl)
	} else {
		raw.SetDeadline(time.Now().Add(time.Minute))
	}
	c := &Conn{conn: raw, r: bufio.NewReader(raw)}
	switch {
	case u.Scheme == "ldaps":
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		c.conn, c.r = tc, bufio.NewReader(tc)
	case !plainOK(host):
		if err := c.startTLS(ctx, cfg); err != nil {
			raw.Close()
			return nil, err
		}
	}
	return c, nil
}

// plainOK says where a connection may stay unencrypted: this machine
// only. Tests stand in for it.
var plainOK = isLocal

func isLocal(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Close unbinds and closes.
func (c *Conn) Close() error {
	c.id++
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(c.id))
		b.AddASN1(cbasn1.Tag(0x42), func(*cryptobyte.Builder) {}) // [APPLICATION 2] NULL: unbind
	})
	if msg, err := b.Bytes(); err == nil {
		c.conn.Write(msg)
	}
	return c.conn.Close()
}

func app(n uint8) cbasn1.Tag { return cbasn1.Tag(0x40 | n).Constructed() }

// send writes one request, op building its protocolOp, and returns its
// message ID.
func (c *Conn) send(op func(*cryptobyte.Builder)) (int, error) {
	c.id++
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(int64(c.id))
		op(b)
	})
	msg, err := b.Bytes()
	if err != nil {
		return 0, err
	}
	_, err = c.conn.Write(msg)
	return c.id, err
}

// recv reads one message for id, returning its protocolOp's tag and body.
func (c *Conn) recv(id int) (cbasn1.Tag, cryptobyte.String, error) {
	for {
		raw, err := readTLV(c.r)
		if err != nil {
			return 0, nil, err
		}
		s := cryptobyte.String(raw)
		var msg cryptobyte.String
		var mid int64
		var tag cbasn1.Tag
		var body cryptobyte.String
		if !s.ReadASN1(&msg, cbasn1.SEQUENCE) || !msg.ReadASN1Int64WithTag(&mid, cbasn1.INTEGER) || !msg.ReadAnyASN1(&body, &tag) {
			return 0, nil, ErrProtocol
		}
		if mid == 0 {
			// An unsolicited notification: the server is going away.
			return 0, nil, fmt.Errorf("%w: the server ended the session", ErrProtocol)
		}
		if int(mid) != id {
			continue
		}
		return tag, body, nil
	}
}

// readTLV reads one BER element (definite lengths, as LDAP requires).
func readTLV(r *bufio.Reader) ([]byte, error) {
	tag, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	if tag&0x1f == 0x1f {
		return nil, ErrProtocol
	}
	l0, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	head := []byte{tag, l0}
	n := int(l0)
	if l0&0x80 != 0 {
		k := int(l0 & 0x7f)
		if k == 0 || k > 4 {
			return nil, ErrProtocol
		}
		n = 0
		for range k {
			b, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			head = append(head, b)
			n = n<<8 | int(b)
		}
	}
	if n > maxMessage {
		return nil, ErrTooLarge
	}
	out := make([]byte, len(head)+n)
	copy(out, head)
	if _, err := io.ReadFull(r, out[len(head):]); err != nil {
		return nil, err
	}
	return out, nil
}

// result reads an LDAPResult: success, or the error it is.
func result(body cryptobyte.String) error {
	var code int
	var matched, diag cryptobyte.String
	if !body.ReadASN1Enum(&code) || !body.ReadASN1(&matched, cbasn1.OCTET_STRING) || !body.ReadASN1(&diag, cbasn1.OCTET_STRING) {
		return ErrProtocol
	}
	if code != 0 {
		return &ResultError{Code: code, Message: printable(string(diag))}
	}
	return nil
}

// printable keeps a server's message from driving a terminal.
func printable(s string) string {
	s = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, s)
	if len(s) > 200 {
		s = s[:200]
	}
	return s
}

func (c *Conn) startTLS(ctx context.Context, cfg *tls.Config) error {
	id, err := c.send(func(b *cryptobyte.Builder) {
		b.AddASN1(app(23), func(b *cryptobyte.Builder) {
			b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) {
				b.AddBytes([]byte("1.3.6.1.4.1.1466.20037"))
			})
		})
	})
	if err != nil {
		return err
	}
	tag, body, err := c.recv(id)
	if err != nil {
		return err
	}
	if tag != app(24) {
		return ErrProtocol
	}
	if err := result(body); err != nil {
		return fmt.Errorf("svldap: the directory refused StartTLS: %w", err)
	}
	if c.r.Buffered() > 0 {
		return fmt.Errorf("%w: data before the TLS handshake", ErrProtocol)
	}
	tc := tls.Client(c.conn, cfg)
	if err := tc.HandshakeContext(ctx); err != nil {
		return err
	}
	c.conn, c.r = tc, bufio.NewReader(tc)
	return nil
}

// Bind authenticates with a DN and password (simple bind); an empty DN
// binds anonymously.
func (c *Conn) Bind(dn string, password []byte) error {
	id, err := c.send(func(b *cryptobyte.Builder) {
		b.AddASN1(app(0), func(b *cryptobyte.Builder) {
			b.AddASN1Int64(3)
			b.AddASN1OctetString([]byte(dn))
			b.AddASN1(cbasn1.Tag(0).ContextSpecific(), func(b *cryptobyte.Builder) { b.AddBytes(password) })
		})
	})
	if err != nil {
		return err
	}
	tag, body, err := c.recv(id)
	if err != nil {
		return err
	}
	if tag != app(1) {
		return ErrProtocol
	}
	return result(body)
}

// Entry is one search result: a DN and its attributes' values.
type Entry struct {
	DN    string
	Attrs map[string][][]byte
}

// Match is one equality test of a search.
type Match struct{ Attr, Value string }

// Search finds the entries under base (whole subtree) that any of anyOf
// match, and returns the attributes want of each. There is no filter
// text: only these equalities, so a value cannot change the search.
func (c *Conn) Search(base string, anyOf []Match, want []string) ([]Entry, error) {
	id, err := c.send(func(b *cryptobyte.Builder) {
		b.AddASN1(app(3), func(b *cryptobyte.Builder) {
			b.AddASN1OctetString([]byte(base))
			b.AddASN1Enum(2) // wholeSubtree
			b.AddASN1Enum(0) // neverDerefAliases
			b.AddASN1Int64(maxEntries)
			b.AddASN1Int64(30) // seconds
			b.AddASN1Boolean(false)
			// or [1] SET OF equalityMatch [3] { attribute, value }
			b.AddASN1(cbasn1.Tag(1).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
				for _, m := range anyOf {
					b.AddASN1(cbasn1.Tag(3).ContextSpecific().Constructed(), func(b *cryptobyte.Builder) {
						b.AddASN1OctetString([]byte(m.Attr))
						b.AddASN1OctetString([]byte(m.Value))
					})
				}
			})
			b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
				for _, w := range want {
					b.AddASN1OctetString([]byte(w))
				}
			})
		})
	})
	if err != nil {
		return nil, err
	}
	var out []Entry
	for {
		tag, body, err := c.recv(id)
		if err != nil {
			return nil, err
		}
		switch tag {
		case app(4): // searchResEntry
			if len(out) >= maxEntries {
				return nil, ErrTooLarge
			}
			e, err := parseEntry(body)
			if err != nil {
				return nil, err
			}
			out = append(out, e)
		case app(19): // a referral to another server: not followed
		case app(5): // searchResDone
			if err := result(body); err != nil {
				var re *ResultError
				// sizeLimitExceeded still returns what fitted.
				if errors.As(err, &re) && re.Code == 4 {
					return out, nil
				}
				return nil, err
			}
			return out, nil
		default:
			return nil, ErrProtocol
		}
	}
}

func parseEntry(body cryptobyte.String) (Entry, error) {
	var dn, attrs cryptobyte.String
	if !body.ReadASN1(&dn, cbasn1.OCTET_STRING) || !body.ReadASN1(&attrs, cbasn1.SEQUENCE) {
		return Entry{}, ErrProtocol
	}
	e := Entry{DN: string(dn), Attrs: map[string][][]byte{}}
	for !attrs.Empty() {
		var attr, typ, vals cryptobyte.String
		if !attrs.ReadASN1(&attr, cbasn1.SEQUENCE) || !attr.ReadASN1(&typ, cbasn1.OCTET_STRING) || !attr.ReadASN1(&vals, cbasn1.SET) {
			return Entry{}, ErrProtocol
		}
		name := strings.ToLower(string(typ))
		for !vals.Empty() {
			var v cryptobyte.String
			if !vals.ReadASN1(&v, cbasn1.OCTET_STRING) {
				return Entry{}, ErrProtocol
			}
			e.Attrs[name] = append(e.Attrs[name], append([]byte(nil), v...))
		}
	}
	return e, nil
}
