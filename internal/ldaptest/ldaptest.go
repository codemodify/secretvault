// Package ldaptest is a pretend LDAP directory for tests: one listener,
// simple binds, equality searches, StartTLS. People are found by mail and
// answer with the attributes given for them.
package ldaptest

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// Options say what the directory holds.
type Options struct {
	// LDAPS serves TLS from the start; otherwise clients may StartTLS.
	LDAPS bool
	// BindDN and Password are the one account; an empty BindDN takes
	// anonymous searches too.
	BindDN, Password string
	// People are by mail address: attribute name to values.
	People map[string]map[string][][]byte
}

// Base is where people are.
const Base = "dc=example,dc=org"

// Server is the directory.
type Server struct {
	// URL is ldap://127.0.0.1:PORT (or ldaps://), and Roots trust its
	// certificate (issued to localhost and 127.0.0.1).
	URL   string
	Roots *x509.CertPool

	o Options

	ln  net.Listener
	tls *tls.Config

	mu       sync.Mutex
	seen     []string
	startTLS bool
}

// New starts a directory.
func New(t *testing.T, o Options) *Server {
	ldaps := o.LDAPS
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "directory"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, DNSNames: []string{"localhost"}, IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	s := &Server{Roots: x509.NewCertPool(), o: o,
		tls: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}}
	s.Roots.AddCert(cert)
	scheme := "ldap"
	if ldaps {
		scheme = "ldaps"
		s.ln, err = tls.Listen("tcp", "127.0.0.1:0", s.tls)
	} else {
		s.ln, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	s.URL = scheme + "://" + s.ln.Addr().String()
	t.Cleanup(func() { s.ln.Close() })
	go s.serve()
	return s
}

// Seen are the values searched for, in order.
func (s *Server) Seen() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.seen...)
}

// DidStartTLS reports whether a client upgraded with StartTLS.
func (s *Server) DidStartTLS() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.startTLS
}

func (s *Server) serve() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		go s.conn(c)
	}
}

func app(n uint8) cbasn1.Tag { return cbasn1.Tag(0x40 | n).Constructed() }

func reply(c io.Writer, id int64, op func(*cryptobyte.Builder)) {
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1Int64(id)
		op(b)
	})
	c.Write(b.BytesOrPanic())
}

func result(b *cryptobyte.Builder, code int64, msg string) {
	b.AddASN1Enum(code)
	b.AddASN1OctetString(nil)
	b.AddASN1OctetString([]byte(msg))
}

// readTLV reads one BER element of definite length.
func readTLV(r *bufio.Reader) ([]byte, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return nil, err
	}
	n := int(head[1])
	if head[1]&0x80 != 0 {
		k := int(head[1] & 0x7f)
		lb := make([]byte, k)
		if _, err := io.ReadFull(r, lb); err != nil {
			return nil, err
		}
		head = append(head, lb...)
		n = 0
		for _, b := range lb {
			n = n<<8 | int(b)
		}
	}
	body := make([]byte, n)
	_, err := io.ReadFull(r, body)
	return append(head, body...), err
}

func (s *Server) conn(c net.Conn) {
	defer c.Close()
	r := bufio.NewReader(c)
	bound := s.o.BindDN == ""
	for {
		raw, err := readTLV(r)
		if err != nil {
			return
		}
		in := cryptobyte.String(raw)
		var msg, body cryptobyte.String
		var id int64
		var tag cbasn1.Tag
		in.ReadASN1(&msg, cbasn1.SEQUENCE)
		msg.ReadASN1Int64WithTag(&id, cbasn1.INTEGER)
		msg.ReadAnyASN1(&body, &tag)
		switch tag {
		case app(23): // StartTLS
			reply(c, id, func(b *cryptobyte.Builder) {
				b.AddASN1(app(24), func(b *cryptobyte.Builder) { result(b, 0, "") })
			})
			tc := tls.Server(c, s.tls)
			if tc.Handshake() != nil {
				return
			}
			s.mu.Lock()
			s.startTLS = true
			s.mu.Unlock()
			c, r = tc, bufio.NewReader(tc)
		case app(0): // bind
			var version int64
			var dn, pass cryptobyte.String
			body.ReadASN1Int64WithTag(&version, cbasn1.INTEGER)
			body.ReadASN1(&dn, cbasn1.OCTET_STRING)
			body.ReadASN1(&pass, cbasn1.Tag(0).ContextSpecific())
			code, why := int64(0), ""
			if string(dn) != s.o.BindDN || string(pass) != s.o.Password {
				code, why = 49, "invalid credentials"
			} else {
				bound = true
			}
			reply(c, id, func(b *cryptobyte.Builder) { b.AddASN1(app(1), func(b *cryptobyte.Builder) { result(b, code, why) }) })
		case app(3): // search
			var base, filter cryptobyte.String
			var n int
			var l int64
			var typesOnly bool
			body.ReadASN1(&base, cbasn1.OCTET_STRING)
			body.ReadASN1Enum(&n)
			body.ReadASN1Enum(&n)
			body.ReadASN1Int64WithTag(&l, cbasn1.INTEGER)
			body.ReadASN1Int64WithTag(&l, cbasn1.INTEGER)
			body.ReadASN1Boolean(&typesOnly)
			body.ReadASN1(&filter, cbasn1.Tag(1).ContextSpecific().Constructed())
			var who string
			for !filter.Empty() {
				var eq, attr, val cryptobyte.String
				filter.ReadASN1(&eq, cbasn1.Tag(3).ContextSpecific().Constructed())
				eq.ReadASN1(&attr, cbasn1.OCTET_STRING)
				eq.ReadASN1(&val, cbasn1.OCTET_STRING)
				s.mu.Lock()
				s.seen = append(s.seen, string(val))
				s.mu.Unlock()
				if string(attr) == "mail" {
					who = string(val)
				}
			}
			if !bound {
				reply(c, id, func(b *cryptobyte.Builder) {
					b.AddASN1(app(5), func(b *cryptobyte.Builder) { result(b, 50, "insufficient access") })
				})
				continue
			}
			if attrs, ok := s.o.People[who]; ok && string(base) == Base {
				reply(c, id, func(b *cryptobyte.Builder) {
					b.AddASN1(app(4), func(b *cryptobyte.Builder) {
						b.AddASN1OctetString([]byte("mail=" + who + "," + Base))
						b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
							for name, vals := range attrs {
								b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
									b.AddASN1OctetString([]byte(name))
									b.AddASN1(cbasn1.SET, func(b *cryptobyte.Builder) {
										for _, v := range vals {
											b.AddASN1OctetString(v)
										}
									})
								})
							}
						})
					})
				})
			}
			reply(c, id, func(b *cryptobyte.Builder) { b.AddASN1(app(5), func(b *cryptobyte.Builder) { result(b, 0, "") }) })
		case cbasn1.Tag(0x42): // unbind
			return
		}
	}
}
