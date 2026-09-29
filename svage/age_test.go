package svage

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"sync"
	"testing"

	"golang.org/x/crypto/ssh"
)

// Keys are slow to make (RSA especially), so the tests share one of each.
var testKeys = sync.OnceValue(func() (k struct {
	x      *X25519Identity
	pq     *HybridIdentity
	ed     Identity
	edPub  string
	rsa    Identity
	rsaPub string
}) {
	var err error
	if k.x, err = GenerateX25519Identity(); err != nil {
		panic(err)
	}
	if k.pq, err = GenerateHybridIdentity(); err != nil {
		panic(err)
	}
	_, edPriv, _ := ed25519.GenerateKey(rand.Reader)
	k.ed, _ = NewSSHEd25519Identity(edPriv)
	edPub, _ := ssh.NewPublicKey(edPriv.Public())
	k.edPub = string(ssh.MarshalAuthorizedKey(edPub))
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	k.rsa, _ = NewSSHRSAIdentity(rk)
	rsaPub, _ := ssh.NewPublicKey(&rk.PublicKey)
	k.rsaPub = string(ssh.MarshalAuthorizedKey(rsaPub))
	return k
})

// tagIdentity opens tagged stanzas, as a token's plugin would.
type tagIdentity struct {
	priv  hpke.PrivateKey
	point []byte // what the tag hashes
	pq    bool
}

func newTagIdentity(t *testing.T, pq bool) (*tagIdentity, *TagRecipient) {
	t.Helper()
	if pq {
		k, err := hpke.MLKEM768P256().GenerateKey()
		if err != nil {
			t.Fatal(err)
		}
		s, _ := bech32Encode("age1tagpq", k.PublicKey().Bytes())
		r, err := ParseTagRecipient(s)
		if err != nil {
			t.Fatal(err)
		}
		return &tagIdentity{priv: k, point: k.PublicKey().Bytes()[mlkem768EncapsSize:], pq: true}, r
	}
	k, err := hpke.DHKEM(ecdh.P256()).GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	u := k.PublicKey().Bytes()
	c := append([]byte{2 | u[64]&1}, u[1:33]...)
	s, _ := bech32Encode("age1tag", c)
	r, err := ParseTagRecipient(s)
	if err != nil {
		t.Fatal(err)
	}
	return &tagIdentity{priv: k, point: c}, r
}

func (id *tagIdentity) Unwrap(stanzas []*Stanza) ([]byte, error) {
	typ, label := "p256tag", p256TagLabel
	if id.pq {
		typ, label = "mlkem768p256tag", mlkem768P256Label
	}
	for _, s := range stanzas {
		if s.Type != typ || len(s.Args) != 2 {
			continue
		}
		tag, _ := decodeB64(s.Args[0])
		enc, _ := decodeB64(s.Args[1])
		want, err := stanzaTag(label, id.point, enc)
		if err != nil || !bytes.Equal(tag, want) {
			continue
		}
		r, err := hpke.NewRecipient(enc, id.priv, hpke.HKDFSHA256(), hpke.ChaCha20Poly1305(), []byte(label))
		if err != nil {
			return nil, err
		}
		return r.Open(nil, s.Body)
	}
	return nil, ErrIncorrectIdentity
}

func encrypt(t *testing.T, armored bool, plain []byte, rs ...Recipient) []byte {
	t.Helper()
	var buf bytes.Buffer
	var dst io.Writer = &buf
	var aw io.WriteCloser
	if armored {
		aw = NewArmorWriter(&buf)
		dst = aw
	}
	w, err := Encrypt(dst, rs...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(plain); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if aw != nil {
		if err := aw.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return buf.Bytes()
}

func decrypt(file []byte, armored bool, ids ...Identity) ([]byte, error) {
	var in io.Reader = bytes.NewReader(file)
	if armored {
		in = NewArmorReader(in)
	}
	r, err := Decrypt(in, ids...)
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func pattern(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func TestEveryRecipientTypeRoundTrips(t *testing.T) {
	k := testKeys()
	edR, err := ParseSSHRecipient(k.edPub)
	if err != nil {
		t.Fatal(err)
	}
	rsaR, err := ParseSSHRecipient(k.rsaPub)
	if err != nil {
		t.Fatal(err)
	}
	pass, _ := NewScryptRecipient([]byte("correct horse battery staple"))
	pass.SetWorkFactor(10)
	passID, _ := NewScryptIdentity([]byte("correct horse battery staple"))
	tagID, tagR := newTagIdentity(t, false)
	tagPQID, tagPQR := newTagIdentity(t, true)
	cases := []struct {
		name string
		r    Recipient
		id   Identity
	}{
		{"X25519", k.x.Recipient(), k.x},
		{"hybrid", k.pq.Recipient(), k.pq},
		{"scrypt", pass, passID},
		{"ssh-ed25519", edR, k.ed},
		{"ssh-rsa", rsaR, k.rsa},
		{"p256tag", tagR, tagID},
		{"mlkem768p256tag", tagPQR, tagPQID},
	}
	sizes := []int{0, 1, 1000, ChunkSize - 1, ChunkSize, ChunkSize + 1, 2 * ChunkSize, 3*ChunkSize + 5}
	for _, c := range cases {
		for _, armored := range []bool{false, true} {
			for _, n := range sizes {
				if c.name != "X25519" && n > 1000 && n != 2*ChunkSize {
					continue // the sizes exercise the stream, not the stanza
				}
				t.Run(fmt.Sprintf("%s/armored=%v/%d", c.name, armored, n), func(t *testing.T) {
					plain := pattern(n)
					file := encrypt(t, armored, plain, c.r)
					got, err := decrypt(file, armored, c.id)
					if err != nil || !bytes.Equal(got, plain) {
						t.Fatalf("got %d bytes, %v", len(got), err)
					}
					if armored {
						return
					}
					ra, size, err := DecryptReaderAt(bytes.NewReader(file), int64(len(file)), c.id)
					if err != nil || size != int64(n) {
						t.Fatalf("DecryptReaderAt: size %d, %v", size, err)
					}
					for _, off := range []int64{0, 1, ChunkSize - 1, ChunkSize, int64(n) - 1} {
						if off < 0 || off >= int64(n) {
							continue
						}
						buf := make([]byte, min(100, int64(n)-off))
						if _, err := ra.ReadAt(buf, off); err != nil && err != io.EOF {
							t.Fatalf("ReadAt %d: %v", off, err)
						}
						if !bytes.Equal(buf, plain[off:off+int64(len(buf))]) {
							t.Fatalf("ReadAt %d read the wrong bytes", off)
						}
					}
				})
			}
		}
	}
}

func TestRecipientsAndIdentitiesSurviveTheirTextForm(t *testing.T) {
	k := testKeys()
	for _, s := range []string{k.x.Recipient().String(), k.pq.Recipient().String(), strings.TrimSpace(k.edPub), strings.TrimSpace(k.rsaPub)} {
		r, err := ParseRecipient(s)
		if err != nil {
			t.Fatalf("%.30s: %v", s, err)
		}
		if r.(fmt.Stringer).String() != s {
			t.Errorf("%.30s... came back as %.30s...", s, r.(fmt.Stringer).String())
		}
	}
	text := "# my keys\n\n" + k.x.String() + "\n  " + k.pq.String() + "  \n# the end\n"
	ids, err := ParseIdentities(strings.NewReader(text))
	if err != nil || len(ids) != 2 {
		t.Fatalf("ParseIdentities: %d, %v", len(ids), err)
	}
	if ids[0].(*X25519Identity).String() != k.x.String() || ids[1].(*HybridIdentity).String() != k.pq.String() {
		t.Error("identities did not survive a file")
	}
	rs, err := ParseRecipients(strings.NewReader(k.edPub + k.x.Recipient().String() + "\n"))
	if err != nil || len(rs) != 2 {
		t.Fatalf("ParseRecipients: %d, %v", len(rs), err)
	}
	for _, bad := range []string{"", "# only a comment\n", "AGE-SECRET-KEY-1QQQQ\n"} {
		if _, err := ParseIdentities(strings.NewReader(bad)); err == nil {
			t.Errorf("ParseIdentities(%q) succeeded", bad)
		}
	}
	// A secret key typed into a recipients file is refused without being
	// repeated in the error.
	_, err = ParseRecipients(strings.NewReader(k.x.String() + "\n"))
	if err == nil || strings.Contains(err.Error(), k.x.String()[20:40]) {
		t.Errorf("an identity as a recipient: %v", err)
	}
	if _, err := ParseIdentity(strings.ToLower(k.x.String())); err == nil {
		t.Error("a lowercase secret key was accepted")
	}
}

func TestTheWrongIdentityIsNoMatch(t *testing.T) {
	k := testKeys()
	other, _ := GenerateX25519Identity()
	otherPQ, _ := GenerateHybridIdentity()
	file := encrypt(t, false, []byte("hello"), k.x.Recipient())
	_, err := decrypt(file, false, other, otherPQ, k.ed)
	var nm *NoIdentityMatchError
	if !errors.As(err, &nm) || len(nm.Errors) != 3 || nm.StanzaTypes[0] != "X25519" {
		t.Fatalf("got %v", err)
	}
	// The right one among wrong ones still works.
	if got, err := decrypt(file, false, other, k.x); err != nil || string(got) != "hello" {
		t.Fatalf("got %q, %v", got, err)
	}
	wrongPass, _ := NewScryptIdentity([]byte("nope"))
	pass, _ := NewScryptRecipient([]byte("yes"))
	pass.SetWorkFactor(10)
	if _, err := decrypt(encrypt(t, false, nil, pass), false, wrongPass); !errors.As(err, &nm) {
		t.Fatalf("a wrong passphrase: %v", err)
	}
}

func TestChangingAnyByteIsDetected(t *testing.T) {
	k := testKeys()
	plain := []byte("attack at dawn")
	file := encrypt(t, false, plain, k.x.Recipient())
	for i := range file {
		for _, bit := range []byte{0x01, 0x80} {
			bad := bytes.Clone(file)
			bad[i] ^= bit
			if got, err := decrypt(bad, false, k.x); err == nil {
				t.Fatalf("flipping bit %#x of byte %d went unnoticed (read %q)", bit, i, got)
			}
		}
	}
}

func TestTruncationAndTrailingDataAreDetected(t *testing.T) {
	k := testKeys()
	file := encrypt(t, false, pattern(2*ChunkSize+10), k.pq.Recipient())
	for _, n := range []int{0, 10, 100, len(file) - ChunkSize - 20, len(file) - 20, len(file) - 1} {
		if _, err := decrypt(file[:n], false, k.pq); err == nil {
			t.Errorf("a file cut to %d of %d bytes decrypted", n, len(file))
		}
	}
	// Cut exactly at a chunk boundary: the rest reads as a whole file
	// only if the last-chunk flag is ignored.
	hdr, _ := parseHeader(bufio.NewReader(bytes.NewReader(file)))
	cut := int(hdr.size) + nonceSize + 2*encChunkSize
	if _, err := decrypt(file[:cut], false, k.pq); !errors.Is(err, ErrPayload) {
		t.Errorf("a file cut at a chunk boundary: %v", err)
	}
	if _, err := decrypt(append(bytes.Clone(file), 0), false, k.pq); !errors.Is(err, ErrPayload) {
		t.Errorf("a byte appended: %v", err)
	}
	if _, _, err := DecryptReaderAt(bytes.NewReader(file[:cut]), int64(cut), k.pq); err == nil {
		t.Error("DecryptReaderAt read a file cut at a chunk boundary")
	}
}

func TestPostQuantumAndClassicalRecipientsDoNotMix(t *testing.T) {
	k := testKeys()
	edR, _ := ParseSSHRecipient(k.edPub)
	_, tagPQ := newTagIdentity(t, true)
	for _, rs := range [][]Recipient{
		{k.pq.Recipient(), k.x.Recipient()},
		{k.x.Recipient(), k.pq.Recipient()},
		{k.pq.Recipient(), edR},
		{tagPQ, k.x.Recipient()},
	} {
		if _, err := Encrypt(io.Discard, rs...); !errors.Is(err, ErrIncompatibleRecipients) {
			t.Errorf("%T with %T: %v", rs[0], rs[1], err)
		}
	}
	// Post-quantum with post-quantum, and classical with classical, is fine.
	if _, err := Encrypt(io.Discard, k.pq.Recipient(), tagPQ); err != nil {
		t.Error(err)
	}
	if _, err := Encrypt(io.Discard, k.x.Recipient(), edR); err != nil {
		t.Error(err)
	}
	// Unless the caller allows it.
	file := func() []byte {
		var buf bytes.Buffer
		w, err := Options{AllowMixedPostQuantum: true}.Encrypt(&buf, k.pq.Recipient(), k.x.Recipient())
		if err != nil {
			t.Fatal(err)
		}
		w.Write([]byte("both"))
		w.Close()
		return buf.Bytes()
	}()
	for _, id := range []Identity{k.x, k.pq} {
		if got, err := decrypt(file, false, id); err != nil || string(got) != "both" {
			t.Errorf("%T: %q %v", id, got, err)
		}
	}
}

func TestAPassphraseIsAlwaysTheOnlyRecipient(t *testing.T) {
	k := testKeys()
	p1, _ := NewScryptRecipient([]byte("one"))
	p2, _ := NewScryptRecipient([]byte("two"))
	p1.SetWorkFactor(10)
	p2.SetWorkFactor(10)
	for _, rs := range [][]Recipient{{p1, k.x.Recipient()}, {k.x.Recipient(), p1}, {p1, p2}} {
		if _, err := Encrypt(io.Discard, rs...); !errors.Is(err, ErrIncompatibleRecipients) {
			t.Errorf("%v", err)
		}
	}
	// A header that has one anyway is malformed, whoever reads it.
	fileKey := make([]byte, FileKeySize)
	ps, _ := p1.Wrap(fileKey)
	xs, _ := k.x.Recipient().Wrap(fileKey)
	hdr, err := marshalHeader(append(xs, ps...), func(b []byte) []byte { return headerMAC(fileKey, b) })
	if err != nil {
		t.Fatal(err)
	}
	_, err = Decrypt(bytes.NewReader(append(hdr, make([]byte, 32)...)), k.x)
	if !errors.Is(err, ErrHeader) {
		t.Fatalf("an X25519 identity read a header with a passphrase stanza: %v", err)
	}
}

func TestScryptWorkFactorIsBounded(t *testing.T) {
	p, _ := NewScryptRecipient([]byte("pw"))
	p.SetWorkFactor(12)
	file := encrypt(t, false, []byte("x"), p)
	id, _ := NewScryptIdentity([]byte("pw"))
	id.SetMaxWorkFactor(11)
	if _, err := decrypt(file, false, id); !errors.Is(err, ErrHeader) || !strings.Contains(err.Error(), "limit") {
		t.Fatalf("got %v", err)
	}
	id.SetMaxWorkFactor(12)
	if got, err := decrypt(file, false, id); err != nil || string(got) != "x" {
		t.Fatalf("got %q %v", got, err)
	}
	for _, bad := range []int{0, 31} {
		if p.SetWorkFactor(bad) == nil || id.SetMaxWorkFactor(bad) == nil {
			t.Errorf("work factor %d accepted", bad)
		}
	}
}

// fakeStanzas is a recipient that makes whatever stanzas it is told to.
type fakeStanzas []*Stanza

func (f fakeStanzas) Wrap([]byte) ([]*Stanza, error) { return f, nil }

func TestHeaderLimitsMatchAge(t *testing.T) {
	mac := func([]byte) []byte { return make([]byte, macSize) }
	parse := func(ss []*Stanza) error {
		var b bytes.Buffer
		b.WriteString(versionLine)
		for _, s := range ss {
			s.marshal(&b)
		}
		b.WriteString("--- " + encodeB64(make([]byte, 32)) + "\n")
		_, err := parseHeader(bufio.NewReader(&b))
		return err
	}
	many := func(n int) []*Stanza {
		ss := make([]*Stanza, n)
		for i := range ss {
			ss[i] = &Stanza{Type: "grease", Body: []byte{1}}
		}
		return ss
	}
	if err := parse(many(MaxStanzas)); err != nil {
		t.Errorf("%d stanzas: %v", MaxStanzas, err)
	}
	if err := parse(many(MaxStanzas + 1)); !errors.Is(err, ErrHeader) {
		t.Errorf("%d stanzas: %v", MaxStanzas+1, err)
	}
	if _, err := marshalHeader(many(MaxStanzas+1), mac); err == nil {
		t.Error("marshalHeader wrote too many stanzas")
	}
	args := make([]string, MaxStanzaArgs+1)
	for i := range args {
		args[i] = "a"
	}
	if err := parse([]*Stanza{{Type: "t", Args: args[:MaxStanzaArgs]}}); err != nil {
		t.Errorf("%d arguments: %v", MaxStanzaArgs, err)
	}
	// marshal refuses it, so build the line by hand.
	line := "-> t " + strings.Join(args, " ") + "\n\n"
	if _, err := parseHeader(bufio.NewReader(strings.NewReader(versionLine + line + "--- " + encodeB64(make([]byte, 32)) + "\n"))); !errors.Is(err, ErrHeader) {
		t.Errorf("%d arguments: %v", MaxStanzaArgs+1, err)
	}
	big := []*Stanza{{Type: "big", Body: make([]byte, MaxHeaderSize)}}
	if err := parse(big); !errors.Is(err, ErrHeader) || !strings.Contains(err.Error(), "larger") {
		t.Errorf("a 2 MiB stanza: %v", err)
	}
	if _, err := Encrypt(io.Discard, fakeStanzas(big)); err == nil {
		t.Error("Encrypt wrote a header over the limit")
	}
}

func TestStanzasThatCannotBeWrittenAreRefused(t *testing.T) {
	for _, s := range []*Stanza{
		{Type: "has space"},
		{Type: ""},
		{Type: "ok", Args: []string{""}},
		{Type: "ok", Args: []string{"new\nline"}},
		{Type: "ok", Args: []string{"é"}},
	} {
		if _, err := Encrypt(io.Discard, fakeStanzas{s}); err == nil {
			t.Errorf("%+v was written", s)
		}
	}
	if _, err := Encrypt(io.Discard); err == nil {
		t.Error("no recipients")
	}
	if _, err := Decrypt(strings.NewReader("")); err == nil {
		t.Error("no identities")
	}
}

func TestEncryptedSSHKeysAskForTheirPassphraseOnlyWhenNeeded(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, err := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("open sesame"))
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(blk)
	asked := 0
	id, err := ParseSSHIdentity(pemBytes, func() ([]byte, error) { asked++; return []byte("open sesame"), nil })
	if err != nil {
		t.Fatal(err)
	}
	k := testKeys()
	if _, err := decrypt(encrypt(t, false, []byte("x"), k.x.Recipient()), false, id); err == nil || asked != 0 {
		t.Fatalf("a file for someone else: asked %d times, %v", asked, err)
	}
	pub, _ := ssh.NewPublicKey(priv.Public())
	r, _ := NewSSHRecipient(pub)
	if got, err := decrypt(encrypt(t, false, []byte("mine"), r), false, id); err != nil || string(got) != "mine" || asked != 1 {
		t.Fatalf("a file for this key: %q, asked %d times, %v", got, asked, err)
	}
	if _, err := ParseSSHIdentity(pemBytes, nil); err == nil {
		t.Error("an encrypted key without a way to ask for its passphrase")
	}
}

func TestEd25519KeysMapToTheirX25519Keys(t *testing.T) {
	// Mapping the public key must agree with deriving from the private
	// key, which is how the identity side gets there.
	for range 20 {
		pub, priv, _ := ed25519.GenerateKey(rand.Reader)
		u, err := ed25519ToX25519(pub)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := NewSSHEd25519Identity(priv)
		if !bytes.Equal(u, id.priv.PublicKey().Bytes()) {
			t.Fatal("the public mapping and the private derivation disagree")
		}
	}
	// y = 1 is the identity point; a y with no x is not on the curve.
	one := make([]byte, 32)
	one[0] = 1
	if _, err := ed25519ToX25519(one); err == nil {
		t.Error("the identity point was accepted")
	}
	two := make([]byte, 32)
	two[0] = 2
	if _, err := ed25519ToX25519(two); err == nil {
		t.Error("y = 2, which is not on the curve, was accepted")
	}
}

func TestP256PointsDecompress(t *testing.T) {
	for range 20 {
		k, _ := ecdh.P256().GenerateKey(rand.Reader)
		u := k.PublicKey().Bytes()
		got, err := decompressP256(append([]byte{2 | u[64]&1}, u[1:33]...))
		if err != nil || !bytes.Equal(got, u) {
			t.Fatalf("decompress: %v", err)
		}
	}
	// About half of all x have no point; whatever does decompress must
	// be a point crypto/ecdh accepts.
	refused := 0
	for x := int64(1); x <= 20; x++ {
		c := make([]byte, 33)
		c[0] = 2
		big.NewInt(x).FillBytes(c[1:])
		u, err := decompressP256(c)
		if err != nil {
			refused++
			continue
		}
		if _, err := ecdh.P256().NewPublicKey(u); err != nil {
			t.Errorf("x = %d decompressed to a point off the curve", x)
		}
	}
	if refused == 0 {
		t.Error("every x decompressed")
	}
}
