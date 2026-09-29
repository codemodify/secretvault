package svgpgagent

import (
	"bufio"
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svpgp"
)

// The server against a backend of the test's own: a version 4 key made by
// svpgp (Ed25519, with a Curve25519 subkey), and a pretend RSA key whose
// answers are fixed, to see how they are written.

type testBackend struct {
	key   *svpgp.Key
	parts map[string]svpgp.KeyPart // by hex keygrip
	rsa   []byte                   // the pretend RSA key's keygrip
	calls []string
}

var errDenied = Errorf(CodeCanceled, "the person said no")

func newTestBackend(t *testing.T) *testBackend {
	t.Helper()
	k, err := svpgp.GenerateKey(svpgp.KeyOptions{Version: 4, UserIDs: []string{"Test <test@example.org>"}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(k.Close)
	b := &testBackend{key: k, parts: map[string]svpgp.KeyPart{}, rsa: bytes.Repeat([]byte{0xAB}, 20)}
	for _, p := range k.Parts() {
		grip, err := Keygrip(p.Algorithm, p.Public)
		if err != nil {
			t.Fatal(err)
		}
		b.parts[hex.EncodeToString(grip)] = p
	}
	return b
}

func (b *testBackend) grip(alg svpgp.PublicKeyAlgorithm) []byte {
	for g, p := range b.parts {
		if p.Algorithm == alg {
			grip, _ := hex.DecodeString(g)
			return grip
		}
	}
	return nil
}

func (b *testBackend) Keys() ([]Key, error) {
	var out []Key
	for g := range b.parts {
		grip, _ := hex.DecodeString(g)
		k, _ := b.Key(grip)
		out = append(out, k)
	}
	return out, nil
}

func (b *testBackend) Key(grip []byte) (Key, error) {
	if bytes.Equal(grip, b.rsa) {
		return Key{Keygrip: grip, Algorithm: svpgp.RSA, Public: svpgp.PublicMaterial{N: bytes.Repeat([]byte{0xC5}, 256), E: []byte{1, 0, 1}}}, nil
	}
	p, ok := b.parts[hex.EncodeToString(grip)]
	if !ok {
		return Key{}, ErrNoKey
	}
	return Key{Keygrip: grip, Algorithm: p.Algorithm, Public: p.Public, Confirm: p.Primary}, nil
}

func (b *testBackend) Sign(grip []byte, h svpgp.HashAlgorithm, digest []byte) ([][]byte, error) {
	b.calls = append(b.calls, "sign")
	if bytes.Equal(grip, b.rsa) {
		return [][]byte{{0x80, 1, 2, 3}}, nil
	}
	if bytes.Equal(digest, make([]byte, len(digest))) {
		return nil, errDenied // a digest of zeros stands for a refusal
	}
	return b.key.SignDigest(b.parts[hex.EncodeToString(grip)].Fingerprint, h, digest)
}

func (b *testBackend) Decrypt(grip []byte, data []byte) ([]byte, error) {
	b.calls = append(b.calls, "decrypt")
	if bytes.Equal(grip, b.rsa) {
		return []byte{9, 'k', 'e', 'y', 0, 0x42}, nil
	}
	return b.key.SharedPoint(b.parts[hex.EncodeToString(grip)].Fingerprint, data)
}

// client is the test's end of a connection.
type client struct {
	t    *testing.T
	r    *bufio.Reader
	out  chan []byte
	done chan error
}

func dial(t *testing.T, b Backend, cfg Config) *client {
	t.Helper()
	a, z := net.Pipe()
	c := &client{t: t, r: bufio.NewReader(a), out: make(chan []byte, 64), done: make(chan error, 1)}
	go func() { c.done <- Serve(z, b, cfg); z.Close() }()
	// net.Pipe does not buffer: the test writes from a goroutine of its
	// own, so that the server can answer a line it has not read to the end.
	go func() {
		for p := range c.out {
			a.SetWriteDeadline(time.Now().Add(5 * time.Second))
			a.Write(p)
		}
	}()
	t.Cleanup(func() { close(c.out); a.Close() })
	a.SetReadDeadline(time.Now().Add(10 * time.Second))
	if l := c.line(); !strings.HasPrefix(l, "OK Pleased to meet you, process ") {
		t.Fatalf("greeting %q", l)
	}
	return c
}

func (c *client) send(s string) { c.out <- []byte(s + "\n") }

func (c *client) line() string {
	c.t.Helper()
	l, err := c.r.ReadString('\n')
	if err != nil {
		c.t.Fatalf("reading: %v (got %q)", err, l)
	}
	return strings.TrimSuffix(l, "\n")
}

// answer is what a command got: its data, status lines and final line.
type answer struct {
	data   []byte
	status []string
	final  string
}

// read reads up to OK, ERR or INQUIRE.
func (c *client) read() answer {
	c.t.Helper()
	var a answer
	for {
		l := c.line()
		switch {
		case strings.HasPrefix(l, "D "):
			a.data = append(a.data, unescapeLine(l[2:])...)
		case strings.HasPrefix(l, "S "):
			a.status = append(a.status, l[2:])
		case strings.HasPrefix(l, "#"):
		default:
			a.final = l
			return a
		}
	}
}

func unescapeLine(s string) []byte { return appendUnescaped(nil, []byte(s)) }

func (c *client) do(cmd string) answer {
	c.t.Helper()
	c.send(cmd)
	return c.read()
}

func (c *client) ok(cmd string) answer {
	c.t.Helper()
	a := c.do(cmd)
	if !strings.HasPrefix(a.final, "OK") {
		c.t.Fatalf("%s: %s", cmd, a.final)
	}
	return a
}

// fails checks that cmd is answered ERR with the code.
func (c *client) fails(cmd string, code int) answer {
	c.t.Helper()
	a := c.do(cmd)
	if want := fmt.Sprintf("ERR %d ", sourceAgent|code); !strings.HasPrefix(a.final, want) {
		c.t.Fatalf("%s: %q, want %q...", cmd, a.final, want)
	}
	return a
}

var cfg = Config{Version: "2.99.0-test", PID: 42, Socket: "/run/test/gpg-agent.sock"}

func TestTheConversationGPGHas(t *testing.T) {
	b := newTestBackend(t)
	c := dial(t, b, cfg)
	c.ok("RESET")
	c.ok("OPTION ttyname=/dev/pts/1")
	c.ok("OPTION putenv=DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/1000/bus")
	c.ok("OPTION --display :0")
	c.ok("OPTION allow-pinentry-notify")
	if a := c.ok("GETINFO version"); string(a.data) != cfg.Version {
		t.Fatalf("version %q", a.data)
	}
	if a := c.ok("getinfo pid"); string(a.data) != "42" {
		t.Fatalf("pid %q", a.data)
	}
	if a := c.ok("GETINFO socket_name"); string(a.data) != cfg.Socket {
		t.Fatalf("socket %q", a.data)
	}
	c.fails("GETINFO ssh_socket_name", CodeNoData)
	c.ok("GETINFO cmd_has_option GET_PASSPHRASE repeat")
	c.fails("GETINFO cmd_has_option GET_PASSPHRASE newsymkey", CodeFalse)
	c.fails("GETINFO restricted", CodeFalse)
	c.fails("GETINFO getenv HOME", CodeNotSupported)
	c.fails("AGENT_ID", codeUnknownCmd) // gnome-keyring's; gpg checks for hijacking

	ed, cv := b.grip(svpgp.EdDSALegacy), b.grip(svpgp.ECDH)
	edHex, cvHex := strings.ToUpper(hex.EncodeToString(ed)), strings.ToUpper(hex.EncodeToString(cv))
	if a := c.ok("HAVEKEY --list=1000"); len(a.data) != 40 || !bytes.Contains(a.data, ed) || !bytes.Contains(a.data, cv) {
		t.Fatalf("HAVEKEY --list: % x", a.data)
	}
	c.fails("HAVEKEY --list=1", 154)
	c.ok("HAVEKEY " + strings.Repeat("00", 20) + " " + edHex)
	c.fails("HAVEKEY "+strings.Repeat("00", 20), CodeNoSecretKey)
	c.fails("HAVEKEY 1234", codeParameter)
	if a := c.ok("HAVEKEY --info " + cvHex); len(a.status) != 1 || a.status[0] != "KEYFILEINFO unknown" {
		t.Fatalf("HAVEKEY --info: %q", a.status)
	}
	if a := c.ok("KEYINFO " + edHex); len(a.status) != 1 || a.status[0] != "KEYINFO "+edHex+" D - - - - - - c" {
		t.Fatalf("KEYINFO: %q", a.status)
	}
	if a := c.ok("KEYINFO --data " + cvHex); string(a.data) != cvHex+" D - - - - - - -\n" {
		t.Fatalf("KEYINFO --data: %q", a.data)
	}
	if a := c.ok("KEYINFO --list"); len(a.status) != 2 {
		t.Fatalf("KEYINFO --list: %q", a.status)
	}
	c.fails("KEYINFO "+strings.Repeat("11", 20), CodeNotFound)
	c.ok("KEYINFO --ssh-list")

	// READKEY: the public key as gpg-agent writes it.
	a := c.ok("READKEY -- " + edHex)
	pk, err := parseSexp(a.data)
	if err != nil || pk.name() != "public-key" {
		t.Fatalf("READKEY: %q %v", a.data, err)
	}
	ecc := pk.find("ecc")
	curve, _ := ecc.find("curve").value()
	flags, _ := ecc.find("flags").value()
	q, _ := ecc.find("q").value()
	if string(curve) != "Ed25519" || string(flags) != "eddsa" || len(q) != 33 || q[0] != 0x40 {
		t.Fatalf("READKEY: %q", a.data)
	}
	c.fails("READKEY --format=ssh "+edHex, CodeNotSupported)

	// Signing: the digest, then the signature, which verifies.
	digest := sha256.Sum256([]byte("hello"))
	c.ok("SIGKEY " + edHex)
	c.ok("SETKEYDESC Please+enter+the+passphrase%0A")
	c.ok("SETHASH 8 " + hex.EncodeToString(digest[:]))
	a = c.ok("PKSIGN")
	sig, err := parseSexp(a.data)
	if err != nil || sig.name() != "sig-val" {
		t.Fatalf("PKSIGN: %q %v", a.data, err)
	}
	r, _ := sig.find("eddsa").find("r").value()
	s, _ := sig.find("eddsa").find("s").value()
	if !ed25519.Verify(ed25519.PublicKey(q[1:]), digest[:], append(append([]byte{}, r...), s...)) {
		t.Fatalf("the signature does not verify: %q", a.data)
	}
	// The key the backend refuses: gpg hears that it was cancelled.
	c.ok("SETHASH --hash=sha256 " + strings.Repeat("00", 32))
	c.fails("PKSIGN", CodeCanceled)
	// Signing with the encryption subkey is the backend's to refuse.
	c.ok("SIGKEY " + cvHex)
	c.ok("SETHASH 8 " + hex.EncodeToString(digest[:]))
	c.fails("PKSIGN", CodeNotSupported)

	// Decrypting: the ciphertext asked for, the shared point back.
	eph, _ := ecdh.X25519().GenerateKey(nil)
	var rcpt []byte
	for _, p := range b.key.Parts() {
		if p.Algorithm == svpgp.ECDH {
			rcpt = p.Public.Point[1:]
		}
	}
	rp, _ := ecdh.X25519().NewPublicKey(rcpt)
	want, _ := eph.ECDH(rp)
	ct := list(atom([]byte("enc-val")), list(atom([]byte("ecdh")), param("s", []byte{1, 2}), param("e", append([]byte{0x40}, eph.PublicKey().Bytes()...))))
	c.ok("SETKEY " + cvHex)
	c.send("PKDECRYPT")
	if a := c.read(); a.final != "INQUIRE CIPHERTEXT" || len(a.status) != 1 || a.status[0] != "INQUIRE_MAXLEN 4096" {
		t.Fatalf("PKDECRYPT asked %+v", a)
	}
	c.send("D " + string(escapeData(ct[:10])))
	c.send("D " + string(escapeData(ct[10:])))
	c.send("END")
	a = c.read()
	if !strings.HasPrefix(a.final, "OK") || len(a.status) != 0 {
		t.Fatalf("PKDECRYPT: %+v", a)
	}
	if exp := param("value", append([]byte{0x40}, want...)); !bytes.Equal(a.data, exp) {
		t.Fatalf("PKDECRYPT gave %x, want %x", a.data, exp)
	}

	// RSA: the padding already gone, and said so.
	rsaHex := hex.EncodeToString(b.rsa)
	c.ok("SETKEY " + rsaHex)
	c.send("PKDECRYPT")
	c.read()
	c.send("D " + string(escapeData(list(atom([]byte("enc-val")), list(atom([]byte("rsa")), param("a", bytes.Repeat([]byte{7}, 256)))))))
	c.send("END")
	a = c.read()
	if !strings.HasPrefix(a.final, "OK") || len(a.status) != 1 || a.status[0] != "PADDING 0" || string(a.data) != "(5:value6:\tkey\x00B)" {
		t.Fatalf("RSA PKDECRYPT: %+v", a)
	}
	// ... and its signatures written as libgcrypt writes an integer.
	c.ok("SIGKEY " + rsaHex)
	c.ok("SETHASH 10 " + strings.Repeat("11", 64))
	if a := c.ok("PKSIGN"); string(a.data) != "(7:sig-val(3:rsa(1:s5:\x00\x80\x01\x02\x03)))" {
		t.Fatalf("RSA PKSIGN: %q", a.data)
	}

	c.ok("NOP")
	c.send("# a comment is not answered")
	c.send("")
	c.ok("nop")
	c.send("BYE")
	if l := c.line(); !strings.HasPrefix(l, "OK") {
		t.Fatalf("BYE: %q", l)
	}
	if err := <-c.done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
}

// escapeData escapes bytes for a D line.
func escapeData(p []byte) []byte {
	var out []byte
	for _, c := range p {
		if c == '%' || c == '\r' || c == '\n' || c == '\\' {
			out = append(out, fmt.Sprintf("%%%02X", c)...)
		} else {
			out = append(out, c)
		}
	}
	return out
}

func TestWhatIsRefused(t *testing.T) {
	c := dial(t, newTestBackend(t), cfg)
	for _, cmd := range []string{"GENKEY", "IMPORT_KEY", "KEYWRAP_KEY --import", "EXPORT_KEY " + strings.Repeat("00", 20),
		"DELETE_KEY " + strings.Repeat("00", 20), "PASSWD " + strings.Repeat("00", 20), "SCD SERIALNO", "LEARN --sendinfo",
		"KEYTOCARD", "PRESET_PASSPHRASE x -1 00", "GET_CONFIRMATION sure?", "MARKTRUSTED " + strings.Repeat("00", 20) + " S x",
		"GET_SECRET x", "PUT_SECRET x", "GETVAL x", "PUTVAL x y", "INPUT FD=3", "SETHASH --inquire", "SETHASH --pss --inquire"} {
		c.fails(cmd, CodeNotSupported)
	}
	c.fails("ISTRUSTED "+strings.Repeat("AB", 20), CodeNotTrusted)
	c.fails("ISTRUSTED nothex", codeParameter)
	c.ok("LISTTRUSTED")
	if a := c.ok("KILLAGENT"); a.final != "OK secretvaultd keeps running" {
		t.Fatalf("KILLAGENT: %q", a.final)
	}
	c.ok("UPDATESTARTUPTTY")
	c.ok("CLEAR_PASSPHRASE --mode=normal abc")
}

func TestJunkIsAnsweredAndTheConnectionGoesOn(t *testing.T) {
	c := dial(t, newTestBackend(t), cfg)
	grip := strings.Repeat("00", 20)
	for cmd, code := range map[string]int{
		"FROBNICATE":                  codeUnknownCmd,
		"\x00\x01\xff binary":         codeUnknownCmd,
		" NOP":                        codeSyntax,
		"OPTION":                      codeSyntax,
		"OPTION =x":                   codeSyntax,
		"OPTION -x":                   codeSyntax,
		"OPTION name=":                codeSyntax,
		"D stray data":                codeUnexpectedCmd,
		"END":                         CodeNotImplemented,
		"GETINFO nothing":             codeParameter,
		"GETINFO cmd_has_option":      CodeInvalidValue,
		"SIGKEY":                      codeParameter,
		"SIGKEY zz" + grip[2:]:        codeParameter,
		"SETKEY " + grip + "00":       codeParameter,
		"SETKEYDESC":                  codeParameter,
		"SETHASH":                     CodeUnsupportedAlg,
		"SETHASH 999 " + grip:         CodeUnsupportedAlg,
		"SETHASH 8 abc":               codeParameter,
		"SETHASH 8 " + grip + "00":    codeParameter,
		"SETHASH --hash=whirlpool 00": codeParameter,
		"READKEY":                     codeParameter,
		"READKEY --card " + grip:      CodeNotSupported,
		"HAVEKEY":                     codeParameter,
		"KEYINFO":                     codeParameter,
		"GET_PASSPHRASE":              codeParameter,
		"GET_PASSPHRASE --no-ask x":   CodeNoData,
		"GET_PASSPHRASE --data x":     CodeNoPinentry,
		"PKSIGN":                      CodeNoSecretKey,
	} {
		c.fails(cmd, code)
	}
	c.ok("SIGKEY " + grip)
	c.fails("PKSIGN", CodeNoData) // no digest yet
	c.ok("SETHASH 8 " + strings.Repeat("11", 32))
	c.fails("PKSIGN", CodeNoSecretKey) // no such key
	c.ok("SETHASH 2 " + strings.Repeat("11", 20))
	c.ok("RESET")
	c.fails("PKSIGN", CodeNoSecretKey)
	c.ok("NOP")
}

// inquire runs PKDECRYPT, answering its inquiry with lines, and returns
// the answer.
func (c *client) pkdecrypt(lines ...string) answer {
	c.t.Helper()
	c.send("PKDECRYPT")
	if a := c.read(); a.final != "INQUIRE CIPHERTEXT" {
		c.t.Fatalf("PKDECRYPT: %+v", a)
	}
	for _, l := range lines {
		c.send(l)
	}
	return c.read()
}

func TestBadCiphertextsAreRefused(t *testing.T) {
	b := newTestBackend(t)
	c := dial(t, b, cfg)
	enc := func(elems ...[]byte) string {
		return "D " + string(escapeData(list(append([][]byte{atom([]byte("enc-val"))}, elems...)...)))
	}
	ecdhE := func(e []byte) []byte { return list(atom([]byte("ecdh")), param("s", []byte{1}), param("e", e)) }
	cvHex := hex.EncodeToString(b.grip(svpgp.ECDH))
	edHex := hex.EncodeToString(b.grip(svpgp.EdDSALegacy))

	// No key set: asked for the ciphertext all the same, as gpg-agent does.
	if a := c.pkdecrypt(enc(ecdhE(make([]byte, 33))), "END"); !strings.HasPrefix(a.final, fmt.Sprintf("ERR %d", sourceAgent|CodeNoSecretKey)) {
		t.Fatalf("without SETKEY: %q", a.final)
	}
	c.ok("SETKEY " + cvHex)
	low := append([]byte{0x40}, make([]byte, 32)...) // a point of small order: the shared secret is zero
	for name, tc := range map[string]struct {
		lines []string
		code  int
	}{
		"canceled":          {[]string{"D (7:enc-val", "CAN"}, codeAssCanceled},
		"a command instead": {[]string{"NOP"}, codeUnexpectedCmd},
		"too much":          {append(slicesRepeat("D "+strings.Repeat("A", 900), 5), "END"), codeTooMuchData},
		"not canonical":     {[]string{"D (enc-val (ecdh (e #40#)))", "END"}, CodeInvalidSexp},
		"a display hint":    {[]string{"D (7:enc-val[1:x]1:y)", "END"}, CodeInvalidSexp},
		"trailing bytes":    {[]string{enc(ecdhE(low)) + "junk", "END"}, CodeInvalidSexp},
		"a leading zero":    {[]string{"D (07:enc-val)", "END"}, CodeInvalidSexp},
		"a length too long": {[]string{"D (99:enc-val)", "END"}, CodeInvalidSexp},
		"unclosed":          {[]string{"D (7:enc-val(4:ecdh", "END"}, CodeInvalidSexp},
		"too deep":          {[]string{"D " + strings.Repeat("(", 20) + "1:x" + strings.Repeat(")", 20), "END"}, CodeInvalidSexp},
		"another list":      {[]string{"D (7:sig-val)", "END"}, CodeInvalidSexp},
		"no algorithm":      {[]string{enc(), "END"}, CodeInvalidSexp},
		"two algorithms":    {[]string{enc(ecdhE(low), ecdhE(low)), "END"}, CodeInvalidSexp},
		"an unknown flag":   {[]string{enc(list(atom([]byte("flags")), atom([]byte("oaep"))), ecdhE(low)), "END"}, CodeNotSupported},
		"ElGamal":           {[]string{enc(list(atom([]byte("elg")), param("a", []byte{1}), param("b", []byte{1}))), "END"}, CodeNotSupported},
		"RSA for ECDH":      {[]string{enc(list(atom([]byte("rsa")), param("a", []byte{1}))), "END"}, CodeNotSupported},
		"no point":          {[]string{enc(list(atom([]byte("ecdh")), param("s", []byte{1}))), "END"}, CodeInvalidSexp},
		"a bad point":       {[]string{enc(ecdhE([]byte{0x40, 1, 2})), "END"}, CodeDecryptFailed},
		"a low-order point": {[]string{enc(ecdhE(low)), "END"}, CodeDecryptFailed},
	} {
		a := c.pkdecrypt(tc.lines...)
		if want := fmt.Sprintf("ERR %d ", sourceAgent|tc.code); !strings.HasPrefix(a.final, want) {
			t.Fatalf("%s: %q, want %q", name, a.final, want)
		}
	}
	// A signing key does not decrypt.
	c.ok("SETKEY " + edHex)
	if a := c.pkdecrypt(enc(ecdhE(low)), "END"); !strings.Contains(a.final, fmt.Sprint(sourceAgent|CodeNotSupported)) {
		t.Fatalf("ECDH with the signing key: %q", a.final)
	}
	c.ok("NOP")
}

func slicesRepeat(s string, n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = s
	}
	return out
}

func TestALineTooLongEndsTheConnection(t *testing.T) {
	c := dial(t, newTestBackend(t), cfg)
	c.send("NOP " + strings.Repeat("x", 2000))
	if l := c.line(); !strings.HasPrefix(l, fmt.Sprintf("ERR %d ", sourceAgent|codeLineTooLong)) {
		t.Fatalf("a long line: %q", l)
	}
	if err := <-c.done; !errors.Is(err, errLineTooLong) {
		t.Fatalf("Serve: %v", err)
	}
	// A line of exactly 1000 bytes is fine.
	c = dial(t, newTestBackend(t), cfg)
	c.ok("NOP " + strings.Repeat("x", maxLine-4))
}

func TestAConnectionThatGoesAwayEndsServing(t *testing.T) {
	a, z := net.Pipe()
	done := make(chan error, 1)
	go func() { done <- Serve(z, newTestBackend(t), cfg) }()
	r := bufio.NewReader(a)
	r.ReadString('\n')
	go a.Write([]byte("SETKEY " + strings.Repeat("00", 20) + "\nPKDECRYPT\n"))
	r.ReadString('\n') // OK
	r.ReadString('\n') // S INQUIRE_MAXLEN
	r.ReadString('\n') // INQUIRE
	a.Close()
	select {
	case err := <-done:
		if err == nil || errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
			t.Fatalf("Serve after a hang-up mid-inquiry: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Serve did not return")
	}
}

func TestPassphrasesOnlyLoopBack(t *testing.T) {
	c := dial(t, newTestBackend(t), cfg)
	// Without loopback nobody is asked on gpg's behalf.
	c.fails("GET_PASSPHRASE --data --repeat=1 -- sym X X X", CodeNoPinentry)
	c.ok("OPTION pinentry-mode=loopback")
	c.send("GET_PASSPHRASE --data --repeat=1 -- sym X X X")
	if a := c.read(); a.final != "INQUIRE PASSPHRASE" || a.status[0] != "INQUIRE_MAXLEN 255" {
		t.Fatalf("GET_PASSPHRASE: %+v", a)
	}
	c.send("D pass%25word%0A")
	c.send("END")
	if a := c.read(); !strings.HasPrefix(a.final, "OK") || string(a.data) != "pass%word\n" {
		t.Fatalf("GET_PASSPHRASE: %+v", a)
	}
	// Without --data the answer is the OK line, in hex.
	c.send("GET_PASSPHRASE sym X X X")
	c.read()
	c.send("D abc")
	c.send("END")
	if a := c.read(); a.final != "OK 616263" {
		t.Fatalf("GET_PASSPHRASE: %+v", a)
	}
	c.send("GET_PASSPHRASE --data sym")
	c.read()
	c.send("D " + strings.Repeat("p", 300))
	c.send("END")
	if a := c.read(); !strings.HasPrefix(a.final, fmt.Sprintf("ERR %d", sourceAgent|codeTooMuchData)) {
		t.Fatalf("a long passphrase: %q", a.final)
	}
	c.ok("OPTION pinentry-mode=ask")
	c.fails("GET_PASSPHRASE --data sym", CodeNoPinentry)
}

func TestSexpReading(t *testing.T) {
	for in, ok := range map[string]bool{
		"(1:a)":                 true,
		"(1:a(2:bc)0:)":         true,
		"3:abc":                 true,
		"(1:a":                  false,
		"1:a)":                  false,
		"(1:ab)":                false,
		"(01:a)":                false,
		"(-1:a)":                false,
		"(+1:a)":                false,
		"(a)":                   false,
		"()extra":               false,
		"":                      false,
		"(1234567890:a)":        false,
		"([4:text]1:a)":         false,
		"(1:a)(1:b)":            false,
		"(((((((((1:a)))))))))": false,
	} {
		if _, err := parseSexp([]byte(in)); (err == nil) != ok {
			t.Errorf("%q: %v", in, err)
		}
	}
	if got := string(mpi([]byte{0, 0, 0x7f})); got != "\x7f" {
		t.Errorf("mpi(0x7f) = %q", got)
	}
	if got := string(mpi([]byte{0xff})); got != "\x00\xff" {
		t.Errorf("mpi(0xff) = %q", got)
	}
}

func FuzzSexp(f *testing.F) {
	f.Add([]byte("(7:enc-val(4:ecdh(1:s1:x)(1:e2:ab)))"))
	f.Add([]byte("(3:rsa(1:a3:abc))"))
	f.Fuzz(func(t *testing.T, b []byte) {
		e, err := parseSexp(b)
		if err != nil {
			return
		}
		e.name()
		e.find("x").value()
	})
}

// FuzzServe feeds anything to the server: it must answer or hang up, and
// never panic.
func FuzzServe(f *testing.F) {
	f.Add([]byte("GETINFO version\nSIGKEY 0000000000000000000000000000000000000000\nSETHASH 8 00\nPKSIGN\n"))
	f.Add([]byte("PKDECRYPT\nD (7:enc-val\nEND\nOPTION a=b\n"))
	f.Add([]byte("GET_PASSPHRASE x\n\x00\xff\n"))
	b := &testBackend{parts: map[string]svpgp.KeyPart{}, rsa: bytes.Repeat([]byte{0xAB}, 20)}
	f.Fuzz(func(t *testing.T, in []byte) {
		var out bytes.Buffer
		Serve(struct {
			io.Reader
			io.Writer
		}{bytes.NewReader(in), &out}, b, cfg)
	})
}
