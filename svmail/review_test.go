package svmail

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svpgp"
)

// Attacks and edge cases found in review: each would once have made a
// report say more than the message proves.

// Any opaque signed message Alice ever sent, put in the signature part of
// a multipart/signed next to someone else's text, must not sign that
// text.
func TestSMIMEAttachedContentInDetachedSignature(t *testing.T) {
	p := getPKI(t)
	alice := p.user(t, "alice@example.org")
	der, err := svcms.Sign([]byte("hello"), alice.key, []*x509.Certificate{alice.cert, p.inter}, svcms.SignOptions{Attached: true})
	if err != nil {
		t.Fatal(err)
	}
	msg := "From: alice@example.org\r\nSubject: urgent\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"b\"\r\n\r\n" +
		"--b\r\nContent-Type: text/plain\r\n\r\nWire the money to account 1234.\r\n--b\r\n" +
		"Content-Type: application/pkcs7-signature\r\nContent-Transfer-Encoding: base64\r\n\r\n" +
		base64.StdEncoding.EncodeToString(der) + "\r\n--b--\r\n"
	r := inspect(t, []byte(msg), &LocalKeys{Roots: []*x509.Certificate{p.root}})
	if r.Signed != CoverNone || len(r.Layers[0].Signatures) != 0 || r.Layers[0].Error == "" || !hasWarning(r, WarnVerification) {
		t.Fatalf("\n%s", dump(r))
	}
	for _, part := range r.Parts {
		if len(part.SignedBy) > 0 {
			t.Fatalf("part %s is marked signed", part.Part)
		}
	}
}

// literalBlock is an armored OpenPGP message holding only literal data:
// neither signed nor encrypted.
func literalBlock(text string) string {
	body := append([]byte{'u', 0, 0, 0, 0, 0}, text...)
	pkt := append([]byte{0xCB, byte(len(body))}, body...)
	var out bytes.Buffer
	w, _ := svpgp.ArmorWriter(&out, svpgp.BlockMessage, true)
	w.Write(pkt)
	w.Close()
	return out.String()
}

func TestUnsignedArmor(t *testing.T) {
	msg := "From: alice@example.org\r\nContent-Type: text/plain\r\n\r\n" + literalBlock("Trust me.\n")
	r := inspect(t, []byte(msg), nil)
	if len(r.Layers) != 0 || r.Signed != CoverNone || !hasWarning(r, WarnUnprotectedText) {
		t.Fatalf("\n%s", dump(r))
	}

	// An unreadable signature part signs nothing either.
	alice := pgpKey(t, "Alice <alice@example.org>")
	out, err := SignPGPMIME([]byte(testMessage), alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	bad := bytes.Replace(out, []byte("Content-Type: application/pgp-signature;"), []byte("Content-Transfer-Encoding: x-unknown\r\nContent-Type: application/pgp-signature;"), 1)
	r = inspect(t, bad, &LocalKeys{PGP: []*svpgp.Key{alice.Public()}})
	if r.Signed != CoverNone || r.Layers[0].Error == "" || !hasWarning(r, WarnVerification) {
		t.Fatalf("\n%s", dump(r))
	}
	for _, part := range r.Parts {
		if len(part.SignedBy) > 0 {
			t.Fatalf("part %s is marked signed", part.Part)
		}
	}

	// Plain literal data in a multipart/encrypted is not decrypted.
	enc := "From: alice@example.org\r\nMIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"e\"\r\n\r\n" +
		"--e\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--e\r\nContent-Type: application/octet-stream\r\n\r\n" +
		literalBlock("Content-Type: text/plain\r\n\r\nnot secret\r\n") + "\r\n--e--\r\n"
	k := &refusingKeys{}
	r = inspect(t, []byte(enc), k)
	if r.Layers[0].Encryption.Decrypted || r.Layers[0].Error == "" || k.req != nil {
		t.Fatalf("\n%s", dump(r))
	}
}

func TestLongFoldedHeader(t *testing.T) {
	var b strings.Builder
	b.WriteString("X-Long: a\r\n")
	for range 240000 {
		b.WriteString(" b\r\n")
	}
	b.WriteString("\r\nbody")
	start := time.Now()
	p, err := ParseMessage([]byte(b.String()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("parsing took %v", d)
	}
	if v := p.Header.Get("X-Long"); len(v) != 1+2*240000 || string(p.Body) != "body" {
		t.Fatalf("value of %d bytes, body %q", len(v), p.Body)
	}
	// A continuation after a line that is not a field belongs to neither.
	p, _ = ParseMessage([]byte("Subject: s\r\nnot a field\r\n continued\r\nTo: t\r\n\r\n"), nil)
	if p.Header.Get("Subject") != "s" || string(p.Header[0].Raw) != "Subject: s\r\n" || p.Header.Get("To") != "t" || len(p.Problems) != 1 {
		t.Fatalf("%+v %q", p.Header, p.Problems)
	}
}

func TestComposeTransportSafety(t *testing.T) {
	alice := pgpKey(t, "Alice <alice@example.org>")
	// Quoted-printable that some encoder left unsafe: a line starting
	// "From ", trailing white space, and a header with trailing space.
	msg := "From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nBcc: secret@example.org\r\nSubject: s\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\nContent-Transfer-Encoding: quoted-printable\r\nX-Note: trailing \r\n\r\n" +
		"From here on   \r\nGr=C3=BC=C3=9Fe\r\n"
	for _, protect := range []bool{false, true} {
		out, err := SignPGPMIME([]byte(msg), alice, &ComposeOptions{ProtectHeaders: protect})
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(out, []byte("secret@example.org")) || bytes.Contains(bytes.ToLower(out), []byte("bcc:")) {
			t.Fatal("Bcc went out in the message")
		}
		root, _ := ParseMessage(out, nil)
		signed := root.Parts[0].Raw
		for _, line := range strings.Split(string(signed), "\r\n") {
			if strings.HasPrefix(line, "From ") || strings.HasSuffix(line, " ") || strings.HasSuffix(line, "\t") {
				t.Fatalf("unsafe line %q in\n%s", line, signed)
			}
		}
		r := inspect(t, out, &LocalKeys{PGP: []*svpgp.Key{alice.Public()}})
		if r.Layers[0].Signatures[0].Status != StatusValid || textOf(r) != "From here on\nGrüße\n" {
			t.Fatalf("\n%s", dump(r))
		}
	}
	bob := pgpKey(t, "Bob <bob@example.org>")
	out, err := EncryptPGPMIME([]byte(msg), []*svpgp.Key{bob.Public()}, nil, &ComposeOptions{ProtectHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	r := inspect(t, out, &LocalKeys{PGP: []*svpgp.Key{bob}})
	if bytes.Contains(out, []byte("secret@example.org")) || bytes.Contains(r.Content.Raw, []byte("secret@example.org")) {
		t.Fatal("Bcc went out in the message")
	}
}

func TestAmbiguousFrom(t *testing.T) {
	alice := pgpKey(t, "Alice <alice@example.org>")
	msg := strings.Replace(testMessage, "From: Alice <alice@example.org>", "From: ceo@corp.example <alice@example.org>", 1)
	out, err := SignPGPMIME([]byte(msg), alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := inspect(t, out, &LocalKeys{PGP: []*svpgp.Key{alice.Public()}})
	if r.Headers.FromAddress != "" || r.Layers[0].Signatures[0].SenderMatch {
		t.Fatalf("\n%s", dump(r))
	}
	msg = strings.Replace(testMessage, "From: Alice <alice@example.org>", "From: alice@example.org, mallory@example.org", 1)
	out, _ = SignPGPMIME([]byte(msg), alice, nil)
	if r := inspect(t, out, nil); r.Headers.FromAddress != "" {
		t.Fatalf("two authors gave %q", r.Headers.FromAddress)
	}
}
