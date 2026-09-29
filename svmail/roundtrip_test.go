package svmail

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svpgp"
)

// What this package writes, it reads: every outgoing form, inspected with
// the right keys, the wrong ones and none, and changed after sending.

func checkBody(t *testing.T, r *Report, signed, encrypted bool) {
	t.Helper()
	if got := textOf(r); got != "Grüße, see attached." {
		t.Fatalf("text %q\n%s", got, dump(r))
	}
	var bin *PartInfo
	for _, p := range r.Parts {
		if p.Filename == "data.bin" {
			bin = p
		}
	}
	if bin == nil || bin.Size != 4 || bin.Disposition != "attachment" {
		t.Fatalf("attachment: %+v", bin)
	}
	for _, p := range r.Parts {
		if signed != (len(p.SignedBy) > 0) || encrypted != (len(p.EncryptedBy) > 0) {
			t.Fatalf("part %s: signed by %v, encrypted by %v", p.Part, p.SignedBy, p.EncryptedBy)
		}
	}
}

func TestPGPMIMESign(t *testing.T) {
	alice := pgpKey(t, "Alice <alice@example.org>")
	for _, protect := range []bool{false, true} {
		out, err := SignPGPMIME([]byte(testMessage), alice, &ComposeOptions{ProtectHeaders: protect})
		if err != nil {
			t.Fatal(err)
		}
		if needsEncoding(bytes.ReplaceAll(out, []byte("\r\n"), []byte("\n"))) && !protect {
			// The signed entity must travel as 7-bit.
			t.Fatal("output is not 7-bit safe")
		}
		r := inspect(t, out, &LocalKeys{PGP: []*svpgp.Key{alice.Public()}})
		if len(r.Layers) != 1 || r.Signed != CoverFull || r.Encrypted != CoverNone {
			t.Fatalf("layers\n%s", dump(r))
		}
		l := r.Layers[0]
		s := l.Signatures[0]
		if l.Format != FormatPGPMIME || l.Covers != "message" || s.Status != StatusValid || !s.Verified || !s.SenderMatch ||
			s.Fingerprint != hexUpper(alice.Fingerprint()) || s.UserIDs[0] != "Alice <alice@example.org>" {
			t.Fatalf("signature\n%s", dump(r))
		}
		checkBody(t, r, true, false)
		if len(r.Warnings) != 0 {
			t.Fatalf("warnings %v", r.Warnings)
		}
		if protect {
			ph := r.Protected
			if ph == nil || ph.HP != "clear" || !ph.Signed || ph.Encrypted || ph.Headers.Subject != "Lunch?" || len(ph.Differences) != 0 {
				t.Fatalf("protected\n%s", dump(r))
			}
		} else if r.Protected != nil {
			t.Fatal("protected headers where none were asked for")
		}

		// Without the key: who signed is known, not whether it is good.
		r = inspect(t, out, nil)
		s = r.Layers[0].Signatures[0]
		if s.Status != StatusUnknownKey || s.Verified || s.Issuer == "" || s.SenderMatch {
			t.Fatalf("no keys\n%s", dump(r))
		}

		// Changed after signing.
		bad := bytes.Replace(out, []byte("AAECAw=="), []byte("AAECBA=="), 1)
		r = inspect(t, bad, &LocalKeys{PGP: []*svpgp.Key{alice.Public()}})
		if s := r.Layers[0].Signatures[0]; s.Status != StatusBad || !hasWarning(r, WarnVerification) {
			t.Fatalf("tampered\n%s", dump(r))
		}
	}
}

func TestPGPMIMEEncrypt(t *testing.T) {
	alice := pgpKey(t, "Alice <alice@example.org>")
	bob := pgpKey(t, "Bob <bob@example.org>")
	carol := pgpKey(t, "Carol <carol@example.org>")
	out, err := EncryptPGPMIME([]byte(testMessage), []*svpgp.Key{bob.Public(), alice.Public()}, alice, &ComposeOptions{ProtectHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte("Lunch?")) || bytes.Contains(out, []byte("attached")) {
		t.Fatal("the subject or body is visible outside")
	}
	r := inspect(t, out, &LocalKeys{PGP: []*svpgp.Key{bob, alice.Public()}})
	if len(r.Layers) != 2 || r.Encrypted != CoverFull || r.Signed != CoverFull {
		t.Fatalf("layers\n%s", dump(r))
	}
	enc, sig := r.Layers[0], r.Layers[1]
	if enc.Kind != KindEncryption || !enc.Encryption.Decrypted || enc.Encryption.Integrity == "none" || len(enc.Encryption.Recipients) != 2 {
		t.Fatalf("encryption\n%s", dump(r))
	}
	if sig.Parent != enc.ID || sig.Signatures[0].Status != StatusValid || !sig.Signatures[0].SenderMatch {
		t.Fatalf("signature\n%s", dump(r))
	}
	checkBody(t, r, true, true)
	if r.Headers.Subject != "[...]" || r.Protected == nil || r.Protected.Headers.Subject != "Lunch?" || !r.Protected.Encrypted || r.Protected.HP != "cipher" {
		t.Fatalf("protected\n%s", dump(r))
	}
	if len(r.Protected.Differences) != 1 || r.Protected.Differences[0].Kind != DiffObscured || hasWarning(r, WarnHeaderMismatch) {
		t.Fatalf("differences\n%s", dump(r))
	}
	if r.Content == nil || r.Content.Layer != enc.ID || !bytes.Contains(r.Content.Raw, []byte("hp=cipher")) {
		t.Fatalf("content %+v", r.Content)
	}

	// The wrong key: the recipients are listed, nothing is decrypted.
	r = inspect(t, out, &LocalKeys{PGP: []*svpgp.Key{carol}})
	if enc := r.Layers[0]; enc.Encryption.Decrypted || enc.Encryption.Error == "" || len(enc.Encryption.Recipients) != 2 ||
		enc.Encryption.Integrity == "" || !hasWarning(r, WarnDecryption) {
		t.Fatalf("wrong key\n%s", dump(r))
	}
	if len(r.Parts) != 0 || r.Content != nil {
		t.Fatal("content without decryption")
	}

	// The outer Subject changed on the way: HP-Outer says it was "[...]".
	bad := bytes.Replace(out, []byte("Subject: [...]"), []byte("Subject: Pay now"), 1)
	r = inspect(t, bad, &LocalKeys{PGP: []*svpgp.Key{bob, alice.Public()}})
	if !hasWarning(r, WarnHeaderMismatch) || r.Protected.Differences[0].Kind != DiffMismatch {
		t.Fatalf("changed subject\n%s", dump(r))
	}

	// Signed, then encrypted as a separate layer (RFC 3156, section 6.1).
	signed, err := SignPGPMIME([]byte(testMessage), alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err = EncryptPGPMIME(signed, []*svpgp.Key{bob.Public()}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	r = inspect(t, out, &LocalKeys{PGP: []*svpgp.Key{bob, alice.Public()}})
	if len(r.Layers) != 2 || r.Layers[1].Kind != KindSignature || r.Layers[1].Parent != 1 || r.Layers[1].Covers != "message" ||
		r.Layers[1].Signatures[0].Status != StatusValid {
		t.Fatalf("sign then encrypt\n%s", dump(r))
	}
	checkBody(t, r, true, true)
}

func TestSMIMESign(t *testing.T) {
	p := getPKI(t)
	for _, email := range []string{"alice@example.org", "rsa-alice@example.org"} {
		u := p.user(t, email)
		msg := strings.Replace(testMessage, "alice@example.org", email, 1)
		out, err := SignSMIME([]byte(msg), u.key, []*x509.Certificate{u.cert, p.inter}, &ComposeOptions{ProtectHeaders: true})
		if err != nil {
			t.Fatal(err)
		}
		keys := &LocalKeys{Roots: []*x509.Certificate{p.root}}
		r := inspect(t, out, keys)
		s := r.Layers[0].Signatures[0]
		if r.Layers[0].Format != FormatSMIMEDetached || s.Status != StatusValid || !s.SenderMatch || s.Certificate == nil ||
			len(s.Chain) != 2 || s.Certificate.Emails[0] != email || s.Hash != "SHA-256" {
			t.Fatalf("%s\n%s", email, dump(r))
		}
		checkBody(t, r, true, false)
		if len(r.Keys) != 1 || r.Keys[0].Source != "smime-signature" || !bytes.Equal(r.Keys[0].Data, u.cert.Raw) {
			t.Fatalf("discovered %+v", r.Keys)
		}
		if r.Protected == nil || !r.Protected.Signed {
			t.Fatal("protected headers not signed")
		}

		// No roots: the signature is sound, the certificate untrusted.
		r = inspect(t, out, nil)
		if s := r.Layers[0].Signatures[0]; s.Status != StatusUntrustedRoot || !s.Verified {
			t.Fatalf("untrusted\n%s", dump(r))
		}

		// Changed after signing, in the body and in a protected header.
		bad := bytes.Replace(out, []byte("AAECAw=="), []byte("AAECBA=="), 1)
		if s := inspect(t, bad, keys).Layers[0].Signatures[0]; s.Status != StatusBad {
			t.Fatalf("tampered: %s", s.Status)
		}
		i := bytes.Index(out, []byte("Subject: Lunch?"))
		bad = append(append(append([]byte{}, out[:i]...), []byte("Subject: Dinner?")...), out[i+len("Subject: Lunch?"):]...)
		r = inspect(t, bad, keys)
		if r.Layers[0].Signatures[0].Status != StatusValid || !hasWarning(r, WarnHeaderMismatch) ||
			r.Protected.Differences[0].Name != "Subject" || r.Protected.Differences[0].Kind != DiffMismatch {
			t.Fatalf("outer subject changed\n%s", dump(r))
		}
	}
}

func TestSMIMESenderMismatch(t *testing.T) {
	p := getPKI(t)
	mallory := p.user(t, "mallory@example.org")
	out, err := SignSMIME([]byte(testMessage), mallory.key, []*x509.Certificate{mallory.cert, p.inter}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := inspect(t, out, &LocalKeys{Roots: []*x509.Certificate{p.root}})
	s := r.Layers[0].Signatures[0]
	if s.Status != StatusValid || s.SenderMatch || s.SenderAddress != "alice@example.org" || !hasWarning(r, WarnSenderMismatch) {
		t.Fatalf("\n%s", dump(r))
	}
	// And for OpenPGP.
	mk := pgpKey(t, "Mallory <mallory@example.org>")
	out, err = SignPGPMIME([]byte(testMessage), mk, nil)
	if err != nil {
		t.Fatal(err)
	}
	r = inspect(t, out, &LocalKeys{PGP: []*svpgp.Key{mk.Public()}})
	if s := r.Layers[0].Signatures[0]; s.Status != StatusValid || s.SenderMatch || !hasWarning(r, WarnSenderMismatch) {
		t.Fatalf("\n%s", dump(r))
	}
}

func TestSMIMEEncrypt(t *testing.T) {
	p := getPKI(t)
	alice := p.user(t, "alice@example.org")
	for _, bobAddr := range []string{"bob@example.org", "rsa-bob@example.org"} {
		bob := p.user(t, bobAddr)
		for _, legacy := range []bool{false, true} {
			out, err := EncryptSMIME([]byte(testMessage), []*x509.Certificate{bob.cert, alice.cert}, alice.key,
				[]*x509.Certificate{alice.cert, p.inter}, &ComposeOptions{ProtectHeaders: true, SMIMELegacy: legacy})
			if err != nil {
				t.Fatal(err)
			}
			keys := &LocalKeys{Roots: []*x509.Certificate{p.root}, SMIME: []svcms.Decrypter{bob.decrypter(t)}}
			r := inspect(t, out, keys)
			if len(r.Layers) != 2 {
				t.Fatalf("\n%s", dump(r))
			}
			enc, sig := r.Layers[0], r.Layers[1]
			wantFormat, wantIntegrity := FormatSMIMEAuthEnveloped, "aead"
			if legacy {
				wantFormat, wantIntegrity = FormatSMIMEEnveloped, "none"
			}
			if enc.Format != wantFormat || !enc.Encryption.Decrypted || enc.Encryption.Integrity != wantIntegrity ||
				len(enc.Encryption.Recipients) != 2 || enc.Encryption.Recipients[0].Serial == "" {
				t.Fatalf("encryption\n%s", dump(r))
			}
			if legacy != hasWarning(r, WarnNoIntegrity) {
				t.Fatalf("integrity warning: %v", r.Warnings)
			}
			if sig.Parent != enc.ID || sig.Signatures[0].Status != StatusValid || !sig.Signatures[0].SenderMatch {
				t.Fatalf("signature\n%s", dump(r))
			}
			checkBody(t, r, true, true)
			if r.Protected == nil || r.Protected.HP != "cipher" || r.Protected.Headers.Subject != "Lunch?" || !r.Protected.Signed {
				t.Fatalf("protected\n%s", dump(r))
			}

			// Not a recipient.
			carol := p.user(t, "carol@example.org")
			r = inspect(t, out, &LocalKeys{SMIME: []svcms.Decrypter{carol.decrypter(t)}})
			if r.Layers[0].Encryption.Decrypted || !hasWarning(r, WarnDecryption) {
				t.Fatalf("not a recipient\n%s", dump(r))
			}
		}
	}

	// Encrypted, then signed outside: the signature covers the
	// ciphertext.
	bob := p.user(t, "bob@example.org")
	enc, err := EncryptSMIME([]byte(testMessage), []*x509.Certificate{bob.cert}, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	out, err := SignSMIME(enc, alice.key, []*x509.Certificate{alice.cert, p.inter}, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := inspect(t, out, &LocalKeys{Roots: []*x509.Certificate{p.root}, SMIME: []svcms.Decrypter{bob.decrypter(t)}})
	if len(r.Layers) != 2 || r.Layers[0].Kind != KindSignature || r.Layers[1].Kind != KindEncryption ||
		r.Layers[0].Signatures[0].Status != StatusValid || !r.Layers[1].Encryption.Decrypted || r.Layers[1].Covers != "message" {
		t.Fatalf("encrypt then sign\n%s", dump(r))
	}
	checkBody(t, r, true, true)
}

func TestPartialSignature(t *testing.T) {
	alice := pgpKey(t, "Alice <alice@example.org>")
	signed, err := SignPGPMIME([]byte(testMessage), alice, nil)
	if err != nil {
		t.Fatal(err)
	}
	// A mailing list, or an attacker, puts the signed body in a
	// multipart/mixed next to text of its own.
	_, body, _ := bytes.Cut(signed, []byte("MIME-Version: 1.0\r\n"))
	outer := "From: Alice <alice@example.org>\r\nSubject: Lunch?\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=\"wrap\"\r\n\r\n" +
		"--wrap\r\nContent-Type: text/plain\r\n\r\nWire the money to account 1234.\r\n--wrap\r\n" + string(body) + "\r\n--wrap--\r\n"
	r := inspect(t, []byte(outer), &LocalKeys{PGP: []*svpgp.Key{alice.Public()}})
	if len(r.Layers) != 1 || r.Layers[0].Covers != "part" || r.Signed != CoverPartial || r.Layers[0].Signatures[0].Status != StatusValid {
		t.Fatalf("\n%s", dump(r))
	}
	if !hasWarning(r, WarnPartialSignature) || !hasWarning(r, WarnUnsignedPart) {
		t.Fatalf("warnings %v", r.Warnings)
	}
	unsigned := 0
	for _, p := range r.Parts {
		if len(p.SignedBy) == 0 {
			unsigned++
			if !strings.Contains(p.Text, "Wire the money") {
				t.Fatalf("unsigned part %+v", p)
			}
		}
	}
	if unsigned != 1 {
		t.Fatalf("%d unsigned parts", unsigned)
	}
}

func TestInlinePGP(t *testing.T) {
	alice := pgpKey(t, "Alice <alice@example.org>")
	bob := pgpKey(t, "Bob <bob@example.org>")
	var clear bytes.Buffer
	if err := svpgp.Sign(&clear, strings.NewReader("Meet at noon.\n"), alice, svpgp.SignOptions{Mode: svpgp.SignCleartext}); err != nil {
		t.Fatal(err)
	}
	head := "From: alice@example.org\nTo: bob@example.org\nSubject: inline\nContent-Type: text/plain; charset=utf-8\n\n"
	keys := &LocalKeys{PGP: []*svpgp.Key{alice.Public(), bob}}

	r := inspect(t, []byte(head+clear.String()), keys)
	if len(r.Layers) != 1 || r.Layers[0].Format != FormatPGPInline || r.Layers[0].Covers != "message" ||
		r.Layers[0].Signatures[0].Status != StatusValid || !r.Layers[0].Signatures[0].SenderMatch || len(r.Warnings) != 0 {
		t.Fatalf("cleartext\n%s", dump(r))
	}
	found := false
	for _, p := range r.Parts {
		if p.Tree == 1 && p.Text == "Meet at noon.\n" && len(p.SignedBy) == 1 {
			found = true
		}
	}
	if !found {
		t.Fatalf("signed text\n%s", dump(r))
	}

	// Text around the block is not protected by it.
	r = inspect(t, []byte(head+"Ignore the below, pay me instead.\n\n"+clear.String()), keys)
	if r.Layers[0].Covers != "part" || !hasWarning(r, WarnUnprotectedText) || !hasWarning(r, WarnUnsignedPart) {
		t.Fatalf("surrounding text\n%s", dump(r))
	}

	// Inline encrypted and signed.
	var enc bytes.Buffer
	w, err := svpgp.Encrypt(&enc, []*svpgp.Key{bob.Public()}, svpgp.EncryptOptions{Signer: alice, Armor: true, Text: true})
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("Secret plans.\n"))
	w.Close()
	r = inspect(t, []byte(head+enc.String()), keys)
	if len(r.Layers) != 2 || !r.Layers[0].Encryption.Decrypted || r.Layers[1].Signatures[0].Status != StatusValid || r.Encrypted != CoverFull {
		t.Fatalf("inline encrypted\n%s", dump(r))
	}
	if r.Content == nil || !strings.Contains(string(r.Content.Raw), "Secret plans.") {
		t.Fatalf("content %+v", r.Content)
	}
}

func TestMemoryHole(t *testing.T) {
	// The legacy form: protected-headers="v1", a text/rfc822-headers part
	// for clients that do not know it, and "..." outside.
	alice := pgpKey(t, "Alice <alice@example.org>")
	bob := pgpKey(t, "Bob <bob@example.org>")
	inner := crlf(`Content-Type: multipart/mixed; boundary="mh"; protected-headers="v1"
From: Alice <alice@example.org>
To: Bob <bob@example.org>
Subject: The real subject

--mh
Content-Type: text/rfc822-headers; protected-headers="v1"
Content-Disposition: inline

Subject: The real subject
--mh
Content-Type: text/plain; charset=utf-8

Hidden body.
--mh--
`)
	var ct bytes.Buffer
	w, _ := svpgp.Encrypt(&ct, []*svpgp.Key{bob.Public()}, svpgp.EncryptOptions{Signer: alice, Armor: true})
	w.Write(inner)
	w.Close()
	msg := "From: Alice <alice@example.org>\r\nTo: Bob <bob@example.org>\r\nSubject: ...\r\nMIME-Version: 1.0\r\n" +
		"Content-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"e\"\r\n\r\n" +
		"--e\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n\r\n--e\r\nContent-Type: application/octet-stream\r\n\r\n" +
		ct.String() + "\r\n--e--\r\n"
	r := inspect(t, []byte(msg), &LocalKeys{PGP: []*svpgp.Key{bob, alice.Public()}})
	ph := r.Protected
	if ph == nil || ph.Form != "memory-hole" || ph.Headers.Subject != "The real subject" || !ph.Signed || !ph.Encrypted {
		t.Fatalf("\n%s", dump(r))
	}
	if len(ph.Differences) != 1 || ph.Differences[0].Kind != DiffObscured || hasWarning(r, WarnHeaderMismatch) {
		t.Fatalf("differences\n%s", dump(r))
	}
	if textOf(r) != "Hidden body." {
		t.Fatalf("text %q", textOf(r))
	}
	legacy := 0
	for _, p := range r.Parts {
		if p.LegacyDisplay {
			legacy++
		}
	}
	if legacy != 1 {
		t.Fatalf("%d legacy display parts", legacy)
	}
}

func TestAutocrypt(t *testing.T) {
	alice := pgpKey(t, "Alice <alice@example.org>")
	bob := pgpKey(t, "Bob <bob@example.org>")
	keydata := func(k *svpgp.Key) string {
		var b bytes.Buffer
		if err := k.Public().Serialize(&b, false); err != nil {
			t.Fatal(err)
		}
		// Folded, as mail carries it.
		s := base64.StdEncoding.EncodeToString(b.Bytes())
		var out strings.Builder
		for len(s) > 70 {
			out.WriteString(s[:70] + "\r\n ")
			s = s[70:]
		}
		return out.String() + s
	}
	head := "From: Alice <alice@example.org>\r\nTo: bob@example.org\r\nSubject: hi\r\n"
	body := "\r\nhello\r\n"
	good := "Autocrypt: addr=alice@example.org; prefer-encrypt=mutual; _extra=ok; keydata=\r\n " + keydata(alice) + "\r\n"

	r := inspect(t, []byte(head+good+body), nil)
	if len(r.Keys) != 1 {
		t.Fatalf("\n%s", dump(r))
	}
	k := r.Keys[0]
	if k.Source != "autocrypt" || k.Type != "openpgp" || k.PreferEncrypt != "mutual" || k.Fingerprint != hexUpper(alice.Fingerprint()) || k.Error != "" || len(k.Data) == 0 {
		t.Fatalf("key %+v", k)
	}
	// For someone else, twice, or with an unknown critical attribute: ignored.
	for name, hdr := range map[string]string{
		"other address": strings.Replace(good, "addr=alice", "addr=eve", 1),
		"twice":         good + good,
		"critical":      strings.Replace(good, "_extra", "extra", 1),
	} {
		r := inspect(t, []byte(head+hdr+body), nil)
		if len(r.Keys) != 0 || !hasWarning(r, WarnKeys) {
			t.Fatalf("%s\n%s", name, dump(r))
		}
	}

	// Gossip inside an encrypted message.
	msg := head + "MIME-Version: 1.0\r\nContent-Type: text/plain\r\n\r\nhello\r\n"
	out, err := EncryptPGPMIME([]byte(msg), []*svpgp.Key{bob.Public()}, nil, &ComposeOptions{ProtectHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	r = inspect(t, out, &LocalKeys{PGP: []*svpgp.Key{bob}})
	if len(r.Keys) != 0 {
		t.Fatalf("gossip where there is none\n%s", dump(r))
	}
	// Gossip belongs to the protected part only, so build it by hand.
	inner := append(crlf("Content-Type: text/plain; hp=\"cipher\"\nFrom: Alice <alice@example.org>\nTo: bob@example.org\n"),
		"Autocrypt-Gossip: addr=bob@example.org; keydata="+keydata(bob)+"\r\n\r\nhello\r\n"...)
	var ct bytes.Buffer
	w, _ := svpgp.Encrypt(&ct, []*svpgp.Key{bob.Public()}, svpgp.EncryptOptions{Armor: true})
	w.Write(inner)
	w.Close()
	enc := head + "MIME-Version: 1.0\r\nContent-Type: multipart/encrypted; protocol=\"application/pgp-encrypted\"; boundary=\"e\"\r\n\r\n" +
		"--e\r\nContent-Type: application/pgp-encrypted\r\n\r\nVersion: 1\r\n--e\r\nContent-Type: application/octet-stream\r\n\r\n" + ct.String() + "\r\n--e--\r\n"
	r = inspect(t, []byte(enc), &LocalKeys{PGP: []*svpgp.Key{bob}})
	if len(r.Keys) != 1 || r.Keys[0].Source != "autocrypt-gossip" || !r.Keys[0].Protected || r.Keys[0].Fingerprint != hexUpper(bob.Fingerprint()) {
		t.Fatalf("gossip\n%s", dump(r))
	}
}

func TestLayerLimit(t *testing.T) {
	alice := pgpKey(t, "Alice <alice@example.org>")
	msg := []byte(testMessage)
	for range 5 {
		var err error
		if msg, err = SignPGPMIME(msg, alice, nil); err != nil {
			t.Fatal(err)
		}
	}
	r, err := InspectWith(msg, &LocalKeys{PGP: []*svpgp.Key{alice.Public()}}, Options{Limits: &Limits{MaxLayers: 3}})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Layers) != 3 || !hasWarning(r, WarnStructure) {
		t.Fatalf("%d layers, warnings %v", len(r.Layers), r.Warnings)
	}
	r = inspect(t, msg, &LocalKeys{PGP: []*svpgp.Key{alice.Public()}})
	if len(r.Layers) != 5 {
		t.Fatalf("%d layers", len(r.Layers))
	}
	for _, l := range r.Layers {
		if l.Signatures[0].Status != StatusValid || l.Covers != "message" {
			t.Fatalf("\n%s", dump(r))
		}
	}
}
