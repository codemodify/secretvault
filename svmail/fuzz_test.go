package svmail

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svpgp"
)

// Nothing, however malformed, may make parsing or inspecting panic or run
// away, and every report must marshal. The seeds are messages made here.

var fuzzLimits = &Limits{MaxSize: 1 << 20, MaxParts: 200}

func fuzzSeeds(f *testing.F) Keys {
	alice := pgpKey(f, "Alice <alice@example.org>")
	bob := pgpKey(f, "Bob <bob@example.org>")
	p := getPKI(f)
	sa, sb := p.user(f, "alice@example.org"), p.user(f, "bob@example.org")
	msg := []byte(testMessage)
	f.Add(msg)
	f.Add([]byte(nested))
	for _, protect := range []bool{false, true} {
		o := &ComposeOptions{ProtectHeaders: protect}
		for _, build := range []func() ([]byte, error){
			func() ([]byte, error) { return SignPGPMIME(msg, alice, o) },
			func() ([]byte, error) { return EncryptPGPMIME(msg, []*svpgp.Key{bob.Public()}, alice, o) },
			func() ([]byte, error) { return SignSMIME(msg, sa.key, []*x509.Certificate{sa.cert}, o) },
			func() ([]byte, error) {
				return EncryptSMIME(msg, []*x509.Certificate{sb.cert}, sa.key, []*x509.Certificate{sa.cert}, o)
			},
		} {
			out, err := build()
			if err != nil {
				f.Fatal(err)
			}
			f.Add(out)
		}
	}
	var clear bytes.Buffer
	svpgp.Sign(&clear, strings.NewReader("inline\n"), alice, svpgp.SignOptions{Mode: svpgp.SignCleartext})
	f.Add([]byte("From: a@b\nContent-Type: text/plain\n\n" + clear.String()))
	f.Add([]byte("From: a@b\nAutocrypt: addr=a@b; keydata=AAAA\n\nx"))
	return &LocalKeys{PGP: []*svpgp.Key{alice.Public(), bob}, Roots: []*x509.Certificate{p.root}, SMIME: []svcms.Decrypter{sb.decrypter(f)}}
}

func FuzzParseMessage(f *testing.F) {
	fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := ParseMessage(data, fuzzLimits)
		if err != nil {
			return
		}
		var walk func(*Part)
		walk = func(p *Part) {
			// Every part's bytes are a slice of the input.
			if len(p.Raw) > 0 && !bytes.Contains(data, p.Raw) {
				t.Fatal("a part's raw bytes are not in the input")
			}
			p.Decoded()
			for _, c := range p.Parts {
				walk(c)
			}
		}
		walk(p)
	})
}

func FuzzInspect(f *testing.F) {
	keys := fuzzSeeds(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, k := range []Keys{nil, keys} {
			r, err := InspectWith(data, k, Options{Limits: fuzzLimits})
			if err != nil {
				continue
			}
			if _, err := json.Marshal(r); err != nil {
				t.Fatal(err)
			}
		}
	})
}
