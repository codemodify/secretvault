package svmail

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcms"
)

// Interoperability with OpenSSL on whole S/MIME messages, both ways:
// `openssl cms` signs and encrypts, in every form it has, and this package
// inspects the result; this package builds messages, and `openssl cms`
// verifies and decrypts them. Everything happens in a temporary directory
// with a throwaway CA.

var opensslBinary, _ = exec.LookPath("openssl")

type osslDir struct {
	t   *testing.T
	dir string
}

type osslUser struct {
	cert     *x509.Certificate
	key      crypto.PrivateKey
	certPath string
	keyPath  string
}

func (o *osslDir) path(name string) string { return filepath.Join(o.dir, name) }

func (o *osslDir) write(name string, data []byte) string {
	o.t.Helper()
	if err := os.WriteFile(o.path(name), data, 0o600); err != nil {
		o.t.Fatal(err)
	}
	return o.path(name)
}

func (o *osslDir) run(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(opensslBinary, args...)
	cmd.Dir = o.dir
	cmd.Env = append(os.Environ(), "HOME="+o.dir)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("openssl %s: %v\n%s", strings.Join(args, " "), err, errb.String())
	}
	return out.Bytes(), nil
}

func (o *osslDir) must(stdin []byte, args ...string) []byte {
	o.t.Helper()
	out, err := o.run(stdin, args...)
	if err != nil {
		o.t.Fatal(err)
	}
	return out
}

// newOSSL makes a CA and three people: Alice (RSA), Bob (P-256) and Carol
// (RSA).
func newOSSL(t *testing.T) (*osslDir, *x509.Certificate, map[string]*osslUser) {
	t.Helper()
	if opensslBinary == "" {
		t.Skip("OpenSSL is not installed")
	}
	if testing.Short() {
		t.Skip("OpenSSL interop is slow")
	}
	o := &osslDir{t: t, dir: t.TempDir()}
	o.write("ca.cnf", []byte("[req]\ndistinguished_name = dn\nprompt = no\n[dn]\nCN = OpenSSL Mail CA\n[v3_ca]\nbasicConstraints = critical,CA:TRUE\nkeyUsage = critical,keyCertSign,cRLSign\nsubjectKeyIdentifier = hash\n"))
	o.must(nil, "req", "-x509", "-config", "ca.cnf", "-extensions", "v3_ca", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-keyout", "ca.key", "-out", "ca.pem", "-days", "30")
	block, _ := pem.Decode(o.must(nil, "x509", "-in", "ca.pem"))
	root, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	users := map[string]*osslUser{}
	for i, u := range []struct{ name, alg, usage string }{
		{"alice", "RSA", "digitalSignature, keyEncipherment"},
		{"bob", "EC", "digitalSignature, keyAgreement"},
		{"carol", "RSA", "digitalSignature, keyEncipherment"},
	} {
		args := []string{"genpkey", "-algorithm", u.alg, "-out", u.name + ".key"}
		if u.alg == "EC" {
			args = append(args, "-pkeyopt", "ec_paramgen_curve:P-256")
		} else {
			args = append(args, "-pkeyopt", "rsa_keygen_bits:2048")
		}
		o.must(nil, args...)
		o.write(u.name+".ext", []byte("basicConstraints = CA:FALSE\nkeyUsage = critical, "+u.usage+"\nextendedKeyUsage = emailProtection\nsubjectAltName = email:"+u.name+"@example.org\n"))
		o.must(nil, "req", "-new", "-key", u.name+".key", "-subj", "/CN="+u.name, "-out", u.name+".csr")
		o.must(nil, "x509", "-req", "-in", u.name+".csr", "-CA", "ca.pem", "-CAkey", "ca.key", "-set_serial", fmt.Sprint(10+i), "-days", "30", "-extfile", u.name+".ext", "-out", u.name+".pem")
		block, _ := pem.Decode(o.must(nil, "x509", "-in", u.name+".pem"))
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		block, _ = pem.Decode(o.must(nil, "pkey", "-in", u.name+".key"))
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			t.Fatal(err)
		}
		users[u.name] = &osslUser{cert: cert, key: key, certPath: o.path(u.name + ".pem"), keyPath: o.path(u.name + ".key")}
	}
	return o, root, users
}

func osslKeys(t *testing.T, root *x509.Certificate, users map[string]*osslUser, who ...string) *LocalKeys {
	k := &LocalKeys{Roots: []*x509.Certificate{root}}
	for _, name := range who {
		d, err := svcms.KeyDecrypter(users[name].cert, users[name].key)
		if err != nil {
			t.Fatal(err)
		}
		k.SMIME = append(k.SMIME, d)
	}
	return k
}

const osslInner = "Content-Type: text/plain; charset=utf-8\n\nHello from OpenSSL\n"

func TestOpenSSLToInspect(t *testing.T) {
	o, root, users := newOSSL(t)
	in := o.write("inner.eml", []byte(osslInner))
	head := []string{"-from", "alice@example.org", "-to", "bob@example.org", "-subject", "from openssl"}
	sign := func(input string, extra ...string) []byte {
		args := append([]string{"cms", "-sign", "-in", input, "-signer", users["alice"].certPath, "-inkey", users["alice"].keyPath}, head...)
		return o.must(nil, append(args, extra...)...)
	}
	encrypt := func(input string, to string, extra ...string) []byte {
		args := append([]string{"cms", "-encrypt", "-in", input}, head...)
		args = append(append(args, extra...), users[to].certPath)
		return o.must(nil, args...)
	}
	keys := osslKeys(t, root, users, "bob", "carol")
	valid := func(t *testing.T, r *Report, l *Layer) {
		t.Helper()
		s := l.Signatures[0]
		if s.Status != StatusValid || !s.SenderMatch || s.Certificate.Emails[0] != "alice@example.org" {
			t.Fatalf("signature\n%s", dump(r))
		}
	}
	text := func(t *testing.T, r *Report) {
		t.Helper()
		if got := textOf(r); got != "Hello from OpenSSL\n" {
			t.Fatalf("text %q\n%s", got, dump(r))
		}
	}

	for _, tc := range []struct {
		name string
		msg  func() []byte
		want []string // the layers' formats, in order
	}{
		{"detached", func() []byte { return sign(in) }, []string{FormatSMIMEDetached}},
		{"detached-stream", func() []byte { return sign(in, "-stream") }, []string{FormatSMIMEDetached}},
		{"detached-pss", func() []byte { return sign(in, "-keyopt", "rsa_padding_mode:pss") }, []string{FormatSMIMEDetached}},
		{"opaque", func() []byte { return sign(in, "-nodetach") }, []string{FormatSMIMEOpaque}},
		{"enveloped-ec", func() []byte { return encrypt(in, "bob", "-aes256") }, []string{FormatSMIMEEnveloped}},
		{"enveloped-rsa-oaep", func() []byte {
			args := append([]string{"cms", "-encrypt", "-in", in, "-aes128"}, head...)
			return o.must(nil, append(args, "-recip", users["carol"].certPath, "-keyopt", "rsa_padding_mode:oaep")...)
		}, []string{FormatSMIMEEnveloped}},
		{"authenveloped-ec", func() []byte { return encrypt(in, "bob", "-aes-256-gcm") }, []string{FormatSMIMEAuthEnveloped}},
		{"authenveloped-rsa-stream", func() []byte { return encrypt(in, "carol", "-aes-128-gcm", "-stream") }, []string{FormatSMIMEAuthEnveloped}},
		{"signed-then-encrypted", func() []byte {
			o.write("signed.eml", sign(in))
			return encrypt(o.path("signed.eml"), "bob", "-aes-256-gcm")
		}, []string{FormatSMIMEAuthEnveloped, FormatSMIMEDetached}},
		{"encrypted-then-signed", func() []byte {
			o.write("enc.eml", encrypt(in, "carol", "-aes256"))
			return sign(o.path("enc.eml"))
		}, []string{FormatSMIMEDetached, FormatSMIMEEnveloped}},
		{"no-smime-type", func() []byte {
			out := bytes.Replace(encrypt(in, "bob", "-aes256"), []byte(" smime-type=enveloped-data;"), nil, 1)
			if bytes.Contains(out, []byte("smime-type")) {
				t.Fatal("the smime-type parameter is still there")
			}
			return out
		}, []string{FormatSMIMEEnveloped}},
		{"legacy-smime-tool", func() []byte {
			args := append([]string{"smime", "-sign", "-in", in, "-signer", users["alice"].certPath, "-inkey", users["alice"].keyPath}, head...)
			return o.must(nil, args...)
		}, []string{FormatSMIMEDetached}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := tc.msg()
			r := inspect(t, raw, keys)
			if len(r.Layers) != len(tc.want) {
				t.Fatalf("\n%s\n%s", raw, dump(r))
			}
			for i, f := range tc.want {
				l := r.Layers[i]
				if l.Format != f {
					t.Fatalf("layer %d is %s\n%s", i+1, l.Format, dump(r))
				}
				if l.Kind == KindSignature {
					valid(t, r, l)
				} else if !l.Encryption.Decrypted {
					t.Fatalf("not decrypted\n%s", dump(r))
				}
			}
			text(t, r)
			if r.Headers.Subject != "from openssl" || r.Headers.FromAddress != "alice@example.org" {
				t.Fatalf("headers %+v", r.Headers)
			}
		})
	}

	t.Run("negative", func(t *testing.T) {
		// Carol's message, but only Bob's key.
		r := inspect(t, encrypt(in, "carol", "-aes256"), osslKeys(t, root, users, "bob"))
		if r.Layers[0].Encryption.Decrypted || !hasWarning(r, WarnDecryption) || r.Layers[0].Encryption.Recipients[0].Serial != "C" {
			t.Fatalf("wrong key\n%s", dump(r))
		}
		// A root nobody trusts.
		r = inspect(t, sign(in), &LocalKeys{})
		if r.Layers[0].Signatures[0].Status != StatusUntrustedRoot {
			t.Fatalf("untrusted\n%s", dump(r))
		}
		// Signed by Alice, claiming to be from Bob.
		fake := bytes.Replace(sign(in), []byte("From: alice@example.org"), []byte("From: bob@example.org"), 1)
		r = inspect(t, fake, keys)
		if s := r.Layers[0].Signatures[0]; s.Status != StatusValid || s.SenderMatch || !hasWarning(r, WarnSenderMismatch) {
			t.Fatalf("sender\n%s", dump(r))
		}
		// The signed text changed.
		bad := bytes.Replace(sign(in), []byte("Hello from OpenSSL"), []byte("Hello from Mallory"), 1)
		if r := inspect(t, bad, keys); r.Layers[0].Signatures[0].Status != StatusBad {
			t.Fatalf("tampered\n%s", dump(r))
		}
	})
}

func TestInspectToOpenSSL(t *testing.T) {
	o, root, users := newOSSL(t)
	ca := o.path("ca.pem")
	alice := users["alice"]
	chain := []*x509.Certificate{alice.cert}
	signer := alice.key.(crypto.Signer)
	msg := []byte(testMessage)
	want := func(t *testing.T, out []byte) {
		t.Helper()
		if !bytes.Contains(out, []byte("Gr=C3=BC=C3=9Fe")) || !bytes.Contains(out, []byte("AAECAw==")) {
			t.Fatalf("openssl output:\n%s", out)
		}
	}
	for _, protect := range []bool{false, true} {
		out, err := SignSMIME(msg, signer, chain, &ComposeOptions{ProtectHeaders: protect})
		if err != nil {
			t.Fatal(err)
		}
		in := o.write("signed.eml", out)
		want(t, o.must(nil, "cms", "-verify", "-in", in, "-CAfile", ca, "-purpose", "smimesign"))
		o.write("bad.eml", bytes.Replace(out, []byte("AAECAw=="), []byte("AAECBA=="), 1))
		if _, err := o.run(nil, "cms", "-verify", "-in", o.path("bad.eml"), "-CAfile", ca); err == nil {
			t.Fatal("openssl verified a changed message")
		}

		for _, to := range []string{"bob", "carol"} {
			for _, legacy := range []bool{false, true} {
				opts := &ComposeOptions{ProtectHeaders: protect, SMIMELegacy: legacy}
				out, err := EncryptSMIME(msg, []*x509.Certificate{users[to].cert}, nil, nil, opts)
				if err != nil {
					t.Fatal(err)
				}
				in := o.write("enc.eml", out)
				plain := o.must(nil, "cms", "-decrypt", "-in", in, "-recip", users[to].certPath, "-inkey", users[to].keyPath)
				want(t, plain)
				if protect != bytes.Contains(plain, []byte("HP-Outer: Subject: [...]")) {
					t.Fatalf("protected headers:\n%s", plain)
				}

				// Signed and encrypted: decrypt, then verify what came out.
				out, err = EncryptSMIME(msg, []*x509.Certificate{users[to].cert}, signer, chain, opts)
				if err != nil {
					t.Fatal(err)
				}
				in = o.write("enc.eml", out)
				plain = o.must(nil, "cms", "-decrypt", "-in", in, "-recip", users[to].certPath, "-inkey", users[to].keyPath)
				o.write("dec.eml", plain)
				want(t, o.must(nil, "cms", "-verify", "-in", o.path("dec.eml"), "-CAfile", ca, "-purpose", "smimesign"))
			}
		}
	}
	_ = root
}
