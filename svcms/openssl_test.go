package svcms

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// Interoperability with OpenSSL, both ways: what `openssl cms` and
// `openssl pkcs12` make, this package reads, and what this package makes,
// OpenSSL reads. Every run works in a temporary directory with a
// throwaway CA; nothing outside it is read or written.

var opensslBinary, _ = exec.LookPath("openssl")

type ossl struct {
	t   *testing.T
	dir string
}

func newOSSL(t *testing.T) *ossl {
	t.Helper()
	if opensslBinary == "" {
		t.Skip("OpenSSL is not installed")
	}
	if testing.Short() {
		t.Skip("OpenSSL interop is slow")
	}
	return &ossl{t: t, dir: t.TempDir()}
}

func (o *ossl) path(name string) string { return filepath.Join(o.dir, name) }

func (o *ossl) write(name string, data []byte) string {
	o.t.Helper()
	p := o.path(name)
	if err := os.WriteFile(p, data, 0o600); err != nil {
		o.t.Fatal(err)
	}
	return p
}

func (o *ossl) read(name string) []byte {
	o.t.Helper()
	b, err := os.ReadFile(o.path(name))
	if err != nil {
		o.t.Fatal(err)
	}
	return b
}

// run runs openssl in the directory, with an environment that points its
// configuration at nothing of the user's.
func (o *ossl) run(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command(opensslBinary, args...)
	cmd.Dir = o.dir
	cmd.Env = append(os.Environ(), "HOME="+o.dir, "RANDFILE="+o.path(".rnd"))
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		return out.Bytes(), fmt.Errorf("openssl %s: %v\n%s", strings.Join(args, " "), err, errb.String())
	}
	return out.Bytes(), nil
}

func (o *ossl) must(stdin []byte, args ...string) []byte {
	o.t.Helper()
	out, err := o.run(stdin, args...)
	if err != nil {
		o.t.Fatal(err)
	}
	return out
}

func pemCert(c *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Raw})
}

func pemKey(t testing.TB, k crypto.PrivateKey) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

// An OpenSSL-made CA and people, made once for all the tests.
type osslPKI struct {
	dir   string
	root  *x509.Certificate
	users map[string]*osslUser
}

type osslUser struct {
	name     string // file stem: NAME.pem, NAME.key
	cert     *x509.Certificate
	key      crypto.PrivateKey
	certPath string
	keyPath  string
}

var (
	osslOnce sync.Once
	osslP    *osslPKI
	osslErr  error
)

const caConf = `[req]
distinguished_name = dn
prompt = no
[dn]
CN = OpenSSL Test CA
[v3_ca]
basicConstraints = critical,CA:TRUE
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
`

func getOSSLPKI(t *testing.T) *osslPKI {
	o := newOSSL(t)
	osslOnce.Do(func() {
		dir, err := os.MkdirTemp("", "svcms-openssl-")
		if err != nil {
			osslErr = err
			return
		}
		o := &ossl{t: t, dir: dir}
		p := &osslPKI{dir: dir, users: map[string]*osslUser{}}
		o.write("ca.cnf", []byte(caConf))
		if _, err := o.run(nil, "req", "-x509", "-config", "ca.cnf", "-extensions", "v3_ca", "-newkey", "rsa:2048", "-nodes",
			"-keyout", "ca.key", "-out", "ca.pem", "-days", "3650"); err != nil {
			osslErr = err
			return
		}
		block, _ := pem.Decode(o.read("ca.pem"))
		p.root, osslErr = x509.ParseCertificate(block.Bytes)
		if osslErr != nil {
			return
		}
		for i, u := range []struct{ name, alg, usage string }{
			{"rsa", "RSA", "digitalSignature, nonRepudiation, keyEncipherment"},
			{"p256", "EC", "digitalSignature, keyAgreement"},
			{"p384", "EC", "digitalSignature, keyAgreement"},
			{"p521", "EC", "digitalSignature, keyAgreement"},
			{"ed25519", "ED25519", "digitalSignature"},
		} {
			args := []string{"genpkey", "-algorithm", u.alg, "-out", u.name + ".key"}
			switch u.name {
			case "rsa":
				args = append(args, "-pkeyopt", "rsa_keygen_bits:2048")
			case "p256", "p384", "p521":
				args = append(args, "-pkeyopt", "ec_paramgen_curve:P-"+u.name[1:])
			}
			if _, err := o.run(nil, args...); err != nil {
				osslErr = err
				return
			}
			email := u.name + "@example.org"
			o.write(u.name+".ext", []byte("basicConstraints = CA:FALSE\nkeyUsage = critical, "+u.usage+
				"\nextendedKeyUsage = emailProtection\nsubjectAltName = email:"+email+
				"\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid\n"))
			if _, err := o.run(nil, "req", "-new", "-key", u.name+".key", "-subj", "/CN=Test "+u.name+"/emailAddress="+email, "-out", u.name+".csr"); err != nil {
				osslErr = err
				return
			}
			if _, err := o.run(nil, "x509", "-req", "-in", u.name+".csr", "-CA", "ca.pem", "-CAkey", "ca.key",
				"-set_serial", fmt.Sprint(100+i), "-days", "365", "-extfile", u.name+".ext", "-out", u.name+".pem"); err != nil {
				osslErr = err
				return
			}
			block, _ := pem.Decode(o.read(u.name + ".pem"))
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				osslErr = err
				return
			}
			block, _ = pem.Decode(o.read(u.name + ".key"))
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				osslErr = err
				return
			}
			p.users[u.name] = &osslUser{name: u.name, cert: cert, key: key, certPath: o.path(u.name + ".pem"), keyPath: o.path(u.name + ".key")}
		}
		osslP = p
	})
	if osslErr != nil {
		t.Fatal(osslErr)
	}
	_ = o
	return osslP
}

func TestMain(m *testing.M) {
	code := m.Run()
	if osslP != nil {
		os.RemoveAll(osslP.dir)
	}
	os.Exit(code)
}

// OpenSSL signs, this package verifies.
func TestOpenSSLSignatures(t *testing.T) {
	p := getOSSLPKI(t)
	o := newOSSL(t)
	content := []byte("Content-Type: text/plain\r\n\r\nSigned by OpenSSL.\r\n")
	msg := o.write("msg.txt", content)
	roots := []*x509.Certificate{p.root}
	for _, tc := range []struct {
		name, user string
		args       []string
		attached   bool
		wantErr    error
	}{
		{"rsa", "rsa", nil, false, nil},
		{"rsa-stream", "rsa", []string{"-stream"}, true, nil}, // streaming DER is attached, in BER
		{"rsa-sha512", "rsa", []string{"-md", "sha512"}, false, nil},
		{"rsa-pss", "rsa", []string{"-keyopt", "rsa_padding_mode:pss"}, false, nil},
		{"rsa-pss-sha384", "rsa", []string{"-md", "sha384", "-keyopt", "rsa_padding_mode:pss", "-keyopt", "rsa_pss_saltlen:48"}, false, nil},
		{"rsa-opaque", "rsa", []string{"-nodetach"}, true, nil},
		{"rsa-opaque-stream", "rsa", []string{"-nodetach", "-stream"}, true, nil},
		{"rsa-noattr", "rsa", []string{"-noattr"}, false, nil},
		{"rsa-sha1", "rsa", []string{"-md", "sha1"}, false, ErrWeakAlgorithm},
		{"p256", "p256", nil, false, nil},
		{"p384", "p384", []string{"-md", "sha384"}, false, nil},
		{"p521", "p521", []string{"-md", "sha512"}, false, nil},
		{"p256-opaque", "p256", []string{"-nodetach"}, true, nil},
		{"ed25519", "ed25519", []string{"-md", "sha512"}, false, nil},
		{"nocerts", "rsa", []string{"-nocerts"}, false, ErrUnknownSigner},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := p.users[tc.user]
			args := append([]string{"cms", "-sign", "-binary", "-in", msg, "-signer", u.certPath, "-inkey", u.keyPath, "-outform", "DER"}, tc.args...)
			der := o.must(nil, args...)
			sd, err := ParseSignedData(der, nil)
			if err != nil {
				t.Fatalf("%v\n%x", err, der)
			}
			if tc.attached != (sd.Content != nil) {
				t.Fatalf("attached content: %v", sd.Content != nil)
			}
			if tc.attached && !bytes.Equal(sd.Content, content) {
				t.Fatal("attached content differs")
			}
			res, err := sd.Verify(VerifyOptions{Content: content, Roots: roots, Email: u.name + "@example.org"})
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantErr != nil {
				if res[0].Valid || !errors.Is(res[0].Err, tc.wantErr) {
					t.Fatalf("got %v, want %v", res[0].Err, tc.wantErr)
				}
				return
			}
			if !res[0].Valid {
				t.Fatalf("not valid: %v", res[0].Err)
			}
			if !res[0].Certificate.Equal(u.cert) {
				t.Fatal("wrong signer")
			}
			if !tc.attached {
				bad := bytes.Clone(content)
				bad[len(bad)-4] ^= 0x20
				res, _ = sd.Verify(VerifyOptions{Content: bad, Roots: roots})
				if res[0].Valid || !errors.Is(res[0].SignatureErr, ErrBadSignature) {
					t.Fatalf("tampered: %v", res[0].Err)
				}
			}
		})
	}
}

// This package signs, OpenSSL verifies.
func TestSignaturesToOpenSSL(t *testing.T) {
	p := getOSSLPKI(t)
	o := newOSSL(t)
	content := []byte("Content-Type: text/plain\r\n\r\nSigned by svcms.\r\n")
	msg := o.write("msg.txt", content)
	ca := o.write("ca.pem", pemCert(p.root))
	for _, tc := range []struct {
		user string
		opts SignOptions
	}{
		{"rsa", SignOptions{}},
		{"rsa", SignOptions{PSS: true}},
		{"rsa", SignOptions{Hash: crypto.SHA384}},
		{"p256", SignOptions{}},
		{"p384", SignOptions{}},
		{"p521", SignOptions{}},
		{"ed25519", SignOptions{}},
		{"rsa", SignOptions{Attached: true}},
	} {
		name := fmt.Sprintf("%s-%v-pss%v-attached%v", tc.user, tc.opts.Hash, tc.opts.PSS, tc.opts.Attached)
		t.Run(name, func(t *testing.T) {
			u := p.users[tc.user]
			der, err := Sign(content, u.key.(crypto.Signer), []*x509.Certificate{u.cert}, tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			sig := o.write("sig.der", der)
			args := []string{"cms", "-verify", "-binary", "-inform", "DER", "-in", sig, "-CAfile", ca, "-purpose", "smimesign"}
			if !tc.opts.Attached {
				args = append(args, "-content", msg)
			}
			out := o.must(nil, args...)
			if !bytes.Equal(out, content) {
				t.Fatalf("openssl output %q", out)
			}
			bad := o.write("bad.txt", append(bytes.Clone(content), 'x'))
			if !tc.opts.Attached {
				if _, err := o.run(nil, "cms", "-verify", "-binary", "-inform", "DER", "-in", sig, "-CAfile", ca, "-content", bad); err == nil {
					t.Fatal("openssl verified changed content")
				}
			}
		})
	}
}

// OpenSSL encrypts, this package decrypts.
func TestOpenSSLEnveloped(t *testing.T) {
	p := getOSSLPKI(t)
	o := newOSSL(t)
	content := []byte("Content-Type: text/plain\r\n\r\nEncrypted by OpenSSL.\r\n")
	msg := o.write("msg.txt", content)
	for _, tc := range []struct {
		name, user string
		args       []string
		auth       bool
		cipher     string
		warn       bool
	}{
		{"rsa-aes256", "rsa", []string{"-aes256"}, false, "AES-256-CBC", false},
		{"rsa-aes128-stream", "rsa", []string{"-aes128", "-stream"}, false, "AES-128-CBC", false},
		{"rsa-oaep", "rsa", []string{"-aes256", "-keyopt", "rsa_padding_mode:oaep"}, false, "AES-256-CBC", false},
		{"rsa-oaep-sha256", "rsa", []string{"-aes256", "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256"}, false, "AES-256-CBC", false},
		{"rsa-gcm", "rsa", []string{"-aes-256-gcm"}, true, "AES-256-GCM", false},
		{"rsa-gcm128-stream", "rsa", []string{"-aes-128-gcm", "-stream"}, true, "AES-128-GCM", false},
		{"rsa-3des", "rsa", []string{"-des3"}, false, "3DES-CBC", true},
		{"p256", "p256", []string{"-aes256"}, false, "AES-256-CBC", false},
		{"p256-gcm", "p256", []string{"-aes-256-gcm"}, true, "AES-256-GCM", false},
		{"p384", "p384", []string{"-aes256"}, false, "AES-256-CBC", false},
		{"p521-gcm", "p521", []string{"-aes-256-gcm"}, true, "AES-256-GCM", false},
		{"p256-sha256kdf", "p256", []string{"-aes128", "-keyopt", "ecdh_kdf_md:sha256"}, false, "AES-128-CBC", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := p.users[tc.user]
			args := []string{"cms", "-encrypt", "-binary", "-in", msg, "-outform", "DER", "-recip", u.certPath}
			args = append(args, tc.args...)
			der := o.must(nil, args...)
			ed, err := ParseEnvelopedData(der, nil)
			if err != nil {
				t.Fatalf("%v\n%x", err, der)
			}
			if ed.Authenticated != tc.auth || ed.ContentEncryption != tc.cipher {
				t.Fatalf("authenticated %v, cipher %s", ed.Authenticated, ed.ContentEncryption)
			}
			d, err := KeyDecrypter(u.cert, u.key)
			if err != nil {
				t.Fatal(err)
			}
			pt, err := ed.Decrypt(d)
			if err != nil {
				t.Fatalf("%v (recipient %s)", err, ed.Recipients[0].KeyEncryption)
			}
			if !bytes.Equal(pt.Content, content) {
				t.Fatalf("got %q", pt.Content)
			}
			if tc.warn != (len(pt.Warnings) > 0) {
				t.Fatalf("warnings %q", pt.Warnings)
			}
			// The wrong key.
			other := p.users["rsa"]
			if tc.user == "rsa" {
				other = p.users["p256"]
			}
			d2, _ := KeyDecrypter(u.cert, other.key)
			if _, err := ed.Decrypt(d2); err == nil {
				t.Fatal("decrypted with the wrong key")
			}
		})
	}
}

// This package encrypts, OpenSSL decrypts.
func TestEnvelopedToOpenSSL(t *testing.T) {
	p := getOSSLPKI(t)
	o := newOSSL(t)
	content := []byte("Content-Type: text/plain\r\n\r\nEncrypted by svcms.\r\n")
	for _, legacy := range []bool{false, true} {
		for _, name := range []string{"rsa", "p256", "p384", "p521"} {
			t.Run(fmt.Sprintf("%s-legacy%v", name, legacy), func(t *testing.T) {
				u := p.users[name]
				der, err := Encrypt(content, []*x509.Certificate{p.users["rsa"].cert, p.users["p256"].cert, u.cert}, EncryptOptions{Legacy: legacy})
				if err != nil {
					t.Fatal(err)
				}
				in := o.write("env.der", der)
				out := o.must(nil, "cms", "-decrypt", "-binary", "-inform", "DER", "-in", in, "-recip", u.certPath, "-inkey", u.keyPath)
				if !bytes.Equal(out, content) {
					t.Fatalf("openssl got %q", out)
				}
			})
		}
	}
}

// OpenSSL writes PKCS #12, this package reads it; and the other way.
func TestOpenSSLPKCS12(t *testing.T) {
	p := getOSSLPKI(t)
	o := newOSSL(t)
	ca := o.write("ca.pem", pemCert(p.root))
	legacyOK := true
	if _, err := o.run(nil, "list", "-providers", "-provider", "legacy"); err != nil {
		legacyOK = false
	}
	pbmac1OK := true
	if out, _ := o.run(nil, "pkcs12", "-help"); !bytes.Contains(out, []byte("pbmac1")) {
		if _, err := o.run(nil, "pkcs12", "-export", "-pbmac1_pbkdf2", "-nokeys", "-in", ca, "-passout", "pass:x", "-out", "probe.p12"); err != nil {
			pbmac1OK = false
		}
	}
	for _, tc := range []struct {
		name, user, pass string
		args             []string
		legacy, pbmac1   bool
		warn             bool
	}{
		{"default-rsa", "rsa", "correct horse", nil, false, false, false},
		{"default-p256", "p256", "correct horse", nil, false, false, false},
		{"default-ed25519", "ed25519", "pässwörd", nil, false, false, false},
		{"empty-password", "rsa", "", nil, false, false, false},
		{"legacy", "rsa", "correct horse", []string{"-legacy"}, true, false, true},
		{"legacy-empty", "p384", "", []string{"-legacy"}, true, false, true},
		{"3des-both", "rsa", "pw", []string{"-legacy", "-certpbe", "PBE-SHA1-3DES", "-keypbe", "PBE-SHA1-3DES"}, true, false, true},
		{"sha512-mac", "rsa", "pw", []string{"-macalg", "sha512", "-iter", "5000"}, false, false, false},
		{"nomac", "rsa", "pw", []string{"-nomac"}, false, false, true},
		{"pbmac1", "rsa", "pw", []string{"-pbmac1_pbkdf2"}, false, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.legacy && !legacyOK {
				t.Skip("this OpenSSL has no legacy provider")
			}
			if tc.pbmac1 && !pbmac1OK {
				t.Skip("this OpenSSL does not write PBMAC1")
			}
			u := p.users[tc.user]
			args := []string{"pkcs12", "-export", "-inkey", u.keyPath, "-in", u.certPath, "-certfile", ca,
				"-name", "Test key", "-passout", "pass:" + tc.pass, "-out", "out.p12"}
			o.must(nil, append(args, tc.args...)...)
			data := o.read("out.p12")
			got, err := DecodePKCS12(data, []byte(tc.pass), nil)
			if err != nil {
				t.Fatal(err)
			}
			if got.Certificate == nil || !got.Certificate.Equal(u.cert) {
				t.Fatal("wrong or no certificate")
			}
			if len(got.CACertificates) != 1 || !got.CACertificates[0].Equal(p.root) {
				t.Fatalf("CA certificates: %d", len(got.CACertificates))
			}
			if !keysEqual(got.PrivateKey, u.key) {
				t.Fatal("wrong private key")
			}
			if got.FriendlyName != "Test key" {
				t.Fatalf("friendly name %q", got.FriendlyName)
			}
			if tc.warn != (len(got.Warnings) > 0) {
				t.Fatalf("warnings: %q", got.Warnings)
			}
			if _, err := DecodePKCS12(data, []byte(tc.pass+"x"), nil); !errors.Is(err, ErrPassword) {
				t.Fatalf("wrong password: %v", err)
			}
		})
	}

	// Ours, read by OpenSSL.
	for _, name := range []string{"rsa", "p256", "ed25519"} {
		t.Run("to-openssl-"+name, func(t *testing.T) {
			u := p.users[name]
			der, err := EncodePKCS12(u.key, u.cert, []*x509.Certificate{p.root}, []byte("s3cret ü"), &PKCS12Options{Iterations: 10000, FriendlyName: "Ours"})
			if err != nil {
				t.Fatal(err)
			}
			in := o.write("ours.p12", der)
			out := o.must(nil, "pkcs12", "-in", in, "-passin", "pass:s3cret ü", "-nodes")
			var certs []*x509.Certificate
			var key crypto.PrivateKey
			for rest := out; ; {
				var b *pem.Block
				b, rest = pem.Decode(rest)
				if b == nil {
					break
				}
				switch b.Type {
				case "CERTIFICATE":
					c, err := x509.ParseCertificate(b.Bytes)
					if err != nil {
						t.Fatal(err)
					}
					certs = append(certs, c)
				case "PRIVATE KEY":
					if key, err = x509.ParsePKCS8PrivateKey(b.Bytes); err != nil {
						t.Fatal(err)
					}
				}
			}
			if len(certs) != 2 || !keysEqual(key, u.key) {
				t.Fatalf("openssl read %d certificates and key %v", len(certs), key != nil)
			}
			if !bytes.Contains(out, []byte("friendlyName: Ours")) {
				t.Fatalf("no friendly name in\n%s", out)
			}
			if _, err := o.run(nil, "pkcs12", "-in", in, "-passin", "pass:wrong", "-nodes"); err == nil {
				t.Fatal("openssl accepted the wrong password")
			}
			// And back.
			got, err := DecodePKCS12(der, []byte("s3cret ü"), nil)
			if err != nil || !keysEqual(got.PrivateKey, u.key) || !got.Certificate.Equal(u.cert) || got.FriendlyName != "Ours" {
				t.Fatalf("round trip: %v", err)
			}
		})
	}
}

func keysEqual(a, b crypto.PrivateKey) bool {
	switch k := a.(type) {
	case *rsa.PrivateKey:
		return k.Equal(b)
	case *ecdsa.PrivateKey:
		return k.Equal(b)
	case ed25519.PrivateKey:
		return k.Equal(b)
	}
	return false
}
