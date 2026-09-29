package svdeliver

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

// clock is a settable clock.
type clock struct {
	mu sync.Mutex
	t  time.Time
}

func newClock() *clock { return &clock{t: time.Now()} }

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// testKey is a signing key of the fake issuer's.
type testKey struct {
	kid  string
	alg  string
	priv crypto.Signer
}

// jwk is the key's public half as a JWKS lists it.
func (k testKey) jwk() map[string]any {
	m := map[string]any{"kid": k.kid, "use": "sig"}
	switch p := k.priv.(type) {
	case *rsa.PrivateKey:
		m["kty"], m["alg"] = "RSA", "RS256"
		m["n"] = b64url.EncodeToString(p.N.Bytes())
		m["e"] = b64url.EncodeToString(big.NewInt(int64(p.E)).Bytes())
	case *ecdsa.PrivateKey:
		pub, _ := p.PublicKey.Bytes() // 0x04 || X || Y
		m["kty"], m["crv"] = "EC", "P-256"
		m["x"], m["y"] = b64url.EncodeToString(pub[1:33]), b64url.EncodeToString(pub[33:])
	case ed25519.PrivateKey:
		m["kty"], m["crv"] = "OKP", "Ed25519"
		m["x"] = b64url.EncodeToString(p.Public().(ed25519.PublicKey))
	}
	return m
}

var rsaKey = sync.OnceValue(func() *rsa.PrivateKey {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return k
})

func newTestKey(t *testing.T, alg, kid string) testKey {
	t.Helper()
	k := testKey{kid: kid, alg: alg}
	switch alg {
	case AlgRS256:
		k.priv = rsaKey()
	case AlgES256:
		p, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k.priv = p
	case AlgEdDSA:
		_, p, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		k.priv = p
	}
	return k
}

// signJWT makes a token with the given header and claims, signed by k
// with alg (which may differ from k's own, to test confusion).
func signJWT(t *testing.T, header, claims map[string]any, k testKey, alg string) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	return signRaw(t, hb, cb, k, alg)
}

func signRaw(t *testing.T, header, claims []byte, k testKey, alg string) string {
	t.Helper()
	signed := b64url.EncodeToString(header) + "." + b64url.EncodeToString(claims)
	h := sha256.Sum256([]byte(signed))
	var sig []byte
	var err error
	switch alg {
	case AlgRS256:
		sig, err = rsa.SignPKCS1v15(rand.Reader, k.priv.(*rsa.PrivateKey), crypto.SHA256, h[:])
	case AlgES256:
		var r, s *big.Int
		r, s, err = ecdsa.Sign(rand.Reader, k.priv.(*ecdsa.PrivateKey), h[:])
		if err == nil {
			sig = append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
		}
	case AlgEdDSA:
		sig = ed25519.Sign(k.priv.(ed25519.PrivateKey), []byte(signed))
	}
	if err != nil {
		t.Fatal(err)
	}
	return signed + "." + b64url.EncodeToString(sig)
}

// fakeIssuer is an OpenID Connect issuer on localhost: discovery, a JWKS,
// and keys to sign tokens with.
type fakeIssuer struct {
	t   *testing.T
	srv *httptest.Server
	URL string

	mu         sync.Mutex
	keys       []testKey
	fetches    int
	discIssuer string // the issuer the discovery document names, when not URL
	jwksURI    string // the jwks_uri it names, when not its own
}

func newFakeIssuer(t *testing.T, keys ...testKey) *fakeIssuer {
	t.Helper()
	f := &fakeIssuer{t: t, keys: keys}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		iss, uri := f.URL, f.URL+"/keys"
		if f.discIssuer != "" {
			iss = f.discIssuer
		}
		if f.jwksURI != "" {
			uri = f.jwksURI
		}
		f.mu.Unlock()
		json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "jwks_uri": uri})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(f.jwks())
	})
	f.srv = httptest.NewTLSServer(mux)
	f.URL = f.srv.URL
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIssuer) jwks() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.fetches++
	var keys []any
	for _, k := range f.keys {
		keys = append(keys, k.jwk())
	}
	return map[string]any{"keys": keys}
}

func (f *fakeIssuer) fetchCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.fetches
}

func (f *fakeIssuer) addKey(k testKey) {
	f.mu.Lock()
	f.keys = append(f.keys, k)
	f.mu.Unlock()
}

// caPEM is the PEM of the issuer's HTTPS certificate, to trust it by.
func (f *fakeIssuer) caPEM() string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: f.srv.Certificate().Raw}))
}

func (f *fakeIssuer) issuer(name string, audiences ...string) *Issuer {
	return &Issuer{Name: name, URL: f.URL, Audiences: audiences, CA: f.caPEM()}
}

// token signs claims (with iss, aud, iat and exp filled in unless given)
// with k.
func (f *fakeIssuer) token(t *testing.T, k testKey, aud string, now time.Time, claims map[string]any) string {
	t.Helper()
	c := map[string]any{"iss": f.URL, "aud": aud, "iat": now.Unix(), "nbf": now.Unix(), "exp": now.Add(5 * time.Minute).Unix()}
	for name, v := range claims {
		if v == nil {
			delete(c, name)
		} else {
			c[name] = v
		}
	}
	return signJWT(t, map[string]any{"alg": k.alg, "kid": k.kid, "typ": "JWT"}, c, k, k.alg)
}
