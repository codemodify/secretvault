package svdeliver

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"time"
)

// An issuer's public keys come from its JWKS (RFC 7517): found through
// OpenID Connect discovery (issuer + /.well-known/openid-configuration,
// whose jwks_uri names the key set), or configured for the issuer when it
// has no public discovery, as Kubernetes clusters often do not.
//
// Fetched keys are kept for an hour. A token signed with a key not in the
// set makes us fetch the set again (the issuer may have rotated its keys),
// but at most every 30 seconds, so tokens with made-up key IDs cannot make
// us hammer the issuer. While a fetch fails, the keys fetched before stay
// in use.

const (
	maxDiscovery = 64 << 10  // the discovery document
	maxJWKS      = 256 << 10 // the key set
	maxJWKSKeys  = 64

	jwksMaxAge     = time.Hour
	jwksMinRefresh = 30 * time.Second
	fetchTimeout   = 10 * time.Second
)

// publicKey is one usable key of an issuer's.
type publicKey struct {
	kid string
	alg string // the only algorithm it verifies: RS256, ES256 or EdDSA
	rsa *rsa.PublicKey
	ec  *ecdsa.PublicKey
	ed  ed25519.PublicKey
}

// verify checks sig over signed with the key, for alg. A key only ever
// verifies its own algorithm.
func (k *publicKey) verify(alg string, signed, sig []byte) bool {
	if alg != k.alg {
		return false
	}
	switch alg {
	case AlgRS256:
		h := sha256.Sum256(signed)
		return rsa.VerifyPKCS1v15(k.rsa, crypto.SHA256, h[:], sig) == nil
	case AlgES256:
		if len(sig) != 64 {
			return false
		}
		h := sha256.Sum256(signed)
		r, s := new(big.Int).SetBytes(sig[:32]), new(big.Int).SetBytes(sig[32:])
		return ecdsa.Verify(k.ec, h[:], r, s)
	case AlgEdDSA:
		return len(sig) == ed25519.SignatureSize && ed25519.Verify(k.ed, signed, sig)
	}
	return false
}

// keySet is a parsed JWKS.
type keySet struct{ keys []*publicKey }

// find returns the keys that may have signed a token with this key ID and
// algorithm: those with the ID, or every key of the algorithm when the
// token names none.
func (s *keySet) find(kid, alg string) []*publicKey {
	if s == nil {
		return nil
	}
	var out []*publicKey
	for _, k := range s.keys {
		if k.alg == alg && (kid == "" || k.kid == kid) {
			out = append(out, k)
		}
	}
	return out
}

func (s *keySet) lookup(_ context.Context, kid, alg string) ([]*publicKey, error) {
	if keys := s.find(kid, alg); len(keys) > 0 {
		return keys, nil
	}
	return nil, errUnknownKey
}

// jwk is one key of a JWKS, as published (RFC 7517, RFC 7518, RFC 8037).
type jwk struct {
	Kty    string   `json:"kty"`
	Kid    string   `json:"kid"`
	Alg    string   `json:"alg"`
	Use    string   `json:"use"`
	KeyOps []string `json:"key_ops"`
	Crv    string   `json:"crv"`
	N      string   `json:"n"`
	E      string   `json:"e"`
	X      string   `json:"x"`
	Y      string   `json:"y"`
}

// parseJWKS reads a JSON Web Key Set, keeping the keys that can verify
// signatures with an accepted algorithm and skipping the rest (encryption
// keys, other algorithms, other curves). A set with no usable key is an
// error.
func parseJWKS(b []byte) (*keySet, error) {
	if len(b) > maxJWKS {
		return nil, fmt.Errorf("the key set is larger than %d bytes", maxJWKS)
	}
	var doc struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("the key set is not a JWKS: %v", err)
	}
	if len(doc.Keys) > maxJWKSKeys {
		return nil, fmt.Errorf("the key set has more than %d keys", maxJWKSKeys)
	}
	s := &keySet{}
	for _, raw := range doc.Keys {
		var j jwk
		if json.Unmarshal(raw, &j) != nil {
			continue
		}
		if k, err := j.publicKey(); err == nil {
			s.keys = append(s.keys, k)
		}
	}
	if len(s.keys) == 0 {
		return nil, errors.New("the key set has no RS256, ES256 or EdDSA signing key")
	}
	return s, nil
}

func (j *jwk) publicKey() (*publicKey, error) {
	if j.Use != "" && j.Use != "sig" {
		return nil, errors.New("not a signing key")
	}
	if j.KeyOps != nil && !slices.Contains(j.KeyOps, "verify") {
		return nil, errors.New("not a verification key")
	}
	k := &publicKey{kid: j.Kid}
	switch j.Kty {
	case "RSA":
		k.alg = AlgRS256
		n, err1 := b64url.DecodeString(j.N)
		e, err2 := b64url.DecodeString(j.E)
		if err1 != nil || err2 != nil || len(e) == 0 || len(e) > 4 || len(n) == 0 || n[0] == 0 {
			return nil, errors.New("bad RSA key")
		}
		var exp int
		for _, b := range e {
			exp = exp<<8 | int(b)
		}
		pub := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: exp}
		// Keys under 2048 bits are too weak; over 8192, too slow to be
		// worth verifying with.
		if bits := pub.N.BitLen(); bits < 2048 || bits > 8192 || exp < 3 || exp%2 == 0 || exp > 1<<31-1 {
			return nil, errors.New("unacceptable RSA key")
		}
		k.rsa = pub
	case "EC":
		k.alg = AlgES256
		x, err1 := b64url.DecodeString(j.X)
		y, err2 := b64url.DecodeString(j.Y)
		if j.Crv != "P-256" || err1 != nil || err2 != nil || len(x) != 32 || len(y) != 32 {
			return nil, errors.New("not a P-256 key")
		}
		pub, err := ecdsa.ParseUncompressedPublicKey(elliptic.P256(), append(append([]byte{4}, x...), y...))
		if err != nil {
			return nil, err // not on the curve
		}
		k.ec = pub
	case "OKP":
		k.alg = AlgEdDSA
		x, err := b64url.DecodeString(j.X)
		if j.Crv != "Ed25519" || err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("not an Ed25519 key")
		}
		k.ed = ed25519.PublicKey(x)
	default:
		return nil, errors.New("unknown key type")
	}
	// A key the set labels with an algorithm is used for that one only.
	if j.Alg != "" && j.Alg != k.alg {
		return nil, errors.New("labelled for another algorithm")
	}
	return k, nil
}

// remoteKeys is an issuer's key set found through discovery, cached.
type remoteKeys struct {
	issuer string
	client *http.Client
	now    func() time.Time

	mu      sync.Mutex
	set     *keySet
	fetched time.Time // when set was fetched
	tried   time.Time // when a fetch was last tried
	err     error     // why the last fetch failed
}

func newRemoteKeys(iss *Issuer, now func() time.Time) (*remoteKeys, error) {
	client, err := issuerClient(iss)
	if err != nil {
		return nil, err
	}
	return &remoteKeys{issuer: iss.URL, client: client, now: now}, nil
}

// issuerClient returns the HTTP client that reaches an issuer: HTTPS
// only, trusting the issuer's own CA when it names one.
func issuerClient(iss *Issuer) (*http.Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if iss.CA != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(iss.CA)) {
			return nil, fmt.Errorf("issuer %s: its CA holds no PEM certificate", iss.Name)
		}
		cfg.RootCAs = pool
	}
	t := &http.Transport{
		TLSClientConfig:       cfg,
		TLSHandshakeTimeout:   fetchTimeout,
		ResponseHeaderTimeout: fetchTimeout,
		MaxIdleConns:          4,
		IdleConnTimeout:       time.Minute,
		Proxy:                 http.ProxyFromEnvironment,
	}
	return &http.Client{
		Transport: t,
		Timeout:   fetchTimeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 || req.URL.Scheme != "https" {
				return errors.New("too many redirects, or a redirect away from HTTPS")
			}
			return nil
		},
	}, nil
}

func (r *remoteKeys) lookup(ctx context.Context, kid, alg string) ([]*publicKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := r.now()
	stale := r.set == nil || now.Sub(r.fetched) > jwksMaxAge
	mayTry := r.tried.IsZero() || now.Sub(r.tried) >= jwksMinRefresh || now.Before(r.tried)
	if stale && mayTry {
		r.refresh(ctx, now)
	}
	if keys := r.set.find(kid, alg); len(keys) > 0 {
		return keys, nil
	}
	// Perhaps the issuer rotated its keys since we fetched them.
	if !stale && mayTry {
		r.refresh(ctx, now)
		if keys := r.set.find(kid, alg); len(keys) > 0 {
			return keys, nil
		}
	}
	if r.set == nil && r.err != nil {
		return nil, fmt.Errorf("the issuer's keys could not be fetched: %w", r.err)
	}
	return nil, errUnknownKey
}

// refresh fetches the key set again, keeping the old one if that fails.
// The caller holds r.mu.
func (r *remoteKeys) refresh(ctx context.Context, now time.Time) {
	r.tried = now
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()
	set, err := r.fetch(ctx)
	if err != nil {
		r.err = err
		return
	}
	r.set, r.fetched, r.err = set, now, nil
}

func (r *remoteKeys) fetch(ctx context.Context) (*keySet, error) {
	disc := strings.TrimSuffix(r.issuer, "/") + "/.well-known/openid-configuration"
	b, err := r.get(ctx, disc, maxDiscovery)
	if err != nil {
		return nil, err
	}
	var meta struct {
		Issuer  string `json:"issuer"`
		JWKSURI string `json:"jwks_uri"`
	}
	if err := json.Unmarshal(b, &meta); err != nil {
		return nil, fmt.Errorf("%s is not a discovery document", disc)
	}
	// OpenID Connect Discovery 1.0, section 4.3: the document must name
	// the issuer it was fetched for.
	if meta.Issuer != r.issuer {
		return nil, fmt.Errorf("the discovery document names the issuer %q, not %q", meta.Issuer, r.issuer)
	}
	u, err := url.Parse(meta.JWKSURI)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, fmt.Errorf("the discovery document's jwks_uri %q is not an HTTPS URL", meta.JWKSURI)
	}
	b, err = r.get(ctx, u.String(), maxJWKS)
	if err != nil {
		return nil, err
	}
	return parseJWKS(b)
}

func (r *remoteKeys) get(ctx context.Context, u string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s answered %s", u, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s answered with more than %d bytes", u, limit)
	}
	return b, nil
}
