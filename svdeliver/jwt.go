package svdeliver

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"time"
)

// ID tokens are JSON Web Tokens (RFC 7519) in the JWS compact form (RFC
// 7515), verified here without a JOSE library:
//
//   - Only RS256, ES256 and EdDSA (Ed25519) are accepted. "none", the HMAC
//     algorithms and everything else are refused before any key is looked
//     at, so a public key can never be used as an HMAC secret.
//   - The key comes from the issuer's JWKS, by kid, and must be of the
//     algorithm's type; a key the JWKS labels with another algorithm is
//     never used. Keys the token carries itself (jwk, jku, x5u, x5c) are
//     ignored.
//   - A header with "crit" is refused: it names extensions we do not
//     implement, which RFC 7515 says must then be rejected.
//   - Sizes are capped before anything is decoded; base64url must be
//     unpadded and canonical; and a member named twice in the header or
//     the claims is refused, so no two parsers can read a token two ways.
//   - iss must be the issuer's, aud must include one of its audiences, exp
//     is required, and exp, nbf and iat are checked with a minute's leeway
//     for clocks that differ.

// The signature algorithms accepted.
const (
	AlgRS256 = "RS256"
	AlgES256 = "ES256"
	AlgEdDSA = "EdDSA"
)

const (
	// maxJWT caps a token as sent. GitHub's and GitLab's are about 1.5 KiB,
	// Kubernetes' a little more.
	maxJWT = 16 << 10

	// ClockLeeway is how far exp, nbf and iat may be off, for clocks that
	// differ.
	ClockLeeway = time.Minute
)

var b64url = base64.RawURLEncoding.Strict()

// A TokenError says why an ID token was refused. Its message speaks of
// the token only, so it can be shown to whoever sent it.
type TokenError struct{ Reason string }

func (e *TokenError) Error() string { return "the ID token was not accepted: " + e.Reason }

func tokenErr(format string, args ...any) error {
	return &TokenError{Reason: fmt.Sprintf(format, args...)}
}

// errUnknownKey is a token signed with a key the issuer does not publish
// (after fetching its keys again).
var errUnknownKey = tokenErr("it is signed with a key its issuer does not publish")

// jws is a token taken apart, not yet verified.
type jws struct {
	alg, kid string
	claims   map[string]any
	signed   []byte // header "." payload: what the signature covers
	sig      []byte
}

// parseJWS takes a compact JWS apart and checks everything that can be
// checked without a key.
func parseJWS(raw string) (*jws, error) {
	if len(raw) > maxJWT {
		return nil, tokenErr("it is longer than %d bytes", maxJWT)
	}
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return nil, tokenErr("it is not a signed JWT (three parts, separated by dots)")
	}
	hb, err1 := b64url.DecodeString(parts[0])
	pb, err2 := b64url.DecodeString(parts[1])
	sig, err3 := b64url.DecodeString(parts[2])
	if err1 != nil || err2 != nil || err3 != nil {
		return nil, tokenErr("a part of it is not unpadded base64url")
	}
	if len(sig) == 0 {
		return nil, tokenErr("it is not signed")
	}
	header, err := objectMembers(hb)
	if err != nil {
		return nil, tokenErr("its header is not a JSON object: %v", err)
	}
	t := &jws{signed: []byte(parts[0] + "." + parts[1]), sig: sig}
	if err := stringMember(header, "alg", &t.alg); err != nil || t.alg == "" {
		return nil, tokenErr("its header names no algorithm")
	}
	switch t.alg {
	case AlgRS256, AlgES256, AlgEdDSA:
	default:
		return nil, tokenErr("its algorithm %q is not accepted (only RS256, ES256 and EdDSA are)", t.alg)
	}
	if _, ok := header["crit"]; ok {
		return nil, tokenErr("its header has critical extensions (crit), which are not supported")
	}
	if err := stringMember(header, "kid", &t.kid); err != nil {
		return nil, tokenErr("its key ID (kid) is not a string")
	}
	members, err := objectMembers(pb)
	if err != nil {
		return nil, tokenErr("its claims are not a JSON object: %v", err)
	}
	t.claims = make(map[string]any, len(members))
	for k, v := range members {
		d := json.NewDecoder(bytes.NewReader(v))
		d.UseNumber()
		var x any
		if err := d.Decode(&x); err != nil {
			return nil, tokenErr("its claim %q does not parse", k)
		}
		t.claims[k] = x
	}
	return t, nil
}

// objectMembers reads a JSON object's members, refusing one named twice
// and anything after the object.
func objectMembers(b []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(b))
	if tok, err := d.Token(); err != nil || tok != json.Delim('{') {
		return nil, errors.New("not an object")
	}
	out := map[string]json.RawMessage{}
	for d.More() {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		k, ok := tok.(string)
		if !ok {
			return nil, errors.New("a member name is not a string")
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("%q appears twice", k)
		}
		var v json.RawMessage
		if err := d.Decode(&v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	if _, err := d.Token(); err != nil { // the closing brace
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, errors.New("something follows the object")
	}
	return out, nil
}

// stringMember reads an optional string member.
func stringMember(m map[string]json.RawMessage, name string, out *string) error {
	v, ok := m[name]
	if !ok {
		return nil
	}
	return json.Unmarshal(v, out)
}

// keyLookup finds the keys that may have signed a token: those with the
// token's key ID (every key of the algorithm's type, when the token names
// none).
type keyLookup interface {
	lookup(ctx context.Context, kid, alg string) ([]*publicKey, error)
}

// verifyJWT checks a token's signature against the issuer's keys and its
// registered claims, and returns its claims.
func verifyJWT(ctx context.Context, raw string, iss *Issuer, keys keyLookup, now time.Time) (map[string]any, error) {
	t, err := parseJWS(raw)
	if err != nil {
		return nil, err
	}
	// The issuer is checked before any key is fetched, so a token from
	// elsewhere never makes us fetch this issuer's keys again. It counts
	// only once the signature verifies, below.
	if got, _ := t.claims["iss"].(string); got != iss.URL {
		return nil, tokenErr("it was issued by %q, not by %q", got, iss.URL)
	}
	candidates, err := keys.lookup(ctx, t.kid, t.alg)
	if err != nil {
		return nil, err
	}
	verified := false
	for _, k := range candidates {
		if k.verify(t.alg, t.signed, t.sig) {
			verified = true
			break
		}
	}
	if !verified {
		return nil, tokenErr("its signature does not verify")
	}
	if err := checkRegisteredClaims(t.claims, iss, now); err != nil {
		return nil, err
	}
	return t.claims, nil
}

// checkRegisteredClaims checks aud, exp, nbf and iat.
func checkRegisteredClaims(c map[string]any, iss *Issuer, now time.Time) error {
	auds, ok := stringList(c["aud"])
	if !ok || len(auds) == 0 {
		return tokenErr("it has no audience (aud)")
	}
	matched := false
	for _, a := range auds {
		for _, want := range iss.Audiences {
			if a == want {
				matched = true
			}
		}
	}
	if !matched {
		return tokenErr("its audience (%s) is not this server's (%s)", strings.Join(auds, ", "), strings.Join(iss.Audiences, ", "))
	}
	exp, ok, err := numericDate(c, "exp")
	switch {
	case err != nil:
		return err
	case !ok:
		return tokenErr("it has no expiry (exp)")
	case now.After(exp.Add(ClockLeeway)):
		return tokenErr("it expired at %s", exp.UTC().Format(time.RFC3339))
	}
	if nbf, ok, err := numericDate(c, "nbf"); err != nil {
		return err
	} else if ok && now.Add(ClockLeeway).Before(nbf) {
		return tokenErr("it is not valid until %s", nbf.UTC().Format(time.RFC3339))
	}
	if iat, ok, err := numericDate(c, "iat"); err != nil {
		return err
	} else if ok && iat.After(now.Add(ClockLeeway)) {
		return tokenErr("it was issued in the future (%s); check the clocks", iat.UTC().Format(time.RFC3339))
	}
	return nil
}

// numericDate reads a NumericDate claim: seconds since the epoch.
func numericDate(c map[string]any, name string) (time.Time, bool, error) {
	v, ok := c[name]
	if !ok {
		return time.Time{}, false, nil
	}
	n, isNum := v.(json.Number)
	f, err := n.Float64()
	if !isNum || err != nil || math.IsNaN(f) || f < 0 || f > 1e11 {
		return time.Time{}, false, tokenErr("its %s is not a time", name)
	}
	sec, frac := math.Modf(f)
	return time.Unix(int64(sec), int64(frac*1e9)), true, nil
}

// stringList reads a claim that is a string or an array of strings.
func stringList(v any) ([]string, bool) {
	switch x := v.(type) {
	case string:
		return []string{x}, true
	case []any:
		out := make([]string, 0, len(x))
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}
