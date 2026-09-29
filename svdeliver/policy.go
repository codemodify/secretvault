package svdeliver

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"
	"unicode/utf8"
)

// Policies. A role says who it is for (one identity: a token's name, a
// client certificate, or an issuer and the claims its ID tokens must
// carry) and what they may do: rules of a vault, an item glob and
// capabilities. Nothing is allowed that no rule allows, and only the
// delivery vaults are reachable at all.
//
// A request authenticated by a token or a certificate has every role
// whose identity matches; one made with a session from an OIDC login has
// the role it logged in to, and nothing else.

// Capabilities a rule can grant.
const (
	CapRead = "read" // an item's fields
	CapList = "list" // item names
)

// Issuer is an OpenID Connect issuer whose ID tokens roles accept.
type Issuer struct {
	Name string `json:"name"`

	// URL is the issuer exactly as its tokens' iss claim has it, like
	// https://token.actions.githubusercontent.com.
	URL string `json:"url"`

	// Audiences are this server's names in the issuer's tokens: a token's
	// aud must include one. Pipelines ask their issuer for a token with
	// one of these.
	Audiences []string `json:"audiences"`

	// JWKS, when set, is the issuer's key set, used instead of discovery
	// (for a Kubernetes cluster whose keys are not published, say).
	JWKS json.RawMessage `json:"jwks,omitempty"`

	// CA, when set, is the PEM certificate authority that the issuer's
	// HTTPS certificate chains to, instead of the system's roots.
	CA string `json:"ca,omitempty"`
}

func (iss *Issuer) check() error {
	if err := checkName("issuer", iss.Name); err != nil {
		return err
	}
	if len(iss.JWKS) > 0 {
		if _, err := parseJWKS(iss.JWKS); err != nil {
			return fmt.Errorf("issuer %s: %v", iss.Name, err)
		}
		if iss.URL == "" || len(iss.URL) > 512 {
			return fmt.Errorf("issuer %s: its URL (the tokens' iss) is empty or too long", iss.Name)
		}
	} else {
		u, err := url.Parse(iss.URL)
		if err != nil || u.Scheme != "https" || u.Host == "" || u.RawQuery != "" || u.Fragment != "" || len(iss.URL) > 512 {
			return fmt.Errorf("issuer %s: %q is not an HTTPS issuer URL (without a key set, its keys are found through discovery)", iss.Name, iss.URL)
		}
	}
	if len(iss.Audiences) == 0 {
		return fmt.Errorf("issuer %s: name at least one audience, which its tokens must carry", iss.Name)
	}
	for _, a := range iss.Audiences {
		if a == "" || len(a) > 512 {
			return fmt.Errorf("issuer %s: an audience is empty or too long", iss.Name)
		}
	}
	if iss.CA != "" {
		if _, err := issuerClient(iss); err != nil {
			return err
		}
	}
	return nil
}

// Role grants an identity capabilities on items of delivery vaults.
type Role struct {
	Name string `json:"name"`

	// The identity: exactly one of these.
	Token string     `json:"token,omitempty"` // a token's name
	Cert  *CertMatch `json:"cert,omitempty"`
	OIDC  *OIDCMatch `json:"oidc,omitempty"`

	Rules []Rule `json:"rules"`

	// TTL is how long a session from an OIDC login to this role lasts, as
	// a duration like "15m". Empty means the server's default.
	TTL string `json:"ttl,omitempty"`
}

// CertMatch recognises a client certificate. Every condition given must
// hold. A subject or SAN is only believed of a certificate that chains to
// the server's client CA; a pinned fingerprint needs no CA.
type CertMatch struct {
	// Subject is a glob over the subject as RFC 2253 text, as
	// `openssl x509 -noout -subject -nameopt RFC2253` prints it:
	// "CN=deploy,O=Acme".
	Subject string `json:"subject,omitempty"`

	// SAN is a glob that one of the certificate's subject alternative
	// names must match: a DNS name, an email address, a URI (such as a
	// SPIFFE ID) or an IP address.
	SAN string `json:"san,omitempty"`

	// Fingerprint pins the certificate itself: the SHA-256 of its DER, in
	// hex (colons and case do not matter).
	Fingerprint string `json:"fingerprint,omitempty"`
}

// OIDCMatch recognises ID tokens: from the named issuer, with every claim
// given matching its glob. Claims not named do not matter.
type OIDCMatch struct {
	Issuer string `json:"issuer"`

	// Claims map a claim to a glob its value must match. A claim inside
	// an object is named by its path, with '/': "kubernetes.io/namespace".
	// A claim that is an array matches if any element does.
	Claims map[string]string `json:"claims"`
}

// Rule allows capabilities on the items of a vault whose names match a
// glob.
type Rule struct {
	Vault        string   `json:"vault"`
	Items        string   `json:"items"`
	Capabilities []string `json:"capabilities"`
}

var nameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)

// checkName accepts the names of vaults, roles, tokens and issuers:
// lowercase letters, digits, '.', '-' and '_', starting with a letter or
// digit, at most 64 bytes. They go into URLs and the audit log as they
// are.
func checkName(what, name string) error {
	if !nameRE.MatchString(name) {
		return fmt.Errorf("%q is not a %s name (lowercase letters, digits, '.', '-' and '_', at most 64)", name, what)
	}
	return nil
}

// MaxSessionTTL is the longest a session can last, whatever a role says.
const MaxSessionTTL = 12 * time.Hour

func (r *Role) check(issuers map[string]*Issuer) error {
	if err := checkName("role", r.Name); err != nil {
		return err
	}
	kinds := 0
	if r.Token != "" {
		kinds++
		if err := checkName("token", r.Token); err != nil {
			return err
		}
	}
	if r.Cert != nil {
		kinds++
		if err := r.Cert.check(); err != nil {
			return fmt.Errorf("role %s: %v", r.Name, err)
		}
	}
	if r.OIDC != nil {
		kinds++
		if err := r.OIDC.check(issuers); err != nil {
			return fmt.Errorf("role %s: %v", r.Name, err)
		}
	}
	if kinds != 1 {
		return fmt.Errorf("role %s: give exactly one identity: a token, a certificate, or an OIDC issuer and claims", r.Name)
	}
	if len(r.Rules) == 0 {
		return fmt.Errorf("role %s: it has no rules, so it would allow nothing", r.Name)
	}
	for _, rule := range r.Rules {
		if err := rule.check(); err != nil {
			return fmt.Errorf("role %s: %v", r.Name, err)
		}
	}
	if r.TTL != "" {
		d, err := time.ParseDuration(r.TTL)
		if err != nil || d < time.Minute || d > MaxSessionTTL {
			return fmt.Errorf("role %s: its ttl %q is not a duration between 1m and %v", r.Name, r.TTL, MaxSessionTTL)
		}
		if r.OIDC == nil {
			return fmt.Errorf("role %s: a ttl is for sessions from OIDC logins only", r.Name)
		}
	}
	return nil
}

func (m *CertMatch) check() error {
	if m.Subject == "" && m.SAN == "" && m.Fingerprint == "" {
		return errors.New("a certificate match needs a subject, a SAN or a fingerprint")
	}
	if m.Fingerprint != "" {
		fp, ok := normaliseFingerprint(m.Fingerprint)
		if !ok {
			return fmt.Errorf("%q is not a SHA-256 certificate fingerprint", m.Fingerprint)
		}
		m.Fingerprint = fp
	}
	for _, g := range []string{m.Subject, m.SAN} {
		if err := checkGlob(g, true); err != nil {
			return err
		}
	}
	return nil
}

func (m *OIDCMatch) check(issuers map[string]*Issuer) error {
	if issuers[m.Issuer] == nil {
		return fmt.Errorf("there is no issuer %q (add it with 'secretvault-server issuer set')", m.Issuer)
	}
	// An issuer such as GitHub's signs tokens for everyone who asks, with
	// whatever audience they ask for: a role that asked nothing of the
	// claims would take every pipeline in the world.
	specific := false
	for claim, g := range m.Claims {
		if claim == "" || len(claim) > 256 {
			return errors.New("a claim's name is empty or too long")
		}
		if err := checkGlob(g, false); err != nil {
			return fmt.Errorf("claim %s: %v", claim, err)
		}
		if strings.Trim(g, "*?") != "" {
			specific = true
		}
	}
	if !specific {
		return errors.New("an OIDC role must match at least one claim with something other than wildcards (repository, project_path, sub...)")
	}
	return nil
}

func (r *Rule) check() error {
	if err := checkGlob(r.Vault, false); err != nil {
		return fmt.Errorf("a rule's vault: %v", err)
	}
	if err := checkGlob(r.Items, false); err != nil {
		return fmt.Errorf("a rule's items: %v", err)
	}
	if len(r.Capabilities) == 0 {
		return errors.New("a rule grants no capability (read, list)")
	}
	for _, c := range r.Capabilities {
		if c != CapRead && c != CapList {
			return fmt.Errorf("%q is not a capability (read, list)", c)
		}
	}
	return nil
}

func checkGlob(g string, mayBeEmpty bool) error {
	if g == "" && !mayBeEmpty {
		return errors.New("an empty pattern")
	}
	if len(g) > 1024 || !utf8.ValidString(g) {
		return errors.New("a pattern is at most 1024 bytes of UTF-8")
	}
	return nil
}

// allows reports whether the role's rules allow cap on the item.
func (r *Role) allows(vault, item, capability string) bool {
	for _, rule := range r.Rules {
		if slices.Contains(rule.Capabilities, capability) && globMatch(rule.Vault, vault) && globMatch(rule.Items, item) {
			return true
		}
	}
	return false
}

// touches reports whether any rule grants cap on some items of the vault.
func (r *Role) touches(vault, capability string) bool {
	for _, rule := range r.Rules {
		if slices.Contains(rule.Capabilities, capability) && globMatch(rule.Vault, vault) {
			return true
		}
	}
	return false
}

// sessionTTL is how long a session for the role lasts.
func (r *Role) sessionTTL(def time.Duration) time.Duration {
	if d, err := time.ParseDuration(r.TTL); err == nil && d > 0 {
		return min(d, MaxSessionTTL)
	}
	return def
}

// matchesClaims reports whether a verified token's claims satisfy the
// role.
func (m *OIDCMatch) matchesClaims(claims map[string]any) bool {
	for name, g := range m.Claims {
		ok := false
		for _, v := range claimValues(claims, name) {
			if globMatch(g, v) {
				ok = true
				break
			}
		}
		if !ok {
			return false
		}
	}
	return true
}

// claimValues returns a claim's values as text: a top-level member of
// that exact name, or else one found by walking objects along the '/'
// path. Strings, numbers and booleans have one value; an array has its
// elements'; objects and nulls have none.
func claimValues(claims map[string]any, name string) []string {
	v, ok := claims[name]
	if !ok {
		var cur any = claims
		for seg := range strings.SplitSeq(name, "/") {
			m, isObject := cur.(map[string]any)
			if !isObject {
				return nil
			}
			if cur, ok = m[seg]; !ok {
				return nil
			}
		}
		v = cur
	}
	if list, isList := v.([]any); isList {
		var out []string
		for _, e := range list {
			if s, ok := scalarText(e); ok {
				out = append(out, s)
			}
		}
		return out
	}
	if s, ok := scalarText(v); ok {
		return []string{s}
	}
	return nil
}

func scalarText(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case bool:
		if x {
			return "true", true
		}
		return "false", true
	}
	return "", false
}

// matches reports whether a client certificate is the one the match
// describes. verified says whether it chains to the client CA.
func (m *CertMatch) matches(leaf *x509.Certificate, verified bool) bool {
	if m.Fingerprint != "" && m.Fingerprint != certFingerprint(leaf) {
		return false
	}
	if m.Subject != "" || m.SAN != "" {
		if !verified {
			return false
		}
		if m.Subject != "" && !globMatch(m.Subject, leaf.Subject.String()) {
			return false
		}
		if m.SAN != "" && !slices.ContainsFunc(sans(leaf), func(s string) bool { return globMatch(m.SAN, s) }) {
			return false
		}
	}
	return true
}

func sans(c *x509.Certificate) []string {
	out := append([]string(nil), c.DNSNames...)
	out = append(out, c.EmailAddresses...)
	for _, u := range c.URIs {
		out = append(out, u.String())
	}
	for _, ip := range c.IPAddresses {
		out = append(out, ip.String())
	}
	return out
}

// certFingerprint is the SHA-256 of a certificate's DER, in lowercase hex.
func certFingerprint(c *x509.Certificate) string {
	s := sha256.Sum256(c.Raw)
	return hex.EncodeToString(s[:])
}

// normaliseFingerprint reads a SHA-256 fingerprint written with or
// without colons, in either case.
func normaliseFingerprint(s string) (string, bool) {
	clean := strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.ToLower(s))
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != sha256.Size {
		return "", false
	}
	return clean, true
}

// globMatch reports whether s matches pattern, where '*' stands for any
// run of characters ('/' included) and '?' for any one character. Every
// other character stands for itself.
func globMatch(pattern, s string) bool {
	p, n := []rune(pattern), []rune(s)
	pi, ni := 0, 0
	star, mark := -1, 0
	for ni < len(n) {
		switch {
		case pi < len(p) && p[pi] == '*':
			star, mark = pi, ni
			pi++
		case pi < len(p) && (p[pi] == '?' || p[pi] == n[ni]):
			pi++
			ni++
		case star >= 0:
			// Let the last star take one more character, and go on.
			pi = star + 1
			mark++
			ni = mark
		default:
			return false
		}
	}
	for pi < len(p) && p[pi] == '*' {
		pi++
	}
	return pi == len(p)
}

// caller is who a request comes from, once authenticated.
type caller struct {
	// identity names them in the audit log: token:NAME,
	// cert:SUBJECT (sha256:...), or oidc:ISSUER:SUBJECT.
	identity string
	roles    []*Role
}

// allowed reports which of the caller's roles allows cap on the item.
func (c *caller) allowed(vault, item, capability string) (string, bool) {
	for _, r := range c.roles {
		if r.allows(vault, item, capability) {
			return r.Name, true
		}
	}
	return "", false
}

// touches reports whether any of the caller's roles grants cap on some
// items of the vault.
func (c *caller) touches(vault, capability string) bool {
	return slices.ContainsFunc(c.roles, func(r *Role) bool { return r.touches(vault, capability) })
}

func (c *caller) roleNames() string {
	names := make([]string, len(c.roles))
	for i, r := range c.roles {
		names[i] = r.Name
	}
	return strings.Join(names, ",")
}
