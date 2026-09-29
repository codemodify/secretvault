package svdeliver

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Machine authentication. A request proves who sent it with one of:
//
//	Authorization: Bearer svdt_...   a token an admin made
//	Authorization: Bearer svds_...   a session from POST /v1/deliver/login/oidc
//	Authorization: Bearer eyJ...     an ID token, with the role in the
//	                                 X-Secretvault-Role header (or ?role=):
//	                                 a login and a request in one
//	a TLS client certificate         when no Authorization header is sent
//
// There are no human logins: people administer the server with the admin
// token and unseal it with their shares.

// RoleHeader names the role an ID token sent as a bearer token logs in to.
const RoleHeader = "X-Secretvault-Role"

// maxSessions caps the sessions held at once.
const maxSessions = 100000

func bearer(r *http.Request) (string, bool) {
	scheme, cred, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || !strings.EqualFold(scheme, "Bearer") {
		return "", false
	}
	cred = strings.TrimSpace(cred)
	return cred, cred != ""
}

// authenticate finds who a request comes from, and the roles they have.
func (s *Server) authenticate(c *call, v *view) (*caller, error) {
	if c.r.Header.Get("Authorization") != "" {
		cred, ok := bearer(c.r)
		switch {
		case !ok:
			return nil, &apiError{status: http.StatusUnauthorized, msg: "the Authorization header is not 'Bearer TOKEN'"}
		case strings.HasPrefix(cred, tokenPrefix):
			return s.tokenCaller(c, v, cred)
		case strings.HasPrefix(cred, sessionPrefix):
			return s.sessionCaller(c, v, cred)
		case strings.HasPrefix(cred, adminPrefix):
			return nil, &apiError{status: http.StatusUnauthorized, msg: "the admin token is for the admin API only; make a token for this"}
		case strings.Count(cred, ".") == 2:
			role := c.r.Header.Get(RoleHeader)
			if role == "" {
				role = c.r.URL.Query().Get("role")
			}
			if role == "" {
				return nil, &apiError{status: http.StatusUnauthorized, msg: "an ID token needs the role to log in to, in the " + RoleHeader + " header"}
			}
			who, _, err := s.oidcCaller(c.r.Context(), v, role, cred, c.now)
			return who, err
		default:
			return nil, &apiError{status: http.StatusUnauthorized, msg: "that is neither a token this server made nor an ID token"}
		}
	}
	if c.r.TLS != nil && len(c.r.TLS.PeerCertificates) > 0 {
		return s.certCaller(c, v)
	}
	return nil, &apiError{status: http.StatusUnauthorized, msg: "no credentials: send 'Authorization: Bearer TOKEN', or a client certificate"}
}

func (s *Server) tokenCaller(c *call, v *view, cred string) (*caller, error) {
	t := v.byHash[tokenHash(cred)]
	switch {
	case t == nil:
		return nil, &apiError{status: http.StatusUnauthorized, msg: "that token is not valid: it was revoked, or never made here"}
	case !t.Expires.IsZero() && !c.now.Before(t.Expires):
		return nil, &apiError{status: http.StatusUnauthorized, msg: fmt.Sprintf("that token expired at %s", t.Expires.UTC().Format(time.RFC3339)),
			reason: "token " + t.Name + " expired"}
	case !t.fromAllowed(c.ip):
		return nil, &apiError{status: http.StatusUnauthorized, msg: fmt.Sprintf("that token may not be used from %s", c.ip),
			reason: "token " + t.Name + " used from outside its CIDRs"}
	}
	who := &caller{identity: "token:" + t.Name}
	for _, r := range sortedRoles(v.pol) {
		if r.Token == t.Name {
			who.roles = append(who.roles, r)
		}
	}
	return who, nil
}

func (s *Server) sessionCaller(c *call, v *view, cred string) (*caller, error) {
	h := tokenHash(cred)
	s.mu.Lock()
	sess := s.sessions[h]
	if sess != nil && !c.now.Before(sess.expires) {
		delete(s.sessions, h)
		sess = nil
	}
	s.mu.Unlock()
	if sess == nil {
		return nil, &apiError{status: http.StatusUnauthorized, msg: "that session is not valid: it expired, or the server was sealed since; log in again"}
	}
	r := v.pol.Roles[sess.role]
	if r == nil || r.OIDC == nil {
		return nil, &apiError{status: http.StatusUnauthorized, msg: "the role that session logged in to is gone; log in again"}
	}
	return &caller{identity: sess.identity, roles: []*Role{r}}, nil
}

// oidcCaller verifies an ID token for a role. The answer for a role that
// does not exist, or does not take this token's claims, is the same.
func (s *Server) oidcCaller(ctx context.Context, v *view, roleName, jwt string, now time.Time) (*caller, *Role, error) {
	notThisRole := &apiError{status: http.StatusForbidden, msg: fmt.Sprintf("the ID token does not satisfy role %q (or there is no such role)", roleName)}
	r := v.pol.Roles[roleName]
	if r == nil || r.OIDC == nil {
		notThisRole.reason = "no OIDC role " + roleName
		return nil, nil, notThisRole
	}
	iss := v.pol.Issuers[r.OIDC.Issuer]
	keys := v.keys[r.OIDC.Issuer]
	if iss == nil || keys == nil {
		return nil, nil, fmt.Errorf("role %s names issuer %s, which is gone", r.Name, r.OIDC.Issuer)
	}
	claims, err := verifyJWT(ctx, jwt, iss, keys.keys, now)
	if err != nil {
		var te *TokenError
		if errors.As(err, &te) {
			return nil, nil, &apiError{status: http.StatusUnauthorized, msg: err.Error()}
		}
		// The issuer's keys could not be fetched: not the token's fault.
		return nil, nil, &apiError{status: http.StatusBadGateway, msg: "the ID token could not be checked: " + err.Error()}
	}
	sub, _ := claims["sub"].(string)
	identity := "oidc:" + iss.Name + ":" + sub
	if !r.OIDC.matchesClaims(claims) {
		notThisRole.reason = identity + " does not match the claims of role " + r.Name + ": " + mismatches(r.OIDC, claims)
		return nil, nil, notThisRole
	}
	return &caller{identity: identity, roles: []*Role{r}}, r, nil
}

// mismatches lists, for the audit log, the claims that did not match.
func mismatches(m *OIDCMatch, claims map[string]any) string {
	var out []string
	for _, name := range sortedKeys(m.Claims) {
		vals := claimValues(claims, name)
		if !slices.ContainsFunc(vals, func(v string) bool { return globMatch(m.Claims[name], v) }) {
			out = append(out, fmt.Sprintf("%s=%q (wants %q)", name, strings.Join(vals, ","), m.Claims[name]))
		}
	}
	return strings.Join(out, "; ")
}

func (s *Server) certCaller(c *call, v *view) (*caller, error) {
	chain := c.r.TLS.PeerCertificates
	leaf := chain[0]
	if c.now.Before(leaf.NotBefore) || c.now.After(leaf.NotAfter) {
		return nil, &apiError{status: http.StatusUnauthorized, msg: "the client certificate is expired or not yet valid"}
	}
	verified := false
	if v.cas != nil {
		inter := x509.NewCertPool()
		for _, ic := range chain[1:] {
			inter.AddCert(ic)
		}
		_, err := leaf.Verify(x509.VerifyOptions{
			Roots:         v.cas,
			Intermediates: inter,
			CurrentTime:   c.now,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		})
		verified = err == nil
	}
	fp := certFingerprint(leaf)
	who := &caller{identity: fmt.Sprintf("cert:%s (sha256:%s)", leaf.Subject, fp[:16])}
	for _, r := range sortedRoles(v.pol) {
		if r.Cert != nil && r.Cert.matches(leaf, verified) {
			who.roles = append(who.roles, r)
		}
	}
	if len(who.roles) == 0 {
		reason := "no role matches " + who.identity
		if !verified {
			reason += " (it does not chain to the client CA)"
		}
		return nil, &apiError{status: http.StatusUnauthorized, msg: "no role takes this client certificate", reason: reason}
	}
	return who, nil
}

// newSession starts a session for a role after a login.
func (s *Server) newSession(who *caller, r *Role, now time.Time, def time.Duration) (Session, error) {
	tok := newSecretToken(sessionPrefix)
	exp := now.Add(r.sessionTTL(def))
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.view == nil {
		return Session{}, errSealed
	}
	if len(s.sessions) >= maxSessions/10 {
		for h, sess := range s.sessions {
			if !now.Before(sess.expires) {
				delete(s.sessions, h)
			}
		}
	}
	if len(s.sessions) >= maxSessions {
		return Session{}, &apiError{status: http.StatusServiceUnavailable, msg: "the server holds too many sessions; try again later"}
	}
	s.sessions[tokenHash(tok)] = &session{identity: who.identity, role: r.Name, expires: exp}
	return Session{Token: tok, Expires: exp.UTC(), Role: r.Name, Identity: who.identity}, nil
}

func sortedRoles(p *policy) []*Role {
	out := make([]*Role, 0, len(p.Roles))
	for _, name := range sortedKeys(p.Roles) {
		out = append(out, p.Roles[name])
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
