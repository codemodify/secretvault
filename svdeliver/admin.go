package svdeliver

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svserver"
)

// The admin API: the policy (vaults, issuers, the client CA, roles and
// tokens), sealing, starting a rekey, and reading the audit log. Every
// call needs the admin token, and so an unsealed server: the token's hash
// is kept in the sealed policy.

func (s *Server) adminSeal(c *call, v *view) {
	s.sealNow()
	s.cfg.Log("sealed by the admin")
	s.mu.Lock()
	st := s.statusLocked(c.now)
	s.mu.Unlock()
	s.ok(c, http.StatusOK, st)
}

func (s *Server) adminRekeyStart(c *call, v *view) {
	var req RekeyRequest
	if err := c.decode(&req); err != nil {
		s.fail(c, err)
		return
	}
	if req.Threshold < 2 || req.Shares < req.Threshold || req.Shares > 255 {
		s.fail(c, &apiError{status: http.StatusBadRequest, msg: fmt.Sprintf("cannot split into %d shares with threshold %d (need 2 <= threshold <= shares <= 255)", req.Shares, req.Threshold)})
		return
	}
	switch req.Credential {
	case "":
		req.Credential = "keep"
	case "keep", "new", "remove":
	default:
		s.fail(c, &apiError{status: http.StatusBadRequest, msg: "credential is keep, new or remove"})
		return
	}
	s.mu.Lock()
	if s.rekey != nil {
		s.mu.Unlock()
		s.fail(c, &apiError{status: http.StatusConflict, msg: "a rekey is in progress already; cancel it first"})
		return
	}
	s.rekey = &rekeyOp{req: req, nonce: hex.EncodeToString(svcrypto.RandomBytes(16))}
	st := s.rekeyStatusLocked(c.now)
	s.mu.Unlock()
	c.a.Reason = fmt.Sprintf("%d shares, %d to unseal; credential: %s", req.Shares, req.Threshold, req.Credential)
	s.ok(c, http.StatusCreated, st)
}

func (s *Server) adminRekeyCancel(c *call, v *view) {
	s.mu.Lock()
	op := s.rekey
	if op != nil {
		op.progress.reset()
		s.rekey = nil
	}
	s.mu.Unlock()
	if op == nil {
		s.fail(c, &apiError{status: http.StatusNotFound, msg: "no rekey is in progress"})
		return
	}
	s.ok(c, http.StatusNoContent, nil)
}

func (s *Server) adminIdentity(c *call, v *view) {
	out := Identity{Recipients: map[string]string{}}
	for suite := range v.ids {
		out.Recipients[suite.String()] = recipientFor(v.ids, suite)
	}
	s.ok(c, http.StatusOK, out)
}

// Tokens.

func tokenInfo(t *tokenRecord) TokenInfo {
	return TokenInfo{Name: t.Name, Created: t.Created, Expires: t.Expires, CIDRs: t.CIDRs}
}

func (s *Server) adminTokens(c *call, v *view) {
	out := []TokenInfo{}
	for _, name := range sortedKeys(v.pol.Tokens) {
		out = append(out, tokenInfo(v.pol.Tokens[name]))
	}
	s.ok(c, http.StatusOK, out)
}

// MaxTokenTTL is the longest a token's expiry may be set.
const MaxTokenTTL = 10 * 365 * 24 * time.Hour

func (s *Server) adminTokenCreate(c *call, v *view) {
	var req TokenRequest
	if err := c.decode(&req); err != nil {
		s.fail(c, err)
		return
	}
	c.a.Target = req.Name
	if err := checkName("token", req.Name); err != nil {
		s.fail(c, &apiError{status: http.StatusBadRequest, msg: err.Error()})
		return
	}
	rec := &tokenRecord{Name: req.Name, Created: c.now.UTC()}
	if req.TTL != "" {
		d, err := time.ParseDuration(req.TTL)
		if err != nil || d < time.Minute || d > MaxTokenTTL {
			s.fail(c, &apiError{status: http.StatusBadRequest, msg: fmt.Sprintf("the ttl %q is not a duration between 1m and %v", req.TTL, MaxTokenTTL)})
			return
		}
		rec.Expires = c.now.Add(d).UTC()
	}
	for _, cidr := range req.CIDRs {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			s.fail(c, &apiError{status: http.StatusBadRequest, msg: fmt.Sprintf("%q is not a CIDR, like 10.0.0.0/8 or 2001:db8::/32", cidr)})
			return
		}
		rec.CIDRs = append(rec.CIDRs, p.Masked().String())
	}
	tok := newSecretToken(tokenPrefix)
	rec.Hash = tokenHash(tok)
	err := s.updatePolicy(func(p *policy) error {
		if p.Tokens[rec.Name] != nil {
			return &apiError{status: http.StatusConflict, msg: "there is a token of that name already; revoke it first"}
		}
		if p.Tokens == nil {
			p.Tokens = map[string]*tokenRecord{}
		}
		p.Tokens[rec.Name] = rec
		return nil
	})
	if err != nil {
		s.fail(c, err)
		return
	}
	s.ok(c, http.StatusCreated, NewToken{TokenInfo: tokenInfo(rec), Token: tok})
}

func (s *Server) adminTokenRevoke(c *call, v *view) {
	name := c.r.PathValue("name")
	c.a.Target = name
	err := s.updatePolicy(func(p *policy) error {
		if p.Tokens[name] == nil {
			return &apiError{status: http.StatusNotFound, msg: "there is no token of that name"}
		}
		delete(p.Tokens, name)
		return nil
	})
	if err != nil {
		s.fail(c, err)
		return
	}
	s.ok(c, http.StatusNoContent, nil)
}

// Roles.

func (s *Server) adminRoles(c *call, v *view) {
	out := sortedRoles(v.pol)
	s.ok(c, http.StatusOK, out)
}

func (s *Server) adminRoleSet(c *call, v *view) {
	name := c.r.PathValue("name")
	c.a.Target = name
	var r Role
	if err := c.decode(&r); err != nil {
		s.fail(c, err)
		return
	}
	if r.Name == "" {
		r.Name = name
	}
	if r.Name != name {
		s.fail(c, &apiError{status: http.StatusBadRequest, msg: "the role's name is not the one in the URL"})
		return
	}
	err := s.updatePolicy(func(p *policy) error {
		if p.Roles == nil {
			p.Roles = map[string]*Role{}
		}
		p.Roles[name] = &r
		return nil
	})
	if err != nil {
		s.fail(c, err)
		return
	}
	s.ok(c, http.StatusOK, &r)
}

func (s *Server) adminRoleRemove(c *call, v *view) {
	name := c.r.PathValue("name")
	c.a.Target = name
	err := s.updatePolicy(func(p *policy) error {
		if p.Roles[name] == nil {
			return &apiError{status: http.StatusNotFound, msg: "there is no role of that name"}
		}
		delete(p.Roles, name)
		return nil
	})
	if err != nil {
		s.fail(c, err)
		return
	}
	s.ok(c, http.StatusNoContent, nil)
}

// Vaults.

func (s *Server) vaultInfo(v *view, vc *VaultConfig, now time.Time) VaultInfo {
	info := VaultInfo{Name: vc.Name, Path: vc.Path, ID: vc.ID, Added: vc.Added}
	dv := v.vaults[vc.Name]
	if dv == nil {
		return info
	}
	suite, err := dv.state(v.ids, now)
	if suite != 0 {
		info.Suite, info.Recipient = suite.String(), recipientFor(v.ids, suite)
	}
	info.Open = err == nil
	if err != nil {
		info.Problem = err.Error()
	}
	return info
}

func (s *Server) adminVaults(c *call, v *view) {
	out := []VaultInfo{}
	for _, name := range sortedKeys(v.pol.Vaults) {
		out = append(out, s.vaultInfo(v, v.pol.Vaults[name], c.now))
	}
	s.ok(c, http.StatusOK, out)
}

func (s *Server) adminVaultAdd(c *call, v *view) {
	var req VaultRequest
	if err := c.decode(&req); err != nil {
		s.fail(c, err)
		return
	}
	c.a.Target = req.Name
	bad := func(msg string) { s.fail(c, &apiError{status: http.StatusBadRequest, msg: msg}) }
	if err := checkName("vault", req.Name); err != nil {
		bad(err.Error())
		return
	}
	path := req.Path
	switch {
	case (req.Path == "") == (req.Sync == ""):
		bad("give the vault's folder (path), or its name on this server's sync hub (sync)")
		return
	case req.Sync != "":
		if s.cfg.SyncRoot == "" {
			bad("this server runs no sync hub to find that vault on")
			return
		}
		if err := svserver.CheckVaultName(req.Sync); err != nil {
			bad(err.Error())
			return
		}
		path = filepath.Join(s.cfg.SyncRoot, "vaults", req.Sync, "files")
	case !filepath.IsAbs(path):
		bad("the vault's folder must be given as an absolute path")
		return
	}
	vlt, err := openVaultReadOnly(filepath.Clean(path))
	if err != nil {
		bad(err.Error())
		return
	}
	vc := &VaultConfig{Name: req.Name, Path: filepath.Clean(path), ID: vlt.ID().String(), Added: c.now.UTC()}
	err = s.updatePolicy(func(p *policy) error {
		if p.Vaults[vc.Name] != nil {
			return &apiError{status: http.StatusConflict, msg: "there is a delivery vault of that name already; remove it first"}
		}
		if p.Vaults == nil {
			p.Vaults = map[string]*VaultConfig{}
		}
		p.Vaults[vc.Name] = vc
		return nil
	})
	if err != nil {
		s.fail(c, err)
		return
	}
	c.a.Reason = "vault " + vc.ID + " in " + vc.Path
	info := VaultInfo{Name: vc.Name, Path: vc.Path, ID: vc.ID, Added: vc.Added}
	if now := s.current(); now != nil {
		info = s.vaultInfo(now, vc, c.now)
	}
	s.ok(c, http.StatusCreated, info)
}

func (s *Server) adminVaultRemove(c *call, v *view) {
	name := c.r.PathValue("name")
	c.a.Target = name
	err := s.updatePolicy(func(p *policy) error {
		if p.Vaults[name] == nil {
			return &apiError{status: http.StatusNotFound, msg: "there is no delivery vault of that name"}
		}
		delete(p.Vaults, name)
		return nil
	})
	if err != nil {
		s.fail(c, err)
		return
	}
	s.ok(c, http.StatusNoContent, nil)
}

// Issuers.

func (s *Server) adminIssuers(c *call, v *view) {
	out := []*Issuer{}
	for _, name := range sortedKeys(v.pol.Issuers) {
		out = append(out, v.pol.Issuers[name])
	}
	s.ok(c, http.StatusOK, out)
}

func (s *Server) adminIssuerSet(c *call, v *view) {
	name := c.r.PathValue("name")
	c.a.Target = name
	var iss Issuer
	if err := c.decode(&iss); err != nil {
		s.fail(c, err)
		return
	}
	if iss.Name == "" {
		iss.Name = name
	}
	if iss.Name != name {
		s.fail(c, &apiError{status: http.StatusBadRequest, msg: "the issuer's name is not the one in the URL"})
		return
	}
	err := s.updatePolicy(func(p *policy) error {
		if p.Issuers == nil {
			p.Issuers = map[string]*Issuer{}
		}
		p.Issuers[name] = &iss
		return nil
	})
	if err != nil {
		s.fail(c, err)
		return
	}
	s.ok(c, http.StatusOK, &iss)
}

func (s *Server) adminIssuerRemove(c *call, v *view) {
	name := c.r.PathValue("name")
	c.a.Target = name
	err := s.updatePolicy(func(p *policy) error {
		if p.Issuers[name] == nil {
			return &apiError{status: http.StatusNotFound, msg: "there is no issuer of that name"}
		}
		var users []string
		for _, r := range sortedRoles(p) {
			if r.OIDC != nil && r.OIDC.Issuer == name {
				users = append(users, r.Name)
			}
		}
		if len(users) > 0 {
			return &apiError{status: http.StatusConflict, msg: "roles use that issuer: " + strings.Join(users, ", ")}
		}
		delete(p.Issuers, name)
		return nil
	})
	if err != nil {
		s.fail(c, err)
		return
	}
	s.ok(c, http.StatusNoContent, nil)
}

// The client CA.

func caSubjects(text string) []string {
	certs, _ := parseCACerts(text)
	out := make([]string, len(certs))
	for i, c := range certs {
		out[i] = c.Subject.String()
	}
	return out
}

func (s *Server) adminCAShow(c *call, v *view) {
	s.ok(c, http.StatusOK, ClientCA{PEM: v.pol.ClientCA, Subjects: caSubjects(v.pol.ClientCA)})
}

func (s *Server) adminCASet(c *call, v *view) {
	var req ClientCA
	if err := c.decode(&req); err != nil {
		s.fail(c, err)
		return
	}
	if _, err := parseCA(req.PEM); err != nil {
		s.fail(c, &apiError{status: http.StatusBadRequest, msg: err.Error()})
		return
	}
	if err := s.updatePolicy(func(p *policy) error { p.ClientCA = req.PEM; return nil }); err != nil {
		s.fail(c, err)
		return
	}
	subjects := caSubjects(req.PEM)
	c.a.Reason = strings.Join(subjects, "; ")
	s.ok(c, http.StatusOK, ClientCA{PEM: req.PEM, Subjects: subjects})
}

func (s *Server) adminCAClear(c *call, v *view) {
	if err := s.updatePolicy(func(p *policy) error { p.ClientCA = ""; return nil }); err != nil {
		s.fail(c, err)
		return
	}
	s.ok(c, http.StatusNoContent, nil)
}

// The admin token, and the audit log.

func (s *Server) adminTokenRotate(c *call, v *view) {
	tok := newSecretToken(adminPrefix)
	if err := s.updatePolicy(func(p *policy) error { p.AdminHash = tokenHash(tok); return nil }); err != nil {
		s.fail(c, err)
		return
	}
	c.a.Reason = "the old admin token no longer works"
	s.ok(c, http.StatusOK, AdminToken{Token: tok})
}

func (s *Server) adminAudit(c *call, v *view) {
	q := c.r.URL.Query()
	after, limit := uint64(0), 100
	if a := q.Get("after"); a != "" {
		n, err := strconv.ParseUint(a, 10, 64)
		if err != nil {
			s.fail(c, &apiError{status: http.StatusBadRequest, msg: "after is not a sequence number"})
			return
		}
		after = n
	}
	if l := q.Get("limit"); l != "" {
		n, err := strconv.Atoi(l)
		if err != nil || n < 1 {
			s.fail(c, &apiError{status: http.StatusBadRequest, msg: "limit is not a positive number"})
			return
		}
		limit = min(n, 10000)
	}
	entries, err := s.audit.read(v.logKey, after, limit)
	out := AuditLog{Entries: entries, Intact: err == nil}
	if out.Entries == nil {
		out.Entries = []AuditEntry{}
	}
	if err != nil {
		if !errors.Is(err, ErrAuditDamaged) {
			s.fail(c, err)
			return
		}
		out.Problem = strings.TrimPrefix(err.Error(), "svdeliver: ")
	}
	s.ok(c, http.StatusOK, out)
}
