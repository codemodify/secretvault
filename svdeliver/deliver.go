package svdeliver

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
)

func (s *Server) routes() {
	// Anyone: the seal's state, and operators' shares (a share is its
	// own credential).
	s.handle("GET /v1/deliver/status", 0, s.handleStatus)
	s.handle("POST /v1/deliver/unseal", maxBody, s.handleUnseal)
	s.handle("POST /v1/deliver/rekey", maxBody, s.handleRekeyShare)

	// Machines.
	s.handle("POST /v1/deliver/login/oidc", maxBody, s.handleLogin)
	s.handle("GET /v1/deliver/secret/{vault}/{item...}", 0, s.handleSecret)
	s.handle("GET /v1/deliver/list/{vault}", 0, s.handleList)
	s.handle("GET /v1/deliver/list/{vault}/{prefix...}", 0, s.handleList)

	// The admin.
	s.admin("POST /v1/deliver/admin/seal", "seal", s.adminSeal)
	s.admin("POST /v1/deliver/admin/rekey", "rekey.start", s.adminRekeyStart)
	s.admin("DELETE /v1/deliver/admin/rekey", "rekey.cancel", s.adminRekeyCancel)
	s.admin("GET /v1/deliver/admin/identity", "identity", s.adminIdentity)
	s.admin("GET /v1/deliver/admin/tokens", "token.list", s.adminTokens)
	s.admin("POST /v1/deliver/admin/tokens", "token.create", s.adminTokenCreate)
	s.admin("DELETE /v1/deliver/admin/tokens/{name}", "token.revoke", s.adminTokenRevoke)
	s.admin("GET /v1/deliver/admin/roles", "role.list", s.adminRoles)
	s.admin("PUT /v1/deliver/admin/roles/{name}", "role.set", s.adminRoleSet)
	s.admin("DELETE /v1/deliver/admin/roles/{name}", "role.remove", s.adminRoleRemove)
	s.admin("GET /v1/deliver/admin/vaults", "vault.list", s.adminVaults)
	s.admin("POST /v1/deliver/admin/vaults", "vault.add", s.adminVaultAdd)
	s.admin("DELETE /v1/deliver/admin/vaults/{name}", "vault.remove", s.adminVaultRemove)
	s.admin("GET /v1/deliver/admin/issuers", "issuer.list", s.adminIssuers)
	s.admin("PUT /v1/deliver/admin/issuers/{name}", "issuer.set", s.adminIssuerSet)
	s.admin("DELETE /v1/deliver/admin/issuers/{name}", "issuer.remove", s.adminIssuerRemove)
	s.admin("GET /v1/deliver/admin/client-ca", "client-ca.show", s.adminCAShow)
	s.admin("PUT /v1/deliver/admin/client-ca", "client-ca.set", s.adminCASet)
	s.admin("DELETE /v1/deliver/admin/client-ca", "client-ca.clear", s.adminCAClear)
	s.admin("POST /v1/deliver/admin/admin-token", "admin-token.rotate", s.adminTokenRotate)
	s.admin("GET /v1/deliver/admin/audit", "audit.read", s.adminAudit)
}

func (s *Server) handleStatus(c *call) {
	s.mu.Lock()
	st := s.statusLocked(c.now)
	s.mu.Unlock()
	reply(c.w, http.StatusOK, st)
}

// handleUnseal takes one share. Shares are held in memory until there
// are enough, or until they time out; they are never logged.
func (s *Server) handleUnseal(c *call) {
	c.a.Op, c.a.Identity = "unseal", "operator"
	var req UnsealRequest
	if err := c.decode(&req); err != nil {
		s.fail(c, err)
		return
	}
	s.mu.Lock()
	st, err := s.unsealStep(c, &req)
	s.mu.Unlock()
	if err != nil {
		s.fail(c, err)
		return
	}
	s.ok(c, http.StatusOK, st)
}

// unsealStep does the work of one unseal call. The caller holds s.mu.
func (s *Server) unsealStep(c *call, req *UnsealRequest) (Status, error) {
	switch {
	case s.root != nil:
		c.a.Reason = "already unsealed"
		return s.statusLocked(c.now), nil
	case req.Reset:
		s.unseal.reset()
		c.a.Op = "unseal.reset"
		return s.statusLocked(c.now), nil
	}
	done, err := s.unseal.add(req.Share, s.seal.Threshold, c.now, s.settings.unsealTimeout)
	if err != nil {
		return Status{}, shareError(err)
	}
	if !done {
		return s.statusLocked(c.now), nil
	}
	key, err := s.unseal.combine()
	if err != nil {
		return Status{}, err
	}
	root, err := s.seal.openRoot(key, slotUnseal)
	clear(key)
	if err != nil {
		return Status{}, &apiError{status: http.StatusBadRequest,
			msg: "those shares do not fit together: one is from an older split or another server. Every share is forgotten; start again"}
	}
	if err := s.unsealWith(root); err != nil {
		return Status{}, err
	}
	c.a.Reason = "unsealed"
	s.cfg.Log("unsealed by the operators' shares")
	return s.statusLocked(c.now), nil
}

func shareError(err error) error {
	var e errShare
	if errors.As(err, &e) {
		return &apiError{status: http.StatusBadRequest, msg: string(e)}
	}
	return err
}

// handleRekeyShare takes one current share towards a rekey the admin
// started. The last one makes the new shares, which it answers.
func (s *Server) handleRekeyShare(c *call) {
	c.a.Op, c.a.Identity = "rekey", "operator"
	var req RekeyShare
	if err := c.decode(&req); err != nil {
		s.fail(c, err)
		return
	}
	s.mu.Lock()
	res, err := s.rekeyStep(c, &req)
	s.mu.Unlock()
	if err != nil {
		s.fail(c, err)
		return
	}
	s.ok(c, http.StatusOK, res)
}

// rekeyStep does the work of one rekey share. The caller holds s.mu.
func (s *Server) rekeyStep(c *call, req *RekeyShare) (*RekeyResult, error) {
	op := s.rekey
	if s.root == nil {
		return nil, errSealed
	}
	if op == nil || subtle.ConstantTimeCompare([]byte(req.Nonce), []byte(op.nonce)) != 1 {
		return nil, &apiError{status: http.StatusNotFound, msg: "no rekey with that nonce is in progress"}
	}
	done, err := op.progress.add(req.Share, s.seal.Threshold, c.now, s.settings.unsealTimeout)
	if err != nil {
		return nil, shareError(err)
	}
	if !done {
		return &RekeyResult{RekeyStatus: *s.rekeyStatusLocked(c.now)}, nil
	}
	key, err := op.progress.combine()
	if err != nil {
		return nil, err
	}
	root, err := s.seal.openRoot(key, slotUnseal)
	clear(key)
	if err != nil {
		return nil, &apiError{status: http.StatusBadRequest,
			msg: "those shares do not fit together: one is from an older split or another server. Every share is forgotten; give them again"}
	}
	same := subtle.ConstantTimeCompare(root.Bytes(), s.root.Bytes()) == 1
	root.Destroy()
	if !same {
		return nil, errors.New("the shares open a root key other than the one in use")
	}
	f := *s.seal
	shares, err := f.rekey(s.root, op.req.Shares, op.req.Threshold)
	if err != nil {
		return nil, err
	}
	res := &RekeyResult{Done: true, Shares: shares}
	switch op.req.Credential {
	case "new":
		if res.Credential, err = f.newCredential(s.root); err != nil {
			return nil, err
		}
	case "remove":
		f.Credential = nil
	}
	f.Rekeyed = c.now.UTC()
	if err := writeSeal(s.cfg.Dir, &f); err != nil {
		return nil, err
	}
	s.seal, s.rekey = &f, nil
	res.RekeyStatus = RekeyStatus{Nonce: op.nonce, Threshold: f.Threshold, NewShares: f.Shares, NewThreshold: f.Threshold, Credential: op.req.Credential}
	c.a.Reason = "new shares made; the old ones no longer unseal"
	s.cfg.Log("the unseal key was rotated: the old shares no longer unseal")
	return res, nil
}

// handleLogin exchanges an ID token for a session in a role.
func (s *Server) handleLogin(c *call) {
	c.a.Op = "login"
	var req LoginRequest
	if err := c.decode(&req); err != nil {
		s.fail(c, err)
		return
	}
	c.a.Role = req.Role
	v := s.current()
	if v == nil {
		s.fail(c, errSealed)
		return
	}
	who, r, err := s.oidcCaller(c.r.Context(), v, req.Role, req.JWT, c.now)
	if who != nil {
		c.a.Identity = who.identity
	}
	if err != nil {
		s.fail(c, err)
		return
	}
	sess, err := s.newSession(who, r, c.now, v.sessTTL)
	if err != nil {
		s.fail(c, err)
		return
	}
	s.ok(c, http.StatusOK, sess)
}

// handleSecret answers an item's fields, or one of them.
func (s *Server) handleSecret(c *call) {
	c.a.Op = "read"
	vault, item, field := c.r.PathValue("vault"), c.r.PathValue("item"), c.r.URL.Query().Get("field")
	c.a.Vault, c.a.Item, c.a.Field = vault, item, field
	v := s.current()
	if v == nil {
		s.fail(c, errSealed)
		return
	}
	if checkName("vault", vault) != nil || svcore.CheckName(item) != nil {
		s.fail(c, &apiError{status: http.StatusBadRequest, msg: "that is not a vault and item name"})
		return
	}
	who, err := s.authenticate(c, v)
	if who != nil {
		c.a.Identity = who.identity
	}
	if err != nil {
		s.fail(c, err)
		return
	}
	// The policy is decided on the names alone, before the vault is
	// touched: what the caller may not read, they cannot learn exists.
	role, ok := who.allowed(vault, item, CapRead)
	if !ok {
		c.a.Role = who.roleNames()
		s.fail(c, &apiError{status: http.StatusNotFound, msg: msgNoSecret, reason: "no rule allows reading it"})
		return
	}
	c.a.Role = role
	vlt, err := s.openVault(v, vault, c)
	if err != nil {
		s.fail(c, err)
		return
	}
	e, err := vlt.Get(item)
	if errors.Is(err, svcore.ErrNotFound) {
		s.fail(c, &apiError{status: http.StatusNotFound, msg: "no such secret"})
		return
	}
	if err != nil {
		s.fail(c, err)
		return
	}
	defer e.Item.Wipe()
	out := Secret{Vault: vault, Item: item, Kind: e.Item.Kind, Version: e.Rev.String(), Updated: e.Time}
	if field != "" {
		f, ok := e.Item.Field(field)
		if !ok {
			s.fail(c, &apiError{status: http.StatusNotFound, msg: "that item has no field " + quote(field)})
			return
		}
		if raw(c.r) {
			s.ok(c, http.StatusOK, rawValue(f.Value))
			return
		}
		out.Field = field
		if utf8.Valid(f.Value) {
			val := string(f.Value)
			out.Value = &val
		} else {
			val := base64.StdEncoding.EncodeToString(f.Value)
			out.ValueBase64 = &val
		}
	} else {
		sf, ok := e.Item.Secret()
		if raw(c.r) {
			if !ok {
				s.fail(c, &apiError{status: http.StatusNotFound, msg: "that item has no secret field: name one with ?field="})
				return
			}
			s.ok(c, http.StatusOK, rawValue(sf.Value))
			return
		}
		if ok {
			out.SecretField = sf.Name
		}
		for _, f := range e.Item.Fields {
			if utf8.Valid(f.Value) {
				if out.Fields == nil {
					out.Fields = map[string]string{}
				}
				out.Fields[f.Name] = string(f.Value)
			} else {
				if out.FieldsBase64 == nil {
					out.FieldsBase64 = map[string]string{}
				}
				out.FieldsBase64[f.Name] = base64.StdEncoding.EncodeToString(f.Value)
			}
		}
	}
	s.ok(c, http.StatusOK, out)
}

// raw reports whether the caller asked for a bare value (?raw=true), for
// curl: the field named, or the item's secret.
func raw(r *http.Request) bool {
	v, ok := r.URL.Query()["raw"]
	return ok && (len(v) == 0 || v[0] == "" || v[0] == "1" || v[0] == "true")
}

// rawValue is a field's value answered as it is.
type rawValue []byte

// openVault returns a delivery vault the caller's role allowed, open.
func (s *Server) openVault(v *view, name string, c *call) (*svcore.Vault, error) {
	dv := v.vaults[name]
	if dv == nil {
		return nil, &apiError{status: http.StatusNotFound, msg: "no such vault"}
	}
	vlt, err := dv.get(v.ids, c.now)
	if err != nil {
		return nil, &apiError{status: http.StatusServiceUnavailable, msg: "vault " + name + " cannot be opened by the server: " + err.Error()}
	}
	return vlt, nil
}

// handleList answers the names of a vault's items, under a prefix, that
// the caller may list.
func (s *Server) handleList(c *call) {
	c.a.Op = "list"
	vault, prefix := c.r.PathValue("vault"), c.r.PathValue("prefix")
	c.a.Vault, c.a.Item = vault, prefix
	v := s.current()
	if v == nil {
		s.fail(c, errSealed)
		return
	}
	if checkName("vault", vault) != nil || len(prefix) > 1024 || !utf8.ValidString(prefix) {
		s.fail(c, &apiError{status: http.StatusBadRequest, msg: "that is not a vault name and prefix"})
		return
	}
	who, err := s.authenticate(c, v)
	if who != nil {
		c.a.Identity = who.identity
	}
	if err != nil {
		s.fail(c, err)
		return
	}
	if !who.touches(vault, CapList) {
		c.a.Role = who.roleNames()
		s.fail(c, &apiError{status: http.StatusNotFound, msg: "no such vault, or not allowed", reason: "no rule allows listing it"})
		return
	}
	c.a.Role = who.roleNames()
	vlt, err := s.openVault(v, vault, c)
	if err != nil {
		s.fail(c, err)
		return
	}
	entries, err := vlt.List(prefix)
	if err != nil {
		s.fail(c, err)
		return
	}
	out := List{Vault: vault, Prefix: prefix, Items: []string{}}
	for _, e := range entries {
		if _, ok := who.allowed(vault, e.Item.Name, CapList); ok {
			out.Items = append(out.Items, e.Item.Name)
		}
		e.Item.Wipe()
	}
	s.ok(c, http.StatusOK, out)
}

func quote(s string) string {
	if len(s) > 64 {
		s = s[:64] + "..."
	}
	return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
}

// recipientFor is the server's recipient for a suite, as text.
func recipientFor(ids map[svcrypto.Suite]*svcrypto.Identity, s svcrypto.Suite) string {
	id := ids[s]
	if id == nil {
		return ""
	}
	return svformat.EncodeRecipient(s, id.Recipient())
}
