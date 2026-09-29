package svdeliver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// ClientOptions configure a Client.
type ClientOptions struct {
	// URL is the server, like https://secrets.example.com:8443, with a
	// path if a proxy mounts it under one.
	URL string

	// Fingerprint pins the server's certificate by its SHA-256 (hex;
	// colons and case do not matter), for a server with a self-signed
	// certificate. Empty means the certificate must chain to CA, or to
	// the system's roots.
	Fingerprint string

	// CA is a PEM certificate authority to trust for the server instead of
	// the system's roots.
	CA []byte

	// Certificate is a client certificate to present, for roles that
	// recognise one.
	Certificate *tls.Certificate

	// Token is sent as "Authorization: Bearer": a token, a session, or the
	// admin token.
	Token string

	// HTTP, when set, carries the requests instead (tests).
	HTTP *http.Client
}

// Client talks to a delivery server.
type Client struct {
	base  *url.URL
	token string
	http  *http.Client
}

// APIError is an error the server answered.
type APIError struct {
	Status  int
	Message string
}

func (e *APIError) Error() string { return e.Message }

// ErrPin is a server whose certificate is not the one pinned.
var ErrPin = errors.New("svdeliver: the server's certificate does not match the pinned fingerprint")

// NewClient returns a client for the server at o.URL.
func NewClient(o ClientOptions) (*Client, error) {
	u, err := url.Parse(o.URL)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("%q is not a server URL", o.URL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		// Plain HTTP only to this machine: tokens and secrets cross it.
		if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("%s is not HTTPS", o.URL)
		}
	default:
		return nil, fmt.Errorf("%s is not HTTPS", o.URL)
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	c := &Client{base: u, token: o.Token, http: o.HTTP}
	if c.http == nil {
		cfg := &tls.Config{MinVersion: tls.VersionTLS12}
		if o.Certificate != nil {
			cfg.Certificates = []tls.Certificate{*o.Certificate}
		}
		if len(o.CA) > 0 {
			pool := x509.NewCertPool()
			if !pool.AppendCertsFromPEM(o.CA) {
				return nil, errors.New("the CA holds no PEM certificate")
			}
			cfg.RootCAs = pool
		}
		if o.Fingerprint != "" {
			pin, ok := normaliseFingerprint(o.Fingerprint)
			if !ok {
				return nil, fmt.Errorf("%q is not a SHA-256 certificate fingerprint", o.Fingerprint)
			}
			want, _ := hex.DecodeString(pin)
			// The pin replaces the chain and name checks: a self-signed
			// certificate has neither, and the pin is stronger than both.
			cfg.InsecureSkipVerify = true
			cfg.VerifyConnection = func(cs tls.ConnectionState) error {
				if len(cs.PeerCertificates) == 0 {
					return ErrPin
				}
				got := sha256.Sum256(cs.PeerCertificates[0].Raw)
				if subtle.ConstantTimeCompare(got[:], want) != 1 {
					return fmt.Errorf("%w (it is %x)", ErrPin, got)
				}
				return nil
			}
		}
		t := http.DefaultTransport.(*http.Transport).Clone()
		t.TLSClientConfig = cfg
		c.http = &http.Client{Transport: t, Timeout: time.Minute}
	}
	return c, nil
}

// SetToken changes the bearer token sent: to a session after a login,
// say.
func (c *Client) SetToken(t string) { c.token = t }

// do sends a request and decodes a 2xx answer into out.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, in, out any) error {
	u := *c.base
	u.Path += path
	u.RawPath = ""
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}
	var body io.Reader
	if in != nil {
		b, err := json.Marshal(in)
		if err != nil {
			return err
		}
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return err
	}
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 64<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		var e ErrorBody
		if json.Unmarshal(b, &e) != nil || e.Error == "" {
			e.Error = fmt.Sprintf("the server answered %s", resp.Status)
		}
		return &APIError{Status: resp.StatusCode, Message: e.Error}
	}
	if out == nil || len(b) == 0 {
		return nil
	}
	return json.Unmarshal(b, out)
}

// itemPath escapes an item's name segment by segment, keeping its
// slashes.
func itemPath(name string) string {
	segs := strings.Split(name, "/")
	for i, s := range segs {
		segs[i] = url.PathEscape(s)
	}
	return strings.Join(segs, "/")
}

// Status is the seal's state.
func (c *Client) Status(ctx context.Context) (Status, error) {
	var st Status
	err := c.do(ctx, http.MethodGet, "/v1/deliver/status", nil, nil, &st)
	return st, err
}

// Unseal gives one unseal share.
func (c *Client) Unseal(ctx context.Context, share string) (Status, error) {
	var st Status
	err := c.do(ctx, http.MethodPost, "/v1/deliver/unseal", nil, UnsealRequest{Share: share}, &st)
	return st, err
}

// UnsealReset forgets the shares given so far.
func (c *Client) UnsealReset(ctx context.Context) (Status, error) {
	var st Status
	err := c.do(ctx, http.MethodPost, "/v1/deliver/unseal", nil, UnsealRequest{Reset: true}, &st)
	return st, err
}

// LoginOIDC exchanges an ID token for a session in a role. It does not
// start using the session: SetToken does.
func (c *Client) LoginOIDC(ctx context.Context, role, jwt string) (Session, error) {
	var s Session
	err := c.do(ctx, http.MethodPost, "/v1/deliver/login/oidc", nil, LoginRequest{Role: role, JWT: jwt}, &s)
	return s, err
}

// Secret returns an item's fields, or one field when field is not empty.
func (c *Client) Secret(ctx context.Context, vault, item, field string) (*Secret, error) {
	var q url.Values
	if field != "" {
		q = url.Values{"field": {field}}
	}
	var s Secret
	if err := c.do(ctx, http.MethodGet, "/v1/deliver/secret/"+url.PathEscape(vault)+"/"+itemPath(item), q, nil, &s); err != nil {
		return nil, err
	}
	return &s, nil
}

// Value returns one field's value: the named one, or the item's secret
// when field is empty.
func (c *Client) Value(ctx context.Context, vault, item, field string) ([]byte, error) {
	s, err := c.Secret(ctx, vault, item, field)
	if err != nil {
		return nil, err
	}
	return s.Bytes()
}

// Bytes is the value of the field asked for, or of the item's secret
// field when none was.
func (s *Secret) Bytes() ([]byte, error) {
	if s.Field != "" {
		switch {
		case s.Value != nil:
			return []byte(*s.Value), nil
		case s.ValueBase64 != nil:
			return base64.StdEncoding.DecodeString(*s.ValueBase64)
		}
		return nil, fmt.Errorf("the server sent no value for %s/%s#%s", s.Vault, s.Item, s.Field)
	}
	if s.SecretField == "" {
		return nil, fmt.Errorf("%s/%s has no secret field: name one", s.Vault, s.Item)
	}
	if v, ok := s.Fields[s.SecretField]; ok {
		return []byte(v), nil
	}
	if v, ok := s.FieldsBase64[s.SecretField]; ok {
		return base64.StdEncoding.DecodeString(v)
	}
	return nil, fmt.Errorf("the server sent no value for %s/%s", s.Vault, s.Item)
}

// List returns the names under prefix the caller may list.
func (c *Client) List(ctx context.Context, vault, prefix string) (List, error) {
	var l List
	err := c.do(ctx, http.MethodGet, "/v1/deliver/list/"+url.PathEscape(vault)+"/"+itemPath(prefix), nil, nil, &l)
	return l, err
}

// The admin API. The client's token must be the admin token.

// Seal seals the server.
func (c *Client) Seal(ctx context.Context) (Status, error) {
	var st Status
	err := c.do(ctx, http.MethodPost, "/v1/deliver/admin/seal", nil, nil, &st)
	return st, err
}

// RekeyStart starts rotating the unseal key.
func (c *Client) RekeyStart(ctx context.Context, req RekeyRequest) (RekeyStatus, error) {
	var st RekeyStatus
	err := c.do(ctx, http.MethodPost, "/v1/deliver/admin/rekey", nil, req, &st)
	return st, err
}

// RekeyCancel cancels a rekey in progress.
func (c *Client) RekeyCancel(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/v1/deliver/admin/rekey", nil, nil, nil)
}

// RekeyShare gives one current share towards a rekey. It needs no token.
func (c *Client) RekeyShare(ctx context.Context, nonce, share string) (RekeyResult, error) {
	var r RekeyResult
	err := c.do(ctx, http.MethodPost, "/v1/deliver/rekey", nil, RekeyShare{Nonce: nonce, Share: share}, &r)
	return r, err
}

// Identity returns the server's recipients.
func (c *Client) Identity(ctx context.Context) (Identity, error) {
	var id Identity
	err := c.do(ctx, http.MethodGet, "/v1/deliver/admin/identity", nil, nil, &id)
	return id, err
}

// Tokens lists the tokens.
func (c *Client) Tokens(ctx context.Context) ([]TokenInfo, error) {
	var out []TokenInfo
	err := c.do(ctx, http.MethodGet, "/v1/deliver/admin/tokens", nil, nil, &out)
	return out, err
}

// CreateToken makes a token.
func (c *Client) CreateToken(ctx context.Context, req TokenRequest) (NewToken, error) {
	var t NewToken
	err := c.do(ctx, http.MethodPost, "/v1/deliver/admin/tokens", nil, req, &t)
	return t, err
}

// RevokeToken removes a token.
func (c *Client) RevokeToken(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/v1/deliver/admin/tokens/"+url.PathEscape(name), nil, nil, nil)
}

// Roles lists the roles.
func (c *Client) Roles(ctx context.Context) ([]Role, error) {
	var out []Role
	err := c.do(ctx, http.MethodGet, "/v1/deliver/admin/roles", nil, nil, &out)
	return out, err
}

// SetRole makes or replaces a role.
func (c *Client) SetRole(ctx context.Context, r Role) (Role, error) {
	var out Role
	err := c.do(ctx, http.MethodPut, "/v1/deliver/admin/roles/"+url.PathEscape(r.Name), nil, r, &out)
	return out, err
}

// RemoveRole removes a role.
func (c *Client) RemoveRole(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/v1/deliver/admin/roles/"+url.PathEscape(name), nil, nil, nil)
}

// Vaults lists the delivery vaults.
func (c *Client) Vaults(ctx context.Context) ([]VaultInfo, error) {
	var out []VaultInfo
	err := c.do(ctx, http.MethodGet, "/v1/deliver/admin/vaults", nil, nil, &out)
	return out, err
}

// AddVault adds a delivery vault.
func (c *Client) AddVault(ctx context.Context, req VaultRequest) (VaultInfo, error) {
	var out VaultInfo
	err := c.do(ctx, http.MethodPost, "/v1/deliver/admin/vaults", nil, req, &out)
	return out, err
}

// RemoveVault removes a delivery vault (the folder stays).
func (c *Client) RemoveVault(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/v1/deliver/admin/vaults/"+url.PathEscape(name), nil, nil, nil)
}

// Issuers lists the OIDC issuers.
func (c *Client) Issuers(ctx context.Context) ([]Issuer, error) {
	var out []Issuer
	err := c.do(ctx, http.MethodGet, "/v1/deliver/admin/issuers", nil, nil, &out)
	return out, err
}

// SetIssuer makes or replaces an issuer.
func (c *Client) SetIssuer(ctx context.Context, iss Issuer) (Issuer, error) {
	var out Issuer
	err := c.do(ctx, http.MethodPut, "/v1/deliver/admin/issuers/"+url.PathEscape(iss.Name), nil, iss, &out)
	return out, err
}

// RemoveIssuer removes an issuer no role uses.
func (c *Client) RemoveIssuer(ctx context.Context, name string) error {
	return c.do(ctx, http.MethodDelete, "/v1/deliver/admin/issuers/"+url.PathEscape(name), nil, nil, nil)
}

// ClientCA returns the client CA.
func (c *Client) ClientCA(ctx context.Context) (ClientCA, error) {
	var out ClientCA
	err := c.do(ctx, http.MethodGet, "/v1/deliver/admin/client-ca", nil, nil, &out)
	return out, err
}

// SetClientCA replaces the client CA.
func (c *Client) SetClientCA(ctx context.Context, pem string) (ClientCA, error) {
	var out ClientCA
	err := c.do(ctx, http.MethodPut, "/v1/deliver/admin/client-ca", nil, ClientCA{PEM: pem}, &out)
	return out, err
}

// ClearClientCA removes the client CA.
func (c *Client) ClearClientCA(ctx context.Context) error {
	return c.do(ctx, http.MethodDelete, "/v1/deliver/admin/client-ca", nil, nil, nil)
}

// RotateAdminToken makes a new admin token; the old one stops working.
func (c *Client) RotateAdminToken(ctx context.Context) (AdminToken, error) {
	var out AdminToken
	err := c.do(ctx, http.MethodPost, "/v1/deliver/admin/admin-token", nil, nil, &out)
	return out, err
}

// Audit reads the audit log: up to limit entries after seq after, or the
// newest limit when after is 0.
func (c *Client) Audit(ctx context.Context, after uint64, limit int) (AuditLog, error) {
	q := url.Values{}
	if after > 0 {
		q.Set("after", fmt.Sprint(after))
	}
	if limit > 0 {
		q.Set("limit", fmt.Sprint(limit))
	}
	var out AuditLog
	err := c.do(ctx, http.MethodGet, "/v1/deliver/admin/audit", q, nil, &out)
	return out, err
}
