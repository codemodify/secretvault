package svdeliver

import (
	"bytes"
	"context"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
)

// Config configures a Server.
type Config struct {
	// Dir is the delivery directory, made by Init.
	Dir string

	// SyncRoot is the sync hub's root directory (svserver), so a vault
	// synced to this server can be added by its name there. Empty means
	// vaults are added by path only.
	SyncRoot string

	// CredentialsDir is where systemd put the service's credentials.
	// Empty means $CREDENTIALS_DIRECTORY.
	CredentialsDir string

	// Now is the clock (tests replace it). Defaults to time.Now.
	Now func() time.Time

	// Log receives what the operator should know about. It never gets a
	// secret. Defaults to discarding it.
	Log func(string)
}

// Server is the delivery API, as an http.Handler for the paths under
// /v1/deliver/. It starts sealed, unless it can unseal itself from a
// systemd credential.
type Server struct {
	cfg      Config
	settings *settings
	mux      *http.ServeMux
	limits   *limiter
	audit    *auditLog

	mu       sync.Mutex
	seal     *sealFile
	root     *svcrypto.Secret // nil while sealed
	ids      map[svcrypto.Suite]*svcrypto.Identity
	view     *view // what requests read; nil while sealed
	vaults   map[string]*deliveryVault
	keys     map[string]*issuerKeys // by issuer name
	sessions map[string]*session    // by token hash
	unseal   shareProgress
	rekey    *rekeyOp
}

// view is the unsealed state a request reads: replaced whole whenever the
// policy changes, never changed in place.
type view struct {
	pol     *policy
	byHash  map[string]*tokenRecord
	vaults  map[string]*deliveryVault
	keys    map[string]*issuerKeys
	cas     *x509.CertPool
	ids     map[svcrypto.Suite]*svcrypto.Identity
	logKey  *svcrypto.Identity
	sessTTL time.Duration
}

// issuerKeys is an issuer's key lookup, kept while its configuration is
// unchanged so that fetched keys stay cached.
type issuerKeys struct {
	conf []byte // the issuer's configuration, as JSON
	keys keyLookup
}

type session struct {
	identity string
	role     string
	expires  time.Time
}

type rekeyOp struct {
	req      RekeyRequest
	nonce    string
	progress shareProgress
}

// New opens the delivery server in cfg.Dir, sealed. If a systemd
// credential holds its credential key, it unseals itself with it.
func New(cfg Config) (*Server, error) {
	if cfg.Dir == "" {
		return nil, errors.New("svdeliver: no delivery directory")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	if cfg.CredentialsDir == "" {
		cfg.CredentialsDir = os.Getenv("CREDENTIALS_DIRECTORY")
	}
	f, err := readSeal(cfg.Dir)
	if err != nil {
		return nil, err
	}
	st, err := readSettings(cfg.Dir)
	if err != nil {
		return nil, err
	}
	audit, err := openAudit(filepath.Join(cfg.Dir, AuditFile), f.suite(), f.AuditKey, f.aad("audit"))
	if err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		settings: st,
		mux:      http.NewServeMux(),
		limits:   newLimiter(st.Rate),
		audit:    audit,
		seal:     f,
		vaults:   map[string]*deliveryVault{},
		keys:     map[string]*issuerKeys{},
		sessions: map[string]*session{},
	}
	s.routes()
	s.autoUnseal()
	return s, nil
}

// Close seals the server and closes its audit log.
func (s *Server) Close() error {
	s.sealNow()
	return s.audit.close()
}

// Sealed reports whether the server is sealed.
func (s *Server) Sealed() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.root == nil
}

// autoUnseal unseals the server with the credential key systemd hands
// it, if there is one.
func (s *Server) autoUnseal() {
	if s.cfg.CredentialsDir == "" {
		return
	}
	path := filepath.Join(s.cfg.CredentialsDir, s.settings.UnsealCredential)
	b, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			s.cfg.Log(fmt.Sprintf("the unseal credential %s could not be read: %v", path, err))
		}
		return
	}
	key, err := svformat.ParseUnsealKey(string(b))
	clear(b)
	a := AuditEntry{Op: "unseal", Identity: "credential " + s.settings.UnsealCredential}
	if err == nil {
		s.mu.Lock()
		var root *svcrypto.Secret
		if root, err = s.seal.openRoot(key, slotCredential); err == nil {
			err = s.unsealWith(root)
		}
		s.mu.Unlock()
		clear(key)
	}
	if err != nil {
		s.cfg.Log(fmt.Sprintf("the unseal credential %s does not unseal this server: %v", path, err))
		a.Outcome, a.Reason = OutcomeFailed, err.Error()
	} else {
		s.cfg.Log("unsealed with the systemd credential " + s.settings.UnsealCredential)
		a.Outcome = OutcomeAllowed
	}
	a.Time = s.cfg.Now().UTC()
	if err := s.audit.record(a); err != nil {
		s.cfg.Log("the audit log could not be written: " + err.Error())
	}
}

// unsealWith opens everything under the root key and serves. The caller
// holds s.mu. The root key is kept (or destroyed, on failure).
func (s *Server) unsealWith(root *svcrypto.Secret) error {
	ids, err := s.seal.identities(root)
	if err != nil {
		root.Destroy()
		return fmt.Errorf("the server's identities do not open: %v", err)
	}
	pol, err := loadPolicy(s.cfg.Dir, s.seal, root)
	if err != nil {
		root.Destroy()
		return err
	}
	logKey, err := s.seal.auditKey(root)
	if err != nil {
		root.Destroy()
		return err
	}
	if !bytes.Equal(logKey.Recipient(), s.seal.AuditKey) {
		// seal.json was altered: entries sealed since went to a key that
		// is not ours. Seal to our own from now on.
		s.cfg.Log("the audit key in seal.json is not this server's; entries are sealed to the right one from now on")
		s.audit.setKey(logKey.Recipient())
	}
	s.root, s.ids = root, ids
	if err := s.install(pol, logKey); err != nil {
		s.root.Destroy()
		s.root, s.ids, s.view = nil, nil, nil
		return err
	}
	s.unseal.reset()
	return nil
}

// install makes pol the policy requests see. The caller holds s.mu.
func (s *Server) install(pol *policy, logKey *svcrypto.Identity) error {
	if logKey == nil && s.view != nil {
		logKey = s.view.logKey
	}
	v := &view{pol: pol, byHash: map[string]*tokenRecord{}, vaults: map[string]*deliveryVault{}, keys: map[string]*issuerKeys{}, ids: s.ids, logKey: logKey, sessTTL: s.settings.sessionTTL}
	for _, t := range pol.Tokens {
		v.byHash[t.Hash] = t
	}
	for name, vc := range pol.Vaults {
		dv := s.vaults[name]
		if dv == nil || dv.cfg.Path != vc.Path || dv.cfg.ID != vc.ID {
			if dv != nil {
				dv.close()
			}
			dv = &deliveryVault{cfg: *vc}
		}
		v.vaults[name] = dv
	}
	for name, dv := range s.vaults {
		if v.vaults[name] == nil {
			dv.close()
		}
	}
	for name, iss := range pol.Issuers {
		conf, _ := json.Marshal(iss)
		k := s.keys[name]
		if k == nil || !bytes.Equal(k.conf, conf) {
			var err error
			if k, err = newIssuerKeys(iss, conf, s.cfg.Now); err != nil {
				return err
			}
		}
		v.keys[name] = k
	}
	if pol.ClientCA != "" {
		pool, err := parseCA(pol.ClientCA)
		if err != nil {
			return err
		}
		v.cas = pool
	}
	s.view, s.vaults, s.keys = v, v.vaults, v.keys
	return nil
}

func newIssuerKeys(iss *Issuer, conf []byte, now func() time.Time) (*issuerKeys, error) {
	if len(iss.JWKS) > 0 {
		set, err := parseJWKS(iss.JWKS)
		if err != nil {
			return nil, err
		}
		return &issuerKeys{conf: conf, keys: set}, nil
	}
	r, err := newRemoteKeys(iss, now)
	if err != nil {
		return nil, err
	}
	return &issuerKeys{conf: conf, keys: r}, nil
}

// parseCA reads a PEM bundle of client CA certificates.
func parseCA(text string) (*x509.CertPool, error) {
	certs, err := parseCACerts(text)
	if err != nil {
		return nil, err
	}
	pool := x509.NewCertPool()
	for _, c := range certs {
		pool.AddCert(c)
	}
	return pool, nil
}

func parseCACerts(text string) ([]*x509.Certificate, error) {
	var out []*x509.Certificate
	rest := []byte(text)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("the client CA: %v", err)
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, errors.New("the client CA holds no PEM certificate")
	}
	return out, nil
}

// updatePolicy changes the policy: a copy is changed, checked, saved
// (sealed), and only then used.
func (s *Server) updatePolicy(change func(p *policy) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.view == nil {
		return errSealed
	}
	p := s.view.pol.clone()
	if err := change(p); err != nil {
		return err
	}
	if err := p.check(); err != nil {
		return &apiError{status: http.StatusBadRequest, msg: err.Error()}
	}
	if err := savePolicy(s.cfg.Dir, s.seal, s.root, p); err != nil {
		return err
	}
	return s.install(p, nil)
}

// sealNow forgets every key, closes the vaults and ends every session.
func (s *Server) sealNow() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.root.Destroy()
	s.root, s.ids, s.view = nil, nil, nil
	for _, dv := range s.vaults {
		dv.close()
	}
	s.vaults, s.keys, s.sessions = map[string]*deliveryVault{}, map[string]*issuerKeys{}, map[string]*session{}
	s.unseal.reset()
	if s.rekey != nil {
		s.rekey.progress.reset()
		s.rekey = nil
	}
}

func (s *Server) current() *view {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.view
}

// status describes the seal. The caller holds s.mu.
func (s *Server) statusLocked(now time.Time) Status {
	st := Status{
		Sealed:     s.root == nil,
		Threshold:  s.seal.Threshold,
		Shares:     s.seal.Shares,
		AutoUnseal: len(s.seal.Credential) > 0,
		Version:    secretvault.Version,
	}
	if s.unseal.count() > 0 {
		if exp := s.unseal.expires(s.settings.unsealTimeout); now.After(exp) {
			s.unseal.reset()
		} else {
			st.Progress, st.ProgressExpires = s.unseal.count(), exp.UTC()
		}
	}
	if s.rekey != nil {
		st.Rekey = s.rekeyStatusLocked(now)
	}
	return st
}

func (s *Server) rekeyStatusLocked(now time.Time) *RekeyStatus {
	op := s.rekey
	rs := &RekeyStatus{Nonce: op.nonce, Threshold: s.seal.Threshold, NewShares: op.req.Shares, NewThreshold: op.req.Threshold, Credential: op.req.Credential}
	if op.progress.count() > 0 {
		if exp := op.progress.expires(s.settings.unsealTimeout); now.After(exp) {
			op.progress.reset()
		} else {
			rs.Progress, rs.Expires = op.progress.count(), exp.UTC()
		}
	}
	return rs
}

// Requests.

// apiError is a request refused: status and msg are answered, reason
// (when it says more) goes to the audit log only.
type apiError struct {
	status int
	msg    string
	reason string
}

func (e *apiError) Error() string { return e.msg }

var errSealed = &apiError{status: http.StatusServiceUnavailable, msg: "the server is sealed: operators unseal it with 'secretvault-server unseal'"}

// msgNoSecret is the answer for an item that does not exist and for one
// the caller may not read, alike, so that no one learns what exists by
// asking for what they may not have.
const msgNoSecret = "no such secret, or not allowed"

// call is one request being answered.
type call struct {
	w    http.ResponseWriter
	r    *http.Request
	ip   string
	now  time.Time
	body []byte
	a    AuditEntry
}

// Body limits.
const (
	maxBody      = 64 << 10
	maxAdminBody = 512 << 10
)

// handle registers h behind rate limiting, reading up to limit bytes of
// body first. A request goes in the audit log once h names its operation
// (c.a.Op).
func (s *Server) handle(pattern string, limit int64, h func(c *call)) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		c := &call{w: w, r: r, ip: clientIP(r), now: s.cfg.Now()}
		c.a = AuditEntry{Time: c.now.UTC(), IP: c.ip}
		if ok, wait := s.limits.allow(c.ip, c.now); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
			reply(w, http.StatusTooManyRequests, ErrorBody{Error: "too many requests; slow down"})
			return
		}
		if limit > 0 {
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
			if err != nil {
				c.a.Op = "request"
				s.fail(c, &apiError{status: http.StatusRequestEntityTooLarge, msg: fmt.Sprintf("the body is larger than %d bytes, or could not be read", limit)})
				return
			}
			c.body = body
		}
		h(c)
	})
}

// admin registers an admin call: the admin token is required, and the
// server must be unsealed (the token's hash is in the sealed policy).
func (s *Server) admin(pattern, op string, h func(c *call, v *view)) {
	s.handle(pattern, maxAdminBody, func(c *call) {
		c.a.Op, c.a.Identity = op, "admin"
		v := s.current()
		if v == nil {
			s.fail(c, errSealed)
			return
		}
		if err := checkAdmin(c.r, v); err != nil {
			c.a.Identity = ""
			s.fail(c, err)
			return
		}
		h(c, v)
	})
}

func checkAdmin(r *http.Request, v *view) *apiError {
	tok, ok := bearer(r)
	if !ok || subtle.ConstantTimeCompare([]byte(tokenHash(tok)), []byte(v.pol.AdminHash)) != 1 {
		return &apiError{status: http.StatusUnauthorized, msg: "the admin API needs the admin token (Authorization: Bearer svda_...)"}
	}
	return nil
}

// decode reads the request's JSON body into v, refusing unknown members
// so that a mistyped one is not silently ignored.
func (c *call) decode(v any) *apiError {
	d := json.NewDecoder(bytes.NewReader(c.body))
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		return &apiError{status: http.StatusBadRequest, msg: "the body is not what this call takes: " + err.Error()}
	}
	return nil
}

// ok answers a request that was done, once it is in the audit log.
func (s *Server) ok(c *call, status int, body any) {
	if c.a.Op != "" {
		c.a.Outcome, c.a.Status = OutcomeAllowed, status
		if err := s.audit.record(c.a); err != nil {
			s.cfg.Log("the audit log could not be written: " + err.Error())
			reply(c.w, http.StatusInternalServerError, ErrorBody{Error: "the audit log could not be written, so this is not answered"})
			return
		}
	}
	switch b := body.(type) {
	case nil:
		c.w.WriteHeader(status)
	case rawValue:
		c.w.Header().Set("Content-Type", "application/octet-stream")
		c.w.WriteHeader(status)
		c.w.Write(b)
	default:
		reply(c.w, status, body)
	}
}

// fail answers a request refused or failed, and logs it.
func (s *Server) fail(c *call, err error) {
	var e *apiError
	if !errors.As(err, &e) {
		s.cfg.Log(err.Error())
		e = &apiError{status: http.StatusInternalServerError, msg: "the server could not do that: " + err.Error()}
	}
	if c.a.Op != "" {
		switch {
		case e == errSealed:
			c.a.Outcome = OutcomeSealed
		case e.status == http.StatusUnauthorized || e.status == http.StatusForbidden || e.status == http.StatusNotFound:
			c.a.Outcome = OutcomeDenied
		default:
			c.a.Outcome = OutcomeFailed
		}
		c.a.Status, c.a.Reason = e.status, e.msg
		if e.reason != "" {
			c.a.Reason = e.reason
		}
		if aerr := s.audit.record(c.a); aerr != nil {
			s.cfg.Log("the audit log could not be written: " + aerr.Error())
		}
	}
	if e.status == http.StatusUnauthorized {
		c.w.Header().Set("WWW-Authenticate", `Bearer realm="secretvault"`)
	}
	reply(c.w, e.status, ErrorBody{Error: e.msg})
}

// ServeHTTP answers the delivery API.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// limiter is a token bucket per IP address.
type limiter struct {
	rate, burst float64
	mu          sync.Mutex
	buckets     map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newLimiter allows rate requests a second per address, in bursts of up
// to ten seconds' worth. A rate below zero turns limiting off.
func newLimiter(rate float64) *limiter {
	if rate < 0 {
		return nil
	}
	return &limiter{rate: rate, burst: max(10*rate, 1), buckets: map[string]*bucket{}}
}

func (l *limiter) allow(key string, now time.Time) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > 10000 {
		for k, b := range l.buckets {
			if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
				delete(l.buckets, k)
			}
		}
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(l.burst, b.tokens+el*l.rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// ListenAndServe serves h on addr until ctx ends, as svserver's does, but
// asking clients for a certificate (which they need not send), for the
// roles that recognise one. cert nil serves plain HTTP, for running
// behind a proxy that terminates TLS (no client certificates then).
func ListenAndServe(ctx context.Context, addr string, h http.Handler, cert *tls.Certificate) error {
	srv := &http.Server{
		Handler:           h,
		ReadHeaderTimeout: 20 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      10 * time.Minute,
		IdleTimeout:       2 * time.Minute,
		MaxHeaderBytes:    64 << 10,
	}
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	errc := make(chan error, 1)
	go func() {
		if cert != nil {
			srv.TLSConfig = &tls.Config{
				Certificates: []tls.Certificate{*cert},
				MinVersion:   tls.VersionTLS12,
				// Asked for, not required: tokens and ID tokens need none.
				// A certificate sent is checked when a request is made
				// (the client CA is in the sealed policy), and the TLS
				// handshake has already proved the client holds its key.
				ClientAuth: tls.RequestClientCert,
			}
			errc <- srv.ServeTLS(ln, "", "")
		} else {
			errc <- srv.Serve(ln)
		}
	}()
	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		stop, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := srv.Shutdown(stop); err != nil {
			srv.Close()
		}
		return nil
	}
}
