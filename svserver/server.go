package svserver

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svstore"
)

// Config configures a Server.
type Config struct {
	// Root is the directory everything is kept in (created 0700).
	Root string

	// AdminToken, when set, lets a device that presents it create vaults.
	AdminToken string

	// OpenRegistration lets any device create a vault, without a token.
	OpenRegistration bool

	// MaxFileSize caps a revision. Zero means DefaultMaxRevision.
	MaxFileSize int64

	// EnrolTTL is how long an enrolment code lasts. Zero means 10 minutes.
	EnrolTTL time.Duration

	// ClockSkew is how far a request's time may be from the server's.
	// Zero means 5 minutes.
	ClockSkew time.Duration

	// Rate is how many requests a second each device, and each IP
	// address, may make, in bursts of ten seconds' worth. Zero means 100;
	// below zero turns rate limiting off.
	Rate float64

	// Now is the clock (tests replace it). Defaults to time.Now.
	Now func() time.Time

	// Log receives what the operator should know about. Defaults to
	// discarding it.
	Log func(string)
}

// Server is the sync server, as an http.Handler. Close it to end the long
// polls in flight before shutting down the HTTP server.
type Server struct {
	cfg     Config
	mux     *http.ServeMux
	replay  *replayCache
	limits  *limiter
	done    chan struct{}
	closing sync.Once

	mu     sync.Mutex // guards vaults, and serialises making vaults
	vaults map[string]*vault
}

// maxJSONBody caps the JSON bodies of the device and vault calls.
const maxJSONBody = 16 << 10

// New returns a server keeping its vaults under cfg.Root.
func New(cfg Config) (*Server, error) {
	if cfg.Root == "" {
		return nil, errors.New("svserver: no root directory")
	}
	if cfg.MaxFileSize <= 0 {
		cfg.MaxFileSize = DefaultMaxRevision
	}
	if cfg.EnrolTTL <= 0 {
		cfg.EnrolTTL = 10 * time.Minute
	}
	if cfg.ClockSkew <= 0 {
		cfg.ClockSkew = 5 * time.Minute
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	if cfg.Log == nil {
		cfg.Log = func(string) {}
	}
	if err := os.MkdirAll(filepath.Join(cfg.Root, "vaults"), 0o700); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:    cfg,
		mux:    http.NewServeMux(),
		replay: newReplayCache(1<<20, cfg.ClockSkew),
		limits: newLimiter(cfg.Rate),
		done:   make(chan struct{}),
		vaults: map[string]*vault{},
	}
	fileBody := cfg.MaxFileSize
	s.route("POST /v1/vaults/{vault}", anyKey, maxJSONBody, s.createVault)
	s.route("PUT /v1/vaults/{vault}/files/{name...}", member, fileBody, s.putFile)
	s.route("GET /v1/vaults/{vault}/files/{name...}", member, 0, s.getFile)
	s.route("DELETE /v1/vaults/{vault}/files/{name...}", member, 0, s.deleteFile)
	s.route("GET /v1/vaults/{vault}/changes", member, 0, s.changes)
	s.route("POST /v1/vaults/{vault}/enrol", member, maxJSONBody, s.enrol)
	s.route("POST /v1/vaults/{vault}/devices", anyKey, maxJSONBody, s.join)
	s.route("GET /v1/vaults/{vault}/devices", member, 0, s.listDevices)
	s.route("DELETE /v1/vaults/{vault}/devices/{key}", member, 0, s.removeDevice)
	return s, nil
}

// ServeHTTP answers the sync API.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h := w.Header()
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	s.mux.ServeHTTP(w, r)
}

// Close ends every long poll and closes the vaults' logs. The server
// answers nothing more after it.
func (s *Server) Close() error {
	s.closing.Do(func() {
		close(s.done)
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, v := range s.vaults {
			v.close()
		}
		s.vaults = map[string]*vault{}
	})
	return nil
}

func (s *Server) closed() bool {
	select {
	case <-s.done:
		return true
	default:
		return false
	}
}

func (s *Server) vaultDir(name string) string { return filepath.Join(s.cfg.Root, "vaults", name) }

var errNoVault = errors.New("no such vault")

// lookup returns a vault that exists, loading it on first use.
func (s *Server) lookup(name string) (*vault, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookupLocked(name)
}

func (s *Server) lookupLocked(name string) (*vault, error) {
	if s.closed() {
		return nil, errors.New("the server is shutting down")
	}
	if v, ok := s.vaults[name]; ok {
		return v, nil
	}
	if _, err := os.Stat(filepath.Join(s.vaultDir(name), devicesFile)); errors.Is(err, fs.ErrNotExist) {
		return nil, errNoVault
	} else if err != nil {
		return nil, err
	}
	v, err := loadVault(name, s.vaultDir(name), s.cfg.Log)
	if err != nil {
		return nil, err
	}
	s.vaults[name] = v
	return v, nil
}

// Requests.

type access int

const (
	member access = iota // a device enrolled in the vault
	anyKey               // any key that signs: making a vault, or joining one
)

// request is an authenticated request.
type request struct {
	name   string // the vault's name
	vault  *vault // for member routes
	device string // the signing key, encoded
	body   []byte
	now    time.Time
}

type handler func(w http.ResponseWriter, r *http.Request, req *request)

// route registers h behind authentication: the request must be signed
// (package documentation), and for member routes by a device of the vault.
func (s *Server) route(pattern string, acc access, maxBody int64, h handler) {
	s.mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
		now := s.cfg.Now()
		if s.closed() {
			fail(w, http.StatusServiceUnavailable, "the server is shutting down")
			return
		}
		if ok, wait := s.limits.allow("ip "+clientIP(r), now); !ok {
			tooMany(w, wait)
			return
		}
		name := r.PathValue("vault")
		if err := CheckVaultName(name); err != nil {
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		cred, err := parseAuthorization(r.Header.Get("Authorization"))
		if err != nil {
			w.Header().Set("WWW-Authenticate", AuthScheme)
			fail(w, http.StatusUnauthorized, err.Error())
			return
		}
		skew := time.Duration(max(now.Unix()-cred.time, cred.time-now.Unix())) * time.Second
		if skew > s.cfg.ClockSkew {
			fail(w, http.StatusUnauthorized, fmt.Sprintf("the request's time is %v from the server's (%s); check the device's clock",
				skew, now.UTC().Format(time.RFC3339)))
			return
		}
		req := &request{name: name, device: cred.device, now: now}
		// Membership is checked before the body is read, so strangers
		// cannot make the server read large bodies.
		if acc == member {
			v, err := s.lookup(name)
			if err != nil && !errors.Is(err, errNoVault) {
				s.internal(w, err)
				return
			}
			if v == nil || !v.hasDevice(cred.device) {
				fail(w, http.StatusForbidden, "this device is not enrolled in that vault (or there is no such vault)")
				return
			}
			req.vault = v
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBody))
		if err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("the body is larger than %d bytes", maxBody))
				return
			}
			fail(w, http.StatusBadRequest, "the body could not be read")
			return
		}
		if !ed25519.Verify(cred.key, SigningString(r.Method, target(r), cred.time, cred.nonce, body), cred.sig) {
			fail(w, http.StatusUnauthorized, "the request's signature does not verify")
			return
		}
		fresh, full := s.replay.add(cred.device+" "+cred.nonce, cred.time+int64(s.cfg.ClockSkew/time.Second)+1, now.Unix())
		if full {
			fail(w, http.StatusServiceUnavailable, "the server is too busy; try again shortly")
			return
		}
		if !fresh {
			fail(w, http.StatusUnauthorized, "that request was already made once")
			return
		}
		if ok, wait := s.limits.allow("device "+cred.device, now); !ok {
			tooMany(w, wait)
			return
		}
		if req.vault != nil {
			req.vault.sawDevice(cred.device, now)
		}
		req.body = body
		h(w, r, req)
	})
}

// target is what a request's signature covers of its URL: the path from
// /v1/ on, and the raw query.
func target(r *http.Request) string {
	t := r.URL.EscapedPath()
	if r.URL.RawQuery != "" {
		t += "?" + r.URL.RawQuery
	}
	return t
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func reply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, msg string) {
	reply(w, status, ErrorBody{Error: msg})
}

func tooMany(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(wait/time.Second)+1))
	fail(w, http.StatusTooManyRequests, "too many requests; slow down")
}

func (s *Server) internal(w http.ResponseWriter, err error) {
	s.cfg.Log(err.Error())
	fail(w, http.StatusInternalServerError, "the server could not do that: "+err.Error())
}

func checkLabel(label string) error {
	if len(label) > 128 || !utf8.ValidString(label) {
		return errors.New("a device label is at most 128 bytes of UTF-8")
	}
	for _, r := range label {
		if unicode.IsControl(r) {
			return errors.New("a device label cannot hold control characters")
		}
	}
	return nil
}

// Vaults and devices.

func (s *Server) createVault(w http.ResponseWriter, r *http.Request, req *request) {
	var in CreateVaultRequest
	if err := json.Unmarshal(req.body, &in); err != nil {
		fail(w, http.StatusBadRequest, "the body is not a vault request")
		return
	}
	if err := checkLabel(in.Label); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if !s.cfg.OpenRegistration {
		if s.cfg.AdminToken == "" || subtle.ConstantTimeCompare([]byte(in.AdminToken), []byte(s.cfg.AdminToken)) != 1 {
			fail(w, http.StatusForbidden, "making a vault on this server needs its admin token")
			return
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	v, err := s.lookupLocked(req.name)
	switch {
	case err == nil && v.hasDevice(req.device):
		reply(w, http.StatusOK, struct{}{}) // made by this device already: a retry
		return
	case err == nil:
		fail(w, http.StatusConflict, "a vault of that name already exists")
		return
	case !errors.Is(err, errNoVault):
		s.internal(w, err)
		return
	}
	// A directory without devices.json is a vault whose making was cut
	// short; its log and any files are taken over.
	v, err = loadVault(req.name, s.vaultDir(req.name), s.cfg.Log)
	if err != nil {
		s.internal(w, err)
		return
	}
	if _, err := v.addDevice(Device{Key: req.device, Label: in.Label, Added: req.now.UTC()}); err != nil {
		v.close()
		s.internal(w, err)
		return
	}
	s.vaults[req.name] = v
	s.cfg.Log(fmt.Sprintf("vault %s made by device %s from %s", req.name, req.device, clientIP(r)))
	reply(w, http.StatusCreated, struct{}{})
}

func (s *Server) enrol(w http.ResponseWriter, r *http.Request, req *request) {
	e, err := req.vault.newCode(req.device, req.now, s.cfg.EnrolTTL)
	if errors.Is(err, errTooMany) {
		fail(w, http.StatusTooManyRequests, err.Error())
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	reply(w, http.StatusOK, e)
}

func (s *Server) join(w http.ResponseWriter, r *http.Request, req *request) {
	var in JoinRequest
	if err := json.Unmarshal(req.body, &in); err != nil {
		fail(w, http.StatusBadRequest, "the body is not a join request")
		return
	}
	if err := checkLabel(in.Label); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	v, err := s.lookup(req.name)
	if errors.Is(err, errNoVault) {
		fail(w, http.StatusForbidden, "that enrolment code is not valid (or there is no such vault)")
		return
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if v.hasDevice(req.device) {
		reply(w, http.StatusOK, struct{}{}) // joined already: a retry
		return
	}
	by, ok := v.useCode(in.Code, req.now)
	if !ok {
		fail(w, http.StatusForbidden, "that enrolment code is not valid: it is wrong, used or expired")
		return
	}
	if _, err := v.addDevice(Device{Key: req.device, Label: in.Label, Added: req.now.UTC(), AddedBy: by}); err != nil {
		s.internal(w, err)
		return
	}
	s.cfg.Log(fmt.Sprintf("vault %s: device %s joined from %s", req.name, req.device, clientIP(r)))
	reply(w, http.StatusCreated, struct{}{})
}

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request, req *request) {
	reply(w, http.StatusOK, req.vault.listDevices())
}

func (s *Server) removeDevice(w http.ResponseWriter, r *http.Request, req *request) {
	key := r.PathValue("key")
	switch err := req.vault.removeDevice(key); {
	case errors.Is(err, errNoDevice):
		fail(w, http.StatusNotFound, err.Error())
	case errors.Is(err, errLastDevice):
		fail(w, http.StatusConflict, err.Error())
	case err != nil:
		s.internal(w, err)
	default:
		s.cfg.Log(fmt.Sprintf("vault %s: device %s removed by %s", req.name, key, req.device))
		w.WriteHeader(http.StatusNoContent)
	}
}

// Files.

func (s *Server) putFile(w http.ResponseWriter, r *http.Request, req *request) {
	name := r.PathValue("name")
	kind, err := ClassifyName(name)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if limit := maxSize(kind, s.cfg.MaxFileSize); int64(len(req.body)) > limit {
		fail(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("a %s is at most %d bytes", kind, limit))
		return
	}
	switch kind {
	case Revision:
		// A revision is named by its hash: refuse one that is not, so no
		// one can plant bytes under a name that honest devices will
		// never be able to write.
		if sum(req.body) != revisionHash(name) {
			fail(w, http.StatusBadRequest, "the revision's contents do not match its name")
			return
		}
	case Descriptor, Slot, Epoch:
		if !json.Valid(req.body) {
			fail(w, http.StatusBadRequest, "a "+kind.String()+" is JSON")
			return
		}
	}
	seq, created, err := req.vault.put(name, req.body)
	switch {
	case errors.Is(err, errConflict):
		fail(w, http.StatusConflict, err.Error())
	case errors.Is(err, errGone):
		fail(w, http.StatusGone, err.Error())
	case err != nil:
		s.internal(w, err)
	case created:
		reply(w, http.StatusCreated, PutResult{Seq: seq, Created: true})
	default:
		reply(w, http.StatusOK, PutResult{Seq: seq})
	}
}

func (s *Server) getFile(w http.ResponseWriter, r *http.Request, req *request) {
	name := r.PathValue("name")
	if _, err := ClassifyName(name); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	data, err := req.vault.files.Read(name)
	if err != nil {
		if errors.Is(err, svstore.ErrNotExist) {
			fail(w, http.StatusNotFound, "no such file")
			return
		}
		s.internal(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)
	w.Write(data)
}

func (s *Server) deleteFile(w http.ResponseWriter, r *http.Request, req *request) {
	name := r.PathValue("name")
	kind, err := ClassifyName(name)
	if err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	if kind != Slot {
		fail(w, http.StatusMethodNotAllowed, "only keyslots are ever removed; every other file is kept")
		return
	}
	seq, err := req.vault.remove(name)
	switch {
	case errors.Is(err, errNoFile):
		fail(w, http.StatusNotFound, err.Error())
	case err != nil:
		s.internal(w, err)
	default:
		reply(w, http.StatusOK, PutResult{Seq: seq})
	}
}

// MaxWait is the longest a request for changes waits for one.
const MaxWait = 60 * time.Second

func (s *Server) changes(w http.ResponseWriter, r *http.Request, req *request) {
	q := r.URL.Query()
	after, err := strconv.ParseUint(q.Get("after"), 10, 64)
	if q.Get("after") == "" {
		after, err = 0, nil
	}
	if err != nil {
		fail(w, http.StatusBadRequest, "after is not a sequence number")
		return
	}
	var wait time.Duration
	if ws := q.Get("wait"); ws != "" {
		n, err := strconv.Atoi(ws)
		if err != nil || n < 0 {
			fail(w, http.StatusBadRequest, "wait is not a number of seconds")
			return
		}
		wait = min(time.Duration(n)*time.Second, MaxWait)
	}
	limit := 1000
	if ls := q.Get("limit"); ls != "" {
		n, err := strconv.Atoi(ls)
		if err != nil || n < 1 {
			fail(w, http.StatusBadRequest, "limit is not a positive number")
			return
		}
		limit = min(n, 10000)
	}
	var timeout <-chan time.Time
	if wait > 0 {
		t := time.NewTimer(wait)
		defer t.Stop()
		timeout = t.C
	}
	for {
		cs, next := req.vault.changes(after, limit)
		if len(cs.Changes) > 0 || wait == 0 {
			reply(w, http.StatusOK, cs)
			return
		}
		select {
		case <-next:
		case <-timeout:
			reply(w, http.StatusOK, cs)
			return
		case <-s.done:
			reply(w, http.StatusOK, cs)
			return
		case <-r.Context().Done():
			return
		}
	}
}
