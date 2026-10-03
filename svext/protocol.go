package svext

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svbrowser"
)

// The protocol, version 1 (docs/browser.md has it whole). Each message is
// one native-messaging frame (svbrowser.ReadFrame, WriteFrame) holding a
// JSON object.
//
//	request   {"v":1,"id":"r7","op":"logins","vault":"","origin":"https://github.com"}
//	answer    {"v":1,"id":"r7","ok":true,"logins":[...]}
//	refusal   {"v":1,"id":"r7","ok":false,"error":"locked","message":"..."}
//	event     {"v":1,"event":"vault","vault":"personal","locked":true}
//
// Every request is checked here, whole, before anything acts on it: its
// size, that it is an object with exactly the members its operation
// takes, each of the type and length it must be. The host checks before
// it passes a request on, and the daemon again.

// Version is the protocol's version: the "v" of every message.
const Version = 1

// Operations.
const (
	OpHello    = "hello"    // extension -> protocol, browser
	OpState    = "state"    // -> vaults
	OpUnlock   = "unlock"   // vault -> vaults (the daemon asks for the passphrase itself)
	OpLock     = "lock"     // vault -> vaults
	OpLogins   = "logins"   // vault, origin -> logins (no secrets)
	OpFill     = "fill"     // vault, origin, login -> username, password, totp
	OpTOTP     = "totp"     // vault, origin, login -> code
	OpCheck    = "check"    // vault, origin, username, password -> status, login
	OpSave     = "save"     // vault, origin, username, password, [login], [title] -> login, created
	OpGenerate = "generate" // [length], [symbols] -> password (answered by the host)
)

// Limits. A request is at most MaxRequest bytes; the browser's own limit
// (1 MiB, svbrowser.MaxFrame) ends the host, as the stream cannot be read
// past a frame over it.
const (
	MaxRequest  = 64 << 10
	MaxID       = 64
	MaxOrigin   = 1024
	MaxVault    = 256
	MaxUsername = 1024
	MaxPassword = 4096
	MaxTitle    = 256
	MaxLogins   = 200

	MinGenerate     = 8
	MaxGenerate     = 128
	DefaultGenerate = 24
)

// members are the members each operation takes, beyond v, id and op;
// required ones are marked true.
var members = map[string]map[string]bool{
	OpHello:    {"extension": false},
	OpState:    {},
	OpUnlock:   {"vault": false},
	OpLock:     {"vault": false},
	OpLogins:   {"vault": false, "origin": true},
	OpFill:     {"vault": false, "origin": true, "login": true},
	OpTOTP:     {"vault": false, "origin": true, "login": true},
	OpCheck:    {"vault": false, "origin": true, "username": false, "password": true},
	OpSave:     {"vault": false, "origin": true, "username": false, "password": true, "login": false, "title": false},
	OpGenerate: {"length": false, "symbols": false},
}

// Error codes.
const (
	CodeBadRequest = "bad-request" // not a request: its shape, a member, a size
	CodeTooLarge   = "too-large"   // over MaxRequest
	CodeUnknownOp  = "unknown-op"
	CodeBusy       = "busy" // too many requests waiting
	CodeNotRunning = "not-running"
	CodeNoVault    = "no-vault"
	CodeLocked     = "locked"
	CodeNotFound   = "not-found" // no such login, or it does not fit the origin
	CodeDenied     = "denied"    // the person said no, or nobody could be asked
	CodeFailed     = "failed"
)

// Error is a refusal, in the protocol's terms.
type Error struct {
	Code    string
	Message string
}

func (e *Error) Error() string { return e.Message }

// Errorf makes an *Error.
func Errorf(code, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Request is a checked request. Password is the caller's to wipe.
type Request struct {
	ID        string
	Op        string
	Extension string
	Vault     string
	Origin    Origin
	Login     string // an item's ID: 32 hex digits
	Username  string
	Password  []byte
	Title     string
	Length    int
	Symbols   bool
}

// Wipe zeroes the request's password.
func (r *Request) Wipe() { clear(r.Password) }

// ParseRequest checks a frame and reads the request in it. On an error,
// the request's id is returned with it when one could be read, to answer.
func ParseRequest(frame []byte) (*Request, error) {
	if len(frame) > MaxRequest {
		return nil, Errorf(CodeTooLarge, "a request of %d bytes, over %d", len(frame), MaxRequest)
	}
	var m map[string]json.RawMessage
	d := json.NewDecoder(bytes.NewReader(frame))
	if err := d.Decode(&m); err != nil || m == nil {
		return nil, Errorf(CodeBadRequest, "a request is one JSON object")
	}
	if _, err := d.Token(); err != io.EOF {
		// Anything after the object, even a stray } or ].
		return nil, Errorf(CodeBadRequest, "a request is one JSON object, and nothing after it")
	}
	defer func() {
		for _, v := range m {
			clear(v)
		}
	}()
	r := &Request{}
	idErr := str(m, "id", &r.ID, MaxID)
	if idErr == nil && !validID(r.ID) {
		idErr = Errorf(CodeBadRequest, "id: 1 to %d letters, digits, '.', '_' or '-'", MaxID)
	}
	if idErr != nil {
		r.ID = ""
		return r, idErr
	}
	var v int
	if err := num(m, "v", &v); err != nil || v != Version {
		return r, Errorf(CodeBadRequest, "v: this host speaks version %d", Version)
	}
	if err := str(m, "op", &r.Op, 32); err != nil {
		return r, err
	}
	allowed, ok := members[r.Op]
	if !ok {
		return r, Errorf(CodeUnknownOp, "no operation %q", r.Op)
	}
	for k := range m {
		if _, ok := allowed[k]; !ok && k != "v" && k != "id" && k != "op" {
			return r, Errorf(CodeBadRequest, "%s takes no member %q", r.Op, k)
		}
	}
	for k, required := range allowed {
		if _, ok := m[k]; required && !ok {
			return r, Errorf(CodeBadRequest, "%s needs %q", r.Op, k)
		}
	}
	err := r.read(m)
	if err != nil {
		r.Wipe()
	}
	return r, err
}

// read reads the members ParseRequest allowed.
func (r *Request) read(m map[string]json.RawMessage) error {
	if _, ok := m["extension"]; ok {
		if err := text(m, "extension", &r.Extension, 64); err != nil {
			return err
		}
	}
	if _, ok := m["vault"]; ok {
		if err := text(m, "vault", &r.Vault, MaxVault); err != nil {
			return err
		}
	}
	if _, ok := m["origin"]; ok {
		var s string
		if err := str(m, "origin", &s, MaxOrigin); err != nil {
			return err
		}
		o, err := ParseOrigin(s)
		if err != nil {
			return Errorf(CodeBadRequest, "origin: %v", err)
		}
		r.Origin = o
	}
	if _, ok := m["login"]; ok {
		if err := str(m, "login", &r.Login, 32); err != nil {
			return err
		}
		if !validLogin(r.Login) {
			return Errorf(CodeBadRequest, "login: an item ID, 32 hex digits")
		}
	}
	if _, ok := m["username"]; ok {
		if err := text(m, "username", &r.Username, MaxUsername); err != nil {
			return err
		}
	}
	if _, ok := m["title"]; ok {
		if err := text(m, "title", &r.Title, MaxTitle); err != nil {
			return err
		}
	}
	if raw, ok := m["password"]; ok {
		p, err := svbrowser.DecodeJSONSecret(raw)
		switch {
		case err != nil:
			return Errorf(CodeBadRequest, "password: a string")
		case len(p) == 0 || len(p) > MaxPassword:
			clear(p)
			return Errorf(CodeBadRequest, "password: 1 to %d bytes", MaxPassword)
		case !utf8.Valid(p) || bytes.ContainsRune(p, utf8.RuneError):
			// U+FFFD is also what a lone surrogate (\ud800) decodes to:
			// refused, not stored mangled.
			clear(p)
			return Errorf(CodeBadRequest, "password: UTF-8 text")
		}
		r.Password = p
	}
	if r.Op == OpGenerate {
		r.Length, r.Symbols = DefaultGenerate, true
		if _, ok := m["length"]; ok {
			if err := num(m, "length", &r.Length); err != nil || r.Length < MinGenerate || r.Length > MaxGenerate {
				return Errorf(CodeBadRequest, "length: %d to %d", MinGenerate, MaxGenerate)
			}
		}
		if raw, ok := m["symbols"]; ok {
			if s := string(raw); s != "true" && s != "false" || json.Unmarshal(raw, &r.Symbols) != nil {
				return Errorf(CodeBadRequest, "symbols: true or false")
			}
		}
	}
	return nil
}

// str reads a string member of at most max bytes.
func str(m map[string]json.RawMessage, k string, out *string, max int) error {
	raw, ok := m[k]
	if !ok {
		return Errorf(CodeBadRequest, "no %q", k)
	}
	if len(raw) == 0 || raw[0] != '"' || json.Unmarshal(raw, out) != nil {
		return Errorf(CodeBadRequest, "%s: a string", k)
	}
	if len(*out) > max {
		return Errorf(CodeBadRequest, "%s: at most %d bytes", k, max)
	}
	return nil
}

// text is str for text people read: no control characters.
func text(m map[string]json.RawMessage, k string, out *string, max int) error {
	if err := str(m, k, out, max); err != nil {
		return err
	}
	if strings.ContainsFunc(*out, func(r rune) bool { return r < 0x20 || r == 0x7f || r == utf8.RuneError }) {
		return Errorf(CodeBadRequest, "%s: no control characters", k)
	}
	return nil
}

// num reads a whole number member.
func num(m map[string]json.RawMessage, k string, out *int) error {
	raw, ok := m[k]
	if !ok {
		return Errorf(CodeBadRequest, "no %q", k)
	}
	if len(raw) == 0 || !(raw[0] == '-' || raw[0] >= '0' && raw[0] <= '9') || bytes.ContainsAny(raw, ".eE") || json.Unmarshal(raw, out) != nil {
		return Errorf(CodeBadRequest, "%s: a whole number", k)
	}
	return nil
}

func validID(s string) bool {
	if s == "" || len(s) > MaxID {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func validLogin(s string) bool {
	if len(s) != 32 || strings.ToLower(s) != s {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

// reply builds an answer in a buffer the caller wipes; secrets never
// become Go strings on the way.
type reply struct{ b []byte }

func newReply(id string) *reply {
	r := &reply{b: make([]byte, 0, 512)}
	r.b = append(r.b, `{"v":1,"id":`...)
	r.value(id)
	r.b = append(r.b, `,"ok":true`...)
	return r
}

func (r *reply) key(k string) {
	r.b = append(r.b, ',')
	r.value(k)
	r.b = append(r.b, ':')
}

// value appends what encoding/json writes (nothing secret).
func (r *reply) value(v any) {
	j, err := json.Marshal(v)
	if err != nil {
		j = []byte("null")
	}
	r.grow(len(j))
	r.b = append(r.b, j...)
}

func (r *reply) set(k string, v any) {
	r.key(k)
	r.value(v)
}

func (r *reply) secret(k string, v []byte) {
	r.key(k)
	r.grow(len(v) + len(v)/4 + 8)
	r.b = svbrowser.AppendJSONSecret(r.b, v)
}

// grow makes room for n more bytes, wiping the buffer it leaves.
func (r *reply) grow(n int) {
	if cap(r.b)-len(r.b) >= n {
		return
	}
	nb := make([]byte, len(r.b), 2*cap(r.b)+n)
	copy(nb, r.b)
	clear(r.b[:cap(r.b)])
	r.b = nb
}

func (r *reply) done() []byte {
	r.grow(1)
	return append(r.b, '}')
}

// Refusal is the answer to request id ("" when it had none that could
// be read) for an error: an *Error's code, else CodeFailed.
func Refusal(id string, err error) []byte {
	var e *Error
	if !errors.As(err, &e) {
		e = &Error{Code: CodeFailed, Message: err.Error()}
	}
	b, _ := json.Marshal(struct {
		V       int    `json:"v"`
		ID      string `json:"id"`
		OK      bool   `json:"ok"`
		Error   string `json:"error"`
		Message string `json:"message,omitempty"`
	}{Version, id, false, e.Code, e.Message})
	return b
}

// VaultEvent tells the extension a vault locked or unlocked.
func VaultEvent(vault string, locked bool) []byte {
	b, _ := json.Marshal(struct {
		V      int    `json:"v"`
		Event  string `json:"event"`
		Vault  string `json:"vault"`
		Locked bool   `json:"locked"`
	}{Version, "vault", vault, locked})
	return b
}

// DownEvent tells the extension secretvault cannot be reached, just
// before the host stops.
func DownEvent(why string) []byte {
	b, _ := json.Marshal(struct {
		V       int    `json:"v"`
		Event   string `json:"event"`
		Error   string `json:"error"`
		Message string `json:"message"`
	}{Version, "down", CodeNotRunning, why})
	return b
}

// GenerateReply answers a generate request with gen (svops.GeneratePassword
// in the host: the managers' generator, with their defaults).
func GenerateReply(r *Request, gen func(n int, symbols bool) ([]byte, error)) []byte {
	p, err := gen(r.Length, r.Symbols)
	if err != nil {
		return Refusal(r.ID, err)
	}
	defer clear(p)
	out := newReply(r.ID)
	out.secret("password", p)
	return out.done()
}
