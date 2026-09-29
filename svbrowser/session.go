// Package svbrowser speaks the KeePassXC-Browser protocol
// (https://github.com/keepassxreboot/keepassxc-browser/blob/develop/keepassxc-protocol.md),
// so KeePassXC's browser extension fills logins from secretvault.
//
// The browser starts a native-messaging host, secretvault-browser, which
// only moves messages (frame.go) between the extension and secretvaultd.
// There a Session holds the conversation:
//
//   - change-public-keys, in the clear, swaps X25519 keys: the extension's
//     for this browser session, and a new one of ours.
//   - Every other message is sealed with NaCl's crypto_box under those
//     keys, with a random 24-byte nonce the extension picks, and answered
//     under that nonce plus one. A nonce is used once: a replayed message,
//     or one of our own answers sent back (crypto_box's key is the same
//     both ways), is refused, and so is a message whose answer would reuse
//     a nonce.
//   - associate stores the extension's long-term identification key under
//     a name, once the person agrees; test-associate proves it again in
//     later sessions. Until one of them has succeeded in this session,
//     nothing that touches the vault's contents is answered.
//
// What the extension asks for is answered by a Backend: secretvaultd's
// vaults and consent broker (svd/browser.go).
package svbrowser

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"sync"

	"golang.org/x/crypto/nacl/box"
)

// HostName is the native-messaging host KeePassXC-Browser starts.
const HostName = "org.keepassxc.keepassxc_browser"

// Version is the KeePassXC version the host says it is. The extension
// turns features on by it: 2.7.6 has everything served here (logins,
// TOTP, groups, saving, the password generator) and not passkeys, which
// came with 2.7.7.
const Version = "2.7.6"

// The extension's IDs in the browsers' stores: the only ones a manifest
// lets start the host.
var (
	FirefoxExtensions = []string{"keepassxc-browser@keepassxc.org"}
	ChromeOrigins     = []string{
		"chrome-extension://oboonakemofpalcgghocfoadofidjkkk/", // the Chrome Web Store
		"chrome-extension://pdffhmdngciaglkoonimfcmckehcpafo/", // Edge Add-ons
	}
)

// Actions.
const (
	ActionChangePublicKeys   = "change-public-keys"
	ActionGetDatabaseHash    = "get-databasehash"
	ActionAssociate          = "associate"
	ActionTestAssociate      = "test-associate"
	ActionGetLogins          = "get-logins"
	ActionSetLogin           = "set-login"
	ActionLockDatabase       = "lock-database"
	ActionGetDatabaseGroups  = "get-database-groups"
	ActionCreateNewGroup     = "create-new-group"
	ActionGetTOTP            = "get-totp"
	ActionDeleteEntry        = "delete-entry"
	ActionGeneratePassword   = "generate-password"
	ActionGetDatabaseEntries = "get-database-entries"
	ActionRequestAutotype    = "request-autotype"
	ActionPasskeysGet        = "passkeys-get"
	ActionPasskeysRegister   = "passkeys-register"

	// Sent unasked, in the clear, when the vault locks or unlocks.
	ActionDatabaseLocked   = "database-locked"
	ActionDatabaseUnlocked = "database-unlocked"
)

// Error codes, as KeePassXC numbers them.
const (
	CodeUnknown                    = 0
	CodeDatabaseNotOpened          = 1
	CodeDatabaseHashNotReceived    = 2
	CodeClientPublicKeyNotReceived = 3
	CodeCannotDecryptMessage       = 4
	CodeActionCancelledOrDenied    = 6
	CodeCannotEncryptMessage       = 7
	CodeAssociationFailed          = 8
	CodeEncryptionKeyUnrecognized  = 10
	CodeIncorrectAction            = 12
	CodeEmptyMessageReceived       = 13
	CodeNoURLProvided              = 14
	CodeNoLoginsFound              = 15
	CodeNoGroupsFound              = 16
	CodeCannotCreateNewGroup       = 17
	CodeNoValidUUIDProvided        = 18
	CodeAccessToAllEntriesDenied   = 19
)

// messages are KeePassXC's words for its codes; the extension shows its
// own translations of most.
var messages = map[int]string{
	CodeUnknown:                    "Unknown error",
	CodeDatabaseNotOpened:          "Database not opened",
	CodeDatabaseHashNotReceived:    "Database hash not available",
	CodeClientPublicKeyNotReceived: "Client public key not received",
	CodeCannotDecryptMessage:       "Cannot decrypt message",
	CodeActionCancelledOrDenied:    "Action cancelled or denied",
	CodeCannotEncryptMessage:       "Message encryption failed.",
	CodeAssociationFailed:          "KeePassXC association failed, try again",
	CodeEncryptionKeyUnrecognized:  "Encryption key is not recognized",
	CodeIncorrectAction:            "Incorrect action",
	CodeEmptyMessageReceived:       "Empty message received",
	CodeNoURLProvided:              "No URL provided",
	CodeNoLoginsFound:              "No logins found",
	CodeNoGroupsFound:              "No groups found",
	CodeCannotCreateNewGroup:       "Cannot create new group",
	CodeNoValidUUIDProvided:        "No valid UUID provided",
	CodeAccessToAllEntriesDenied:   "Access to all entries is denied",
}

// Error is a refusal in the protocol's terms, for a Backend to return.
// Any other error goes to the extension as CodeUnknown.
type Error struct {
	Code int
	Why  string // for the log, when there is more to say than the code
}

func (e *Error) Error() string {
	if e.Why != "" {
		return e.Why
	}
	return messages[e.Code]
}

// Errorf makes an *Error.
func Errorf(code int, format string, args ...any) *Error {
	return &Error{Code: code, Why: fmt.Sprintf(format, args...)}
}

// Backend answers the extension: which vault, what is in it, and whether
// the person allows it. Every method but Open is called with the vault
// open, and those after associate and test-associate only for an
// associated extension.
type Backend interface {
	// Open makes sure the vault is unlocked. With unlock set, the
	// extension asked for it to be (triggerUnlock), and the person may be
	// asked for its passphrase; else a locked vault is CodeDatabaseNotOpened.
	Open(ctx context.Context, unlock bool) error

	// Hash tells the vault apart from others, to the extension (it keys
	// its associations by it). It must be stable and reveal nothing.
	Hash(ctx context.Context) (string, error)

	// Associate asks the person whether the extension may connect, and
	// stores its identification key (base64) under a new name, returned.
	Associate(ctx context.Context, idKey string) (string, error)

	// Associated reports whether name holds idKey, for this browser.
	Associated(ctx context.Context, name, idKey string) (bool, error)

	// Logins returns the logins for a page that the person allows.
	Logins(ctx context.Context, q LoginQuery) ([]Login, error)

	// SaveLogin stores a login: a new item, or a change to one.
	SaveLogin(ctx context.Context, s SaveLogin) error

	// Groups returns the vault's folders, as a tree under its root.
	Groups(ctx context.Context) (Group, error)

	// CreateGroup makes a folder (a path, "Work/Sites") to save into.
	CreateGroup(ctx context.Context, folder string) (Group, error)

	// TOTP returns an item's current one-time code ("" when it has no key).
	TOTP(ctx context.Context, uuid string) (string, error)

	// Delete deletes an item, if the person allows.
	Delete(ctx context.Context, uuid string) (bool, error)

	// Lock locks the vault.
	Lock(ctx context.Context) error

	// GeneratePassword returns a new random password; the caller wipes it.
	GeneratePassword(ctx context.Context) ([]byte, error)
}

// LoginQuery is a get-logins: the page, and where its form posts.
type LoginQuery struct {
	URL       string
	SubmitURL string
	HTTPAuth  bool
}

// Login is one login given to the extension. Password is wiped once sent.
type Login struct {
	Login    string // the username
	Name     string // a title for people
	Password []byte
	UUID     string // the item's ID
	Group    string // the folder it is in
	TOTP     string // its current one-time code, if it has a key
}

// SaveLogin is a set-login. With UUID, it changes that item; else it
// makes a new one, in the folder GroupUUID names (the default when "").
type SaveLogin struct {
	URL       string
	SubmitURL string
	Login     string
	Password  []byte
	UUID      string
	Group     string
	GroupUUID string
}

// maxNonces is how many nonces a session remembers: replays are refused
// for its last 32,768 messages and their answers.
const maxNonces = 1 << 16

// Session is one extension's conversation, from its change-public-keys
// on. It is safe for concurrent use: the relay hands messages over as they
// come, and one waiting on a person does not hold up the others.
type Session struct {
	b Backend

	mu    sync.Mutex
	k     *sessionKeys // nil before change-public-keys
	assoc *association
}

type sessionKeys struct {
	clientID  string
	clientKey string   // the extension's public key, as it sent it
	shared    [32]byte // crypto_box's key, both ways
	used      map[[24]byte]bool
	order     [][24]byte
}

type association struct{ name, key string }

// NewSession starts a conversation answered by b.
func NewSession(b Backend) *Session { return &Session{b: b} }

// Close forgets the session's keys.
func (s *Session) Close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.k != nil {
		clear(s.k.shared[:])
		s.k = nil
	}
	s.assoc = nil
}

// Notice is a message the host sends unasked: ActionDatabaseLocked or
// ActionDatabaseUnlocked.
func Notice(action string) []byte {
	b, _ := json.Marshal(map[string]string{"action": action})
	return b
}

// Handle answers one message from the extension; nil when nothing is to
// be sent back.
func (s *Session) Handle(ctx context.Context, frame []byte) []byte {
	var outer fields
	if err := json.Unmarshal(frame, &outer); err != nil || len(outer) == 0 {
		return errorReply("", CodeEmptyMessageReceived, "")
	}
	action := outer.str("action")
	clientID := outer.str("clientID")
	if clientID == "" {
		// KeePassXC does not answer a message from no client either.
		return nil
	}
	if action == "" {
		return errorReply(action, CodeIncorrectAction, "")
	}
	if action == ActionChangePublicKeys {
		return s.changeKeys(clientID, outer.str("publicKey"), outer.str("nonce"))
	}
	k, nonce, in, code := s.open(clientID, outer.str("nonce"), outer.str("message"))
	if code != 0 {
		return errorReply(action, code, "")
	}
	defer in.wipe()
	if in.str("action") != action {
		return errorReply(action, CodeIncorrectAction, "")
	}
	requestID := ""
	if action == ActionGeneratePassword {
		requestID = outer.str("requestID")
	}
	o := newObject()
	defer func() { clear(o.b[:cap(o.b)]) }()
	o.value("version", Version)
	o.value("success", "true")
	o.value("nonce", encodeNonce(nonce))
	if err := s.serve(ctx, action, in, outer.str("triggerUnlock") == "true", o); err != nil {
		code := CodeUnknown
		var e *Error
		if errors.As(err, &e) {
			code = e.Code
		}
		return errorReply(action, code, requestID)
	}
	body := o.done()
	return s.seal(k, action, nonce, body)
}

// changeKeys answers change-public-keys: a new key pair of ours, and the
// extension's key for this session.
func (s *Session) changeKeys(clientID, publicKey, nonceText string) []byte {
	const action = ActionChangePublicKeys
	n, ok := decodeNonce(nonceText)
	theirs, ok2 := decodeKey(publicKey)
	if !ok || !ok2 {
		return errorReply(action, CodeClientPublicKeyNotReceived, "")
	}
	ours, secret, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return errorReply(action, CodeEncryptionKeyUnrecognized, "")
	}
	k := &sessionKeys{clientID: clientID, clientKey: publicKey, used: map[[24]byte]bool{}}
	box.Precompute(&k.shared, theirs, secret)
	clear(secret[:])
	reply := increment(n)
	k.use(n)
	k.use(reply)
	s.mu.Lock()
	if s.k != nil {
		clear(s.k.shared[:])
	}
	s.k, s.assoc = k, nil
	s.mu.Unlock()
	b, _ := json.Marshal(map[string]string{
		"action":    action,
		"version":   Version,
		"publicKey": base64.StdEncoding.EncodeToString(ours[:]),
		"success":   "true",
		"nonce":     encodeNonce(reply),
	})
	return b
}

// open checks and decrypts a sealed message, and marks its nonce and its
// answer's as used. It returns a protocol error code, or 0.
func (s *Session) open(clientID, nonceText, message string) (*sessionKeys, [24]byte, fields, int) {
	var none [24]byte
	s.mu.Lock()
	defer s.mu.Unlock()
	k := s.k
	if k == nil || k.clientID != clientID {
		return nil, none, nil, CodeClientPublicKeyNotReceived
	}
	n, ok := decodeNonce(nonceText)
	if !ok {
		return nil, none, nil, CodeCannotDecryptMessage
	}
	sealed, err := base64.StdEncoding.DecodeString(message)
	if err != nil || len(sealed) < box.Overhead || len(sealed) > MaxFrame {
		return nil, none, nil, CodeCannotDecryptMessage
	}
	plain, ok := box.OpenAfterPrecomputation(nil, sealed, &n, &k.shared)
	if !ok {
		return nil, none, nil, CodeCannotDecryptMessage
	}
	defer clear(plain)
	reply := increment(n)
	if k.used[n] || k.used[reply] {
		return nil, none, nil, CodeCannotDecryptMessage
	}
	k.use(n)
	k.use(reply)
	var in fields
	if err := json.Unmarshal(plain, &in); err != nil || in == nil {
		return nil, none, nil, CodeCannotDecryptMessage
	}
	return k, reply, in, 0
}

// use marks a nonce used, forgetting the oldest beyond maxNonces.
func (k *sessionKeys) use(n [24]byte) {
	if len(k.order) >= maxNonces {
		delete(k.used, k.order[0])
		k.order = k.order[1:]
	}
	k.used[n] = true
	k.order = append(k.order, n)
}

// seal answers under the keys the message came with, if they are still
// the session's.
func (s *Session) seal(k *sessionKeys, action string, nonce [24]byte, body []byte) []byte {
	s.mu.Lock()
	if s.k != k {
		s.mu.Unlock()
		return errorReply(action, CodeCannotEncryptMessage, "")
	}
	sealed := box.SealAfterPrecomputation(nil, body, &nonce, &k.shared)
	s.mu.Unlock()
	b, _ := json.Marshal(map[string]string{
		"action":  action,
		"message": base64.StdEncoding.EncodeToString(sealed),
		"nonce":   encodeNonce(nonce),
	})
	if len(b) > MaxFrame {
		return errorReply(action, CodeCannotEncryptMessage, "")
	}
	return b
}

// errorReply is an answer in the clear: KeePassXC sends refusals so, with
// the code as a string.
func errorReply(action string, code int, requestID string) []byte {
	m := map[string]string{"action": action, "errorCode": strconv.Itoa(code), "error": messages[code]}
	if requestID != "" {
		m["requestID"] = requestID
	}
	b, _ := json.Marshal(m)
	return b
}

// served are the actions answered, after the vault is open.
var served = map[string]bool{
	ActionGetDatabaseHash: true, ActionAssociate: true, ActionTestAssociate: true,
	ActionGetLogins: true, ActionSetLogin: true, ActionLockDatabase: true,
	ActionGetDatabaseGroups: true, ActionCreateNewGroup: true, ActionGetTOTP: true,
	ActionDeleteEntry: true, ActionGeneratePassword: true,
}

// serve answers a decrypted request, adding its values to o.
func (s *Session) serve(ctx context.Context, action string, in fields, unlock bool, o *object) error {
	switch {
	case action == ActionGetDatabaseEntries:
		// Every entry's title and URL at once: KeePassXC refuses it
		// unless a setting allows it; secretvault always does.
		return &Error{Code: CodeAccessToAllEntriesDenied}
	case !served[action]:
		// request-autotype, passkeys-get and passkeys-register among
		// them: KeePassXC before 2.7.7 answers them the same way.
		return &Error{Code: CodeIncorrectAction}
	}
	if err := s.b.Open(ctx, unlock); err != nil {
		return err
	}
	hash := func() error {
		h, err := s.b.Hash(ctx)
		if err == nil {
			o.value("hash", h)
		}
		return err
	}

	switch action {
	case ActionGetDatabaseHash:
		return hash()

	case ActionAssociate:
		key := in.str("key")
		s.mu.Lock()
		ours := s.k != nil && key != "" && key == s.k.clientKey
		s.mu.Unlock()
		if !ours {
			return &Error{Code: CodeAssociationFailed}
		}
		idKey := in.str("idKey")
		if idKey == "" {
			idKey = key // older extensions identify with the session key
		}
		if _, ok := decodeKey(idKey); !ok {
			return &Error{Code: CodeAssociationFailed}
		}
		name, err := s.b.Associate(ctx, idKey)
		if err != nil {
			return err
		}
		s.setAssociation(name, idKey)
		o.value("id", name)
		return hash()

	case ActionTestAssociate:
		name, key := in.str("id"), in.str("key")
		if name == "" || key == "" {
			return &Error{Code: CodeDatabaseNotOpened} // as KeePassXC answers
		}
		ok, err := s.b.Associated(ctx, name, key)
		if err != nil {
			return err
		}
		if !ok {
			return &Error{Code: CodeAssociationFailed}
		}
		s.setAssociation(name, key)
		o.value("id", name)
		return hash()
	}

	a, err := s.association(ctx)
	if err != nil {
		return err
	}
	switch action {
	case ActionGetLogins:
		url := in.str("url")
		if url == "" {
			return &Error{Code: CodeNoURLProvided}
		}
		if raw, ok := in["keys"]; ok && !listsAssociation(raw, a) {
			return &Error{Code: CodeAssociationFailed}
		}
		logins, err := s.b.Logins(ctx, LoginQuery{URL: url, SubmitURL: in.str("submitUrl"), HTTPAuth: in.str("httpAuth") == "true"})
		defer func() {
			for i := range logins {
				clear(logins[i].Password)
			}
		}()
		if err != nil {
			return err
		}
		o.value("count", len(logins))
		o.key("entries")
		o.grow(1)
		o.b = append(o.b, '[')
		for i, l := range logins {
			if i > 0 {
				o.grow(1)
				o.b = append(o.b, ',')
			}
			e := newObject()
			e.value("login", l.Login)
			e.value("name", l.Name)
			e.secret("password", l.Password)
			e.value("uuid", l.UUID)
			e.value("group", l.Group)
			if l.TOTP != "" {
				e.value("totp", l.TOTP)
			}
			j := e.done()
			o.grow(len(j))
			o.b = append(o.b, j...)
			clear(e.b[:cap(e.b)])
		}
		o.grow(1)
		o.b = append(o.b, ']')
		o.value("id", in.str("id"))
		return hash()

	case ActionSetLogin:
		url := in.str("url")
		if url == "" {
			return &Error{Code: CodeNoURLProvided}
		}
		password, err := decodeSecret(in["password"])
		if err != nil {
			password = nil
		}
		defer clear(password)
		uuid := in.str("uuid")
		if uuid != "" && !validUUID(uuid) {
			return &Error{Code: CodeNoValidUUIDProvided}
		}
		err = s.b.SaveLogin(ctx, SaveLogin{URL: url, SubmitURL: in.str("submitUrl"), Login: in.str("login"), Password: password,
			UUID: uuid, Group: in.str("group"), GroupUUID: in.str("groupUuid")})
		if err != nil {
			return err
		}
		o.raw("count", []byte("null"))
		o.raw("entries", []byte("null"))
		o.value("error", "success")
		return hash()

	case ActionLockDatabase:
		return s.b.Lock(ctx)

	case ActionGetDatabaseGroups:
		root, err := s.b.Groups(ctx)
		if err != nil {
			return err
		}
		// Nested as KeePassXC nests it: the extension reads groups.groups.
		o.value("groups", map[string][]Group{"groups": {root}})
		return nil

	case ActionCreateNewGroup:
		g, err := s.b.CreateGroup(ctx, in.str("groupName"))
		if err != nil {
			return err
		}
		o.value("name", g.Name)
		o.value("uuid", g.UUID)
		return nil

	case ActionGetTOTP:
		uuid := in.str("uuid")
		if !validUUID(uuid) {
			return &Error{Code: CodeNoValidUUIDProvided}
		}
		code, err := s.b.TOTP(ctx, uuid)
		if err != nil {
			return err
		}
		o.value("totp", code)
		return nil

	case ActionDeleteEntry:
		uuid := in.str("uuid")
		if !validUUID(uuid) {
			return &Error{Code: CodeNoValidUUIDProvided}
		}
		ok, err := s.b.Delete(ctx, uuid)
		if err != nil {
			return err
		}
		o.value("success", strconv.FormatBool(ok))
		return nil

	case ActionGeneratePassword:
		p, err := s.b.GeneratePassword(ctx)
		if err != nil {
			return err
		}
		o.secret("password", p)
		clear(p)
		return nil
	}
	return &Error{Code: CodeIncorrectAction}
}

func (s *Session) setAssociation(name, key string) {
	s.mu.Lock()
	s.assoc = &association{name: name, key: key}
	s.mu.Unlock()
}

// association is what this session proved, checked again: an association
// removed meanwhile ends it.
func (s *Session) association(ctx context.Context) (*association, error) {
	s.mu.Lock()
	a := s.assoc
	s.mu.Unlock()
	if a == nil {
		return nil, &Error{Code: CodeAssociationFailed}
	}
	ok, err := s.b.Associated(ctx, a.name, a.key)
	if err != nil {
		return nil, err
	}
	if !ok {
		s.mu.Lock()
		if s.assoc == a {
			s.assoc = nil
		}
		s.mu.Unlock()
		return nil, &Error{Code: CodeAssociationFailed}
	}
	return a, nil
}

// listsAssociation reports whether a get-logins' keys include the
// session's association, as KeePassXC requires of the database searched.
func listsAssociation(raw json.RawMessage, a *association) bool {
	var keys []struct {
		ID  string `json:"id"`
		Key string `json:"key"`
	}
	if json.Unmarshal(raw, &keys) != nil {
		return false
	}
	for _, k := range keys {
		if k.ID == a.name && k.Key == a.key {
			return true
		}
	}
	return false
}

// validUUID is KeePassXC's test for an entry ID: 32 hex digits.
func validUUID(s string) bool {
	if len(s) != 32 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func decodeNonce(s string) ([24]byte, bool) {
	var n [24]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != len(n) {
		return n, false
	}
	copy(n[:], b)
	return n, true
}

func encodeNonce(n [24]byte) string { return base64.StdEncoding.EncodeToString(n[:]) }

func decodeKey(s string) (*[32]byte, bool) {
	var k [32]byte
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != len(k) {
		return nil, false
	}
	copy(k[:], b)
	return &k, true
}

// increment adds one to a nonce, read little-endian, as libsodium's
// sodium_increment and the extension do.
func increment(n [24]byte) [24]byte {
	c := uint16(1)
	for i := range n {
		c += uint16(n[i])
		n[i] = byte(c)
		c >>= 8
	}
	return n
}
