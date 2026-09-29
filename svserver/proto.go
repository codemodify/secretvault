package svserver

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// The wire protocol, shared with the client (svsync). Bodies of files are
// raw bytes; everything structured is JSON.

// Operations in the change log.
const (
	OpCreate = "create"
	OpRemove = "remove"

	// OpEvent is something about the vault that changed on the server and
	// is not a file: an emergency grant (Name EmergencyEvent + its ID).
	// It carries no data; a device asks for what changed. Devices that do
	// not know an event's name skip it, as they skip any name that is not
	// one of a vault's files.
	OpEvent = "event"
)

// EmergencyEvent prefixes the name of an event about an emergency grant:
// "emergency/<grant id>".
const EmergencyEvent = "emergency/"

// Change is one entry of a vault's change log: a file created or removed,
// or an event.
type Change struct {
	Seq  uint64 `json:"seq"`
	Op   string `json:"op"`
	Name string `json:"name"`

	// Size and SHA256 (hex) describe a created file, so a client can tell
	// whether it already holds the same bytes without fetching them.
	Size   int64  `json:"size,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// Changes answers GET .../changes.
type Changes struct {
	// Log identifies the vault's change log. It changes only if the log
	// was started again (the vault was made anew on the server, or its
	// log lost), which tells a client its cursor means nothing any more.
	Log string `json:"log"`

	// Latest is the sequence number of the newest change.
	Latest uint64 `json:"latest"`

	Changes []Change `json:"changes"`

	// More is set when Changes was cut at the limit asked for.
	More bool `json:"more,omitempty"`
}

// PutResult answers PUT and DELETE of a file: the sequence number of the
// change that created (or removed) it.
type PutResult struct {
	Seq     uint64 `json:"seq"`
	Created bool   `json:"created,omitempty"`
}

// CreateVaultRequest is the body of POST /v1/vaults/{vault}.
type CreateVaultRequest struct {
	AdminToken string `json:"admin_token,omitempty"`
	Label      string `json:"label,omitempty"` // for the creating device
}

// JoinRequest is the body of POST /v1/vaults/{vault}/devices.
type JoinRequest struct {
	Code  string `json:"code"`
	Label string `json:"label,omitempty"`
}

// Enrolment answers POST /v1/vaults/{vault}/enrol: a one-time code that
// lets one more device join.
type Enrolment struct {
	Code    string    `json:"code"`
	Expires time.Time `json:"expires"`
}

// Device is a device key enrolled in a vault.
type Device struct {
	Key      string     `json:"key"` // the Ed25519 public key, unpadded base64url
	Label    string     `json:"label,omitempty"`
	Added    time.Time  `json:"added"`
	AddedBy  string     `json:"added_by,omitempty"` // the device that enrolled it; "" for the first
	LastSeen *time.Time `json:"last_seen,omitempty"`
}

// ErrorBody is how every error is answered.
type ErrorBody struct {
	Error string `json:"error"`
}

// AuthScheme names the request-signing scheme in the Authorization header.
const AuthScheme = "SV1"

var b64 = base64.RawURLEncoding

// EncodeKey writes a device public key as the server names it.
func EncodeKey(pub ed25519.PublicKey) string { return b64.EncodeToString(pub) }

// DecodeKey reads a device public key as EncodeKey writes it.
func DecodeKey(s string) (ed25519.PublicKey, error) {
	b, err := b64.DecodeString(s)
	if err != nil || len(b) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("svserver: %q is not a device key", s)
	}
	return ed25519.PublicKey(b), nil
}

// SigningString is what a device signs for one request:
//
//	"SV1\n" + method + "\n" + target + "\n" + time + "\n" + nonce + "\n" + hex(SHA-256(body))
//
// target is the request's path from "/v1/" on, with "?" and the raw query
// if there is one; time is Unix seconds in decimal.
func SigningString(method, target string, unix int64, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(AuthScheme + "\n" + method + "\n" + target + "\n" + strconv.FormatInt(unix, 10) + "\n" + nonce + "\n" + hex.EncodeToString(sum[:]))
}

// Authorization signs a request with a device key and returns the value
// of its Authorization header. Each call uses a fresh nonce, so no two
// requests are alike.
func Authorization(key ed25519.PrivateKey, method, target string, body []byte, now time.Time) string {
	var n [16]byte
	rand.Read(n[:])
	nonce := b64.EncodeToString(n[:])
	unix := now.Unix()
	sig := ed25519.Sign(key, SigningString(method, target, unix, nonce, body))
	return fmt.Sprintf("%s device=%s, time=%d, nonce=%s, sig=%s",
		AuthScheme, EncodeKey(key.Public().(ed25519.PublicKey)), unix, nonce, b64.EncodeToString(sig))
}

// credentials are the parts of an Authorization header.
type credentials struct {
	key    ed25519.PublicKey
	device string // key, encoded
	time   int64
	nonce  string
	sig    []byte
}

var errAuthHeader = errors.New("the Authorization header is missing or is not SV1")

func parseAuthorization(h string) (credentials, error) {
	var c credentials
	scheme, rest, ok := strings.Cut(h, " ")
	if !ok || scheme != AuthScheme {
		return c, errAuthHeader
	}
	seen := map[string]bool{}
	for part := range strings.SplitSeq(rest, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || seen[k] {
			return c, errAuthHeader
		}
		seen[k] = true
		var err error
		switch k {
		case "device":
			c.device = v
			c.key, err = DecodeKey(v)
		case "time":
			c.time, err = strconv.ParseInt(v, 10, 64)
		case "nonce":
			var n []byte
			n, err = b64.DecodeString(v)
			if err == nil && len(n) != 16 {
				err = errAuthHeader
			}
			c.nonce = v
		case "sig":
			c.sig, err = b64.DecodeString(v)
			if err == nil && len(c.sig) != ed25519.SignatureSize {
				err = errAuthHeader
			}
		default:
			err = errAuthHeader
		}
		if err != nil {
			return c, errAuthHeader
		}
	}
	if len(seen) != 4 {
		return c, errAuthHeader
	}
	return c, nil
}
