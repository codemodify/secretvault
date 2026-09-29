package svsync

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svserver"
)

// Remote is where a vault is synced to: a server, and the vault's name
// there. It is plain configuration, and holds nothing secret.
type Remote struct {
	// URL is the server's address, like https://sync.example.com:8443, with
	// a path if the server is mounted under one.
	URL string `json:"url"`

	// Vault is the vault's name on the server (svserver.CheckVaultName);
	// by convention the vault's own ID.
	Vault string `json:"vault"`

	// Fingerprint pins the server's certificate by its SHA-256 (hex; colons
	// and case do not matter), for a server with a self-signed certificate.
	// Empty means the certificate must be trusted by the system's roots.
	Fingerprint string `json:"fingerprint,omitempty"`
}

// base checks r and returns its URL.
func (r Remote) base() (*url.URL, error) {
	u, err := url.Parse(r.URL)
	if err != nil || u.Host == "" || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("svsync: %q is not a server URL", r.URL)
	}
	switch u.Scheme {
	case "https":
	case "http":
		// Plain HTTP only to this machine: the requests are signed and the
		// files sealed, but nothing else about the traffic should be open.
		if ip := net.ParseIP(u.Hostname()); u.Hostname() != "localhost" && (ip == nil || !ip.IsLoopback()) {
			return nil, fmt.Errorf("svsync: %s is not HTTPS", r.URL)
		}
	default:
		return nil, fmt.Errorf("svsync: %s is not HTTPS", r.URL)
	}
	if err := svserver.CheckVaultName(r.Vault); err != nil {
		return nil, err
	}
	if _, err := parseFingerprint(r.Fingerprint); err != nil {
		return nil, err
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	return u, nil
}

// parseFingerprint reads a certificate fingerprint; nil for none.
func parseFingerprint(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	clean := strings.NewReplacer(":", "", " ", "", "-", "").Replace(strings.ToLower(s))
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != sha256.Size {
		return nil, fmt.Errorf("svsync: %q is not a SHA-256 certificate fingerprint", s)
	}
	return b, nil
}

// ErrPin is a server whose certificate is not the one pinned.
var ErrPin = errors.New("svsync: the server's certificate does not match the pinned fingerprint")

// newHTTPClient returns a client that trusts the pinned certificate, if
// there is one, and else the system's roots.
func newHTTPClient(pin []byte) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	if pin != nil {
		// The pin replaces the chain and name checks: a self-signed
		// certificate has neither, and the pin is stronger than both.
		t.TLSClientConfig.InsecureSkipVerify = true
		t.TLSClientConfig.VerifyConnection = func(cs tls.ConnectionState) error {
			if len(cs.PeerCertificates) == 0 {
				return ErrPin
			}
			got := sha256.Sum256(cs.PeerCertificates[0].Raw)
			if subtle.ConstantTimeCompare(got[:], pin) != 1 {
				return fmt.Errorf("%w (it is %x)", ErrPin, got)
			}
			return nil
		}
	}
	t.ResponseHeaderTimeout = svserver.MaxWait + 30*time.Second
	return &http.Client{Transport: t}
}

// Invite is what a device that is already enrolled hands to a new one
// (as text or a QR code): where the vault is, how to trust the server,
// and a one-time code to enrol with.
type Invite struct {
	Remote
	Code    string
	Expires time.Time
}

const inviteScheme = "secretvault-sync"

// String writes the invite as a URI:
//
//	secretvault-sync:?url=...&vault=...&fp=...&code=...
func (i Invite) String() string {
	q := url.Values{}
	q.Set("url", i.URL)
	q.Set("vault", i.Vault)
	if i.Fingerprint != "" {
		q.Set("fp", i.Fingerprint)
	}
	q.Set("code", i.Code)
	return inviteScheme + ":?" + q.Encode()
}

// ParseInvite reads an invite as String writes it.
func ParseInvite(s string) (Invite, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), inviteScheme+":?")
	if !ok {
		return Invite{}, errors.New("svsync: not a sync invite")
	}
	q, err := url.ParseQuery(rest)
	if err != nil {
		return Invite{}, fmt.Errorf("svsync: not a sync invite: %w", err)
	}
	i := Invite{Remote: Remote{URL: q.Get("url"), Vault: q.Get("vault"), Fingerprint: q.Get("fp")}, Code: q.Get("code")}
	if _, err := i.base(); err != nil {
		return Invite{}, err
	}
	if i.Code == "" {
		return Invite{}, errors.New("svsync: the invite has no code")
	}
	return i, nil
}
