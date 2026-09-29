package svtrust

import (
	"bytes"
	"context"
	"crypto/sha1"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	"github.com/codemodify/secretvault/svpgp"
)

// Finding keys: the Web Key Directory, keyservers, and an organisation's
// directory. Lookups go only where they are pointed; nothing here runs on
// its own.

// Found is what a lookup found.
type Found struct {
	// Keys each carry the addresses they are bound to and the verification
	// the lookup gives them, if any.
	Keys []*Key
	// URL is where they came from.
	URL string
	// Policy holds the domain's WKD policy flags ("mailbox-only",
	// "protocol-version: 13", ...), passed through as the domain wrote
	// them.
	Policy []string
}

// MaxKeySize is how much a lookup reads, by default.
const MaxKeySize = 1 << 20

// DefaultClient is the HTTP client lookups use when given none: a
// 30-second limit on the whole request, and at most three redirects, none
// from https to anything else.
func DefaultClient() *http.Client {
	return &http.Client{
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("too many redirects")
			}
			if via[0].URL.Scheme == "https" && req.URL.Scheme != "https" {
				return errors.New("a redirect away from https")
			}
			return nil
		},
	}
}

// errHTTPNotFound is a 404.
var errHTTPNotFound = errors.New("not found")

// fetch gets a URL, refusing more than max bytes.
func fetch(ctx context.Context, client *http.Client, u string, max int64) ([]byte, error) {
	if client == nil {
		client = DefaultClient()
	}
	if max <= 0 {
		max = MaxKeySize
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotFound:
		return nil, errHTTPNotFound
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: %s", u, resp.Status)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s: more than %d bytes", u, max)
	}
	return b, nil
}

// The Web Key Directory (draft-koch-openpgp-webkey-service).

// zbase32 is the z-base-32 alphabet WKD hashes are written in.
const zbase32 = "ybndrfg8ejkmcpqxot1uwisza345h769"

func zbase32Encode(b []byte) string {
	var sb strings.Builder
	var acc, bits uint
	for _, c := range b {
		acc = acc<<8 | uint(c)
		bits += 8
		for bits >= 5 {
			bits -= 5
			sb.WriteByte(zbase32[acc>>bits&31])
		}
	}
	if bits > 0 {
		sb.WriteByte(zbase32[acc<<(5-bits)&31])
	}
	return sb.String()
}

// WKDHash is the WKD name of an address's local part: z-base-32 of the
// SHA-1 of the local part, its ASCII letters lowercased.
func WKDHash(local string) string {
	lower := []byte(local)
	for i, c := range lower {
		if 'A' <= c && c <= 'Z' {
			lower[i] = c + 'a' - 'A'
		}
	}
	sum := sha1.Sum(lower)
	return zbase32Encode(sum[:])
}

// WKDURLs are where the advanced and the direct method look for an
// address's key.
func WKDURLs(address string) (advanced, direct string, err error) {
	addr := ParseAddress(address)
	if addr == "" {
		return "", "", fmt.Errorf("svtrust: %q is not an email address", address)
	}
	i := strings.LastIndexByte(addr, '@')
	local, domain := addr[:i], strings.ToLower(addr[i+1:])
	path := "/hu/" + WKDHash(local) + "?l=" + url.QueryEscape(local)
	return "https://openpgpkey." + domain + "/.well-known/openpgpkey/" + domain + path,
		"https://" + domain + "/.well-known/openpgpkey" + path, nil
}

// WKD looks keys up in the Web Key Directory of an address's domain.
type WKD struct {
	Client  *http.Client // nil means DefaultClient()
	MaxSize int64        // 0 means MaxKeySize
	// Now is the clock (tests replace it).
	Now func() time.Time
}

// Lookup asks the address's domain for its key: by the advanced method,
// and by the direct one if the openpgpkey subdomain does not exist. Only
// keys that name the address in a user ID are kept (others are refused),
// and each is bound to that address alone, published by its domain
// (MethodWKD).
func (w *WKD) Lookup(ctx context.Context, address string) (*Found, error) {
	adv, dir, err := WKDURLs(address)
	if err != nil {
		return nil, err
	}
	addr := ParseAddress(address)
	u := adv
	data, err := fetch(ctx, w.Client, u, w.MaxSize)
	if err != nil && hostMissing(err) {
		u = dir
		data, err = fetch(ctx, w.Client, u, w.MaxSize)
	}
	if errors.Is(err, errHTTPNotFound) {
		return nil, fmt.Errorf("%w: %s publishes no key for %s", ErrNotFound, domainOf(addr), addr)
	}
	if err != nil {
		return nil, err
	}
	pks, err := svpgp.ReadKeys(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	now := nowOr(w.Now)
	f := &Found{URL: u, Policy: w.policy(ctx, u)}
	for _, pk := range pks {
		k, err := fromOpenPGP(pk.Public())
		pk.Close()
		if err != nil || !containsAddr(k.Addresses, addr) {
			continue
		}
		k.Addresses, k.Source, k.Added = []string{addr}, u, now
		k.Events = []Event{{Level: Published, Method: MethodWKD, At: now, Source: u, Addresses: []string{addr}}}
		f.Keys = append(f.Keys, k)
	}
	if len(f.Keys) == 0 {
		return nil, fmt.Errorf("svtrust: the key %s publishes for %s does not name that address; refused", domainOf(addr), addr)
	}
	return f, nil
}

// policy reads the WKD policy flags beside a key URL, if the domain has
// any.
func (w *WKD) policy(ctx context.Context, keyURL string) []string {
	i := strings.Index(keyURL, "/hu/")
	if i < 0 {
		return nil
	}
	data, err := fetch(ctx, w.Client, keyURL[:i]+"/policy", 64<<10)
	if err != nil {
		return nil
	}
	var flags []string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
			flags = append(flags, line)
		}
	}
	return flags
}

// hostMissing reports whether err means the host does not exist or takes
// no connections: what sends WKD to the direct method.
func hostMissing(err error) bool {
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return dns.IsNotFound
	}
	return errors.Is(err, syscall.ECONNREFUSED)
}

func domainOf(addr string) string {
	_, d, _ := strings.Cut(addr, "@")
	return strings.ToLower(d)
}

func nowOr(now func() time.Time) time.Time {
	if now == nil {
		now = time.Now
	}
	return now().UTC().Truncate(time.Second)
}

// Keyservers.

// DefaultKeyserver is keys.openpgp.org, which gives out an address on a
// key only once the address's owner has confirmed it by email.
const DefaultKeyserver = "https://keys.openpgp.org"

// Keyserver looks keys up on a keyserver: by its VKS API
// (/vks/v1/by-email/..., /vks/v1/by-fingerprint/...), which
// keys.openpgp.org serves and which returns only addresses confirmed by
// email, and else by the older HKP (/pks/lookup?op=get), whose keyservers
// check nothing.
type Keyserver struct {
	// URL is the keyserver: https://host, or hkps://host (https) or
	// hkp://host (http on port 11371). "" means DefaultKeyserver.
	URL     string
	Client  *http.Client // nil means DefaultClient()
	MaxSize int64        // 0 means MaxKeySize
	Now     func() time.Time
}

// base is the keyserver's URL, with hkp and hkps made http and https.
func (s *Keyserver) base() (string, error) {
	raw := s.URL
	if raw == "" {
		raw = DefaultKeyserver
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("svtrust: %q is not a keyserver URL", raw)
	}
	switch u.Scheme {
	case "hkps":
		u.Scheme = "https"
	case "hkp":
		u.Scheme = "http"
		if u.Port() == "" {
			u.Host += ":11371"
		}
	case "https", "http":
	default:
		return "", fmt.Errorf("svtrust: a keyserver URL starts https://, hkps:// or hkp://, not %s://", u.Scheme)
	}
	return strings.TrimSuffix(u.String(), "/"), nil
}

// ByEmail asks the keyserver for an address's keys. Keys from VKS are
// bound to the addresses on them, which the keyserver checked by email
// (MethodKeyserver); keys from HKP to the addresses they name, unverified.
// Either way only keys naming the address are kept.
func (s *Keyserver) ByEmail(ctx context.Context, address string) (*Found, error) {
	addr := ParseAddress(address)
	if addr == "" {
		return nil, fmt.Errorf("svtrust: %q is not an email address", address)
	}
	base, err := s.base()
	if err != nil {
		return nil, err
	}
	keep := func(k *Key) bool { return containsAddr(k.Addresses, addr) }
	return s.lookup(ctx, base+"/vks/v1/by-email/"+url.PathEscape(addr),
		base+"/pks/lookup?op=get&options=mr&search="+url.QueryEscape(addr), keep, addr)
}

// ByFingerprint asks the keyserver for the key with a fingerprint or key
// ID. Only a key it names is kept.
func (s *Keyserver) ByFingerprint(ctx context.Context, fingerprint string) (*Found, error) {
	fp := NormalizeFingerprint(fingerprint)
	if !isHex(fp) || len(fp) != 16 && !openPGPFingerprint(fp) {
		return nil, fmt.Errorf("svtrust: %q is not an OpenPGP fingerprint or key ID", fingerprint)
	}
	base, err := s.base()
	if err != nil {
		return nil, err
	}
	vks := base + "/vks/v1/by-fingerprint/" + fp
	if len(fp) == 16 {
		vks = base + "/vks/v1/by-keyid/" + fp
	}
	keep := func(k *Key) bool { return k.matches(fp) }
	return s.lookup(ctx, vks, base+"/pks/lookup?op=get&options=mr&search=0x"+fp, keep, fp)
}

// lookup tries VKS, then HKP.
func (s *Keyserver) lookup(ctx context.Context, vks, hkp string, keep func(*Key) bool, what string) (*Found, error) {
	now := nowOr(s.Now)
	u, verified := vks, true
	data, err := fetch(ctx, s.Client, u, s.MaxSize)
	if errors.Is(err, errHTTPNotFound) {
		u, verified = hkp, false
		data, err = fetch(ctx, s.Client, u, s.MaxSize)
	}
	if errors.Is(err, errHTTPNotFound) {
		return nil, fmt.Errorf("%w: the keyserver has no key for %s", ErrNotFound, what)
	}
	if err != nil {
		return nil, err
	}
	pks, err := svpgp.ReadKeys(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", u, err)
	}
	f := &Found{URL: u}
	for _, pk := range pks {
		k, err := fromOpenPGP(pk.Public())
		pk.Close()
		if err != nil || !keep(k) {
			continue
		}
		k.Source, k.Added = u, now
		if verified && len(k.Addresses) > 0 {
			k.Events = []Event{{Level: Published, Method: MethodKeyserver, At: now, Source: u, Addresses: k.Addresses}}
		}
		f.Keys = append(f.Keys, k)
	}
	if len(f.Keys) == 0 {
		return nil, fmt.Errorf("%w: the keyserver's answer has no key for %s", ErrNotFound, what)
	}
	return f, nil
}

// Directory is an organisation's directory of people and their keys: LDAP
// or Active Directory, or an organisation's secretvault server. None is
// written yet; LookupDirectory is how one is used.
type Directory interface {
	// Name names the directory for people: "Example Corp (LDAP)".
	Name() string
	// Lookup returns the keys the directory holds for an address, each
	// with the addresses the directory binds it to.
	Lookup(ctx context.Context, address string) ([]*Key, error)
}

// LookupDirectory asks a directory for an address's keys and records on
// each that the organisation vouches for it (MethodOrgDirectory), for the
// addresses the directory gives. Which directories to ask is the caller's
// choice: asking one is believing it.
func LookupDirectory(ctx context.Context, d Directory, address string, now time.Time) (*Found, error) {
	addr := ParseAddress(address)
	if addr == "" {
		return nil, fmt.Errorf("svtrust: %q is not an email address", address)
	}
	keys, err := d.Lookup(ctx, addr)
	if err != nil {
		return nil, err
	}
	if now.IsZero() {
		now = time.Now()
	}
	now = now.UTC().Truncate(time.Second)
	f := &Found{URL: d.Name()}
	for _, k := range keys {
		if len(k.Addresses) == 0 {
			k.Addresses = []string{addr}
		}
		k.Source, k.Added = d.Name(), now
		k.Events = append(k.Events, Event{Level: Organisation, Method: MethodOrgDirectory, At: now, Source: d.Name(), Addresses: k.Addresses})
		f.Keys = append(f.Keys, k)
	}
	if len(f.Keys) == 0 {
		return nil, fmt.Errorf("%w: %s has no key for %s", ErrNotFound, d.Name(), addr)
	}
	return f, nil
}
