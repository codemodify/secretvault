package svext

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

// Which logins a page may be offered. The extension names the page by
// its origin (scheme, host, port: "https://github.com"), the browser's own
// idea of who the page is, and a login fits it by one of its stored URLs:
//
//   - The scheme: a login kept for https is never offered to http. One
//     kept for http is offered to https on the same host, an upgrade that
//     sends it nowhere it did not go before. A stored URL without a scheme
//     is taken as https. Nothing but http and https is matched.
//   - The port: a stored port must be the page's; a stored URL without one
//     fits only the scheme's default port (a service on another port of a
//     host is another origin, as browsers see it).
//   - The host: the page's own (MatchHost), or another name with the same
//     registrable domain by the Public Suffix List (MatchSite):
//     login.example.co.uk fits www.example.co.uk; alice.github.io does
//     not fit bob.github.io, nor does co.uk fit anything but itself. An IP
//     address, and a name of one label (localhost), fit only themselves.
//
// The same rules are in the extension (lib/origin.js), which checks again
// before it fills.

// Match is how a stored URL fits an origin.
type Match int

const (
	MatchNone Match = iota
	MatchSite       // the same registrable domain
	MatchHost       // the same host
)

func (m Match) String() string {
	switch m {
	case MatchHost:
		return "host"
	case MatchSite:
		return "site"
	}
	return "none"
}

// Origin is a page's origin: an http or https scheme, an ASCII host in
// lower case, and its port (the scheme's default when the URL names none).
type Origin struct {
	Scheme string
	Host   string
	Port   int
}

func defaultPort(scheme string) int {
	if scheme == "http" {
		return 80
	}
	return 443
}

// String is the origin as browsers write it: no default port, no path.
func (o Origin) String() string {
	host := o.Host
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if o.Port == defaultPort(o.Scheme) {
		return o.Scheme + "://" + host
	}
	return o.Scheme + "://" + host + ":" + strconv.Itoa(o.Port)
}

// ErrBadOrigin is an origin that is not one: what the extension sends must
// be exactly scheme://host[:port], as window.location.origin is.
var ErrBadOrigin = errors.New("not an http or https origin")

// ParseOrigin reads an origin as the extension sends it. It is strict: a
// path, a query, a user name or a default port written out is refused,
// so that one origin has one spelling.
func ParseOrigin(s string) (Origin, error) {
	if s == "" || len(s) > MaxOrigin {
		return Origin{}, ErrBadOrigin
	}
	u, err := url.Parse(s)
	if err != nil || u.User != nil || u.Path != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" {
		return Origin{}, ErrBadOrigin
	}
	o, ok := originOf(u)
	if !ok || o.String() != s {
		return Origin{}, ErrBadOrigin
	}
	return o, nil
}

// originOf is a parsed URL's origin.
func originOf(u *url.URL) (Origin, bool) {
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return Origin{}, false
	}
	host := u.Hostname()
	if host == "" {
		return Origin{}, false
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() == nil && !strings.Contains(u.Host, "[") {
			return Origin{}, false
		}
		host = ip.String()
	} else {
		var ok bool
		if host, ok = asciiHost(host); !ok {
			return Origin{}, false
		}
	}
	port := defaultPort(scheme)
	if p := u.Port(); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil || n < 1 || n > 65535 {
			return Origin{}, false
		}
		port = n
	}
	return Origin{Scheme: scheme, Host: host, Port: port}, true
}

// StoredOrigin reads a URL as an item keeps it ("github.com",
// "https://github.com/login", "http://intranet:8080/"), and returns its
// origin; ok is false when it names no http or https host.
func StoredOrigin(stored string) (Origin, bool) {
	s := strings.TrimSpace(stored)
	if s == "" || len(s) > 4096 || strings.ContainsAny(s, "<>^`{|}*\" \t\r\n\\") {
		return Origin{}, false
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil {
		return Origin{}, false
	}
	return originOf(u)
}

// MatchURL says how a stored URL fits a page's origin, by the list l.
func MatchURL(l *SuffixList, stored string, page Origin) Match {
	s, ok := StoredOrigin(stored)
	if !ok {
		return MatchNone
	}
	return MatchOrigin(l, s, page)
}

// MatchOrigin says how a stored origin fits a page's.
func MatchOrigin(l *SuffixList, stored, page Origin) Match {
	switch {
	case stored.Scheme == page.Scheme && stored.Port == page.Port:
	case stored.Scheme == "http" && page.Scheme == "https" && stored.Port == 80 && page.Port == 443:
		// An upgrade, on the default ports.
	default:
		return MatchNone
	}
	if stored.Host == page.Host {
		return MatchHost
	}
	rd := l.RegistrableDomain(page.Host)
	if rd != "" && rd == l.RegistrableDomain(stored.Host) {
		return MatchSite
	}
	return MatchNone
}
