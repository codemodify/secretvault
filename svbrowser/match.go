package svbrowser

import (
	"net"
	"net/url"
	"path"
	"strings"
)

// Which stored URLs fit the page the extension is on. The rules are
// KeePassXC's (BrowserService::handleURL, with its default of matching the
// scheme), except that there is no public suffix list:
//
//   - A stored URL without a scheme is taken as https.
//   - The scheme must be the page's: a login kept for https is not offered
//     to http.
//   - A stored port must be the page's (a missing port is the scheme's
//     default); a stored URL without one fits any port.
//   - The host must be the page's, or a parent domain of it: github.com
//     fits gist.github.com, not evilgithub.com. A bare top-level name
//     ("com") fits nothing but itself, and an IP address or localhost only
//     itself. Without the public suffix list, a stored "co.uk" would fit
//     every site under it: nobody stores that by accident.
//   - Wildcards and quoted exact URLs (KeePassXC's additional-URL syntax)
//     are not read: such a URL fits nothing.

// Priority says how well stored fits the page at siteURL, whose form posts
// to formURL (which may be ""): 0 when it does not fit, else higher for a
// closer fit, with KeePassXC's ranks: 100 the same URL, 90 the same but
// for the query, 85 a parent path, 80 the page's host, 70 the form's host,
// 60 a parent domain of the page's host, 50 of the form's.
func Priority(stored, siteURL, formURL string) int {
	site := parseSite(siteURL)
	entry := parseStored(stored)
	if site == nil || entry == nil || !fits(entry, site) {
		return 0
	}
	best := rank(entry, site, 80, 60)
	if form := parseSite(formURL); form != nil && form.Scheme == entry.Scheme {
		best = max(best, rank(entry, form, 70, 50))
	}
	return max(best, 1)
}

// Host is the host of a page's URL, for saying which site is asking; ""
// when it has none.
func Host(pageURL string) string {
	if u := parseSite(pageURL); u != nil {
		return u.Hostname()
	}
	return ""
}

// parseSite reads a page URL as the extension sends it.
func parseSite(s string) *url.URL {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Scheme == "" || u.Hostname() == "" {
		return nil
	}
	return normal(u)
}

// parseStored reads a URL as it is kept in an item.
func parseStored(s string) *url.URL {
	s = strings.TrimSpace(s)
	if s == "" || strings.ContainsAny(s, "<>^`{|}*\" ") {
		return nil
	}
	if !strings.Contains(s, "://") {
		s = "https://" + s
	}
	u, err := url.Parse(s)
	if err != nil || u.Hostname() == "" {
		return nil
	}
	return normal(u)
}

func normal(u *url.URL) *url.URL {
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.TrimSuffix(strings.ToLower(u.Hostname()), ".")
	if port := u.Port(); port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else if strings.Contains(host, ":") {
		u.Host = "[" + host + "]"
	} else {
		u.Host = host
	}
	u.User, u.Fragment, u.RawFragment = nil, "", ""
	if u.Path == "" {
		u.Path = "/"
	}
	return u
}

func defaultPort(scheme string) string {
	switch scheme {
	case "https", "wss":
		return "443"
	case "http", "ws":
		return "80"
	case "ftp":
		return "21"
	}
	return ""
}

func port(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	return defaultPort(u.Scheme)
}

// fits reports whether a stored URL may be offered on a page at all.
func fits(entry, site *url.URL) bool {
	if entry.Scheme != site.Scheme {
		return false
	}
	if entry.Port() != "" && port(entry) != port(site) {
		return false
	}
	return hostFits(entry.Hostname(), site.Hostname())
}

// hostFits reports whether a stored host is the page's, or a parent
// domain of it that is more than a top-level name.
func hostFits(stored, page string) bool {
	if stored == page {
		return true
	}
	if net.ParseIP(stored) != nil || net.ParseIP(page) != nil || !strings.Contains(stored, ".") {
		return false
	}
	return strings.HasSuffix(page, "."+stored)
}

// rank is KeePassXC's sortPriority for one page URL; sameHost and parent
// are the ranks for a host match and a parent-domain match.
func rank(entry, page *url.URL, sameHost, parent int) int {
	switch {
	case entry.String() == page.String():
		return 100
	case withoutQuery(entry) == withoutQuery(page):
		return 90
	case entry.Host == page.Host && isParentPath(entry.Path, page.Path):
		return 85
	case entry.Hostname() == page.Hostname():
		return sameHost
	case hostFits(entry.Hostname(), page.Hostname()):
		return parent
	}
	return 0
}

func withoutQuery(u *url.URL) string {
	c := *u
	c.RawQuery, c.ForceQuery = "", false
	return c.String()
}

// isParentPath reports whether dir is a directory above p: /a above /a/b.
func isParentPath(dir, p string) bool {
	dir = path.Clean("/" + dir)
	p = path.Clean("/" + p)
	if dir == p {
		return false
	}
	return dir == "/" || strings.HasPrefix(p, dir+"/")
}
