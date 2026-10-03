package svext

import (
	"bufio"
	"bytes"
	"net"
	"strings"
	"sync"

	"github.com/codemodify/secretvault/browser"
)

// The Public Suffix List says where a name stops being a registry's and
// starts being someone's: "co.uk" and "github.io" are public suffixes,
// so "example.co.uk" and "alice.github.io" are each one owner's
// (registrable domains), and "bob.github.io" is someone else's. Its ICANN
// and private sections are both read: it is the private section that
// keeps alice.github.io's logins from bob.github.io.
//
// The list is the one the extension bundles (package browser), fetched by
// scripts/update-psl.sh. Its algorithm is the list's own
// (https://github.com/publicsuffix/list/wiki/Format): the longest rule
// that fits wins, an exception rule ("!www.ck") over the wildcard it
// excepts, and a name no rule fits has its last label as its suffix.

// SuffixList is a parsed Public Suffix List.
type SuffixList struct {
	rules      map[string]bool // "co.uk"
	wildcards  map[string]bool // "ck" for "*.ck"
	exceptions map[string]bool // "www.ck" for "!www.ck"
}

// ParseSuffixList reads the list's text. Rules are kept in the ASCII
// form browsers send names in.
func ParseSuffixList(data []byte) *SuffixList {
	l := &SuffixList{rules: map[string]bool{}, wildcards: map[string]bool{}, exceptions: map[string]bool{}}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}
		if i := strings.IndexAny(line, " \t"); i >= 0 {
			line = line[:i]
		}
		set := l.rules
		switch {
		case strings.HasPrefix(line, "!"):
			set, line = l.exceptions, line[1:]
		case strings.HasPrefix(line, "*."):
			set, line = l.wildcards, line[2:]
		}
		if a, ok := asciiHost(line); ok {
			set[a] = true
		}
	}
	return l
}

var (
	listOnce sync.Once
	list     *SuffixList
)

// Suffixes is the bundled list, parsed once.
func Suffixes() *SuffixList {
	listOnce.Do(func() { list = ParseSuffixList(browser.PSL()) })
	return list
}

// Len is the number of rules: none means the list was not read.
func (l *SuffixList) Len() int { return len(l.rules) + len(l.wildcards) + len(l.exceptions) }

// PublicSuffix is the public suffix of an ASCII host name ("co.uk" for
// "www.example.co.uk").
func (l *SuffixList) PublicSuffix(host string) string {
	labels := strings.Split(host, ".")
	for i := range labels {
		s := strings.Join(labels[i:], ".")
		if l.exceptions[s] {
			return strings.Join(labels[i+1:], ".")
		}
		if l.rules[s] {
			return s
		}
		if i+1 < len(labels) && l.wildcards[strings.Join(labels[i+1:], ".")] {
			return s
		}
	}
	return labels[len(labels)-1]
}

// RegistrableDomain is the public suffix and the label before it
// ("example.co.uk" for "www.example.co.uk"); "" for a public suffix
// itself, an IP address, or a name of one label ("localhost").
func (l *SuffixList) RegistrableDomain(host string) string {
	if host == "" || net.ParseIP(host) != nil || !strings.Contains(host, ".") {
		return ""
	}
	ps := l.PublicSuffix(host)
	if ps == host {
		return ""
	}
	rest := strings.TrimSuffix(host, "."+ps)
	return rest[strings.LastIndexByte(rest, '.')+1:] + "." + ps
}
