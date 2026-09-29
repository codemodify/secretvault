package svrpc

import (
	"fmt"
	"regexp"
	"strings"
)

// Ref is an sv:// reference to one value in a vault:
//
//	sv://VAULT/ITEM[#FIELD]
//
// VAULT "-" is the default vault (Vault is "" then). Without FIELD it
// names the item's secret: its password or secret field, else its first
// concealed or key field (svcore.Item.Secret).
type Ref struct {
	Vault string
	Item  string
	Field string
}

var refPattern = regexp.MustCompile(`^sv://([^/]*)/(.+?)(?:#([^#]+))?$`)

// ParseRef reads a reference.
func ParseRef(s string) (Ref, error) {
	m := refPattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return Ref{}, fmt.Errorf("%q is not a reference (sv://VAULT/ITEM[#FIELD], VAULT - for the default)", s)
	}
	r := Ref{Vault: m[1], Item: m[2], Field: m[3]}
	if r.Vault == "-" {
		r.Vault = ""
	}
	return r, nil
}

// String writes the reference back as text, "-" for the default vault.
func (r Ref) String() string {
	v := r.Vault
	if v == "" {
		v = "-"
	}
	s := "sv://" + v + "/" + r.Item
	if r.Field != "" {
		s += "#" + r.Field
	}
	return s
}
