package svldap

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svtrust"
)

// Directory is an LDAP directory as the trust store asks one
// (svtrust.Directory): the keys it holds for an address.
type Directory struct {
	// Label names the organisation: "Example Corp".
	Label string
	// URL is ldaps://host or ldap://host (StartTLS), and BaseDN where
	// people are: "dc=example,dc=com".
	URL, BaseDN string
	// BindDN and Password authenticate; an empty BindDN is anonymous.
	// Password is asked for each lookup, and its result wiped after.
	BindDN   string
	Password func(context.Context) ([]byte, error)
	// TLS is the TLS configuration (nil: the system's roots).
	TLS *tls.Config
}

// Name is how the directory is named to people.
func (d *Directory) Name() string { return d.Label + " (LDAP)" }

// The attributes certificates and OpenPGP keys are kept in:
// userCertificate (RFC 4523; Active Directory and OpenLDAP) and pgpKey
// (the OpenPGP LDAP schema).
var keyAttrs = []string{"userCertificate;binary", "userCertificate", "pgpKey"}

// Lookup returns the keys the directory holds for address, bound to it.
func (d *Directory) Lookup(ctx context.Context, address string) ([]*svtrust.Key, error) {
	c, err := Dial(ctx, d.URL, d.TLS)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if d.BindDN != "" {
		var pass []byte
		if d.Password != nil {
			if pass, err = d.Password(ctx); err != nil {
				return nil, err
			}
		}
		err = c.Bind(d.BindDN, pass)
		clear(pass)
		if err != nil {
			return nil, err
		}
	}
	entries, err := c.Search(d.BaseDN, []Match{
		{Attr: "mail", Value: address},
		{Attr: "proxyAddresses", Value: "smtp:" + address}, // Active Directory's other addresses
	}, keyAttrs)
	if err != nil {
		return nil, err
	}
	var out []*svtrust.Key
	var problems []string
	for _, e := range entries {
		for name, vals := range e.Attrs {
			if !strings.HasPrefix(name, "usercertificate") && name != "pgpkey" {
				continue
			}
			for _, v := range vals {
				keys, err := svtrust.ParseKeys(v)
				if err != nil {
					problems = append(problems, fmt.Sprintf("%s %s: %v", e.DN, name, err))
					continue
				}
				for _, k := range keys {
					k.Addresses = []string{address}
					out = append(out, k)
				}
			}
		}
	}
	if len(out) == 0 && len(problems) > 0 {
		return nil, errors.New("svldap: " + strings.Join(problems, "; "))
	}
	return out, nil
}
