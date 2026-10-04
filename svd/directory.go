package svd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svldap"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svtrust"
)

// Organisations' LDAP directories, asked for people's keys by contact
// lookups. A directory's answers are recorded as the organisation vouching
// for the key, for the address asked about: configuring one is trusting
// it, so only secretvault's own programs may.

func init() {
	registerMethod(svrpc.MDirectoryAdd, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.DirectoryConfig
		if err := decode(&p); err != nil {
			return nil, err
		}
		if !cl.cli {
			return nil, errOwnPrograms
		}
		if err := checkDirectory(p); err != nil {
			return nil, err
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		for _, x := range d.cfg.Directories {
			if x.Name == p.Name {
				return nil, svrpc.Errorf(svrpc.CodeExists, "there is already a directory %q", p.Name)
			}
		}
		d.cfg.Directories = append(d.cfg.Directories, p)
		if err := d.cfg.save(d.home); err != nil {
			d.cfg.Directories = d.cfg.Directories[:len(d.cfg.Directories)-1]
			return nil, err
		}
		return nil, nil
	})
	registerMethod(svrpc.MDirectoryList, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		d.mu.Lock()
		defer d.mu.Unlock()
		return append([]svrpc.DirectoryConfig{}, d.cfg.Directories...), nil
	})
	registerMethod(svrpc.MDirectoryRemove, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.DirectoryRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		if !cl.cli {
			return nil, errOwnPrograms
		}
		d.mu.Lock()
		defer d.mu.Unlock()
		for i, x := range d.cfg.Directories {
			if x.Name == p.Name {
				d.cfg.Directories = append(d.cfg.Directories[:i:i], d.cfg.Directories[i+1:]...)
				return nil, d.cfg.save(d.home)
			}
		}
		return nil, svrpc.Errorf(svrpc.CodeNotFound, "there is no directory %q", p.Name)
	})
}

func checkDirectory(p svrpc.DirectoryConfig) error {
	switch {
	case p.Name == "":
		return svrpc.Errorf(svrpc.CodeInvalidParams, "a directory needs a name")
	case !strings.HasPrefix(p.URL, "ldap://") && !strings.HasPrefix(p.URL, "ldaps://"):
		return svrpc.Errorf(svrpc.CodeInvalidParams, "%q is not an LDAP URL (ldaps://host, or ldap://host with StartTLS)", p.URL)
	case p.BaseDN == "":
		return svrpc.Errorf(svrpc.CodeInvalidParams, "a directory needs the base DN people are under (dc=example,dc=com)")
	}
	if p.Password != "" {
		if _, err := svrpc.ParseRef(p.Password); err != nil {
			return svrpc.Errorf(svrpc.CodeInvalidParams, "the password must be a reference to a vault item: %v", err)
		}
	}
	return nil
}

// directories are the configured directories to ask, as svtrust asks
// them; only the named one when name is set. Bind passwords are read from
// their vault items on behalf of cl, with its consent.
func (d *Daemon) directories(ctx context.Context, cl *client, name string) ([]svtrust.Directory, error) {
	d.mu.Lock()
	cfgs := append([]svrpc.DirectoryConfig(nil), d.cfg.Directories...)
	d.mu.Unlock()
	var out []svtrust.Directory
	for _, c := range cfgs {
		if name != "" && c.Name != name {
			continue
		}
		dir := &svldap.Directory{Label: c.Name, URL: c.URL, BaseDN: c.BaseDN, BindDN: c.BindDN}
		if c.CAFile != "" {
			pem, err := os.ReadFile(c.CAFile)
			if err != nil {
				return nil, err
			}
			roots := x509.NewCertPool()
			if !roots.AppendCertsFromPEM(pem) {
				return nil, fmt.Errorf("%s has no certificate", c.CAFile)
			}
			dir.TLS = &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}
		}
		if c.Password != "" {
			ref := c.Password
			dir.Password = func(ctx context.Context) ([]byte, error) { return d.readRef(ctx, cl, ref) }
		}
		out = append(out, dir)
	}
	if name != "" && len(out) == 0 {
		return nil, svrpc.Errorf(svrpc.CodeNotFound, "there is no directory %q ('secretvault contact directory ls')", name)
	}
	return out, nil
}

// readRef reads the value a reference names, as cl reading that item.
func (d *Daemon) readRef(ctx context.Context, cl *client, s string) ([]byte, error) {
	ref, err := svrpc.ParseRef(s)
	if err != nil {
		return nil, err
	}
	_, e, err := d.item(ctx, cl, ref.Vault, ref.Item, svbroker.OpRead)
	if err != nil {
		return nil, err
	}
	defer e.Item.Wipe()
	if ref.Field != "" {
		if f, ok := e.Item.Field(ref.Field); ok {
			if e.Item.Kind == svcore.KindPasskey && f.Type == svcore.FieldKey {
				return nil, fmt.Errorf("%s: a passkey's key is used inside secretvault, not handed out", ref.Item)
			}
			return append([]byte(nil), f.Value...), nil
		}
		return nil, fmt.Errorf("%s has no field %q", ref.Item, ref.Field)
	}
	if f, ok := e.Item.Secret(); ok {
		return append([]byte(nil), f.Value...), nil
	}
	return nil, errors.New(ref.Item + " holds no secret")
}
