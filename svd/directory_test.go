package svd

import (
	"strings"
	"testing"

	"github.com/codemodify/secretvault/internal/ldaptest"
	"github.com/codemodify/secretvault/svrpc"
)

func TestAnOrganisationsDirectoryVouchesForItsPeople(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	alice, _ := smimeUser(t, "alice@example.org")
	s := ldaptest.New(t, ldaptest.Options{BindDN: "cn=reader,dc=example,dc=org", Password: "dir-pass",
		People: map[string]map[string][][]byte{"alice@example.org": {"userCertificate;binary": {alice.Raw}}}})
	// The bind password is kept in the vault, and named by reference.
	if _, err := cli.Put(ctx(t), "", svrpc.Item{Kind: "password", Name: "ldap/reader",
		Fields: []svrpc.Field{{Name: "password", Type: "concealed", Value: []byte("dir-pass")}}}); err != nil {
		t.Fatal(err)
	}
	dir := svrpc.DirectoryConfig{Name: "Example", URL: s.URL, BaseDN: ldaptest.Base, BindDN: "cn=reader,dc=example,dc=org", Password: "sv://-/ldap/reader"}
	if err := h.connect("/usr/bin/some-app", nil).AddDirectory(ctx(t), dir); err == nil {
		t.Fatal("another program configured a directory")
	}
	if err := cli.AddDirectory(ctx(t), dir); err != nil {
		t.Fatal(err)
	}
	if ds, err := cli.Directories(ctx(t)); err != nil || len(ds) != 1 {
		t.Fatalf("directories: %+v, %v", ds, err)
	}
	res, err := cli.LookupContact(ctx(t), svrpc.ContactLookupParams{Query: "alice@example.org", Directory: "Example", Add: true})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Found) != 1 || !strings.Contains(res.Found[0].URL, "Example (LDAP)") || len(res.Added) != 1 {
		t.Fatalf("lookup: %+v", res)
	}
	v, err := cli.CheckSigner(ctx(t), svrpc.TrustCheckParams{Key: alice.Raw, From: "alice@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	if v.Level != "organisation" || !v.Bound {
		t.Fatalf("the verdict: %+v", v)
	}
	if err := cli.RemoveDirectory(ctx(t), "Example"); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.LookupContact(ctx(t), svrpc.ContactLookupParams{Query: "alice@example.org", Directory: "Example"}); err == nil {
		t.Fatal("a removed directory was asked")
	}
}
