package svrpc

import "testing"

func TestReferencesParseAndPrintBack(t *testing.T) {
	for _, c := range []struct {
		in   string
		want Ref
		out  string
	}{
		{"sv://prod/db/postgres#password", Ref{"prod", "db/postgres", "password"}, "sv://prod/db/postgres#password"},
		{"sv://-/api/token", Ref{"", "api/token", ""}, "sv://-/api/token"},
		{" sv:///api/token ", Ref{"", "api/token", ""}, "sv://-/api/token"},
		{"sv://prod/backup/*", Ref{"prod", "backup/*", ""}, "sv://prod/backup/*"},
		{"sv://prod/x#a#b", Ref{"prod", "x#a", "b"}, "sv://prod/x#a#b"}, // an item name may hold a #
	} {
		r, err := ParseRef(c.in)
		if err != nil || r != c.want || r.String() != c.out {
			t.Errorf("%q: %+v %q %v", c.in, r, r.String(), err)
		}
	}
	for _, bad := range []string{"", "prod/db", "sv://prod", "sv://prod/", "https://prod/x"} {
		if _, err := ParseRef(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}
