package svdeliver

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGlobs(t *testing.T) {
	cases := []struct {
		pattern, name string
		want          bool
	}{
		{"prod/db/*", "prod/db/password", true},
		{"prod/db/*", "prod/db/replica/password", true}, // '*' crosses '/'
		{"prod/db/*", "prod/db", false},
		{"prod/db/*", "prod/dbx/password", false},
		{"prod/*/password", "prod/db/password", true},
		{"prod/*/password", "prod/db/user", false},
		{"*", "", true},
		{"*", "anything/at/all", true},
		{"refs/heads/*", "refs/heads/main", true},
		{"refs/heads/*", "refs/tags/v1", false},
		{"acme/app", "acme/app", true},
		{"acme/app", "acme/app-evil", false},
		{"acme/app", "acme/ap", false},
		{"v?.*", "v1.2", true},
		{"v?.*", "v12.2", false},
		{"*a*b*", "xxaxxbxx", true},
		{"*a*b*", "xxbxxaxx", false},
		{"süß/*", "süß/x", true},
		{"??", "ß!", true},
		{"", "", true},
		{"", "x", false},
	}
	for _, c := range cases {
		if got := globMatch(c.pattern, c.name); got != c.want {
			t.Errorf("globMatch(%q, %q) = %v, want %v", c.pattern, c.name, got, c.want)
		}
	}
}

func claimsOf(t *testing.T, doc string) map[string]any {
	t.Helper()
	// As parseJWS decodes claims: numbers as json.Number.
	members, err := objectMembers([]byte(doc))
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]any{}
	for k, v := range members {
		d := json.NewDecoder(strings.NewReader(string(v)))
		d.UseNumber()
		var x any
		if err := d.Decode(&x); err != nil {
			t.Fatal(err)
		}
		out[k] = x
	}
	return out
}

func TestClaimMatching(t *testing.T) {
	gh := claimsOf(t, `{"sub":"repo:acme/app:environment:prod","repository":"acme/app","repository_id":"123456","ref":"refs/heads/main",
		"environment":"prod","job_workflow_ref":"acme/workflows/.github/workflows/deploy.yml@refs/heads/main","run_attempt":"1"}`)
	k8s := claimsOf(t, `{"sub":"system:serviceaccount:payments:api","aud":["https://secrets.example.com"],
		"kubernetes.io":{"namespace":"payments","serviceaccount":{"name":"api","uid":"e2c3"},"pod":{"name":"api-7d9"}},
		"kubernetes.io/serviceaccount/namespace":"legacy","groups":["dev","ops"],"n":42,"ok":true}`)
	cases := []struct {
		claims map[string]any
		match  map[string]string
		want   bool
	}{
		{gh, map[string]string{"repository": "acme/app", "ref": "refs/heads/main"}, true},
		{gh, map[string]string{"repository": "acme/app", "ref": "refs/heads/dev"}, false},
		{gh, map[string]string{"repository": "acme/*", "environment": "prod"}, true},
		{gh, map[string]string{"job_workflow_ref": "acme/workflows/.github/workflows/deploy.yml@*"}, true},
		{gh, map[string]string{"repository": "acme/app", "missing": "*"}, false}, // a claim named must be there
		{k8s, map[string]string{"kubernetes.io/namespace": "payments", "kubernetes.io/serviceaccount/name": "api"}, true},
		{k8s, map[string]string{"kubernetes.io/serviceaccount/name": "web"}, false},
		{k8s, map[string]string{"sub": "system:serviceaccount:payments:*"}, true},
		// A top-level member of that exact name wins over the path.
		{k8s, map[string]string{"kubernetes.io/serviceaccount/namespace": "legacy"}, true},
		{k8s, map[string]string{"kubernetes.io": "*"}, false}, // an object has no value
		{k8s, map[string]string{"groups": "ops"}, true},
		{k8s, map[string]string{"groups": "admin"}, false},
		{k8s, map[string]string{"n": "42", "ok": "true"}, true},
	}
	for i, c := range cases {
		m := &OIDCMatch{Issuer: "x", Claims: c.match}
		if got := m.matchesClaims(c.claims); got != c.want {
			t.Errorf("case %d: %v matched %v, want %v", i, c.match, got, c.want)
		}
	}
}

func TestRolesAreChecked(t *testing.T) {
	issuers := map[string]*Issuer{"github": {Name: "github", URL: "https://token.actions.githubusercontent.com", Audiences: []string{aud}}}
	rules := []Rule{{Vault: "prod", Items: "app/*", Capabilities: []string{CapRead}}}
	cases := map[string]struct {
		role Role
		want string // "" for accepted
	}{
		"token":            {Role{Name: "app", Token: "deploy-bot", Rules: rules}, ""},
		"oidc":             {Role{Name: "ci", OIDC: &OIDCMatch{Issuer: "github", Claims: map[string]string{"repository": "acme/app"}}, Rules: rules, TTL: "30m"}, ""},
		"cert":             {Role{Name: "svc", Cert: &CertMatch{SAN: "spiffe://acme/app"}, Rules: rules}, ""},
		"no identity":      {Role{Name: "x", Rules: rules}, "exactly one identity"},
		"two identities":   {Role{Name: "x", Token: "a", Cert: &CertMatch{Fingerprint: strings.Repeat("ab", 32)}, Rules: rules}, "exactly one identity"},
		"no rules":         {Role{Name: "x", Token: "a"}, "no rules"},
		"bad capability":   {Role{Name: "x", Token: "a", Rules: []Rule{{Vault: "prod", Items: "*", Capabilities: []string{"write"}}}}, "not a capability"},
		"unknown issuer":   {Role{Name: "x", OIDC: &OIDCMatch{Issuer: "gitlab", Claims: map[string]string{"project_path": "a/b"}}, Rules: rules}, "no issuer"},
		"any repository":   {Role{Name: "x", OIDC: &OIDCMatch{Issuer: "github", Claims: map[string]string{"repository": "*"}}, Rules: rules}, "other than wildcards"},
		"no claims":        {Role{Name: "x", OIDC: &OIDCMatch{Issuer: "github"}, Rules: rules}, "other than wildcards"},
		"bad fingerprint":  {Role{Name: "x", Cert: &CertMatch{Fingerprint: "abc"}, Rules: rules}, "not a SHA-256"},
		"empty cert match": {Role{Name: "x", Cert: &CertMatch{}, Rules: rules}, "needs a subject"},
		"ttl for a token":  {Role{Name: "x", Token: "a", Rules: rules, TTL: "1h"}, "OIDC logins only"},
		"ttl too long":     {Role{Name: "x", OIDC: &OIDCMatch{Issuer: "github", Claims: map[string]string{"repository": "a/b"}}, Rules: rules, TTL: "48h"}, "between"},
		"bad name":         {Role{Name: "Prod Deploy", Token: "a", Rules: rules}, "not a role name"},
	}
	for name, c := range cases {
		err := c.role.check(issuers)
		switch {
		case c.want == "" && err != nil:
			t.Errorf("%s: refused: %v", name, err)
		case c.want != "" && (err == nil || !strings.Contains(err.Error(), c.want)):
			t.Errorf("%s: %v, want an error saying %q", name, err, c.want)
		}
	}
}

func TestRulesDenyByDefault(t *testing.T) {
	r := &Role{Name: "app", Token: "t", Rules: []Rule{
		{Vault: "prod", Items: "app/*", Capabilities: []string{CapRead}},
		{Vault: "prod", Items: "*", Capabilities: []string{CapList}},
	}}
	who := &caller{roles: []*Role{r}}
	for _, c := range []struct {
		vault, item, cap string
		want             bool
	}{
		{"prod", "app/db", CapRead, true},
		{"prod", "other/db", CapRead, false},
		{"prod", "other/db", CapList, true},
		{"staging", "app/db", CapRead, false},
		{"prod", "app/db", "write", false},
	} {
		if _, got := who.allowed(c.vault, c.item, c.cap); got != c.want {
			t.Errorf("%s %s/%s: %v, want %v", c.cap, c.vault, c.item, got, c.want)
		}
	}
	if (&caller{}).touches("prod", CapList) {
		t.Error("a caller without roles may list")
	}
}
