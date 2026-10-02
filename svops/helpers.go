package svops

import (
	"net/url"
	"path/filepath"
	"strings"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// The credential helpers other programs run: git's and docker's, which
// keep their logins as items under git/ and docker/. An interface lists
// and edits those items like any others; these say which item a helper
// reads.

// Helpers are the names the CLI answers to when linked under them, and
// the command each stands for. They are links to the secretvault program
// (scripts/install.sh makes them), so the daemon still knows the program
// for secretvault's own.
var Helpers = map[string]string{
	"git-credential-secretvault":    "git-credential",
	"docker-credential-secretvault": "docker-credential",
	"age-plugin-secretvault":        "age-plugin",
	"secretvault-browser":           "browser-host",
}

// HelperName is the command a program name stands for ("" when none).
func HelperName(argv0 string) string {
	return Helpers[strings.TrimSuffix(filepath.Base(argv0), ".exe")]
}

// GitCredentialFields are the request's fields that pick a login.
var GitCredentialFields = []string{"protocol", "host", "path", "username"}

// GitItemName is the item git's helper stores a login as.
func GitItemName(kv map[string]string) string {
	name := "git/" + PathSafe(kv["host"])
	if kv["path"] != "" {
		name += "/" + PathSafe(kv["path"])
	}
	if kv["username"] != "" {
		name += "/" + PathSafe(kv["username"])
	}
	return name
}

// GitMatches reports whether an item stored by git's helper answers a
// request.
func GitMatches(it *svrpc.Item, kv map[string]string) bool {
	for _, k := range GitCredentialFields {
		if kv[k] != "" && it.Attrs["git_"+k] != kv[k] {
			return false
		}
	}
	return it.Attrs["git_host"] != ""
}

// GitItem is the item git's helper stores for a request with a password.
func GitItem(kv map[string]string) svrpc.Item {
	attrs := map[string]string{}
	for _, k := range GitCredentialFields {
		if kv[k] != "" {
			attrs["git_"+k] = kv[k]
		}
	}
	return svrpc.Item{Kind: "login", Name: GitItemName(kv), Label: kv["host"], Attrs: attrs, Fields: []svrpc.Field{
		{Name: "username", Type: svcore.FieldText, Value: []byte(kv["username"])},
		{Name: "password", Type: svcore.FieldConcealed, Value: []byte(kv["password"])},
		{Name: "url", Type: svcore.FieldURL, Value: []byte(kv["protocol"] + "://" + kv["host"])},
	}}
}

// DockerItemName is the item docker's helper keeps a registry's login as.
func DockerItemName(server string) string {
	u := server
	if p, err := url.Parse(server); err == nil && p.Host != "" {
		u = p.Host + p.Path
	}
	return "docker/" + PathSafe(u)
}

// DockerItem is the item docker's helper stores for a registry.
func DockerItem(server, username, secret string) svrpc.Item {
	return svrpc.Item{Kind: "login", Name: DockerItemName(server), Label: server,
		Attrs: map[string]string{"docker_server": server}, Fields: []svrpc.Field{
			{Name: "username", Type: svcore.FieldText, Value: []byte(username)},
			{Name: "password", Type: svcore.FieldConcealed, Value: []byte(secret)},
			{Name: "url", Type: svcore.FieldURL, Value: []byte(server)},
		}}
}
