package svdeliver

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
)

// A passkey's key signs inside secretvault for the browser extension: a
// delivery gives its site and account, never its key.
func TestAPasskeysKeyIsNotDelivered(t *testing.T) {
	f := newFixture(t)
	if _, err := f.vault.Put(svcore.Item{Kind: svcore.KindPasskey, Name: "prod/passkeys/example.com", Fields: []svcore.Field{
		{Name: "rp_id", Type: svcore.FieldText, Value: []byte("example.com")},
		{Name: "private_key", Type: svcore.FieldKey, Value: []byte("MIGHAgEAMBMGsecretkey")},
	}}); err != nil {
		t.Fatal(err)
	}
	admin := f.unsealed()
	tok := f.token(admin, "app", TokenRequest{CIDRs: []string{"127.0.0.0/8", "::1/128"}})
	f.role(admin, Role{Name: "app", Token: "app", Rules: []Rule{{Vault: "main", Items: "prod/*", Capabilities: []string{CapRead}}}})

	code, body := f.get("/v1/deliver/secret/main/prod/passkeys/example.com", tok)
	var s Secret
	if code != http.StatusOK || json.Unmarshal([]byte(body), &s) != nil || s.Fields["rp_id"] != "example.com" || s.SecretField != "" {
		t.Fatalf("%d %s", code, body)
	}
	for _, path := range []string{"", "?field=private_key", "?field=private_key&raw=true", "?raw"} {
		if code, body := f.get("/v1/deliver/secret/main/prod/passkeys/example.com"+path, tok); strings.Contains(body, "secretkey") {
			t.Errorf("%s: the key was delivered: %d %s", path, code, body)
		}
	}
}
