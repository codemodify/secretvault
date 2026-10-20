package svimport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svrpc"
)

func passkeyItem(t *testing.T, name string, alg int) (svrpc.Item, *svext.KeyPair) {
	t.Helper()
	kp, err := svext.NewKeyPair(alg)
	if err != nil {
		t.Fatal(err)
	}
	r := &svext.PasskeyRecord{RPID: "github.com", UserName: "ada", DisplayName: "Ada L.", CredentialID: []byte("cred-0123456789ab"),
		UserHandle: []byte("handle-1"), Alg: alg, PrivateKey: kp.Private, Created: time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)}
	it := svrpc.Item{Kind: svext.PasskeyKind, Name: name, Label: "GitHub", Tags: []string{"work"}}
	for _, f := range r.Fields() {
		it.Fields = append(it.Fields, svrpc.Field{Name: f.Name, Type: f.Type, Value: f.Value})
	}
	return it, kp
}

func field(it svrpc.Item, n string) ([]byte, bool) {
	for _, f := range it.Fields {
		if f.Name == n {
			return f.Value, true
		}
	}
	return nil, false
}

// A passkey goes out as CXF's passkey credential, its key as PKCS #8 DER
// in base64url, and comes back the same passkey.
func TestPasskeysRoundTripThroughCXF(t *testing.T) {
	es, kp := passkeyItem(t, "passkeys/github.com", svext.AlgES256)
	ed, _ := passkeyItem(t, "passkeys/github.com (2)", svext.AlgEdDSA)
	var buf bytes.Buffer
	if err := ExportCXF([]svrpc.Item{es, ed}, &buf); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Accounts []struct {
			Items []struct {
				CreationAt  int64            `json:"creationAt"`
				Credentials []map[string]any `json:"credentials"`
				Scope       struct {
					URLs []string `json:"urls"`
				} `json:"scope"`
			} `json:"items"`
		} `json:"accounts"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	item := doc.Accounts[0].Items[0]
	if len(item.Credentials) != 1 {
		t.Fatalf("the credentials: %v", item.Credentials)
	}
	c := item.Credentials[0]
	if c["type"] != "passkey" || c["rpId"] != "github.com" || c["username"] != "ada" || c["userDisplayName"] != "Ada L." ||
		c["credentialId"] != svext.B64.EncodeToString([]byte("cred-0123456789ab")) || c["userHandle"] != svext.B64.EncodeToString([]byte("handle-1")) ||
		c["key"] != svext.B64.EncodeToString(kp.Private) {
		t.Errorf("the passkey credential: %v", c)
	}
	if item.CreationAt != time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC).Unix() || len(item.Scope.URLs) != 1 || item.Scope.URLs[0] != "https://github.com" {
		t.Errorf("creationAt %d, scope %v", item.CreationAt, item.Scope.URLs)
	}

	res := mustImport(t, FormatCXF, buf.Bytes(), Options{})
	if len(res.Warnings) != 0 || len(res.Items) != 2 {
		t.Fatalf("%d items, warnings %q", len(res.Items), res.Warnings)
	}
	for i, want := range []svrpc.Item{es, ed} {
		got := res.Items[i]
		if got.Kind != svext.PasskeyKind || got.Name != want.Name || strings.Join(got.Tags, ",") != "work" {
			t.Errorf("%s came back as %s %q %q %v", want.Name, got.Kind, got.Name, got.Label, got.Tags)
		}
		w, err := svext.ReadPasskey(func(n string) ([]byte, bool) { return field(want, n) }, true)
		if err != nil {
			t.Fatal(err)
		}
		g, err := svext.ReadPasskey(func(n string) ([]byte, bool) { return field(got, n) }, true)
		if err != nil {
			t.Fatalf("%s: %v", got.Name, err)
		}
		if g.RPID != w.RPID || g.UserName != w.UserName || g.DisplayName != w.DisplayName || !bytes.Equal(g.CredentialID, w.CredentialID) ||
			!bytes.Equal(g.UserHandle, w.UserHandle) || !bytes.Equal(g.PrivateKey, w.PrivateKey) || g.Alg != w.Alg || !g.Created.Equal(w.Created) {
			t.Errorf("%s came back as %+v", want.Name, g)
		}
	}
}

// A passkey from another manager: an item with a login and a passkey
// becomes a login and a passkey; a key secretvault cannot sign with is
// left behind, said so.
func TestPasskeysComeFromAnotherManagersCXF(t *testing.T) {
	seed, _ := hex.DecodeString("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
	der, _ := x509.MarshalPKCS8PrivateKey(ed25519.NewKeyFromSeed(seed))
	doc := `{"version":{"major":1,"minor":0},"exporterRpId":"other.example","exporterDisplayName":"Other","timestamp":1,
	"accounts":[{"id":"a","username":"","email":"","collections":[],"items":[
	  {"id":"i1","title":"Example","creationAt":1767225600,"scope":{"urls":["https://example.com/login"],"androidApps":[]},"credentials":[
	    {"type":"basic-auth","username":{"fieldType":"string","value":"ada"},"password":{"fieldType":"concealed-string","value":"hunter2"}},
	    {"type":"passkey","credentialId":"` + svext.B64.EncodeToString([]byte("c1")) + `","rpId":"example.com","username":"ada","userDisplayName":"Ada",
	     "userHandle":"` + svext.B64.EncodeToString([]byte("u1")) + `","key":"` + svext.B64.EncodeToString(der) + `"}]},
	  {"id":"i2","title":"Broken","credentials":[
	    {"type":"passkey","credentialId":"YWJj","rpId":"broken.example","username":"x","userDisplayName":"","userHandle":"eA","key":"bm90LWEta2V5"}]}
	]}]}`
	res := mustImport(t, FormatCXF, []byte(doc), Options{})
	byName := map[string]svrpc.Item{}
	for _, it := range res.Items {
		byName[it.Name] = it
	}
	login, pk := byName["Example"], byName["Example passkey"]
	if login.Kind != "login" || pk.Kind != svext.PasskeyKind {
		t.Fatalf("items: %v", res.Items)
	}
	r, err := svext.ReadPasskey(func(n string) ([]byte, bool) { return field(pk, n) }, true)
	if err != nil || r.RPID != "example.com" || r.Alg != svext.AlgEdDSA || string(r.CredentialID) != "c1" || string(r.UserHandle) != "u1" || r.Created.Unix() != 1767225600 {
		t.Errorf("the passkey: %+v %v", r, err)
	}
	if _, ok := byName["Broken"]; ok || len(res.Warnings) != 1 || !strings.Contains(res.Warnings[0], "passkey whose key secretvault cannot use") {
		t.Errorf("the broken one: %v; warnings %q", byName["Broken"], res.Warnings)
	}
}
