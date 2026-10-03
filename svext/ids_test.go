package svext

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"regexp"
	"testing"

	"github.com/codemodify/secretvault/browser"
)

// The names are in two places, the Go constants and the extension's
// files: they must say the same.
func TestTheExtensionAndItsHostAgreeOnTheirNames(t *testing.T) {
	b, err := fs.ReadFile(browser.Extension(), "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var m struct {
		Key      string `json:"key"`
		Settings struct {
			Gecko struct {
				ID string `json:"id"`
			} `json:"gecko"`
		} `json:"browser_specific_settings"`
	}
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	if m.Settings.Gecko.ID != FirefoxID {
		t.Errorf("manifest.json's gecko id is %q, svext.FirefoxID %q", m.Settings.Gecko.ID, FirefoxID)
	}
	// Chromium names an extension by its key: the first 16 bytes of the
	// key's SHA-256, each hex digit as a letter from a to p.
	der, err := base64.StdEncoding.DecodeString(m.Key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		t.Fatalf("manifest.json's key: %v", err)
	}
	sum := sha256.Sum256(der)
	id := []byte(hex.EncodeToString(sum[:16]))
	for i, c := range id {
		if c >= 'a' {
			id[i] = c - 'a' + 'k'
		} else {
			id[i] = c - '0' + 'a'
		}
	}
	if string(id) != ChromeID {
		t.Errorf("manifest.json's key makes the ID %s, svext.ChromeID is %s", id, ChromeID)
	}
	// The extension's protocol module names the host.
	js, _ := fs.ReadFile(browser.Extension(), "lib/protocol.js")
	if !regexp.MustCompile(`const HOST = "` + regexp.QuoteMeta(HostName) + `"`).Match(js) {
		t.Errorf("lib/protocol.js does not name the host %s", HostName)
	}
	if !Ours(FirefoxID) || !Ours(ChromeOrigin) || Ours("keepassxc-browser@keepassxc.org") || Ours("chrome-extension://"+ChromeID) {
		t.Error("Ours")
	}
}
