package svops

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"io"
	"io/fs"
	"testing"

	"github.com/codemodify/secretvault/browser"
)

// Each family of browsers gets the source manifest without what only the
// other reads, and nothing else changed.
func TestEachTargetsManifestIsTheSourcesWithoutTheOtherFamilysKeys(t *testing.T) {
	src, err := fs.ReadFile(browser.Extension(), "manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	var want map[string]any
	if err := json.Unmarshal(src, &want); err != nil {
		t.Fatal(err)
	}
	for _, target := range ExtensionTargets {
		b, err := ExtensionManifest(target)
		if err != nil {
			t.Fatal(err)
		}
		var got map[string]any
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatalf("%s: %v\n%s", target, err, b)
		}
		bg := got["background"].(map[string]any)
		war := got["web_accessible_resources"].([]any)[0].(map[string]any)
		switch target {
		case TargetFirefox:
			if _, ok := got["key"]; ok {
				t.Error("firefox: the Chromium key is there")
			}
			if _, ok := got["minimum_chrome_version"]; ok {
				t.Error("firefox: minimum_chrome_version is there")
			}
			if _, ok := bg["service_worker"]; ok || bg["scripts"] == nil {
				t.Errorf("firefox: background %v", bg)
			}
			if _, ok := war["use_dynamic_url"]; ok {
				t.Error("firefox: use_dynamic_url is there")
			}
			if got["browser_specific_settings"] == nil {
				t.Error("firefox: no gecko ID")
			}
		case TargetChromium:
			if _, ok := got["browser_specific_settings"]; ok {
				t.Error("chromium: browser_specific_settings is there")
			}
			if _, ok := bg["scripts"]; ok || bg["service_worker"] != "background.js" {
				t.Errorf("chromium: background %v", bg)
			}
			if war["use_dynamic_url"] != true || got["key"] != want["key"] {
				t.Errorf("chromium: %v, key %v", war, got["key"])
			}
		}
		// Nothing else differs.
		for k, v := range want {
			if k == "background" || k == "web_accessible_resources" || k == "key" || k == "minimum_chrome_version" || k == "browser_specific_settings" {
				continue
			}
			a, _ := json.Marshal(v)
			c, _ := json.Marshal(got[k])
			if !bytes.Equal(a, c) {
				t.Errorf("%s: %s is %s, not %s", target, k, c, a)
			}
		}
		// The package carries this manifest, first; Chromium's zip is the
		// Chrome Web Store's, which takes no key.
		if target == TargetChromium {
			if b, err = ExtensionStoreManifest(); err != nil {
				t.Fatal(err)
			}
			var store map[string]any
			json.Unmarshal(b, &store)
			if _, ok := store["key"]; ok || store["background"] == nil || store["browser_specific_settings"] != nil {
				t.Errorf("the store's manifest:\n%s", b)
			}
		}
		var buf bytes.Buffer
		if err := PackExtension(&buf, target); err != nil {
			t.Fatal(err)
		}
		z, err := zip.NewReader(bytes.NewReader(buf.Bytes()), int64(buf.Len()))
		if err != nil {
			t.Fatal(err)
		}
		f, _ := z.File[0].Open()
		packed, _ := io.ReadAll(f)
		if z.File[0].Name != "manifest.json" || !bytes.Equal(packed, b) {
			t.Errorf("%s: the package's first file is %s:\n%s", target, z.File[0].Name, packed)
		}
	}
	if _, err := ParseExtensionTarget("brave"); err != nil {
		t.Error(err)
	}
	if _, err := ParseExtensionTarget("safari"); err == nil {
		t.Error("safari is a target")
	}
}
