package browser

import (
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The extension's pure modules (origin matching, the protocol's messages,
// what form fields are for) are tested under node --test, with no
// packages of npm's: this runs them when node is here, and says so when
// it is not.
func TestTheExtensionsModulesPassTheirTestsUnderNode(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node is not installed: the extension's own tests (browser/test) did not run")
	}
	v, err := exec.Command(node, "--version").Output()
	if err != nil {
		t.Skipf("node --version: %v", err)
	}
	major, _ := strconv.Atoi(strings.SplitN(strings.TrimPrefix(strings.TrimSpace(string(v)), "v"), ".", 2)[0])
	if major < 20 {
		t.Skipf("node %s is older than 20, which the tests need", strings.TrimSpace(string(v)))
	}
	files, err := filepath.Glob(filepath.Join("test", "*.test.mjs"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no tests in browser/test (%v)", err)
	}
	cmd := exec.Command(node, append([]string{"--test", "--test-reporter=spec"}, files...)...)
	home := t.TempDir()
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + home, "XDG_CONFIG_HOME=" + home, "NO_COLOR=1"}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("node --test: %v\n%s", err, out)
	}
	t.Logf("node %s:\n%s", strings.TrimSpace(string(v)), out)
}

func TestTheExtensionIsEmbeddedWhole(t *testing.T) {
	ext := Extension()
	for _, f := range []string{"manifest.json", "background.js", "content.js", "panel.html", "panel.js", "panel.css",
		"lib/psl.js", "lib/origin.js", "lib/protocol.js", "lib/forms.js", "lib/style.js", "lib/webauthn.js", PSLPath, "icons/128.png",
		"passkey-page.js", "passkey-bridge.js", "passkey.html", "passkey.js", "passkey.css"} {
		if _, err := fs.Stat(ext, f); err != nil {
			t.Errorf("%s is not embedded: %v", f, err)
		}
	}
	// Nothing but the extension: its tests stay out of the package.
	fs.WalkDir(ext, ".", func(p string, d fs.DirEntry, err error) error {
		if strings.HasSuffix(p, ".mjs") || strings.HasSuffix(p, ".json") && p != "manifest.json" || strings.HasSuffix(p, ".go") || strings.HasPrefix(d.Name(), ".") && p != "." {
			t.Errorf("%s is in the extension", p)
		}
		return nil
	})
	if psl := PSL(); !strings.Contains(string(psl), "===END PRIVATE DOMAINS===") {
		t.Error("the Public Suffix List is cut short")
	}
}
