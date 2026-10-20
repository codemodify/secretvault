package svops

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
)

// The desktop manager's look is kept in gui.json, in the settings folder,
// readable by its owner alone; missing or not one of the choices, it is
// the default, following the desktop.
func TestTheDesktopManagersLookIsKept(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(svcore.EnvConfig, dir)
	if got := LoadGUIPrefs().Look; got != LookDesktop {
		t.Fatalf("with no file: %q", got)
	}
	if err := SaveGUIPrefs(GUIPrefs{Look: LookDark}); err != nil {
		t.Fatal(err)
	}
	if got := LoadGUIPrefs().Look; got != LookDark {
		t.Fatalf("saved dark, read %q", got)
	}
	st, err := os.Stat(filepath.Join(dir, GUIFile))
	if err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("gui.json: %v, %v", st, err)
	}
	os.WriteFile(filepath.Join(dir, GUIFile), []byte(`{"look": "purple"}`), 0o600)
	if got := LoadGUIPrefs().Look; got != LookDesktop {
		t.Fatalf("an unknown look reads as %q", got)
	}
	found := false
	for _, p := range Where(WhereOptions{Config: dir, Data: t.TempDir()}) {
		found = found || p.Path == filepath.Join(dir, GUIFile) && strings.Contains(p.What, "desktop manager looks")
	}
	if !found {
		t.Fatal("where things are kept does not list gui.json")
	}
}
