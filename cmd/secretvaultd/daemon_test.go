package main

import (
	"os/exec"
	"strings"
	"testing"
)

// The daemon holds unlocked keys for hours; it must not carry a GUI
// toolkit's attack surface (or its cgo) along with them. Interfaces run as
// separate processes and talk to it over the socket.
func TestTheDaemonLinksNoUserInterface(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", ".").Output()
	if err != nil {
		t.Skipf("go list: %v", err)
	}
	for _, dep := range strings.Fields(string(out)) {
		for _, banned := range []string{"github.com/codemodify/uitoolkit", "github.com/codemodify/paintengine2d", "golang.org/x/term",
			"github.com/rivo/tview", "github.com/gdamore/tcell"} {
			if strings.HasPrefix(dep, banned) {
				t.Errorf("secretvaultd depends on %s", dep)
			}
		}
	}
}
