// Command secretvault-gui is the desktop password manager, built on
// github.com/codemodify/uitoolkit: vaults, items, search, generator,
// history and conflict resolution, settings, and a tray icon to lock,
// unlock and search from anywhere. It talks to secretvaultd and holds no
// keys itself.
//
// A stub in milestone 0: it does not import uitoolkit yet, so the whole
// tree still builds with CGO_ENABLED=0. See docs/roadmap.md (track T4) and
// uitoolkit-gaps.md for what the toolkit needs first.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "secretvault-gui: not implemented yet (see docs/roadmap.md, track T4)")
	os.Exit(1)
}
