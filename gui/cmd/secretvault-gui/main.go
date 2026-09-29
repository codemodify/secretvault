// Command secretvault-gui is the desktop password manager, built on
// github.com/codemodify/uitoolkit: vaults, items, search, generator,
// history and conflict resolution, settings, and a tray icon to lock,
// unlock and search from anywhere. It talks to secretvaultd and holds no
// keys itself.
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "secretvault-gui: not implemented yet (see docs/roadmap.md, track T4)")
	os.Exit(1)
}
