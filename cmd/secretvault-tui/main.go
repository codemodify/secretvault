// Command secretvault-tui is the terminal password manager: browse and
// search vaults, view, edit and generate items, copy with auto-clear, and
// resolve sync conflicts, in a full-screen terminal interface. It talks to
// secretvaultd like every other client and holds no keys itself.
//
// A stub in milestone 0; see docs/roadmap.md (track T4).
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "secretvault-tui: not implemented yet (see docs/roadmap.md, track T4)")
	os.Exit(1)
}
