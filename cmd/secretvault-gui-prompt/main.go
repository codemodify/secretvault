// Command secretvault-gui-prompt is the graphical counterpart of
// secretvault-tui-prompt: a small, focused uitoolkit window that asks for a
// passphrase or approval on behalf of secretvaultd (unlock this vault; may
// this program read this item; confirm this SSH signature).
//
// Like the terminal prompt it speaks the pinentry (Assuan) protocol, so it
// doubles as a pinentry for gpg-agent and as an askpass helper.
//
// A stub until uitoolkit gains what uitoolkit-gaps.md lists (items 1-6);
// until then secretvaultd asks through the desktop's own pinentry. See
// docs/architecture.md, "Prompts".
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "secretvault-gui-prompt: not implemented yet (see docs/architecture.md, Prompts)")
	os.Exit(1)
}
