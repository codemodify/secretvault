// Command secretvault-gui-prompt is secretvaultd's desktop prompt: it
// speaks the pinentry protocol (docs/architecture.md, "Prompts") and asks
// for passphrases and consent in a dialog window made with uitoolkit.
package main

import (
	"fmt"
	"os"

	"github.com/codemodify/uitoolkit"
)

func main() {
	_ = uitoolkit.Options{}
	fmt.Fprintln(os.Stderr, "secretvault-gui-prompt: not implemented yet")
	os.Exit(1)
}
