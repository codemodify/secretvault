// Command secretvault-tui-prompt asks a person for a secret or a decision
// on a terminal, on behalf of secretvaultd.
//
// It speaks the pinentry protocol (Assuan) on stdin and stdout, so it is at
// once secretvaultd's terminal prompter and a drop-in pinentry-curses for
// gpg-agent. Run with --askpass PROMPT it behaves as an SSH_ASKPASS /
// SUDO_ASKPASS / GIT_ASKPASS helper. Run with --agent in a terminal, it
// registers with secretvaultd as the session's prompter, like pkttyagent
// does for polkit, for sessions with no graphical display.
//
// A stub in milestone 0; see docs/architecture.md, "Prompts".
package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "secretvault-tui-prompt: not implemented yet (see docs/architecture.md, Prompts)")
	os.Exit(1)
}
