//go:build linux || freebsd || netbsd || openbsd

package svmanager

import (
	"time"

	"github.com/codemodify/secretvault/svops"
)

// systemClipboard is where the manager's copies go: through the CLI
// beside this program where there is one (clip.go), else through
// uitoolkit.
func systemClipboard() Clipboard {
	if exe := svops.CLIProgram(); exe != "" {
		return helperClipboard{exe: exe, fallback: desktopClipboard{}, wait: 3 * time.Second}
	}
	return desktopClipboard{}
}
