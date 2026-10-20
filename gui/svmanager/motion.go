package svmanager

import (
	"os"
	"time"

	"github.com/codemodify/uitoolkit/style"
)

// How the window moves: the turn to Settings (flip.go), the vault's door
// (lockface.go) and the notes that fade (notes.go) go by one clock, which
// a test can set.

// flipFrame is the time between two frames of a movement.
const flipFrame = 16 * time.Millisecond

// motion is how the window moves: animated at all (not offscreen, unless
// a test asks, and not where UITK_ANIMATIONS=0), and quickly, a fade
// rather than a movement, where the toolkit animates nothing.
func (m *Manager) motion() (animate, quick bool) {
	if m.opts.Headless && !m.flipAnyway || os.Getenv(style.AnimationsEnv) == "0" {
		return false, false
	}
	return true, !style.Animations()
}

// flipNow is the time, for a movement (a test's clock in tests).
func (m *Manager) flipNow() time.Time {
	if m.clock != nil {
		return m.clock()
	}
	return time.Now()
}
