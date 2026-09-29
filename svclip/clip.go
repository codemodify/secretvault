// Package svclip puts a secret on the clipboard for a while, then takes
// it back: the clipboard is cleared when the time is up, unless something
// else has been copied since. Clipboard managers are told the contents are
// a secret (x-kde-passwordManagerHint on Linux; the exclusion formats on
// Windows), so they do not keep it in their history.
//
// The clipboard is served by whoever set it, so Copy blocks for as long as
// the secret stays copied; the CLI runs it in a detached process of its
// own.
package svclip

import (
	"errors"
	"time"
)

// DefaultTTL is how long a copied secret stays on the clipboard.
const DefaultTTL = 30 * time.Second

// ErrUnavailable is a session with no clipboard secretvault can reach.
var ErrUnavailable = errors.New("svclip: no clipboard secretvault can use in this session")

// Copy puts secret on the clipboard, serves pastes, and clears it after
// ttl if it is still ours. It returns whether it cleared. ready, if not
// nil, is called with the backend's name ("wayland", "x11", "windows") as
// soon as the secret is on the clipboard. The caller wipes secret
// afterwards.
func Copy(secret []byte, ttl time.Duration, ready func(backend string)) (cleared bool, err error) {
	if ready == nil {
		ready = func(string) {}
	}
	return copyText(secret, ttl, ready)
}

// Paste returns the clipboard's text (nil when empty).
func Paste() ([]byte, error) { return pasteText() }
