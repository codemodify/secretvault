package svmanager

import (
	"bufio"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Copies through the secretvault CLI, on Linux and the BSDs.
//
// There the manager copies as the CLI and the TUI do: the CLI beside this
// program, run as `secretvault __clip SECONDS` with the secret on its
// stdin, takes the clipboard in a process of its own (svclip, Wayland's
// data control or X11), serves it, and clears it when its time is up if
// it is still its own. Since v0.23.4 uitoolkit's secret clipboard does
// what was asked of it on Linux too (uitoolkit-gaps.md, 47, 48, 52 and
// 55), and going back to it was weighed; svclip is still the safer of the
// two there. The helper takes one clipboard and ends only its own copy,
// so none of what uitoolkit's two owners in one process can get wrong
// reaches it: a loss of the last copy handled as the next is made, which
// ends the new one while it is put on the clipboard with nothing left to
// clear it (57); a clear on its timer's goroutine against Wayland state
// the event loop changes unlocked (59); a Wayland copy that unsets the
// primary selection whoever holds it (58). And this program's heap holds
// no copy of the secret while it is on the clipboard.
// A copy taken back (its vault locked, the program quitting) is the
// helper ended: its selection goes with it, and only if it still has it.
//
// Where there is no CLI beside this program, or it cannot reach a
// clipboard, the copy goes to uitoolkit's. On the BSDs uitoolkit has no
// clipboard of its own, so there the helper is the only way. On Windows a
// helper ended leaves its copy on the clipboard, and macOS has no svclip
// yet: both copy through uitoolkit (clip_other.go), which since v0.23.4
// ends a copy another program has replaced there too (52); a Windows copy
// that fails is still taken for one that was made (60).

// helperMax is the most the helper reads (cmd/secretvault's clipHelper);
// a larger copy goes to the fallback, whole, rather than to a helper
// that stops reading and leaves the write waiting.
const helperMax = 1 << 20

// helperClipboard copies through the CLI at exe, and through fallback
// when that cannot.
type helperClipboard struct {
	exe      string
	fallback Clipboard
	wait     time.Duration // how long the helper has to say it has the clipboard
}

// SetSecret copies data through the helper, and wipes it once the helper
// has it; or hands it to the fallback, which takes it over.
func (h helperClipboard) SetSecret(data []byte, ttl time.Duration) Copied {
	if c, err := h.copy(data, ttl); err == nil {
		clear(data)
		return c
	}
	return h.fallback.SetSecret(data, ttl)
}

// copy starts the helper, hands it data, and waits for it to say it has
// the clipboard ("ok BACKEND") or why not ("error: ...").
func (h helperClipboard) copy(data []byte, ttl time.Duration) (*helperCopy, error) {
	if len(data) > helperMax {
		return nil, errors.New("too large for the clipboard helper")
	}
	secs := max(1, int(math.Ceil(ttl.Seconds())))
	cmd := exec.Command(h.exe, "__clip", strconv.Itoa(secs))
	in, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	_, werr := in.Write(data)
	in.Close()
	c := &helperCopy{proc: cmd.Process}
	said := make(chan string, 1)
	go func() {
		// Wait closes the pipe, so it comes after the reading.
		line, _ := bufio.NewReader(out).ReadString('\n')
		said <- strings.TrimSpace(line)
		io.Copy(io.Discard, out)
		cmd.Wait()
		c.gone()
	}()
	select {
	case s := <-said:
		if strings.HasPrefix(s, "ok ") && werr == nil {
			return c, nil
		}
		if werr != nil {
			// It did not take all of it: what it has is not the secret.
			s = werr.Error()
		}
		c.Clear()
		if s == "" {
			s = "the clipboard helper stopped"
		}
		return nil, errors.New(strings.TrimPrefix(s, "error: "))
	case <-time.After(h.wait):
		c.Clear()
		return nil, errors.New("the clipboard helper did not answer")
	}
}

// helperCopy is one copy a helper holds: it is gone when the helper has
// ended, at its timeout, when another copy took the clipboard, or when it
// was ended.
type helperCopy struct {
	proc      *os.Process
	mu        sync.Mutex
	ended     bool
	onCleared func()
}

// Clear ends the helper, which takes its copy off the clipboard if the
// clipboard still holds it; anything copied since is left alone.
func (c *helperCopy) Clear() {
	c.mu.Lock()
	ended := c.ended
	c.mu.Unlock()
	if !ended {
		c.proc.Kill()
	}
}

// OnCleared runs fn once the helper has ended, on whatever goroutine saw
// it end; at once if it has.
func (c *helperCopy) OnCleared(fn func()) {
	c.mu.Lock()
	if c.ended {
		c.mu.Unlock()
		if fn != nil {
			fn()
		}
		return
	}
	c.onCleared = fn
	c.mu.Unlock()
}

func (c *helperCopy) gone() {
	c.mu.Lock()
	c.ended = true
	fn := c.onCleared
	c.onCleared = nil
	c.mu.Unlock()
	if fn != nil {
		fn()
	}
}
