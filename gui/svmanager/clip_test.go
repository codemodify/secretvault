package svmanager

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// fakeClipHelper is this test binary run as the CLI's clipboard helper
// (secretvault __clip SECONDS, the secret on stdin): it takes no
// clipboard. It writes what it was given and how it was asked to
// SVMANAGER_FAKE_CLIP_OUT, then, as how says: "ok" says it has the
// clipboard and holds it for SECONDS or until it is ended; "fail" says it
// cannot; "mute" says nothing.
func fakeClipHelper(how string) int {
	secret, _ := io.ReadAll(os.Stdin)
	os.WriteFile(os.Getenv("SVMANAGER_FAKE_CLIP_OUT"), []byte(string(secret)+" "+strings.Join(os.Args[1:], " ")), 0o600)
	switch how {
	case "ok":
		fmt.Println("ok fake")
		os.Stdout.Close()
		secs := 30
		if len(os.Args) > 2 {
			secs, _ = strconv.Atoi(os.Args[2])
		}
		time.Sleep(time.Duration(secs) * time.Second)
	case "fail":
		fmt.Println("error: no clipboard here")
		return 1
	case "mute":
		time.Sleep(10 * time.Second)
	}
	return 0
}

// On Linux a copy goes through the CLI beside the manager, as the CLI and
// the TUI copy (uitoolkit-gaps.md, 47 and 48): the helper is given the
// secret and the time, the manager's copy is wiped once it has it, and
// ending the helper takes the copy back, which is said. A helper that
// cannot copy, or does not answer, leaves the copy to uitoolkit's
// clipboard. Headless: the helper here is this test binary, and takes no
// clipboard.
func TestCopiesGoThroughTheCLI(t *testing.T) {
	out := filepath.Join(t.TempDir(), "got")
	t.Setenv("SVMANAGER_FAKE_CLIP_OUT", out)
	t.Setenv("SVMANAGER_FAKE_CLIP", "ok")
	fallback := &fakeClipboard{}
	clip := helperClipboard{exe: os.Args[0], fallback: fallback, wait: 10 * time.Second}

	data := []byte("hunter2-github")
	c := clip.SetSecret(data, 30*time.Second)
	if got, _ := os.ReadFile(out); string(got) != "hunter2-github __clip 30" {
		t.Fatalf("the helper was given %q", got)
	}
	if !allZero(data) || fallback.count() != 0 {
		t.Fatal("the manager kept its copy, or the copy went to uitoolkit's clipboard as well")
	}
	gone := make(chan struct{})
	c.OnCleared(func() { close(gone) })
	c.Clear()
	select {
	case <-gone:
	case <-time.After(10 * time.Second):
		t.Fatal("ending the helper was not heard of")
	}

	// It goes by itself at its time.
	c = clip.SetSecret([]byte("short-lived"), time.Second)
	gone = make(chan struct{})
	c.OnCleared(func() { close(gone) })
	select {
	case <-gone:
	case <-time.After(10 * time.Second):
		t.Fatal("a helper at its time was not heard of")
	}

	// More than the helper reads goes to uitoolkit's whole, the helper not
	// started (it would stop reading, and the write would wait).
	os.Remove(out)
	big := make([]byte, helperMax+1)
	clip.SetSecret(big, 30*time.Second)
	if last := fallback.last(); last == nil || len(last.data) != len(big) {
		t.Fatal("a copy larger than the helper reads did not go to uitoolkit's clipboard")
	}
	if _, err := os.Stat(out); err == nil {
		t.Fatal("a helper was started for a copy larger than it reads")
	}

	for _, how := range []string{"fail", "mute"} {
		t.Setenv("SVMANAGER_FAKE_CLIP", how)
		clip.wait = 500 * time.Millisecond
		data := []byte("to-" + how)
		clip.SetSecret(data, 30*time.Second)
		if last := fallback.last(); last == nil || last.text != "to-"+how || &last.data[0] != &data[0] {
			t.Fatalf("a helper that does %s: the copy did not go to uitoolkit's clipboard", how)
		}
	}
}
