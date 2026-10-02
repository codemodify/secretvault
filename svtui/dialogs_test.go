package svtui

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"
)

// A dialog that comes while another is up waits for it, and is never
// shown over a passphrase being typed; what either holds is wiped
// however it goes.
func TestADialogWaitsForTheOneUp(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.waitFor("Locked: Enter unlocks")
	h.typeText("N")
	h.waitFor("New vault")
	h.tabs(3)
	h.typeText("half typed")
	var typed []byte
	h.eventually("the passphrase typed", func() bool {
		if s, ok := h.u.app.GetFocus().(*secretInput); ok && len(s.buf) == len("half typed") {
			typed = s.buf
			return true
		}
		return false
	})
	planned, cancelled := false, false
	h.u.post(func() {
		h.u.showPlan("A later plan", "something to do", "Do it", func() { planned = true }, func() { cancelled = true })
	})
	time.Sleep(100 * time.Millisecond)
	if s := h.text(); !strings.Contains(s, "New vault") || strings.Contains(s, "A later plan") {
		t.Fatalf("the plan did not wait:\n%s", s)
	}
	h.key(tcell.KeyEscape)
	h.waitFor("A later plan")
	if !bytes.Equal(typed, make([]byte, len(typed))) {
		t.Fatalf("the passphrase typed is still held: %q", typed)
	}
	h.key(tcell.KeyEscape)
	h.waitGone("A later plan")
	h.eventually("the plan cancelled", func() bool { return cancelled && !planned })

	// A worker's question that is given up on goes, even while it waits.
	h.typeText("N")
	h.waitFor("New vault")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := h.u.askFromWorker(ctx, "A worker asks", "", "Answer", true)
		done <- err
	}()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a question given up on was answered")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the worker still waits")
	}
	h.key(tcell.KeyEscape)
	h.waitGone("New vault")
	time.Sleep(100 * time.Millisecond)
	if strings.Contains(h.text(), "A worker asks") {
		t.Fatalf("a question given up on was shown:\n%s", h.text())
	}
}

// Something shown once is never replaced unseen by what comes next.
func TestOnceViewsWaitTheirTurn(t *testing.T) {
	h := newHarness(t)
	h.start(Options{}, "")
	h.waitFor("Locked: Enter unlocks")
	first, second := []byte("FIRST-SECRET-123"), []byte("SECOND-SECRET-456")
	h.u.post(func() {
		h.u.showOnce("The first", []onceLine{{secret: first}}, nil)
		h.u.showOnce("The second", []onceLine{{secret: second}}, nil)
	})
	h.waitFor("FIRST-SECRET-123")
	if strings.Contains(h.text(), "SECOND-SECRET") {
		t.Fatal("the second replaced the first")
	}
	h.key(tcell.KeyEscape)
	h.waitFor("This is not shown again")
	h.typeText("y")
	h.waitFor("SECOND-SECRET-456")
	if !bytes.Equal(first, make([]byte, len(first))) {
		t.Fatal("the first is still held")
	}
	h.closeOnce()
	if !bytes.Equal(second, make([]byte, len(second))) {
		t.Fatal("the second is still held")
	}
}
