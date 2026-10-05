// Package ptytest gives tests a terminal of their own: a pseudo-terminal
// whose far side the test reads and types into, so what asks on a
// terminal (svterm, secretvault-tui-prompt) is tested as it runs, without
// the person's terminal. It works on Linux; elsewhere, tests that need
// one are skipped.
package ptytest

import (
	"bytes"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// PTY is a pseudo-terminal: Path is the terminal to open, as a program
// asking on it would, and the test reads what is written to it (Wait)
// and types into it (Type).
type PTY struct {
	Path   string
	master *os.File

	mu   sync.Mutex
	out  bytes.Buffer
	read chan struct{}
}

// Open makes a pseudo-terminal, closed when the test ends.
func Open(t testing.TB) *PTY {
	t.Helper()
	master, path, err := open()
	if err != nil {
		t.Skipf("no pseudo-terminal here: %v", err)
	}
	p := &PTY{Path: path, master: master, read: make(chan struct{}, 1)}
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := master.Read(buf)
			p.mu.Lock()
			p.out.Write(buf[:n])
			p.mu.Unlock()
			select {
			case p.read <- struct{}{}:
			default:
			}
			if err != nil {
				return
			}
		}
	}()
	t.Cleanup(func() { master.Close() })
	return p
}

// Output is everything written to the terminal so far.
func (p *PTY) Output() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.out.String()
}

// Wait waits until the terminal has been written want, and fails the
// test if it is not within ten seconds.
func (p *PTY) Wait(t testing.TB, want string) {
	t.Helper()
	deadline := time.After(10 * time.Second)
	for !strings.Contains(p.Output(), want) {
		select {
		case <-p.read:
		case <-time.After(20 * time.Millisecond):
		case <-deadline:
			t.Fatalf("the terminal never said %q; it said:\n%s", want, p.Output())
		}
	}
}

// Type types s into the terminal.
func (p *PTY) Type(t testing.TB, s string) {
	t.Helper()
	if _, err := p.master.Write([]byte(s)); err != nil {
		t.Fatal(err)
	}
}
