package svmanager

import (
	"fmt"

	"github.com/codemodify/secretvault/svrpc"
)

// Questions asked in the middle of local work: an operation of svops that
// finds it needs a passphrase (an OpenPGP key's own, a file's, an SSH
// key's) takes a callback, which runs on the worker's goroutine and asks
// here, waiting for the answer, as the CLI asks on its terminal.

// answer is what a question from a worker got back.
type answer struct {
	secret []byte
	err    error
}

// askSecret asks for a secret in a dialog and waits for it, from any
// goroutine but the interface's. With repeat it is a new one, asked
// twice, at least minLen characters long. The caller wipes what it gets.
func (m *Manager) askSecret(title, label, note string, repeat bool, minLen int) ([]byte, error) {
	ch := make(chan answer, 1)
	m.post(func() {
		f := m.newForm(title)
		if note != "" {
			f.intro(note)
		}
		var take func() ([]byte, bool)
		if repeat {
			take = f.newPassphraseMin(label, minLen)
		} else {
			s := f.secret(label, "")
			take = func() ([]byte, bool) {
				if s.Len() < max(1, minLen) {
					f.fail(fmt.Sprintf("Type at least %d characters.", max(1, minLen)))
					return nil, false
				}
				return s.Bytes(), true
			}
		}
		f.onClose(func() {
			select {
			case ch <- answer{err: svrpc.ErrCanceled}:
			default: // answered already
			}
		})
		f.show("Continue", func() {
			b, ok := take()
			if !ok {
				return
			}
			select {
			case ch <- answer{secret: b}:
			default:
				clear(b)
			}
			f.close()
		})
	})
	select {
	case a := <-ch:
		return a.secret, a.err
	case <-m.done:
		return nil, svrpc.ErrCanceled
	}
}

// askYes asks a question with two answers from a worker, and waits.
func (m *Manager) askYes(title, text, yes, no string) (bool, error) {
	ch := make(chan bool, 1)
	m.post(func() {
		f := m.newForm(title)
		f.intro(text)
		if no != "" {
			f.note("Cancel answers “" + no + "”.")
		}
		f.onClose(func() {
			select {
			case ch <- false: // closed without saying yes: no
			default:
			}
		})
		f.show(yes, func() {
			select {
			case ch <- true:
			default:
			}
			f.close()
		})
	})
	select {
	case ok := <-ch:
		return ok, nil
	case <-m.done:
		return false, svrpc.ErrCanceled
	}
}
