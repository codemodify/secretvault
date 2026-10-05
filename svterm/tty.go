// Package svterm asks people for secrets and decisions on a terminal: the
// CLI's own prompts, and TerminalUI, the terminal face of the pinentry
// protocol (svprompt). It is kept apart from svprompt so that secretvaultd,
// which drives prompts but never reads a terminal itself, links none of it.
package svterm

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"golang.org/x/term"

	"github.com/codemodify/secretvault/svprompt"
)

// ErrNoTerminal is a prompt with no terminal to ask on.
var ErrNoTerminal = errors.New("svprompt: no terminal to ask on")

// ErrMismatch is a new secret whose two entries differ.
var ErrMismatch = errors.New("svprompt: the two entries do not match")

// Terminal is a terminal opened for prompting. It reads the terminal
// itself, not stdin, so it works while stdin carries data.
type Terminal struct {
	in, out *os.File
	r       *bufio.Reader
}

// OpenTerminal opens the terminal at path, or the controlling terminal
// when path is "".
func OpenTerminal(path string) (*Terminal, error) {
	var in, out *os.File
	var err error
	if path == "" {
		in, out, err = openTerminal()
	} else {
		in, err = os.OpenFile(path, os.O_RDWR, 0)
		out = in
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoTerminal, err)
	}
	if !term.IsTerminal(int(in.Fd())) {
		in.Close()
		return nil, fmt.Errorf("%w: %s is not a terminal", ErrNoTerminal, in.Name())
	}
	return &Terminal{in: in, out: out}, nil
}

// Close closes the terminal.
func (t *Terminal) Close() {
	t.in.Close()
	if t.out != t.in {
		t.out.Close()
	}
}

// Printf writes to the terminal.
func (t *Terminal) Printf(format string, args ...any) { fmt.Fprintf(t.out, format, args...) }

// ShowSecret writes secret on a line of its own, indented and set apart by
// blank lines, for the person to write down (a new recovery key). It goes
// straight from its bytes to the terminal.
func (t *Terminal) ShowSecret(secret []byte) {
	t.out.Write([]byte("\n    "))
	t.out.Write(secret)
	t.out.Write([]byte("\n\n"))
}

// ReadSecret reads a line without echo. The caller zeroes the result.
func (t *Terminal) ReadSecret(prompt string) ([]byte, error) {
	fmt.Fprint(t.out, prompt)
	b, err := term.ReadPassword(int(t.in.Fd()))
	fmt.Fprintln(t.out)
	return b, err
}

// ReadLine reads a line with echo.
func (t *Terminal) ReadLine(prompt string) (string, error) {
	fmt.Fprint(t.out, prompt)
	if t.r == nil {
		t.r = bufio.NewReader(t.in)
	}
	s, err := t.r.ReadString('\n')
	if err != nil && !(errors.Is(err, io.EOF) && s != "") {
		return "", err
	}
	return strings.TrimRight(s, "\r\n"), nil
}

// ReadNewSecret asks twice and returns the secret when both entries match
// and it is at least min bytes long.
func (t *Terminal) ReadNewSecret(prompt, again string, min int) ([]byte, error) {
	a, err := t.ReadSecret(prompt)
	if err != nil {
		return nil, err
	}
	if len(a) < min {
		clear(a)
		return nil, fmt.Errorf("svprompt: too short: use at least %d characters", min)
	}
	if again == "" {
		again = "Again: "
	}
	b, err := t.ReadSecret(again)
	if err != nil {
		clear(a)
		return nil, err
	}
	defer clear(b)
	if string(a) != string(b) {
		clear(a)
		return nil, ErrMismatch
	}
	return a, nil
}

// Choose lists the choices, numbered, and reads the number of one. An
// empty answer or "q" cancels.
func (t *Terminal) Choose(choices []svprompt.Choice) (string, error) {
	for i, c := range choices {
		t.Printf("  %d) %s\n", i+1, c.Label)
	}
	for {
		s, err := t.ReadLine(fmt.Sprintf("Choose 1-%d (Enter to cancel): ", len(choices)))
		if err != nil {
			return "", err
		}
		s = strings.TrimSpace(s)
		if s == "" || strings.EqualFold(s, "q") {
			return "", svprompt.ErrCanceled
		}
		if n, err := strconv.Atoi(s); err == nil && n >= 1 && n <= len(choices) {
			return choices[n-1].ID, nil
		}
		t.Printf("Please answer with a number from 1 to %d.\n", len(choices))
	}
}

// Secret asks for a secret on the controlling terminal. The caller zeroes
// the result.
func Secret(prompt string) ([]byte, error) {
	t, err := OpenTerminal("")
	if err != nil {
		return nil, err
	}
	defer t.Close()
	return t.ReadSecret(prompt)
}

// NewSecret asks for a new secret twice on the controlling terminal.
func NewSecret(prompt string, min int) ([]byte, error) {
	t, err := OpenTerminal("")
	if err != nil {
		return nil, err
	}
	defer t.Close()
	return t.ReadNewSecret(prompt, "", min)
}
