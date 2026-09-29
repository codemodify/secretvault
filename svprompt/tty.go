// Package svprompt asks people for secrets. Today that is the terminal
// prompt the CLI uses; the pinentry-compatible (Assuan) prompt protocol that
// secretvaultd speaks to secretvault-tui-prompt and secretvault-gui-prompt
// lands here too (docs/architecture.md, "Prompts").
package svprompt

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// ErrNoTerminal is a prompt with no terminal to ask on.
var ErrNoTerminal = errors.New("svprompt: no terminal to ask on")

// ErrMismatch is a new secret whose two entries differ.
var ErrMismatch = errors.New("svprompt: the two entries do not match")

// Secret asks for a secret on the controlling terminal, without echo. It
// reads the terminal itself, not stdin, so it works while stdin carries
// data. The caller zeroes the result.
func Secret(prompt string) ([]byte, error) {
	in, out, err := openTerminal()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoTerminal, err)
	}
	defer in.Close()
	if out != in {
		defer out.Close()
	}
	return readSecret(in, out, prompt)
}

func readSecret(in *os.File, out io.Writer, prompt string) ([]byte, error) {
	fmt.Fprint(out, prompt)
	b, err := term.ReadPassword(int(in.Fd()))
	fmt.Fprintln(out)
	return b, err
}

// NewSecret asks for a new secret twice and returns it when both entries
// match and it is at least min bytes long.
func NewSecret(prompt string, min int) ([]byte, error) {
	in, out, err := openTerminal()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoTerminal, err)
	}
	defer in.Close()
	if out != in {
		defer out.Close()
	}
	a, err := readSecret(in, out, prompt)
	if err != nil {
		return nil, err
	}
	if len(a) < min {
		clear(a)
		return nil, fmt.Errorf("svprompt: too short: use at least %d characters", min)
	}
	b, err := readSecret(in, out, "Again: ")
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
