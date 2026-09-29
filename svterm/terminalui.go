package svterm

import (
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svprompt"
)

// TerminalUI shows pinentry prompts (svprompt.UI) on a terminal: the one the client
// named with OPTION ttyname, else Default, else the controlling terminal.
type TerminalUI struct {
	Default string
}

func (u TerminalUI) open(r svprompt.Request) (*Terminal, error) {
	path := r.TTY
	if path == "" {
		path = u.Default
	}
	t, err := OpenTerminal(path)
	if err != nil {
		return nil, err
	}
	t.Printf("\n")
	if r.Title != "" {
		t.Printf("%s\n%s\n", r.Title, strings.Repeat("─", min(len([]rune(r.Title)), 60)))
	}
	if r.Description != "" {
		t.Printf("%s\n", r.Description)
	}
	if r.Error != "" {
		t.Printf("! %s\n", r.Error)
	}
	return t, nil
}

func (u TerminalUI) GetPin(r svprompt.Request) ([]byte, error) {
	t, err := u.open(r)
	if err != nil {
		return nil, err
	}
	defer t.Close()
	prompt := r.Prompt
	if prompt == "" {
		prompt = "Passphrase:"
	}
	prompt = strings.TrimRight(prompt, " ") + " "
	if r.Repeat != "" {
		for {
			pin, err := t.ReadNewSecret(prompt, strings.TrimRight(r.Repeat, " ")+" ", 1)
			if err == ErrMismatch {
				t.Printf("! The two entries do not match; try again.\n")
				continue
			}
			return pin, err
		}
	}
	pin, err := t.ReadSecret(prompt)
	if err == nil && len(pin) == 0 {
		return nil, svprompt.ErrCanceled
	}
	return pin, err
}

func (u TerminalUI) Confirm(r svprompt.Request, notOK string) (string, error) {
	t, err := u.open(r)
	if err != nil {
		return "", err
	}
	defer t.Close()
	ok, cancel := r.OK, r.Cancel
	if ok == "" {
		ok = "OK"
	}
	if cancel == "" {
		cancel = "Cancel"
	}
	choices := []svprompt.Choice{{ID: "ok", Label: ok}}
	if notOK != "" {
		choices = append(choices, svprompt.Choice{ID: "notok", Label: notOK})
	}
	choices = append(choices, svprompt.Choice{ID: "cancel", Label: cancel})
	id, err := t.Choose(choices)
	if err == svprompt.ErrCanceled {
		return "cancel", nil
	}
	return id, err
}

func (u TerminalUI) Choose(r svprompt.Request, choices []svprompt.Choice) (string, error) {
	if len(choices) == 0 {
		return "", fmt.Errorf("svprompt: nothing to choose from")
	}
	t, err := u.open(r)
	if err != nil {
		return "", err
	}
	defer t.Close()
	return t.Choose(choices)
}

func (u TerminalUI) Message(r svprompt.Request) error {
	t, err := u.open(r)
	if err != nil {
		return err
	}
	defer t.Close()
	_, err = t.ReadLine("Press Enter to continue.")
	return err
}
