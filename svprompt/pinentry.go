package svprompt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Request describes one prompt.
type Request struct {
	Title       string
	Description string // may span lines
	Prompt      string // the label before the entry ("Passphrase:")
	Error       string // shown when retrying after a wrong entry
	OK, Cancel  string // button labels; "" for the program's own
	Repeat      string // for a new secret: the prompt of the second entry
	Timeout     time.Duration
	TTY         string // for terminal pinentries: which terminal to use
}

// Choice is one answer offered by Choose.
type Choice struct {
	ID    string
	Label string
}

// Pinentry drives a pinentry program: one process per prompt, as gpg-agent
// does. Program must be an absolute path; secretvaultd never looks one up
// on PATH, so a planted "pinentry" earlier on PATH is never run.
type Pinentry struct {
	Program string
	Env     []string // the environment for the program (DISPLAY, WAYLAND_DISPLAY, ...)
}

// session is one running pinentry.
type session struct {
	cmd  *exec.Cmd
	in   io.WriteCloser
	out  *bufio.Reader
	stop context.CancelFunc
}

func (p *Pinentry) start(ctx context.Context) (*session, error) {
	if !filepath.IsAbs(p.Program) {
		return nil, fmt.Errorf("svprompt: pinentry program %q is not an absolute path", p.Program)
	}
	ctx, cancel := context.WithCancel(ctx)
	cmd := exec.CommandContext(ctx, p.Program)
	cmd.Env = p.Env
	cmd.Stderr = nil
	in, err := cmd.StdinPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	outPipe, err := cmd.StdoutPipe()
	if err != nil {
		cancel()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		cancel()
		return nil, err
	}
	s := &session{cmd: cmd, in: in, out: bufio.NewReader(outPipe), stop: cancel}
	if _, _, err := s.response(nil); err != nil {
		s.close()
		return nil, fmt.Errorf("svprompt: %s did not greet: %w", p.Program, err)
	}
	return s, nil
}

func (s *session) close() {
	fmt.Fprintf(s.in, "BYE\n")
	s.in.Close()
	done := make(chan struct{})
	go func() { s.cmd.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		s.stop()
		<-done
	}
	s.stop()
}

// command sends one command and reads its response. Data lines are
// collected (unescaped) into the returned slice, which the caller wipes.
func (s *session) command(format string, args ...any) ([]byte, []string, error) {
	line := fmt.Sprintf(format, args...)
	if len(line) > maxLine {
		return nil, nil, fmt.Errorf("svprompt: command longer than %d bytes", maxLine)
	}
	if _, err := io.WriteString(s.in, line+"\n"); err != nil {
		return nil, nil, err
	}
	return s.response(nil)
}

// response reads lines until OK or ERR.
func (s *session) response(data []byte) ([]byte, []string, error) {
	var status []string
	for {
		line, err := s.out.ReadString('\n')
		if err != nil {
			clear(data)
			return nil, nil, err
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case line == "OK" || strings.HasPrefix(line, "OK "):
			return data, status, nil
		case strings.HasPrefix(line, "ERR"):
			clear(data)
			return nil, status, parseErr(line)
		case strings.HasPrefix(line, "D "):
			data = append(data, unescapeBytes(line[2:])...)
		case strings.HasPrefix(line, "S "):
			status = append(status, line[2:])
		case strings.HasPrefix(line, "INQUIRE"):
			// We ask for nothing that inquires (no quality bar); refuse.
			io.WriteString(s.in, "CAN\n")
		case strings.HasPrefix(line, "#"), line == "":
		default:
			clear(data)
			return nil, status, fmt.Errorf("svprompt: unexpected pinentry line %q", line)
		}
	}
}

func (s *session) setup(r Request) error {
	cmds := []string{}
	if r.TTY != "" {
		cmds = append(cmds, "OPTION ttyname="+escape(r.TTY))
		if t := os.Getenv("TERM"); t != "" {
			cmds = append(cmds, "OPTION ttytype="+escape(t))
		}
	}
	if r.Title != "" {
		cmds = append(cmds, "SETTITLE "+escape(r.Title))
	}
	if r.Description != "" {
		cmds = append(cmds, "SETDESC "+escape(r.Description))
	}
	if r.Prompt != "" {
		cmds = append(cmds, "SETPROMPT "+escape(r.Prompt))
	}
	if r.Error != "" {
		cmds = append(cmds, "SETERROR "+escape(r.Error))
	}
	if r.OK != "" {
		cmds = append(cmds, "SETOK "+escape(label(r.OK)))
	}
	if r.Cancel != "" {
		cmds = append(cmds, "SETCANCEL "+escape(label(r.Cancel)))
	}
	if r.Timeout > 0 {
		cmds = append(cmds, fmt.Sprintf("SETTIMEOUT %d", int(r.Timeout.Seconds())))
	}
	for _, c := range cmds {
		if _, _, err := s.command("%s", c); err != nil {
			var ae *AssuanError
			// Old pinentries lack some commands; a prompt without a
			// title is still a prompt.
			if errors.As(err, &ae) && ae.kind() == errUnknownCmd {
				continue
			}
			return err
		}
	}
	return nil
}

func mapErr(err error) error {
	var ae *AssuanError
	if errors.As(err, &ae) {
		switch ae.kind() {
		case errCanceled, errNotConfirmed:
			return ErrCanceled
		case errTimeout:
			return ErrTimeout
		}
	}
	return err
}

// GetPassphrase asks for a secret. With r.Repeat set it asks twice and
// only returns when both entries match (the pinentry checks). The caller
// zeroes the result.
func (p *Pinentry) GetPassphrase(ctx context.Context, r Request) ([]byte, error) {
	s, err := p.start(ctx)
	if err != nil {
		return nil, err
	}
	defer s.close()
	if err := s.setup(r); err != nil {
		return nil, err
	}
	if r.Repeat != "" {
		if _, _, err := s.command("SETREPEAT %s", escape(r.Repeat)); err != nil {
			return nil, err
		}
		s.command("SETREPEATERROR %s", escape("The two entries do not match."))
	}
	data, _, err := s.command("GETPIN")
	if err != nil {
		return nil, mapErr(err)
	}
	return data, nil
}

// Choose asks the person to pick one of choices, and returns its ID.
//
// secretvault's own prompts understand an extension (ADDCHOICE and CHOOSE)
// that shows every choice. Any other pinentry gets CONFIRM with three
// buttons, which carry the first three choices (OK, the "not OK" button,
// and Cancel); the rest are reachable later in the manager.
func (p *Pinentry) Choose(ctx context.Context, r Request, choices []Choice) (string, error) {
	if len(choices) == 0 {
		return "", errors.New("svprompt: nothing to choose from")
	}
	s, err := p.start(ctx)
	if err != nil {
		return "", err
	}
	defer s.close()
	if err := s.setup(r); err != nil {
		return "", err
	}
	extended := true
	for _, c := range choices {
		if _, _, err := s.command("ADDCHOICE %s %s", escape(c.ID), escape(c.Label)); err != nil {
			var ae *AssuanError
			if errors.As(err, &ae) && ae.kind() == errUnknownCmd {
				extended = false
				break
			}
			return "", err
		}
	}
	if extended {
		data, _, err := s.command("CHOOSE")
		if err != nil {
			return "", mapErr(err)
		}
		id := string(data)
		for _, c := range choices {
			if c.ID == id {
				return id, nil
			}
		}
		return "", fmt.Errorf("svprompt: the prompt chose %q, which was not offered", id)
	}

	// Plain pinentry: OK, NOTOK and CANCEL carry up to three choices.
	s.command("SETOK %s", escape(label(choices[0].Label)))
	if len(choices) > 2 {
		s.command("SETNOTOK %s", escape(label(choices[1].Label)))
	}
	last := choices[len(choices)-1]
	if len(choices) > 1 {
		s.command("SETCANCEL %s", escape(label(last.Label)))
	}
	_, _, err = s.command("CONFIRM")
	var ae *AssuanError
	switch {
	case err == nil:
		return choices[0].ID, nil
	case errors.As(err, &ae) && ae.kind() == errNotConfirmed && len(choices) > 2:
		return choices[1].ID, nil
	case errors.As(err, &ae) && (ae.kind() == errCanceled || ae.kind() == errNotConfirmed) && len(choices) > 1:
		return last.ID, nil
	}
	return "", mapErr(err)
}

// Notice shows r with one button (r.OK, "Cancel" when empty) until ctx
// ends, when the program is closed, or until the person presses the
// button, which returns ErrCanceled. It is how gpg-agent says "touch your
// key": a window the waiting side takes down itself.
func (p *Pinentry) Notice(ctx context.Context, r Request) error {
	if r.OK == "" {
		r.OK = "Cancel"
	}
	s, err := p.start(ctx)
	if err != nil {
		return err
	}
	defer s.close()
	if err := s.setup(r); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return err
	}
	_, _, err = s.command("MESSAGE")
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil {
		return ErrCanceled
	}
	return mapErr(err)
}

// Probe starts the program and asks its version, to check it is a working
// pinentry without showing anything.
func (p *Pinentry) Probe(ctx context.Context) (string, error) {
	s, err := p.start(ctx)
	if err != nil {
		return "", err
	}
	defer s.close()
	data, _, err := s.command("GETINFO version")
	return string(data), err
}
