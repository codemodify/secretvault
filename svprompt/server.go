package svprompt

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"
)

// UI is what a prompt program shows. The server keeps the settings the
// client sent (title, description, buttons, ...) in the Request it passes.
type UI interface {
	// GetPin asks for a secret; with r.Repeat set, asks twice and compares.
	GetPin(r Request) ([]byte, error)
	// Confirm shows r with OK and Cancel, and NotOK when notOK is not "".
	// It returns "ok", "notok" or "cancel".
	Confirm(r Request, notOK string) (string, error)
	// Choose shows the choices and returns the chosen ID.
	Choose(r Request, choices []Choice) (string, error)
	// Message shows r with a single button.
	Message(r Request) error
}

// Serve speaks the pinentry protocol on r and w, as a pinentry program
// does on its stdin and stdout, until the client says BYE or goes away.
func Serve(r io.Reader, w io.Writer, ui UI, flavor string) error {
	in := bufio.NewReader(r)
	out := bufio.NewWriter(w)
	send := func(format string, args ...any) error {
		fmt.Fprintf(out, format+"\n", args...)
		return out.Flush()
	}
	okLine := func() error { return send("OK") }
	errLine := func(code int, msg string) error { return send("ERR %d %s", 5<<24|code, escape(msg)) }

	var req Request
	var notOK string
	var choices []Choice
	// SETSECRET's secret, read from the line's bytes and never made a
	// string; wiped when replaced, on RESET, and when the session ends.
	var secret []byte
	defer func() { clear(secret) }()
	if err := send("OK Pleased to meet you, process %d", os.Getpid()); err != nil {
		return err
	}
	for {
		raw, err := readCommand(in)
		if errors.Is(err, errLineTooLong) {
			errLine(errUnknownCmd, "line too long")
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if c, rest, _ := bytes.Cut(raw, []byte(" ")); string(bytes.ToUpper(c)) == "SETSECRET" {
			clear(secret)
			secret = appendUnescaped(nil, rest)
			clear(raw) // the line's bytes, still in in's buffer
			req.Secret = secret
			okLine()
			continue
		}
		line := string(raw)
		cmd, arg, _ := strings.Cut(line, " ")
		arg = unescape(arg)
		switch strings.ToUpper(cmd) {
		case "":
			continue
		case "BYE":
			okLine()
			return nil
		case "RESET":
			clear(secret)
			req, notOK, choices, secret = Request{}, "", nil, nil
			okLine()
		case "OPTION":
			name, value, _ := strings.Cut(arg, "=")
			if strings.TrimSpace(name) == "ttyname" {
				req.TTY = strings.TrimSpace(value)
			}
			okLine()
		case "SETTITLE":
			req.Title = arg
			okLine()
		case "SETDESC":
			req.Description = arg
			okLine()
		case "SETPROMPT":
			req.Prompt = arg
			okLine()
		case "SETERROR":
			req.Error = arg
			okLine()
		case "SETOK":
			req.OK = plainLabel(arg)
			okLine()
		case "SETCANCEL":
			req.Cancel = plainLabel(arg)
			okLine()
		case "SETNOTOK":
			notOK = plainLabel(arg)
			okLine()
		case "SETREPEAT":
			req.Repeat = arg
			if req.Repeat == "" {
				req.Repeat = "Repeat:"
			}
			okLine()
		case "SETTIMEOUT":
			n, _ := strconv.Atoi(arg)
			req.Timeout = time.Duration(n) * time.Second
			okLine()
		case "SETREPEATERROR":
			req.RepeatError = arg
			okLine()
		case "SETKEYINFO", "SETQUALITYBAR", "SETQUALITYBAR_TT", "SETGENPIN", "SETGENPIN_TT":
			okLine() // accepted and ignored
		case "GETINFO":
			switch arg {
			case "version":
				send("D %s", escape("secretvault-1"))
			case "flavor":
				send("D %s", escape(flavor))
			case "pid":
				send("D %d", os.Getpid())
			case "ttyinfo":
				send("D %s", escape(req.TTY))
			default:
				errLine(errNotSupported, "not supported")
				continue
			}
			okLine()
		case "ADDCHOICE":
			id, lab, _ := strings.Cut(arg, " ")
			choices = append(choices, Choice{ID: id, Label: lab})
			okLine()
		case "CHOOSE":
			id, err := ui.Choose(req, choices)
			if err != nil {
				reportErr(err, errLine)
				continue
			}
			send("D %s", escape(id))
			okLine()
		case "GETPIN":
			pin, err := ui.GetPin(req)
			if err != nil {
				reportErr(err, errLine)
				continue
			}
			if req.Repeat != "" {
				send("S PIN_REPEATED")
			}
			// Straight to w, past out: send flushes every line, so
			// nothing is waiting there, and the secret must not be left
			// in out's array. writeData escapes on bytes and wipes what
			// it built; long secrets span several D lines.
			err = writeData(w, pin)
			clear(pin)
			if err != nil {
				return err
			}
			okLine()
		case "CONFIRM":
			if strings.Contains(arg, "--one-button") {
				if err := ui.Message(req); err != nil {
					reportErr(err, errLine)
					continue
				}
				okLine()
				continue
			}
			res, err := ui.Confirm(req, notOK)
			if err != nil {
				reportErr(err, errLine)
				continue
			}
			switch res {
			case "ok":
				okLine()
			case "notok":
				errLine(errNotConfirmed, "Not confirmed")
			default:
				errLine(errCanceled, "Operation cancelled")
			}
		case "MESSAGE":
			if err := ui.Message(req); err != nil {
				reportErr(err, errLine)
				continue
			}
			okLine()
		default:
			errLine(errUnknownCmd, "Unknown IPC command")
		}
	}
}

// errLineTooLong is a command past Assuan's line limit, read and dropped.
var errLineTooLong = errors.New("svprompt: line too long")

// readCommand reads one line, without its line ending, as a view of in's
// buffer that the next read replaces. A line past the limit is read to
// its end and dropped (errLineTooLong).
func readCommand(in *bufio.Reader) ([]byte, error) {
	line, err := in.ReadSlice('\n')
	if errors.Is(err, bufio.ErrBufferFull) {
		for errors.Is(err, bufio.ErrBufferFull) {
			_, err = in.ReadSlice('\n')
		}
		if err != nil {
			return nil, err
		}
		return nil, errLineTooLong
	}
	if err != nil && !(errors.Is(err, io.EOF) && len(line) > 0) {
		return nil, err
	}
	line = bytes.TrimRight(line, "\r\n")
	if len(line) > maxLine {
		return nil, errLineTooLong
	}
	return line, nil
}

func reportErr(err error, errLine func(int, string) error) {
	switch {
	case errors.Is(err, ErrCanceled):
		errLine(errCanceled, "Operation cancelled")
	case errors.Is(err, ErrTimeout):
		errLine(errTimeout, "Timeout")
	default:
		errLine(errCanceled, err.Error())
	}
}
