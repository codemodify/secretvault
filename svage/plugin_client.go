package svage

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// The client's side of the plugin protocol: running age-plugin-NAME for
// an AGE-PLUGIN-NAME-1... identity or an age1NAME1... recipient.

// PluginUI is how a plugin reaches the person, through the client. Each
// function may be nil, and each may fail; the plugin is told and decides
// what to do.
type PluginUI struct {
	// DisplayMessage shows a message from plugin name.
	DisplayMessage func(name, message string) error
	// RequestValue asks for a value (a PIN, when secret). The caller
	// zeroes what it returns once sent.
	RequestValue func(name, prompt string, secret bool) ([]byte, error)
	// Confirm asks the person to choose between yes and no (no may be "").
	Confirm func(name, prompt, yes, no string) (bool, error)
}

// PluginIdentity is an AGE-PLUGIN-NAME-1... identity: unwrapping runs
// the plugin.
type PluginIdentity struct {
	name, encoding string
	ui             *PluginUI
}

// NewPluginIdentity reads an AGE-PLUGIN-NAME-1... identity. ui may be
// nil: the plugin then gets "fail" whenever it asks for anything.
func NewPluginIdentity(s string, ui *PluginUI) (*PluginIdentity, error) {
	name, data, err := ParsePluginIdentity(s)
	if err != nil {
		return nil, err
	}
	clear(data)
	return &PluginIdentity{name: name, encoding: s, ui: ui}, nil
}

// Name is the plugin's name.
func (i *PluginIdentity) Name() string { return i.name }

// String is the identity as given.
func (i *PluginIdentity) String() string { return i.encoding }

// Recipient is the identity used as a recipient: the plugin wraps to its
// public half (age -e -i IDENTITY).
func (i *PluginIdentity) Recipient() *PluginRecipient {
	return &PluginRecipient{name: i.name, encoding: i.encoding, ui: i.ui, identity: true}
}

// Unwrap implements Identity by running the plugin's identity-v1.
func (i *PluginIdentity) Unwrap(stanzas []*Stanza) (fileKey []byte, err error) {
	defer func() {
		if err != nil && !errors.Is(err, ErrIncorrectIdentity) {
			err = fmt.Errorf("svage: plugin %s: %w", i.name, err)
		}
	}()
	pc, err := startPlugin(i.name, PluginIdentityV1)
	if err != nil {
		return nil, err
	}
	defer func() { err = pc.finish(err) }()
	c := newPluginConn(pc, pc)
	if err := c.write("add-identity", nil, i.encoding); err != nil {
		return nil, err
	}
	for _, s := range stanzas {
		if err := c.write("recipient-stanza", s.Body, append([]string{"0", s.Type}, s.Args...)...); err != nil {
			return nil, err
		}
	}
	if err := c.write("done", nil); err != nil {
		return nil, err
	}
	for {
		s, err := c.read()
		if err != nil {
			clear(fileKey)
			return nil, err
		}
		switch s.Type {
		case "file-key":
			if len(s.Args) != 1 || s.Args[0] != "0" || fileKey != nil || len(s.Body) != FileKeySize {
				clear(s.Body)
				clear(fileKey)
				return nil, errors.New("a malformed file-key")
			}
			fileKey = s.Body
			if err := c.write("ok", nil); err != nil {
				clear(fileKey)
				return nil, err
			}
		case "error":
			clear(fileKey)
			c.write("ok", nil)
			return nil, errors.New(printable(s.Body))
		case "done":
			if fileKey == nil {
				return nil, fmt.Errorf("%w (plugin %s)", ErrIncorrectIdentity, i.name)
			}
			return fileKey, nil
		default:
			if err := i.ui.handle(i.name, c, s); err != nil {
				clear(fileKey)
				return nil, err
			}
		}
	}
}

// PluginRecipient is an age1NAME1... recipient: wrapping runs the plugin.
type PluginRecipient struct {
	name, encoding string
	ui             *PluginUI
	identity       bool // the encoding is an identity's
}

// NewPluginRecipient reads an age1NAME1... recipient. ui may be nil.
func NewPluginRecipient(s string, ui *PluginUI) (*PluginRecipient, error) {
	name, _, err := ParsePluginRecipient(s)
	if err != nil {
		return nil, err
	}
	return &PluginRecipient{name: name, encoding: s, ui: ui}, nil
}

// Name is the plugin's name.
func (r *PluginRecipient) Name() string { return r.name }

// String is the recipient as given (a placeholder for an identity's).
func (r *PluginRecipient) String() string {
	if r.identity {
		return "(the public half of a " + r.name + " identity)"
	}
	return r.encoding
}

// Wrap implements Recipient.
func (r *PluginRecipient) Wrap(fileKey []byte) ([]*Stanza, error) {
	s, _, err := r.WrapWithLabels(fileKey)
	return s, err
}

// WrapWithLabels implements RecipientWithLabels by running the plugin's
// recipient-v1.
func (r *PluginRecipient) WrapWithLabels(fileKey []byte) (stanzas []*Stanza, labels []string, err error) {
	defer func() {
		if err != nil {
			err = fmt.Errorf("svage: plugin %s: %w", r.name, err)
		}
	}()
	pc, err := startPlugin(r.name, PluginRecipientV1)
	if err != nil {
		return nil, nil, err
	}
	defer func() { err = pc.finish(err) }()
	c := newPluginConn(pc, pc)
	add := "add-recipient"
	if r.identity {
		add = "add-identity"
	}
	for _, cmd := range []struct {
		typ  string
		body []byte
		args []string
	}{
		{add, nil, []string{r.encoding}},
		{"wrap-file-key", fileKey, nil},
		{"extension-labels", nil, nil},
		{"done", nil, nil},
	} {
		if err := c.write(cmd.typ, cmd.body, cmd.args...); err != nil {
			return nil, nil, err
		}
	}
	gotLabels := false
	for {
		s, err := c.read()
		if err != nil {
			return nil, nil, err
		}
		switch s.Type {
		case "recipient-stanza":
			if len(s.Args) < 2 || s.Args[0] != "0" {
				return nil, nil, errors.New("a malformed recipient-stanza")
			}
			stanzas = append(stanzas, &Stanza{Type: s.Args[1], Args: s.Args[2:], Body: s.Body})
			if err := c.write("ok", nil); err != nil {
				return nil, nil, err
			}
		case "labels":
			if gotLabels || len(s.Body) != 0 {
				return nil, nil, errors.New("a malformed labels command")
			}
			gotLabels, labels = true, s.Args
			if err := c.write("ok", nil); err != nil {
				return nil, nil, err
			}
		case "error":
			c.write("ok", nil)
			return nil, nil, errors.New(printable(s.Body))
		case "done":
			if len(stanzas) == 0 {
				return nil, nil, errors.New("the plugin made no stanza")
			}
			return stanzas, labels, nil
		default:
			if err := r.ui.handle(r.name, c, s); err != nil {
				return nil, nil, err
			}
		}
	}
}

// handle answers a plugin's request for help, or "unsupported".
func (ui *PluginUI) handle(name string, c *pluginConn, s *Stanza) error {
	if ui == nil {
		ui = &PluginUI{}
	}
	switch s.Type {
	case "msg":
		if ui.DisplayMessage == nil || ui.DisplayMessage(name, printable(s.Body)) != nil {
			return c.write("fail", nil)
		}
		return c.write("ok", nil)
	case "request-public", "request-secret":
		if ui.RequestValue == nil {
			return c.write("fail", nil)
		}
		v, err := ui.RequestValue(name, printable(s.Body), s.Type == "request-secret")
		if err != nil {
			return c.write("fail", nil)
		}
		defer clear(v)
		return c.write("ok", v)
	case "confirm":
		if len(s.Args) != 1 && len(s.Args) != 2 {
			return errors.New("a malformed confirm command")
		}
		yes, err := decodeB64(s.Args[0])
		if err != nil {
			return errors.New("a malformed confirm command")
		}
		var no []byte
		if len(s.Args) == 2 {
			if no, err = decodeB64(s.Args[1]); err != nil {
				return errors.New("a malformed confirm command")
			}
		}
		if ui.Confirm == nil {
			return c.write("fail", nil)
		}
		ok, err := ui.Confirm(name, printable(s.Body), printable(yes), printable(no))
		if err != nil {
			return c.write("fail", nil)
		}
		answer := "no"
		if ok {
			answer = "yes"
		}
		return c.write("ok", nil, answer)
	}
	return c.write("unsupported", nil)
}

// pluginProcess is a running plugin: its stdin and stdout, and a record
// of what it said on stderr for when it fails.
type pluginProcess struct {
	io.Reader
	io.Writer
	finish func(err error) error
}

// startPlugin runs age-plugin-NAME for a state machine. A variable, so
// tests can serve a plugin in-process.
var startPlugin = execPlugin

func execPlugin(name, sm string) (*pluginProcess, error) {
	if !validPluginName(name) || strings.ContainsAny(name, `/\`) {
		return nil, fmt.Errorf("invalid plugin name %q", name)
	}
	// LookPath skips PATH entries relative to the working directory, as
	// the plugin spec requires.
	path, err := exec.LookPath("age-plugin-" + name)
	if err != nil {
		return nil, fmt.Errorf("age-plugin-%s is not installed (on PATH): %v", name, err)
	}
	cmd := exec.Command(path, "--age-plugin="+sm)
	cmd.Dir = os.TempDir()
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	stderr := &tailBuffer{max: 4096}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &pluginProcess{Reader: stdout, Writer: stdin, finish: func(err error) error {
		stdin.Close()
		exited := make(chan error, 1)
		go func() { exited <- cmd.Wait() }()
		var werr error
		select {
		case werr = <-exited:
		case <-time.After(5 * time.Second):
			cmd.Process.Kill()
			werr = <-exited
		}
		if err != nil && werr != nil {
			if msg := strings.TrimSpace(printable(stderr.bytes())); msg != "" {
				return fmt.Errorf("%w (it said: %s)", err, msg)
			}
		}
		return err
	}}, nil
}

// tailBuffer keeps the last max bytes written to it.
type tailBuffer struct {
	mu  sync.Mutex
	b   []byte
	max int
}

func (t *tailBuffer) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.b = append(t.b, p...)
	if len(t.b) > t.max {
		t.b = t.b[len(t.b)-t.max:]
	}
	return len(p), nil
}

func (t *tailBuffer) bytes() []byte {
	t.mu.Lock()
	defer t.mu.Unlock()
	return bytes.Clone(t.b)
}
