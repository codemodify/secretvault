// Command secretvault-gui-prompt asks a person for a secret or a decision
// in a small window of its own, built with uitoolkit. It is what
// secretvaultd shows on a desktop (docs/architecture.md, "Prompts"), and it
// has two ways to run:
//
//	secretvault-gui-prompt           a pinentry: speaks the Assuan protocol on
//	                                 stdin/stdout, as gpg-agent and secretvaultd
//	                                 expect (pinentry-program in gpg-agent.conf)
//	secretvault-gui-prompt PROMPT    an askpass helper: asks in a window and
//	                                 prints the answer (SSH_ASKPASS, SUDO_ASKPASS,
//	                                 GIT_ASKPASS)
//
// secretvault-tui-prompt's third way, --agent, has no counterpart here:
// secretvaultd starts this program itself for every desktop question, with
// the session's display, so nothing needs to stay running and registered.
//
// Every dialog carries secretvault's header and says who is asking. The
// passphrase is typed into a uitoolkit SecretField and is never a Go
// string on its way to the pipe; the keyboard is held while it is typed,
// the window stays out of screen captures where the platform allows it,
// and input methods are off in the field.
package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svprompt"
	"github.com/codemodify/uitoolkit"
)

const usage = "usage: secretvault-gui-prompt [PROMPT]"

func main() {
	_ = svcrypto.NoCoreDumps()
	args := os.Args[1:]
	switch {
	case len(args) == 0:
		os.Exit(pinentry())
	case args[0] == "--agent":
		fmt.Fprintln(os.Stderr, "secretvault-gui-prompt: there is no --agent here: secretvaultd starts this prompt itself\n"+
			"for each question on the desktop. Where there is no desktop, run secretvault-tui-prompt --agent.")
		os.Exit(2)
	case args[0] == "-h" || args[0] == "--help":
		fmt.Fprintln(os.Stderr, usage)
	default:
		os.Exit(askpass(strings.Join(args, " ")))
	}
}

// pinentry serves the pinentry protocol on stdin and stdout, and shows its
// questions on this, the main, thread.
func pinentry() int {
	k := newDesk()
	served := make(chan error, 1)
	go func() { served <- svprompt.Serve(os.Stdin, os.Stdout, pinentryUI{k}, "uitoolkit") }()
	if err := k.run(served); err != nil {
		fmt.Fprintln(os.Stderr, "secretvault-gui-prompt:", err)
		return 1
	}
	return 0
}

// askpass asks for one secret and prints it, as askpass helpers do. ssh
// also asks its helper for a yes or no (SSH_ASKPASS_PROMPT=confirm, when a
// key added with ssh-add -c is used), and to show a notice it will take
// down itself (SSH_ASKPASS_PROMPT=none, "confirm user presence").
func askpass(prompt string) int {
	r := svprompt.Request{Description: strings.TrimSpace(prompt)}
	var d *dialog
	switch os.Getenv("SSH_ASKPASS_PROMPT") {
	case "confirm":
		r.Title, r.OK, r.Cancel = "Allow this?", "Yes", "No"
		d = newDialog(askConfirm, r)
	case "none":
		r.Title = "Notice"
		d = newDialog(askMessage, r)
	default:
		r.Title, r.Prompt = "A program asks for a passphrase", "Passphrase:"
		d = newDialog(askPIN, r)
	}
	k := newDesk()
	k.show(d)
	a := <-d.answer
	defer uitoolkit.WipeBytes(a.secret)
	switch {
	case a.err != nil:
		if !errors.Is(a.err, svprompt.ErrCanceled) && !errors.Is(a.err, svprompt.ErrTimeout) {
			fmt.Fprintln(os.Stderr, "secretvault-gui-prompt:", a.err)
		}
		return 1
	case d.kind == askConfirm && a.choice != "ok":
		return 1
	case d.kind == askPIN:
		os.Stdout.Write(a.secret)
		os.Stdout.Write([]byte("\n"))
	}
	return 0
}

// pinentryUI is svprompt.UI in windows: each call hands a dialog to the
// UI thread and waits for its answer.
type pinentryUI struct{ k *desk }

func (u pinentryUI) GetPin(r svprompt.Request) ([]byte, error) {
	a := u.k.ask(newDialog(askPIN, r))
	return a.secret, a.err
}

func (u pinentryUI) Confirm(r svprompt.Request, notOK string) (string, error) {
	d := newDialog(askConfirm, r)
	d.notOK = notOK
	a := u.k.ask(d)
	return a.choice, a.err
}

func (u pinentryUI) Choose(r svprompt.Request, choices []svprompt.Choice) (string, error) {
	if len(choices) == 0 {
		return "", errors.New("nothing to choose from")
	}
	d := newDialog(askChoose, r)
	d.choices = choices
	a := u.k.ask(d)
	return a.choice, a.err
}

func (u pinentryUI) Message(r svprompt.Request) error {
	return u.k.ask(newDialog(askMessage, r)).err
}

// desk puts dialogs on screen one at a time, on the UI thread: the
// process's main thread, which uitoolkit's windows are made and run on.
// The protocol runs on a goroutine of its own and hands its questions
// over through ask.
type desk struct {
	opts  uitoolkit.Options
	queue chan *dialog
	// asker names the program that started this one, for the dialogs to
	// show; it is worked out when the first dialog opens (a probe that
	// only asks GETINFO never needs it), and tests replace it.
	asker     func() string
	askerName string
	askerDone bool
	app       *uitoolkit.Application
}

func newDesk() *desk {
	return &desk{
		// The desktop's look, light or dark as it is, at its scale. A
		// prompt lives for seconds, so it does not watch look.json.
		opts:  uitoolkit.Options{DisableLookWatch: true},
		queue: make(chan *dialog),
		asker: askedBy,
	}
}

// ask shows d and waits for its answer. It is called from the protocol's
// goroutine, never the UI thread.
func (k *desk) ask(d *dialog) answer {
	k.queue <- d
	return <-d.answer
}

// run shows each dialog handed to ask until served says the protocol is
// over, and returns its error.
func (k *desk) run(served <-chan error) error {
	for {
		select {
		case err := <-served:
			return err
		case d := <-k.queue:
			k.show(d)
		}
	}
}

// errNoDisplay is a prompt with nowhere to be shown.
var errNoDisplay = errors.New("there is no desktop to show the prompt on (neither WAYLAND_DISPLAY nor DISPLAY is set)")

// show opens d and runs the window until it is answered.
func (k *desk) show(d *dialog) {
	a, err := k.application()
	if err != nil {
		d.fail(err)
		return
	}
	d.asker = k.who()
	if err := d.open(a); err != nil {
		d.fail(err)
		return
	}
	if err := a.Run(); err != nil {
		d.fail(err)
	}
	// Run ends when the window closes: answered, or taken away by the
	// desktop without an answer, which is a cancel.
	d.fail(svprompt.ErrCanceled)
}

// application is the uitoolkit application, made when the first dialog
// needs it: a probe (GETINFO version) never connects to the display.
func (k *desk) application() (*uitoolkit.Application, error) {
	if k.app == nil {
		k.app = newApplication(k.opts)
	}
	// With no display, uitoolkit falls back to drawing offscreen, where a
	// prompt would wait unseen until it timed out.
	if !k.opts.Headless && k.app.BackendName() == "offscreen" {
		return nil, errNoDisplay
	}
	return k.app, nil
}

// newApplication is the application the dialogs open in: in the look
// opts gives, or else the desktop's (secretui.MatchDesktop).
func newApplication(opts uitoolkit.Options) *uitoolkit.Application {
	a := uitoolkit.New(opts)
	if opts.Look == nil {
		secretui.MatchDesktop(a)
	}
	return a
}

func (k *desk) who() string {
	if !k.askerDone {
		k.askerDone = true
		if k.asker != nil {
			k.askerName = k.asker()
		}
	}
	return k.askerName
}

// askedBy names the program that started this one, for the dialog to say
// who is asking: ssh or sudo for an askpass, gpg-agent for a pinentry.
// When that is the secretvaultd installed beside this program it says
// nothing, because the daemon's own description names the program it is
// asking for, and naming the daemon as well would muddle which one wants
// the vault. Anything else is named, so a prompt started by a program
// pretending to be secretvaultd shows it.
func askedBy() string {
	p, err := svpeer.Describe(os.Getppid())
	if err != nil {
		return ""
	}
	if daemon, ok := besideMe("secretvaultd"); ok && p.Exe == daemon {
		return ""
	}
	return fmt.Sprintf("%s, process %d", p.Display(), p.PID)
}

// besideMe is where the named secretvault program is when it is installed
// beside this one.
func besideMe(name string) (string, bool) {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	exe, err := os.Executable()
	if err != nil {
		return "", false
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Join(filepath.Dir(exe), name), true
}
