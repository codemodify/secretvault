package main

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svprompt"
	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/a11y/a11ytest"
	"github.com/codemodify/uitoolkit/diag"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// The tests drive the prompt the way secretvaultd and gpg-agent do: the
// pinentry protocol over a pipe to svprompt.Serve, with this program's
// dialogs as its UI. The test goroutine stands in for the UI thread. It
// takes each dialog Serve hands over, opens it in a headless window, and
// types and clicks into it with uitoolkit's own drivers, so a key takes
// the path a real one takes.
//
// Nothing here opens a window on a display, reads a clipboard or reaches
// a bus: TestMain takes the display, the session bus and the user's
// directories away before anything runs.
func TestMain(m *testing.M) {
	tmp, err := os.MkdirTemp("", "svguiprompt")
	if err != nil {
		panic(err)
	}
	for k, v := range map[string]string{
		"DISPLAY": "", "WAYLAND_DISPLAY": "", "UITK_BACKEND": "",
		"DBUS_SESSION_BUS_ADDRESS": "unix:path=" + filepath.Join(tmp, "no-bus"),
		"XDG_RUNTIME_DIR":          tmp, "XDG_CONFIG_HOME": filepath.Join(tmp, "config"),
		"XDG_DATA_HOME": filepath.Join(tmp, "data"), "XDG_CACHE_HOME": filepath.Join(tmp, "cache"),
		// The bundled typefaces, so what is measured does not depend on
		// what this machine has installed.
		"UITK_SYSTEM_FONTS": "0",
	} {
		os.Setenv(k, v)
	}
	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

// Serve's ERR codes: GPG_ERR_SOURCE_PINENTRY (5) in the top byte.
const (
	errCanceledLine = "ERR 83886179 Operation cancelled"
	errTimeoutLine  = "ERR 83886142 Timeout"
	errNotConfirmed = "ERR 83886194 Not confirmed"
)

// harness is one pinentry session with the prompt.
type harness struct {
	t     *testing.T
	k     *desk
	app   *uitoolkit.Application
	cmds  chan string
	lines chan string
	pins  chan []byte // what the UI handed Serve, to see it wiped
}

// recordingUI keeps each passphrase the dialogs handed Serve, so a test
// can check Serve wiped it after sending.
type recordingUI struct {
	pinentryUI
	pins chan []byte
}

func (u recordingUI) GetPin(r svprompt.Request) ([]byte, error) {
	p, err := u.pinentryUI.GetPin(r)
	if p != nil {
		u.pins <- p
	}
	return p, err
}

func newHarness(t *testing.T, look style.LookAndFeel) *harness {
	t.Helper()
	return newHarnessAt(t, look, 0)
}

// newHarnessAt is newHarness at a display scale (0 is 1x).
func newHarnessAt(t *testing.T, look style.LookAndFeel, scale float32) *harness {
	t.Helper()
	k := newDesk()
	k.opts = uitoolkit.Options{Headless: true, Look: look, Scale: scale, DisableLookWatch: true}
	k.asker = func() string { return "" }
	k.app = uitoolkit.New(k.opts)
	h := &harness{t: t, k: k, app: k.app, cmds: make(chan string, 64), lines: make(chan string, 64), pins: make(chan []byte, 8)}

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() {
		svprompt.Serve(inR, outW, recordingUI{pinentryUI{k}, h.pins}, "uitoolkit")
		outW.Close()
	}()
	go func() {
		for c := range h.cmds {
			io.WriteString(inW, c+"\n")
		}
		inW.Close()
	}()
	go func() {
		s := bufio.NewScanner(outR)
		for s.Scan() {
			h.lines <- s.Text()
		}
		close(h.lines)
	}()
	t.Cleanup(func() { close(h.cmds) })
	if l := h.reply(); !strings.HasPrefix(l, "OK Pleased to meet you") {
		t.Fatalf("greeting %q", l)
	}
	return h
}

func (h *harness) send(cmd string) { h.cmds <- cmd }

// reply is the prompt's next line. Meanwhile it runs the UI thread's
// frames, as the real loop would, so timers fire.
func (h *harness) reply() string {
	h.t.Helper()
	deadline := time.After(10 * time.Second)
	for {
		select {
		case l, ok := <-h.lines:
			if !ok {
				h.t.Fatal("the prompt closed its output")
			}
			return l
		case <-deadline:
			h.t.Fatal("no reply from the prompt")
		case <-time.After(5 * time.Millisecond):
			h.app.PumpOnce()
		}
	}
}

func (h *harness) expect(want string) {
	h.t.Helper()
	if got := h.reply(); got != want {
		h.t.Fatalf("the prompt said %q, want %q", got, want)
	}
}

// do sends commands that each answer OK.
func (h *harness) do(cmds ...string) {
	h.t.Helper()
	for _, c := range cmds {
		h.send(c)
		h.expect("OK")
	}
}

// dialog takes the next dialog Serve hands over and opens it, as the UI
// thread does, laid out and focused.
func (h *harness) dialog() *dialog {
	h.t.Helper()
	select {
	case d := <-h.k.queue:
		d.asker = h.k.who()
		if err := d.open(h.app); err != nil {
			h.t.Fatal(err)
		}
		h.app.PumpOnce()
		return d
	case <-time.After(10 * time.Second):
		h.t.Fatal("no dialog was opened")
	}
	return nil
}

func surface(t *testing.T, d *dialog) *platform.Offscreen {
	t.Helper()
	o, ok := d.win.Surface().(*platform.Offscreen)
	if !ok {
		t.Fatalf("surface %T", d.win.Surface())
	}
	return o
}

func TestAPassphraseIsTypedAndSentOnADataLine(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.do("SETTITLE Unlock vault Personal", "SETDESC mail wants a secret.%0A%0AEnter the passphrase.", "SETPROMPT Passphrase:")
	h.send("GETPIN")
	d := h.dialog()

	// A dialog, centred, asked to stay above, activated, out of screen
	// captures, and holding the keyboard with no input method while the
	// field has it.
	o := surface(t, d)
	if o.WindowRole() != platform.RoleDialog || !o.Centered() || !o.KeepAboveRequested() || o.Activations() == 0 {
		t.Fatalf("role %v, centred %v, above %v, activated %d", o.WindowRole(), o.Centered(), o.KeepAboveRequested(), o.Activations())
	}
	if o.Sizing() != platform.SizingFixed {
		t.Fatalf("sizing %v", o.Sizing())
	}
	if !o.ExcludeFromCapture() {
		t.Fatal("the dialog did not ask to stay out of screen captures")
	}
	if d.win.Focus() != d.pin || !o.SecureInput() || !d.frame.Holding() {
		t.Fatalf("focus %T, secure input %v", d.win.Focus(), o.SecureInput())
	}
	if _, _, _, _, ime := o.IMECursor(); ime {
		t.Fatal("the input method is on in the passphrase field")
	}
	if got := d.frame.Header().Title; got != "Unlock vault Personal" {
		t.Fatalf("header %q", got)
	}

	// Escapes survive: '%', '\\' and a space, typed as a keyboard would.
	d.win.Type(`correct horse 100%\`)
	if d.pin.Len() != 19 {
		t.Fatalf("the field holds %d runes", d.pin.Len())
	}
	d.win.Press(platform.KeyReturn)
	h.expect(`D correct horse 100%25%5C`)
	h.expect("OK")

	if !d.win.Closed() || o.SecureInput() || !d.pin.Empty() {
		t.Fatalf("after the answer: closed %v, secure input %v, field empty %v", d.win.Closed(), o.SecureInput(), d.pin.Empty())
	}
	if p := <-h.pins; bytes.ContainsFunc(p, func(r rune) bool { return r != 0 }) {
		t.Fatal("the passphrase handed to Serve was not wiped after it was sent")
	}
}

func TestEscapeAndCancelRefuse(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.send("GETPIN")
	d := h.dialog()
	d.win.Type("half typed")
	d.win.Press(platform.KeyEscape)
	h.expect(errCanceledLine)
	if !d.pin.Empty() {
		t.Fatal("a cancelled passphrase was left in the field")
	}

	h.send("GETPIN")
	d = h.dialog()
	if !d.win.ClickComponent(d.buttons["cancel"]) {
		t.Fatal("no Cancel button to click")
	}
	h.expect(errCanceledLine)

	// The window manager's close button is a cancel too.
	h.send("GETPIN")
	d = h.dialog()
	d.win.Inject(platform.Event{Kind: platform.EventClose})
	h.app.PumpOnce()
	h.expect(errCanceledLine)
}

func TestAWrongPassphraseIsSaidAndTheOKButtonAnswers(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.do("SETERROR That passphrase does not open this vault.", "SETOK _Unlock")
	h.send("GETPIN")
	d := h.dialog()
	if d.problem == nil || d.problem.Text != "That passphrase does not open this vault." {
		t.Fatalf("error line %+v", d.problem)
	}
	if d.buttons["ok"].Text != "Unlock" {
		t.Fatalf("OK button %q: the mnemonic marker should be gone", d.buttons["ok"].Text)
	}
	d.win.Type("second try")
	d.win.ClickComponent(d.buttons["ok"])
	h.expect("D second try")
	h.expect("OK")
}

func TestATimeoutCancelsThePrompt(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.do("SETTIMEOUT 1")
	h.send("GETPIN")
	d := h.dialog()
	d.win.Type("too slow")
	start := time.Now()
	h.expect(errTimeoutLine)
	if waited := time.Since(start); waited < 500*time.Millisecond {
		t.Fatalf("timed out after %v", waited)
	}
	if !d.win.Closed() || !d.pin.Empty() {
		t.Fatal("a timed-out prompt was left open, or its field full")
	}
}

func TestANewPassphraseMustBeTypedTheSameTwice(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.do("SETREPEAT Repeat:", "SETREPEATERROR The two do not match.")
	h.send("GETPIN")
	d := h.dialog()
	if d.repeat == nil {
		t.Fatal("no second field")
	}

	d.win.Type("tr0ub4dor")
	d.win.Press(platform.KeyReturn) // on to the second field
	if d.win.Focus() != d.repeat {
		t.Fatalf("Enter in the first field left the focus on %T", d.win.Focus())
	}
	d.win.Type("tr0ub4dor&3")
	d.win.Press(platform.KeyReturn)
	if d.problem.Text != "The two do not match." || !d.repeat.Empty() || d.win.Closed() {
		t.Fatalf("mismatch: error %q, second field emptied %v, closed %v", d.problem.Text, d.repeat.Empty(), d.win.Closed())
	}
	if d.win.Focus() != d.repeat || !surface(t, d).SecureInput() {
		t.Fatal("after a mismatch the second field should have the keyboard, held")
	}

	d.win.Type("tr0ub4dor")
	d.win.Press(platform.KeyReturn)
	h.expect("S PIN_REPEATED")
	h.expect("D tr0ub4dor")
	h.expect("OK")
}

// The keyboard is held while a passphrase field has it, and let go while
// a button does; the header says it is held while it is.
func TestTheKeyboardIsHeldOnlyInTheField(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.send("GETPIN")
	d := h.dialog()
	o := surface(t, d)
	if !o.SecureInput() || !d.frame.Header().Held() {
		t.Fatalf("not held in the field, or not said: %v", d.frame.Header().Held())
	}
	d.win.Press(platform.KeyTab)
	if _, ok := d.win.Focus().(*widgets.Button); !ok || o.SecureInput() || d.frame.Header().Held() {
		t.Fatalf("on %T the keyboard is held: %v", d.win.Focus(), o.SecureInput())
	}
	d.win.FocusOn(d.pin)
	if !o.SecureInput() || !d.frame.Header().Held() {
		t.Fatal("not held again back in the field")
	}
	d.win.Press(platform.KeyEscape)
	h.expect(errCanceledLine)
}

// A passphrase dialog says when Caps Lock is on, beside its buttons, and
// takes no room for it: the dialog keeps its height and its buttons their
// place. Nothing that is not asking for a passphrase says it.
func TestAPassphraseDialogSaysCapsLockIsOn(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.do("SETDESC mail wants a secret.%0A%0AEnter the passphrase.")
	h.send("GETPIN")
	d := h.dialog()
	o := surface(t, d)
	if d.caps == nil || d.caps.On() {
		t.Fatal("a Caps Lock line is showing with Caps Lock off")
	}
	_, height := d.win.Size()
	ok := widget.DeviceOrigin(d.buttons["ok"])

	// Caps Lock pressed: the press carries the state before, the
	// release the state after.
	d.win.Inject(platform.Event{Kind: platform.EventKeyDown})
	o.SetLockKeys(true, false)
	d.win.Inject(platform.Event{Kind: platform.EventKeyUp, Mods: platform.ModCapsLock})
	h.app.PumpOnce()
	if !d.caps.On() || d.caps.Bounds().Empty() || d.caps.Text != "Caps Lock is on" {
		t.Fatal("Caps Lock is on and the dialog does not say so")
	}
	if _, now := d.win.Size(); now != height || widget.DeviceOrigin(d.buttons["ok"]) != ok {
		t.Fatalf("the dialog moved to say it: %d tall, was %d; OK at %v, was %v", now, height, widget.DeviceOrigin(d.buttons["ok"]), ok)
	}
	d.win.Type("SECRET")
	d.win.Press(platform.KeyA, platform.ModCapsLock)
	d.win.Inject(platform.Event{Kind: platform.EventKeyDown, Mods: platform.ModCapsLock})
	o.SetLockKeys(false, false)
	d.win.Inject(platform.Event{Kind: platform.EventKeyUp})
	h.app.PumpOnce()
	if d.caps.On() {
		t.Fatal("Caps Lock is off and the dialog still says it is on")
	}
	d.win.Press(platform.KeyEscape)
	h.expect(errCanceledLine)

	h.do("RESET", "SETDESC Do you really want to delete the key?")
	h.send("CONFIRM")
	d = h.dialog()
	if d.caps != nil {
		t.Fatal("a confirmation watches Caps Lock")
	}
	d.win.Press(platform.KeyEscape)
	h.expect(errCanceledLine)
}

// A dialog is the same size at any display scale, in the desktop's
// logical pixels: its spacing scales with the display as its text and
// controls do, once (uitoolkit-gaps.md, 14).
func TestADialogIsTheSameAtEveryScale(t *testing.T) {
	size := func(scale float32) (int, int) {
		h := newHarnessAt(t, uitoolkit.LightLook(), scale)
		h.do("SETTITLE Allow access to vault Personal?",
			"SETDESC mail (/usr/bin/mail) wants to read \"imap\" in vault \"Personal\".%0A%0AProgram: /usr/bin/mail%0AProcess: 4242")
		h.do(consent...)
		h.send("CHOOSE")
		d := h.dialog()
		w, ht := d.win.Size()
		d.win.Press(platform.KeyEscape)
		h.expect(errCanceledLine)
		return w, ht
	}
	w1, h1 := size(1)
	w2, h2 := size(2)
	if w2 < w1-2 || w2 > w1+2 || h2 < h1-6 || h2 > h1+6 {
		t.Fatalf("%dx%d at 1x, %dx%d at 2x", w1, h1, w2, h2)
	}
}

var consent = []string{
	"ADDCHOICE once Allow once",
	"ADDCHOICE until-lock Allow until the vault locks",
	"ADDCHOICE always Always allow",
	"ADDCHOICE deny Deny",
}

func TestConsentOffersEveryChoiceAndDenyIsTheDefault(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.do("SETTITLE Allow access to vault Personal?",
		"SETDESC mail (/usr/bin/mail) wants to read \"imap\" in vault \"Personal\".%0A%0AProgram: /usr/bin/mail%0AProcess: 4242")
	h.do(consent...)
	h.send("CHOOSE")
	d := h.dialog()
	for _, id := range []string{"once", "until-lock", "always", "deny"} {
		if d.buttons[id] == nil {
			t.Fatalf("no %q button", id)
		}
	}
	if !d.buttons["deny"].Primary || d.win.Focus() != d.buttons["deny"] {
		t.Fatalf("the default is not Deny: focus %v", d.win.Focus())
	}
	if surface(t, d).SecureInput() {
		t.Fatal("the keyboard is held with no passphrase field")
	}
	// The program is set out as facts, a line each. Their values wrap
	// when they are too long for the line, and a short one measured at
	// its own width is still one line (uitoolkit-gaps.md, 17): the form
	// is not measured taller than its two lines.
	if len(d.factValues) != 2 || d.factValues[0].Text != "/usr/bin/mail" || d.factValues[1].Text != "4242" {
		t.Fatalf("%d facts", len(d.factValues))
	}
	if !d.factValues[0].Wrap {
		t.Fatal("a fact's value does not wrap")
	}
	line := d.win.Look().Font().Height()
	if h := d.factValues[0].Parent().Bounds().Dy(); h > 2.6*line {
		t.Fatalf("two facts take %v, a line is %v", h, line)
	}
	d.win.ClickComponent(d.buttons["until-lock"])
	h.expect("D until-lock")
	h.expect("OK")

	// Enter, unread, denies.
	h.do(consent...)
	h.send("CHOOSE")
	d = h.dialog()
	d.win.Press(platform.KeyReturn)
	h.expect("D deny")
	h.expect("OK")

	// Escape is a cancel, which secretvaultd takes as no.
	h.do(consent...)
	h.send("CHOOSE")
	d = h.dialog()
	d.win.Press(platform.KeyEscape)
	h.expect(errCanceledLine)
}

// A plain CONFIRM (gpg-agent's questions): OK, a "not OK" when one was
// set, and Cancel.
func TestConfirmHasItsThreeAnswers(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.do("SETDESC Do you really want to delete the key?", "SETOK _Yes", "SETNOTOK _No")
	h.send("CONFIRM")
	d := h.dialog()
	if d.buttons["ok"].Text != "Yes" || d.buttons["notok"].Text != "No" || d.buttons["cancel"].Text != "Cancel" {
		t.Fatalf("buttons %q %q %q", d.buttons["ok"].Text, d.buttons["notok"].Text, d.buttons["cancel"].Text)
	}
	d.win.ClickComponent(d.buttons["notok"])
	h.expect(errNotConfirmed)

	h.send("CONFIRM")
	d = h.dialog()
	d.win.Press(platform.KeyReturn)
	h.expect("OK")

	h.send("CONFIRM")
	d = h.dialog()
	d.win.Press(platform.KeyEscape)
	h.expect(errCanceledLine)
}

func TestAMessageHasOneButton(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.do("SETDESC The key was imported.")
	h.send("MESSAGE")
	d := h.dialog()
	if len(d.buttons) != 1 {
		t.Fatalf("%d buttons", len(d.buttons))
	}
	d.win.Press(platform.KeyReturn)
	h.expect("OK")

	h.send("CONFIRM --one-button")
	d = h.dialog()
	d.win.ClickComponent(d.buttons["ok"])
	h.expect("OK")
}

// A probe only asks what the program is: no display is touched and no
// window made.
func TestAProbeOpensNoWindow(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.send("GETINFO version")
	h.expect("D secretvault-1")
	h.expect("OK")
	h.send("GETINFO flavor")
	h.expect("D uitoolkit")
	h.expect("OK")
	if n := len(h.app.Windows()); n != 0 {
		t.Fatalf("%d windows", n)
	}
}

// With no desktop the prompt says so at once rather than waiting unseen.
func TestWithNoDisplayThePromptRefusesAtOnce(t *testing.T) {
	k := newDesk()
	k.asker = func() string { return "" }
	d := newDialog(askPIN, svprompt.Request{})
	k.show(d) // DISPLAY and WAYLAND_DISPLAY are empty (TestMain)
	a := <-d.answer
	if a.err != errNoDisplay || a.secret != nil {
		t.Fatalf("answer %+v", a)
	}
}

// The program that started the prompt is named, unless it is the daemon.
func TestTheAskerIsNamed(t *testing.T) {
	h := newHarness(t, uitoolkit.LightLook())
	h.k.asker = func() string { return "ssh (/usr/bin/ssh), process 77" }
	h.do("SETDESC Enter passphrase for key '/home/ada/.ssh/id_ed25519':")
	h.send("GETPIN")
	d := h.dialog()
	if !labelled(d, "Asked by:") || !labelled(d, "ssh (/usr/bin/ssh), process 77") {
		t.Fatal("the asker is not shown")
	}
	d.win.Press(platform.KeyEscape)
	h.expect(errCanceledLine)
}

func labelled(d *dialog, text string) bool {
	found := false
	var walk func(c interface{ Children() []uitoolkit.Component })
	walk = func(c interface{ Children() []uitoolkit.Component }) {
		for _, ch := range c.Children() {
			if l, ok := ch.(*widgets.Label); ok && l.Text == text {
				found = true
			}
			walk(ch)
		}
	}
	walk(d.frame)
	return found
}

func TestDescriptionsNameTheProgramAsFacts(t *testing.T) {
	paras, facts := splitDescription("mail (/usr/bin/mail) wants to read \"imap\".\n\nProgram: /usr/bin/mail\nProcess: 4242")
	if len(paras) != 1 || len(facts) != 2 || facts[0] != (fact{"Program", "/usr/bin/mail"}) || facts[1] != (fact{"Process", "4242"}) {
		t.Fatalf("paras %q, facts %q", paras, facts)
	}
	// Prose that merely holds a colon stays prose.
	for _, desc := range []string{
		"Please enter the passphrase to unlock the OpenPGP secret key:\n\"Alice <alice@example.com>\"",
		"Enter passphrase for key '/home/ada/.ssh/id_ed25519': ",
		"note: lower case is not a label",
	} {
		if _, facts := splitDescription(desc); facts != nil {
			t.Errorf("%q gave facts %q", desc, facts)
		}
	}
	if paras, _ := splitDescription("one\r\ntwo\n\n\n\nthree"); len(paras) != 2 || len(paras[0]) != 2 {
		t.Fatalf("paragraphs %q", paras)
	}
}

// The passphrase must never become a string: a Go string cannot be
// wiped. dialog.go is the code that handles it, and it converts nothing
// to a string at all; one conversion reached for out of habit would undo
// the SecretField and show up in no behavioural test.
func TestTheDialogsMakeNoStrings(t *testing.T) {
	src, err := os.ReadFile("dialog.go")
	if err != nil {
		t.Fatal(err)
	}
	code := regexp.MustCompile(`(?m)//.*$`).ReplaceAll(src, nil)
	if i := bytes.Index(code, []byte("string(")); i >= 0 {
		line := bytes.Count(src[:i], []byte("\n")) + 1
		t.Fatalf("dialog.go:%d converts to a string", line)
	}
	for _, bad := range []string{"fmt.", "strconv."} {
		if bytes.Contains(code, []byte(bad)) {
			t.Fatalf("dialog.go uses %s, which formats into strings", bad)
		}
	}
}

// A second answer racing the first (a click as the timeout fires) is
// dropped, and a secret in it wiped.
func TestOnlyTheFirstAnswerCounts(t *testing.T) {
	d := newDialog(askPIN, svprompt.Request{})
	d.finish(answer{err: svprompt.ErrTimeout})
	late := []byte("late")
	d.finish(answer{secret: late})
	if a := <-d.answer; a.err != svprompt.ErrTimeout {
		t.Fatalf("answer %+v", a)
	}
	if string(late) != "\x00\x00\x00\x00" {
		t.Fatalf("the late secret was left as %q", late)
	}
	select {
	case a := <-d.answer:
		t.Fatalf("a second answer went out: %+v", a)
	default:
	}
}

// Every kind of dialog passes an accessibility audit, and what it says
// is read aloud: the program asking, not only the word "Program" beside
// it, and in a passphrase dialog that the keyboard is held. The keyboard
// goes from the field to the second field, OK and
// Cancel, and round again. And the toolkit did everything it was told.
func TestTheDialogsAreAccessible(t *testing.T) {
	h := newHarness(t, nil)
	h.do("SETTITLE Allow access to vault Personal?",
		"SETDESC mail (/usr/bin/mail) wants to read \"imap\".%0A%0AProgram: /usr/bin/mail%0AProcess: 4242")
	h.do(consent...)
	h.send("CHOOSE")
	d := h.dialog()
	tree := a11ytest.Audit(t, "consent", d.win.AccessibleTree())
	var read []string
	tree.Walk(func(n *a11y.Node) bool {
		read = append(read, n.Name)
		return true
	})
	for _, want := range []string{"Program:", "/usr/bin/mail", "Process:", "4242", "Deny"} {
		if !slicesContains(read, want) {
			t.Errorf("a screen reader does not hear %q: %q", want, read)
		}
	}
	d.win.Press(platform.KeyEscape)
	h.expect(errCanceledLine)

	h.do("RESET", "SETPROMPT Passphrase:", "SETREPEAT Repeat:")
	h.send("GETPIN")
	d = h.dialog()
	held := false
	a11ytest.Audit(t, "new passphrase", d.win.AccessibleTree()).Walk(func(n *a11y.Node) bool {
		held = held || n.Description == "Keyboard held"
		return true
	})
	if !held {
		t.Error("a screen reader is not told the keyboard is held")
	}
	order := []widget.Component{d.pin, d.repeat, d.buttons["ok"], d.buttons["cancel"], d.pin}
	for i, want := range order {
		if d.win.Focus() != want {
			t.Fatalf("Tab %d: the keyboard is on %T", i, d.win.Focus())
		}
		d.win.Press(platform.KeyTab)
	}
	d.win.Press(platform.KeyEscape)
	h.expect(errCanceledLine)

	for _, f := range uitoolkit.Diagnostics() {
		if f.Level == diag.Warn {
			t.Errorf("uitoolkit did not do what it was told: %v", f)
		}
	}
}

func slicesContains(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}
