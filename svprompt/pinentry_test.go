package svprompt

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// The test binary doubles as a pinentry: with SVPROMPT_TEST_PINENTRY set
// it serves the protocol on stdin/stdout with a scripted UI, so the tests
// run the real client against the real server across a real process.
func TestMain(m *testing.M) {
	if mode := os.Getenv("SVPROMPT_TEST_PINENTRY"); mode != "" {
		var in io.Reader = os.Stdin
		if mode == "plain" || strings.HasPrefix(mode, "plain-") {
			in = hideExtension(os.Stdin)
		}
		Serve(in, os.Stdout, scriptedUI(mode), "test")
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// sawSecretCommand is a plain pinentry having been sent SETSECRET, which
// it must never be: the secret would be on a command it does not know.
var sawSecretCommand bool

// hideExtension makes the server answer ADDCHOICE like a plain pinentry.
func hideExtension(r io.Reader) io.Reader {
	pr, pw := io.Pipe()
	go func() {
		s := bufio.NewScanner(r)
		for s.Scan() {
			line := s.Text()
			sawSecretCommand = sawSecretCommand || strings.HasPrefix(line, "SETSECRET")
			if strings.HasPrefix(line, "ADDCHOICE") || line == "CHOOSE" || strings.HasPrefix(line, "SETSECRET") {
				line = "X" + line
			}
			io.WriteString(pw, line+"\n")
		}
		pw.Close()
	}()
	return pr
}

type scriptedUI string

func (m scriptedUI) GetPin(r Request) ([]byte, error) {
	if s, ok := strings.CutPrefix(string(m), "pin:"); ok {
		// Echo the description back into the answer so the test can see
		// escaping survived: "pin:" + secret, and "|" + description.
		if r.Description == "echo" {
			return []byte(s + "|" + r.Title), nil
		}
		return []byte(s), nil
	}
	if s, ok := strings.CutPrefix(string(m), "long:"); ok {
		return bytes.Repeat([]byte(s), 700), nil
	}
	return nil, ErrCanceled
}

func (m scriptedUI) Confirm(r Request, notOK string) (string, error) {
	if s, ok := strings.CutPrefix(string(m), "plain-secret-"); ok {
		// A plain pinentry has the secret at the end of the description,
		// the default on OK and the other answer on "not OK".
		if !strings.HasSuffix(r.Description, "\n\n"+testSecret) || r.OK != "I have written it down" || notOK != "Don't keep it" || len(r.Secret) != 0 || sawSecretCommand {
			return "", errors.New("the secret was not shown as a plain pinentry shows it")
		}
		return s, nil
	}
	if s, ok := strings.CutPrefix(string(m), "plain-"); ok {
		return s, nil
	}
	return "cancel", nil
}

func (m scriptedUI) Choose(r Request, choices []Choice) (string, error) {
	if m == "secret" {
		// Ours: the secret apart from the description, intact.
		if string(r.Secret) != testSecret || strings.Contains(r.Description, testSecret) {
			return "", errors.New("the secret did not arrive apart and intact")
		}
		return choices[len(choices)-1].ID, nil
	}
	if s, ok := strings.CutPrefix(string(m), "choose:"); ok {
		return s, nil
	}
	return "", ErrCanceled
}

func (m scriptedUI) Message(r Request) error {
	if m == "hold" { // nobody presses the button
		time.Sleep(time.Minute)
	}
	if r.OK != "Cancel" {
		return errors.New("the notice's button is not Cancel")
	}
	return nil
}

func fake(t *testing.T, mode string) *Pinentry {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return &Pinentry{Program: exe, Env: append(os.Environ(), "SVPROMPT_TEST_PINENTRY="+mode)}
}

func tctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestAPassphraseCrossesThePinentryProtocolIntact(t *testing.T) {
	secret := "p%a\ns\\s 100%"
	got, err := fake(t, "pin:"+secret).GetPassphrase(tctx(t), Request{Title: "Unlock 50% of it\nnow", Description: "echo"})
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != secret+"|Unlock 50% of it\nnow" {
		t.Fatalf("got %q", got)
	}
}

func TestLongSecretsSpanSeveralDataLines(t *testing.T) {
	got, err := fake(t, "long:%x").GetPassphrase(tctx(t), Request{})
	if err != nil || string(got) != strings.Repeat("%x", 700) {
		t.Fatalf("got %d bytes, %v", len(got), err)
	}
}

func TestDismissingAPromptIsCanceled(t *testing.T) {
	if _, err := fake(t, "cancel").GetPassphrase(tctx(t), Request{}); !errors.Is(err, ErrCanceled) {
		t.Fatalf("err = %v", err)
	}
	if _, err := fake(t, "cancel").Choose(tctx(t), Request{}, []Choice{{"a", "A"}}); !errors.Is(err, ErrCanceled) {
		t.Fatalf("err = %v", err)
	}
}

// A notice stays until it is withdrawn, which closes the pinentry; its
// one button calls it off.
func TestANoticeStaysUntilWithdrawnOrCalledOff(t *testing.T) {
	c, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := fake(t, "hold").Notice(c, Request{Description: "Touch your security key."}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("withdrawn: %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the notice outlived its withdrawal")
	}
	if err := fake(t, "ok").Notice(tctx(t), Request{Description: "Touch your security key."}); !errors.Is(err, ErrCanceled) {
		t.Fatalf("called off: %v", err)
	}
}

// testSecret is a recovery key's stand-in, with what needs escaping.
const testSecret = "SVRK1-ABCD-%25-100%\\-EFGH"

var showing = []Choice{{"no-recovery", "Don't keep it"}, {"written", "I have written it down"}}

// A secret to write down goes apart from the description to our own
// prompts, and at the end of it to any other pinentry.
func TestASecretIsShownApartOrAtTheEnd(t *testing.T) {
	r := Request{Title: "Recovery key for vault mail", Description: "Write this down."}
	got, err := fake(t, "secret").ShowSecret(tctx(t), r, []byte(testSecret), showing)
	if err != nil || got != "written" {
		t.Fatalf("ours: %q, %v", got, err)
	}
	for mode, want := range map[string]string{"plain-secret-ok": "written", "plain-secret-notok": "no-recovery"} {
		got, err := fake(t, mode).ShowSecret(tctx(t), r, []byte(testSecret), showing)
		if err != nil || got != want {
			t.Errorf("%s: %q, %v; want %q", mode, got, err, want)
		}
	}
	if _, err := fake(t, "plain-cancel").ShowSecret(tctx(t), r, []byte(testSecret), showing); !errors.Is(err, ErrCanceled) {
		t.Errorf("dismissed: %v", err)
	}
	if _, err := fake(t, "cancel").ShowSecret(tctx(t), r, []byte(testSecret), showing); !errors.Is(err, ErrCanceled) {
		t.Errorf("dismissed: %v", err)
	}
}

// keepUI is a UI that keeps the secret it was shown, to see it wiped.
type keepUI struct {
	scriptedUI
	shown chan []byte
}

func (u keepUI) Choose(r Request, choices []Choice) (string, error) {
	u.shown <- r.Secret
	return choices[0].ID, nil
}

// The server reads SETSECRET's secret from the line's bytes, and wipes it
// when the session moves on.
func TestTheServerWipesASecretShown(t *testing.T) {
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	ui := keepUI{shown: make(chan []byte, 1)}
	go func() { Serve(inR, outW, ui, "test"); outW.Close() }()
	lines := bufio.NewScanner(outR)
	read := func() string {
		if !lines.Scan() {
			t.Fatal("the server went away")
		}
		return lines.Text()
	}
	read() // the greeting
	// Written from a goroutine: the server answers each command before
	// it reads the next, and its answers wait for this side to read them.
	send := func(cmds ...string) {
		go func() {
			for _, c := range cmds {
				io.WriteString(inW, c+"\n")
			}
		}()
	}
	send("SETSECRET "+escape(testSecret), "ADDCHOICE a A", "CHOOSE")
	if l := read(); l != "OK" {
		t.Fatal(l)
	}
	read()
	shown := <-ui.shown
	if string(shown) != testSecret {
		t.Fatalf("the secret arrived as %q", shown)
	}
	read()
	read()
	send("RESET")
	read()
	if strings.Trim(string(shown), "\x00") != "" {
		t.Fatalf("the secret was left as %q", shown)
	}
	send("SETSECRET " + strings.Repeat("x", 1200))
	if l := read(); !strings.HasPrefix(l, "ERR") {
		t.Fatalf("a line past the limit: %q", l)
	}
	inW.Close()
}

var consent = []Choice{{"once", "Allow once"}, {"until-lock", "Allow until locked"}, {"always", "Always allow"}, {"deny", "Deny"}}

func TestOurOwnPromptsOfferEveryChoice(t *testing.T) {
	got, err := fake(t, "choose:always").Choose(tctx(t), Request{Title: "Mail wants a secret"}, consent)
	if err != nil || got != "always" {
		t.Fatalf("got %q, %v", got, err)
	}
	if _, err := fake(t, "choose:bogus").Choose(tctx(t), Request{}, consent); err == nil {
		t.Fatal("a choice that was not offered was accepted")
	}
}

func TestPlainPinentriesGetThreeButtons(t *testing.T) {
	for mode, want := range map[string]string{"plain-ok": "once", "plain-notok": "until-lock", "plain-cancel": "deny"} {
		got, err := fake(t, mode).Choose(tctx(t), Request{}, consent)
		if err != nil || got != want {
			t.Errorf("%s: got %q, %v; want %q", mode, got, err, want)
		}
	}
}

// TestTheSystemPinentryAnswersAProbe checks our side of the protocol
// against the real program. It shows nothing and touches nothing: the
// pinentry gets no display and no session bus (only PATH), and is asked
// for its version alone.
func TestTheSystemPinentryAnswersAProbe(t *testing.T) {
	for _, p := range []string{"/usr/bin/pinentry-tty", "/usr/bin/pinentry"} {
		if _, err := os.Stat(p); err != nil {
			continue
		}
		v, err := (&Pinentry{Program: p, Env: []string{"PATH=/usr/bin"}}).Probe(tctx(t))
		if err != nil {
			t.Fatalf("%s: %v", p, err)
		}
		if v == "" {
			t.Fatalf("%s gave no version", p)
		}
		return
	}
	t.Skip("no system pinentry")
}

func TestRelativeProgramsAreRefused(t *testing.T) {
	if _, err := (&Pinentry{Program: "pinentry"}).Probe(tctx(t)); err == nil {
		t.Fatal("a pinentry looked up on PATH was run")
	}
}

func TestEscapingRoundTrips(t *testing.T) {
	for _, s := range []string{"", "plain", "100%", "a\nb\r\nc", "%%0A", "\\end\\"} {
		if got := unescape(escape(s)); got != s {
			t.Errorf("escape round trip of %q gave %q", s, got)
		}
		if got := string(appendUnescaped(nil, appendData(nil, []byte(s)))); got != s {
			t.Errorf("data round trip of %q gave %q", s, got)
		}
	}
}

// A long secret goes out as several D lines, none over the limit and none
// splitting an escape, and comes back whole.
func TestDataLinesKeepToTheLimit(t *testing.T) {
	secret := bytes.Repeat([]byte("ab%\n"), 600)
	var out bytes.Buffer
	if err := writeData(&out, secret); err != nil {
		t.Fatal(err)
	}
	var got []byte
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	if len(lines) < 2 {
		t.Fatalf("%d line(s)", len(lines))
	}
	for _, l := range lines {
		if len(l) > maxLine || !strings.HasPrefix(l, "D ") {
			t.Fatalf("line of %d bytes: %.20q", len(l), l)
		}
		if i := strings.LastIndexByte(l, '%'); i >= 0 && i > len(l)-3 {
			t.Fatalf("an escape is split: ...%q", l[len(l)-5:])
		}
		got = appendUnescaped(got, []byte(l[2:]))
	}
	if !bytes.Equal(got, secret) {
		t.Fatal("the secret did not come back whole")
	}
	if out.Reset(); writeData(&out, nil) != nil || out.Len() != 0 {
		t.Fatalf("an empty secret sent %q", out.String())
	}
}

// The reader the daemon hears a pinentry through wipes each line once the
// next is read, and everything when the session ends.
func TestTheLineReaderWipesWhatItRead(t *testing.T) {
	l := newLineReader(strings.NewReader("D s3cret\nOK\n"))
	line, err := l.next()
	if err != nil || string(line) != "D s3cret" {
		t.Fatalf("%q, %v", line, err)
	}
	if line, err = l.next(); err != nil || string(line) != "OK" {
		t.Fatalf("%q, %v", line, err)
	}
	if bytes.Contains(l.buf, []byte("s3cret")) {
		t.Fatal("the D line is still in the buffer after the next line was read")
	}
	l.wipe()
	if bytes.ContainsFunc(l.buf, func(r rune) bool { return r != 0 }) {
		t.Fatal("wipe left bytes behind")
	}
	if _, err := l.next(); !errors.Is(err, io.EOF) {
		t.Fatalf("after the end: %v", err)
	}
}

func TestButtonLabelsLoseTheirMnemonics(t *testing.T) {
	for in, want := range map[string]string{"_OK": "OK", "_Cancel": "Cancel", "Allow once": "Allow once", "a__b": "a_b", "__init__": "_init_"} {
		if got := plainLabel(in); got != want {
			t.Errorf("plainLabel(%q) = %q, want %q", in, got, want)
		}
	}
	for _, s := range []string{"a_b", "_", "Allow until the vault locks"} {
		if got := plainLabel(label(s)); got != s {
			t.Errorf("label round trip of %q gave %q", s, got)
		}
	}
}
