package svterm

import (
	"bufio"
	"io"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/internal/ptytest"
	"github.com/codemodify/secretvault/svprompt"
)

// secretvault-tui-prompt's pinentry, on a terminal of the test's own: a
// secret to write down (SETSECRET) is shown set apart from what it is,
// and the answer is typed.
func TestASecretIsShownOnTheTerminalAndAnAnswerChosen(t *testing.T) {
	pty := ptytest.Open(t)
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	go func() { svprompt.Serve(inR, outW, TerminalUI{Default: pty.Path}, "tty"); outW.Close() }()
	lines := bufio.NewScanner(outR)
	read := func() string {
		t.Helper()
		if !lines.Scan() {
			t.Fatal("the prompt went away")
		}
		return lines.Text()
	}
	read() // the greeting
	go func() {
		for _, c := range []string{
			"SETTITLE Recovery key for vault mail",
			"SETDESC Write this recovery key down.",
			"SETSECRET SVRK1-ABCD-EFGH-100%25",
			"ADDCHOICE no-recovery Don't keep a recovery key",
			"ADDCHOICE written I have written it down",
			"CHOOSE",
		} {
			io.WriteString(inW, c+"\n")
		}
	}()
	for range 5 {
		if l := read(); l != "OK" {
			t.Fatalf("the prompt said %q", l)
		}
	}
	pty.Wait(t, "Choose 1-2")
	out := pty.Output()
	desc := strings.Index(out, "Write this recovery key down.")
	key := strings.Index(out, "\n    SVRK1-ABCD-EFGH-100%\r\n")
	if desc < 0 || key < desc || !strings.Contains(out, "2) I have written it down") {
		t.Fatalf("the terminal said:\n%s", out)
	}
	pty.Type(t, "2\n")
	if l := read(); l != "D written" {
		t.Fatalf("the answer: %q", l)
	}
	inW.Close()
}
