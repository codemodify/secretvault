package main

import (
	"context"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/internal/ptytest"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svterm"
)

// The terminal agent (--agent), on a terminal of the test's own: what the
// daemon asks when a program wants a new vault, as the person sees it.
func TestTheAgentShowsANewVaultsQuestionsAndItsRecoveryKey(t *testing.T) {
	pty := ptytest.Open(t)
	term, err := svterm.OpenTerminal(pty.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer term.Close()
	answer := answerOn(term)
	ask := func(q svrpc.PromptAsk, typed string) svrpc.PromptAnswer {
		t.Helper()
		got := make(chan svrpc.PromptAnswer, 1)
		go func() {
			a, _ := answer(context.Background(), q)
			got <- a
		}()
		// Typed once the question has been put, all of it.
		pty.Wait(t, q.Title)
		pty.Wait(t, q.Choices[len(q.Choices)-1].Label)
		pty.Type(t, typed)
		return <-got
	}

	a := ask(svrpc.PromptAsk{Kind: svrpc.PromptChoose, Title: `comms-mail wants a new vault called "mail"`,
		Description: "comms-mail asks for a new, empty vault.",
		Choices: []svrpc.Choice{{ID: svrpc.ChoiceCreate, Label: "Create the vault"}, {ID: svrpc.ChoiceNever, Label: "Don't ask again for this program"},
			{ID: svrpc.ChoiceDeny, Label: "Don't create it"}}}, "1\n")
	if a.Choice != svrpc.ChoiceCreate || !strings.Contains(pty.Output(), "3) Don't create it") {
		t.Fatalf("the question: %+v\n%s", a, pty.Output())
	}

	a = ask(svrpc.PromptAsk{Kind: svrpc.PromptShowSecret, Title: "Recovery key for vault mail",
		Description: "Write this recovery key down.", Show: "SVRK1-TEST-KEY",
		Choices: []svrpc.Choice{{ID: svrpc.ChoiceNoRecovery, Label: "Don't keep a recovery key"}, {ID: svrpc.ChoiceWritten, Label: "I have written it down"}}}, "2\n")
	out := pty.Output()
	if a.Choice != svrpc.ChoiceWritten || strings.Index(out, "\n    SVRK1-TEST-KEY") < strings.Index(out, "Write this recovery key down.") {
		t.Fatalf("the recovery key: %+v\n%s", a, out)
	}

	// Enter alone is no answer: dismissed.
	a = ask(svrpc.PromptAsk{Kind: svrpc.PromptShowSecret, Title: "Recovery key for vault other", Show: "SVRK1-OTHER",
		Choices: []svrpc.Choice{{ID: svrpc.ChoiceNoRecovery, Label: "Don't keep a recovery key"}, {ID: svrpc.ChoiceWritten, Label: "I have written it down"}}}, "\n")
	if !a.Canceled {
		t.Fatalf("dismissed: %+v", a)
	}
}
