// Command secretvault-tui-prompt asks a person for a secret or a decision
// on a terminal. It has three ways to run:
//
//	secretvault-tui-prompt           a pinentry: speaks the Assuan protocol on
//	                                 stdin/stdout, as gpg-agent and secretvaultd
//	                                 expect (pinentry-program in gpg-agent.conf)
//	secretvault-tui-prompt PROMPT    an askpass helper: asks on the terminal and
//	                                 prints the answer (SSH_ASKPASS, SUDO_ASKPASS,
//	                                 GIT_ASKPASS)
//	secretvault-tui-prompt --agent   answers secretvaultd's prompts in this
//	                                 terminal, for sessions without a desktop,
//	                                 like pkttyagent does for polkit
package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svprompt"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svterm"
)

func main() {
	_ = svcrypto.NoCoreDumps()
	args := os.Args[1:]
	switch {
	case len(args) == 0:
		if err := svprompt.Serve(os.Stdin, os.Stdout, svterm.TerminalUI{}, "tty"); err != nil {
			fmt.Fprintln(os.Stderr, "secretvault-tui-prompt:", err)
			os.Exit(1)
		}
	case args[0] == "--agent":
		os.Exit(agent())
	case args[0] == "-h" || args[0] == "--help":
		fmt.Fprintln(os.Stderr, "usage: secretvault-tui-prompt [PROMPT | --agent]")
	default:
		os.Exit(askpass(strings.Join(args, " ")))
	}
}

// askpass asks for one secret and prints it, as askpass helpers do.
func askpass(prompt string) int {
	t, err := svterm.OpenTerminal("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "secretvault-tui-prompt:", err)
		return 1
	}
	defer t.Close()
	secret, err := t.ReadSecret(strings.TrimRight(prompt, " ") + " ")
	if err != nil {
		return 1
	}
	os.Stdout.Write(secret)
	os.Stdout.Write([]byte("\n"))
	clear(secret)
	return 0
}

// agent registers with secretvaultd and answers its prompts here.
func agent() int {
	t, err := svterm.OpenTerminal("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "secretvault-tui-prompt:", err)
		return 1
	}
	defer t.Close()
	answer := func(_ context.Context, q svrpc.PromptAsk) (svrpc.PromptAnswer, error) {
		t.Printf("\n\a%s\n%s\n", q.Title, strings.Repeat("─", min(len([]rune(q.Title)), 60)))
		if q.Description != "" {
			t.Printf("%s\n", q.Description)
		}
		if q.Error != "" {
			t.Printf("! %s\n", q.Error)
		}
		switch q.Kind {
		case svrpc.PromptChoose:
			var choices []svprompt.Choice
			for _, c := range q.Choices {
				choices = append(choices, svprompt.Choice{ID: c.ID, Label: c.Label})
			}
			id, err := t.Choose(choices)
			if err != nil {
				return svrpc.PromptAnswer{Canceled: true}, nil
			}
			return svrpc.PromptAnswer{Choice: id}, nil
		case svrpc.PromptNewPassphrase:
			p, err := t.ReadNewSecret("New passphrase: ", "", 8)
			if err != nil {
				return svrpc.PromptAnswer{Canceled: true}, nil
			}
			return svrpc.PromptAnswer{Secret: p}, nil
		default:
			prompt := q.Prompt
			if prompt == "" {
				prompt = "Passphrase:"
			}
			p, err := t.ReadSecret(prompt + " ")
			if err != nil || len(p) == 0 {
				return svrpc.PromptAnswer{Canceled: true}, nil
			}
			return svrpc.PromptAnswer{Secret: p}, nil
		}
	}
	c, err := secretvault.Connect(secretvault.Options{Name: "secretvault-tui-prompt", Prompter: answer})
	if err != nil {
		fmt.Fprintln(os.Stderr, "secretvault-tui-prompt:", err)
		return 1
	}
	defer c.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := c.RegisterPrompter(ctx, os.Getenv("TTY")); err != nil {
		fmt.Fprintln(os.Stderr, "secretvault-tui-prompt:", err)
		return 1
	}
	t.Printf("Answering secretvault's prompts in this terminal. Ctrl+C to stop.\n")
	select {
	case <-ctx.Done():
	case <-c.Done():
		t.Printf("secretvaultd went away.\n")
	}
	return 0
}
