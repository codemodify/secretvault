package svd

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/codemodify/secretvault/svprompt"
	"github.com/codemodify/secretvault/svrpc"
)

// Prompter puts a question to a person.
type Prompter interface {
	// Passphrase asks for a passphrase (or, for PromptNewPassphrase, a new
	// one twice). The caller zeroes the result.
	Passphrase(ctx context.Context, q svrpc.PromptAsk) ([]byte, error)
	// Choose asks the person to pick one of q.Choices.
	Choose(ctx context.Context, q svrpc.PromptAsk) (string, error)
	// Describe names the prompter, for status output.
	Describe() string
}

// rpcPrompter asks through a connected client: the CLI prompting on its
// own terminal, or a registered secretvault-tui-prompt --agent.
type rpcPrompter struct {
	c    *client
	desc string
}

func (p rpcPrompter) ask(ctx context.Context, q svrpc.PromptAsk) (svrpc.PromptAnswer, error) {
	var ans svrpc.PromptAnswer
	if err := p.c.conn.Call(ctx, svrpc.MPromptAsk, q, &ans); err != nil {
		return ans, err
	}
	if ans.Canceled {
		clear(ans.Secret)
		return ans, svrpc.ErrCanceled
	}
	return ans, nil
}

func (p rpcPrompter) Passphrase(ctx context.Context, q svrpc.PromptAsk) ([]byte, error) {
	ans, err := p.ask(ctx, q)
	return ans.Secret, err
}

func (p rpcPrompter) Choose(ctx context.Context, q svrpc.PromptAsk) (string, error) {
	ans, err := p.ask(ctx, q)
	if err != nil {
		return "", err
	}
	for _, c := range q.Choices {
		if c.ID == ans.Choice {
			return ans.Choice, nil
		}
	}
	return "", errors.New("the prompt answered with a choice that was not offered")
}

func (p rpcPrompter) Describe() string { return p.desc }

// pinentryPrompter asks through a pinentry program on the desktop.
type pinentryPrompter struct {
	p *svprompt.Pinentry
}

func request(q svrpc.PromptAsk) svprompt.Request {
	r := svprompt.Request{Title: q.Title, Description: q.Description, Prompt: q.Prompt, Error: q.Error}
	if q.Kind == svrpc.PromptNewPassphrase {
		r.Repeat = "Repeat:"
	}
	return r
}

func mapPromptErr(err error) error {
	if errors.Is(err, svprompt.ErrCanceled) || errors.Is(err, svprompt.ErrTimeout) {
		return svrpc.ErrCanceled
	}
	return err
}

func (p pinentryPrompter) Passphrase(ctx context.Context, q svrpc.PromptAsk) ([]byte, error) {
	b, err := p.p.GetPassphrase(ctx, request(q))
	return b, mapPromptErr(err)
}

func (p pinentryPrompter) Choose(ctx context.Context, q svrpc.PromptAsk) (string, error) {
	var choices []svprompt.Choice
	for _, c := range q.Choices {
		choices = append(choices, svprompt.Choice{ID: c.ID, Label: c.Label})
	}
	id, err := p.p.Choose(ctx, request(q), choices)
	return id, mapPromptErr(err)
}

func (p pinentryPrompter) Describe() string { return "desktop (" + p.p.Program + ")" }

// desktopPrompter picks the pinentry for desktop prompts. secretvault's
// own GUI prompt is not built yet (see uitoolkit-gaps.md), so the system's
// pinentry stands in: the one that fits the desktop, from the system's own
// program directories only, never from PATH.
func desktopPrompter(cfg PromptConfig) Prompter {
	if cfg.Program == "none" {
		return nil
	}
	env := os.Environ()
	if cfg.Program != "" {
		return pinentryPrompter{&svprompt.Pinentry{Program: cfg.Program, Env: env}}
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return nil
	}
	desk := strings.ToUpper(os.Getenv("XDG_CURRENT_DESKTOP"))
	order := []string{"pinentry-qt", "pinentry-gnome3", "pinentry-gtk", "pinentry-gtk-2"}
	if strings.Contains(desk, "GNOME") || strings.Contains(desk, "UNITY") || strings.Contains(desk, "CINNAMON") ||
		strings.Contains(desk, "MATE") || strings.Contains(desk, "XFCE") || strings.Contains(desk, "BUDGIE") {
		order = []string{"pinentry-gnome3", "pinentry-gtk", "pinentry-gtk-2", "pinentry-qt"}
	}
	for _, name := range order {
		for _, dir := range []string{"/usr/bin", "/usr/local/bin", "/bin"} {
			p := dir + "/" + name
			if st, err := os.Stat(p); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
				return pinentryPrompter{&svprompt.Pinentry{Program: p, Env: env}}
			}
		}
	}
	return nil
}
