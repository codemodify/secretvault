package svd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svprompt"
	"github.com/codemodify/secretvault/svrpc"
)

// Prompter puts a question to a person.
type Prompter interface {
	// Passphrase asks for a passphrase (or, for PromptNewPassphrase, a new
	// one twice; for PromptPIN, a security key's PIN). The caller zeroes
	// the result.
	Passphrase(ctx context.Context, q svrpc.PromptAsk) ([]byte, error)
	// Choose asks the person to pick one of q.Choices.
	Choose(ctx context.Context, q svrpc.PromptAsk) (string, error)
	// Describe names the prompter, for status output.
	Describe() string
}

// noticer is a Prompter that can also tell the person something while the
// daemon waits on them ("touch your security key"). The notice shows until
// stop is called; if the person calls it off first, cancel is called.
type noticer interface {
	Notice(ctx context.Context, q svrpc.PromptAsk, cancel func()) (stop func())
}

// rpcPrompter asks through a connected client: the CLI prompting on its
// own terminal, or a registered secretvault-tui-prompt --agent.
type rpcPrompter struct {
	c    *client
	desc string
}

// Notice has the client show q (a PromptNotice), which it answers at
// once: a line on a terminal cannot be taken back, so there is nothing to
// withdraw. The answer is ignored, since clients that predate notices
// answer them as cancelled; a person at a terminal calls the wait off
// with Ctrl+C, which closes the connection.
func (p rpcPrompter) Notice(ctx context.Context, q svrpc.PromptAsk, _ func()) func() {
	c, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	var ans svrpc.PromptAnswer
	p.c.conn.Call(c, svrpc.MPromptAsk, q, &ans)
	clear(ans.Secret)
	return func() {}
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

// Notice shows q in a pinentry window of its own until stop closes it; its
// one button, Cancel, calls the wait off.
func (p pinentryPrompter) Notice(ctx context.Context, q svrpc.PromptAsk, cancel func()) func() {
	nctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := p.p.Notice(nctx, request(q)); errors.Is(err, svprompt.ErrCanceled) {
			cancel()
		}
	}()
	return func() { stop(); <-done }
}

func (p pinentryPrompter) Describe() string { return "desktop (" + p.p.Program + ")" }

// The seams desktopPrompter and sibling look at the machine through; the
// tests replace them, so they neither depend on what is installed nor
// start anything.
var (
	// executable is the running daemon's own path.
	executable = os.Executable
	// goos is the platform the rules are for.
	goos = runtime.GOOS
	// systemBinDirs are the only places a system pinentry is taken from.
	systemBinDirs = []string{"/usr/bin", "/usr/local/bin", "/bin"}
)

// desktopPrompter picks the pinentry for desktop prompts, in this order:
//
//  1. the program the config names ("none" turns desktop prompts off);
//  2. secretvault-gui-prompt beside the daemon, when there is a desktop to
//     show it on;
//  3. the system's pinentry that fits the desktop, from the system's own
//     program directories only, never from PATH.
func desktopPrompter(cfg PromptConfig) Prompter {
	if cfg.Program == "none" {
		return nil
	}
	env := os.Environ()
	if cfg.Program != "" {
		return pinentryPrompter{&svprompt.Pinentry{Program: cfg.Program, Env: env}}
	}
	if hasDisplay() {
		if p, ok := ownProgram("secretvault-gui-prompt"); ok && isProgram(p) {
			return pinentryPrompter{&svprompt.Pinentry{Program: p, Env: env}}
		}
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
		for _, dir := range systemBinDirs {
			p := dir + "/" + name
			if isProgram(p) {
				return pinentryPrompter{&svprompt.Pinentry{Program: p, Env: env}}
			}
		}
	}
	return nil
}

// hasDisplay reports whether there is a desktop to open a window on: a
// Wayland or X11 display in the environment on Linux and the BSDs, and
// always on Windows and macOS, where a process that can run at all can
// make a window.
func hasDisplay() bool {
	if goos == "windows" || goos == "darwin" {
		return true
	}
	return os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("DISPLAY") != ""
}

// ownProgram is where the named secretvault program is when it is
// installed beside the running daemon.
func ownProgram(name string) (string, bool) {
	if goos == "windows" {
		name += ".exe"
	}
	exe, err := executable()
	if err != nil {
		return "", false
	}
	if real, err := filepath.EvalSymlinks(exe); err == nil {
		exe = real
	}
	return filepath.Join(filepath.Dir(exe), name), true
}

// isProgram reports whether p is a file that can be run. Windows keeps no
// execute bit, so a regular file is enough there.
func isProgram(p string) bool {
	st, err := os.Stat(p)
	if err != nil || !st.Mode().IsRegular() {
		return false
	}
	return goos == "windows" || st.Mode()&0o111 != 0
}
