package svd

import (
	"context"
	"errors"
	"os"
	"os/exec"
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
	// Choose asks the person to pick one of q.Choices; for a
	// PromptShowSecret, while it shows q.Show.
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
	end, err := p.c.turn(c)
	if err != nil {
		return func() {}
	}
	defer end()
	var ans svrpc.PromptAnswer
	p.c.conn.Call(c, svrpc.MPromptAsk, q, &ans)
	clear(ans.Secret)
	return func() {}
}

func (p rpcPrompter) ask(ctx context.Context, q svrpc.PromptAsk) (svrpc.PromptAnswer, error) {
	var ans svrpc.PromptAnswer
	end, err := p.c.turn(ctx)
	if err != nil {
		return ans, err
	}
	defer end()
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
	r := svprompt.Request{Title: q.Title, Description: q.Description, Prompt: q.Prompt, Error: q.Error, OK: q.OK}
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
	if q.Kind == svrpc.PromptShowSecret {
		// A new recovery key: secretvault's own prompts show it apart
		// (SETSECRET); a system pinentry, at the end of the description.
		show := []byte(q.Show)
		defer clear(show)
		id, err := p.p.ShowSecret(ctx, request(q), show, choices)
		return id, mapPromptErr(err)
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
func desktopPrompter(cfg PromptConfig) Prompter { return desktopPrompterIn(cfg, os.Environ()) }

// desktopPrompterIn is desktopPrompter for a session whose environment is
// env: the pinentry runs with it, and it says where the display is.
func desktopPrompterIn(cfg PromptConfig, env []string) Prompter {
	if cfg.Program == "none" {
		return nil
	}
	getenv := func(k string) string { return lookupEnv(env, k) }
	if cfg.Program != "" {
		return pinentryPrompter{&svprompt.Pinentry{Program: cfg.Program, Env: env}}
	}
	if hasDisplayIn(getenv) {
		if p, ok := ownProgram("secretvault-gui-prompt"); ok && isProgram(p) {
			return pinentryPrompter{&svprompt.Pinentry{Program: p, Env: env}}
		}
	}
	if getenv("DISPLAY") == "" && getenv("WAYLAND_DISPLAY") == "" {
		return nil
	}
	desk := strings.ToUpper(getenv("XDG_CURRENT_DESKTOP"))
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
func hasDisplay() bool { return hasDisplayIn(os.Getenv) }

func hasDisplayIn(getenv func(string) string) bool {
	if goos == "windows" || goos == "darwin" {
		return true
	}
	return getenv("WAYLAND_DISPLAY") != "" || getenv("DISPLAY") != ""
}

// lookupEnv is the value of k in env (the last one, as the kernel reads it).
func lookupEnv(env []string, k string) string {
	for i := len(env) - 1; i >= 0; i-- {
		if v, ok := strings.CutPrefix(env[i], k+"="); ok {
			return v
		}
	}
	return ""
}

// sessionVars are what a prompt needs to reach the person's desktop.
var sessionVars = []string{"WAYLAND_DISPLAY", "DISPLAY", "XAUTHORITY", "XDG_CURRENT_DESKTOP", "XDG_SESSION_TYPE", "DBUS_SESSION_BUS_ADDRESS"}

// promptEnv is the environment a desktop prompt runs with: the daemon's
// own, and, when that has no display (a daemon started with the session,
// before the desktop was up), the session's as the desktop has told the
// user's service manager (sessionEnv).
func promptEnv() []string {
	env := os.Environ()
	if goos != "linux" || lookupEnv(env, "WAYLAND_DISPLAY") != "" || lookupEnv(env, "DISPLAY") != "" {
		return env
	}
	session := sessionEnv()
	for _, k := range sessionVars {
		if v := lookupEnv(session, k); v != "" && lookupEnv(env, k) == "" {
			env = append(env, k+"="+v)
		}
	}
	return env
}

// sessionEnv is the user's systemd manager's environment, which desktops
// fill in as they start (dbus-update-activation-environment, systemctl
// --user import-environment). Tests stand in for it.
var sessionEnv = func() []string {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "systemctl", "--user", "show-environment").Output()
	if err != nil {
		return nil
	}
	return strings.Split(strings.TrimSpace(string(out)), "\n")
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
