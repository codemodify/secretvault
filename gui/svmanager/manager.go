// Package svmanager is secretvault-gui, the desktop password manager, as
// a library, so that tests can drive it in a headless window.
//
// It is a client of secretvaultd, as the CLI and secretvault-tui are: it
// never opens a vault itself and holds no keys. When the daemon needs to
// know the person is there (to unlock a vault, or to allow this program to
// use one), it asks this program for the vault's passphrase (prompt.ask),
// and the question is put in a dialog window of its own, into a
// uitoolkit.SecretField (prompt.go). The daemon treats secretvault-gui as
// one of secretvault's own programs, as it does the CLI, but knows it by
// its executable rather than by a terminal.
//
// The window is the vaults and the folders their item names make, the
// items of the vault being shown, filtered as you type, and the item open
// beside them. Everything that talks to the daemon runs off the
// interface's goroutine, because the daemon may answer only after asking
// the person, through this same interface.
//
// Secrets are masked until revealed, one field at a time. Concealed values
// are held in the byte slices they arrived in, drawn from those bytes
// (secret.go) and typed into SecretFields, and wiped when the item is
// left, when its vault locks, when the window is hidden to the tray, and on
// quit. Copies go to the clipboard through uitoolkit's secret clipboard,
// which keeps them out of clipboard managers and clears them after 30
// seconds. The exceptions, where a secret does become a Go string, are
// listed in docs/architecture.md ("The desktop manager").
package svmanager

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/codemodify/uitoolkit/app"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svrpc"
)

// Options configure the manager.
type Options struct {
	// App is the application the manager's windows belong to; its look is
	// theirs. Required.
	App *app.Application

	// Headless keeps the windows offscreen (tests and screenshots).
	Headless bool

	// Vault is the vault shown first ("" for the default vault).
	Vault string

	// Socket is the daemon's socket (the usual one when "").
	Socket string

	// Connect reaches the daemon: secretvault.Connect when nil. Tests
	// point it at a daemon of their own.
	Connect func(secretvault.Options) (*secretvault.Client, error)

	// Clipboard takes copies: the desktop's, through uitoolkit, when nil.
	Clipboard Clipboard

	// ClipTTL is how long a copy stays on the clipboard (30 seconds when
	// 0).
	ClipTTL time.Duration

	// Tray puts an icon in the desktop's tray, where it has one, and then
	// closing the window hides it there instead of quitting.
	Tray bool

	// PickFile asks where to save a file (save) or which file to attach,
	// and calls done with the path, or "" when the person changed their
	// mind. The toolkit's file dialog asks when nil.
	PickFile func(save bool, suggested string, done func(path string))

	// Now is the clock for one-time codes (time.Now when nil).
	Now func() time.Time
}

// clipTTL is how long a copy stays on the clipboard, unless Options say.
const clipTTL = 30 * time.Second

// callTimeout bounds one request to the daemon, prompts included.
const callTimeout = 5 * time.Minute

// Manager is the desktop manager. Make it with New and run it with Run.
type Manager struct {
	opts   Options
	app    *app.Application
	win    *app.Window
	client *secretvault.Client // replaced by a reconnect; the interface's goroutine only
	now    func() time.Time
	clip   Clipboard
	ttl    time.Duration
	tray   platform.StatusItem

	ctx      context.Context
	cancel   context.CancelFunc
	done     chan struct{} // closed on quit
	quitOnce sync.Once
	hasOTP   atomic.Bool

	promptMu sync.Mutex // one question from the daemon at a time

	// The state below is only touched on the interface's goroutine.

	vaults     []svrpc.VaultInfo
	syncs      map[string]svrpc.SyncStatus // by vault, for the vaults that sync
	vault      string                      // the vault whose items are shown
	listed     bool                        // its items have been listed
	listing    bool                        // and are being listed
	lists      int                         // counts the listings
	entries    []svrpc.Entry               // its items, without their fields, by name
	shown      []int                       // the entries the search and folder let through
	folder     string                      // the folder shown: a name prefix ending in "/", or ""
	query      string                      // the search, as typed
	cursor     string                      // the item selected in the list
	cur        *svrpc.Entry                // the open item, with its fields
	otp        map[int]*svotp.Key          // the open item's one-time password keys, by field
	itemGen    int                         // changes whenever the open item does
	listGen    int                         // changes whenever the vault shown does
	busy       int
	gone       bool   // the daemon went away
	goneWhy    string // and why, in plain words
	dialing    bool   // a reconnect is on its way
	copied     Copied // the last copy, taken back when its vault locks
	copiedFrom string // the vault it came from

	hist    *history      // the history page, with its revisions' fields
	vpage   *vaultPage    // the vault page: grants, audit log, sync
	editor  *editor       // the open item editor
	asking  *promptDialog // the daemon's question on the screen
	promptN int

	gen      generator // the generator's settings, kept between uses
	hidden   bool      // the window is hidden in the tray
	excluded bool      // the window is kept out of screen captures (syncCapture)

	minimiseHook func() // tests: what minimising the window does

	ui *ui
}

// New builds the manager's window and connects to secretvaultd, starting
// it if need be. A daemon that cannot be reached is not an error here:
// the window says so, and offers to try again. Start (or Run) fills it.
func New(opts Options) (*Manager, error) {
	if opts.App == nil {
		return nil, errors.New("svmanager: Options.App is required")
	}
	m := &Manager{
		opts:  opts,
		app:   opts.App,
		now:   opts.Now,
		clip:  opts.Clipboard,
		ttl:   opts.ClipTTL,
		otp:   map[int]*svotp.Key{},
		syncs: map[string]svrpc.SyncStatus{},
		done:  make(chan struct{}),
		gen:   defaultGenerator(),
	}
	if m.now == nil {
		m.now = time.Now
	}
	if m.clip == nil {
		m.clip = desktopClipboard{}
	}
	if m.ttl == 0 {
		m.ttl = clipTTL
	}
	m.ctx, m.cancel = context.WithCancel(context.Background())
	win, err := m.app.NewWindow(platform.WindowOptions{
		Title: "secretvault", Width: 1120, Height: 700, MinWidth: 760, MinHeight: 440,
		Headless: opts.Headless,
	})
	if err != nil {
		m.cancel()
		return nil, err
	}
	m.win = win
	win.SetIcon(secretui.Icon(16), secretui.Icon(24), secretui.Icon(32), secretui.Icon(48), secretui.Icon(64), secretui.Icon(128))
	win.SetOnCloseRequest(m.closeRequested)
	m.build()
	if opts.Tray {
		m.startTray()
	}
	m.connect()
	return m, nil
}

// Window is the manager's main window.
func (m *Manager) Window() *app.Window { return m.win }

// Start lists the vaults and shows the first one. Run calls it; tests
// that pump the application themselves call it instead.
func (m *Manager) Start() {
	go m.tick()
	m.post(m.start)
}

// Run shows the manager and returns when the person quits.
func (m *Manager) Run() error {
	m.Start()
	err := m.app.Run()
	m.shutdown()
	return err
}

// Quit wipes what is held and ends the run loop.
func (m *Manager) Quit() {
	m.shutdown()
	m.app.Quit()
}

// Close is Quit for a manager whose loop is not running (tests).
func (m *Manager) Close() {
	m.shutdown()
	if !m.win.Closed() {
		m.win.Close()
	}
}

func (m *Manager) shutdown() {
	m.quitOnce.Do(func() {
		close(m.done)
		m.cancel()
		m.closeItem()
		m.wipeHistory()
		if m.editor != nil {
			m.editor.wipe()
			m.editor = nil
		}
		if m.asking != nil {
			m.dropPrompt(m.asking.id)
		}
		if m.copied != nil {
			m.copied.Clear()
			m.copied = nil
		}
		if m.ui != nil {
			// Every dialog up, and those under it, wipes what it holds as
			// it goes (a recovery key, a generated password, a passphrase
			// being typed).
			m.win.SetOverlay(nil)
		}
		if m.tray != nil {
			m.tray.Close()
		}
		if m.client != nil {
			m.client.Close()
		}
	})
}

// quitting reports whether the manager has shut down.
func (m *Manager) quitting() bool {
	select {
	case <-m.done:
		return true
	default:
		return false
	}
}

// post runs fn on the interface's goroutine. Everything from the daemon
// arrives on other goroutines, and widgets may only be touched from that
// one.
func (m *Manager) post(fn func()) {
	m.app.Post(func() {
		if !m.quitting() {
			fn()
		}
	})
}

// call runs fn, which talks to the daemon, off the interface's goroutine,
// and then hands its error to then on the interface's goroutine. The
// daemon may answer only after asking the person, through this program,
// so waiting for it here would hang both.
//
// sent are the secrets fn sends, which are wiped once fn is done with
// them, or at once when there is no daemon to send them to and fn is not
// run at all.
func (m *Manager) call(fn func(ctx context.Context, c *secretvault.Client) error, then func(error), sent ...[]byte) {
	c := m.client
	if c == nil || m.gone {
		for _, b := range sent {
			clear(b)
		}
		then(errGone)
		return
	}
	m.busy++
	m.drawStatus()
	go func() {
		ctx, cancel := context.WithTimeout(m.ctx, callTimeout)
		err := fn(ctx, c)
		cancel()
		for _, b := range sent {
			clear(b)
		}
		m.post(func() {
			m.busy--
			then(err)
			m.drawStatus()
		})
	}()
}

// errGone is a request made while there is no daemon to make it to.
var errGone = errors.New("secretvaultd is not running")

// connect reaches the daemon, starting it if need be.
func (m *Manager) connect() {
	m.connected(m.dial())
}

// dial connects, from any goroutine: starting the daemon can take a few
// seconds.
func (m *Manager) dial() (*secretvault.Client, error) {
	connect := m.opts.Connect
	if connect == nil {
		connect = secretvault.Connect
	}
	return connect(secretvault.Options{Socket: m.opts.Socket, Name: "secretvault-gui", Prompter: m.prompt, OnEvent: m.event})
}

// connected takes what dial made of it.
func (m *Manager) connected(c *secretvault.Client, err error) {
	if err != nil {
		m.gone, m.goneWhy = true, m.describe(err)
		m.showGone()
		return
	}
	m.client, m.gone, m.goneWhy = c, false, ""
	go m.watch(c)
}

// watch notices the daemon going away.
func (m *Manager) watch(c *secretvault.Client) {
	select {
	case <-c.Done():
		m.post(func() {
			if m.client == c {
				m.daemonGone()
			}
		})
	case <-m.done:
	}
}

// reconnect tries the daemon again, after it went away.
func (m *Manager) reconnect() {
	if !m.gone || m.dialing {
		return
	}
	m.dialing = true
	m.busy++
	m.say("Connecting to secretvaultd…")
	go func() {
		c, err := m.dial()
		m.post(func() {
			m.dialing = false
			m.busy--
			m.connected(c, err)
			if m.gone {
				m.say("%s", m.goneWhy)
				return
			}
			m.say("Connected to secretvaultd.")
			m.start()
		})
	}()
}

// daemonGone forgets everything the daemon told us: without it nothing
// shown can be trusted to be current, and nothing can be done.
func (m *Manager) daemonGone() {
	m.gone, m.goneWhy = true, "secretvaultd went away."
	if m.client != nil {
		m.client.Close()
		m.client = nil
	}
	if m.asking != nil {
		m.dropPrompt(m.asking.id) // nobody is waiting for the answer now
	}
	if m.copied != nil {
		// Its vault's locking can no longer be heard of: the daemon
		// that went away most likely took every vault's keys with it.
		m.copied.Clear()
		m.copied = nil
	}
	m.listGen++ // an answer on its way is from a daemon that has gone
	m.closeItem()
	m.wipeHistory()
	if m.editor != nil {
		m.editor.close()
	}
	m.closeVaultPage()
	m.entries, m.shown, m.listed = nil, nil, false
	m.vaults = nil
	m.drawVaults()
	m.drawFolders()
	m.drawItems()
	m.showGone()
	m.drawStatus()
}

// tick redraws one-time codes every second, while one is shown.
func (m *Manager) tick() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if m.hasOTP.Load() {
				m.post(m.drawCodes)
			}
		case <-m.done:
			return
		}
	}
}

// say puts a message in the status bar.
func (m *Manager) say(format string, args ...any) {
	m.ui.message = fmt.Sprintf(format, args...)
	m.drawStatus()
}

// fail puts an error in the status bar, in plain words.
func (m *Manager) fail(err error) {
	m.ui.message = m.describe(err)
	m.drawStatus()
}

// describe turns an error from the daemon into something to tell a person.
func (m *Manager) describe(err error) string {
	var e *svrpc.Error
	switch {
	case errors.Is(err, errGone), errors.Is(err, secretvault.ErrNoDaemon):
		return "secretvaultd is not running, and could not be started."
	case errors.Is(err, svrpc.ErrCanceled):
		return "Canceled."
	case errors.Is(err, svrpc.ErrWrongKey):
		return "That passphrase does not open this vault."
	case errors.Is(err, svrpc.ErrDenied):
		return sentence(err.Error())
	case errors.Is(err, svrpc.ErrLocked):
		return "The vault is locked; Ctrl+U unlocks it."
	case errors.Is(err, svrpc.ErrNoPrompter):
		return "Nobody could be asked for permission: " + err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "secretvaultd took too long to answer."
	case errors.Is(err, context.Canceled):
		return "Canceled."
	case errors.As(err, &e):
		return sentence(e.Message)
	}
	return sentence(err.Error())
}

// sentence capitalises s and ends it with a full stop.
func sentence(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	r, size := utf8.DecodeRuneInString(s)
	s = string(unicode.ToUpper(r)) + s[size:]
	if !strings.HasSuffix(s, ".") && !strings.HasSuffix(s, "?") && !strings.HasSuffix(s, "!") {
		s += "."
	}
	return s
}

// root is where dialogs go up.
func (m *Manager) root() *widgets.FlexBox { return m.ui.column }
