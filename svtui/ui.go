// Package svtui is secretvault-tui, the full-screen terminal password
// manager, as a library so that tests can drive it on a simulated screen.
//
// It is a client of secretvaultd, as the CLI is: it never opens a vault
// itself. When the daemon needs to know the person is there, it asks this
// program for the vault's passphrase (prompt.ask), which is put to the
// person in a dialog drawn inside the interface (prompt.go).
//
// The screen is three tabs (tabs.go) between a line naming them and a
// status line: Vault, three panes (the vaults, the items of the vault
// being shown, and the open item); Disk, the encrypted disks beside the
// one selected; and Tools.
// Everything that talks to the daemon runs off the interface's goroutine,
// because the daemon may answer only after asking the person, through
// this same interface.
//
// Secrets are masked until revealed. Concealed values, keys and the
// passphrases typed for the daemon are kept in byte slices, not Go
// strings: they are drawn from those bytes straight into the screen's
// cells and typed into buffers of their own (secret.go), and wiped when
// the item is left, when its vault locks, and on quit. The exceptions are
// a one-time password key, which svotp reads from a string while it is
// parsed, and pasted text, which tview hands over as one.
package svtui

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

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svrpc"
)

// Options configure the manager.
type Options struct {
	// Vault is the vault shown first ("" for the default vault).
	Vault string

	// Socket is the daemon's socket (the usual one when "").
	Socket string

	// Connect reaches the daemon: secretvault.Connect when nil. Tests
	// point it at a daemon of their own.
	Connect func(secretvault.Options) (*secretvault.Client, error)

	// Clip puts a secret on the clipboard for ttl and returns the name of
	// the clipboard it used. When nil, the secretvault CLI installed
	// beside this program does it (secretvault __clip SECONDS).
	Clip func(secret []byte, ttl time.Duration) (string, error)

	// Screen, when set, is drawn on instead of the terminal (tests use
	// tcell's simulation screen).
	Screen tcell.Screen

	// Now is the clock for one-time codes (time.Now when nil).
	Now func() time.Time

	// CLI is the secretvault command-line program, named to other
	// programs (the browsers' manifests, gpg's agent-program, the
	// helpers' links): svops.CLIProgram() when "", the one beside this
	// program. Daemon is secretvaultd, for the keyring takeover's service
	// files: the one beside this program when "".
	CLI, Daemon string

	// HostSocket is the host daemon's admin socket (svrpc.HostAdminSocket()
	// when ""), and SystemdCreds runs systemd-creds to seal the host
	// identity (the real one when nil): tests stand in.
	HostSocket   string
	SystemdCreds func(stdin []byte, args ...string) ([]byte, error)
}

// clipTTL is how long a copy stays on the clipboard.
const clipTTL = 30 * time.Second

// callTimeout bounds one request to the daemon, prompts included.
const callTimeout = 5 * time.Minute

// Pages, bottom to top. The daemon's prompts always go on top.
const (
	pageMain   = "main"
	pagePanel  = "panel"    // help, history, grants, audit
	pageRev    = "revision" // one revision, over the history
	pageForm   = "form"     // the item editor
	pageDialog = "dialog"   // questions, confirmations, the generator
	pagePrompt = "prompt"   // the daemon's questions
)

// UI is the terminal manager. Create it with New and run it with Run.
type UI struct {
	opts   Options
	app    *tview.Application
	client *secretvault.Client
	now    func() time.Time
	clip   func([]byte, time.Duration) (string, error)

	pages      *tview.Pages
	tabs       *tview.Pages    // the main page: the Vault, Disk and Tools tabs
	top        *tview.Flex     // the line of the tabs: their names, the keys to them
	strip      *tview.TextView // the tabs' names
	bar        *tview.Flex     // the status line and the hints
	body       *tview.Flex     // the Vault tab
	disks      *panel          // the Disk tab
	diskDetail *tview.TextView // the Disk tab's selected disk
	tools      *panel          // the Tools tab
	vaultList  *tview.List
	itemList   *tview.List
	filter     *tview.InputField
	middle     *tview.Flex
	detail     *detailView
	status     *tview.TextView
	hints      *tview.TextView

	// The state below is only touched on the interface's goroutine.

	tab        int             // the tab shown
	vaultFocus tview.Primitive // what had the focus when the Vault tab was left
	stripAt    [][2]int        // where each tab's name is on the strip
	disksGen   int             // changes whenever the disks are asked for

	vaults   []svrpc.VaultInfo
	vault    string            // the vault whose items are shown
	listed   bool              // its items have been listed
	lists    int               // counts the listings
	entries  []svrpc.Entry     // its items, without their fields
	kind     int               // the row of svops.KindRows whose items are listed
	vrows    []vaultRow        // the vault list's rows: the vaults, and the open one's
	names    map[string]string // the names the list shows them by (svops.ShownNames)
	shown    []int             // the rows the filter lets through: entries by index
	cursor   string            // the item under the item list's cursor
	redraw   bool              // the item list is being refilled
	cur      *svrpc.Entry      // the open item, with its fields
	otp      map[int]*svotp.Key
	revealed bool
	itemGen  int // changes whenever the open item does
	listGen  int // changes whenever the vault shown does
	message  string
	busy     int
	gone     bool // the daemon went away

	history  []svrpc.Entry // the history panel's revisions, with fields
	revision *revisionView // the revision open over the history
	editor   *editor       // the open item editor
	resume   map[string]tview.Primitive

	panels map[string]*panel // the panels up, by page

	hostMu        sync.Mutex
	host          *secretvault.Client // the host daemon, once the host panel reached it
	hostRecipient string              // its identity's recipient, as it last said
	once          *onceView           // what is shown only once, while it is
	value         []byte              // a value resolved from a reference, while it is shown
	onceQueue     []pendingOnce       // once views waiting for the one up to close

	dialogSeq    int             // numbers the dialogs
	dialogID     int             // the dialog up
	dialogCancel func()          // cancels it, wiping what it holds
	dialogQueue  []pendingDialog // dialogs waiting for it to close
	emergency    []string        // requests for emergency access, for the status line

	asking   *promptDialog // the daemon's question on the screen
	promptID int
	promptMu sync.Mutex // one prompt at a time
	hasOTP   atomic.Bool

	queue    chan func()
	done     chan struct{} // closed on quit
	quitOnce sync.Once
	ctx      context.Context
	cancel   context.CancelFunc
}

// New connects to secretvaultd (starting it if need be) and builds the
// interface. Run shows it.
func New(opts Options) (*UI, error) {
	u := &UI{
		opts:   opts,
		app:    tview.NewApplication(),
		now:    opts.Now,
		clip:   opts.Clip,
		otp:    map[int]*svotp.Key{},
		resume: map[string]tview.Primitive{},
		panels: map[string]*panel{},
		queue:  make(chan func(), 256),
		done:   make(chan struct{}),
	}
	if u.now == nil {
		u.now = time.Now
	}
	if u.clip == nil {
		u.clip = helperClip
	}
	u.ctx, u.cancel = context.WithCancel(context.Background())
	connect := opts.Connect
	if connect == nil {
		connect = secretvault.Connect
	}
	c, err := connect(secretvault.Options{Socket: opts.Socket, Name: "secretvault-tui", Prompter: u.prompt, OnEvent: u.event})
	if err != nil {
		u.cancel()
		return nil, err
	}
	u.client = c
	u.build()
	if opts.Screen != nil {
		u.app.SetScreen(opts.Screen) // which initialises it
	}
	return u, nil
}

func (u *UI) build() {
	u.vaultList = tview.NewList().ShowSecondaryText(false).SetHighlightFullLine(true).SetWrapAround(false)
	u.vaultList.SetBorder(true).SetTitle(" Vaults ")
	u.vaultList.SetSelectedFunc(func(i int, _, _ string, _ rune) { u.vaultRowChosen(i) })

	u.itemList = tview.NewList().ShowSecondaryText(false).SetHighlightFullLine(true).SetWrapAround(false)
	u.itemList.SetBorder(true).SetTitle(" Items ")
	u.itemList.SetChangedFunc(func(i int, _, _ string, _ rune) { u.itemMoved(i) })

	u.filter = tview.NewInputField().SetLabel("/ ").SetFieldWidth(0)
	u.filter.SetChangedFunc(func(string) { u.applyFilter() })
	u.filter.SetDoneFunc(func(key tcell.Key) {
		if key == tcell.KeyEscape {
			u.filter.SetText("")
			u.middle.ResizeItem(u.filter, 0, 0)
		}
		if strings.TrimSpace(u.filter.GetText()) == "" {
			u.middle.ResizeItem(u.filter, 0, 0)
		}
		u.app.SetFocus(u.itemList)
	})
	u.middle = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(u.filter, 0, 0, false).
		AddItem(u.itemList, 0, 1, true)

	u.detail = newDetailView()
	u.detail.SetBorder(true).SetTitle(" Item ")
	u.detail.reset("Nothing open.\n\nEnter opens the item under the cursor;\n? lists every key.")

	for _, p := range []interface {
		SetFocusFunc(func()) *tview.Box
		SetBlurFunc(func()) *tview.Box
		SetBorderColor(tcell.Color) *tview.Box
	}{u.vaultList, u.itemList, u.detail} {
		p.SetFocusFunc(func() { p.SetBorderColor(tview.Styles.SecondaryTextColor) })
		p.SetBlurFunc(func() { p.SetBorderColor(tview.Styles.BorderColor) })
	}

	u.status = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	u.hints = tview.NewTextView().SetDynamicColors(true).SetWrap(false).SetTextAlign(tview.AlignRight)
	u.hints.SetText("[gray]" + vaultsHints)

	u.body = tview.NewFlex().
		AddItem(u.vaultList, 20, 0, false).
		AddItem(u.middle, 0, 2, true).
		AddItem(u.detail, 0, 3, false)
	u.disks = u.newDisksTab()
	u.tools = u.newToolsTab()
	u.tabs = tview.NewPages().
		AddPage(tabNames[tabVaults], u.body, true, true).
		AddPage(tabNames[tabDisks], u.disks.frame, true, false).
		AddPage(tabNames[tabTools], u.tools.frame, true, false)
	u.pages = tview.NewPages().AddPage(pageMain, u.tabs, true, true)
	u.strip = tview.NewTextView().SetDynamicColors(true).SetWrap(false)
	u.drawStrip()
	u.top = tview.NewFlex().
		AddItem(u.strip, 0, 1, false).
		AddItem(tview.NewTextView().SetDynamicColors(true).SetWrap(false).SetTextAlign(tview.AlignRight).SetText("[gray]"+tabsHint), len(tabsHint), 0, false)
	u.top.SetMouseCapture(u.stripMouse)
	u.bar = tview.NewFlex().
		AddItem(u.status, 0, 1, false).
		AddItem(u.hints, len(vaultsHints), 0, false)
	root := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(u.top, 1, 0, false).
		AddItem(u.pages, 0, 1, true).
		AddItem(u.bar, 1, 0, false)

	u.app.SetRoot(root, true).EnableMouse(true).EnablePaste(true)
	u.app.SetInputCapture(u.keys)
	u.app.SetFocus(u.itemList)
	u.drawStatus()
}

// Run shows the manager and returns when the person quits. It closes the
// connection to the daemon on the way out.
func (u *UI) Run() error {
	go u.pump()
	go u.watch()
	go u.tick()
	u.post(u.start)
	err := u.app.Run()
	u.shutdown()
	u.client.Close()
	u.closeHost()
	return err
}

// post runs fn on the interface's goroutine, in the order posted.
// Everything from the daemon arrives on other goroutines, and tview may
// only be touched from its own.
func (u *UI) post(fn func()) {
	select {
	case u.queue <- fn:
	case <-u.done:
	}
}

func (u *UI) pump() {
	for {
		select {
		case fn := <-u.queue:
			u.app.QueueUpdateDraw(func() {
				select {
				case <-u.done:
				default:
					fn()
				}
			})
		case <-u.done:
			return
		}
	}
}

// call runs fn, which talks to the daemon, off the interface's goroutine,
// and then hands its error to then on the interface's goroutine. The
// daemon may answer only after asking the person, through this interface,
// so waiting for it here would hang both.
func (u *UI) call(fn func(ctx context.Context, c *secretvault.Client) error, then func(error)) {
	u.busy++
	u.drawStatus()
	go func() {
		ctx, cancel := context.WithTimeout(u.ctx, callTimeout)
		err := fn(ctx, u.client)
		cancel()
		u.post(func() {
			u.busy--
			then(err)
			u.drawStatus()
		})
	}()
}

// watch notices the daemon going away.
func (u *UI) watch() {
	select {
	case <-u.client.Done():
		u.post(u.daemonGone)
	case <-u.done:
	}
}

// tick redraws one-time codes every second, while one is shown.
func (u *UI) tick() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			if u.hasOTP.Load() {
				u.post(u.drawItem)
			}
		case <-u.done:
			return
		}
	}
}

// quit wipes what is held and stops the interface.
func (u *UI) quit() {
	u.shutdown()
	u.app.Stop()
}

func (u *UI) shutdown() {
	u.quitOnce.Do(func() {
		close(u.done)
		u.cancel()
		u.closeItem()
		u.wipeHistory()
		u.wipeOnce()
		u.dropDialogs()
		u.closePage(pageDialog)
		if u.editor != nil {
			u.editor.wipe()
		}
	})
}

func (u *UI) daemonGone() {
	u.gone = true
	u.closeItem()
	u.wipeHistory()
	u.wipeOnce()
	u.dropDialogs()
	for _, p := range []string{pageRev, pageSub, pagePanel, pageInfo, pageForm, pageDialog} {
		u.closePage(p)
	}
	if u.editor != nil {
		u.editor.wipe()
		u.editor = nil
	}
	u.entries, u.names, u.shown, u.listed = nil, nil, nil, false
	u.vaults = nil
	u.drawVaults()
	u.drawItems()
	u.disksGen++ // what is being asked for is dropped
	u.disks.clear()
	u.disks.setHead("")
	u.drawDiskDetail()
	u.detail.reset("secretvault's background service (secretvaultd) stopped.\n\nNothing can be shown until it is back. q quits.")
	u.drawStatus()
}

// keys handles the keys of the main screen. Dialogs and panels have
// their own, and so does the item filter while it is typed in.
func (u *UI) keys(ev *tcell.EventKey) *tcell.EventKey {
	if ev.Key() == tcell.KeyCtrlC {
		u.quit()
		return nil
	}
	if front, _ := u.pages.GetFrontPage(); front != pageMain {
		return ev
	}
	focus := u.app.GetFocus()
	if focus == u.filter {
		return ev
	}
	if u.tab != tabVaults {
		return u.tabKeys(ev)
	}
	switch ev.Key() {
	case tcell.KeyTab:
		u.cycle(1, true)
		return nil
	case tcell.KeyBacktab:
		u.cycle(-1, true)
		return nil
	case tcell.KeyRight:
		u.cycle(1, false)
		return nil
	case tcell.KeyLeft:
		u.cycle(-1, false)
		return nil
	case tcell.KeyEscape:
		if u.filter.GetText() != "" {
			u.filter.SetText("")
			u.middle.ResizeItem(u.filter, 0, 0)
			return nil
		}
		return ev
	case tcell.KeyRune:
	default:
		return ev
	}
	if ev.Modifiers()&(tcell.ModAlt|tcell.ModCtrl) != 0 {
		return ev
	}
	switch ev.Rune() {
	case '/':
		u.middle.ResizeItem(u.filter, 1, 0)
		u.app.SetFocus(u.filter)
	case 'c':
		u.copySecret()
	case 'u':
		u.copyUsername()
	case 'o':
		u.copyCode()
	case 'r':
		u.toggleReveal()
	case 'e':
		u.editItem()
	case 'n':
		u.newItem(nil)
	case 'd':
		u.deleteItem()
	case 'm':
		u.renameItem()
	case '>':
		u.moveItem(false)
	case '+':
		u.moveItem(true)
	case 'h':
		u.showHistory()
	case 'f':
		u.showFiles()
	case 'y':
		u.copyReference()
	default:
		if !u.everyTabKey(ev.Rune()) {
			return ev
		}
	}
	return nil
}

// cycle moves the focus between the three panes; wrap says whether it
// goes round (Tab) or stops at the ends (arrow keys).
func (u *UI) cycle(dir int, wrap bool) {
	panes := []tview.Primitive{u.vaultList, u.itemList, u.detail}
	at := 1
	for i, p := range panes {
		if p == u.app.GetFocus() {
			at = i
		}
	}
	at += dir
	switch {
	case wrap:
		at = (at + len(panes)) % len(panes)
	case at < 0, at >= len(panes):
		return
	}
	u.app.SetFocus(panes[at])
}

// openPage shows p over what is there, focusing focus. Closing it gives
// the focus back to whatever had it.
func (u *UI) openPage(name string, p, focus tview.Primitive) {
	if front, _ := u.pages.GetFrontPage(); front != name {
		u.resume[front] = u.app.GetFocus()
	}
	if pn := u.panels[name]; pn != nil && pn.frame != p {
		delete(u.panels, name) // replaced by something else
		if pn.onClose != nil {
			pn.onClose() // the history wipes its revisions
		}
	}
	u.pages.AddPage(name, p, true, true)
	if u.pages.HasPage(pagePrompt) && name != pagePrompt {
		// The daemon's question stays on top, and keeps the keyboard.
		u.pages.SendToFront(pagePrompt)
		if front, _ := u.pages.GetFrontPage(); front == pagePrompt {
			u.resume[name] = focus
			return
		}
	}
	u.app.SetFocus(focus)
}

// closePage removes a page, and gives the focus back to what had it
// before the page opened (if the page was the one in front).
func (u *UI) closePage(name string) {
	if !u.pages.HasPage(name) {
		return
	}
	front, _ := u.pages.GetFrontPage()
	cur := u.app.GetFocus()
	u.pages.RemovePage(name)
	delete(u.resume, name)
	delete(u.panels, name)
	if front != name {
		u.app.SetFocus(cur)
		if name == pageDialog {
			u.dialogClosed()
		}
		return
	}
	front, _ = u.pages.GetFrontPage()
	next := u.resume[front]
	switch {
	case next == nil:
		next = u.pages
	case next == u.filter && u.filter.GetText() == "":
		u.middle.ResizeItem(u.filter, 0, 0)
		next = u.itemList
	}
	u.app.SetFocus(next)
	if name == pageDialog {
		u.dialogClosed()
	}
}

// say puts a message in the status line.
func (u *UI) say(format string, args ...any) {
	u.message = tview.Escape(fmt.Sprintf(format, args...))
	u.drawStatus()
}

// fail puts an error in the status line, in plain words.
func (u *UI) fail(err error) {
	u.message = "[red]" + tview.Escape(u.describe(err)) + "[-]"
	u.drawStatus()
}

// describe turns an error from the daemon into something to tell a person.
func (u *UI) describe(err error) string {
	if u.gone {
		return svops.DaemonNotAnswering
	}
	return describeErr(err)
}

// describeErr is describe for workers: it reads no state of the
// interface's.
func describeErr(err error) string {
	var e *svrpc.Error
	switch {
	case errors.Is(err, secretvault.ErrNoDaemon):
		return svops.DaemonNotAnswering
	case errors.Is(err, svrpc.ErrCanceled):
		return "Canceled."
	case errors.Is(err, svrpc.ErrWrongKey):
		return "That passphrase does not open this vault."
	case errors.Is(err, svrpc.ErrDenied):
		return sentence(err.Error())
	case errors.Is(err, svrpc.ErrLocked):
		return "The vault is locked; U unlocks it."
	case errors.Is(err, svrpc.ErrNoPrompter):
		return "Nobody could be asked for permission, so nothing was done: " + err.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return svops.DaemonTooSlow
	case errors.Is(err, context.Canceled):
		return "Canceled."
	case errors.As(err, &e):
		return sentence(ownWords(e.Message))
	}
	return sentence(ownWords(err.Error()))
}

// ownWords puts svops' messages that keep the CLI's words (its commands
// and flags) in the TUI's own. They are svops' exported errors, which the
// CLI's tests hold to their text.
func ownWords(s string) string {
	return wordsReplacer.Replace(s)
}

var wordsReplacer = strings.NewReplacer(
	svops.ErrNoOwnKeys.Error(), "no keys to show: make an OpenPGP key in Keys (P, then n), or name key items or people's public keys",
	svops.ErrNoDefaultVault.Error(), "there is no default vault: N makes one, and V makes one the default",
	svops.ErrNoGnuPGKey.Error(), "the vault holds no OpenPGP key gpg can use: make one in Keys (P, then n, version 4), or import one",
	svops.ErrNotOneSecretKey.Error(), "someone's public key goes to Contacts (C, then a)",
	"pick another name with --item ("+svops.ErrKeyExists.Error()+")", "give another item name ("+svops.ErrKeyExists.Error()+")",
	svops.ErrNoAgeIdentity.Error(), "make one in Keys (P, then k)",
	svops.ErrUninstallFirst.Error(), "uninstall first (Browsers, then u)",
	"(use --force to overwrite it, or -o)", "(tick Replace to write over it, or choose another name)",
)

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

func (u *UI) drawStatus() {
	var b strings.Builder
	switch {
	case u.gone:
		b.WriteString(" [red]secretvault's background service stopped: nothing can be shown until it is back. q quits.[-]")
		u.status.SetText(b.String())
		return
	case u.vault == "":
		b.WriteString(" [gray]no vault[-]")
	default:
		fmt.Fprintf(&b, " [::b]%s[::-] ", tview.Escape(u.vault))
		switch v := u.vaultInfo(u.vault); {
		case v == nil:
		case v.ID == "":
			b.WriteString("[red]folder missing[-]")
		case v.Locked:
			b.WriteString("[gray]locked[-]")
		default:
			b.WriteString("[green]unlocked[-]")
			if u.listed {
				if len(u.entries) == 1 {
					b.WriteString(" · 1 item")
				} else {
					fmt.Fprintf(&b, " · %d items", len(u.entries))
				}
			}
		}
	}
	if u.busy > 0 {
		b.WriteString(" [yellow]…[-]")
	}
	if len(u.emergency) > 0 {
		fmt.Fprintf(&b, "  │ [yellow]%s[-]", tview.Escape(u.emergency[0]))
		if len(u.emergency) > 1 {
			fmt.Fprintf(&b, " [yellow](and %d more: E)[-]", len(u.emergency)-1)
		}
	}
	if u.message != "" {
		b.WriteString("  │ " + u.message)
	}
	u.status.SetText(b.String())
}
