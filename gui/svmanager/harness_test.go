package svmanager

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/app"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/internal/fidotest"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svfido"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svstore"
)

// Nothing in these tests reaches the machine they run on: no display (the
// windows are headless), no session bus, no keyring, no clipboard (a fake
// takes the copies), no tray (uitoolkit's fake), no system command (svops's
// CommandRunner is a fake that refuses), a home of their own (so no
// ~/.gnupg, no browser profile, no ~/.local/share/secretvault, no
// ~/.docker: DOCKER_CONFIG is theirs too; nor Windows' APPDATA and
// LOCALAPPDATA), and a daemon of their own on a
// temporary socket, with a temporary home.
func TestMain(m *testing.M) {
	if how := os.Getenv("SVMANAGER_FAKE_CLIP"); how != "" {
		// Run by a test as the CLI's clipboard helper (clip_test.go).
		os.Exit(fakeClipHelper(how))
	}
	for _, k := range []string{"DISPLAY", "WAYLAND_DISPLAY", "AT_SPI_BUS_ADDRESS", "DBUS_SYSTEM_BUS_ADDRESS",
		"SECRETVAULT_SOCK", "SECRETVAULT_HOME", "SECRETVAULT_VAULT", "SECRETVAULT_HOST", "GNUPGHOME",
		"UITK_THEME", "UITK_NATIVE_DIALOGS"} {
		os.Unsetenv(k)
	}
	dir, err := os.MkdirTemp("", "svgui-env")
	if err != nil {
		panic(err)
	}
	// Every bus address leads nowhere, and so does the runtime directory
	// a client falls back to for one ($XDG_RUNTIME_DIR/bus).
	os.Setenv("DBUS_SESSION_BUS_ADDRESS", "unix:path=/nonexistent/svgui-test")
	os.Setenv("DBUS_SYSTEM_BUS_ADDRESS", "unix:path=/nonexistent/svgui-test-system")
	os.Setenv("XDG_RUNTIME_DIR", filepath.Join(dir, "run"))
	os.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, "config"))
	os.Setenv("XDG_DATA_HOME", filepath.Join(dir, "data"))
	os.Setenv("XDG_CACHE_HOME", filepath.Join(dir, "cache"))
	os.Setenv("XDG_STATE_HOME", filepath.Join(dir, "state"))
	os.Setenv("HOME", filepath.Join(dir, "home"))
	// Windows' homes for programs' data: no browser profile there either.
	os.Setenv("APPDATA", filepath.Join(dir, "appdata"))
	os.Setenv("LOCALAPPDATA", filepath.Join(dir, "localappdata"))
	os.Setenv("USERPROFILE", filepath.Join(dir, "home"))
	os.Setenv("DOCKER_CONFIG", filepath.Join(dir, "docker"))
	os.Setenv("SECRETVAULT_HOME", filepath.Join(dir, "secretvault"))
	os.MkdirAll(filepath.Join(dir, "secretvault"), 0o700)
	os.Setenv("SECRETVAULT_SOCK", filepath.Join(dir, "nowhere.sock"))
	os.Setenv("SECRETVAULT_HOST_DATA", filepath.Join(dir, "host-data"))
	os.Setenv("SECRETVAULT_HOST_RUNTIME", filepath.Join(dir, "host-run"))
	os.Setenv("UITK_TRAY", "fake")
	svops.CommandRunner = commands.run
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

// commands records the system commands svops would have run, and runs
// none: each fails, as a command that is not there does.
var commands = &fakeCommands{}

type fakeCommands struct {
	mu   sync.Mutex
	runs []string
}

func (f *fakeCommands) run(name string, args ...string) ([]byte, error) {
	f.mu.Lock()
	f.runs = append(f.runs, strings.Join(append([]string{name}, args...), " "))
	f.mu.Unlock()
	return nil, errors.New("not run in tests: " + name)
}

var pass = "correct horse battery staple"

const totpURI = "otpauth://totp/Example:ada?secret=JBSWY3DPEHPK3PXP&issuer=Example"

// nobody is the desktop in these tests: there is nobody there to ask, so
// nothing ever pops up on the machine running them.
type nobody struct{}

func (nobody) Passphrase(context.Context, svrpc.PromptAsk) ([]byte, error) {
	return nil, svrpc.ErrCanceled
}
func (nobody) Choose(context.Context, svrpc.PromptAsk) (string, error) { return "", svrpc.ErrCanceled }
func (nobody) Describe() string                                        { return "nobody" }

func login(name, user, password string) svrpc.Item {
	return svrpc.Item{Kind: "login", Name: name, Fields: []svrpc.Field{
		{Name: "username", Type: "text", Value: []byte(user)},
		{Name: "password", Type: "concealed", Value: []byte(password)},
	}}
}

// fakeClipboard records copies instead of making them.
type fakeClipboard struct {
	mu     sync.Mutex
	copies []*fakeCopy
}

type fakeCopy struct {
	mu        sync.Mutex
	data      []byte
	text      string // what was copied, kept for the test to compare
	ttl       time.Duration
	cleared   bool
	onCleared func()
}

func (f *fakeClipboard) SetSecret(data []byte, ttl time.Duration) Copied {
	c := &fakeCopy{data: data, text: string(data), ttl: ttl}
	f.mu.Lock()
	f.copies = append(f.copies, c)
	f.mu.Unlock()
	return c
}

func (f *fakeClipboard) last() *fakeCopy {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.copies) == 0 {
		return nil
	}
	return f.copies[len(f.copies)-1]
}

func (f *fakeClipboard) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.copies)
}

func (c *fakeCopy) Clear() {
	c.mu.Lock()
	clear(c.data)
	already := c.cleared
	c.cleared = true
	fn := c.onCleared
	c.onCleared = nil
	c.mu.Unlock()
	if fn != nil && !already {
		fn()
	}
}

// OnCleared is as uitoolkit's: at most once, and at once for a copy that
// has gone already.
func (c *fakeCopy) OnCleared(fn func()) {
	c.mu.Lock()
	if c.cleared {
		c.mu.Unlock()
		fn()
		return
	}
	c.onCleared = fn
	c.mu.Unlock()
}

func (c *fakeCopy) wiped() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, b := range c.data {
		if b != 0 {
			return false
		}
	}
	return c.cleared
}

// harness is a real daemon in this process, a vault with a few items, and
// the manager in a headless window, driven through uitoolkit's test
// helpers.
type harness struct {
	t     *testing.T
	dir   string
	sock  string
	admin *secretvault.Client // sets things up and checks them, as the CLI would
	app   *app.Application
	m     *Manager
	clip  *fakeClipboard
	now   time.Time

	picks      []string // the paths the next file dialogs answer with
	daemonStop func()

	tweaks []func(*svd.Options) // to the daemon's options
	d      *svd.Daemon

	keysMu sync.Mutex
	keys   []*fidotest.Authenticator // the security keys plugged in
}

// plug plugs in a software security key.
func (h *harness) plug(o fidotest.Options) *fidotest.Authenticator {
	a := fidotest.New(o)
	h.t.Cleanup(a.Stop)
	h.keysMu.Lock()
	h.keys = append(h.keys, a)
	h.keysMu.Unlock()
	return a
}

// openKeys is the daemon's way to the security keys: software ones only.
func (h *harness) openKeys(ctx context.Context) ([]*svfido.Device, error) {
	h.keysMu.Lock()
	keys := append([]*fidotest.Authenticator(nil), h.keys...)
	h.keysMu.Unlock()
	var out []*svfido.Device
	for _, a := range keys {
		d, err := svfido.NewDevice(ctx, a.Transport(), a.Name())
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, nil
}

// fakeSealer seals login keys in the clear, marked, as the OS would seal
// them to the user.
type fakeSealer struct{}

func (fakeSealer) Name() string     { return "test sealer" }
func (fakeSealer) Available() error { return nil }
func (fakeSealer) Seal(name string, secret []byte) ([]byte, error) {
	return append([]byte(name+":"), secret...), nil
}
func (fakeSealer) Unseal(name string, sealed []byte) ([]byte, error) {
	b, ok := bytes.CutPrefix(sealed, []byte(name+":"))
	if !ok {
		return nil, errors.New("sealed for something else")
	}
	return append([]byte(nil), b...), nil
}

// noNetwork refuses every request: contact lookups go nowhere.
type noNetwork struct{}

func (noNetwork) RoundTrip(r *http.Request) (*http.Response, error) {
	return nil, errors.New("no network in tests: " + r.URL.Host)
}

func newHarness(t *testing.T, tweaks ...func(*svd.Options)) *harness {
	t.Helper()
	a := svcrypto.DefaultArgon2
	svcrypto.DefaultArgon2 = svcrypto.KDFParams{Alg: svcrypto.Argon2id, Time: 1, MemoryKiB: 64, Threads: 1}
	t.Cleanup(func() { svcrypto.DefaultArgon2 = a })

	dir, err := os.MkdirTemp("", "svgui") // short: socket paths have a length limit
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &harness{t: t, dir: dir, sock: filepath.Join(dir, "s", "d.sock"), clip: &fakeClipboard{},
		now: time.Date(2026, 9, 29, 12, 0, 10, 0, time.UTC), tweaks: tweaks}
	h.startDaemon()
	t.Cleanup(func() { h.stopDaemon() })
	c := h.ctx()
	if _, err := h.admin.CreateVault(c, svrpc.VaultCreateParams{Name: "personal", Passphrase: []byte(pass)}); err != nil {
		t.Fatal(err)
	}
	gh := login("web/github.com", "ada", "hunter2-github")
	gh.Label, gh.Tags, gh.Attrs = "GitHub", []string{"dev"}, map[string]string{"service": "github"}
	gh.Fields = append(gh.Fields, svrpc.Field{Name: "url", Type: "url", Value: []byte("https://github.com")})
	for _, it := range []svrpc.Item{
		gh,
		login("web/gitlab.com", "ada", "gitlab-pass-42"),
		login("mail/fastmail", "ada@fastmail.com", "fastmail-secret"),
		{Kind: "otp", Name: "2fa/example", Fields: []svrpc.Field{{Name: "otp", Type: "otp", Value: []byte(totpURI)}}},
	} {
		if _, err := h.admin.Put(c, "", it); err != nil {
			t.Fatal(err)
		}
	}
	if err := h.admin.Lock(c, "", true); err != nil {
		t.Fatal(err)
	}
	return h
}

// startDaemon runs secretvaultd in this process, on the harness's socket
// and home, and connects the admin client to it.
func (h *harness) startDaemon() {
	h.t.Helper()
	// Every client is one of secretvault's own programs here, as the GUI
	// is to a daemon installed beside it; the GUI is the windowed one.
	var mu sync.Mutex
	var conns []net.Conn
	opts := svd.Options{Home: filepath.Join(h.dir, "home"), Socket: h.sock, Desktop: nobody{},
		IsCLI:      func(*svpeer.Process) bool { return true },
		IsWindowed: func(*svpeer.Process) bool { return true },
		// Software security keys only, a sealer of its own, and no
		// network: nothing reaches the machine's keys, its OS sealing or
		// the internet.
		SecurityKeys: h.openKeys,
		Sealer:       fakeSealer{},
		HTTP:         &http.Client{Transport: noNetwork{}},
		Peer: func(c net.Conn) (*svpeer.Process, error) {
			mu.Lock()
			conns = append(conns, c)
			mu.Unlock()
			return svpeer.FromConn(c)
		}}
	for _, tweak := range h.tweaks {
		tweak(&opts)
	}
	d, err := svd.New(opts)
	if err != nil {
		h.t.Fatal(err)
	}
	h.d = d
	ln, cleanup, err := svd.Listen(h.sock)
	if err != nil {
		h.t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	d.StartSync(ctx)
	go func() { d.Serve(ctx, ln); close(done) }()
	// A daemon process that stops takes its connections with it; Serve
	// alone leaves them open, so they are closed here.
	h.daemonStop = func() {
		cancel()
		<-done
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
		cleanup()
	}
	h.admin, err = secretvault.Connect(secretvault.Options{Socket: h.sock, NoStart: true, Name: "admin"})
	if err != nil {
		h.t.Fatal(err)
	}
}

// addConflicted makes a vault, "shared", in which two devices changed the
// item "site" at the same time, as two devices syncing through a folder
// would, and registers it with the daemon, locked.
func (h *harness) addConflicted() {
	h.t.Helper()
	path := filepath.Join(h.dir, "shared")
	store, err := svstore.OpenDir(path)
	if err != nil {
		h.t.Fatal(err)
	}
	base := time.Date(2026, 9, 1, 9, 0, 0, 0, time.UTC)
	a, _, err := svcore.Create(store, 0, svcore.NewSlot{Type: svformat.SlotPassphrase, Passphrase: []byte(pass)},
		svcore.Options{Device: svformat.ID{0xA}, Now: func() time.Time { return base }})
	if err != nil {
		h.t.Fatal(err)
	}
	site := func(p string) svcore.Item {
		return svcore.Item{Kind: "login", Name: "site", Fields: []svcore.Field{{Name: "password", Type: "concealed", Value: []byte(p)}}}
	}
	if _, err := a.Put(site("original")); err != nil {
		h.t.Fatal(err)
	}
	b, err := svcore.Open(store, svcore.Options{Device: svformat.ID{0xB}, Now: func() time.Time { return base.Add(time.Hour) }})
	if err != nil {
		h.t.Fatal(err)
	}
	if err := b.Unlock(svcore.Passphrase([]byte(pass))); err != nil {
		h.t.Fatal(err)
	}
	a.Put(site("from laptop"))
	b.Put(site("from desktop")) // the later clock: it wins
	a.Lock()
	b.Lock()
	if _, err := h.admin.AddVault(h.ctx(), "shared", path); err != nil {
		h.t.Fatal(err)
	}
}

// stopDaemon stops it, closing every connection.
func (h *harness) stopDaemon() {
	if h.daemonStop == nil {
		return
	}
	h.admin.Close()
	h.daemonStop()
	h.daemonStop = nil
}

func (h *harness) ctx() context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	h.t.Cleanup(cancel)
	return c
}

// start runs the manager in a headless window, in the dark look unless
// look says otherwise.
func (h *harness) start(opts Options) {
	h.t.Helper()
	look := opts.App
	if look == nil {
		h.app = uitoolkit.New(uitoolkit.Options{Look: style.DarkLook(), Headless: true, Scale: 1, DisableLookWatch: true})
	} else {
		h.app = look
	}
	opts.App = h.app
	opts.Headless = true
	opts.Connect = func(o secretvault.Options) (*secretvault.Client, error) {
		o.Socket, o.NoStart = h.sock, true
		return secretvault.Connect(o)
	}
	if opts.Clipboard == nil {
		opts.Clipboard = h.clip
	}
	opts.PickFile = func(_ PickMode, _ string, done func(string)) {
		if len(h.picks) == 0 {
			done("")
			return
		}
		p := h.picks[0]
		h.picks = h.picks[1:]
		done(p)
	}
	if opts.Now == nil {
		opts.Now = func() time.Time { return h.now }
	}
	m, err := New(opts)
	if err != nil {
		h.t.Fatal(err)
	}
	h.m = m
	h.t.Cleanup(func() {
		m.Close()
		for _, w := range h.app.Windows() {
			w.Close()
		}
	})
	m.Start()
	h.pump()
}

func (h *harness) win() *app.Window { return h.m.win }

// pump runs a frame, and whatever the daemon's answers posted.
func (h *harness) pump() { h.app.PumpOnce() }

// waitFor pumps until cond holds.
func (h *harness) waitFor(what string, cond func() bool) {
	h.t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		h.pump()
		if cond() {
			return
		}
		time.Sleep(3 * time.Millisecond)
	}
	h.t.Fatalf("%s never happened; the window says:\n%s", what, h.text())
}

// idle pumps until nothing is waiting on the daemon.
func (h *harness) idle() {
	h.t.Helper()
	h.waitFor("the daemon answering", func() bool { return h.m.busy == 0 })
	h.pump()
}

// text is everything the window says, as assistive technology reads it:
// names, values and descriptions, a line each.
func (h *harness) text() string { return windowText(h.win()) }

func windowText(w *app.Window) string {
	var b strings.Builder
	w.AccessibleTree().Walk(func(n *a11y.Node) bool {
		for _, s := range []string{n.Name, n.Value, n.Description} {
			if s != "" {
				b.WriteString(s)
				b.WriteByte('\n')
			}
		}
		return true
	})
	return b.String()
}

func (h *harness) waitText(want string) {
	h.t.Helper()
	h.waitFor("showing "+want, func() bool { return strings.Contains(h.text(), want) })
}

// asking waits for the daemon's question to be up, and returns it.
func (h *harness) asking() *promptDialog {
	h.t.Helper()
	h.waitFor("the passphrase dialog", func() bool { return h.m.asking != nil && h.m.asking.win != nil })
	h.pump()
	return h.m.asking
}

// unlock answers the passphrase dialog the first listing brings up.
func (h *harness) unlock() {
	h.t.Helper()
	h.waitText("Vault personal is locked")
	h.win().Press(platform.KeyU, platform.ModCtrl)
	d := h.asking()
	d.win.Type(pass)
	d.win.Press(platform.KeyReturn)
	h.waitFor("the items", func() bool { return h.m.listed && len(h.m.entries) == 4 })
	h.idle()
}

// selectItem selects an item in the list, as a click on its row does.
func (h *harness) selectItem(name string) {
	h.t.Helper()
	for n, i := range h.m.shown {
		if h.m.entries[i].Item.Name == name {
			h.m.ui.items.Selected = n
			h.m.itemSelected(n)
			h.pump()
			return
		}
	}
	h.t.Fatalf("%s is not in the list", name)
}

// open selects an item and opens it with Enter.
func (h *harness) open(name string) {
	h.t.Helper()
	h.selectItem(name)
	h.win().FocusOn(h.m.ui.items)
	h.win().Press(platform.KeyReturn)
	h.waitFor("opening "+name, func() bool { return h.m.cur != nil && h.m.cur.Item.Name == name && h.m.ui.view.open() })
	h.idle()
}

// prove presents the key on the admin connection, as the CLI does with
// --passphrase-file: the daemon then lets it use the vault.
func (h *harness) prove() {
	h.t.Helper()
	if _, err := h.admin.Unlock(h.ctx(), "", &svrpc.Key{Type: "passphrase", Secret: []byte(pass)}); err != nil {
		h.t.Fatal(err)
	}
}

// get reads an item as the CLI would, presenting the key.
func (h *harness) get(name string) (svrpc.Entry, error) {
	h.prove()
	return h.admin.Get(h.ctx(), "", name)
}

func field(e svrpc.Entry, name string) string {
	for _, f := range e.Item.Fields {
		if f.Name == name {
			return string(f.Value)
		}
	}
	return ""
}

// find is the first component under root that match accepts.
func find[T widget.Component](root widget.Component, match func(T) bool) T {
	var zero, hit T
	found := false
	widget.Walk(root, func(c widget.Component) {
		if found {
			return
		}
		if t, ok := c.(T); ok && (match == nil || match(t)) {
			hit, found = t, true
		}
	})
	if !found {
		return zero
	}
	return hit
}

// button is the button labelled text under root.
// shown reports whether c is on the screen: it and everything it is in
// visible.
func shown(c widget.Component) bool {
	if c == nil {
		return false
	}
	for ; c != nil; c = c.Parent() {
		if !c.Visible() {
			return false
		}
	}
	return true
}

func button(root widget.Component, text string) *widgets.Button {
	return find(root, func(b *widgets.Button) bool { return b.Text == text })
}

// overlay is the dialog up over the window, or nil.
func (h *harness) overlay() widget.Component { return h.win().Overlay() }

// click presses a button the way a pointer does.
func (h *harness) click(w *app.Window, b *widgets.Button) {
	h.t.Helper()
	if b == nil {
		h.t.Fatalf("no such button; the window says:\n%s", windowText(w))
	}
	// A button scrolled out of sight is scrolled to first, as a person
	// would: uitoolkit's ClickComponent does that.
	if !w.ClickComponent(b) {
		h.t.Fatalf("button %q has no box to click", b.Text)
	}
}
