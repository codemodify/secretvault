// Package svd is secretvaultd: the process that holds vault keys and
// brokers every access to them. Clients (the CLI, the managers, the faces
// such as the Secret Service) talk to it over svrpc; it identifies each
// caller (svpeer), checks what has been decided about it (svbroker), asks
// a person when nothing has (svprompt), and records the outcome in the
// audit log.
//
// The package is the daemon as a library, so tests (and later the
// all-in-one builds) can run it in-process on a temporary socket.
package svd

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svfido"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svseal"
	"github.com/codemodify/secretvault/svsync"
)

// ErrRunning is a second daemon on a socket that already has one.
var ErrRunning = errors.New("a secretvaultd is already running")

// Mode is who the daemon serves (docs/architecture.md, "Daemon modes").
type Mode int

const (
	// ModeUser is a person's own daemon, in their session: it asks them
	// before any program uses a secret.
	ModeUser Mode = iota
	// ModeHost is the machine's system service (host.go): it serves the
	// machine's services by policy, and never asks anyone.
	ModeHost
)

// Options configure a daemon.
type Options struct {
	// Mode is ModeUser (the default) or ModeHost.
	Mode Mode

	// Host configures host mode.
	Host HostOptions

	// Home is the data directory (svcore.Home() when "", or in host mode
	// svrpc.HostDataDir()).
	Home string

	// Socket is the path it serves, for Status.
	Socket string

	// IsCLI reports whether a peer is one of secretvault's own terminal
	// programs, the only clients ever asked to prompt for a passphrase.
	// Nil means: "secretvault" or "secretvault-tui" in the daemon's own
	// directory.
	IsCLI func(*svpeer.Process) bool

	// IsPromptAgent reports whether a peer is secretvault-tui-prompt, the
	// only program besides the CLI that may register as the prompter. Nil
	// means: the one in the daemon's own directory.
	IsPromptAgent func(*svpeer.Process) bool

	// IsPortal reports whether a caller on the bus is xdg-desktop-portal,
	// the only one that may ask for a Flatpak app's secret (portal.go).
	// Nil means: a program named xdg-desktop-portal that the
	// administrator installed.
	IsPortal func(*svpeer.Process) bool

	// Sealer keeps the keys of vaults opened at login (svseal.Default when
	// nil; tests stand in their own).
	Sealer svseal.Sealer

	// Desktop, when set, replaces the desktop prompter (tests).
	Desktop Prompter

	// Peer identifies a connection's program (svpeer.FromConn when nil,
	// or in host mode svpeer.FromConnAnyUser; tests stand in fake
	// programs).
	Peer func(net.Conn) (*svpeer.Process, error)

	// Launcher identifies the program that started a browser relay: the
	// browser, which consent and the audit log then name (svpeer.Parent
	// of the relay when nil; tests stand in a browser).
	Launcher func(relay *svpeer.Process) (*svpeer.Process, error)

	// SecurityKeys opens the FIDO2 security keys plugged in
	// (svfido.OpenAll when nil; tests plug in software keys).
	SecurityKeys func(context.Context) ([]*svfido.Device, error)

	// IdleUnit is what AutoLock.IdleMinutes counts (time.Minute when 0;
	// tests shorten it).
	IdleUnit time.Duration

	// Log receives one line per notable event. Nothing secret is logged.
	Log func(string)

	// HTTP fetches keys for contact lookups (WKD, keyservers);
	// svtrust.DefaultClient() when nil (tests point it elsewhere).
	HTTP *http.Client

	// Now is the clock (tests replace it).
	Now func() time.Time
}

// Daemon is a running secretvaultd.
type Daemon struct {
	opts   Options
	home   string
	broker *svbroker.Broker
	audit  *svbroker.Audit
	svOpts svcore.Options

	mu      sync.Mutex
	cfg     *Config
	vaults  map[string]*managedVault // by name
	clients map[*client]bool
	agent   *client // a registered secretvault-tui-prompt --agent
	desktop Prompter
	ss      *secretService // the Secret Service face, when serving
	ssStop  func()
	stores  sync.Map // *svcore.Vault -> its contacts' *svtrust.Store (trust.go)

	syncCtx context.Context  // set by StartSync; nil while the daemon does not sync
	syncID  *svsync.Identity // this device's key for sync servers

	host *hostState // host mode's identity, policy and log; nil in user mode
}

// New prepares a daemon: it reads the config and opens (locked) every
// registered vault.
func New(opts Options) (*Daemon, error) {
	host := opts.Mode == ModeHost
	if host && runtime.GOOS != "linux" {
		return nil, errors.New("svd: host mode runs on Linux only: it serves systemd's credentials")
	}
	if opts.Home == "" && host {
		opts.Home = svrpc.HostDataDir()
	}
	if opts.Home == "" {
		h, err := svcore.Home()
		if err != nil {
			return nil, err
		}
		opts.Home = h
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Log == nil {
		opts.Log = func(string) {}
	}
	if opts.Peer == nil {
		opts.Peer = svpeer.FromConn
		if host {
			opts.Peer = svpeer.FromConnAnyUser // services of other users, by policy
		}
	}
	if opts.Launcher == nil {
		opts.Launcher = func(relay *svpeer.Process) (*svpeer.Process, error) { return svpeer.Parent(relay.PID) }
	}
	if opts.IdleUnit == 0 {
		opts.IdleUnit = time.Minute
	}
	if opts.IsCLI == nil {
		cli, tui := sibling("secretvault"), sibling("secretvault-tui")
		opts.IsCLI = func(p *svpeer.Process) bool { return cli(p) || tui(p) }
	}
	if opts.IsPromptAgent == nil {
		opts.IsPromptAgent = sibling("secretvault-tui-prompt")
	}
	if opts.Sealer == nil {
		opts.Sealer = svseal.Default()
	}
	if opts.IsPortal == nil {
		opts.IsPortal = func(p *svpeer.Process) bool {
			return p.SystemOwned && filepath.Base(p.Exe) == "xdg-desktop-portal"
		}
	}
	device, err := svcore.Device(opts.Home)
	if err != nil {
		return nil, err
	}
	autoLock := DefaultAutoLock
	if host {
		autoLock = svrpc.AutoLock{} // nothing locks on idle unless the config says so
	}
	cfg, err := loadConfig(opts.Home, autoLock)
	if err != nil {
		return nil, err
	}
	d := &Daemon{
		opts:    opts,
		home:    opts.Home,
		broker:  svbroker.New(device),
		audit:   svbroker.NewAudit(filepath.Join(opts.Home, "audit")),
		svOpts:  svcore.Options{Device: device, Now: opts.Now},
		cfg:     cfg,
		vaults:  map[string]*managedVault{},
		clients: map[*client]bool{},
	}
	for _, vc := range cfg.Vaults {
		mv, err := d.openVault(vc)
		if err != nil {
			opts.Log(fmt.Sprintf("vault %s at %s: %v", vc.Name, vc.Path, err))
		}
		d.vaults[vc.Name] = mv // kept even when missing: it shows as unavailable
	}
	if host {
		// Nobody is there to ask: no desktop prompt, ever.
		if err := d.startHost(); err != nil {
			return nil, err
		}
		return d, nil
	}
	d.desktop = opts.Desktop
	if d.desktop == nil {
		d.desktop = desktopPrompter(cfg.Prompt)
	}
	return d, nil
}

// defaultAutoLock is how a newly registered vault locks itself: after 15
// idle minutes, on screen lock and on sleep for a person; never, for the
// host (the vault's auto_lock in config.json changes it).
func (d *Daemon) defaultAutoLock() svrpc.AutoLock {
	if d.host != nil {
		return svrpc.AutoLock{}
	}
	return DefaultAutoLock
}

// sibling matches the named secretvault program installed beside the
// running daemon: the default IsCLI and IsPromptAgent.
func sibling(name string) func(*svpeer.Process) bool {
	return func(p *svpeer.Process) bool {
		path, ok := ownProgram(name)
		return ok && p.Exe == path
	}
}

// Serve accepts clients on ln until ctx ends, then locks every vault. In
// host mode ln is root's admin socket.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	defer d.LockAll("daemon stopping")
	defer d.stopAllSync()
	r := roleUser
	if d.host != nil {
		r = roleAdmin
	}
	return accept(ctx, ln, func(c net.Conn) { d.serveConn(c, r) })
}

// accept hands every connection on ln to serve until ctx ends.
func accept(ctx context.Context, ln net.Listener, serve func(net.Conn)) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return err
		}
		go serve(conn)
	}
}

// role is what a connection may do, by the socket it came in on.
type role int

const (
	roleUser    role = iota // a person's daemon: consent decides
	roleAdmin               // host mode, the admin socket: root, who may do anything
	roleService             // host mode, the services socket: what the policy lists
)

// client is one connected program.
type client struct {
	conn      *svrpc.Conn
	proc      *svpeer.Process
	role      role
	cli       bool // secretvault's own CLI (in host mode, root on the admin socket)
	name      string
	canPrompt bool

	// A face that takes a connection over (the browser relay, browser.go)
	// sets these, under Daemon.mu: face is its state, events receives the
	// daemon's notifications in the connection's place, and closed runs
	// when the connection is gone.
	face   any
	events func(method string, ev svrpc.VaultEvent)
	closed func()
}

// identity is the key decisions about this client are stored under. The
// CLI on a terminal is known by its terminal session, so "allow until
// locked" covers that terminal, not every copy of the CLI.
func (c *client) identity() string {
	if c.cli && c.proc.Terminal != "" {
		return "terminal:" + c.proc.Terminal
	}
	return c.proc.Identity()
}

// display is how the client is named in prompts.
func (c *client) display() string {
	if c.cli && c.proc.Terminal != "" {
		return fmt.Sprintf("%s in terminal %s", filepath.Base(c.proc.Exe), c.proc.TTY)
	}
	return c.proc.Display()
}

// mayPrompt reports whether the daemon may ask this client to prompt for
// a passphrase: only secretvault's own CLI, and only when it offered. Any
// other program asked to collect a passphrase would learn it. The host
// daemon asks nobody.
func (c *client) mayPrompt() bool { return c.role == roleUser && c.cli && c.canPrompt }

func (d *Daemon) serveConn(nc net.Conn, r role) {
	proc, err := d.opts.Peer(nc)
	if err != nil {
		d.opts.Log("refused a connection: " + err.Error())
		nc.Close()
		return
	}
	cl := &client{proc: proc, role: r}
	switch r {
	case roleUser:
		cl.cli = d.opts.IsCLI(proc)
	case roleAdmin:
		// The admin socket is 0600 already; the kernel's word on the peer
		// is checked too. The host daemon runs as root, so this is root,
		// who is trusted as secretvault's own programs are.
		if proc.UID != os.Getuid() {
			d.opts.Log(fmt.Sprintf("refused process %d of uid %d on the admin socket", proc.PID, proc.UID))
			nc.Close()
			return
		}
		cl.cli = true
	}
	cl.conn = svrpc.NewConn(nc, d.handle)
	cl.conn.Value = cl
	d.mu.Lock()
	d.clients[cl] = true
	d.mu.Unlock()
	cl.conn.Run()
	d.mu.Lock()
	delete(d.clients, cl)
	if d.agent == cl {
		d.agent = nil
	}
	closed := cl.closed
	d.mu.Unlock()
	d.broker.DropConn(cl)
	if closed != nil {
		closed()
	}
}

// notify sends an event to every client.
func (d *Daemon) notify(method string, ev svrpc.VaultEvent) {
	d.mu.Lock()
	var all []*client
	var faces []func(string, svrpc.VaultEvent)
	for c := range d.clients {
		switch {
		case c.events != nil:
			faces = append(faces, c.events)
		case c.role != roleService: // local services hear nothing about vaults
			all = append(all, c)
		}
	}
	d.mu.Unlock()
	for _, c := range all {
		go c.conn.Notify(method, ev)
	}
	for _, f := range faces {
		go f(method, ev)
	}
}

// Status describes the daemon.
func (d *Daemon) Status() svrpc.Status {
	st := svrpc.Status{Version: secretvault.Version, PID: os.Getpid(), Home: d.home, Socket: d.opts.Socket}
	st.Vaults = d.vaultInfos()
	if d.host != nil {
		st.Mode = "host"
		st.Prompts = "none (the host daemon asks nobody)"
		return st
	}
	st.Prompts = "none (no desktop prompter found)"
	if d.desktop != nil {
		st.Prompts = d.desktop.Describe()
	}
	d.mu.Lock()
	if d.agent != nil {
		st.Prompts = "terminal agent (" + d.agent.proc.TTY + "), else " + st.Prompts
	}
	d.mu.Unlock()
	return st
}

// LockAll locks every vault, saying why in the log.
func (d *Daemon) LockAll(why string) {
	d.mu.Lock()
	var all []*managedVault
	for _, mv := range d.vaults {
		all = append(all, mv)
	}
	d.mu.Unlock()
	for _, mv := range all {
		d.lock(mv, why)
	}
}
