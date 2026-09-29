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
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// ErrRunning is a second daemon on a socket that already has one.
var ErrRunning = errors.New("a secretvaultd is already running")

// Options configure a daemon.
type Options struct {
	// Home is the data directory (svcore.Home() when "").
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

	// Desktop, when set, replaces the desktop prompter (tests).
	Desktop Prompter

	// Peer identifies a connection's program (svpeer.FromConn when nil;
	// tests stand in fake programs).
	Peer func(net.Conn) (*svpeer.Process, error)

	// IdleUnit is what AutoLock.IdleMinutes counts (time.Minute when 0;
	// tests shorten it).
	IdleUnit time.Duration

	// Log receives one line per notable event. Nothing secret is logged.
	Log func(string)

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
}

// New prepares a daemon: it reads the config and opens (locked) every
// registered vault.
func New(opts Options) (*Daemon, error) {
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
	device, err := svcore.Device(opts.Home)
	if err != nil {
		return nil, err
	}
	cfg, err := loadConfig(opts.Home)
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
	d.desktop = opts.Desktop
	if d.desktop == nil {
		d.desktop = desktopPrompter(cfg.Prompt)
	}
	return d, nil
}

// sibling matches the named secretvault program installed beside the
// running daemon: the default IsCLI and IsPromptAgent.
func sibling(name string) func(*svpeer.Process) bool {
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return func(p *svpeer.Process) bool {
		exe, err := os.Executable()
		if err != nil {
			return false
		}
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			exe = real
		}
		return p.Exe == filepath.Join(filepath.Dir(exe), name)
	}
}

// Serve accepts clients on ln until ctx ends, then locks every vault.
func (d *Daemon) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		ln.Close()
	}()
	defer d.LockAll("daemon stopping")
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
		go d.serveConn(conn)
	}
}

// client is one connected program.
type client struct {
	conn      *svrpc.Conn
	proc      *svpeer.Process
	cli       bool // secretvault's own CLI
	name      string
	canPrompt bool
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
// other program asked to collect a passphrase would learn it.
func (c *client) mayPrompt() bool { return c.cli && c.canPrompt }

func (d *Daemon) serveConn(nc net.Conn) {
	proc, err := d.opts.Peer(nc)
	if err != nil {
		d.opts.Log("refused a connection: " + err.Error())
		nc.Close()
		return
	}
	cl := &client{proc: proc, cli: d.opts.IsCLI(proc)}
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
	d.mu.Unlock()
	d.broker.DropConn(cl)
}

// notify sends an event to every client.
func (d *Daemon) notify(method string, ev svrpc.VaultEvent) {
	d.mu.Lock()
	var all []*client
	for c := range d.clients {
		all = append(all, c)
	}
	d.mu.Unlock()
	for _, c := range all {
		go c.conn.Notify(method, ev)
	}
}

// Status describes the daemon.
func (d *Daemon) Status() svrpc.Status {
	st := svrpc.Status{Version: secretvault.Version, PID: os.Getpid(), Home: d.home, Socket: d.opts.Socket}
	st.Vaults = d.vaultInfos()
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
