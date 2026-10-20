package secretvault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svrpc"
)

// Client is a connection to secretvaultd. Programs use it to read and
// store secrets; every request is subject to the person's consent, which
// the daemon asks for on its own (a client never sees a passphrase unless
// it is secretvault's own CLI).
//
//	c, err := secretvault.Connect(secretvault.Options{Name: "comms-mail"})
//	...
//	e, err := c.Get(ctx, "", "comms-mail/vault-key")
//
// Errors are *svrpc.Error, matched by code with errors.Is: a vault that
// is not there (named, or no default) is svrpc.ErrNoVault, and an item
// (key, slot, grant) that is not there in a vault that is, ErrNotFound.
type Client struct {
	conn *svrpc.Conn
	opts Options
}

// Options configure a connection.
type Options struct {
	// Socket is the daemon's socket (svrpc.DefaultSocket() when "").
	Socket string

	// Name is the program's name, as the daemon's logs show it. Prompts
	// name programs by what the operating system says they are, not by
	// this.
	Name string

	// NoStart stops Connect from starting the daemon when none answers.
	NoStart bool

	// Prompter answers the daemon's prompt.ask calls. Only secretvault's
	// own CLI is ever asked (for a passphrase, on its terminal); other
	// programs leave it nil.
	Prompter func(ctx context.Context, q svrpc.PromptAsk) (svrpc.PromptAnswer, error)

	// OnEvent receives the daemon's notifications (vault.locked, ...).
	OnEvent func(method string, ev svrpc.VaultEvent)

	// OnNotify receives any other notification, as sent (the browser
	// relay's browser.frame).
	OnNotify func(method string, params json.RawMessage)
}

// ErrNoDaemon is a daemon that is not running and could not be started.
var ErrNoDaemon = errors.New("secretvaultd is not running")

// Connect connects to secretvaultd, starting it first if nothing answers.
func Connect(opts Options) (*Client, error) {
	if opts.Socket == "" {
		opts.Socket = svrpc.DefaultSocket()
	}
	c, err := dial(opts, 300*time.Millisecond, nil)
	if err == nil || opts.NoStart {
		return c, err
	}
	exited, serr := startDaemon(opts.Socket)
	if serr != nil {
		return nil, fmt.Errorf("%w and could not be started: %v", ErrNoDaemon, serr)
	}
	return dial(opts, 10*time.Second, exited)
}

// dial connects, retrying for up to wait. exited, when not nil, reports a
// daemon that was just started and has already stopped: there is then
// no point waiting any longer.
func dial(opts Options, wait time.Duration, exited <-chan string) (*Client, error) {
	deadline := time.Now().Add(wait)
	for {
		nc, err := net.Dial("unix", opts.Socket)
		if err == nil {
			return newClient(nc, opts)
		}
		select {
		case why := <-exited:
			return nil, fmt.Errorf("%w: it stopped at once: %s", ErrNoDaemon, why)
		default:
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("%w (%v)", ErrNoDaemon, err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func newClient(nc net.Conn, opts Options) (*Client, error) {
	c := &Client{opts: opts}
	c.conn = svrpc.NewConn(nc, c.serve)
	go c.conn.Run()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var res svrpc.HelloResult
	name := opts.Name
	if name == "" {
		name = filepath.Base(os.Args[0])
	}
	if err := c.conn.Call(ctx, svrpc.MHello, svrpc.HelloParams{Client: name, Version: Version, CanPrompt: opts.Prompter != nil}, &res); err != nil {
		c.conn.Close()
		return nil, err
	}
	return c, nil
}

// serve answers what the daemon sends this client.
func (c *Client) serve(ctx context.Context, _ *svrpc.Conn, method string, params json.RawMessage) (any, error) {
	switch method {
	case svrpc.MPromptAsk:
		if c.opts.Prompter == nil {
			return nil, svrpc.ErrNoPrompter
		}
		var q svrpc.PromptAsk
		if err := json.Unmarshal(params, &q); err != nil {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
		}
		return c.opts.Prompter(ctx, q)
	case svrpc.EVaultLocked, svrpc.EVaultUnlocked, svrpc.EItemChanged, svrpc.EEmergency:
		if c.opts.OnEvent != nil {
			var ev svrpc.VaultEvent
			json.Unmarshal(params, &ev)
			c.opts.OnEvent(method, ev)
		}
		return nil, nil
	}
	if c.opts.OnNotify != nil {
		c.opts.OnNotify(method, params)
		return nil, nil
	}
	return nil, svrpc.Errorf(svrpc.CodeMethodNotFound, "no method %q", method)
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Done is closed when the connection is gone.
func (c *Client) Done() <-chan struct{} { return c.conn.Done() }

// Call makes a raw protocol call (see svrpc for methods and shapes).
func (c *Client) Call(ctx context.Context, method string, params, result any) error {
	return c.conn.Call(ctx, method, params, result)
}

// startDaemon runs secretvaultd (the one beside this program, else on
// PATH), logging to secretvaultd.log beside its socket. The channel it
// returns says why, if the daemon stops before anyone reads it.
func startDaemon(socket string) (<-chan string, error) {
	bin := daemonBinary()
	if bin == "" {
		return nil, errors.New("no secretvaultd beside this program or on PATH")
	}
	dir := filepath.Dir(socket)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	logPath := filepath.Join(dir, "secretvaultd.log")
	logf, err := os.OpenFile(logPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		return nil, err
	}
	start, _ := logf.Seek(0, io.SeekEnd)
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), svrpc.EnvSocket+"="+socket)
	cmd.Stdout, cmd.Stderr = logf, logf
	detach(cmd)
	if err := cmd.Start(); err != nil {
		logf.Close()
		return nil, err
	}
	logf.Close() // the daemon has its own copy
	exited := make(chan string, 1)
	go func() {
		err := cmd.Wait()
		why := fmt.Sprint(err)
		if b, rerr := os.ReadFile(logPath); rerr == nil && int64(len(b)) > start {
			if tail := strings.TrimSpace(string(b[start:])); tail != "" {
				why = tail
			}
		}
		exited <- why
	}()
	return exited, nil
}

func daemonBinary() string {
	name := "secretvaultd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	if exe, err := os.Executable(); err == nil {
		if real, err := filepath.EvalSymlinks(exe); err == nil {
			p := filepath.Join(filepath.Dir(real), name)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				return p
			}
		}
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	return ""
}

// Typed calls. vault "" is the default vault.

func (c *Client) Status(ctx context.Context) (st svrpc.Status, err error) {
	err = c.conn.Call(ctx, svrpc.MStatus, nil, &st)
	return
}

// Where lists every place secretvault keeps or changes anything, as the
// daemon uses them, grouped as svrpc.PlaceGroups (svrpc.MWhere). Only
// secretvault's own programs are told.
func (c *Client) Where(ctx context.Context) ([]svrpc.Place, error) {
	var out []svrpc.Place
	err := c.conn.Call(ctx, svrpc.MWhere, nil, &out)
	return out, err
}

func (c *Client) Vaults(ctx context.Context) (out []svrpc.VaultInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MVaultList, nil, &out)
	return
}

func (c *Client) CreateVault(ctx context.Context, p svrpc.VaultCreateParams) (out svrpc.VaultCreateResult, err error) {
	err = c.conn.Call(ctx, svrpc.MVaultCreate, p, &out)
	return
}

// RequestVault asks for a new vault called name, for this program. The
// daemon asks the person, in secretvault's own prompt, whether to create
// it, and has them choose its passphrase (and shows them its recovery
// key); this program sees neither. It returns the new vault's name. The
// vault is unlocked and locks itself as any vault does, and this program
// still asks before it reads or stores anything in it.
//
// The errors, by errors.Is: svrpc.ErrExists, a vault of that name is
// there already (nothing was asked); svrpc.ErrDenied, the person said no,
// now or for good ("Don't ask again for this program"); svrpc.ErrCanceled,
// they dismissed the question or chose no passphrase; svrpc.ErrNoPrompter,
// nobody could be asked. A second request while one waits fails at once.
// Wait as long as a person may take: a minute or more.
func (c *Client) RequestVault(ctx context.Context, name string) (string, error) {
	var out svrpc.VaultRequestResult
	err := c.conn.Call(ctx, svrpc.MVaultRequest, svrpc.VaultRequestParams{Name: name}, &out)
	return out.Vault, err
}

func (c *Client) AddVault(ctx context.Context, name, path string) (out svrpc.VaultInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MVaultAdd, svrpc.VaultAddParams{Name: name, Path: path}, &out)
	return
}

func (c *Client) ForgetVault(ctx context.Context, vault string) error {
	return c.conn.Call(ctx, svrpc.MVaultForget, svrpc.VaultRef{Vault: vault}, nil)
}

func (c *Client) SetDefault(ctx context.Context, vault string) error {
	return c.conn.Call(ctx, svrpc.MVaultDefault, svrpc.VaultRef{Vault: vault}, nil)
}

// Unlock unlocks a vault with key, or with key nil asks the person.
func (c *Client) Unlock(ctx context.Context, vault string, key *svrpc.Key) (out svrpc.VaultInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MVaultUnlock, svrpc.UnlockParams{Vault: vault, Key: key}, &out)
	return
}

func (c *Client) Lock(ctx context.Context, vault string, all bool) error {
	return c.conn.Call(ctx, svrpc.MVaultLock, svrpc.LockParams{Vault: vault, All: all}, nil)
}

func (c *Client) Verify(ctx context.Context, vault string) (out svrpc.VerifyResult, err error) {
	err = c.conn.Call(ctx, svrpc.MVaultVerify, svrpc.VaultRef{Vault: vault}, &out)
	return
}

func (c *Client) Passwd(ctx context.Context, vault string, passphrase []byte) (out svrpc.SlotInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MVaultPasswd, svrpc.PasswdParams{Vault: vault, Passphrase: passphrase}, &out)
	return
}

// Rotate rotates a vault's master key (see svrpc.RotateParams).
func (c *Client) Rotate(ctx context.Context, p svrpc.RotateParams) (out svrpc.RotateResult, err error) {
	err = c.conn.Call(ctx, svrpc.MVaultRotate, p, &out)
	return
}

func (c *Client) Slots(ctx context.Context, vault string) (out []svrpc.SlotInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MSlotList, svrpc.VaultRef{Vault: vault}, &out)
	return
}

func (c *Client) AddSlot(ctx context.Context, p svrpc.SlotAddParams) (out svrpc.SlotInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MSlotAdd, p, &out)
	return
}

func (c *Client) RemoveSlot(ctx context.Context, vault, id string) error {
	return c.conn.Call(ctx, svrpc.MSlotRemove, svrpc.SlotRemoveParams{Vault: vault, ID: id}, nil)
}

// Get returns an item with its fields. The caller should zero field values
// when done with them.
func (c *Client) Get(ctx context.Context, vault, name string) (out svrpc.Entry, err error) {
	err = c.conn.Call(ctx, svrpc.MItemGet, svrpc.ItemRef{Vault: vault, Name: name}, &out)
	return
}

// List returns items (without their fields) whose names start with prefix.
func (c *Client) List(ctx context.Context, vault, prefix string) (out []svrpc.Entry, err error) {
	err = c.conn.Call(ctx, svrpc.MItemList, svrpc.ListParams{Vault: vault, Prefix: prefix}, &out)
	return
}

func (c *Client) Put(ctx context.Context, vault string, it svrpc.Item) (out svrpc.Entry, err error) {
	err = c.conn.Call(ctx, svrpc.MItemPut, svrpc.PutParams{Vault: vault, Item: it}, &out)
	return
}

func (c *Client) Delete(ctx context.Context, vault, name string) error {
	return c.conn.Call(ctx, svrpc.MItemDelete, svrpc.ItemRef{Vault: vault, Name: name}, nil)
}

func (c *Client) Rename(ctx context.Context, vault, from, to string) (out svrpc.Entry, err error) {
	err = c.conn.Call(ctx, svrpc.MItemRename, svrpc.RenameParams{Vault: vault, From: from, To: to}, &out)
	return
}

// MoveItems moves items to another vault, inside the daemon: p names them
// (Names), or says what their names start with (Prefix, svrpc.PrefixOf;
// "" is every item), and p.To the vault they go to. Their contents,
// attached files and private keys never reach this program. The person
// is asked once, in secretvault's own prompt, which names both vaults
// and the items, and unlocks either vault if need be. Every item is
// written to p.To before any is taken out of p.Vault, where they stay
// in the deleted items, to be brought back.
//
// The result says which items are where. So does an error that has
// something to say about the items: CodeExists (Clashes: p.To has those
// names already; nothing was written), CodeNotFound (Missing),
// CodeFailed (Conflicts, to settle first; or a failure midway: Both are
// in both vaults, NotDone only in p.Vault, and nothing is lost).
func (c *Client) MoveItems(ctx context.Context, p svrpc.MoveParams) (svrpc.MoveResult, error) {
	return c.moveItems(ctx, svrpc.MItemMove, p)
}

// CopyItems is MoveItems, but p.Vault keeps the items as they are.
func (c *Client) CopyItems(ctx context.Context, p svrpc.MoveParams) (svrpc.MoveResult, error) {
	return c.moveItems(ctx, svrpc.MItemCopy, p)
}

func (c *Client) moveItems(ctx context.Context, method string, p svrpc.MoveParams) (svrpc.MoveResult, error) {
	var out svrpc.MoveResult
	err := c.conn.Call(ctx, method, p, &out)
	var e *svrpc.Error
	if errors.As(err, &e) && len(e.Data) > 0 {
		json.Unmarshal(e.Data, &out)
	}
	return out, err
}

func (c *Client) History(ctx context.Context, vault, name string) (out []svrpc.Entry, err error) {
	err = c.conn.Call(ctx, svrpc.MItemHistory, svrpc.ItemRef{Vault: vault, Name: name}, &out)
	return
}

func (c *Client) Grants(ctx context.Context, vault string) (out []svrpc.Grant, err error) {
	err = c.conn.Call(ctx, svrpc.MGrantList, svrpc.VaultRef{Vault: vault}, &out)
	return
}

func (c *Client) Revoke(ctx context.Context, vault, id string) error {
	return c.conn.Call(ctx, svrpc.MGrantRevoke, svrpc.GrantRef{Vault: vault, ID: id}, nil)
}

// Grant decides about a program ahead of time (see svrpc.GrantAddParams).
func (c *Client) Grant(ctx context.Context, p svrpc.GrantAddParams) (out svrpc.Grant, err error) {
	err = c.conn.Call(ctx, svrpc.MGrantAdd, p, &out)
	return
}

func (c *Client) Audit(ctx context.Context, vault string, limit int) (out []svrpc.AuditEntry, err error) {
	err = c.conn.Call(ctx, svrpc.MAuditList, svrpc.AuditParams{Vault: vault, Limit: limit}, &out)
	return
}

// ServeKeyring turns the daemon's Secret Service face on or off (only
// secretvault's own CLI may).
func (c *Client) ServeKeyring(ctx context.Context, enable bool) error {
	return c.conn.Call(ctx, svrpc.MKeyringServe, svrpc.KeyringServeParams{Enable: enable}, nil)
}

// SecurityKeys lists the FIDO2 security keys the daemon can see.
func (c *Client) SecurityKeys(ctx context.Context) (out []svrpc.FIDO2Device, err error) {
	err = c.conn.Call(ctx, svrpc.MFIDO2List, nil, &out)
	return
}

// RegisterPrompter makes this connection the session's prompter
// (secretvault-tui-prompt --agent).
func (c *Client) RegisterPrompter(ctx context.Context, terminal string) error {
	return c.conn.Call(ctx, svrpc.MPromptRegister, svrpc.PromptRegisterParams{Terminal: terminal}, nil)
}

// SetLoginUnlock sets a vault to open when the person logs in, or not.
func (c *Client) SetLoginUnlock(ctx context.Context, vault string, on bool) (out svrpc.VaultInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MVaultLogin, svrpc.VaultLoginParams{Vault: vault, On: on}, &out)
	return
}

// Restore makes an earlier revision of an item (or a deleted item) current
// again; restoring one of its conflicting versions settles the conflict.
func (c *Client) Restore(ctx context.Context, p svrpc.RestoreParams) (out svrpc.Entry, err error) {
	err = c.conn.Call(ctx, svrpc.MItemRestore, p, &out)
	return
}

// Deleted lists deleted items whose names start with prefix.
func (c *Client) Deleted(ctx context.Context, vault, prefix string) (out []svrpc.DeletedItem, err error) {
	err = c.conn.Call(ctx, svrpc.MItemDeleted, svrpc.ListParams{Vault: vault, Prefix: prefix}, &out)
	return
}
