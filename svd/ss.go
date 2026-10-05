package svd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svstore"
)

// The Secret Service face (https://specifications.freedesktop.org/
// secret-service/latest/): secretvaultd as org.freedesktop.secrets, the
// keyring every Linux desktop application already uses through libsecret,
// KWallet's bridge, go-keyring, secretstorage and the like.
//
//	/org/freedesktop/secrets                          the service
//	/org/freedesktop/secrets/collection/<vault>       a vault (name escaped)
//	/org/freedesktop/secrets/collection/<vault>/<id>  an item (its object ID)
//	/org/freedesktop/secrets/collection/__session     the "session" collection:
//	                                                  in memory, gone when the daemon stops
//	/org/freedesktop/secrets/aliases/default          the default vault
//	/org/freedesktop/secrets/session/<n>, /prompt/<n>
//
// Consent fits the protocol's own model. To a program, an item it has not
// been allowed to read looks locked: it asks to unlock it, gets a prompt
// object, and calling Prompt shows the person the consent question (and
// the passphrase, if the vault itself is locked). A program that stores an
// item may read and change it from then on. Everything is audited like
// any other access.

const (
	ssBusName     = "org.freedesktop.secrets"
	ssRoot        = svdbus.ObjectPath("/org/freedesktop/secrets")
	ssCollections = "/org/freedesktop/secrets/collection/"
	ssAliases     = "/org/freedesktop/secrets/aliases/"
	ssSessions    = "/org/freedesktop/secrets/session/"
	ssPrompts     = "/org/freedesktop/secrets/prompt/"
	ssNoPrompt    = svdbus.ObjectPath("/")
	ssMemoryName  = "__session"

	ifService    = "org.freedesktop.Secret.Service"
	ifCollection = "org.freedesktop.Secret.Collection"
	ifItem       = "org.freedesktop.Secret.Item"
	ifSession    = "org.freedesktop.Secret.Session"
	ifPrompt     = "org.freedesktop.Secret.Prompt"

	errIsLocked     = "org.freedesktop.Secret.Error.IsLocked"
	errNoSession    = "org.freedesktop.Secret.Error.NoSession"
	errNoSuchObject = "org.freedesktop.Secret.Error.NoSuchObject"
	errNotSupported = "org.freedesktop.DBus.Error.NotSupported"
)

// ssSecret is the Secret struct: (session, parameters, value, content type).
type ssSecret struct {
	Session     svdbus.ObjectPath
	Parameters  []byte
	Value       []byte
	ContentType string
}

// secretService serves org.freedesktop.secrets on one bus connection.
type secretService struct {
	d   *Daemon
	bus *svdbus.Conn

	mu       sync.Mutex
	sessions map[svdbus.ObjectPath]*ssSession
	prompts  map[svdbus.ObjectPath]*ssPrompt
	callers  map[string]*ssCaller // by unique name
	next     int
	memory   *managedVault // the "session" collection
}

// ssCaller is a program on the bus.
type ssCaller struct {
	*client
	seen map[string]bool // item object IDs it found or made: their metadata is readable to it
}

// ErrSecretServiceTaken is the bus name owned by another keyring.
var ErrSecretServiceTaken = errors.New("another keyring owns org.freedesktop.secrets")

// ServeSecretService makes the daemon the Secret Service on bus, until ctx
// ends. When another keyring (such as gnome-keyring or ksecretd) holds the
// name, it queues behind it if queue is set (and takes over the moment the
// other one lets go; `secretvault keyring takeover` arranges that), else
// fails with ErrSecretServiceTaken.
func (d *Daemon) ServeSecretService(ctx context.Context, bus *svdbus.Conn, queue bool) error {
	ss := &secretService{d: d, bus: bus, sessions: map[svdbus.ObjectPath]*ssSession{},
		prompts: map[svdbus.ObjectPath]*ssPrompt{}, callers: map[string]*ssCaller{}}
	if err := bus.Export(ssRoot, ss.serviceInterface()); err != nil {
		return err
	}
	if err := bus.ExportSubtree(ssRoot, svdbus.Subtree{Lookup: ss.lookup, Children: ss.children}); err != nil {
		return err
	}
	if err := bus.Export(portalPath, ss.portalInterface()); err != nil {
		return err
	}
	// Programs that leave: their sessions close and their grants on this
	// connection go.
	if _, err := bus.SubscribeFunc(ctx, svdbus.MatchRule{Type: svdbus.TypeSignal, Sender: "org.freedesktop.DBus",
		Interface: "org.freedesktop.DBus", Member: "NameOwnerChanged"}, ss.nameOwnerChanged); err != nil {
		return err
	}
	cctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	flags := svdbus.NameDoNotQueue
	if queue {
		flags = 0
	}
	reply, err := bus.RequestName(cctx, ssBusName, flags)
	if err != nil {
		return err
	}
	switch reply {
	case svdbus.RequestNamePrimaryOwner, svdbus.RequestNameAlreadyOwner:
		d.opts.Log("serving the Secret Service (org.freedesktop.secrets)")
	case svdbus.RequestNameInQueue:
		d.opts.Log("another keyring holds org.freedesktop.secrets; secretvault takes over when it lets go")
	default:
		return ErrSecretServiceTaken
	}
	d.mu.Lock()
	d.ss = ss
	d.mu.Unlock()
	return nil
}

func (ss *secretService) nameOwnerChanged(m *svdbus.Message) {
	var name, old, now string
	if m.Decode(&name, &old, &now) != nil || now != "" || !strings.HasPrefix(name, ":") {
		return
	}
	ss.mu.Lock()
	c := ss.callers[name]
	delete(ss.callers, name)
	for p, s := range ss.sessions {
		if s.owner == name {
			clear(s.key)
			delete(ss.sessions, p)
		}
	}
	for p, pr := range ss.prompts {
		if pr.owner == name {
			pr.cancel()
			delete(ss.prompts, p)
		}
	}
	ss.mu.Unlock()
	if c != nil {
		ss.d.broker.DropConn(c.client)
	}
}

// caller identifies the program behind a bus name. The bus vouches for
// its process (and, on recent buses, gives a pidfd, which pins the process
// so a reused process ID cannot stand in for it).
func (ss *secretService) caller(ctx context.Context, sender string) (*ssCaller, error) {
	ss.mu.Lock()
	c := ss.callers[sender]
	ss.mu.Unlock()
	if c != nil {
		return c, nil
	}
	creds, err := ss.bus.GetConnectionCredentials(ctx, sender)
	if err != nil {
		return nil, err
	}
	if creds.ProcessFD >= 0 {
		defer closeFD(int(creds.ProcessFD))
	}
	if creds.UnixUserID != int64(os.Getuid()) || creds.ProcessID == 0 {
		return nil, svdbus.NewError(svdbus.ErrorAccessDenied, "callers must run as this user")
	}
	proc, err := svpeer.Describe(int(creds.ProcessID))
	if err != nil {
		return nil, svdbus.NewError(svdbus.ErrorAccessDenied, "the caller could not be identified")
	}
	if creds.ProcessFD >= 0 && !pidfdAlive(int(creds.ProcessFD)) {
		return nil, svdbus.NewError(svdbus.ErrorAccessDenied, "the caller went away")
	}
	proc.UID = int(creds.UnixUserID)
	c = &ssCaller{client: &client{proc: proc}, seen: map[string]bool{}}
	ss.mu.Lock()
	if prev := ss.callers[sender]; prev != nil {
		c = prev
	} else {
		ss.callers[sender] = c
	}
	ss.mu.Unlock()
	return c, nil
}

func (ss *secretService) newPath(prefix string) svdbus.ObjectPath {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	ss.next++
	return svdbus.ObjectPath(fmt.Sprintf("%s%d", prefix, ss.next))
}

// Paths and vaults.

func collectionPath(name string) svdbus.ObjectPath {
	if name == ssMemoryName {
		return svdbus.ObjectPath(ssCollections + ssMemoryName)
	}
	return svdbus.ObjectPath(ssCollections + svdbus.EscapePathElement(name))
}

func itemPath(vault string, id svformat.ID) svdbus.ObjectPath {
	return collectionPath(vault) + svdbus.ObjectPath("/"+id.String())
}

// memoryVault is the "session" collection: made on first use, kept only
// in memory, lost when the daemon stops.
func (ss *secretService) memoryVault() (*managedVault, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	if ss.memory != nil {
		return ss.memory, nil
	}
	key := svcrypto.RandomBytes(64)
	defer clear(key)
	v, _, err := svcore.Create(svstore.NewMem(), 0, svcore.NewSlot{Type: svformat.SlotKeyfile, Keyfile: key}, ss.d.svOpts)
	if err != nil {
		return nil, err
	}
	ss.memory = &managedVault{cfg: VaultConfig{Name: ssMemoryName}, v: v}
	return ss.memory, nil
}

// resolveCollection finds the vault a collection or alias path names.
func (ss *secretService) resolveCollection(path svdbus.ObjectPath) (*managedVault, bool) {
	p := string(path)
	switch {
	case strings.HasPrefix(p, ssAliases):
		switch strings.TrimPrefix(p, ssAliases) {
		case "default":
			mv, err := ss.d.vault("")
			return mv, err == nil
		case "session":
			mv, err := ss.memoryVault()
			return mv, err == nil
		}
		return nil, false
	case strings.HasPrefix(p, ssCollections):
		elem := strings.TrimPrefix(p, ssCollections)
		if strings.Contains(elem, "/") {
			return nil, false
		}
		if elem == ssMemoryName {
			mv, err := ss.memoryVault()
			return mv, err == nil
		}
		name, err := svdbus.UnescapePathElement(elem)
		if err != nil {
			return nil, false
		}
		mv, err := ss.d.vault(name)
		return mv, err == nil
	}
	return nil, false
}

// resolveItem finds an item path's vault and object ID.
func (ss *secretService) resolveItem(path svdbus.ObjectPath) (*managedVault, svformat.ID, bool) {
	i := strings.LastIndexByte(string(path), '/')
	if i < 0 {
		return nil, svformat.ID{}, false
	}
	mv, ok := ss.resolveCollection(path[:i])
	if !ok {
		return nil, svformat.ID{}, false
	}
	id, err := svformat.ParseID(string(path[i+1:]))
	return mv, id, err == nil
}

// vaults lists every collection: the registered vaults, and the session
// collection if it exists.
func (ss *secretService) vaults() []*managedVault {
	ss.d.mu.Lock()
	var out []*managedVault
	for _, mv := range ss.d.vaults {
		if mv.v != nil {
			out = append(out, mv)
		}
	}
	ss.d.mu.Unlock()
	ss.mu.Lock()
	if ss.memory != nil {
		out = append(out, ss.memory)
	}
	ss.mu.Unlock()
	return out
}

// entryByID returns an unlocked vault's item by object ID.
func entryByID(mv *managedVault, id svformat.ID) (svcore.Entry, error) {
	entries, err := mv.v.List("")
	if err != nil {
		return svcore.Entry{}, err
	}
	var found svcore.Entry
	ok := false
	for _, e := range entries {
		if e.ID == id {
			found, ok = e, true
		} else {
			e.Item.Wipe()
		}
	}
	if !ok {
		return svcore.Entry{}, svdbus.NewError(errNoSuchObject, "no such item")
	}
	return found, nil
}

// matches reports whether an item carries every attribute asked for.
func matches(it *svcore.Item, attrs map[string]string) bool {
	for k, v := range attrs {
		if it.Attrs[k] != v {
			return false
		}
	}
	return true
}

// permitted reports whether c may do op to an item right now, without
// asking anyone.
func (ss *secretService) permitted(c *ssCaller, mv *managedVault, item string, op svbroker.Op) bool {
	if mv.v.Locked() {
		return false
	}
	if ss.d.broker.ConnAllowed(c.client, mv.v) {
		return true
	}
	dec, found, err := ss.d.broker.Check(mv.v, c.client, c.identity(), item, op)
	return err == nil && found && dec.Allows()
}

// visible reports whether c may read an item's metadata (label,
// attributes, dates): items it found by searching, made, or may read, or
// every item when it may list the vault.
func (ss *secretService) visible(c *ssCaller, mv *managedVault, id svformat.ID) bool {
	ss.mu.Lock()
	seen := c.seen[id.String()]
	ss.mu.Unlock()
	return seen || ss.permitted(c, mv, id.String(), svbroker.OpRead) || ss.permitted(c, mv, "", svbroker.OpList)
}

func (ss *secretService) remember(c *ssCaller, ids ...svformat.ID) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	for _, id := range ids {
		c.seen[id.String()] = true
	}
}

// itemSecret and contentTypeOf read an item as the Secret Service sees it:
// its primary secret, and its content type (text/plain unless stored).
func itemSecret(it *svcore.Item) []byte {
	if f, ok := it.Secret(); ok {
		return f.Value
	}
	return nil
}

func contentTypeOf(it *svcore.Item) string {
	if f, ok := it.Field("content_type"); ok && len(f.Value) > 0 {
		return string(f.Value)
	}
	return "text/plain"
}

// labelOf is what the Secret Service calls the item's label.
func labelOf(it *svcore.Item) string {
	if it.Label != "" {
		return it.Label
	}
	return it.Name
}

var errDenied = svdbus.NewError(svdbus.ErrorAccessDenied, "not allowed")

func asDBusError(err error) error {
	if err == nil {
		return nil
	}
	var de *svdbus.Error
	if errors.As(err, &de) {
		return err
	}
	switch {
	case errors.Is(err, svcore.ErrLocked):
		return svdbus.NewError(errIsLocked, "the vault is locked")
	case errors.Is(err, svcore.ErrNotFound):
		return svdbus.NewError(errNoSuchObject, "no such item")
	case errors.Is(err, svrpc.ErrNoVault):
		// The Secret Service has one error for any object that is not
		// there; the message says it is the collection.
		return svdbus.NewError(errNoSuchObject, "no such collection: "+err.Error())
	}
	return svdbus.NewError(svdbus.ErrorFailed, err.Error())
}
