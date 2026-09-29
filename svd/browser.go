package svd

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svbrowser"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// The browser face: secretvaultd as the backend of KeePassXC's browser
// extension, KeePassXC-Browser (svbrowser speaks its protocol).
//
// The browser starts secretvault-browser, a relay, which opens a session
// here (browser.open) and hands over the extension's messages
// (browser.message). The relay is only a pipe. The program asking is the
// browser that started it, which the daemon finds for itself (the relay's
// parent, Options.Launcher) and names in every prompt and audit entry: a
// program that runs the relay itself is named as what it is, and one that
// is not the relay cannot open a session at all.
//
//   - Connecting (associate) asks the person once: "firefox wants to
//     connect its KeePassXC-Browser extension to secretvault as
//     firefox-3f2a". The association is a vault record of this device,
//     tied to the browser's identity; `secretvault browser ls` and `rm`
//     list and remove them.
//   - Each login handed to the extension is a read of that item, decided
//     like any other program's (a remembered decision, else a prompt)
//     and audited. Saving one is a write; the extension's groups are the
//     vault's folders, which is listing it; a one-time code is a read.
//   - A session is on one vault: the default, unless the relay names
//     another. When that vault locks or unlocks, the extension is told.

func init() {
	registerMethod(svrpc.MBrowserOpen, (*Daemon).browserOpen)
	registerMethod(svrpc.MBrowserMessage, (*Daemon).browserMessage)
	registerMethod(svrpc.MBrowserList, (*Daemon).browserList)
	registerMethod(svrpc.MBrowserRemove, (*Daemon).browserRemove)
}

// associationKind is the vault record kind browser associations are kept
// under.
const associationKind = "browser-association"

// browserAssociation is an extension connected to a vault, on one device.
type browserAssociation struct {
	Device    svformat.ID `json:"device"`
	Name      string      `json:"name"`
	Key       string      `json:"key"` // the extension's identification public key, base64
	Identity  string      `json:"identity"`
	Program   string      `json:"program"`
	Extension string      `json:"extension,omitempty"`
	Created   time.Time   `json:"created"`
}

type associationRecord struct {
	id svformat.ID
	a  browserAssociation
}

// browserAssociations are this device's associations with mv.
func (d *Daemon) browserAssociations(mv *managedVault) ([]associationRecord, error) {
	recs, err := mv.v.Records(associationKind)
	if err != nil {
		return nil, err
	}
	var out []associationRecord
	for _, r := range recs {
		var a browserAssociation
		err := json.Unmarshal(r.Data, &a)
		clear(r.Data)
		if err == nil && a.Device == d.svOpts.Device {
			out = append(out, associationRecord{id: r.ID, a: a})
		}
	}
	return out, nil
}

// defaultFolder is where a login the extension saves goes, unless it
// names a group.
const defaultFolder = "web"

// maxMadeFolders bounds the folders create-new-group may name before
// anything is saved into them.
const maxMadeFolders = 256

// browserSession is one browser's conversation with a vault.
type browserSession struct {
	d      *Daemon
	relay  *client // the relay's connection
	app    *client // the browser: who consent and the audit log name
	origin string  // the extension, as the browser named it
	vault  string
	proto  *svbrowser.Session

	save    sync.Mutex // one save at a time, so two never take one name
	mu      sync.Mutex
	folders map[string]string // folders create-new-group named, by ID
}

func (d *Daemon) browserOpen(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.BrowserOpenParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	if !cl.cli {
		return nil, svrpc.Errorf(svrpc.CodeDenied, "only secretvault-browser, the host a browser starts, may open a browser session")
	}
	proc, err := d.opts.Launcher(cl.proc)
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeDenied, "the program that started secretvault-browser could not be identified: %v", err)
	}
	mv, err := d.vault(p.Vault)
	if err != nil {
		return nil, err
	}
	b := &browserSession{d: d, relay: cl, app: &client{proc: proc}, origin: p.Origin, vault: mv.cfg.Name, folders: map[string]string{}}
	b.proto = svbrowser.NewSession(b)
	d.mu.Lock()
	if cl.face != nil {
		d.mu.Unlock()
		return nil, svrpc.Errorf(svrpc.CodeExists, "this connection already has a browser session")
	}
	cl.face, cl.events, cl.closed = b, b.event, b.close
	d.mu.Unlock()
	d.opts.Log(fmt.Sprintf("browser session: %s, extension %q, vault %s", b.app.display(), p.Origin, mv.cfg.Name))
	return svrpc.BrowserOpenResult{Browser: b.app.display(), Vault: mv.cfg.Name}, nil
}

func (d *Daemon) browserMessage(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.BrowserFrame
	if err := decode(&p); err != nil {
		return nil, err
	}
	d.mu.Lock()
	b, _ := cl.face.(*browserSession)
	d.mu.Unlock()
	if b == nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidRequest, "open a browser session first (%s)", svrpc.MBrowserOpen)
	}
	return svrpc.BrowserFrame{Frame: b.proto.Handle(ctx, p.Frame)}, nil
}

func (d *Daemon) browserList(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.VaultRef
	if err := decode(&p); err != nil {
		return nil, err
	}
	mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
	if err != nil {
		return nil, err
	}
	recs, err := d.browserAssociations(mv)
	if err != nil {
		return nil, err
	}
	out := []svrpc.BrowserAssociation{}
	for _, r := range recs {
		out = append(out, svrpc.BrowserAssociation{Name: r.a.Name, Vault: mv.cfg.Name, Program: r.a.Program, Extension: r.a.Extension, Created: r.a.Created})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Created.Before(out[j].Created) })
	return out, nil
}

func (d *Daemon) browserRemove(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.BrowserRemoveParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
	if err != nil {
		return nil, err
	}
	recs, err := d.browserAssociations(mv)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if r.a.Name == p.Name {
			if err := mv.v.DeleteRecord(r.id); err != nil {
				return nil, err
			}
			d.recorder(cl, mv, "", svbroker.OpManage)("allowed", "disconnected the browser extension "+p.Name)
			return nil, nil
		}
	}
	return nil, svrpc.Errorf(svrpc.CodeNotFound, "no browser is connected to vault %q as %q", mv.cfg.Name, p.Name)
}

// event tells the extension when the session's vault locks or unlocks.
func (b *browserSession) event(method string, ev svrpc.VaultEvent) {
	if ev.Vault != b.vault {
		return
	}
	action := ""
	switch method {
	case svrpc.EVaultLocked:
		action = svbrowser.ActionDatabaseLocked
	case svrpc.EVaultUnlocked:
		action = svbrowser.ActionDatabaseUnlocked
	default:
		return
	}
	b.relay.conn.Notify(svrpc.EBrowserFrame, svrpc.BrowserFrame{Frame: svbrowser.Notice(action)})
}

// close ends the session with its relay's connection.
func (b *browserSession) close() {
	b.proto.Close()
	b.d.broker.DropConn(b.app)
}

// fail turns an error into the protocol's terms.
func (b *browserSession) fail(err error) error {
	var be *svbrowser.Error
	switch {
	case err == nil, errors.As(err, &be):
		return err
	case errors.Is(err, svcore.ErrLocked), errors.Is(err, svrpc.ErrLocked):
		return &svbrowser.Error{Code: svbrowser.CodeDatabaseNotOpened, Why: err.Error()}
	case errors.Is(err, svrpc.ErrDenied), errors.Is(err, svrpc.ErrCanceled), errors.Is(err, svrpc.ErrNoPrompter), errors.Is(err, svrpc.ErrWrongKey):
		return &svbrowser.Error{Code: svbrowser.CodeActionCancelledOrDenied, Why: err.Error()}
	}
	b.d.opts.Log("browser: " + err.Error())
	return err
}

// unlocked is the session's vault, which must be unlocked.
func (b *browserSession) unlocked() (*managedVault, error) {
	mv, err := b.d.vault(b.vault)
	if err != nil {
		return nil, &svbrowser.Error{Code: svbrowser.CodeDatabaseNotOpened, Why: err.Error()}
	}
	if mv.v.Locked() {
		return nil, &svbrowser.Error{Code: svbrowser.CodeDatabaseNotOpened}
	}
	return mv, nil
}

// decide is the daemon's consent, for the browser.
func (b *browserSession) decide(ctx context.Context, mv *managedVault, item, itemName string, op svbroker.Op, why string) error {
	record := b.d.recorder(b.app, mv, itemName, op)
	return b.d.decide(ctx, b.app, mv, item, itemName, op, why, false, false, record)
}

func (b *browserSession) Open(ctx context.Context, unlock bool) error {
	mv, err := b.d.vault(b.vault)
	if err != nil {
		return &svbrowser.Error{Code: svbrowser.CodeDatabaseNotOpened, Why: err.Error()}
	}
	if !mv.v.Locked() {
		return nil
	}
	if !unlock {
		return &svbrowser.Error{Code: svbrowser.CodeDatabaseNotOpened}
	}
	why := fmt.Sprintf("%s asks to unlock vault %q for its KeePassXC-Browser extension.", b.app.display(), mv.cfg.Name)
	if _, _, err := b.d.ensureUnlocked(ctx, b.app, mv, why); err != nil {
		b.d.recorder(b.app, mv, "", svbroker.OpManage)(outcomeOf(err), err.Error())
		return &svbrowser.Error{Code: svbrowser.CodeDatabaseNotOpened, Why: err.Error()}
	}
	return nil
}

// browserKey keys what the face derives from a vault: its hash and its
// folders' IDs. It comes from the vault key, so they reveal nothing.
func browserKey(mv *managedVault) ([]byte, error) {
	return mv.v.DeriveKey("browser", 32)
}

// Hash is an HMAC of this device's ID and the vault's, under a key of the
// vault's: stable, different on each device (as associations are), and
// telling nothing to whoever reads it in the browser's profile.
func (b *browserSession) Hash(context.Context) (string, error) {
	mv, err := b.unlocked()
	if err != nil {
		return "", err
	}
	key, err := browserKey(mv)
	if err != nil {
		return "", b.fail(err)
	}
	defer clear(key)
	mac := hmac.New(sha256.New, key)
	device, vault := b.d.svOpts.Device, mv.v.ID()
	mac.Write([]byte("database\x00"))
	mac.Write(device[:])
	mac.Write(vault[:])
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// folderIDs gives folders their IDs, the extension's group UUIDs: an HMAC
// of the path under the vault's browser key, cut to 16 bytes. done wipes
// the key.
func folderIDs(mv *managedVault) (id func(folder string) string, done func(), err error) {
	key, err := browserKey(mv)
	if err != nil {
		return nil, nil, err
	}
	id = func(folder string) string {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte("folder\x00" + folder))
		return hex.EncodeToString(mac.Sum(nil)[:16])
	}
	return id, func() { clear(key) }, nil
}

func (b *browserSession) Associate(ctx context.Context, idKey string) (string, error) {
	mv, err := b.unlocked()
	if err != nil {
		return "", err
	}
	record := func(outcome, reason string) {
		b.d.audit.Record(mv.v, svbroker.Entry{Program: b.app.display(), Identity: b.app.identity(), PID: b.app.proc.PID,
			Op: svbroker.OpManage, Outcome: outcome, Reason: reason})
	}
	if strings.HasPrefix(b.app.identity(), "unknown:") {
		// Nothing lasting can attach to a program known only by its
		// process ID.
		record("denied", "connecting KeePassXC-Browser: the browser could not be identified")
		return "", &svbrowser.Error{Code: svbrowser.CodeActionCancelledOrDenied, Why: "the browser could not be identified"}
	}
	mv.prompt.Lock()
	defer mv.prompt.Unlock()
	taken, err := b.d.browserAssociations(mv)
	if err != nil {
		return "", b.fail(err)
	}
	name := associationName(b.app.proc, taken)
	p := b.d.consentPrompter(b.app)
	if p == nil {
		record("denied", "connecting KeePassXC-Browser: no way to ask")
		return "", &svbrowser.Error{Code: svbrowser.CodeActionCancelledOrDenied, Why: "there is no way to ask you here"}
	}
	ext := "its KeePassXC-Browser extension"
	if b.origin != "" {
		ext += " (" + b.origin + ")"
	}
	choice, err := p.Choose(ctx, svrpc.PromptAsk{
		Kind:  svrpc.PromptChoose,
		Title: "Connect a browser to vault " + mv.cfg.Name + "?",
		Description: fmt.Sprintf("%s wants to connect %s to secretvault as %q.\n\n"+
			"It may then ask for the logins in vault %q, and you are asked about each, as for any program.\n\nProgram: %s\nProcess: %d",
			b.app.display(), ext, name, mv.cfg.Name, b.app.proc.Exe, b.app.proc.PID),
		Choices: []svrpc.Choice{{ID: svrpc.ChoiceAlways, Label: "Connect"}, {ID: svrpc.ChoiceDeny, Label: "Deny"}},
	})
	if err != nil || choice != svrpc.ChoiceAlways {
		why := "the person said no"
		if err != nil {
			why = err.Error()
		}
		record("denied", "connecting KeePassXC-Browser: "+why)
		return "", &svbrowser.Error{Code: svbrowser.CodeActionCancelledOrDenied, Why: why}
	}
	a := browserAssociation{Device: b.d.svOpts.Device, Name: name, Key: idKey, Identity: b.app.identity(),
		Program: b.app.display(), Extension: b.origin, Created: b.d.opts.Now().UTC()}
	if _, err := mv.v.PutRecord(associationKind, svformat.ID{}, a); err != nil {
		return "", b.fail(err)
	}
	record("allowed", "connected KeePassXC-Browser as "+name)
	b.d.opts.Log(fmt.Sprintf("%s connected KeePassXC-Browser to vault %s as %s", b.app.display(), mv.cfg.Name, name))
	return name, nil
}

// associationName is a new name for an association: the browser's, and
// four hex digits ("firefox-3f2a").
func associationName(p *svpeer.Process, taken []associationRecord) string {
	base := ""
	switch {
	case p.Flatpak != "":
		base = p.Flatpak[strings.LastIndexByte(p.Flatpak, '.')+1:]
	case p.Snap != "":
		base = p.Snap
	case p.Exe != "":
		base = strings.TrimSuffix(filepath.Base(p.Exe), ".exe")
	}
	base = strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 'a' - 'A'
		}
		return -1
	}, base)
	if base == "" {
		base = "browser"
	}
	for {
		name := base + "-" + hex.EncodeToString(svcrypto.RandomBytes(2))
		free := true
		for _, t := range taken {
			if t.a.Name == name {
				free = false
			}
		}
		if free {
			return name
		}
	}
}

func (b *browserSession) Associated(_ context.Context, name, idKey string) (bool, error) {
	mv, err := b.unlocked()
	if err != nil {
		return false, err
	}
	recs, err := b.d.browserAssociations(mv)
	if err != nil {
		return false, b.fail(err)
	}
	for _, r := range recs {
		if r.a.Name == name && r.a.Identity == b.app.identity() && subtle.ConstantTimeCompare([]byte(r.a.Key), []byte(idKey)) == 1 {
			return true, nil
		}
	}
	return false, nil
}

// loginURLs are the URLs a login is kept for: its URL fields (by type, or
// named url, url2..., website) and its url attributes (url, *_url).
func loginURLs(it *svcore.Item) []string {
	var out []string
	for _, f := range it.Fields {
		n := strings.ToLower(f.Name)
		if f.Type == svcore.FieldURL || n == "website" || strings.HasPrefix(n, "url") && strings.Trim(n[3:], "0123456789 ()") == "" {
			out = append(out, string(f.Value))
		}
	}
	for k, v := range it.Attrs {
		if k = strings.ToLower(k); k == "url" || strings.HasSuffix(k, "_url") {
			out = append(out, v)
		}
	}
	return out
}

// username is a login's user name.
func username(it *svcore.Item) (field, value string) {
	for _, n := range []string{"username", "login", "user", "email"} {
		if f, ok := it.Field(n); ok {
			return f.Name, string(f.Value)
		}
	}
	for _, f := range it.Fields {
		if f.Type == svcore.FieldEmail {
			return f.Name, string(f.Value)
		}
	}
	return "", ""
}

// totpKey is a login's TOTP key, if it has one. HOTP keys are left out:
// filling one in would need its counter moved on.
func totpKey(it *svcore.Item) *svotp.Key {
	for _, f := range it.Fields {
		n := strings.ToLower(f.Name)
		if f.Type != svcore.FieldOTP && n != "otp" && n != "totp" {
			continue
		}
		if k, err := svotp.ParseField(f.Value); err == nil {
			if k.Type == "totp" {
				return k
			}
			k.Wipe()
		}
	}
	return nil
}

// folderOf is the folder an item is in ("" at the top).
func folderOf(name string) string {
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		return name[:i]
	}
	return ""
}

func (b *browserSession) Logins(ctx context.Context, q svbrowser.LoginQuery) ([]svbrowser.Login, error) {
	mv, err := b.unlocked()
	if err != nil {
		return nil, err
	}
	entries, err := mv.v.List("")
	if err != nil {
		return nil, b.fail(err)
	}
	type match struct {
		e    svcore.Entry
		rank int
	}
	var matches []match
	for _, e := range entries {
		best := 0
		if e.Item.Kind == "login" {
			for _, u := range loginURLs(&e.Item) {
				best = max(best, svbrowser.Priority(u, q.URL, q.SubmitURL))
			}
		}
		if best == 0 {
			e.Item.Wipe()
			continue
		}
		matches = append(matches, match{e, best})
	}
	defer func() {
		for _, m := range matches {
			m.e.Item.Wipe()
		}
	}()
	sort.SliceStable(matches, func(i, j int) bool { return matches[i].rank > matches[j].rank })

	host := svbrowser.Host(q.URL)
	var out []svbrowser.Login
	var failure error
	for _, m := range matches {
		name := m.e.Item.Name
		why := fmt.Sprintf("%s wants the login %q for %s, through its KeePassXC-Browser extension.", b.app.display(), name, host)
		if err := b.decide(ctx, mv, m.e.ID.String(), name, svbroker.OpRead, why); err != nil {
			if ctx.Err() != nil {
				break
			}
			if !errors.Is(err, svrpc.ErrDenied) && !errors.Is(err, svrpc.ErrCanceled) && failure == nil {
				failure = err
			}
			continue
		}
		it := &m.e.Item
		l := svbrowser.Login{Name: it.Label, UUID: m.e.ID.String(), Group: mv.cfg.Name}
		if l.Name == "" {
			l.Name = name
		}
		if f := folderOf(name); f != "" {
			l.Group = f[strings.LastIndexByte(f, '/')+1:]
		}
		_, l.Login = username(it)
		if f, ok := it.Secret(); ok {
			l.Password = bytes.Clone(f.Value)
		}
		if k := totpKey(it); k != nil {
			l.TOTP, _ = k.Code(b.d.opts.Now())
			k.Wipe()
		}
		out = append(out, l)
	}
	// A vault locked while the person was being asked hands nothing out.
	if mv.v.Locked() || ctx.Err() != nil {
		for i := range out {
			clear(out[i].Password)
		}
		return nil, &svbrowser.Error{Code: svbrowser.CodeDatabaseNotOpened}
	}
	if len(out) == 0 {
		if failure != nil {
			return nil, b.fail(failure)
		}
		// Refused and missing look alike, so a refusal tells nothing.
		return nil, &svbrowser.Error{Code: svbrowser.CodeNoLoginsFound}
	}
	return out, nil
}

// segment makes text usable as one part of an item name.
func segment(s string) string {
	s = strings.TrimSpace(strings.Map(func(r rune) rune {
		if r == '/' || r < 0x20 || r == 0x7f {
			return '_'
		}
		return r
	}, s))
	if len(s) > 200 {
		s = strings.ToValidUTF8(s[:200], "")
	}
	if s == "" || s == "." || s == ".." {
		return "unnamed"
	}
	return s
}

// freeName is a name for a new login for host in folder, not yet taken.
func freeName(mv *managedVault, folder, host, login string) string {
	base := segment(host)
	if folder != "" {
		base = folder + "/" + base
	}
	free := func(n string) bool {
		e, err := mv.v.Get(n)
		if err == nil {
			e.Item.Wipe()
		}
		return err != nil
	}
	if free(base) {
		return base
	}
	if login != "" {
		if n := base + " (" + segment(login) + ")"; free(n) {
			return n
		}
	}
	for i := 2; ; i++ {
		if n := fmt.Sprintf("%s (%d)", base, i); free(n) {
			return n
		}
	}
}

// folderFor is the folder a group UUID names: the root, one the vault has,
// one create-new-group made, or else the default.
func (b *browserSession) folderFor(mv *managedVault, groupUUID string) string {
	if groupUUID == "" {
		return defaultFolder
	}
	want := strings.ToLower(groupUUID)
	b.mu.Lock()
	f, ok := b.folders[want]
	b.mu.Unlock()
	if ok {
		return f
	}
	id, done, err := folderIDs(mv)
	if err != nil {
		return defaultFolder
	}
	defer done()
	if want == id("") {
		return ""
	}
	entries, _ := mv.v.List("")
	var names []string
	for _, e := range entries {
		names = append(names, e.Item.Name)
		e.Item.Wipe()
	}
	for _, f := range svbrowser.Folders(names) {
		if id(f) == want {
			return f
		}
	}
	return defaultFolder
}

func (b *browserSession) SaveLogin(ctx context.Context, s svbrowser.SaveLogin) error {
	mv, err := b.unlocked()
	if err != nil {
		return err
	}
	host := svbrowser.Host(s.URL)
	if host == "" {
		return &svbrowser.Error{Code: svbrowser.CodeNoURLProvided}
	}
	b.save.Lock()
	defer b.save.Unlock()
	if s.UUID != "" {
		id, err := svformat.ParseID(strings.ToLower(s.UUID))
		if err != nil {
			return &svbrowser.Error{Code: svbrowser.CodeNoValidUUIDProvided}
		}
		if e, err := mv.v.GetID(id); err == nil {
			return b.updateLogin(ctx, mv, e, s, host)
		}
		// Gone meanwhile: KeePassXC saves it as a new login.
	}
	folder := b.folderFor(mv, s.GroupUUID)
	name := freeName(mv, folder, host, s.Login)
	why := fmt.Sprintf("%s wants to save a new login %q for %s, through its KeePassXC-Browser extension.", b.app.display(), name, host)
	if err := b.decide(ctx, mv, "", name, svbroker.OpWrite, why); err != nil {
		return b.fail(err)
	}
	if e, err := mv.v.Get(name); err == nil {
		// Taken while the person was deciding.
		e.Item.Wipe()
		name = freeName(mv, folder, host, s.Login)
	}
	it := svcore.Item{Kind: "login", Name: name, Label: host}
	if s.Login != "" {
		it.Fields = append(it.Fields, svcore.Field{Name: "username", Type: svcore.FieldText, Value: []byte(s.Login)})
	}
	it.Fields = append(it.Fields,
		svcore.Field{Name: "password", Type: svcore.FieldConcealed, Value: bytes.Clone(s.Password)},
		svcore.Field{Name: "url", Type: svcore.FieldURL, Value: []byte(s.URL)})
	defer it.Wipe()
	e, err := mv.v.Put(it)
	if err != nil {
		return b.fail(err)
	}
	e.Item.Wipe()
	// The program that saves a login may read, change and delete it.
	b.d.broker.Remember(mv.v, svbroker.Grant{Identity: b.app.identity(), Program: b.app.display(), Item: e.ID.String(),
		ItemName: name, Ops: []svbroker.Op{svbroker.OpRead, svbroker.OpWrite, svbroker.OpDelete}, Decision: svbroker.AllowAlways})
	b.d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: name})
	return nil
}

// updateLogin changes a login's user name and password.
func (b *browserSession) updateLogin(ctx context.Context, mv *managedVault, e svcore.Entry, s svbrowser.SaveLogin, host string) error {
	defer e.Item.Wipe()
	name := e.Item.Name
	why := fmt.Sprintf("%s wants to change the login %q, for %s, through its KeePassXC-Browser extension.", b.app.display(), name, host)
	if err := b.decide(ctx, mv, e.ID.String(), name, svbroker.OpWrite, why); err != nil {
		return b.fail(err)
	}
	it := e.Item
	defer it.Wipe() // what SetField appends is not in e.Item
	if field, _ := username(&it); field != "" || s.Login != "" {
		if field == "" {
			field = "username"
		}
		it.SetField(svcore.Field{Name: field, Type: svcore.FieldText, Value: []byte(s.Login)})
	}
	pw := "password"
	if f, ok := it.Secret(); ok {
		pw = f.Name
	}
	it.SetField(svcore.Field{Name: pw, Type: svcore.FieldConcealed, Value: bytes.Clone(s.Password)})
	ne, err := mv.v.Put(it)
	if err != nil {
		return b.fail(err)
	}
	ne.Item.Wipe()
	b.d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: name})
	return nil
}

func (b *browserSession) Groups(ctx context.Context) (svbrowser.Group, error) {
	mv, err := b.unlocked()
	if err != nil {
		return svbrowser.Group{}, err
	}
	why := fmt.Sprintf("%s wants to see the folders of vault %q, to offer a place to save a login, through its KeePassXC-Browser extension.",
		b.app.display(), mv.cfg.Name)
	if err := b.decide(ctx, mv, "", "", svbroker.OpList, why); err != nil {
		return svbrowser.Group{}, b.fail(err)
	}
	entries, err := mv.v.List("")
	if err != nil {
		return svbrowser.Group{}, b.fail(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Item.Name)
		e.Item.Wipe()
	}
	folders := svbrowser.Folders(names)
	b.mu.Lock()
	for _, f := range b.folders {
		folders = append(folders, f)
	}
	b.mu.Unlock()
	id, done, err := folderIDs(mv)
	if err != nil {
		return svbrowser.Group{}, b.fail(err)
	}
	defer done()
	return svbrowser.Tree(mv.cfg.Name, folders, id), nil
}

// CreateGroup names a folder to save into. Folders are only prefixes of
// item names, so nothing is written: the folder is remembered for this
// session, and exists once a login is saved into it.
func (b *browserSession) CreateGroup(_ context.Context, path string) (svbrowser.Group, error) {
	mv, err := b.unlocked()
	if err != nil {
		return svbrowser.Group{}, err
	}
	folder, ok := svbrowser.CleanFolder(path)
	if !ok || folder == "" {
		return svbrowser.Group{}, &svbrowser.Error{Code: svbrowser.CodeCannotCreateNewGroup}
	}
	id, done, err := folderIDs(mv)
	if err != nil {
		return svbrowser.Group{}, b.fail(err)
	}
	defer done()
	uuid := id(folder)
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, known := b.folders[uuid]; !known && len(b.folders) >= maxMadeFolders {
		return svbrowser.Group{}, &svbrowser.Error{Code: svbrowser.CodeCannotCreateNewGroup}
	}
	b.folders[uuid] = folder
	return svbrowser.Group{Name: folder[strings.LastIndexByte(folder, '/')+1:], UUID: uuid, Children: []svbrowser.Group{}}, nil
}

// byID finds an item the extension names by its ID, and decides whether
// the browser may do op to it. found is false when there is no such item.
func (b *browserSession) byID(ctx context.Context, uuid string, op svbroker.Op, what string) (mv *managedVault, e svcore.Entry, found bool, err error) {
	mv, err = b.unlocked()
	if err != nil {
		return nil, e, false, err
	}
	id, err := svformat.ParseID(strings.ToLower(uuid))
	if err != nil {
		return nil, e, false, &svbrowser.Error{Code: svbrowser.CodeNoValidUUIDProvided}
	}
	e, err = mv.v.GetID(id)
	if errors.Is(err, svcore.ErrNotFound) {
		return mv, e, false, nil
	}
	if err != nil {
		return nil, e, false, b.fail(err)
	}
	why := fmt.Sprintf("%s wants %s %q, through its KeePassXC-Browser extension.", b.app.display(), what, e.Item.Name)
	if err := b.decide(ctx, mv, e.ID.String(), e.Item.Name, op, why); err != nil {
		e.Item.Wipe()
		return nil, svcore.Entry{}, false, b.fail(err)
	}
	return mv, e, true, nil
}

func (b *browserSession) TOTP(ctx context.Context, uuid string) (string, error) {
	_, e, found, err := b.byID(ctx, uuid, svbroker.OpRead, "the one-time code of")
	if err != nil || !found {
		return "", err
	}
	defer e.Item.Wipe()
	k := totpKey(&e.Item)
	if k == nil {
		return "", nil
	}
	defer k.Wipe()
	code, _ := k.Code(b.d.opts.Now())
	return code, nil
}

func (b *browserSession) Delete(ctx context.Context, uuid string) (bool, error) {
	mv, e, found, err := b.byID(ctx, uuid, svbroker.OpDelete, "to delete")
	if err != nil || !found {
		return false, err
	}
	e.Item.Wipe()
	if err := mv.v.Delete(e.Item.Name); err != nil {
		return false, b.fail(err)
	}
	b.d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: e.Item.Name})
	return true, nil
}

func (b *browserSession) Lock(context.Context) error {
	mv, err := b.d.vault(b.vault)
	if err != nil {
		return &svbrowser.Error{Code: svbrowser.CodeDatabaseNotOpened, Why: err.Error()}
	}
	b.d.lock(mv, "asked by "+b.app.display()+" through KeePassXC-Browser")
	return nil
}

// GeneratePassword makes a password as 'secretvault gen' does. Nothing of
// the vault's is involved, so nobody is asked.
func (b *browserSession) GeneratePassword(context.Context) ([]byte, error) {
	return svcrypto.Password(24)
}

// A browserSession is the svbrowser backend.
var _ svbrowser.Backend = (*browserSession)(nil)
