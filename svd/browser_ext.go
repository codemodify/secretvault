package svd

import (
	"bytes"
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// The secretvault extension's face (svext; the extension is
// browser/extension). It is reached the way the KeePassXC-Browser face is
// (browser.go): the browser starts the host, secretvault-browser, which
// opens a session here with browser.open naming svext.Protocol, then hands
// over the extension's requests with browser.message.
//
// Who asks is the browser that started the host, as the daemon finds it
// (Options.Launcher), never what the host or the extension says. What
// page asks is the origin the extension names: the extension is the
// browser's, and the browser started the host for it alone (its manifest's
// allowed_extensions), so the origin is the browser's word. Every prompt
// and audit entry names both: "firefox wants the login "web/github.com"
// for https://github.com, through the secretvault extension".
//
//   - Listing the logins that fit a page (titles and user names, no
//     passwords) is listing the vault, decided as for any program.
//   - Filling one is a read of that item, decided like any other: a
//     remembered decision, else a prompt. So is its one-time code.
//   - Checking whether a login a page sent is new is listing the vault
//     too: the comparison is made here, and nothing stored leaves.
//   - Saving is a write; the browser may then read, change and delete
//     the login it saved, as with KeePassXC-Browser.
//   - Unlocking is the daemon's own passphrase prompt: the extension
//     never sees a passphrase.
//
// Unlike KeePassXC-Browser, the extension makes no association: the
// browser lets only it start this host, and each decision is the broker's.

// extSession is one browser's secretvault extension.
type extSession struct {
	d      *Daemon
	relay  *client // the host's connection
	app    *client // the browser: who consent and the audit log name
	origin string  // the extension, as the browser named it
	proto  *svext.Session

	save sync.Mutex // one save at a time, so two never take one name
}

// extOpen opens a session for the secretvault extension of the browser
// proc, which started the host on cl.
func (d *Daemon) extOpen(cl *client, p svrpc.BrowserOpenParams, proc *svpeer.Process) (any, error) {
	if !svext.Ours(p.Origin) {
		return nil, svrpc.Errorf(svrpc.CodeDenied, "the secretvault extension's protocol serves the secretvault extension only, not %q", p.Origin)
	}
	b := &extSession{d: d, relay: cl, app: &client{proc: proc}, origin: p.Origin}
	b.proto = svext.NewSession(b)
	d.mu.Lock()
	if cl.face != nil {
		d.mu.Unlock()
		return nil, svrpc.Errorf(svrpc.CodeExists, "this connection already has a browser session")
	}
	cl.face, cl.events, cl.closed = b, b.event, b.close
	d.mu.Unlock()
	d.opts.Log(fmt.Sprintf("browser session: %s, the secretvault extension (%s)", b.app.display(), p.Origin))
	return svrpc.BrowserOpenResult{Browser: b.app.display()}, nil
}

// event tells the extension when a vault locks or unlocks.
func (b *extSession) event(method string, ev svrpc.VaultEvent) {
	switch method {
	case svrpc.EVaultLocked, svrpc.EVaultUnlocked:
		b.relay.conn.Notify(svrpc.EBrowserFrame, svrpc.BrowserFrame{Frame: svext.VaultEvent(ev.Vault, method == svrpc.EVaultLocked)})
	}
}

func (b *extSession) close() { b.d.broker.DropConn(b.app) }

// through ends what prompts and the audit log say of a request.
const through = ", through the secretvault extension."

// fail turns an error into the protocol's terms.
func (b *extSession) fail(err error) error {
	var e *svext.Error
	switch {
	case err == nil, errors.As(err, &e):
		return err
	case errors.Is(err, svcore.ErrLocked), errors.Is(err, svrpc.ErrLocked):
		return &svext.Error{Code: svext.CodeLocked, Message: err.Error()}
	case errors.Is(err, svrpc.ErrDenied), errors.Is(err, svrpc.ErrCanceled), errors.Is(err, svrpc.ErrNoPrompter), errors.Is(err, svrpc.ErrWrongKey):
		return &svext.Error{Code: svext.CodeDenied, Message: err.Error()}
	case errors.Is(err, svcore.ErrNotFound):
		return &svext.Error{Code: svext.CodeNotFound, Message: "no such login"}
	}
	b.d.opts.Log("browser extension: " + err.Error())
	return &svext.Error{Code: svext.CodeFailed, Message: err.Error()}
}

func (b *extSession) vault(name string) (*managedVault, error) {
	mv, err := b.d.vault(name)
	if err != nil {
		return nil, &svext.Error{Code: svext.CodeNoVault, Message: err.Error()}
	}
	return mv, nil
}

// unlocked is a vault, which must be unlocked.
func (b *extSession) unlocked(name string) (*managedVault, error) {
	mv, err := b.vault(name)
	if err != nil {
		return nil, err
	}
	b.d.fresh(mv)
	if mv.v.Locked() {
		return nil, svext.Errorf(svext.CodeLocked, "vault %q is locked", mv.cfg.Name)
	}
	return mv, nil
}

// decide is the daemon's consent, for the browser.
func (b *extSession) decide(ctx context.Context, mv *managedVault, item, itemName string, op svbroker.Op, why string) error {
	record := b.d.recorder(b.app, mv, itemName, op)
	if err := b.d.decide(ctx, b.app, mv, item, itemName, op, why, false, false, record); err != nil {
		return b.fail(err)
	}
	return b.stillOpen(mv)
}

// confirm is decide for a request that is asked about every time, whatever
// was remembered (but a no), saying why it is asked: a login handed to
// another host of its site than the one it was saved for, or one chosen
// in a panel inside the page, which the extension cannot vouch for.
func (b *extSession) confirm(ctx context.Context, mv *managedVault, item, itemName string, op svbroker.Op, why, because string) error {
	record := b.d.recorder(b.app, mv, itemName, op)
	// A remembered no still holds; only a yes is asked again.
	if dec, found, err := b.d.broker.Check(mv.v, b.app, b.app.identity(), item, op); err != nil {
		return b.fail(err)
	} else if found && !dec.Allows() {
		record("denied", "remembered decision")
		return b.fail(denied(mv))
	}
	why += "\n(" + because + ", so this is asked every time.)"
	if err := b.d.ask(ctx, b.app, mv, item, itemName, op, why, record, true); err != nil {
		return b.fail(err)
	}
	return b.stillOpen(mv)
}

func (b *extSession) stillOpen(mv *managedVault) error {
	if mv.v.Locked() {
		// Locked while the person was being asked: nothing is handed out.
		return svext.Errorf(svext.CodeLocked, "vault %q locked", mv.cfg.Name)
	}
	return nil
}

func (b *extSession) Hello(context.Context) (svext.Hello, error) {
	return svext.Hello{Browser: b.app.display(), Version: secretvault.Version}, nil
}

func (b *extSession) Vaults(context.Context) ([]svext.Vault, error) {
	var out []svext.Vault
	for _, v := range b.d.vaultInfos() {
		out = append(out, svext.Vault{Name: v.Name, Locked: v.Locked, Default: v.Default})
	}
	return out, nil
}

func (b *extSession) Unlock(ctx context.Context, vault string) error {
	mv, err := b.vault(vault)
	if err != nil {
		return err
	}
	why := fmt.Sprintf("%s asks to unlock vault %q for the secretvault extension.", b.app.display(), mv.cfg.Name)
	if _, _, err := b.d.ensureUnlocked(ctx, b.app, mv, why); err != nil {
		b.d.recorder(b.app, mv, "", svbroker.OpManage)(outcomeOf(err), err.Error())
		return b.fail(err)
	}
	return nil
}

func (b *extSession) Lock(_ context.Context, vault string) error {
	mv, err := b.vault(vault)
	if err != nil {
		return err
	}
	b.d.lock(mv, "asked by "+b.app.display()+" through the secretvault extension")
	return nil
}

// fit is how well a login fits an origin, and the stored URL that fits.
func fit(it *svcore.Item, o svext.Origin) (svext.Match, string) {
	if it.Kind != "login" {
		return svext.MatchNone, ""
	}
	best, url := svext.MatchNone, ""
	list := svext.Suffixes()
	for _, u := range loginURLs(it) {
		if m := svext.MatchURL(list, u, o); m > best {
			best, url = m, u
		}
	}
	return best, url
}

func title(e *svcore.Entry) string {
	if e.Item.Label != "" {
		return e.Item.Label
	}
	return e.Item.Name
}

// fitting are the entries of mv that fit o, best first; the caller wipes
// them.
func fitting(mv *managedVault, o svext.Origin) ([]svcore.Entry, []svext.Match, []string, error) {
	entries, err := mv.v.List("")
	if err != nil {
		return nil, nil, nil, err
	}
	type found struct {
		e   svcore.Entry
		m   svext.Match
		url string
	}
	var fs []found
	for _, e := range entries {
		m, url := fit(&e.Item, o)
		if m == svext.MatchNone {
			e.Item.Wipe()
			continue
		}
		fs = append(fs, found{e, m, url})
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].m != fs[j].m {
			return fs[i].m > fs[j].m
		}
		return strings.ToLower(title(&fs[i].e)) < strings.ToLower(title(&fs[j].e))
	})
	out := make([]svcore.Entry, len(fs))
	ms := make([]svext.Match, len(fs))
	urls := make([]string, len(fs))
	for i, f := range fs {
		out[i], ms[i], urls[i] = f.e, f.m, f.url
	}
	return out, ms, urls, nil
}

func wipeAll(es []svcore.Entry) {
	for i := range es {
		es[i].Item.Wipe()
	}
}

// clip cuts what a vault holds to what the extension is sent of it, so
// that the most logins an answer holds stay well under a frame.
func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

func (b *extSession) Logins(ctx context.Context, vault string, o svext.Origin) ([]svext.Login, error) {
	mv, err := b.unlocked(vault)
	if err != nil {
		return nil, err
	}
	why := fmt.Sprintf("%s wants to see which logins in vault %q are for %s (their names and user names)%s", b.app.display(), mv.cfg.Name, o, through)
	if err := b.decide(ctx, mv, "", "", svbroker.OpList, why); err != nil {
		return nil, err
	}
	es, ms, urls, err := fitting(mv, o)
	if err != nil {
		return nil, b.fail(err)
	}
	defer wipeAll(es)
	out := []svext.Login{}
	for i := range es {
		if len(out) == svext.MaxLogins {
			break
		}
		_, user := username(&es[i].Item)
		k := totpKey(&es[i].Item)
		if k != nil {
			k.Wipe()
		}
		out = append(out, svext.Login{ID: es[i].ID.String(), Title: clip(title(&es[i]), 256), Username: clip(user, 1024),
			URL: clip(urls[i], 1024), Match: ms[i].String(), TOTP: k != nil})
	}
	return out, nil
}

// login finds the login id names, which must fit o (with exact, its very
// host): a login that does not is as good as none. The caller wipes it.
func (b *extSession) login(mv *managedVault, id string, o svext.Origin, exact bool) (svcore.Entry, svext.Match, error) {
	nf := svext.Errorf(svext.CodeNotFound, "no such login for %s", o)
	oid, err := svformat.ParseID(id)
	if err != nil {
		return svcore.Entry{}, svext.MatchNone, nf
	}
	e, err := mv.v.GetID(oid)
	if err != nil {
		if errors.Is(err, svcore.ErrNotFound) {
			return svcore.Entry{}, svext.MatchNone, nf
		}
		return svcore.Entry{}, svext.MatchNone, b.fail(err)
	}
	m, _ := fit(&e.Item, o)
	if m == svext.MatchNone || exact && m != svext.MatchHost {
		e.Item.Wipe()
		return svcore.Entry{}, svext.MatchNone, nf
	}
	return e, m, nil
}

// read decides whether the browser may read a login for o: as any read,
// when the login is the page's host's; asked every time when it is
// another host's of the same site, which a remembered decision about the
// login (one made on its own host, or for saving it) does not cover, or
// when the extension asks so (chosen in a panel inside the page, which a
// page could have tricked the person into clicking).
func (b *extSession) read(ctx context.Context, mv *managedVault, e *svcore.Entry, m svext.Match, why string, confirm bool) error {
	switch {
	case m == svext.MatchSite:
		return b.confirm(ctx, mv, e.ID.String(), e.Item.Name, svbroker.OpRead, why, "It was saved for another host of this site")
	case confirm:
		return b.confirm(ctx, mv, e.ID.String(), e.Item.Name, svbroker.OpRead, why, "It was chosen in a panel inside the page")
	}
	return b.decide(ctx, mv, e.ID.String(), e.Item.Name, svbroker.OpRead, why)
}

func (b *extSession) Fill(ctx context.Context, vault string, o svext.Origin, id string, confirm bool) (svext.Credentials, error) {
	mv, err := b.unlocked(vault)
	if err != nil {
		return svext.Credentials{}, err
	}
	e, m, err := b.login(mv, id, o, false)
	if err != nil {
		return svext.Credentials{}, err
	}
	defer e.Item.Wipe()
	why := fmt.Sprintf("%s wants the login %q for %s%s", b.app.display(), e.Item.Name, o, through)
	if err := b.read(ctx, mv, &e, m, why, confirm); err != nil {
		return svext.Credentials{}, err
	}
	var c svext.Credentials
	_, c.Username = username(&e.Item)
	if f, ok := e.Item.Secret(); ok {
		c.Password = bytes.Clone(f.Value)
	}
	if k := totpKey(&e.Item); k != nil {
		c.TOTP, _ = k.Code(b.d.opts.Now())
		k.Wipe()
	}
	return c, nil
}

func (b *extSession) TOTP(ctx context.Context, vault string, o svext.Origin, id string, confirm bool) (string, error) {
	mv, err := b.unlocked(vault)
	if err != nil {
		return "", err
	}
	e, m, err := b.login(mv, id, o, false)
	if err != nil {
		return "", err
	}
	defer e.Item.Wipe()
	k := totpKey(&e.Item)
	if k == nil {
		return "", svext.Errorf(svext.CodeNotFound, "the login %q has no one-time code", e.Item.Name)
	}
	defer k.Wipe()
	why := fmt.Sprintf("%s wants the one-time code of the login %q for %s%s", b.app.display(), e.Item.Name, o, through)
	if err := b.read(ctx, mv, &e, m, why, confirm); err != nil {
		return "", err
	}
	code, _ := k.Code(b.d.opts.Now())
	return code, nil
}

// Check compares what a page sent with the logins that fit it. Known is
// a login of the site with that user name and password; changed is one
// of the page's very host with that user name and another password
// (another host's login is never offered for changing, from this page).
func (b *extSession) Check(ctx context.Context, vault string, o svext.Origin, user string, password []byte) (svext.CheckResult, error) {
	mv, err := b.unlocked(vault)
	if err != nil {
		return svext.CheckResult{}, err
	}
	why := fmt.Sprintf("%s wants to know whether vault %q holds the login just sent to %s, to offer saving it%s", b.app.display(), mv.cfg.Name, o, through)
	if err := b.decide(ctx, mv, "", "", svbroker.OpList, why); err != nil {
		return svext.CheckResult{}, err
	}
	es, ms, _, err := fitting(mv, o)
	if err != nil {
		return svext.CheckResult{}, b.fail(err)
	}
	defer wipeAll(es)
	changed := ""
	for i := range es {
		if _, u := username(&es[i].Item); u != user {
			continue
		}
		f, ok := es[i].Item.Secret()
		if ok && subtle.ConstantTimeCompare(f.Value, password) == 1 {
			return svext.CheckResult{Status: svext.StatusKnown, Login: es[i].ID.String()}, nil
		}
		if changed == "" && ms[i] == svext.MatchHost {
			changed = es[i].ID.String()
		}
	}
	if changed != "" {
		return svext.CheckResult{Status: svext.StatusChanged, Login: changed}, nil
	}
	return svext.CheckResult{Status: svext.StatusNew}, nil
}

func (b *extSession) Save(ctx context.Context, vault string, o svext.Origin, s svext.SaveLogin) (string, bool, error) {
	mv, err := b.unlocked(vault)
	if err != nil {
		return "", false, err
	}
	b.save.Lock()
	defer b.save.Unlock()
	if s.Login != "" {
		return b.update(ctx, mv, o, s)
	}
	name := freeName(mv, defaultFolder, o.Host, s.Username)
	why := fmt.Sprintf("%s wants to save a new login %q for %s%s", b.app.display(), name, o, through)
	if err := b.decide(ctx, mv, "", name, svbroker.OpWrite, why); err != nil {
		return "", false, err
	}
	if e, err := mv.v.Get(name); err == nil {
		// Taken while the person was deciding.
		e.Item.Wipe()
		name = freeName(mv, defaultFolder, o.Host, s.Username)
	}
	label := s.Title
	if label == "" {
		label = o.Host
	}
	it := svcore.Item{Kind: "login", Name: name, Label: label}
	if s.Username != "" {
		it.Fields = append(it.Fields, svcore.Field{Name: "username", Type: svcore.FieldText, Value: []byte(s.Username)})
	}
	it.Fields = append(it.Fields,
		svcore.Field{Name: "password", Type: svcore.FieldConcealed, Value: bytes.Clone(s.Password)},
		svcore.Field{Name: "url", Type: svcore.FieldURL, Value: []byte(o.String())})
	defer it.Wipe()
	e, err := mv.v.Put(it)
	if err != nil {
		return "", false, b.fail(err)
	}
	e.Item.Wipe()
	// The program that saves a login may read, change and delete it.
	b.d.broker.Remember(mv.v, svbroker.Grant{Identity: b.app.identity(), Program: b.app.display(), Item: e.ID.String(),
		ItemName: name, Ops: []svbroker.Op{svbroker.OpRead, svbroker.OpWrite, svbroker.OpDelete}, Decision: svbroker.AllowAlways})
	b.d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: name})
	return e.ID.String(), true, nil
}

// update changes a login's password, and its user name when one is given.
// Only a login of the page's very host may be changed from it: another
// host of the site could otherwise overwrite its sibling's password.
func (b *extSession) update(ctx context.Context, mv *managedVault, o svext.Origin, s svext.SaveLogin) (string, bool, error) {
	e, _, err := b.login(mv, s.Login, o, true)
	if err != nil {
		return "", false, err
	}
	defer e.Item.Wipe()
	name := e.Item.Name
	why := fmt.Sprintf("%s wants to change the password of the login %q, for %s%s", b.app.display(), name, o, through)
	if err := b.decide(ctx, mv, e.ID.String(), name, svbroker.OpWrite, why); err != nil {
		return "", false, err
	}
	it := e.Item
	defer it.Wipe() // what SetField appends is not in e.Item
	if s.Username != "" {
		field, _ := username(&it)
		if field == "" {
			field = "username"
		}
		it.SetField(svcore.Field{Name: field, Type: svcore.FieldText, Value: []byte(s.Username)})
	}
	pw := "password"
	if f, ok := it.Secret(); ok {
		pw = f.Name
	}
	it.SetField(svcore.Field{Name: pw, Type: svcore.FieldConcealed, Value: bytes.Clone(s.Password)})
	ne, err := mv.v.Put(it)
	if err != nil {
		return "", false, b.fail(err)
	}
	ne.Item.Wipe()
	b.d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: name})
	return ne.ID.String(), false, nil
}

// An extSession is the svext backend.
var _ svext.Backend = (*extSession)(nil)
