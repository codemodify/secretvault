package svd

import (
	"context"
	"errors"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// org.freedesktop.Secret.Service.

func (ss *secretService) serviceInterface() *svdbus.Interface {
	return &svdbus.Interface{
		Name: ifService,
		Methods: []*svdbus.Method{
			{Name: "OpenSession", In: args("algorithm", "s", "input", "v"), Out: args("output", "v", "result", "o"), Handler: ss.openSession},
			{Name: "CreateCollection", In: args("properties", "a{sv}", "alias", "s"), Out: args("collection", "o", "prompt", "o"), Handler: ss.createCollection},
			{Name: "SearchItems", In: args("attributes", "a{ss}"), Out: args("unlocked", "ao", "locked", "ao"), Handler: ss.searchItems},
			{Name: "Unlock", In: args("objects", "ao"), Out: args("unlocked", "ao", "prompt", "o"), Handler: ss.unlock},
			{Name: "Lock", In: args("objects", "ao"), Out: args("locked", "ao", "Prompt", "o"), Handler: ss.lockObjects},
			{Name: "GetSecrets", In: args("items", "ao", "session", "o"), Out: args("secrets", "a{o(oayays)}"), Handler: ss.getSecrets},
			{Name: "ReadAlias", In: args("name", "s"), Out: args("collection", "o"), Handler: ss.readAlias},
			{Name: "SetAlias", In: args("name", "s", "collection", "o"), Handler: ss.setAlias},
		},
		Properties: []*svdbus.Property{
			{Name: "Collections", Type: "ao", EmitsChanged: svdbus.EmitsChangedInvalidates, Get: func(context.Context, *svdbus.Call) (any, error) {
				var out []svdbus.ObjectPath
				for _, mv := range ss.vaults() {
					out = append(out, collectionPath(mv.cfg.Name))
				}
				return nonNilPaths(out), nil
			}},
		},
		Signals: []*svdbus.Signal{
			{Name: "CollectionCreated", Args: args("collection", "o")},
			{Name: "CollectionDeleted", Args: args("collection", "o")},
			{Name: "CollectionChanged", Args: args("collection", "o")},
		},
	}
}

// args builds an argument list from name, type pairs.
func args(pairs ...string) []svdbus.Arg {
	var out []svdbus.Arg
	for i := 0; i+1 < len(pairs); i += 2 {
		out = append(out, svdbus.Arg{Name: pairs[i], Type: svdbus.Signature(pairs[i+1])})
	}
	return out
}

func nonNilPaths(p []svdbus.ObjectPath) []svdbus.ObjectPath {
	if p == nil {
		return []svdbus.ObjectPath{}
	}
	return p
}

func (ss *secretService) openSession(ctx context.Context, call *svdbus.Call) ([]any, error) {
	var alg string
	var input svdbus.Variant
	if err := call.Decode(&alg, &input); err != nil {
		return nil, err
	}
	if _, err := ss.caller(ctx, call.Sender()); err != nil {
		return nil, err
	}
	s := &ssSession{owner: call.Sender()}
	output := svdbus.MakeVariant("")
	switch alg {
	case algPlain:
	case algDH:
		var pub []byte
		if err := input.Store(&pub); err != nil {
			return nil, svdbus.NewError(svdbus.ErrorInvalidArgs, "the dh session wants a public key (ay)")
		}
		serverPub, key, err := dhSession(pub)
		if err != nil {
			return nil, svdbus.NewError(svdbus.ErrorInvalidArgs, err.Error())
		}
		s.key = key
		output = svdbus.MakeVariant(serverPub)
	default:
		return nil, svdbus.NewError(errNotSupported, "unknown session algorithm "+alg)
	}
	path := ss.newPath(ssSessions)
	ss.mu.Lock()
	ss.sessions[path] = s
	ss.mu.Unlock()
	return []any{output, path}, nil
}

// session finds a session the caller opened.
func (ss *secretService) session(path svdbus.ObjectPath, sender string) (*ssSession, error) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	s := ss.sessions[path]
	if s == nil || s.owner != sender {
		return nil, svdbus.NewError(errNoSession, "no such session")
	}
	return s, nil
}

func (ss *secretService) createCollection(ctx context.Context, call *svdbus.Call) ([]any, error) {
	var props map[string]svdbus.Variant
	var alias string
	if err := call.Decode(&props, &alias); err != nil {
		return nil, err
	}
	switch alias {
	case "default":
		if mv, err := ss.d.vault(""); err == nil {
			return []any{collectionPath(mv.cfg.Name), ssNoPrompt}, nil
		}
	case "session":
		mv, err := ss.memoryVault()
		if err != nil {
			return nil, asDBusError(err)
		}
		return []any{collectionPath(mv.cfg.Name), ssNoPrompt}, nil
	}
	return nil, svdbus.NewError(errNotSupported, "secretvault makes new vaults with 'secretvault init', not over the Secret Service")
}

func (ss *secretService) searchItems(ctx context.Context, call *svdbus.Call) ([]any, error) {
	var attrs map[string]string
	if err := call.Decode(&attrs); err != nil {
		return nil, err
	}
	c, err := ss.caller(ctx, call.Sender())
	if err != nil {
		return nil, err
	}
	// Only an unlocked vault can be searched: its attributes are
	// encrypted. When every vault is locked, the default one is unlocked
	// for this search, asking the person, for as long as the caller waits.
	anyOpen := false
	for _, mv := range ss.vaults() {
		anyOpen = anyOpen || !mv.v.Locked()
	}
	if !anyOpen {
		if mv, err := ss.d.vault(""); err == nil {
			why := describeRequest(c.client, mv, "", svbroker.OpList)
			ss.d.ensureUnlocked(ctx, c.client, mv, why)
		}
	}
	var unlocked, locked []svdbus.ObjectPath
	for _, mv := range ss.vaults() {
		if mv.v.Locked() {
			continue
		}
		entries, err := mv.v.List("")
		if err != nil {
			continue
		}
		for _, e := range entries {
			if matches(&e.Item, attrs) {
				ss.remember(c, e.ID)
				if ss.permitted(c, mv, e.ID.String(), svbroker.OpRead) {
					unlocked = append(unlocked, itemPath(mv.cfg.Name, e.ID))
				} else {
					locked = append(locked, itemPath(mv.cfg.Name, e.ID))
				}
			}
			e.Item.Wipe()
		}
	}
	return []any{nonNilPaths(unlocked), nonNilPaths(locked)}, nil
}

// unlock answers which objects the caller may use now, and a prompt for
// the rest: unlocking their vaults and asking the person about the caller.
func (ss *secretService) unlock(ctx context.Context, call *svdbus.Call) ([]any, error) {
	var objects []svdbus.ObjectPath
	if err := call.Decode(&objects); err != nil {
		return nil, err
	}
	c, err := ss.caller(ctx, call.Sender())
	if err != nil {
		return nil, err
	}
	var done, pending []svdbus.ObjectPath
	for _, o := range objects {
		if mv, ok := ss.resolveCollection(o); ok {
			if mv.v.Locked() {
				pending = append(pending, o)
			} else {
				done = append(done, o)
			}
			continue
		}
		if mv, id, ok := ss.resolveItem(o); ok {
			if ss.permitted(c, mv, id.String(), svbroker.OpRead) {
				done = append(done, o)
			} else {
				pending = append(pending, o)
			}
		}
	}
	prompt := ssNoPrompt
	if len(pending) > 0 {
		prompt = ss.newPrompt(c, call.Sender(), func(ctx context.Context) (svdbus.Variant, bool) {
			var got []svdbus.ObjectPath
			canceled := false
			for _, o := range pending {
				var err error
				if mv, ok := ss.resolveCollection(o); ok {
					why := describeRequest(c.client, mv, "", svbroker.OpList)
					_, _, err = ss.d.ensureUnlocked(ctx, c.client, mv, why)
				} else if mv, id, ok := ss.resolveItem(o); ok {
					name := ""
					if !mv.v.Locked() {
						if e, err := entryByID(mv, id); err == nil {
							name = e.Item.Name
							e.Item.Wipe()
						}
					}
					err = ss.d.authorize(ctx, c.client, mv, id.String(), name, svbroker.OpRead)
				}
				if err == nil {
					got = append(got, o)
				} else if isCanceled(err) {
					canceled = true
				}
			}
			return svdbus.MakeVariant(nonNilPaths(got)), canceled && len(got) == 0
		})
	}
	return []any{nonNilPaths(done), prompt}, nil
}

// lockObjects locks the vaults of the objects named. Anyone may lock.
func (ss *secretService) lockObjects(ctx context.Context, call *svdbus.Call) ([]any, error) {
	var objects []svdbus.ObjectPath
	if err := call.Decode(&objects); err != nil {
		return nil, err
	}
	c, err := ss.caller(ctx, call.Sender())
	if err != nil {
		return nil, err
	}
	var locked []svdbus.ObjectPath
	for _, o := range objects {
		mv, ok := ss.resolveCollection(o)
		if !ok {
			if m, _, ok2 := ss.resolveItem(o); ok2 {
				mv, ok = m, true
			}
		}
		if ok && mv.cfg.Name != ssMemoryName {
			ss.d.lock(mv, "asked by "+c.display())
			locked = append(locked, o)
		}
	}
	return []any{nonNilPaths(locked), ssNoPrompt}, nil
}

func (ss *secretService) getSecrets(ctx context.Context, call *svdbus.Call) ([]any, error) {
	var items []svdbus.ObjectPath
	var sessionPath svdbus.ObjectPath
	if err := call.Decode(&items, &sessionPath); err != nil {
		return nil, err
	}
	c, err := ss.caller(ctx, call.Sender())
	if err != nil {
		return nil, err
	}
	s, err := ss.session(sessionPath, call.Sender())
	if err != nil {
		return nil, err
	}
	out := map[svdbus.ObjectPath]ssSecret{}
	for _, p := range items {
		mv, id, ok := ss.resolveItem(p)
		if !ok || !ss.permitted(c, mv, id.String(), svbroker.OpRead) {
			continue // locked (to this caller) items are left out
		}
		sec, err := ss.readSecret(c, mv, id, sessionPath, s)
		if err == nil {
			out[p] = sec
		}
	}
	return []any{out}, nil
}

// readSecret reads and seals an item's secret for a session, and audits it.
func (ss *secretService) readSecret(c *ssCaller, mv *managedVault, id svformat.ID, sessionPath svdbus.ObjectPath, s *ssSession) (ssSecret, error) {
	e, err := entryByID(mv, id)
	if err != nil {
		return ssSecret{}, err
	}
	defer e.Item.Wipe()
	params, value, err := s.seal(itemSecret(&e.Item))
	if err != nil {
		return ssSecret{}, err
	}
	ss.d.recorder(c.client, mv, e.Item.Name, svbroker.OpRead)("allowed", "read over the Secret Service")
	ss.d.touch(mv)
	return ssSecret{Session: sessionPath, Parameters: params, Value: value, ContentType: contentTypeOf(&e.Item)}, nil
}

func (ss *secretService) readAlias(ctx context.Context, call *svdbus.Call) ([]any, error) {
	var name string
	if err := call.Decode(&name); err != nil {
		return nil, err
	}
	if mv, ok := ss.resolveCollection(svdbus.ObjectPath(ssAliases + name)); ok {
		return []any{collectionPath(mv.cfg.Name)}, nil
	}
	return []any{ssNoPrompt}, nil
}

// setAlias moves the "default" alias: which vault new secrets go to. It
// needs a standing permission to manage that vault.
func (ss *secretService) setAlias(ctx context.Context, call *svdbus.Call) ([]any, error) {
	var name string
	var target svdbus.ObjectPath
	if err := call.Decode(&name, &target); err != nil {
		return nil, err
	}
	c, err := ss.caller(ctx, call.Sender())
	if err != nil {
		return nil, err
	}
	if name != "default" {
		return nil, svdbus.NewError(errNotSupported, "only the default alias can be set")
	}
	mv, ok := ss.resolveCollection(target)
	if !ok || mv.cfg.Name == ssMemoryName {
		return nil, svdbus.NewError(errNoSuchObject, "no such collection")
	}
	if mv.cfg.RequestedBy != "" {
		// A vault a program asked for becomes the default only when the
		// person makes it so, in secretvault: as the default, it would
		// get every other program's new secrets.
		return nil, svdbus.NewError(svdbus.ErrorAccessDenied, "a vault a program asked for is made the default only in secretvault")
	}
	if !ss.permitted(c, mv, "", svbroker.OpManage) {
		return nil, errDenied
	}
	return nil, asDBusError(ss.d.setDefault(mv.cfg.Name))
}

// isCanceled reports whether the person said no, or walked away.
func isCanceled(err error) bool {
	return errors.Is(err, svrpc.ErrCanceled) || errors.Is(err, svrpc.ErrDenied)
}
