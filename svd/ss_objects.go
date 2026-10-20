package svd

import (
	"context"
	"strings"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svformat"
)

// lookup gives the interfaces of a path under /org/freedesktop/secrets.
func (ss *secretService) lookup(path svdbus.ObjectPath) []*svdbus.Interface {
	p := string(path)
	switch {
	case strings.HasPrefix(p, ssSessions):
		ss.mu.Lock()
		_, ok := ss.sessions[path]
		ss.mu.Unlock()
		if ok {
			return []*svdbus.Interface{ss.sessionInterface(path)}
		}
	case strings.HasPrefix(p, ssPrompts):
		ss.mu.Lock()
		pr := ss.prompts[path]
		ss.mu.Unlock()
		if pr != nil {
			return []*svdbus.Interface{ss.promptInterface(path, pr)}
		}
	case strings.HasPrefix(p, ssCollections), strings.HasPrefix(p, ssAliases):
		if mv, ok := ss.resolveCollection(path); ok {
			return []*svdbus.Interface{ss.collectionInterface(mv)}
		}
		if mv, id, ok := ss.resolveItem(path); ok {
			return []*svdbus.Interface{ss.itemInterface(mv, id)}
		}
	}
	return nil
}

func (ss *secretService) children(path svdbus.ObjectPath) []string {
	switch string(path) {
	case string(ssRoot):
		return []string{"collection", "aliases", "session", "prompt"}
	case strings.TrimSuffix(ssCollections, "/"):
		var out []string
		for _, mv := range ss.vaults() {
			out = append(out, strings.TrimPrefix(string(collectionPath(mv.cfg.Name)), ssCollections))
		}
		return out
	case strings.TrimSuffix(ssAliases, "/"):
		return []string{"default", "session"}
	}
	return nil
}

func (ss *secretService) sessionInterface(path svdbus.ObjectPath) *svdbus.Interface {
	return &svdbus.Interface{Name: ifSession, Methods: []*svdbus.Method{{
		Name: "Close",
		Handler: func(ctx context.Context, call *svdbus.Call) ([]any, error) {
			ss.mu.Lock()
			defer ss.mu.Unlock()
			if s := ss.sessions[path]; s != nil && s.owner == call.Sender() {
				clear(s.key)
				delete(ss.sessions, path)
			}
			return nil, nil
		},
	}}}
}

// org.freedesktop.Secret.Collection.

func (ss *secretService) collectionInterface(mv *managedVault) *svdbus.Interface {
	label := mv.cfg.Name
	if label == ssMemoryName {
		label = "session"
	}
	return &svdbus.Interface{
		Name: ifCollection,
		Methods: []*svdbus.Method{
			{Name: "Delete", Out: args("prompt", "o"), Handler: func(context.Context, *svdbus.Call) ([]any, error) {
				return nil, svdbus.NewError(errNotSupported, "vaults are deleted with secretvault, not over the Secret Service")
			}},
			{Name: "SearchItems", In: args("attributes", "a{ss}"), Out: args("results", "ao"), Handler: func(ctx context.Context, call *svdbus.Call) ([]any, error) {
				var attrs map[string]string
				if err := call.Decode(&attrs); err != nil {
					return nil, err
				}
				c, err := ss.caller(ctx, call.Sender())
				if err != nil {
					return nil, err
				}
				var out []svdbus.ObjectPath
				if !mv.v.Locked() {
					entries, _ := mv.v.List("")
					for _, e := range entries {
						if matches(&e.Item, attrs) {
							ss.remember(c, e.ID)
							out = append(out, itemPath(mv.cfg.Name, e.ID))
						}
						e.Item.Wipe()
					}
				}
				return []any{nonNilPaths(out)}, nil
			}},
			{Name: "CreateItem", In: args("properties", "a{sv}", "secret", "(oayays)", "replace", "b"), Out: args("item", "o", "prompt", "o"),
				Handler: func(ctx context.Context, call *svdbus.Call) ([]any, error) { return ss.createItem(ctx, call, mv) }},
		},
		Properties: []*svdbus.Property{
			{Name: "Items", Type: "ao", EmitsChanged: svdbus.EmitsChangedInvalidates, Get: func(ctx context.Context, call *svdbus.Call) (any, error) {
				c, err := ss.caller(ctx, call.Sender())
				if err != nil || mv.v.Locked() {
					return []svdbus.ObjectPath{}, err
				}
				entries, _ := mv.v.List("")
				var out []svdbus.ObjectPath
				for _, e := range entries {
					if ss.visible(c, mv, e.ID) {
						out = append(out, itemPath(mv.cfg.Name, e.ID))
					}
					e.Item.Wipe()
				}
				return nonNilPaths(out), nil
			}},
			{Name: "Label", Type: "s", Get: func(context.Context, *svdbus.Call) (any, error) { return label, nil },
				Set: func(context.Context, *svdbus.Call, svdbus.Variant) error {
					return svdbus.NewError(errNotSupported, "vaults are renamed with secretvault")
				}},
			{Name: "Locked", Type: "b", Get: func(context.Context, *svdbus.Call) (any, error) { return mv.v.Locked(), nil }},
			{Name: "Created", Type: "t", Get: func(context.Context, *svdbus.Call) (any, error) { return uint64(mv.v.Created().Unix()), nil }},
			{Name: "Modified", Type: "t", Get: func(context.Context, *svdbus.Call) (any, error) { return uint64(mv.v.Created().Unix()), nil }},
		},
		Signals: []*svdbus.Signal{
			{Name: "ItemCreated", Args: args("item", "o")},
			{Name: "ItemDeleted", Args: args("item", "o")},
			{Name: "ItemChanged", Args: args("item", "o")},
		},
	}
}

// itemFromProperties reads CreateItem's properties.
func itemFromProperties(props map[string]svdbus.Variant) (label string, attrs map[string]string, err error) {
	attrs = map[string]string{}
	if v, ok := props[ifItem+".Label"]; ok {
		if err := v.Store(&label); err != nil {
			return "", nil, svdbus.NewError(svdbus.ErrorInvalidArgs, "the label must be a string")
		}
	}
	if v, ok := props[ifItem+".Attributes"]; ok {
		if err := v.Store(&attrs); err != nil {
			return "", nil, svdbus.NewError(svdbus.ErrorInvalidArgs, "the attributes must be a{ss}")
		}
	}
	return label, attrs, nil
}

// itemName makes a unique item name for a Secret Service item: its
// label, with '/' replaced.
func itemName(mv *managedVault, label string) string {
	base := strings.ReplaceAll(strings.TrimSpace(label), "/", "∕")
	base = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, base)
	if base == "" || base == "." || base == ".." || !utf8.ValidString(base) {
		base = "secret"
	}
	if len(base) > 200 {
		base = base[:200]
	}
	return mv.v.FreeName(base)
}

// createItem stores a new item (or replaces the one with the same
// attributes). A caller that may not yet write to the vault gets a prompt.
func (ss *secretService) createItem(ctx context.Context, call *svdbus.Call, mv *managedVault) ([]any, error) {
	var props map[string]svdbus.Variant
	var sec ssSecret
	var replace bool
	if err := call.Decode(&props, &sec, &replace); err != nil {
		return nil, err
	}
	c, err := ss.caller(ctx, call.Sender())
	if err != nil {
		return nil, err
	}
	s, err := ss.session(sec.Session, call.Sender())
	if err != nil {
		return nil, err
	}
	label, attrs, err := itemFromProperties(props)
	if err != nil {
		return nil, err
	}
	value, err := s.open(sec.Parameters, sec.Value)
	if err != nil {
		return nil, svdbus.NewError(svdbus.ErrorInvalidArgs, err.Error())
	}
	contentType := sec.ContentType

	store := func(ctx context.Context) (svdbus.ObjectPath, error) {
		defer clear(value)
		// replace: the item with exactly these attributes, if any.
		var existing *svcore.Entry
		if replace {
			entries, _ := mv.v.List("")
			for i := range entries {
				if existing == nil && entries[i].Item.Kind != svcore.KindPasskey && len(entries[i].Item.Attrs) == len(attrs) && matches(&entries[i].Item, attrs) {
					existing = &entries[i]
				} else {
					entries[i].Item.Wipe()
				}
			}
		}
		var it svcore.Item
		if existing != nil {
			it = existing.Item
			if err := ss.d.authorize(ctx, c.client, mv, existing.ID.String(), it.Name, svbroker.OpWrite); err != nil {
				it.Wipe()
				return "", err
			}
		} else {
			it = svcore.Item{Kind: "password", Name: itemName(mv, label)}
			if err := ss.d.authorize(ctx, c.client, mv, "", it.Name, svbroker.OpWrite); err != nil {
				return "", err
			}
		}
		it.Label, it.Attrs = label, attrs
		it.SetField(svcore.Field{Name: secretFieldName(&it), Type: svcore.FieldConcealed, Value: append([]byte(nil), value...)})
		if contentType != "" && contentType != "text/plain" {
			it.SetField(svcore.Field{Name: "content_type", Type: svcore.FieldText, Value: []byte(contentType)})
		}
		e, err := mv.v.Put(it)
		it.Wipe()
		if err != nil {
			return "", err
		}
		e.Item.Wipe()
		// The program that stores a secret may read, change and delete it.
		ss.d.broker.Remember(mv.v, svbroker.Grant{Identity: c.identity(), Program: c.display(), Item: e.ID.String(),
			ItemName: e.Item.Name, Ops: []svbroker.Op{svbroker.OpRead, svbroker.OpWrite, svbroker.OpDelete}, Decision: svbroker.AllowAlways})
		ss.remember(c, e.ID)
		path := itemPath(mv.cfg.Name, e.ID)
		signal := "ItemCreated"
		if existing != nil {
			signal = "ItemChanged"
		}
		ss.bus.Emit(collectionPath(mv.cfg.Name), ifCollection, signal, path)
		return path, nil
	}

	if ss.permitted(c, mv, "", svbroker.OpWrite) {
		path, err := store(ctx)
		if err != nil {
			return nil, asDBusError(err)
		}
		return []any{path, ssNoPrompt}, nil
	}
	prompt := ss.newPrompt(c, call.Sender(), func(ctx context.Context) (svdbus.Variant, bool) {
		path, err := store(ctx)
		if err != nil {
			return svdbus.MakeVariant(ssNoPrompt), isCanceled(err)
		}
		return svdbus.MakeVariant(path), false
	})
	return []any{ssNoPrompt, prompt}, nil
}

// secretFieldName is the field a Secret Service secret lives in: the
// item's existing primary secret, else "secret".
func secretFieldName(it *svcore.Item) string {
	if f, ok := it.Secret(); ok {
		return f.Name
	}
	return "secret"
}

// org.freedesktop.Secret.Item.

func (ss *secretService) itemInterface(mv *managedVault, id svformat.ID) *svdbus.Interface {
	path := itemPath(mv.cfg.Name, id)
	// metadata returns the item when the caller may see it.
	metadata := func(ctx context.Context, call *svdbus.Call) (*svcore.Entry, error) {
		c, err := ss.caller(ctx, call.Sender())
		if err != nil {
			return nil, err
		}
		if mv.v.Locked() {
			return nil, svdbus.NewError(errIsLocked, "the vault is locked")
		}
		if !ss.visible(c, mv, id) {
			return nil, errDenied
		}
		e, err := entryByID(mv, id)
		if err != nil {
			return nil, err
		}
		return &e, nil
	}
	return &svdbus.Interface{
		Name: ifItem,
		Methods: []*svdbus.Method{
			{Name: "Delete", Out: args("Prompt", "o"), Handler: func(ctx context.Context, call *svdbus.Call) ([]any, error) {
				c, err := ss.caller(ctx, call.Sender())
				if err != nil {
					return nil, err
				}
				del := func(ctx context.Context) error {
					e, err := entryByID(mv, id)
					if err != nil {
						return err
					}
					e.Item.Wipe()
					if err := ss.d.authorize(ctx, c.client, mv, id.String(), e.Item.Name, svbroker.OpDelete); err != nil {
						return err
					}
					if err := mv.v.Delete(e.Item.Name); err != nil {
						return err
					}
					ss.bus.Emit(collectionPath(mv.cfg.Name), ifCollection, "ItemDeleted", path)
					return nil
				}
				if ss.permitted(c, mv, id.String(), svbroker.OpDelete) {
					return []any{ssNoPrompt}, asDBusError(del(ctx))
				}
				return []any{ss.newPrompt(c, call.Sender(), func(ctx context.Context) (svdbus.Variant, bool) {
					err := del(ctx)
					return svdbus.MakeVariant(""), err != nil && isCanceled(err)
				})}, nil
			}},
			{Name: "GetSecret", In: args("session", "o"), Out: args("secret", "(oayays)"), Handler: func(ctx context.Context, call *svdbus.Call) ([]any, error) {
				var sp svdbus.ObjectPath
				if err := call.Decode(&sp); err != nil {
					return nil, err
				}
				c, err := ss.caller(ctx, call.Sender())
				if err != nil {
					return nil, err
				}
				s, err := ss.session(sp, call.Sender())
				if err != nil {
					return nil, err
				}
				if !ss.permitted(c, mv, id.String(), svbroker.OpRead) {
					return nil, svdbus.NewError(errIsLocked, "unlock the item first (the person has not allowed this program yet)")
				}
				sec, err := ss.readSecret(c, mv, id, sp, s)
				if err != nil {
					return nil, asDBusError(err)
				}
				return []any{sec}, nil
			}},
			{Name: "SetSecret", In: args("secret", "(oayays)"), Handler: func(ctx context.Context, call *svdbus.Call) ([]any, error) {
				var sec ssSecret
				if err := call.Decode(&sec); err != nil {
					return nil, err
				}
				c, err := ss.caller(ctx, call.Sender())
				if err != nil {
					return nil, err
				}
				s, err := ss.session(sec.Session, call.Sender())
				if err != nil {
					return nil, err
				}
				if !ss.permitted(c, mv, id.String(), svbroker.OpWrite) {
					return nil, svdbus.NewError(errIsLocked, "unlock the item first (the person has not allowed this program yet)")
				}
				value, err := s.open(sec.Parameters, sec.Value)
				if err != nil {
					return nil, svdbus.NewError(svdbus.ErrorInvalidArgs, err.Error())
				}
				defer clear(value)
				e, err := entryByID(mv, id)
				if err != nil {
					return nil, err
				}
				it := e.Item
				defer it.Wipe()
				if it.Kind == svcore.KindPasskey {
					return nil, svdbus.NewError(errNotSupported, "a passkey has no secret to set: it is made and used by the browser extension")
				}
				it.SetField(svcore.Field{Name: secretFieldName(&it), Type: svcore.FieldConcealed, Value: append([]byte(nil), value...)})
				if sec.ContentType != "" && sec.ContentType != "text/plain" {
					it.SetField(svcore.Field{Name: "content_type", Type: svcore.FieldText, Value: []byte(sec.ContentType)})
				}
				if _, err := mv.v.Put(it); err != nil {
					return nil, asDBusError(err)
				}
				ss.d.recorder(c.client, mv, it.Name, svbroker.OpWrite)("allowed", "changed over the Secret Service")
				ss.bus.Emit(collectionPath(mv.cfg.Name), ifCollection, "ItemChanged", path)
				return nil, nil
			}},
		},
		Properties: []*svdbus.Property{
			{Name: "Locked", Type: "b", Get: func(ctx context.Context, call *svdbus.Call) (any, error) {
				c, err := ss.caller(ctx, call.Sender())
				if err != nil {
					return true, err
				}
				return !ss.permitted(c, mv, id.String(), svbroker.OpRead), nil
			}},
			{Name: "Attributes", Type: "a{ss}",
				Get: func(ctx context.Context, call *svdbus.Call) (any, error) {
					e, err := metadata(ctx, call)
					if err != nil {
						return nil, err
					}
					defer e.Item.Wipe()
					attrs := e.Item.Attrs
					if attrs == nil {
						attrs = map[string]string{}
					}
					return attrs, nil
				},
				Set: func(ctx context.Context, call *svdbus.Call, v svdbus.Variant) error {
					var attrs map[string]string
					if err := v.Store(&attrs); err != nil {
						return svdbus.NewError(svdbus.ErrorInvalidArgs, "attributes must be a{ss}")
					}
					return ss.changeItem(ctx, call, mv, id, func(it *svcore.Item) { it.Attrs = attrs })
				}},
			{Name: "Label", Type: "s",
				Get: func(ctx context.Context, call *svdbus.Call) (any, error) {
					e, err := metadata(ctx, call)
					if err != nil {
						return nil, err
					}
					defer e.Item.Wipe()
					return labelOf(&e.Item), nil
				},
				Set: func(ctx context.Context, call *svdbus.Call, v svdbus.Variant) error {
					var label string
					if err := v.Store(&label); err != nil {
						return svdbus.NewError(svdbus.ErrorInvalidArgs, "the label must be a string")
					}
					return ss.changeItem(ctx, call, mv, id, func(it *svcore.Item) { it.Label = label })
				}},
			{Name: "Created", Type: "t", Get: func(ctx context.Context, call *svdbus.Call) (any, error) {
				e, err := metadata(ctx, call)
				if err != nil {
					return nil, err
				}
				defer e.Item.Wipe()
				created := e.Time
				if hist, err := mv.v.History(e.Item.Name); err == nil {
					for _, h := range hist {
						if h.Time.Before(created) {
							created = h.Time
						}
						h.Item.Wipe()
					}
				}
				return uint64(created.Unix()), nil
			}},
			{Name: "Modified", Type: "t", Get: func(ctx context.Context, call *svdbus.Call) (any, error) {
				e, err := metadata(ctx, call)
				if err != nil {
					return nil, err
				}
				defer e.Item.Wipe()
				return uint64(e.Time.Unix()), nil
			}},
		},
	}
}

// changeItem applies a metadata change a caller may make without a prompt.
func (ss *secretService) changeItem(ctx context.Context, call *svdbus.Call, mv *managedVault, id svformat.ID, change func(*svcore.Item)) error {
	c, err := ss.caller(ctx, call.Sender())
	if err != nil {
		return err
	}
	if !ss.permitted(c, mv, id.String(), svbroker.OpWrite) {
		return svdbus.NewError(errIsLocked, "unlock the item first")
	}
	e, err := entryByID(mv, id)
	if err != nil {
		return err
	}
	defer e.Item.Wipe()
	change(&e.Item)
	if _, err := mv.v.Put(e.Item); err != nil {
		return asDBusError(err)
	}
	ss.bus.Emit(collectionPath(mv.cfg.Name), ifCollection, "ItemChanged", itemPath(mv.cfg.Name, id))
	return nil
}
