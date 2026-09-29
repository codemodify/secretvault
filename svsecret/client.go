package svsecret

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/codemodify/secretvault/svdbus"
)

// A client of whichever keyring owns org.freedesktop.secrets: enough to
// read everything out of it, for importing before secretvault takes over.

const (
	busName      = "org.freedesktop.secrets"
	servicePath  = svdbus.ObjectPath("/org/freedesktop/secrets")
	ifService    = "org.freedesktop.Secret.Service"
	ifCollection = "org.freedesktop.Secret.Collection"
	ifItem       = "org.freedesktop.Secret.Item"
	ifPrompt     = "org.freedesktop.Secret.Prompt"
	noPrompt     = svdbus.ObjectPath("/")
)

// Owner describes the program that owns org.freedesktop.secrets.
type Owner struct {
	UniqueName string
	PID        uint32
	Exe        string // "" if it cannot be read
}

// ErrNoKeyring is a session where nothing owns org.freedesktop.secrets.
var ErrNoKeyring = errors.New("svsecret: no keyring owns org.freedesktop.secrets")

// CurrentOwner asks the bus who owns org.freedesktop.secrets.
func CurrentOwner(ctx context.Context, bus *svdbus.Conn) (Owner, error) {
	name, err := bus.GetNameOwner(ctx, busName)
	if err != nil {
		return Owner{}, ErrNoKeyring
	}
	o := Owner{UniqueName: name}
	if pid, err := bus.GetConnectionUnixProcessID(ctx, name); err == nil {
		o.PID = pid
		o.Exe, _ = os.Readlink("/proc/" + strconv.Itoa(int(pid)) + "/exe")
	}
	return o, nil
}

// Client reads from the keyring over one session.
type Client struct {
	bus     *svdbus.Conn
	session svdbus.ObjectPath
	key     []byte
}

// Open opens a session with the keyring: DH if it offers it, else plain.
func Open(ctx context.Context, bus *svdbus.Conn) (*Client, error) {
	k := NewDHKey()
	r, err := bus.Call(ctx, busName, servicePath, ifService, "OpenSession", DH, svdbus.MakeVariant(k.Pub))
	if err == nil {
		var out svdbus.Variant
		var session svdbus.ObjectPath
		if err := r.Decode(&out, &session); err != nil {
			return nil, err
		}
		var peer []byte
		if err := out.Store(&peer); err != nil {
			return nil, fmt.Errorf("svsecret: the keyring's session reply: %w", err)
		}
		key, err := k.SessionKey(peer)
		if err != nil {
			return nil, err
		}
		return &Client{bus: bus, session: session, key: key}, nil
	}
	r, err = bus.Call(ctx, busName, servicePath, ifService, "OpenSession", Plain, svdbus.MakeVariant(""))
	if err != nil {
		return nil, err
	}
	var out svdbus.Variant
	var session svdbus.ObjectPath
	if err := r.Decode(&out, &session); err != nil {
		return nil, err
	}
	return &Client{bus: bus, session: session}, nil
}

// Close closes the session and forgets its key.
func (c *Client) Close() {
	c.bus.CallNoReply(busName, c.session, "org.freedesktop.Secret.Session", "Close")
	clear(c.key)
}

// Secret is one item read out of a keyring.
type Secret struct {
	Collection  string // the collection's label
	Label       string
	Attributes  map[string]string
	Value       []byte
	ContentType string
	Created     time.Time
	Modified    time.Time
}

// Wipe zeroes the value.
func (s *Secret) Wipe() { clear(s.Value) }

// ReadAll reads every item of every collection. A locked collection is
// unlocked through the keyring's own prompt (the person sees the keyring's
// usual unlock dialog); one that stays locked is skipped with a warning.
func (c *Client) ReadAll(ctx context.Context) ([]Secret, []string, error) {
	v, err := c.bus.GetProperty(ctx, busName, servicePath, ifService, "Collections")
	if err != nil {
		return nil, nil, err
	}
	var collections []svdbus.ObjectPath
	if err := v.Store(&collections); err != nil {
		return nil, nil, err
	}
	var out []Secret
	var warnings []string
	for _, col := range collections {
		label := string(col)
		if lv, err := c.bus.GetProperty(ctx, busName, col, ifCollection, "Label"); err == nil {
			lv.Store(&label)
		}
		if err := c.unlock(ctx, col); err != nil {
			warnings = append(warnings, fmt.Sprintf("collection %q stayed locked: %v", label, err))
			continue
		}
		iv, err := c.bus.GetProperty(ctx, busName, col, ifCollection, "Items")
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("collection %q: %v", label, err))
			continue
		}
		var items []svdbus.ObjectPath
		if err := iv.Store(&items); err != nil || len(items) == 0 {
			continue
		}
		if err := c.unlock(ctx, items...); err != nil {
			warnings = append(warnings, fmt.Sprintf("items of %q stayed locked: %v", label, err))
			continue
		}
		r, err := c.bus.Call(ctx, busName, servicePath, ifService, "GetSecrets", items, c.session)
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("secrets of %q: %v", label, err))
			continue
		}
		var secrets map[svdbus.ObjectPath]struct {
			Session     svdbus.ObjectPath
			Parameters  []byte
			Value       []byte
			ContentType string
		}
		if err := r.Decode(&secrets); err != nil {
			return nil, nil, err
		}
		for _, item := range items {
			sec, ok := secrets[item]
			if !ok {
				warnings = append(warnings, fmt.Sprintf("an item of %q gave no secret", label))
				continue
			}
			value, err := OpenSecret(c.key, sec.Parameters, sec.Value)
			clear(sec.Value)
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("an item of %q did not decrypt", label))
				continue
			}
			s := Secret{Collection: label, Value: value, ContentType: sec.ContentType, Attributes: map[string]string{}}
			all, err := c.bus.GetAllProperties(ctx, busName, item, ifItem)
			if err == nil {
				if v, ok := all["Label"]; ok {
					v.Store(&s.Label)
				}
				if v, ok := all["Attributes"]; ok {
					v.Store(&s.Attributes)
				}
				var t uint64
				if v, ok := all["Created"]; ok && v.Store(&t) == nil {
					s.Created = time.Unix(int64(t), 0)
				}
				if v, ok := all["Modified"]; ok && v.Store(&t) == nil {
					s.Modified = time.Unix(int64(t), 0)
				}
			}
			out = append(out, s)
		}
	}
	return out, warnings, nil
}

// unlock asks the keyring to unlock objects, following its prompt.
func (c *Client) unlock(ctx context.Context, objects ...svdbus.ObjectPath) error {
	r, err := c.bus.Call(ctx, busName, servicePath, ifService, "Unlock", objects)
	if err != nil {
		return err
	}
	var done []svdbus.ObjectPath
	var prompt svdbus.ObjectPath
	if err := r.Decode(&done, &prompt); err != nil {
		return err
	}
	if prompt == noPrompt {
		return nil
	}
	sub, err := c.bus.Subscribe(ctx, svdbus.MatchRule{Type: svdbus.TypeSignal, Path: prompt, Interface: ifPrompt, Member: "Completed"})
	if err != nil {
		return err
	}
	defer sub.Close()
	if _, err := c.bus.Call(ctx, busName, prompt, ifPrompt, "Prompt", ""); err != nil {
		return err
	}
	select {
	case m := <-sub.C:
		var dismissed bool
		var result svdbus.Variant
		if err := m.Decode(&dismissed, &result); err != nil {
			return err
		}
		if dismissed {
			return errors.New("the unlock was dismissed")
		}
		return nil
	case <-ctx.Done():
		c.bus.CallNoReply(busName, prompt, ifPrompt, "Dismiss")
		return ctx.Err()
	}
}
