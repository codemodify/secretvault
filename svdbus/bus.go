package svdbus

import (
	"context"
	"fmt"
)

// Methods of the bus daemon itself (org.freedesktop.DBus).

func (c *Conn) busCall(ctx context.Context, member string, args ...any) (*Message, error) {
	return c.Call(ctx, BusName, BusPath, BusInterface, member, args...)
}

// AddMatch asks the bus to route the messages rule matches to this
// connection. Subscribe does this itself; AddMatch is for rules managed by
// hand.
func (c *Conn) AddMatch(ctx context.Context, rule MatchRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}
	_, err := c.busCall(ctx, "AddMatch", rule.String())
	return err
}

// RemoveMatch removes one instance of a rule added with AddMatch.
func (c *Conn) RemoveMatch(ctx context.Context, rule MatchRule) error {
	if err := rule.Validate(); err != nil {
		return err
	}
	_, err := c.busCall(ctx, "RemoveMatch", rule.String())
	return err
}

// RequestNameFlags are RequestName's flags.
type RequestNameFlags uint32

const (
	// NameAllowReplacement lets a later request with NameReplaceExisting
	// take the name away.
	NameAllowReplacement RequestNameFlags = 0x1

	// NameReplaceExisting takes the name from an owner that allowed it.
	NameReplaceExisting RequestNameFlags = 0x2

	// NameDoNotQueue fails at once instead of queueing for the name.
	NameDoNotQueue RequestNameFlags = 0x4
)

// RequestNameReply is RequestName's result.
type RequestNameReply uint32

const (
	RequestNamePrimaryOwner RequestNameReply = 1 // the name is ours
	RequestNameInQueue      RequestNameReply = 2 // queued behind the owner
	RequestNameExists       RequestNameReply = 3 // owned, and NameDoNotQueue was given
	RequestNameAlreadyOwner RequestNameReply = 4 // it was already ours
)

func (r RequestNameReply) String() string {
	switch r {
	case RequestNamePrimaryOwner:
		return "primary owner"
	case RequestNameInQueue:
		return "in queue"
	case RequestNameExists:
		return "exists"
	case RequestNameAlreadyOwner:
		return "already owner"
	}
	return fmt.Sprintf("RequestNameReply(%d)", uint32(r))
}

// ReleaseNameReply is ReleaseName's result.
type ReleaseNameReply uint32

const (
	ReleaseNameReleased    ReleaseNameReply = 1 // released, or left the queue
	ReleaseNameNonExistent ReleaseNameReply = 2 // nobody owns the name
	ReleaseNameNotOwner    ReleaseNameReply = 3 // someone else owns it
)

// RequestName asks the bus for a well-known name. When the name is taken
// from us later, the bus sends NameLost (subscribe to it with a rule on
// sender org.freedesktop.DBus, member NameLost) and Names stops listing it.
func (c *Conn) RequestName(ctx context.Context, name string, flags RequestNameFlags) (RequestNameReply, error) {
	if err := ValidateBusName(name); err != nil || isUniqueName(name) {
		return 0, invalidf("cannot request the name %.80q", name)
	}
	m := NewMethodCall(BusName, BusPath, BusInterface, "RequestName", name, uint32(flags))
	r, err := c.roundTrip(ctx, m, func(r *Message) {
		if r.Type == TypeMethodReturn && r.Signature == "u" {
			if code := RequestNameReply(r.Body[0].(uint32)); code == RequestNamePrimaryOwner || code == RequestNameAlreadyOwner {
				c.mu.Lock()
				c.names[name] = struct{}{}
				c.mu.Unlock()
			}
		}
	})
	if err != nil {
		return 0, err
	}
	var code uint32
	if err := r.Decode(&code); err != nil {
		return 0, err
	}
	return RequestNameReply(code), nil
}

// ReleaseName gives up a well-known name, or leaves its queue.
func (c *Conn) ReleaseName(ctx context.Context, name string) (ReleaseNameReply, error) {
	if err := ValidateBusName(name); err != nil || isUniqueName(name) {
		return 0, invalidf("cannot release the name %.80q", name)
	}
	m := NewMethodCall(BusName, BusPath, BusInterface, "ReleaseName", name)
	r, err := c.roundTrip(ctx, m, func(r *Message) {
		if r.Type == TypeMethodReturn && r.Signature == "u" && ReleaseNameReply(r.Body[0].(uint32)) == ReleaseNameReleased {
			c.mu.Lock()
			delete(c.names, name)
			c.mu.Unlock()
		}
	})
	if err != nil {
		return 0, err
	}
	var code uint32
	if err := r.Decode(&code); err != nil {
		return 0, err
	}
	return ReleaseNameReply(code), nil
}

// GetNameOwner returns the unique name that owns name. A name nobody owns is
// a *Error named ErrorNameHasNoOwner.
func (c *Conn) GetNameOwner(ctx context.Context, name string) (string, error) {
	r, err := c.busCall(ctx, "GetNameOwner", name)
	if err != nil {
		return "", err
	}
	var owner string
	return owner, r.Decode(&owner)
}

// NameHasOwner reports whether anyone owns name.
func (c *Conn) NameHasOwner(ctx context.Context, name string) (bool, error) {
	r, err := c.busCall(ctx, "NameHasOwner", name)
	if err != nil {
		return false, err
	}
	var has bool
	return has, r.Decode(&has)
}

// ListNames lists every name on the bus, unique and well-known.
func (c *Conn) ListNames(ctx context.Context) ([]string, error) {
	r, err := c.busCall(ctx, "ListNames")
	if err != nil {
		return nil, err
	}
	var names []string
	return names, r.Decode(&names)
}

// Credentials are what the bus knows about the process behind a connection,
// from GetConnectionCredentials. The bus reads them from the socket when
// the peer connects, so the peer cannot lie about them.
type Credentials struct {
	// UnixUserID is the peer's uid, or -1 when the bus did not say.
	UnixUserID int64

	// UnixGroupIDs are the peer's groups, when the bus says.
	UnixGroupIDs []uint32

	// ProcessID is the peer's pid, or 0 when the bus did not say. A pid can
	// be reused once the process exits; prefer ProcessFD where there is one.
	ProcessID uint32

	// ProcessFD is a pidfd for the peer's process (Linux, recent buses), or
	// -1. It keeps naming the same process even after it exits. The caller
	// owns it: see Close.
	ProcessFD UnixFD

	// SecurityLabel is the peer's LSM label (SELinux, AppArmor, Smack) as
	// the bus reports it, NUL included.
	SecurityLabel []byte

	// WindowsSID is the peer's security identifier on Windows buses.
	WindowsSID string

	// Extra holds any other credentials the bus reports.
	Extra map[string]Variant
}

// Close closes ProcessFD, if there is one.
func (cr *Credentials) Close() {
	if cr.ProcessFD >= 0 {
		closeFD(cr.ProcessFD)
		cr.ProcessFD = -1
	}
}

// GetConnectionCredentials asks the bus who is behind a connection, given
// its unique or well-known name: typically the sender of a call being
// served.
func (c *Conn) GetConnectionCredentials(ctx context.Context, name string) (*Credentials, error) {
	r, err := c.busCall(ctx, "GetConnectionCredentials", name)
	if err != nil {
		return nil, err
	}
	var raw map[string]Variant
	if err := r.Decode(&raw); err != nil {
		r.CloseFDs()
		return nil, err
	}
	cr := &Credentials{UnixUserID: -1, ProcessFD: -1, Extra: map[string]Variant{}}
	for k, v := range raw {
		ok := true
		switch k {
		case "UnixUserID":
			var u uint32
			if ok = v.Store(&u) == nil; ok {
				cr.UnixUserID = int64(u)
			}
		case "UnixGroupIDs":
			ok = v.Store(&cr.UnixGroupIDs) == nil
		case "ProcessID":
			ok = v.Store(&cr.ProcessID) == nil
		case "ProcessFD":
			cr.ProcessFD, ok = v.Value.(UnixFD)
			if !ok {
				cr.ProcessFD = -1
			}
		case "LinuxSecurityLabel":
			ok = v.Store(&cr.SecurityLabel) == nil
		case "WindowsSID":
			ok = v.Store(&cr.WindowsSID) == nil
		default:
			cr.Extra[k] = v
		}
		if !ok {
			cr.Extra[k] = v
		}
	}
	// Any other descriptor the reply carried is of no use to anyone.
	for _, fd := range r.FDs() {
		if fd != cr.ProcessFD {
			closeFD(fd)
		}
	}
	return cr, nil
}

// GetConnectionUnixProcessID asks the bus for the pid behind a connection.
func (c *Conn) GetConnectionUnixProcessID(ctx context.Context, name string) (uint32, error) {
	r, err := c.busCall(ctx, "GetConnectionUnixProcessID", name)
	if err != nil {
		return 0, err
	}
	var pid uint32
	return pid, r.Decode(&pid)
}

// GetConnectionUnixUser asks the bus for the uid behind a connection.
func (c *Conn) GetConnectionUnixUser(ctx context.Context, name string) (uint32, error) {
	r, err := c.busCall(ctx, "GetConnectionUnixUser", name)
	if err != nil {
		return 0, err
	}
	var uid uint32
	return uid, r.Decode(&uid)
}
