package svdbus

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"strings"
)

// Interface describes one interface of an exported object: its methods,
// properties and signals. The description drives dispatch, argument
// checking, reply encoding and introspection alike.
type Interface struct {
	Name        string
	Methods     []*Method
	Properties  []*Property
	Signals     []*Signal
	Annotations []Annotation
}

// Method is one method of an Interface.
type Method struct {
	Name string

	// In and Out are the arguments and results. A call whose signature is
	// not exactly In's is refused with InvalidArgs before the handler runs;
	// the handler's results are encoded as Out.
	In, Out []Arg

	Handler     MethodHandler
	Annotations []Annotation
}

// MethodHandler serves a method call. It returns the reply's values (as many
// as the method's Out), or an error: a *Error goes back to the caller as it
// is, and any other error as org.freedesktop.DBus.Error.Failed carrying the
// error's text. ctx is cancelled when the connection closes.
//
// Handlers run concurrently, each on its own goroutine, and may make calls
// on the same connection. Descriptors among the arguments belong to the
// handler, which must close them. Descriptors among the results are handed
// over: the connection closes them once the reply is written (return a
// duplicate to keep one).
type MethodHandler func(ctx context.Context, call *Call) ([]any, error)

// Arg is one argument of a method or signal.
type Arg struct {
	Name string
	Type Signature // one complete type
}

// Signal is one signal of an Interface, for introspection and for encoding
// Emit's arguments.
type Signal struct {
	Name        string
	Args        []Arg
	Annotations []Annotation
}

// Property is one property of an Interface, served through
// org.freedesktop.DBus.Properties. It is readable when Get is set and
// writable when Set is.
type Property struct {
	Name string
	Type Signature // one complete type

	// Get returns the value, as a Go value that encodes as Type.
	Get func(ctx context.Context, call *Call) (any, error)

	// Set changes the value; value's signature has been checked to be Type.
	Set func(ctx context.Context, call *Call, value Variant) error

	// EmitsChanged says what PropertiesChanged carries when the value
	// changes, including after a successful Set, which emits it on its own.
	EmitsChanged EmitsChanged

	Annotations []Annotation
}

// EmitsChanged is the org.freedesktop.DBus.Property.EmitsChangedSignal
// annotation.
type EmitsChanged uint8

const (
	EmitsChangedTrue        EmitsChanged = iota // PropertiesChanged carries the new value
	EmitsChangedInvalidates                     // PropertiesChanged names it as invalidated
	EmitsChangedConst                           // the value never changes
	EmitsChangedFalse                           // changes are not signalled
)

func (e EmitsChanged) String() string {
	switch e {
	case EmitsChangedTrue:
		return "true"
	case EmitsChangedInvalidates:
		return "invalidates"
	case EmitsChangedConst:
		return "const"
	}
	return "false"
}

// Annotation is a name and value attached to an interface or member in
// introspection data, such as org.freedesktop.DBus.Deprecated=true.
type Annotation struct {
	Name, Value string
}

// Call is a method call being served.
type Call struct {
	Conn    *Conn
	Message *Message
}

// Sender is the caller's unique name: pass it to GetConnectionCredentials
// to learn who is calling.
func (c *Call) Sender() string { return c.Message.Sender }

// Path is the object path called.
func (c *Call) Path() ObjectPath { return c.Message.Path }

// Args are the call's arguments, decoded generically.
func (c *Call) Args() []any { return c.Message.Body }

// Decode stores the arguments into dst, one pointer per argument (see
// Store).
func (c *Call) Decode(dst ...any) error { return c.Message.Decode(dst...) }

// Subtree serves every object under a path prefix, for objects that come and
// go, such as a Secret Service's collections and items.
type Subtree struct {
	// Lookup returns the interfaces of the object at path (the prefix itself
	// or anything below it), or nil when there is none. It is called for
	// every call and must be safe for concurrent use.
	Lookup func(path ObjectPath) []*Interface

	// Children lists the names of path's direct child nodes, for
	// introspection. It may be nil.
	Children func(path ObjectPath) []string
}

// object is a statically exported path.
type object struct {
	ifaces []*Interface
}

const (
	peerInterface           = "org.freedesktop.DBus.Peer"
	introspectableInterface = "org.freedesktop.DBus.Introspectable"
	propertiesInterface     = "org.freedesktop.DBus.Properties"
)

func isStandardInterface(name string) bool {
	return name == peerInterface || name == introspectableInterface || name == propertiesInterface
}

// validate checks an interface description.
func (i *Interface) validate() error {
	if i == nil {
		return invalidf("nil interface")
	}
	if err := ValidateInterfaceName(i.Name); err != nil {
		return err
	}
	if isStandardInterface(i.Name) {
		return invalidf("%s is provided by the connection", i.Name)
	}
	seen := map[string]bool{}
	for _, m := range i.Methods {
		if m == nil || m.Handler == nil {
			return invalidf("%s has a method without a handler", i.Name)
		}
		if err := ValidateMemberName(m.Name); err != nil {
			return err
		}
		if seen[m.Name] {
			return invalidf("%s declares %s twice", i.Name, m.Name)
		}
		seen[m.Name] = true
		if err := validateArgs(m.In); err != nil {
			return fmt.Errorf("%s.%s: %w", i.Name, m.Name, err)
		}
		if err := validateArgs(m.Out); err != nil {
			return fmt.Errorf("%s.%s: %w", i.Name, m.Name, err)
		}
	}
	seen = map[string]bool{}
	for _, s := range i.Signals {
		if s == nil {
			return invalidf("%s has a nil signal", i.Name)
		}
		if err := ValidateMemberName(s.Name); err != nil {
			return err
		}
		if seen[s.Name] {
			return invalidf("%s declares the signal %s twice", i.Name, s.Name)
		}
		seen[s.Name] = true
		if err := validateArgs(s.Args); err != nil {
			return fmt.Errorf("%s.%s: %w", i.Name, s.Name, err)
		}
	}
	seen = map[string]bool{}
	for _, p := range i.Properties {
		if p == nil || p.Get == nil && p.Set == nil {
			return invalidf("%s has a property that can be neither read nor written", i.Name)
		}
		if err := ValidateMemberName(p.Name); err != nil {
			return err
		}
		if seen[p.Name] {
			return invalidf("%s declares the property %s twice", i.Name, p.Name)
		}
		seen[p.Name] = true
		if _, err := parseSingle(string(p.Type)); err != nil {
			return fmt.Errorf("%s.%s: %w", i.Name, p.Name, err)
		}
	}
	return nil
}

func validateArgs(args []Arg) error {
	for _, a := range args {
		if _, err := parseSingle(string(a.Type)); err != nil {
			return err
		}
	}
	if _, err := parseSignature(string(argsSignature(args))); err != nil {
		return err
	}
	return nil
}

func argsSignature(args []Arg) Signature {
	var b strings.Builder
	for _, a := range args {
		b.WriteString(string(a.Type))
	}
	return Signature(b.String())
}

// Export serves interfaces at path, adding them to any already there (an
// interface of the same name is replaced). Peer, Introspectable and
// Properties are provided on every object. An exported Interface is read
// concurrently from then on and must not be changed; export a new one
// instead.
func (c *Conn) Export(path ObjectPath, ifaces ...*Interface) error {
	if err := path.Validate(); err != nil {
		return err
	}
	for i, iface := range ifaces {
		if err := iface.validate(); err != nil {
			return err
		}
		for _, other := range ifaces[:i] {
			if other.Name == iface.Name {
				return invalidf("%s given twice", iface.Name)
			}
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	o := c.objects[path]
	if o == nil {
		o = &object{}
		c.objects[path] = o
	}
	for _, iface := range ifaces {
		if i := slices.IndexFunc(o.ifaces, func(x *Interface) bool { return x.Name == iface.Name }); i >= 0 {
			o.ifaces[i] = iface
		} else {
			o.ifaces = append(o.ifaces, iface)
		}
	}
	return nil
}

// Unexport stops serving the named interfaces at path, or the whole object
// when no names are given.
func (c *Conn) Unexport(path ObjectPath, names ...string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	o := c.objects[path]
	if o == nil {
		return
	}
	if len(names) > 0 {
		o.ifaces = slices.DeleteFunc(o.ifaces, func(x *Interface) bool { return slices.Contains(names, x.Name) })
	}
	if len(names) == 0 || len(o.ifaces) == 0 {
		delete(c.objects, path)
	}
}

// ExportSubtree serves every object at and below prefix through st, for
// paths with no statically exported object. Where subtrees nest, the
// deepest whose Lookup finds an object serves it.
func (c *Conn) ExportSubtree(prefix ObjectPath, st Subtree) error {
	if err := prefix.Validate(); err != nil {
		return err
	}
	if st.Lookup == nil {
		return invalidf("subtree %s without a Lookup", prefix)
	}
	c.mu.Lock()
	c.subtrees[prefix] = &st
	c.mu.Unlock()
	return nil
}

// UnexportSubtree stops serving the subtree at prefix.
func (c *Conn) UnexportSubtree(prefix ObjectPath) {
	c.mu.Lock()
	delete(c.subtrees, prefix)
	c.mu.Unlock()
}

// under reports whether path is prefix or below it.
func under(path, prefix ObjectPath) bool {
	return prefix == "/" || path == prefix || strings.HasPrefix(string(path), string(prefix)+"/")
}

// lookup finds the interfaces of the object at path: a static export, or
// else the deepest subtree whose Lookup knows the path.
func (c *Conn) lookup(path ObjectPath) []*Interface {
	c.mu.Lock()
	if o := c.objects[path]; o != nil {
		ifaces := slices.Clone(o.ifaces)
		c.mu.Unlock()
		return ifaces
	}
	type candidate struct {
		prefix ObjectPath
		st     *Subtree
	}
	var cands []candidate
	for prefix, st := range c.subtrees {
		if under(path, prefix) {
			cands = append(cands, candidate{prefix, st})
		}
	}
	c.mu.Unlock()
	slices.SortFunc(cands, func(a, b candidate) int { return len(b.prefix) - len(a.prefix) })
	for _, cand := range cands {
		if ifaces := cand.st.Lookup(path); len(ifaces) > 0 {
			var valid []*Interface
			for _, i := range ifaces {
				if err := i.validate(); err != nil {
					c.opts.logger.Error("svdbus: subtree returned an invalid interface", "path", path, "err", err)
					continue
				}
				valid = append(valid, i)
			}
			return valid
		}
	}
	return nil
}

// children lists the names of path's direct child nodes: from static
// exports and subtree prefixes below it, and from the Children of subtrees
// that contain it.
func (c *Conn) children(path ObjectPath) []string {
	set := map[string]struct{}{}
	add := func(p ObjectPath) {
		if name, ok := childOf(path, p); ok {
			set[name] = struct{}{}
		}
	}
	var lists []func(ObjectPath) []string
	c.mu.Lock()
	for p := range c.objects {
		add(p)
	}
	for p, st := range c.subtrees {
		add(p)
		if under(path, p) && st.Children != nil {
			lists = append(lists, st.Children)
		}
	}
	c.mu.Unlock()
	for _, list := range lists {
		for _, name := range list(path) {
			if name != "" && validateObjectPath("/"+name) == nil && !strings.Contains(name, "/") {
				set[name] = struct{}{}
			}
		}
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	slices.Sort(out)
	return out
}

// childOf returns the first element of p below parent.
func childOf(parent, p ObjectPath) (string, bool) {
	var rest string
	switch {
	case parent == "/":
		if p == "/" {
			return "", false
		}
		rest = string(p[1:])
	case strings.HasPrefix(string(p), string(parent)+"/"):
		rest = string(p[len(parent)+1:])
	default:
		return "", false
	}
	name, _, _ := strings.Cut(rest, "/")
	return name, true
}

// dispatchCall runs on the reader: it hands the call to a handler goroutine,
// or refuses it when too many are running.
func (c *Conn) dispatchCall(m *Message) {
	if m.bodyErr != nil {
		c.replyError(m, ErrorInvalidArgs, m.bodyErr.Error())
		return
	}
	select {
	case c.sem <- struct{}{}:
		go func() {
			defer func() { <-c.sem }()
			c.serve(m)
		}()
	default:
		m.CloseFDs()
		c.replyError(m, ErrorLimitsExceeded, "too many calls in progress")
	}
}

func (c *Conn) replyError(call *Message, name, text string) {
	if call.Flags&FlagNoReplyExpected != 0 {
		return
	}
	_ = c.send(NewErrorReply(call, name, text), nil)
}

func (c *Conn) serve(m *Message) {
	reply := c.handle(m)
	if m.Flags&FlagNoReplyExpected != 0 || reply == nil {
		return
	}
	err := c.send(reply, nil)
	if err != nil && !errors.Is(err, ErrClosed) {
		c.opts.logger.Error("svdbus: cannot send a reply", "call", m.String(), "err", err)
		c.replyError(m, ErrorFailed, "the reply could not be encoded")
	}
}

// handle finds and runs the method a call is for, and returns its reply.
func (c *Conn) handle(m *Message) *Message {
	user := c.lookup(m.Path)
	exists := len(user) > 0
	hasChildren := !exists && len(c.children(m.Path)) > 0
	ifaces := append(user, peerIface)
	if exists || hasChildren {
		ifaces = append(ifaces, c.introspectable(m.Path, &ifaces))
	}
	if exists {
		ifaces = append(ifaces, c.properties(m.Path, user))
	}

	iface, method := findMethod(ifaces, m.Interface, m.Member)
	if method == nil {
		m.CloseFDs()
		switch {
		case !exists && !hasChildren && m.Interface != peerInterface:
			return NewErrorReply(m, ErrorUnknownObject, fmt.Sprintf("No such object path '%s'", m.Path))
		case m.Interface != "" && iface == nil:
			return NewErrorReply(m, ErrorUnknownInterface,
				fmt.Sprintf("No such interface '%s' at object path '%s'", m.Interface, m.Path))
		}
		return NewErrorReply(m, ErrorUnknownMethod,
			fmt.Sprintf("No such method '%s' in interface '%s' at object path '%s' (signature '%s')",
				m.Member, m.Interface, m.Path, m.Signature))
	}
	if want := argsSignature(method.In); m.Signature != want {
		m.CloseFDs()
		return NewErrorReply(m, ErrorInvalidArgs,
			fmt.Sprintf("%s.%s takes arguments of signature '%s', not '%s'", iface.Name, method.Name, want, m.Signature))
	}
	out, err := c.invoke(method.Handler, &Call{Conn: c, Message: m})
	if err != nil {
		return errorReply(m, err)
	}
	r := NewMethodReturn(m, out...)
	r.Signature = argsSignature(method.Out)
	r.handOver = true
	return r
}

// findMethod finds a method by interface and name; with no interface named,
// the first method of that name in any interface.
func findMethod(ifaces []*Interface, ifaceName, member string) (*Interface, *Method) {
	var found *Interface
	for _, i := range ifaces {
		if ifaceName != "" && i.Name != ifaceName {
			continue
		}
		found = i
		for _, m := range i.Methods {
			if m.Name == member {
				return i, m
			}
		}
	}
	if ifaceName == "" {
		return nil, nil
	}
	return found, nil
}

func (c *Conn) invoke(h MethodHandler, call *Call) (out []any, err error) {
	defer func() {
		if p := recover(); p != nil {
			c.opts.logger.Error("svdbus: method handler panicked", "call", call.Message.String(),
				"panic", fmt.Sprint(p), "stack", string(debug.Stack()))
			out, err = nil, NewError(ErrorFailed, "internal error")
		}
	}()
	return h(c.ctx, call)
}

func errorReply(call *Message, err error) *Message {
	var de *Error
	if errors.As(err, &de) {
		return NewErrorReply(call, de.Name, de.Body...)
	}
	return NewErrorReply(call, ErrorFailed, err.Error())
}

// Emit broadcasts a signal. When the interface is exported at path and
// declares the signal, its arguments are encoded by the declared types;
// otherwise their types are inferred.
func (c *Conn) Emit(path ObjectPath, iface, member string, args ...any) error {
	return c.EmitTo("", path, iface, member, args...)
}

// EmitTo sends a signal to one connection only, or broadcasts it when dest
// is empty.
func (c *Conn) EmitTo(dest string, path ObjectPath, iface, member string, args ...any) error {
	m := NewSignal(path, iface, member, args...)
	m.Destination = dest
	for _, i := range c.lookup(path) {
		if i.Name != iface {
			continue
		}
		for _, s := range i.Signals {
			if s.Name == member {
				m.Signature = argsSignature(s.Args)
			}
		}
	}
	return c.send(m, nil)
}
