package svdbus

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// The bus daemon's own name, object and interface.
const (
	BusName      = "org.freedesktop.DBus"
	BusPath      = ObjectPath("/org/freedesktop/DBus")
	BusInterface = "org.freedesktop.DBus"
)

// DefaultCallTimeout is how long a call waits for its reply when its context
// has no deadline, as with the reference implementation.
const DefaultCallTimeout = 25 * time.Second

// Option configures a connection.
type Option func(*options)

type options struct {
	noFDs        bool
	handlerLimit int
	callTimeout  time.Duration
	signalBuffer int
	maxMessage   int
	logger       *slog.Logger
}

func defaultOptions() options {
	return options{
		handlerLimit: 1024,
		callTimeout:  DefaultCallTimeout,
		signalBuffer: 1024,
		maxMessage:   MaxMessageSize,
		logger:       slog.New(slog.DiscardHandler),
	}
}

// WithoutUnixFDs does not ask the bus to pass file descriptors.
func WithoutUnixFDs() Option { return func(o *options) { o.noFDs = true } }

// WithHandlerLimit bounds the method calls served at once (1024 by
// default). Calls beyond it are refused with
// org.freedesktop.DBus.Error.LimitsExceeded rather than queued, so a flood
// of calls cannot stall the connection.
func WithHandlerLimit(n int) Option {
	return func(o *options) { o.handlerLimit = max(n, 1) }
}

// WithCallTimeout sets how long calls wait for a reply when their context
// has no deadline (DefaultCallTimeout by default); zero waits for ever.
func WithCallTimeout(d time.Duration) Option { return func(o *options) { o.callTimeout = max(d, 0) } }

// WithSignalBuffer sets how many signals a subscription holds for a slow
// receiver (1024 by default) before it drops the oldest.
func WithSignalBuffer(n int) Option { return func(o *options) { o.signalBuffer = max(n, 1) } }

// WithMaxMessageSize lowers the largest message accepted from the bus
// (MaxMessageSize by default). Decoded values can take several times the
// space of their encoding, so a daemon may want far less.
func WithMaxMessageSize(n int) Option {
	return func(o *options) { o.maxMessage = min(max(n, 4096), MaxMessageSize) }
}

// WithLogger logs what the connection cannot report to a caller, such as a
// handler that panicked or returned a reply that cannot be encoded.
func WithLogger(l *slog.Logger) Option {
	return func(o *options) {
		if l != nil {
			o.logger = l
		}
	}
}

// Conn is a connection to a message bus. It is safe for concurrent use.
type Conn struct {
	tr   transport
	rd   *msgReader
	opts options
	guid string
	fds  bool

	serial atomic.Uint32
	wmu    sync.Mutex // serialises writes

	mu       sync.Mutex
	name     string
	closed   bool
	err      error
	pending  map[uint32]*pendingCall
	subs     []*Subscription
	names    map[string]struct{}
	watches  map[string]*nameWatch
	objects  map[ObjectPath]*object
	subtrees map[ObjectPath]*Subtree

	watchMu sync.Mutex // serialises starting and stopping name watches

	sem    chan struct{} // bounds the handlers running
	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}
}

// pendingCall is a method call waiting for its reply.
type pendingCall struct {
	dest  string
	hook  func(*Message) // runs on the reader, in stream order, before delivery
	done  chan struct{}
	reply *Message
	err   error
}

// ConnectSession connects to the session bus (see SessionBusAddress).
func ConnectSession(opts ...Option) (*Conn, error) {
	addr, err := SessionBusAddress()
	if err != nil {
		return nil, err
	}
	return Connect(addr, opts...)
}

// ConnectSystem connects to the system bus (see SystemBusAddress).
func ConnectSystem(opts ...Option) (*Conn, error) {
	return Connect(SystemBusAddress(), opts...)
}

// Connect connects to the bus at address, trying each of its alternatives in
// turn, and gives up after DefaultCallTimeout.
func Connect(address string, opts ...Option) (*Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCallTimeout)
	defer cancel()
	return ConnectContext(ctx, address, opts...)
}

// ConnectContext is Connect bounded by ctx instead. It authenticates, sends
// Hello and returns once the bus has given the connection its unique name.
func ConnectContext(ctx context.Context, address string, opts ...Option) (*Conn, error) {
	o := defaultOptions()
	for _, f := range opts {
		f(&o)
	}
	addrs, err := ParseAddresses(address)
	if err != nil {
		return nil, err
	}
	var errs []error
	for _, a := range addrs {
		c, err := connect(ctx, a, o)
		if err == nil {
			return c, nil
		}
		errs = append(errs, fmt.Errorf("svdbus: %s: %w", a, err))
	}
	return nil, errors.Join(errs...)
}

func connect(ctx context.Context, a Address, o options) (*Conn, error) {
	tr, err := dialTransport(ctx, a)
	if err != nil {
		return nil, err
	}
	if dl, ok := ctx.Deadline(); ok {
		_ = tr.setDeadline(dl)
	}
	stop := context.AfterFunc(ctx, func() { _ = tr.setDeadline(time.Unix(1, 0)) })
	rd := newMsgReader(tr, o.maxMessage)
	guid, fds, err := authenticate(tr, rd, authIdentity(), !o.noFDs)
	if err == nil && a.Params["guid"] != "" && !strings.EqualFold(a.Params["guid"], guid) {
		err = fmt.Errorf("%w: the server's GUID %s is not the address's %s", ErrAuth, guid, a.Params["guid"])
	}
	if !stop() && err == nil {
		err = ctx.Err()
	}
	if err != nil {
		_ = tr.close()
		return nil, err
	}
	_ = tr.setDeadline(time.Time{})

	cctx, cancel := context.WithCancel(context.Background())
	c := &Conn{
		tr: tr, rd: rd, opts: o, guid: guid, fds: fds,
		pending:  map[uint32]*pendingCall{},
		names:    map[string]struct{}{},
		watches:  map[string]*nameWatch{},
		objects:  map[ObjectPath]*object{},
		subtrees: map[ObjectPath]*Subtree{},
		sem:      make(chan struct{}, o.handlerLimit),
		ctx:      cctx,
		cancel:   cancel,
		done:     make(chan struct{}),
	}
	go c.readLoop()

	var name string
	reply, err := c.Call(ctx, BusName, BusPath, BusInterface, "Hello")
	if err == nil {
		err = reply.Decode(&name)
	}
	if err == nil {
		err = ValidateBusName(name)
	}
	if err != nil {
		c.Close()
		return nil, err
	}
	c.mu.Lock()
	c.name = name
	c.names[name] = struct{}{}
	c.mu.Unlock()
	return c, nil
}

// UniqueName is the name the bus gave this connection, such as ":1.42".
func (c *Conn) UniqueName() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.name
}

// ServerGUID is the bus's GUID from authentication.
func (c *Conn) ServerGUID() string { return c.guid }

// CanPassFDs reports whether the bus agreed to pass file descriptors.
func (c *Conn) CanPassFDs() bool { return c.fds }

// Names lists the names this connection owns: its unique name and any
// well-known names acquired, following NameAcquired and NameLost.
func (c *Conn) Names() []string {
	c.mu.Lock()
	out := make([]string, 0, len(c.names))
	for n := range c.names {
		out = append(out, n)
	}
	c.mu.Unlock()
	slices.Sort(out)
	return out
}

// Done is closed once the connection has closed, whether by Close or because
// the bus went away.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Err returns nil while the connection is open, and afterwards why it
// closed: ErrClosed after Close, or the error that broke it.
func (c *Conn) Err() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.closed {
		return nil
	}
	return c.err
}

// Close closes the connection. Calls waiting for replies fail with
// ErrClosed, subscriptions' channels close, and handlers' contexts are
// cancelled. It is safe to call more than once.
func (c *Conn) Close() error {
	c.shutdown(ErrClosed)
	<-c.done
	return nil
}

func closedErr(cause error) error {
	if errors.Is(cause, ErrClosed) {
		return cause
	}
	return fmt.Errorf("%w: %w", ErrClosed, cause)
}

func (c *Conn) shutdown(cause error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	c.closed = true
	c.err = closedErr(cause)
	pending, subs := c.pending, c.subs
	c.pending, c.subs = nil, nil
	c.mu.Unlock()

	c.cancel()
	_ = c.tr.close()
	for _, pc := range pending {
		pc.err = c.err
		close(pc.done)
	}
	for _, s := range subs {
		s.stop()
	}
}

func (c *Conn) readLoop() {
	defer close(c.done)
	for {
		m, err := c.rd.next()
		if err != nil {
			c.shutdown(err)
			c.rd.closeQueued()
			return
		}
		switch m.Type {
		case TypeMethodReturn, TypeError:
			c.dispatchReply(m)
		case TypeSignal:
			c.dispatchSignal(m)
		case TypeMethodCall:
			c.dispatchCall(m)
		default:
			m.CloseFDs() // unknown types are ignored, as the specification says
		}
	}
}

func (c *Conn) nextSerial() uint32 {
	for {
		if s := c.serial.Add(1); s != 0 {
			return s
		}
	}
}

// send writes m with a fresh serial, first registering pc for its reply.
func (c *Conn) send(m *Message, pc *pendingCall) error {
	m.Serial = c.nextSerial()
	data, fds, err := m.Marshal()
	if err != nil {
		return err
	}
	if len(fds) > 0 && !c.fds {
		err = fmt.Errorf("%w: the bus did not agree to pass file descriptors", ErrUnsupported)
	}
	c.mu.Lock()
	if err == nil && c.closed {
		err = c.err
	}
	if err != nil {
		c.mu.Unlock()
		if m.handOver {
			for _, fd := range fds {
				closeFD(fd)
			}
		}
		return err
	}
	if pc != nil {
		c.pending[m.Serial] = pc
	}
	c.mu.Unlock()

	c.wmu.Lock()
	err = c.tr.write(data, fds)
	c.wmu.Unlock()
	if m.handOver {
		for _, fd := range fds {
			closeFD(fd)
		}
	}
	if err != nil {
		// Part of a message may have gone; the stream is unusable.
		c.shutdown(err)
		return closedErr(err)
	}
	return nil
}

// forget drops a pending call, reporting whether it was still waiting.
func (c *Conn) forget(serial uint32) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := c.pending[serial]; ok {
		delete(c.pending, serial)
		return true
	}
	return false
}

// Send sends m. A method call that expects a reply waits for it, bounded by
// ctx (or the call timeout when ctx has no deadline), and returns it; an
// error reply is returned as a *Error. Anything else returns once written.
// Send sets m.Serial.
func (c *Conn) Send(ctx context.Context, m *Message) (*Message, error) {
	if m.Type != TypeMethodCall || m.Flags&FlagNoReplyExpected != 0 {
		return nil, c.send(m, nil)
	}
	return c.roundTrip(ctx, m, nil)
}

func (c *Conn) roundTrip(ctx context.Context, m *Message, hook func(*Message)) (*Message, error) {
	if _, ok := ctx.Deadline(); !ok && c.opts.callTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, c.opts.callTimeout)
		defer cancel()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	pc := &pendingCall{dest: m.Destination, hook: hook, done: make(chan struct{})}
	if err := c.send(m, pc); err != nil {
		c.forget(m.Serial)
		return nil, err
	}
	select {
	case <-pc.done:
	case <-ctx.Done():
		if c.forget(m.Serial) {
			return nil, fmt.Errorf("svdbus: %s.%s: %w", m.Interface, m.Member, ctx.Err())
		}
		<-pc.done // the reply was already on its way: take it
	}
	if pc.err != nil {
		return nil, pc.err
	}
	r := pc.reply
	if r.bodyErr != nil {
		return nil, r.bodyErr
	}
	if r.Type == TypeError {
		r.CloseFDs()
		return nil, r.Err()
	}
	return r, nil
}

// Call calls a method and waits for its reply. The arguments' signature is
// inferred from their Go types; to give one, build the message with
// NewMethodCall, set Signature, and use Send.
func (c *Conn) Call(ctx context.Context, dest string, path ObjectPath, iface, member string, args ...any) (*Message, error) {
	return c.Send(ctx, NewMethodCall(dest, path, iface, member, args...))
}

// CallNoReply calls a method without waiting, and asks the callee not to
// reply at all.
func (c *Conn) CallNoReply(dest string, path ObjectPath, iface, member string, args ...any) error {
	m := NewMethodCall(dest, path, iface, member, args...)
	m.Flags |= FlagNoReplyExpected
	return c.send(m, nil)
}

// replyFrom reports whether a reply's sender can be the peer a call went to.
// Replies from a well-known name come from its owner's unique name, which is
// not tracked; the bus itself only routes replies that were expected.
func replyFrom(dest, sender string) bool {
	if dest == "" || !isUniqueName(dest) && dest != BusName {
		return true
	}
	return dest == sender
}

func (c *Conn) dispatchReply(m *Message) {
	c.mu.Lock()
	pc := c.pending[m.ReplySerial]
	if pc != nil && !replyFrom(pc.dest, m.Sender) {
		pc = nil
	}
	if pc != nil {
		delete(c.pending, m.ReplySerial)
	}
	c.mu.Unlock()
	if pc == nil {
		m.CloseFDs()
		return
	}
	if pc.hook != nil && m.bodyErr == nil {
		pc.hook(m)
	}
	pc.reply = m
	close(pc.done)
}

func (c *Conn) dispatchSignal(m *Message) {
	if m.bodyErr != nil {
		return
	}
	if m.Sender == BusName && m.Path == BusPath && m.Interface == BusInterface {
		c.busSignal(m)
	}
	c.mu.Lock()
	var targets []*Subscription
	for _, s := range c.subs {
		if c.matchLocked(&s.rule, m) {
			targets = append(targets, s)
		}
	}
	c.mu.Unlock()
	if len(targets) == 0 {
		m.CloseFDs()
		return
	}
	for i, s := range targets {
		msg := m
		if i < len(targets)-1 && m.raw != nil {
			// Every subscriber owns its descriptors, so each but the last
			// gets duplicates.
			var err error
			if msg, err = m.withOwnFDs(); err != nil {
				c.opts.logger.Error("svdbus: cannot duplicate a signal's descriptors", "signal", m.String(), "err", err)
				continue
			}
		}
		s.enqueue(msg)
	}
}

// busSignal follows the bus's signals about names.
func (c *Conn) busSignal(m *Message) {
	switch m.Member {
	case "NameAcquired", "NameLost":
		if m.Signature != "s" {
			return
		}
		name := m.Body[0].(string)
		c.mu.Lock()
		if m.Member == "NameAcquired" {
			c.names[name] = struct{}{}
		} else {
			delete(c.names, name)
		}
		c.mu.Unlock()
	case "NameOwnerChanged":
		if m.Signature != "sss" {
			return
		}
		c.mu.Lock()
		if w := c.watches[m.Body[0].(string)]; w != nil {
			w.owner = m.Body[2].(string)
		}
		c.mu.Unlock()
	}
}

// withOwnFDs returns a copy of a received signal with duplicated
// descriptors, decoded afresh so its body refers to them.
func (m *Message) withOwnFDs() (*Message, error) {
	fds := make([]UnixFD, len(m.fds))
	for i, fd := range m.fds {
		fds[i] = -1
		if fd < 0 {
			continue
		}
		n, err := dupFD(fd)
		if err != nil {
			for _, d := range fds[:i] {
				closeFD(d)
			}
			return nil, err
		}
		fds[i] = n
	}
	cp := *m
	cp.fds = fds
	types, err := parseSignature(string(m.Signature))
	if err == nil {
		d := &decoder{buf: m.raw, order: m.order}
		d.setFDs(fds)
		cp.Body, err = d.body(types)
	}
	if err != nil {
		cp.CloseFDs()
		return nil, err
	}
	return &cp, nil
}
