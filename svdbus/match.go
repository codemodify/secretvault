package svdbus

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"
)

// MatchRule selects messages, both at the bus (AddMatch) and locally, to
// route signals to subscriptions. Empty fields match anything.
type MatchRule struct {
	Type          MessageType // zero matches every type
	Sender        string      // a unique or well-known name
	Interface     string
	Member        string
	Path          ObjectPath
	PathNamespace ObjectPath     // the path or anything below it
	Destination   string         // a unique name
	Args          map[int]string // argN: the Nth argument is this string
	ArgPaths      map[int]string // argNpath: path-prefix match on a string or object path argument
	Arg0Namespace string         // the first argument is this name or below it
}

// Validate checks the rule against the specification.
func (r MatchRule) Validate() error {
	if r.Type > TypeSignal {
		return invalidf("match rule type %d", r.Type)
	}
	if r.Sender != "" {
		if err := ValidateBusName(r.Sender); err != nil {
			return err
		}
	}
	if r.Interface != "" {
		if err := ValidateInterfaceName(r.Interface); err != nil {
			return err
		}
	}
	if r.Member != "" {
		if err := ValidateMemberName(r.Member); err != nil {
			return err
		}
	}
	if r.Path != "" && r.PathNamespace != "" {
		return invalidf("match rule has both path and path_namespace")
	}
	if r.Path != "" {
		if err := r.Path.Validate(); err != nil {
			return err
		}
	}
	if r.PathNamespace != "" {
		if err := r.PathNamespace.Validate(); err != nil {
			return err
		}
	}
	if r.Destination != "" {
		if err := ValidateBusName(r.Destination); err != nil || !isUniqueName(r.Destination) {
			return invalidf("match rule destination %.80q is not a unique name", r.Destination)
		}
	}
	for _, args := range []map[int]string{r.Args, r.ArgPaths} {
		for n, v := range args {
			if n < 0 || n > 63 {
				return invalidf("match rule argument %d is not 0 to 63", n)
			}
			if !utf8.ValidString(v) || strings.IndexByte(v, 0) >= 0 {
				return invalidf("match rule argument %d is not UTF-8 without NUL bytes", n)
			}
		}
	}
	if r.Arg0Namespace != "" && !dottedName(r.Arg0Namespace, false, true) && !dottedName(r.Arg0Namespace+".x", false, true) {
		return invalidf("match rule arg0namespace %.80q", r.Arg0Namespace)
	}
	return nil
}

// String formats the rule as the bus reads it, for example
// type='signal',interface='org.freedesktop.login1.Manager',member='PrepareForSleep'.
func (r MatchRule) String() string {
	var parts []string
	add := func(k, v string) {
		if v != "" {
			parts = append(parts, k+"="+quoteMatchValue(v))
		}
	}
	if r.Type != 0 {
		add("type", r.Type.String())
	}
	add("sender", r.Sender)
	add("interface", r.Interface)
	add("member", r.Member)
	add("path", string(r.Path))
	add("path_namespace", string(r.PathNamespace))
	add("destination", r.Destination)
	for _, n := range sortedKeys(r.Args) {
		parts = append(parts, fmt.Sprintf("arg%d=%s", n, quoteMatchValue(r.Args[n])))
	}
	for _, n := range sortedKeys(r.ArgPaths) {
		parts = append(parts, fmt.Sprintf("arg%dpath=%s", n, quoteMatchValue(r.ArgPaths[n])))
	}
	add("arg0namespace", r.Arg0Namespace)
	return strings.Join(parts, ",")
}

func sortedKeys(m map[int]string) []int {
	keys := make([]int, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}

// quoteMatchValue quotes a value the way match rules do: inside single
// quotes, where an apostrophe cannot appear, so each one closes the quotes,
// is written as a backslash and an apostrophe, and opens them again.
func quoteMatchValue(v string) string {
	return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'"
}

// matches applies the rule to m, except for the sender, which needs the
// connection to resolve well-known names.
func (r *MatchRule) matches(m *Message) bool {
	if r.Type != 0 && m.Type != r.Type {
		return false
	}
	if r.Interface != "" && m.Interface != r.Interface ||
		r.Member != "" && m.Member != r.Member ||
		r.Path != "" && m.Path != r.Path ||
		r.Destination != "" && m.Destination != r.Destination {
		return false
	}
	if ns := r.PathNamespace; ns != "" && ns != "/" && m.Path != ns && !strings.HasPrefix(string(m.Path), string(ns)+"/") {
		return false
	}
	for n, want := range r.Args {
		if n >= len(m.Body) {
			return false
		}
		if s, ok := m.Body[n].(string); !ok || s != want {
			return false
		}
	}
	for n, want := range r.ArgPaths {
		if n >= len(m.Body) {
			return false
		}
		var got string
		switch v := m.Body[n].(type) {
		case string:
			got = v
		case ObjectPath:
			got = string(v)
		default:
			return false
		}
		if got != want &&
			!(strings.HasSuffix(want, "/") && strings.HasPrefix(got, want)) &&
			!(strings.HasSuffix(got, "/") && strings.HasPrefix(want, got)) {
			return false
		}
	}
	if ns := r.Arg0Namespace; ns != "" {
		if len(m.Body) == 0 {
			return false
		}
		s, ok := m.Body[0].(string)
		if !ok || s != ns && !strings.HasPrefix(s, ns+".") {
			return false
		}
	}
	return true
}

// matchLocked applies the whole rule, resolving a well-known sender to the
// unique name that owns it. The caller holds c.mu.
func (c *Conn) matchLocked(r *MatchRule, m *Message) bool {
	if r.Sender != "" {
		want := r.Sender
		if !isUniqueName(want) && want != BusName {
			w := c.watches[want]
			if w == nil || w.owner == "" {
				return false
			}
			want = w.owner
		}
		if m.Sender != want {
			return false
		}
	}
	return r.matches(m)
}

// Subscription receives the signals that match a rule, in the order they
// arrived, from a queue of its own: a slow receiver delays nobody else, and
// past the connection's signal buffer the oldest are dropped.
type Subscription struct {
	// C delivers the signals, for subscriptions made by Subscribe. It is
	// closed when the subscription or the connection closes.
	C <-chan *Message

	conn    *Conn
	rule    MatchRule
	ch      chan *Message
	fn      func(*Message)
	watched string // a well-known sender whose owner is being followed

	mu      sync.Mutex
	queue   []*Message
	stopped bool
	dropped uint64
	max     int
	wake    chan struct{}
	quit    chan struct{}
	once    sync.Once
}

// Subscribe adds rule at the bus and delivers the signals that match it on
// the returned subscription's channel. A zero rule Type means signals; a
// well-known Sender is followed to whichever connection owns it, so only
// that owner's signals match.
//
// Received messages may be shared between subscriptions: treat them as
// read-only. File descriptors in them belong to the subscriber.
func (c *Conn) Subscribe(ctx context.Context, rule MatchRule) (*Subscription, error) {
	return c.subscribe(ctx, rule, make(chan *Message), nil)
}

// SubscribeFunc is Subscribe with a callback instead of a channel. The
// callback runs on the subscription's own goroutine, one signal at a time,
// and may make calls on the connection.
func (c *Conn) SubscribeFunc(ctx context.Context, rule MatchRule, fn func(*Message)) (*Subscription, error) {
	if fn == nil {
		return nil, errors.New("svdbus: SubscribeFunc needs a function")
	}
	return c.subscribe(ctx, rule, nil, fn)
}

func (c *Conn) subscribe(ctx context.Context, rule MatchRule, ch chan *Message, fn func(*Message)) (*Subscription, error) {
	if rule.Type == 0 {
		rule.Type = TypeSignal
	}
	if rule.Type != TypeSignal {
		return nil, invalidf("subscriptions receive signals, not %s messages", rule.Type)
	}
	if err := rule.Validate(); err != nil {
		return nil, err
	}
	s := &Subscription{
		C: ch, conn: c, rule: rule, ch: ch, fn: fn,
		max: c.opts.signalBuffer, wake: make(chan struct{}, 1), quit: make(chan struct{}),
	}
	if rule.Sender != "" && !isUniqueName(rule.Sender) && rule.Sender != BusName {
		if err := c.watchName(ctx, rule.Sender); err != nil {
			return nil, err
		}
		s.watched = rule.Sender
	}
	c.mu.Lock()
	if c.closed {
		err := c.err
		c.mu.Unlock()
		if s.watched != "" {
			c.unwatchName(ctx, s.watched)
		}
		return nil, err
	}
	c.subs = append(c.subs, s)
	c.mu.Unlock()
	go s.run()
	if err := c.AddMatch(ctx, rule); err != nil {
		s.close(ctx, false)
		return nil, err
	}
	return s, nil
}

// Rule returns the rule the subscription was made with.
func (s *Subscription) Rule() MatchRule { return s.rule }

// Dropped counts the signals dropped because the receiver fell behind.
func (s *Subscription) Dropped() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.dropped
}

// Close stops delivery, closes C, and removes the rule from the bus. A
// callback already running is left to finish.
func (s *Subscription) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), DefaultCallTimeout)
	defer cancel()
	return s.close(ctx, true)
}

func (s *Subscription) close(ctx context.Context, removeMatch bool) error {
	var err error
	s.once.Do(func() {
		c := s.conn
		c.mu.Lock()
		if i := slices.Index(c.subs, s); i >= 0 {
			c.subs = slices.Delete(c.subs, i, i+1)
		}
		closed := c.closed
		c.mu.Unlock()
		s.stop()
		if closed {
			return
		}
		if removeMatch {
			err = c.RemoveMatch(ctx, s.rule)
		}
		if s.watched != "" {
			c.unwatchName(ctx, s.watched)
		}
	})
	return err
}

func (s *Subscription) stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	s.mu.Unlock()
	close(s.quit)
}

func (s *Subscription) enqueue(m *Message) {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		m.CloseFDs()
		return
	}
	var old *Message
	if len(s.queue) >= s.max {
		old = s.queue[0]
		s.queue[0] = nil
		s.queue = s.queue[1:]
		s.dropped++
	}
	s.queue = append(s.queue, m)
	s.mu.Unlock()
	if old != nil {
		old.CloseFDs()
	}
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (s *Subscription) run() {
	defer func() {
		if s.ch != nil {
			close(s.ch)
		}
		s.mu.Lock()
		q := s.queue
		s.queue = nil
		s.mu.Unlock()
		for _, m := range q {
			m.CloseFDs()
		}
	}()
	for {
		select {
		case <-s.quit:
			return
		case <-s.wake:
		}
		for {
			s.mu.Lock()
			if len(s.queue) == 0 {
				s.mu.Unlock()
				break
			}
			m := s.queue[0]
			s.queue[0] = nil
			s.queue = s.queue[1:]
			s.mu.Unlock()
			if s.fn != nil {
				select {
				case <-s.quit:
					m.CloseFDs()
					return
				default:
				}
				s.fn(m)
				continue
			}
			select {
			case s.ch <- m:
			case <-s.quit:
				m.CloseFDs()
				return
			}
		}
	}
}

// nameWatch follows which connection owns a well-known name, for matching
// subscriptions by sender.
type nameWatch struct {
	owner string
	refs  int
}

func ownerRule(name string) MatchRule {
	return MatchRule{
		Type: TypeSignal, Sender: BusName, Interface: BusInterface, Member: "NameOwnerChanged",
		Path: BusPath, Args: map[int]string{0: name},
	}
}

// watchName starts following name's owner, or counts one more user of an
// existing watch. The owner is set from GetNameOwner's reply on the reader
// goroutine, in stream order with NameOwnerChanged, so neither overwrites
// news with something older.
func (c *Conn) watchName(ctx context.Context, name string) error {
	c.watchMu.Lock()
	defer c.watchMu.Unlock()
	c.mu.Lock()
	if w := c.watches[name]; w != nil {
		w.refs++
		c.mu.Unlock()
		return nil
	}
	w := &nameWatch{refs: 1}
	c.watches[name] = w
	c.mu.Unlock()

	rule := ownerRule(name)
	err := c.AddMatch(ctx, rule)
	if err == nil {
		m := NewMethodCall(BusName, BusPath, BusInterface, "GetNameOwner", name)
		_, err = c.roundTrip(ctx, m, func(r *Message) {
			owner := ""
			if r.Type == TypeMethodReturn && r.Signature == "s" {
				owner = r.Body[0].(string)
			}
			c.mu.Lock()
			w.owner = owner
			c.mu.Unlock()
		})
		var de *Error
		if errors.As(err, &de) && de.Name == ErrorNameHasNoOwner {
			err = nil
		}
		if err != nil {
			_ = c.RemoveMatch(ctx, rule)
		}
	}
	if err != nil {
		c.mu.Lock()
		delete(c.watches, name)
		c.mu.Unlock()
	}
	return err
}

func (c *Conn) unwatchName(ctx context.Context, name string) {
	c.watchMu.Lock()
	defer c.watchMu.Unlock()
	c.mu.Lock()
	w := c.watches[name]
	if w == nil {
		c.mu.Unlock()
		return
	}
	if w.refs--; w.refs > 0 {
		c.mu.Unlock()
		return
	}
	delete(c.watches, name)
	c.mu.Unlock()
	_ = c.RemoveMatch(ctx, ownerRule(name))
}
