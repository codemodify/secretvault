// Package svrpc is the protocol between secretvaultd and its clients:
// JSON-RPC 2.0, one message per line (NDJSON), over a local socket.
//
// A connection is symmetric. Clients call the daemon (item.get,
// vault.unlock, ...), and the daemon calls back into clients that offered
// to help, chiefly to ask the person at a client's terminal for a
// passphrase (prompt.ask). Either side may send notifications (messages
// without an id), which the daemon uses for events such as vault.locked.
//
// This package holds the connection machinery (conn.go) and the method
// names and message shapes (methods.go); it knows nothing about vaults.
package svrpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"sync"
)

// MaxMessage is the largest message either side accepts, in bytes.
const MaxMessage = 16 << 20

// Handler serves a request or notification from the peer. For a
// notification (no id) the result is discarded. Handlers run concurrently,
// each on its own goroutine, so one may call back into the peer while it
// is being served.
type Handler func(ctx context.Context, c *Conn, method string, params json.RawMessage) (any, error)

// Conn is one JSON-RPC connection.
type Conn struct {
	rw      io.ReadWriteCloser
	handler Handler

	wmu sync.Mutex // serialises writes
	w   *bufio.Writer

	mu      sync.Mutex
	nextID  uint64
	pending map[uint64]chan *message
	closed  bool
	err     error

	ctx    context.Context
	cancel context.CancelFunc
	done   chan struct{}

	// Value holds whatever the owner attaches (the daemon's per-client
	// state). It is not used by the connection itself.
	Value any
}

// message is any JSON-RPC 2.0 message.
type message struct {
	JSONRPC string           `json:"jsonrpc"`
	ID      *json.RawMessage `json:"id,omitempty"`
	Method  string           `json:"method,omitempty"`
	Params  json.RawMessage  `json:"params,omitempty"`
	Result  json.RawMessage  `json:"result,omitempty"`
	Error   *Error           `json:"error,omitempty"`
}

// NewConn wraps rw. Call Run to start reading; until then nothing is
// received. handler may be nil for a side that serves nothing.
func NewConn(rw io.ReadWriteCloser, handler Handler) *Conn {
	ctx, cancel := context.WithCancel(context.Background())
	return &Conn{
		rw:      rw,
		handler: handler,
		w:       bufio.NewWriter(rw),
		pending: map[uint64]chan *message{},
		ctx:     ctx,
		cancel:  cancel,
		done:    make(chan struct{}),
	}
}

// Run reads and dispatches messages until the connection closes, and
// returns why it closed (nil for a clean close by either side).
func (c *Conn) Run() error {
	defer close(c.done)
	r := bufio.NewReaderSize(c.rw, 64<<10)
	var err error
	for {
		var line []byte
		line, err = readLine(r)
		if err != nil {
			break
		}
		if len(line) == 0 {
			continue
		}
		var m message
		if jerr := json.Unmarshal(line, &m); jerr != nil || m.JSONRPC != "2.0" {
			c.reply(nil, nil, &Error{Code: CodeParse, Message: "not a JSON-RPC 2.0 message"})
			continue
		}
		switch {
		case m.Method != "":
			go c.serve(m)
		case m.ID != nil:
			c.deliver(&m)
		}
	}
	c.shutdown(err)
	if errors.Is(err, io.EOF) || errors.Is(err, errClosed) {
		return nil
	}
	return err
}

var errClosed = errors.New("svrpc: connection closed")

// readLine reads one newline-terminated line of at most MaxMessage bytes.
func readLine(r *bufio.Reader) ([]byte, error) {
	var buf []byte
	for {
		chunk, err := r.ReadSlice('\n')
		buf = append(buf, chunk...)
		if err == nil {
			if len(buf)-1 > MaxMessage {
				return nil, fmt.Errorf("svrpc: message larger than %d bytes", MaxMessage)
			}
			return buf[:len(buf)-1], nil
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			// No newline yet: a line that has already reached the limit
			// can only end over it.
			if len(buf) >= MaxMessage {
				return nil, fmt.Errorf("svrpc: message larger than %d bytes", MaxMessage)
			}
			continue
		}
		if err == io.EOF && len(buf) > 0 {
			return nil, io.ErrUnexpectedEOF
		}
		return nil, err
	}
}

func (c *Conn) serve(m message) {
	if c.handler == nil {
		if m.ID != nil {
			c.reply(m.ID, nil, &Error{Code: CodeMethodNotFound, Message: "this side serves no methods"})
		}
		return
	}
	result, err := c.handler(c.ctx, c, m.Method, m.Params)
	if m.ID == nil {
		return // a notification: nobody is waiting
	}
	if err != nil {
		c.reply(m.ID, nil, AsError(err))
		return
	}
	raw, jerr := json.Marshal(result)
	if jerr != nil {
		c.reply(m.ID, nil, &Error{Code: CodeInternal, Message: "cannot encode result: " + jerr.Error()})
		return
	}
	c.reply(m.ID, raw, nil)
}

func (c *Conn) reply(id *json.RawMessage, result json.RawMessage, e *Error) {
	if id == nil {
		null := json.RawMessage("null")
		id = &null
	}
	m := message{JSONRPC: "2.0", ID: id, Error: e}
	if e == nil {
		if result == nil {
			result = json.RawMessage("null")
		}
		m.Result = result
	}
	_ = c.send(&m)
}

func (c *Conn) deliver(m *message) {
	id, err := strconv.ParseUint(string(*m.ID), 10, 64)
	if err != nil {
		return
	}
	c.mu.Lock()
	ch := c.pending[id]
	delete(c.pending, id)
	c.mu.Unlock()
	if ch != nil {
		ch <- m
	}
}

func (c *Conn) send(m *message) error {
	b, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if len(b) > MaxMessage {
		return fmt.Errorf("svrpc: message larger than %d bytes", MaxMessage)
	}
	c.wmu.Lock()
	defer c.wmu.Unlock()
	if _, err := c.w.Write(append(b, '\n')); err != nil {
		return err
	}
	return c.w.Flush()
}

// Call sends a request and waits for its response, decoding the result
// into result (which may be nil). A JSON-RPC error comes back as *Error.
func (c *Conn) Call(ctx context.Context, method string, params, result any) error {
	raw, err := marshalParams(params)
	if err != nil {
		return err
	}
	c.mu.Lock()
	if c.closed {
		err := c.err
		c.mu.Unlock()
		return fmt.Errorf("svrpc: %s: %w", method, err)
	}
	c.nextID++
	id := c.nextID
	ch := make(chan *message, 1)
	c.pending[id] = ch
	c.mu.Unlock()

	idRaw := json.RawMessage(strconv.FormatUint(id, 10))
	if err := c.send(&message{JSONRPC: "2.0", ID: &idRaw, Method: method, Params: raw}); err != nil {
		c.forget(id)
		return err
	}
	select {
	case m := <-ch:
		if m == nil {
			c.mu.Lock()
			err := c.err
			c.mu.Unlock()
			return fmt.Errorf("svrpc: %s: %w", method, err)
		}
		if m.Error != nil {
			return m.Error
		}
		if result != nil && len(m.Result) > 0 {
			return json.Unmarshal(m.Result, result)
		}
		return nil
	case <-ctx.Done():
		c.forget(id)
		return ctx.Err()
	}
}

func (c *Conn) forget(id uint64) {
	c.mu.Lock()
	delete(c.pending, id)
	c.mu.Unlock()
}

// Notify sends a notification: a request nobody answers.
func (c *Conn) Notify(method string, params any) error {
	raw, err := marshalParams(params)
	if err != nil {
		return err
	}
	return c.send(&message{JSONRPC: "2.0", Method: method, Params: raw})
}

func marshalParams(params any) (json.RawMessage, error) {
	if params == nil {
		return nil, nil
	}
	return json.Marshal(params)
}

// Close closes the connection. Pending calls fail.
func (c *Conn) Close() error {
	c.shutdown(errClosed)
	return c.rw.Close()
}

func (c *Conn) shutdown(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	c.closed = true
	if err == nil || errors.Is(err, io.EOF) {
		err = errClosed
	}
	c.err = err
	for id, ch := range c.pending {
		close(ch)
		delete(c.pending, id)
	}
	c.cancel()
}

// Done is closed when Run has returned.
func (c *Conn) Done() <-chan struct{} { return c.done }

// Context is cancelled when the connection closes; handlers use it to stop
// work (and prompts) nobody is waiting for any more.
func (c *Conn) Context() context.Context { return c.ctx }
