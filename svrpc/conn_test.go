package svrpc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

type pair struct{ a, b *Conn }

func newPair(t *testing.T, ha, hb Handler) pair {
	t.Helper()
	x, y := net.Pipe()
	p := pair{NewConn(x, ha), NewConn(y, hb)}
	go p.a.Run()
	go p.b.Run()
	t.Cleanup(func() { p.a.Close(); p.b.Close() })
	return p
}

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestCallsGoBothWaysAndCanCallBack(t *testing.T) {
	var p pair
	server := func(ctx context.Context, c *Conn, method string, params json.RawMessage) (any, error) {
		switch method {
		case "add":
			var xs []int
			json.Unmarshal(params, &xs)
			return xs[0] + xs[1], nil
		case "ask":
			// Call back into the client while serving it: how the daemon
			// asks a CLI to prompt on its terminal.
			var ans PromptAnswer
			if err := c.Call(ctx, MPromptAsk, PromptAsk{Kind: PromptPassphrase}, &ans); err != nil {
				return nil, err
			}
			return string(ans.Secret), nil
		}
		return nil, Errorf(CodeMethodNotFound, "no %s", method)
	}
	client := func(ctx context.Context, c *Conn, method string, params json.RawMessage) (any, error) {
		if method == MPromptAsk {
			return PromptAnswer{Secret: []byte("hunter2")}, nil
		}
		return nil, Errorf(CodeMethodNotFound, "no %s", method)
	}
	p = newPair(t, client, server)

	var sum int
	if err := p.a.Call(ctx(t), "add", []int{2, 3}, &sum); err != nil || sum != 5 {
		t.Fatalf("add = %d, %v", sum, err)
	}
	var got string
	if err := p.a.Call(ctx(t), "ask", nil, &got); err != nil || got != "hunter2" {
		t.Fatalf("ask = %q, %v", got, err)
	}
}

func TestErrorsKeepTheirCodes(t *testing.T) {
	p := newPair(t, nil, func(context.Context, *Conn, string, json.RawMessage) (any, error) {
		return nil, ErrLocked
	})
	err := p.a.Call(ctx(t), "item.get", nil, nil)
	if !errors.Is(err, ErrLocked) || errors.Is(err, ErrDenied) {
		t.Fatalf("err = %v", err)
	}
	p2 := newPair(t, nil, func(context.Context, *Conn, string, json.RawMessage) (any, error) {
		return nil, errors.New("plain failure")
	})
	var e *Error
	if err := p2.a.Call(ctx(t), "x", nil, nil); !errors.As(err, &e) || e.Code != CodeFailed || e.Message != "plain failure" {
		t.Fatalf("plain error became %v", err)
	}
	// The client side serves nothing: a call to it is refused, not hung.
	if err := p.b.Call(ctx(t), "anything", nil, nil); !errors.As(err, &e) || e.Code != CodeMethodNotFound {
		t.Fatalf("call to a side without a handler: %v", err)
	}
}

func TestNotificationsArriveWithoutAReply(t *testing.T) {
	got := make(chan string, 1)
	p := newPair(t, func(_ context.Context, _ *Conn, method string, params json.RawMessage) (any, error) {
		var ev VaultEvent
		json.Unmarshal(params, &ev)
		got <- method + ":" + ev.Vault
		return nil, nil
	}, nil)
	if err := p.b.Notify(EVaultLocked, VaultEvent{Vault: "work"}); err != nil {
		t.Fatal(err)
	}
	select {
	case s := <-got:
		if s != "vault.locked:work" {
			t.Fatalf("got %q", s)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("notification never arrived")
	}
}

func TestClosingFailsCallsInFlight(t *testing.T) {
	block := make(chan struct{})
	p := newPair(t, nil, func(context.Context, *Conn, string, json.RawMessage) (any, error) {
		<-block
		return nil, nil
	})
	defer close(block)
	errc := make(chan error, 1)
	go func() { errc <- p.a.Call(context.Background(), "slow", nil, nil) }()
	time.Sleep(50 * time.Millisecond)
	p.b.Close()
	select {
	case err := <-errc:
		if err == nil {
			t.Fatal("a call survived its connection")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the call hung after the connection closed")
	}
	if err := p.a.Call(ctx(t), "after", nil, nil); err == nil {
		t.Fatal("a call on a closed connection succeeded")
	}
}

func TestACallStopsWaitingWhenItsContextEnds(t *testing.T) {
	block := make(chan struct{})
	defer close(block)
	p := newPair(t, nil, func(context.Context, *Conn, string, json.RawMessage) (any, error) {
		<-block
		return nil, nil
	})
	c, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := p.a.Call(c, "slow", nil, nil); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v", err)
	}
}

func TestGarbageAndOversizedMessagesAreRefused(t *testing.T) {
	x, y := net.Pipe()
	c := NewConn(y, func(context.Context, *Conn, string, json.RawMessage) (any, error) { return "ok", nil })
	done := make(chan error, 1)
	go func() { done <- c.Run() }()
	defer x.Close()

	var mu sync.Mutex
	var replies []string
	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := x.Read(buf)
			if err != nil {
				return
			}
			mu.Lock()
			replies = append(replies, string(buf[:n]))
			mu.Unlock()
		}
	}()
	x.Write([]byte("this is not json\n"))
	time.Sleep(50 * time.Millisecond)
	mu.Lock()
	gotParseError := strings.Contains(strings.Join(replies, ""), "-32700")
	mu.Unlock()
	if !gotParseError {
		t.Fatalf("no parse error for garbage: %q", replies)
	}
	// A line beyond MaxMessage ends the connection.
	go x.Write([]byte(strings.Repeat("a", MaxMessage+10)))
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("an oversized message closed the connection cleanly")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an oversized message did not end the connection")
	}
}
