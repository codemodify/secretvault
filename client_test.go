package secretvault

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svrpc"
)

// fakeDaemon answers a client over a pipe with serve, as secretvaultd
// would, and keeps each request's parameters.
func fakeDaemon(t *testing.T, serve func(method string, params json.RawMessage) (any, error)) *Client {
	t.Helper()
	a, b := net.Pipe()
	d := svrpc.NewConn(b, func(_ context.Context, _ *svrpc.Conn, method string, params json.RawMessage) (any, error) {
		if method == svrpc.MHello {
			return svrpc.HelloResult{Daemon: "secretvaultd"}, nil
		}
		return serve(method, params)
	})
	go d.Run()
	c, err := newClient(a, Options{Name: "comms-mail"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); d.Close() })
	return c
}

func tctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)
	return c
}

func TestRequestVaultSendsTheNameAloneAndReturnsTheVault(t *testing.T) {
	var got json.RawMessage
	c := fakeDaemon(t, func(method string, params json.RawMessage) (any, error) {
		if method != svrpc.MVaultRequest {
			return nil, svrpc.Errorf(svrpc.CodeMethodNotFound, "no method %q", method)
		}
		got = params
		return svrpc.VaultRequestResult{Vault: "mail"}, nil
	})
	name, err := c.RequestVault(tctx(t), "mail")
	if err != nil || name != "mail" {
		t.Fatalf("RequestVault = %q, %v", name, err)
	}
	if string(got) != `{"name":"mail"}` {
		t.Fatalf("the request carried %s", got)
	}
}

func TestRequestVaultsErrorsAreTheirOwn(t *testing.T) {
	for _, code := range []int{svrpc.CodeExists, svrpc.CodeDenied, svrpc.CodeCanceled, svrpc.CodeNoPrompter} {
		c := fakeDaemon(t, func(string, json.RawMessage) (any, error) { return nil, svrpc.Errorf(code, "no") })
		_, err := c.RequestVault(tctx(t), "mail")
		var e *svrpc.Error
		if !errors.As(err, &e) || e.Code != code {
			t.Fatalf("code %d came back as %v", code, err)
		}
	}
}

// A missing vault and a missing item are told apart by errors.Is.
func TestAMissingVaultIsNotAMissingItem(t *testing.T) {
	c := fakeDaemon(t, func(method string, params json.RawMessage) (any, error) {
		var p svrpc.ItemRef
		json.Unmarshal(params, &p)
		if p.Vault != "personal" {
			return nil, svrpc.Errorf(svrpc.CodeNoVault, "there is no vault named %q", p.Vault)
		}
		return nil, svrpc.Errorf(svrpc.CodeNotFound, "no such item: %q", p.Name)
	})
	_, err := c.Get(tctx(t), "mail", "comms-mail/key")
	if !errors.Is(err, svrpc.ErrNoVault) || errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("a missing vault: %v", err)
	}
	_, err = c.Get(tctx(t), "personal", "comms-mail/key")
	if !errors.Is(err, svrpc.ErrNotFound) || errors.Is(err, svrpc.ErrNoVault) {
		t.Fatalf("a missing item: %v", err)
	}
	if svrpc.CodeNoVault != -32008 {
		t.Fatalf("CodeNoVault is %d: the number is part of the protocol", svrpc.CodeNoVault)
	}
}
