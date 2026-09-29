package main

import (
	"testing"

	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svrpc"
)

// The host daemon's paths come from its flags, else the environment,
// else /var/lib/secretvault and /run/secretvault.
func TestHostPathsComeFromFlagsThenTheEnvironment(t *testing.T) {
	t.Setenv(svrpc.EnvHostData, "")
	t.Setenv(svrpc.EnvHostRuntime, "")
	o := hostFlags{}.options()
	if o.Mode != svd.ModeHost || o.Home != "/var/lib/secretvault" || o.Host.Runtime != "/run/secretvault" || o.Socket != "/run/secretvault/admin.sock" {
		t.Fatalf("defaults: %+v", o)
	}
	t.Setenv(svrpc.EnvHostData, "/tmp/d")
	t.Setenv(svrpc.EnvHostRuntime, "/tmp/r")
	if o := (hostFlags{}).options(); o.Home != "/tmp/d" || o.Host.Runtime != "/tmp/r" {
		t.Fatalf("from the environment: %+v", o)
	}
	o = hostFlags{data: "/x/d", runtime: "/x/r", policy: "/x/p.json", identity: "/x/id"}.options()
	if o.Home != "/x/d" || o.Host.Runtime != "/x/r" || o.Host.Policy != "/x/p.json" || o.Host.Identity != "/x/id" || o.Socket != "/x/r/admin.sock" {
		t.Fatalf("from flags: %+v", o)
	}
}
