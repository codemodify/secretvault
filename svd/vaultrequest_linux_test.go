//go:build linux

package svd

import (
	"testing"

	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svrpc"
)

// The Secret Service's default alias is the default vault: a vault a
// program asked for is not made it there either, whoever may manage it.
func TestTheKeyringDoesNotMakeAVaultAskedForTheDefault(t *testing.T) {
	h := newSSHarness(t)
	mail := h.connect("/usr/bin/comms-mail", nil)
	h.desk.script("choose:"+svrpc.ChoiceCreate, "pass:"+newPass, "choose:"+svrpc.ChoiceWritten)
	if _, err := mail.RequestVault(ctx(t), "mail"); err != nil {
		t.Fatal(err)
	}
	n := h.desk.count()
	c, err := svdbus.ConnectSession()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Call(ctx(t), ssBusName, ssRoot, ifService, "SetAlias", "default", collectionPath("mail"))
	if !isDBusError(err, svdbus.ErrorAccessDenied) {
		t.Fatalf("SetAlias to the vault asked for: %v", err)
	}
	if h.desk.count() != n {
		t.Fatal("somebody was asked")
	}
	cli := h.connect("/usr/bin/secretvault", &scripted{})
	vs, _ := cli.Vaults(ctx(t))
	for _, v := range vs {
		if v.Default != (v.Name == "personal") {
			t.Fatalf("defaults: %+v", vs)
		}
	}
}
