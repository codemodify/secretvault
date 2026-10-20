package svd

import (
	"context"
	"errors"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svrpc"
)

// A vault that is not there has its own code (svrpc.CodeNoVault), apart
// from an item that is not there (CodeNotFound): a program that skipped
// vault.list must not take "no such vault" for "no password saved".

// namesAVault are the methods that name a vault, each with what it needs
// besides to reach the vault: every one says a missing vault with
// CodeNoVault.
var namesAVault = map[string]map[string]any{
	svrpc.MVaultUnlock:  {},
	svrpc.MVaultLock:    {},
	svrpc.MVaultVerify:  {},
	svrpc.MVaultPasswd:  {"passphrase": []byte("long enough passphrase")},
	svrpc.MVaultRotate:  {"passphrase": []byte("long enough passphrase")},
	svrpc.MVaultForget:  {},
	svrpc.MVaultDefault: {},
	svrpc.MVaultLogin:   {"on": false},
	svrpc.MSlotList:     {},
	svrpc.MSlotAdd:      {"type": "recovery"},
	svrpc.MSlotRemove:   {"id": "00000000000000000000000000000000"},
	svrpc.MItemGet:      {"name": "x"},
	svrpc.MItemList:     {},
	svrpc.MItemPut:      {"item": svrpc.Item{Kind: "login", Name: "x"}},
	svrpc.MItemDelete:   {"name": "x"},
	svrpc.MItemRename:   {"from": "x", "to": "y"},
	svrpc.MItemHistory:  {"name": "x"},
	svrpc.MItemMove:     {"to": "personal", "names": []string{"x"}},
	svrpc.MItemCopy:     {"to": "personal", "prefix": ""},
	svrpc.MItemDeleted:  {},
	svrpc.MItemRestore:  {"name": "x"},
	svrpc.MGrantList:    {},
	svrpc.MGrantAdd:     {"program": "/bin/sh", "decision": "allow-always"},
	svrpc.MGrantRevoke:  {"id": "x"},
	svrpc.MAuditList:    {},
	svrpc.MFileGet:      {"item": "x", "name": "f"},
	svrpc.MFileAttach:   {"item": "x", "name": "f", "data": []byte("d")},
	svrpc.MFileRemove:   {"item": "x", "name": "f"},
	svrpc.MDeviceList:   {},
	svrpc.MSyncStatus:   {},

	svrpc.MContainerDelete: {"path": "/nowhere/private.img"},
}

// ownOnly are secretvault's own programs' to call: a program is refused
// before the vault is looked for.
var ownOnly = map[string]bool{svrpc.MVaultForget: true, svrpc.MVaultDefault: true, svrpc.MVaultLogin: true, svrpc.MSyncStatus: true}

// unsafeToCall are left out of the sweep below: they reach the network,
// take the connection over, or need a host daemon.
var unsafeToCall = map[string]bool{
	svrpc.MBrowserOpen: true, svrpc.MBrowserMessage: true, svrpc.MPromptRegister: true, svrpc.MKeyringServe: true,
	svrpc.MSyncJoin: true, svrpc.MSyncSetup: true, svrpc.MSyncInvite: true, svrpc.MContactLookup: true,
	svrpc.MDirectoryAdd: true, svrpc.MDirectoryList: true, svrpc.MDirectoryRemove: true,
	svrpc.MEmergencyRequest: true, svrpc.MEmergencyAccept: true, svrpc.MEmergencyOpen: true,
	svrpc.MVaultCreate: true, svrpc.MVaultAdd: true, svrpc.MVaultRequest: true, svrpc.MHello: true, svrpc.MFIDO2List: true,
}

func TestAMissingVaultIsNotAMissingItem(t *testing.T) {
	h := newHarness(t)
	term := &scripted{}
	cli := h.connect("/usr/bin/secretvault", term)
	mail := h.connect("/usr/bin/comms-mail", nil)

	// No vault at all: the default is missing too.
	for _, c := range []interface {
		Get(context.Context, string, string) (svrpc.Entry, error)
	}{cli, mail} {
		if _, err := c.Get(ctx(t), "", "x"); !errors.Is(err, svrpc.ErrNoVault) || errors.Is(err, svrpc.ErrNotFound) {
			t.Fatalf("no vault yet: %v", err)
		}
	}
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "personal", Passphrase: pass}); err != nil {
		t.Fatal(err)
	}

	// A missing item in a vault that is there is still not found.
	if _, err := cli.Get(ctx(t), "personal", "x"); !errors.Is(err, svrpc.ErrNotFound) || errors.Is(err, svrpc.ErrNoVault) {
		t.Fatalf("a missing item: %v", err)
	}
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	if _, err := mail.Get(ctx(t), "personal", "x"); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("a missing item, for a program: %v", err)
	}

	// Every method that names a vault, from secretvault's CLI and from a
	// program, says a missing one with its own code, and asks nobody.
	asked := h.desk.count()
	names := make([]string, 0, len(namesAVault))
	for m := range namesAVault {
		names = append(names, m)
	}
	sort.Strings(names)
	for _, m := range names {
		params := map[string]any{"vault": "nope"}
		for k, v := range namesAVault[m] {
			params[k] = v
		}
		for who, c := range map[string]interface {
			Call(context.Context, string, any, any) error
		}{"the CLI": cli, "a program": mail} {
			err := c.Call(ctx(t), m, params, nil)
			if c == mail && ownOnly[m] {
				// Refused before any vault is looked for.
				if !errors.Is(err, svrpc.ErrDenied) {
					t.Errorf("%s from %s: %v", m, who, err)
				}
				continue
			}
			if !errors.Is(err, svrpc.ErrNoVault) {
				t.Errorf("%s from %s: %v", m, who, err)
			}
		}
	}
	if h.desk.count() != asked || term.count() != 0 {
		t.Error("a missing vault had somebody asked")
	}

	// And a sweep of every method there is: none says a missing vault
	// as anything else, nor anything else as a missing vault.
	all := map[string]bool{}
	for m := range handlers {
		all[m] = true
	}
	for _, m := range []string{svrpc.MStatus, svrpc.MVaultList, svrpc.MVaultCreate, svrpc.MVaultAdd, svrpc.MVaultForget,
		svrpc.MVaultDefault, svrpc.MVaultUnlock, svrpc.MVaultLock, svrpc.MVaultVerify, svrpc.MVaultPasswd, svrpc.MVaultRotate,
		svrpc.MSlotList, svrpc.MSlotAdd, svrpc.MSlotRemove, svrpc.MItemGet, svrpc.MItemList, svrpc.MItemPut, svrpc.MItemDelete,
		svrpc.MItemRename, svrpc.MItemHistory, svrpc.MGrantList, svrpc.MGrantRevoke, svrpc.MGrantAdd, svrpc.MAuditList} {
		all[m] = true
	}
	for m := range all {
		if unsafeToCall[m] || strings.HasPrefix(m, "host.") {
			continue
		}
		params := map[string]any{"vault": "nope", "name": "x", "from": "x", "to": "y", "id": "x"}
		c, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		err := cli.Call(c, m, params, nil)
		cancel()
		var e *svrpc.Error
		if !errors.As(err, &e) {
			continue
		}
		missing := strings.Contains(e.Message, `vault named "nope"`) || strings.Contains(e.Message, "no vault")
		switch {
		case missing && e.Code != svrpc.CodeNoVault:
			t.Errorf("%s says a missing vault with code %d: %s", m, e.Code, e.Message)
		case e.Code == svrpc.CodeNotFound && strings.Contains(e.Message, "vault"):
			t.Errorf("%s: not found, about a vault: %s", m, e.Message)
		}
	}
}

func TestAVaultWhoseFolderIsGoneIsMissing(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	h.d.mu.Lock()
	h.d.vaults["personal"].v = nil // as the daemon finds a vault whose folder went
	h.d.mu.Unlock()
	if _, err := cli.Get(ctx(t), "personal", "mail/imap"); !errors.Is(err, svrpc.ErrNoVault) || !strings.Contains(err.Error(), "folder") {
		t.Fatalf("a missing folder: %v", err)
	}
}
