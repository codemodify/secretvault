package svd

import (
	"bytes"
	"context"
	"errors"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svserver"
)

// syncServer is a sync server on a TLS test listener.
type syncServer struct {
	root string
	url  string
	fp   string
}

const adminToken = "let-me-in"

func newSyncServer(t *testing.T) *syncServer {
	t.Helper()
	root := t.TempDir()
	s, err := svserver.New(svserver.Config{Root: root, AdminToken: adminToken, Rate: -1})
	if err != nil {
		t.Fatal(err)
	}
	h := httptest.NewTLSServer(s)
	t.Cleanup(func() {
		s.Close()
		h.Close()
	})
	return &syncServer{root: root, url: h.URL, fp: svserver.Fingerprint(h.Certificate().Raw)}
}

// eventually retries f until it succeeds or a few seconds pass.
func eventually(t *testing.T, what string, f func() error) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for {
		err := f()
		if err == nil {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: %v", what, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func getSecret(cli *secretvault.Client, vault, name string) (string, error) {
	e, err := cli.Get(context.Background(), vault, name)
	if err != nil {
		return "", err
	}
	return secretOf(e), nil
}

// twoDevices sets up a vault on one daemon, syncs it to a server, and
// joins a second daemon to it; the second has it unlocked.
func twoDevices(t *testing.T) (srv *syncServer, a, b *harness, ca, cb *secretvault.Client) {
	t.Helper()
	srv = newSyncServer(t)
	a, b = newHarness(t), newHarness(t)
	ca = a.setup()
	st, err := ca.SyncSetup(ctx(t), svrpc.SyncSetupParams{URL: srv.url, Fingerprint: srv.fp, AdminToken: adminToken, Label: "laptop"})
	if err != nil {
		t.Fatal(err)
	}
	if st.Pushed == 0 || st.Vault != "personal" || st.Device == "" {
		t.Fatalf("status after setup: %+v", st)
	}
	inv, err := ca.SyncInvite(ctx(t), "")
	if err != nil {
		t.Fatal(err)
	}
	cb = b.connect("/usr/bin/secretvault", &scripted{})
	v, err := cb.SyncJoin(ctx(t), svrpc.SyncJoinParams{Invite: inv.Invite, Name: "shared", Label: "desktop"})
	if err != nil {
		t.Fatal(err)
	}
	if !v.Locked || v.ID == "" || v.Path != filepath.Join(b.home, "vaults", "shared") {
		t.Fatalf("joined vault: %+v", v)
	}
	if _, err := cb.Unlock(ctx(t), "shared", &svrpc.Key{Type: "passphrase", Secret: pass}); err != nil {
		t.Fatal(err)
	}
	return
}

func TestAVaultSyncsBetweenTwoDaemonsBothWays(t *testing.T) {
	_, a, b, ca, cb := twoDevices(t)

	if s, err := getSecret(cb, "shared", "mail/imap"); err != nil || s != "hunter2" {
		t.Fatalf("the joined copy: %q, %v", s, err)
	}
	// Writes travel at once, both ways, and the open vault sees them.
	if _, err := cb.Put(ctx(t), "shared", login("web/forum", "from-b")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "b's write reaching a", func() error {
		s, err := getSecret(ca, "", "web/forum")
		if err == nil && s != "from-b" {
			err = errors.New("wrong value " + s)
		}
		return err
	})
	if _, err := ca.Put(ctx(t), "", login("mail/imap", "changed-on-a")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a's change reaching b", func() error {
		s, err := getSecret(cb, "shared", "mail/imap")
		if err == nil && s != "changed-on-a" {
			err = errors.New("still " + s)
		}
		return err
	})

	// Status, a sync on demand, and the devices.
	st, err := cb.SyncNow(ctx(t), "shared")
	if err != nil || st.Error != "" || st.LastOK.IsZero() || st.Pulled == 0 {
		t.Fatalf("sync now: %+v, %v", st, err)
	}
	devs, err := ca.SyncDevices(ctx(t), "")
	if err != nil || len(devs) != 2 {
		t.Fatalf("devices: %+v, %v", devs, err)
	}
	var this, other svrpc.SyncDevice
	for _, dv := range devs {
		if dv.This {
			this = dv
		} else {
			other = dv
		}
	}
	if this.Label != "laptop" || other.Label != "desktop" {
		t.Fatalf("devices: %+v", devs)
	}
	if err := ca.SyncRemove(ctx(t), "", this.Key); err == nil {
		t.Fatal("a device removed itself instead of turning sync off")
	}

	// Both keep syncing across a restart of each daemon.
	a.restart()
	b.restart()
	ca = a.connect("/usr/bin/secretvault", &scripted{})
	cb = b.connect("/usr/bin/secretvault", &scripted{})
	for _, c := range []struct {
		cli   *secretvault.Client
		vault string
	}{{ca, "personal"}, {cb, "shared"}} {
		if _, err := c.cli.Unlock(ctx(t), c.vault, &svrpc.Key{Type: "passphrase", Secret: pass}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ca.Put(ctx(t), "", login("after/restart", "yes")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "a write after restarting", func() error {
		_, err := getSecret(cb, "shared", "after/restart")
		return err
	})

	// Off: the vault stays, and stops syncing.
	if err := cb.SyncOff(ctx(t), "shared"); err != nil {
		t.Fatal(err)
	}
	if sts, err := cb.SyncStatus(ctx(t), ""); err != nil || len(sts) != 0 {
		t.Fatalf("status after off: %+v, %v", sts, err)
	}
	if _, err := ca.Put(ctx(t), "", login("after/off", "no")); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.SyncNow(ctx(t), ""); err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := getSecret(cb, "shared", "after/off"); err == nil {
		t.Fatal("a vault still synced after sync off")
	}
	if _, err := getSecret(cb, "shared", "after/restart"); err != nil {
		t.Fatalf("the vault itself went with sync off: %v", err)
	}
}

func TestARotationOnOneDeviceLocksTheOther(t *testing.T) {
	_, _, _, ca, cb := twoDevices(t)
	newPass := []byte("a new passphrase for everyone")
	if _, err := ca.Rotate(ctx(t), svrpc.RotateParams{Passphrase: newPass}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the other device locking", func() error {
		vs, err := cb.Vaults(context.Background())
		if err != nil {
			return err
		}
		for _, v := range vs {
			if v.Name == "shared" && !v.Locked {
				return errors.New("still unlocked")
			}
		}
		return nil
	})
	// The old passphrase no longer opens it; the new one does, and the
	// items written before the rotation are still there.
	if _, err := cb.Unlock(ctx(t), "shared", &svrpc.Key{Type: "passphrase", Secret: pass}); err == nil {
		t.Fatal("the old passphrase still opens the rotated vault")
	}
	if _, err := cb.Unlock(ctx(t), "shared", &svrpc.Key{Type: "passphrase", Secret: newPass}); err != nil {
		t.Fatal(err)
	}
	if s, err := getSecret(cb, "shared", "mail/imap"); err != nil || s != "hunter2" {
		t.Fatalf("after the rotation: %q, %v", s, err)
	}
}

func TestOnlySecretvaultsOwnProgramsChangeWhereVaultsAreKept(t *testing.T) {
	srv := newSyncServer(t)
	h := newHarness(t)
	h.setup()
	app := h.connect("/usr/bin/some-app", nil)
	for what, err := range map[string]error{
		"vault add":     func() error { _, err := app.AddVault(ctx(t), "evil", t.TempDir()); return err }(),
		"vault forget":  app.ForgetVault(ctx(t), "personal"),
		"vault default": app.SetDefault(ctx(t), "personal"),
		"vault create": func() error {
			_, err := app.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "evil", Passphrase: pass})
			return err
		}(),
		"sync setup": func() error {
			_, err := app.SyncSetup(ctx(t), svrpc.SyncSetupParams{URL: srv.url, Fingerprint: srv.fp, AdminToken: adminToken})
			return err
		}(),
		"sync join": func() error {
			_, err := app.SyncJoin(ctx(t), svrpc.SyncJoinParams{Invite: "secretvault-sync:?url=https://x&vault=v&code=c", Name: "evil"})
			return err
		}(),
		"sync status": func() error { _, err := app.SyncStatus(ctx(t), ""); return err }(),
	} {
		if !errors.Is(err, svrpc.ErrDenied) {
			t.Errorf("%s from another program: %v", what, err)
		}
	}
	if h.desk.count() != 0 {
		t.Fatal("refusing asked the desktop anyway")
	}
}

func TestJoiningNeedsAnEmptyFolderAndAWorkingInvite(t *testing.T) {
	srv := newSyncServer(t)
	a, b := newHarness(t), newHarness(t)
	ca := a.setup()
	if _, err := ca.SyncSetup(ctx(t), svrpc.SyncSetupParams{URL: srv.url, Fingerprint: "00" + srv.fp[2:], AdminToken: adminToken}); err == nil || !strings.Contains(err.Error(), "pinned") {
		t.Fatalf("a wrong pin: %v", err)
	}
	if _, err := ca.SyncSetup(ctx(t), svrpc.SyncSetupParams{URL: srv.url, Fingerprint: srv.fp, AdminToken: "wrong"}); err == nil {
		t.Fatal("a wrong admin token made a vault")
	}
	if _, err := ca.SyncSetup(ctx(t), svrpc.SyncSetupParams{URL: srv.url, Fingerprint: srv.fp, AdminToken: adminToken}); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.SyncSetup(ctx(t), svrpc.SyncSetupParams{URL: srv.url, Fingerprint: srv.fp, AdminToken: adminToken}); !errors.Is(err, svrpc.ErrExists) {
		t.Fatalf("setting up twice: %v", err)
	}
	inv, err := ca.SyncInvite(ctx(t), "")
	if err != nil {
		t.Fatal(err)
	}
	cb := b.connect("/usr/bin/secretvault", &scripted{})
	full := filepath.Join(t.TempDir(), "full")
	os.MkdirAll(full, 0o700)
	os.WriteFile(filepath.Join(full, "something"), []byte("x"), 0o600)
	if _, err := cb.SyncJoin(ctx(t), svrpc.SyncJoinParams{Invite: inv.Invite, Name: "shared", Path: full}); !errors.Is(err, svrpc.ErrExists) {
		t.Fatalf("joining into a full folder: %v", err)
	}
	if _, err := cb.SyncJoin(ctx(t), svrpc.SyncJoinParams{Invite: "not an invite", Name: "shared"}); err == nil {
		t.Fatal("a bad invite was accepted")
	}
	if _, err := cb.SyncJoin(ctx(t), svrpc.SyncJoinParams{Invite: inv.Invite, Name: "shared"}); err != nil {
		t.Fatal(err)
	}
	// The code works once.
	c2 := newHarness(t).connect("/usr/bin/secretvault", &scripted{})
	if _, err := c2.SyncJoin(ctx(t), svrpc.SyncJoinParams{Invite: inv.Invite, Name: "again"}); err == nil {
		t.Fatal("an invite worked twice")
	}
}

func TestAVaultInASyncedFolderSeesOtherDevicesWrites(t *testing.T) {
	a, b := newHarness(t), newHarness(t)
	folder := filepath.Join(t.TempDir(), "Sync", "personal")
	ca := a.connect("/usr/bin/secretvault", &scripted{})
	if _, err := ca.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "personal", Path: folder, Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	// The other device sees the same folder, as Syncthing would give it.
	cb := b.connect("/usr/bin/secretvault", &scripted{})
	if _, err := cb.AddVault(ctx(t), "personal", folder); err != nil {
		t.Fatal(err)
	}
	if _, err := cb.Unlock(ctx(t), "", &svrpc.Key{Type: "passphrase", Secret: pass}); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Put(ctx(t), "", login("web/forum", "from-a")); err != nil {
		t.Fatal(err)
	}
	if s, err := getSecret(cb, "", "web/forum"); err != nil || s != "from-a" {
		t.Fatalf("the other device's write: %q, %v", s, err)
	}

	// A rotation there locks the vault here; the next request asks for
	// the new passphrase, on the terminal that made it.
	newPass := []byte("a new passphrase for everyone")
	if _, err := ca.Rotate(ctx(t), svrpc.RotateParams{Passphrase: newPass}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(1100 * time.Millisecond) // past the once-a-second refresh
	term := &scripted{}
	term.script("pass:" + string(newPass))
	cb2 := b.connect("/usr/bin/secretvault", term)
	if s, err := getSecret(cb2, "", "web/forum"); err != nil || s != "from-a" {
		t.Fatalf("after the rotation: %q, %v", s, err)
	}
	term.done(t)
}

func TestAttachedFilesSyncWithTheirItems(t *testing.T) {
	_, _, _, ca, cb := twoDevices(t)
	data := bytes.Repeat([]byte("scan"), 50000)
	if _, err := ca.Attach(ctx(t), svrpc.FileAttachParams{Item: "mail/imap", Name: "scan.png", Type: "image/png", Data: data}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the file reaching the other device", func() error {
		fd, err := cb.File(context.Background(), "shared", "mail/imap", "scan.png")
		if err == nil && !bytes.Equal(fd.Data, data) {
			err = errors.New("different contents")
		}
		return err
	})
}
