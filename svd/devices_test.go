package svd

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// thisDevice is the entry for the asking daemon's own device.
func thisDevice(t *testing.T, cli *secretvault.Client, vault string) svrpc.Device {
	t.Helper()
	devs, err := cli.Devices(ctx(t), vault)
	if err != nil {
		t.Fatal(err)
	}
	for _, d := range devs {
		if d.This {
			return d
		}
	}
	t.Fatalf("this device is not registered: %+v", devs)
	return svrpc.Device{}
}

func TestTheDaemonRegistersItselfAndSignsWhatItWrites(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	me := thisDevice(t, cli, "")
	host, _ := os.Hostname()
	if me.Label != host || me.Device != h.d.svOpts.Device.String() || me.Key != h.d.svOpts.Signer.ID().String() || !me.Vouched {
		t.Fatalf("this device: %+v", me)
	}
	if fi, err := os.Stat(filepath.Join(h.home, svcore.DeviceKeyFile)); err != nil || (runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600) {
		t.Fatalf("the device key file: %v", err)
	}
	e, err := cli.Get(ctx(t), "", "mail/imap")
	if err != nil {
		t.Fatal(err)
	}
	if s := e.Signature; s.Status != svrpc.SigVerified || !s.Mine || s.Key != me.Key || s.Label != host {
		t.Fatalf("the item's signature: %+v", s)
	}
	hist, err := cli.History(ctx(t), "", "mail/imap")
	if err != nil || len(hist) != 1 || hist[0].Signature.Status != svrpc.SigVerified {
		t.Fatalf("history: %+v, %v", hist, err)
	}

	// Across a restart the key, and so the registration, stay.
	h.restart()
	cli = h.connect("/usr/bin/secretvault", &scripted{})
	if _, err := cli.Unlock(ctx(t), "", &svrpc.Key{Type: "passphrase", Secret: pass}); err != nil {
		t.Fatal(err)
	}
	if again := thisDevice(t, cli, ""); again.Key != me.Key {
		t.Fatalf("the key changed across a restart: %s, then %s", me.Key, again.Key)
	}
	if devs, _ := cli.Devices(ctx(t), ""); len(devs) != 1 {
		t.Fatalf("the device registered twice: %+v", devs)
	}

	// Naming, and the policy.
	if d, err := cli.LabelDevice(ctx(t), "", "", "laptop"); err != nil || d.Label != "laptop" || !d.This {
		t.Fatalf("label: %+v, %v", d, err)
	}
	if _, err := cli.VouchDevice(ctx(t), "", me.Key, false); err == nil {
		t.Fatal("the device vouched for itself")
	}
	if _, err := cli.RemoveDevice(ctx(t), "", ""); err == nil {
		t.Fatal("removing no device worked")
	}
	if _, err := cli.RemoveDevice(ctx(t), "", "ffffffff"); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("removing a device that is not there: %v", err)
	}
	yes := true
	if p, err := cli.Signatures(ctx(t), "", &yes); err != nil || !p.Require || p.Vault != "personal" {
		t.Fatalf("requiring signatures: %+v, %v", p, err)
	}
	if _, err := cli.Put(ctx(t), "", login("under/policy", "x")); err != nil {
		t.Fatalf("a write under the policy: %v", err)
	}
	if p, err := cli.Signatures(ctx(t), "", nil); err != nil || !p.Require {
		t.Fatalf("the policy: %+v, %v", p, err)
	}
}

// Two daemons share a vault through a sync server: each registers itself
// and signs its writes, and each one's writes are attributed to it on the
// other.
func TestTwoDaemonsAttributeEachOthersWrites(t *testing.T) {
	_, a, b, ca, cb := twoDevices(t)
	keyA, keyB := a.d.svOpts.Signer.ID().String(), b.d.svOpts.Signer.ID().String()
	if keyA == keyB {
		t.Fatal("the two daemons have the same key")
	}
	if _, err := cb.Put(ctx(t), "shared", login("web/forum", "from-b")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "b's signed write reaching a", func() error {
		e, err := ca.Get(ctx(t), "", "web/forum")
		if err != nil {
			return err
		}
		if s := e.Signature; s.Status != svrpc.SigVerified || s.Key != keyB || s.Mine || s.Device != b.d.svOpts.Device.String() {
			return fmt.Errorf("signature %+v", s)
		}
		return nil
	})
	e, err := cb.Get(ctx(t), "shared", "mail/imap")
	if err != nil || e.Signature.Key != keyA || e.Signature.Status != svrpc.SigVerified || e.Signature.Mine {
		t.Fatalf("a's item on b: %+v, %v", e.Signature, err)
	}

	// A names B's device, and vouches for it; B hears the name.
	if d, err := ca.LabelDevice(ctx(t), "", keyB[:10], "desktop"); err != nil || d.Label != "desktop" || d.This {
		t.Fatalf("labelling b from a: %+v, %v", d, err)
	}
	if d, err := ca.VouchDevice(ctx(t), "", keyB, false); err != nil || !d.Vouched {
		t.Fatalf("vouching for b: %+v, %v", d, err)
	}
	eventually(t, "the label reaching b", func() error {
		if d := thisDevice(t, cb, "shared"); d.Label != "desktop" {
			return fmt.Errorf("b calls itself %q", d.Label)
		}
		return nil
	})
	eventually(t, "b's write, on a, from a vouched-for device", func() error {
		e, err := ca.Get(ctx(t), "", "web/forum")
		if err == nil && (!e.Signature.Vouched || e.Signature.Label != "desktop") {
			err = fmt.Errorf("signature %+v", e.Signature)
		}
		return err
	})

	// A requires signatures; B's writes still count, as they are signed.
	yes := true
	if _, err := ca.Signatures(ctx(t), "", &yes); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the policy reaching b", func() error {
		p, err := cb.Signatures(ctx(t), "shared", nil)
		if err == nil && !p.Require {
			err = errors.New("not yet")
		}
		return err
	})
	if _, err := cb.Put(ctx(t), "shared", login("web/after-policy", "from-b")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "b's write under the policy reaching a", func() error {
		_, err := ca.Get(ctx(t), "", "web/after-policy")
		return err
	})

	// A removes B: B's writes still verify, marked as a removed device's.
	if d, err := ca.RemoveDevice(ctx(t), "", keyB); err != nil || !d.Removed {
		t.Fatalf("removing b: %+v, %v", d, err)
	}
	if e, err := ca.Get(ctx(t), "", "web/after-policy"); err != nil || !e.Signature.Removed || e.Signature.Status != svrpc.SigVerified {
		t.Fatalf("b's write after b was removed: %+v, %v", e.Signature, err)
	}
	if rep, err := ca.Verify(ctx(t), ""); err != nil || len(rep.Problems) != 0 {
		t.Fatalf("verify: %+v, %v", rep, err)
	}
}
