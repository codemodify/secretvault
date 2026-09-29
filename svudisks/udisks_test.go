package svudisks_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/internal/dbustest"
	"github.com/codemodify/secretvault/internal/udiskstest"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svluks"
	"github.com/codemodify/secretvault/svudisks"
)

// Every test here talks to udiskstest's pretend UDisks2 on a private bus:
// no loop device, dm-crypt mapping or mount is ever made.

func ctx(t *testing.T) context.Context {
	c, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	t.Cleanup(cancel)
	return c
}

// image makes a LUKS2 image that opens with key.
func image(t *testing.T, key []byte) (string, *os.File) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "c.img")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	f.Truncate(svluks.DataOffset + 1<<20)
	_, vk, err := svluks.Format(f, key, svluks.Options{KDF: svluks.KeyKDF})
	if err != nil {
		t.Fatal(err)
	}
	vk.Destroy()
	return p, f
}

func TestAttachUnlockFormatMount(t *testing.T) {
	fake := udiskstest.Start(t)
	c, err := svudisks.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	key := []byte("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	path, f := image(t, key)

	loop, err := c.LoopSetup(ctx(t), f)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Unlock(ctx(t), loop, []byte("not the key")); err == nil || !strings.Contains(err.Error(), "unlocking the container: Error unlocking") {
		t.Fatalf("a wrong key: %v", err)
	}
	clear, err := c.Unlock(ctx(t), loop, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Format(ctx(t), clear, "ext4", svudisks.FormatOptions{Label: "Stuff", TakeOwnership: true}); err != nil {
		t.Fatal(err)
	}
	mp, err := c.Mount(ctx(t), clear, "noexec")
	if err != nil {
		t.Fatal(err)
	}
	st, _ := fake.Image(path)
	if st.FSType != "ext4" || st.Label != "Stuff" || !st.Owned || st.MountPoint != mp || st.MountOptions != "noexec" {
		t.Fatalf("the fake saw %+v", st)
	}

	devs, err := c.Devices(ctx(t))
	if err != nil {
		t.Fatal(err)
	}
	var sawLoop, sawClear bool
	for _, d := range devs {
		switch d.Path {
		case loop:
			sawLoop = d.IsLoop && d.IsEncrypted && d.BackingFile == path && d.Cleartext == clear && d.SetupByUID == uint32(os.Getuid()) && d.Device == "/dev/loop0"
		case clear:
			sawClear = d.CryptoBacking == loop && d.HasFilesystem && slices.Equal(d.MountPoints, []string{mp}) && d.IDType == "ext4" && d.IDLabel == "Stuff"
		}
	}
	if !sawLoop || !sawClear {
		t.Fatalf("devices: %+v", devs)
	}

	// Busy and out-of-order refusals come back as plain errors.
	if err := c.Lock(ctx(t), loop); !errors.Is(err, svudisks.ErrBusy) {
		t.Fatalf("locking while mounted: %v", err)
	}
	if err := c.Unmount(ctx(t), clear); err != nil {
		t.Fatal(err)
	}
	if err := c.Lock(ctx(t), loop); err != nil {
		t.Fatal(err)
	}
	if err := c.DeleteLoop(ctx(t), loop); err != nil {
		t.Fatal(err)
	}
	if len(fake.Attached()) != 0 {
		t.Fatalf("still attached: %+v", fake.Attached())
	}
}

func TestErrorsInPlainWords(t *testing.T) {
	fake := udiskstest.Start(t)
	c, err := svudisks.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, f := image(t, []byte("k"))
	for _, e := range []struct {
		name, want string
		is         error
	}{
		{svudisks.ErrorNotAuthorized, "attaching the image as a disk: not authorized: your session is not active", svudisks.ErrNotAuthorized},
		{svudisks.ErrorNotAuthorizedDismiss, "not authorized: the password prompt was dismissed", svudisks.ErrNotAuthorized},
		{svudisks.ErrorNotAuthorizedObtain, "polkit wants an administrator's password", svudisks.ErrNotAuthorized},
		{svudisks.ErrorFailed, "attaching the image as a disk: something broke", nil},
	} {
		fake.Fail("LoopSetup", e.name, "something broke")
		_, err := c.LoopSetup(ctx(t), f)
		var ue *svudisks.Error
		if err == nil || !strings.Contains(err.Error(), e.want) || !errors.As(err, &ue) || e.is != nil && !errors.Is(err, e.is) {
			t.Errorf("%s: %v", e.name, err)
		}
	}
}

func TestNotRunning(t *testing.T) {
	dbustest.PrivateBus(t) // a bus with no UDisks2 on it
	c, err := svudisks.Connect()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, err = c.Devices(ctx(t))
	if !errors.Is(err, svudisks.ErrNotRunning) || !strings.Contains(err.Error(), "UDisks2 is not running") {
		t.Fatalf("no UDisks2: %v", err)
	}
	var ue *svudisks.Error
	if !errors.As(err, &ue) || ue.Name != svdbus.ErrorServiceUnknown {
		t.Fatalf("error %#v", err)
	}
}
