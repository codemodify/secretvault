//go:build linux

package svfido

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The device nodes here are files in a temporary directory: tests never
// open a real /dev/hidraw node.
func TestANodeWeMayNotOpenSaysHowToFixIt(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root opens anything")
	}
	class, dev := fakeSysfs(t, map[string][2]string{
		"hidraw4": {yubikeyDescriptor, "HID_NAME=Yubico YubiKey FIDO\n"},
	})
	infos, err := enumerate(class, dev)
	if err != nil || len(infos) != 1 {
		t.Fatalf("enumerate = %v, %v", infos, err)
	}
	if err := os.WriteFile(infos[0].Path, nil, 0o000); err != nil {
		t.Fatal(err)
	}
	_, err = openTransport(infos[0])
	var pe *PermissionError
	if !errors.As(err, &pe) || !errors.Is(err, os.ErrPermission) {
		t.Fatalf("opening a root-only node: %v", err)
	}
	msg := err.Error()
	for _, want := range []string{"Yubico YubiKey FIDO at " + infos[0].Path, "udev", "60-fido-id.rules", "libfido2", "plug it in again"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the message lacks %q:\n%s", want, msg)
		}
	}
}

func TestANodeThatIsNotADeviceIsRefused(t *testing.T) {
	p := filepath.Join(t.TempDir(), "hidraw9")
	if err := os.WriteFile(p, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openTransport(DeviceInfo{Path: p}); err == nil || !strings.Contains(err.Error(), "not a device") {
		t.Fatalf("a regular file: %v", err)
	}
}
