package svfido

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A YubiKey 5's FIDO interface, as the kernel exposes it.
const yubikeyDescriptor = "06 d0 f1 09 01 a1 01 09 20 15 00 26 ff 00 75 08 95 40 81 02 09 21 15 00 26 ff 00 75 08 95 40 91 02 c0"

// A mouse: generic desktop page, no FIDO collection.
const mouseDescriptor = "05 01 09 02 a1 01 09 01 a1 00 05 09 19 01 29 05 15 00 25 01 75 01 95 05 81 02 75 03 95 01 81 01 c0 c0"

func TestFIDODescriptorsAreRecognised(t *testing.T) {
	for name, tc := range map[string]struct {
		desc      string
		fido      bool
		in, out   int
		wantError bool
	}{
		"a YubiKey": {desc: yubikeyDescriptor, fido: true, in: 64, out: 64},
		"a mouse":   {desc: mouseDescriptor},
		"an extended usage": {
			// Usage 0xF1D00001 in four bytes, carrying its own page.
			desc: "0b 01 00 d0 f1 a1 01 75 08 95 40 81 02 91 02 c0", fido: true, in: 64, out: 64,
		},
		"a FIDO page nested inside another collection": {
			desc: "05 01 09 02 a1 01 06 d0 f1 09 01 a1 01 c0 c0",
		},
		"a long item is skipped": {
			desc: "fe 02 10 aa bb " + yubikeyDescriptor, fido: true, in: 64, out: 64,
		},
		"truncated":             {desc: "06 d0", wantError: true},
		"a truncated long item": {desc: "fe 05 10 aa", wantError: true},
	} {
		d, err := parseDescriptor(mustHex(t, tc.desc))
		if (err != nil) != tc.wantError {
			t.Errorf("%s: error %v", name, err)
			continue
		}
		if err == nil && (d.fido != tc.fido || (tc.fido && (d.input != tc.in || d.output != tc.out))) {
			t.Errorf("%s: %+v", name, d)
		}
	}
}

// fakeSysfs builds /sys/class/hidraw and /dev in a temporary directory.
func fakeSysfs(t *testing.T, devices map[string][2]string) (class, dev string) {
	t.Helper()
	root := t.TempDir()
	class, dev = filepath.Join(root, "sys", "class", "hidraw"), filepath.Join(root, "dev")
	for name, d := range devices {
		dir := filepath.Join(class, name, "device")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dir, "report_descriptor"), mustHex(t, d[0]), 0o444)
		os.WriteFile(filepath.Join(dir, "uevent"), []byte(d[1]), 0o444)
	}
	os.MkdirAll(dev, 0o755)
	return class, dev
}

func TestSecurityKeysAreFoundInSysfs(t *testing.T) {
	class, dev := fakeSysfs(t, map[string][2]string{
		"hidraw0":  {mouseDescriptor, "HID_ID=0003:0000046D:0000C077\nHID_NAME=Logitech Mouse\n"},
		"hidraw10": {yubikeyDescriptor, "DRIVER=hid-generic\nHID_ID=0003:00001050:00000407\nHID_NAME=Yubico YubiKey OTP+FIDO+CCID\nHID_PHYS=usb-0000:00:14.0-2/input1\n"},
		"hidraw2":  {yubikeyDescriptor, "HID_ID=0003:000020A0:000042B1\nHID_NAME=Nitrokey \x1b[31mFIDO2\n"},
		// 32-byte reports: CTAPHID on paper only.
		"hidraw3":    {"06 d0 f1 09 01 a1 01 75 08 95 20 81 02 91 02 c0", "HID_NAME=Odd\n"},
		"notahidraw": {yubikeyDescriptor, ""},
	})
	got, err := enumerate(class, dev)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("found %+v", got)
	}
	nitro, yubi := got[0], got[1]
	if nitro.Path != filepath.Join(dev, "hidraw2") || nitro.Name != "Nitrokey [31mFIDO2" || nitro.Vendor != 0x20a0 || nitro.Product != 0x42b1 {
		t.Fatalf("first: %+v (control characters must not reach a terminal)", nitro)
	}
	if yubi.Path != filepath.Join(dev, "hidraw10") || yubi.Name != "Yubico YubiKey OTP+FIDO+CCID" || yubi.Vendor != 0x1050 || yubi.Product != 0x0407 {
		t.Fatalf("second: %+v", yubi)
	}
	if none, err := enumerate(filepath.Join(t.TempDir(), "missing"), dev); err != nil || len(none) != 0 {
		t.Fatalf("no hidraw class at all: %v, %v", none, err)
	}
}
