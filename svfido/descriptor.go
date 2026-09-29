package svfido

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Finding FIDO devices among the HID devices. A FIDO device's report
// descriptor opens an application collection with usage page 0xF1D0
// (FIDO Alliance) and usage 0x01 (CTAPHID), and its reports are 64 bytes
// (CTAP 2.1 §11.2.8.1). The descriptor is readable by everyone in sysfs,
// so a key is found, and named, even when its /dev node is root's.

const (
	fidoUsagePage = 0xF1D0
	fidoUsage     = 0x01
)

// hidDescriptor is what matters about a report descriptor.
type hidDescriptor struct {
	fido          bool // a top-level CTAPHID application collection
	input, output int  // report sizes in bytes (the largest seen)
}

// parseDescriptor walks HID report descriptor items (HID 1.11 §6.2.2).
// It reads what a FIDO check needs: usage pages and usages up to the
// first top-level collection, and report sizes.
func parseDescriptor(d []byte) (hidDescriptor, error) {
	var out hidDescriptor
	var page, usage uint32
	var haveUsage bool
	var reportSize, reportCount uint32
	depth := 0
	for len(d) > 0 {
		prefix := d[0]
		if prefix == 0xFE { // a long item: skipped
			if len(d) < 3 || len(d) < 3+int(d[1]) {
				return out, errors.New("svfido: a truncated long item in a report descriptor")
			}
			d = d[3+int(d[1]):]
			continue
		}
		size := int(prefix & 0x03)
		if size == 3 {
			size = 4
		}
		if len(d) < 1+size {
			return out, errors.New("svfido: a truncated report descriptor")
		}
		var v uint32
		for i := size; i >= 1; i-- {
			v = v<<8 | uint32(d[i])
		}
		d = d[1+size:]
		kind, tag := (prefix>>2)&0x03, prefix>>4
		switch kind {
		case 1: // global
			switch tag {
			case 0x0: // Usage Page
				page = v
			case 0x7: // Report Size, in bits
				reportSize = v
			case 0x9: // Report Count
				reportCount = v
			}
		case 2: // local
			if tag == 0x0 && !haveUsage { // Usage; the first one names the collection
				usage, haveUsage = v, true
				if size == 4 { // an extended usage carries its own page
					usage = v & 0xFFFF
					page = v >> 16
				}
			}
		case 0: // main
			switch tag {
			case 0xA: // Collection
				if depth == 0 && v == 0x01 && page == fidoUsagePage && haveUsage && usage == fidoUsage {
					out.fido = true
				}
				depth++
			case 0xC: // End Collection
				depth = max(depth-1, 0)
			case 0x8: // Input
				out.input = max(out.input, int(reportSize*reportCount/8))
			case 0x9: // Output
				out.output = max(out.output, int(reportSize*reportCount/8))
			}
			haveUsage = false // local items last until the next main item
		}
	}
	return out, nil
}

// DeviceInfo describes a FIDO device found on this machine.
type DeviceInfo struct {
	Path    string // the device node: /dev/hidrawN
	Name    string // the product's name, as the kernel knows it
	Vendor  uint16 // USB vendor ID
	Product uint16 // USB product ID
}

func (i DeviceInfo) String() string {
	if i.Name != "" {
		return i.Name
	}
	return i.Path
}

// enumerate finds FIDO devices in a sysfs hidraw class directory
// (/sys/class/hidraw), naming their nodes under dev (/dev). It reads
// files only; the devices themselves are not opened.
func enumerate(class, dev string) ([]DeviceInfo, error) {
	entries, err := os.ReadDir(class)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil // no HID devices at all
	}
	if err != nil {
		return nil, err
	}
	var out []DeviceInfo
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "hidraw") {
			continue
		}
		if _, err := strconv.Atoi(strings.TrimPrefix(name, "hidraw")); err != nil {
			continue
		}
		desc, err := os.ReadFile(filepath.Join(class, name, "device", "report_descriptor"))
		if err != nil || len(desc) > 4096 {
			continue
		}
		hd, err := parseDescriptor(desc)
		if err != nil || !hd.fido {
			continue
		}
		if hd.input != ReportSize || hd.output != ReportSize {
			// CTAPHID over other report sizes exists on paper only.
			continue
		}
		info := DeviceInfo{Path: filepath.Join(dev, name)}
		readUevent(filepath.Join(class, name, "device", "uevent"), &info)
		out = append(out, info)
	}
	sort.Slice(out, func(i, j int) bool { return natural(out[i].Path) < natural(out[j].Path) })
	return out, nil
}

// natural sorts hidraw2 before hidraw10.
func natural(p string) string {
	i := strings.LastIndexFunc(p, func(r rune) bool { return r < '0' || r > '9' })
	n, _ := strconv.Atoi(p[i+1:])
	return fmt.Sprintf("%s%010d", p[:i+1], n)
}

// readUevent fills in the name and USB IDs from a HID device's uevent:
//
//	HID_ID=0003:00001050:00000407
//	HID_NAME=Yubico YubiKey OTP+FIDO+CCID
func readUevent(path string, info *DeviceInfo) {
	b, err := os.ReadFile(path)
	if err != nil || len(b) > 64<<10 {
		return
	}
	sc := bufio.NewScanner(bytes.NewReader(b))
	for sc.Scan() {
		k, v, _ := strings.Cut(sc.Text(), "=")
		switch k {
		case "HID_NAME":
			info.Name = strings.Map(func(r rune) rune {
				if r < 0x20 || r == 0x7f {
					return -1
				}
				return r
			}, v)
		case "HID_ID":
			parts := strings.Split(v, ":")
			if len(parts) == 3 {
				if n, err := strconv.ParseUint(parts[1], 16, 32); err == nil {
					info.Vendor = uint16(n)
				}
				if n, err := strconv.ParseUint(parts[2], 16, 32); err == nil {
					info.Product = uint16(n)
				}
			}
		}
	}
}
