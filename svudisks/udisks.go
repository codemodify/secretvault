// Package svudisks drives UDisks2, the disk service of Linux desktops,
// over the system bus with our own D-Bus code (svdbus): attaching an image
// file as a loop device, unlocking the LUKS volume on it with the kernel's
// dm-crypt, formatting and mounting what that reveals, and undoing each
// step. It is the route file managers take for USB drives, so polkit lets
// the person at an active session do all of it without an administrator's
// password, and nothing here runs as root.
//
// Keys go to UDisks as the keyfile_contents option (bytes), never as a
// passphrase string, and nothing is ever asked on a terminal. Errors from
// UDisks and polkit come back as *Error, in plain words.
package svudisks

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svdbus"
)

// UDisks2's names on the bus.
const (
	Service         = "org.freedesktop.UDisks2"
	RootPath        = svdbus.ObjectPath("/org/freedesktop/UDisks2")
	ManagerPath     = svdbus.ObjectPath("/org/freedesktop/UDisks2/Manager")
	IfaceManager    = "org.freedesktop.UDisks2.Manager"
	IfaceBlock      = "org.freedesktop.UDisks2.Block"
	IfaceLoop       = "org.freedesktop.UDisks2.Loop"
	IfaceEncrypted  = "org.freedesktop.UDisks2.Encrypted"
	IfaceFilesystem = "org.freedesktop.UDisks2.Filesystem"
	objectManager   = "org.freedesktop.DBus.ObjectManager"
)

// Client talks to UDisks2.
type Client struct {
	bus *svdbus.Conn
	own bool
}

// Connect connects to UDisks2 on the system bus.
func Connect() (*Client, error) {
	bus, err := svdbus.ConnectSystem(svdbus.WithMaxMessageSize(16 << 20))
	if err != nil {
		return nil, fmt.Errorf("svudisks: the system bus: %w", err)
	}
	if !bus.CanPassFDs() {
		bus.Close()
		return nil, errors.New("svudisks: the system bus does not pass file descriptors, which attaching an image needs")
	}
	return &Client{bus: bus, own: true}, nil
}

// New uses a connection the caller made (and closes).
func New(bus *svdbus.Conn) *Client { return &Client{bus: bus} }

// Close closes the connection Connect made.
func (c *Client) Close() error {
	if c.own {
		return c.bus.Close()
	}
	return nil
}

// Done is closed when the connection is gone.
func (c *Client) Done() <-chan struct{} { return c.bus.Done() }

// Device is one of UDisks2's block devices, and what it knows of it.
type Device struct {
	Path   svdbus.ObjectPath
	Device string // /dev/loop0, /dev/dm-3

	// Loop devices: the file behind it, and who attached it.
	IsLoop      bool
	BackingFile string
	SetupByUID  uint32

	// Encrypted devices: the unlocked device on top ("/" when locked).
	IsEncrypted bool
	Cleartext   svdbus.ObjectPath

	// Unlocked devices: the encrypted device under them ("/" otherwise).
	CryptoBacking svdbus.ObjectPath

	// What blkid found on it.
	IDUsage, IDType, IDLabel, IDUUID string

	// Filesystems: where it is mounted, if anywhere.
	HasFilesystem bool
	MountPoints   []string
}

// Devices lists every block device UDisks2 knows.
func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	reply, err := c.bus.Call(ctx, Service, RootPath, objectManager, "GetManagedObjects")
	if err != nil {
		return nil, explain("listing the disks", err)
	}
	var objs map[svdbus.ObjectPath]map[string]map[string]svdbus.Variant
	if err := reply.Decode(&objs); err != nil {
		return nil, fmt.Errorf("svudisks: UDisks2 listed its disks in an unexpected form: %w", err)
	}
	var out []Device
	for path, ifaces := range objs {
		block, ok := ifaces[IfaceBlock]
		if !ok {
			continue
		}
		d := Device{Path: path, Device: bytesProp(block, "Device"), CryptoBacking: pathProp(block, "CryptoBackingDevice"),
			IDUsage: strProp(block, "IdUsage"), IDType: strProp(block, "IdType"), IDLabel: strProp(block, "IdLabel"), IDUUID: strProp(block, "IdUUID")}
		if loop, ok := ifaces[IfaceLoop]; ok {
			d.IsLoop, d.BackingFile = true, bytesProp(loop, "BackingFile")
			loop["SetupByUID"].Store(&d.SetupByUID)
		}
		if enc, ok := ifaces[IfaceEncrypted]; ok {
			d.IsEncrypted, d.Cleartext = true, pathProp(enc, "CleartextDevice")
		}
		if fs, ok := ifaces[IfaceFilesystem]; ok {
			d.HasFilesystem = true
			var mps [][]byte
			fs["MountPoints"].Store(&mps)
			for _, mp := range mps {
				d.MountPoints = append(d.MountPoints, strings.TrimRight(string(mp), "\x00"))
			}
		}
		out = append(out, d)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out, nil
}

func strProp(props map[string]svdbus.Variant, name string) string {
	var s string
	props[name].Store(&s)
	return s
}

func pathProp(props map[string]svdbus.Variant, name string) svdbus.ObjectPath {
	var p svdbus.ObjectPath
	if props[name].Store(&p) != nil || p == "" {
		return "/"
	}
	return p
}

// bytesProp reads a NUL-terminated byte-string property (ay), as UDisks2
// gives file names.
func bytesProp(props map[string]svdbus.Variant, name string) string {
	var b []byte
	props[name].Store(&b)
	return strings.TrimRight(string(b), "\x00")
}

func noOptions() map[string]svdbus.Variant { return map[string]svdbus.Variant{} }

// LoopSetup attaches an image file as a loop device, passing UDisks2 the
// open file (so it needs no access to the file's path), and returns the
// loop device. Partitions are not scanned for: an image holds one volume.
func (c *Client) LoopSetup(ctx context.Context, f *os.File) (svdbus.ObjectPath, error) {
	opts := map[string]svdbus.Variant{"no-part-scan": svdbus.MakeVariant(true)}
	reply, err := c.bus.Call(ctx, Service, ManagerPath, IfaceManager, "LoopSetup", svdbus.UnixFD(f.Fd()), opts)
	if err != nil {
		return "", explain("attaching the image as a disk", err)
	}
	var loop svdbus.ObjectPath
	if err := reply.Decode(&loop); err != nil {
		return "", fmt.Errorf("svudisks: LoopSetup answered %v", reply.Body)
	}
	return loop, nil
}

// Unlock unlocks the LUKS volume on dev with key, given as the
// keyfile_contents option, and returns the unlocked (cleartext) device.
func (c *Client) Unlock(ctx context.Context, dev svdbus.ObjectPath, key []byte) (svdbus.ObjectPath, error) {
	opts := map[string]svdbus.Variant{"keyfile_contents": {Signature: "ay", Value: key}}
	reply, err := c.bus.Call(ctx, Service, dev, IfaceEncrypted, "Unlock", "", opts)
	if err != nil {
		return "", explain("unlocking the container", err)
	}
	var cleartext svdbus.ObjectPath
	if err := reply.Decode(&cleartext); err != nil {
		return "", fmt.Errorf("svudisks: Unlock answered %v", reply.Body)
	}
	return cleartext, nil
}

// Lock locks the LUKS volume on dev (the encrypted device, not the
// cleartext one).
func (c *Client) Lock(ctx context.Context, dev svdbus.ObjectPath) error {
	_, err := c.bus.Call(ctx, Service, dev, IfaceEncrypted, "Lock", noOptions())
	return explain("locking the container", err)
}

// FormatOptions shape a new filesystem.
type FormatOptions struct {
	Label string

	// TakeOwnership makes the person asking the owner of the new
	// filesystem's root directory. Only filesystems with owners (ext4,
	// btrfs, ...) take it; FAT and exFAT are mounted as their user instead.
	TakeOwnership bool
}

// Format makes a filesystem of type fstype (ext4, exfat, vfat, btrfs, ...)
// on dev, erasing what was there.
func (c *Client) Format(ctx context.Context, dev svdbus.ObjectPath, fstype string, o FormatOptions) error {
	opts := noOptions()
	if o.Label != "" {
		opts["label"] = svdbus.MakeVariant(o.Label)
	}
	if o.TakeOwnership {
		opts["take-ownership"] = svdbus.MakeVariant(true)
	}
	_, err := c.bus.Call(ctx, Service, dev, IfaceBlock, "Format", fstype, opts)
	return explain("making the "+fstype+" filesystem", err)
}

// Mount mounts the filesystem on dev where UDisks2 mounts removable disks
// (/run/media/USER/LABEL) and returns that place. options are mount
// options ("ro,noexec"), from those UDisks2 allows.
//
// A filesystem that was just made or unlocked may take a moment to be
// seen (udev probes it), so a device not yet known to hold one is retried
// for a few seconds.
func (c *Client) Mount(ctx context.Context, dev svdbus.ObjectPath, options string) (string, error) {
	opts := noOptions()
	if options != "" {
		opts["options"] = svdbus.MakeVariant(options)
	}
	for try := 0; ; try++ {
		reply, err := c.bus.Call(ctx, Service, dev, IfaceFilesystem, "Mount", opts)
		var de *svdbus.Error
		if err != nil && errors.As(err, &de) && try < 20 &&
			(de.Name == svdbus.ErrorUnknownMethod || de.Name == svdbus.ErrorUnknownInterface || de.Name == svdbus.ErrorUnknownObject) {
			select {
			case <-ctx.Done():
				return "", explain("mounting it", err)
			case <-time.After(250 * time.Millisecond):
			}
			continue
		}
		if err != nil {
			return "", explain("mounting it", err)
		}
		var mp string
		if err := reply.Decode(&mp); err != nil {
			return "", fmt.Errorf("svudisks: Mount answered %v", reply.Body)
		}
		return mp, nil
	}
}

// Unmount unmounts the filesystem on dev.
func (c *Client) Unmount(ctx context.Context, dev svdbus.ObjectPath) error {
	_, err := c.bus.Call(ctx, Service, dev, IfaceFilesystem, "Unmount", noOptions())
	return explain("unmounting it", err)
}

// DeleteLoop detaches a loop device from its file.
func (c *Client) DeleteLoop(ctx context.Context, dev svdbus.ObjectPath) error {
	_, err := c.bus.Call(ctx, Service, dev, IfaceLoop, "Delete", noOptions())
	return explain("detaching the image", err)
}
