package svcontainer

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"time"

	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svudisks"
)

// ErrNoMount is an operating system where secretvault cannot mount
// containers yet.
var ErrNoMount = fmt.Errorf("mounting containers on %s comes in a later release; for now secretvault mounts them on Linux", osName())

// ErrNotOpen is closing a container that is not open.
var ErrNotOpen = errors.New("that container is not open")

func osName() string {
	if runtime.GOOS == "darwin" {
		return "macOS"
	}
	return runtime.GOOS
}

// Disks mounts containers with the OS's own tools: on Linux, UDisks2.
type Disks struct {
	ud *svudisks.Client
}

// ConnectDisks reaches the OS's disk service, or returns ErrNoMount.
func ConnectDisks() (*Disks, error) {
	if runtime.GOOS != "linux" {
		return nil, ErrNoMount
	}
	ud, err := svudisks.Connect()
	if err != nil {
		return nil, err
	}
	return &Disks{ud: ud}, nil
}

// Close closes the connection.
func (d *Disks) Close() error { return d.ud.Close() }

// Done is closed when the connection is gone.
func (d *Disks) Done() <-chan struct{} { return d.ud.Done() }

// Status is where an image is: attached as a disk, unlocked, mounted.
type Status struct {
	Image      string
	Attached   bool
	Unlocked   bool
	MountPoint string
	Device     string // the decrypted device, /dev/dm-N

	loop, cleartext svdbus.ObjectPath
	ours            bool // attached by this user
}

// Mounted reports whether the image's filesystem is mounted.
func (s Status) Mounted() bool { return s.MountPoint != "" }

// Canonical is a path as the kernel reports a loop device's file: absolute,
// with no symbolic links (in as much of it as exists).
func Canonical(path string) string {
	abs, err := filepath.Abs(path)
	if err != nil {
		return filepath.Clean(path)
	}
	if real, err := filepath.EvalSymlinks(abs); err == nil {
		return real
	}
	if dir, err := filepath.EvalSymlinks(filepath.Dir(abs)); err == nil {
		return filepath.Join(dir, filepath.Base(abs))
	}
	return abs
}

// All is the status of every image attached as a disk.
func (d *Disks) All(ctx context.Context) ([]Status, error) {
	devs, err := d.ud.Devices(ctx)
	if err != nil {
		return nil, err
	}
	uid := uint32(os.Getuid())
	var out []Status
	for _, l := range devs {
		if !l.IsLoop || l.BackingFile == "" {
			continue
		}
		s := Status{Image: l.BackingFile, Attached: true, loop: l.Path, ours: l.SetupByUID == uid}
		for _, c := range devs {
			if c.CryptoBacking == l.Path {
				s.Unlocked, s.cleartext, s.Device = true, c.Path, c.Device
				if len(c.MountPoints) > 0 {
					s.MountPoint = c.MountPoints[0]
				}
			}
		}
		out = append(out, s)
	}
	return out, nil
}

// Status is the status of the image at path.
func (d *Disks) Status(ctx context.Context, path string) (Status, error) {
	all, err := d.All(ctx)
	if err != nil {
		return Status{}, err
	}
	want := Canonical(path)
	for _, s := range all {
		if s.Image == want {
			return s, nil
		}
	}
	return Status{Image: want}, nil
}

// Format attaches a new image, unlocks it with key, makes a filesystem of
// type fstype on it and mounts it. take-ownership makes the person the
// owner of the new filesystem's root, where the filesystem has owners.
func (d *Disks) Format(ctx context.Context, path string, key []byte, fstype, label, mountOptions string) (Status, error) {
	if err := CheckFormat(fstype, label); err != nil {
		return Status{}, err
	}
	s, undo, err := d.attach(ctx, path, key)
	if err != nil {
		return s, err
	}
	owned := fstype != "vfat" && fstype != "exfat"
	if err := d.ud.Format(ctx, s.cleartext, fstype, svudisks.FormatOptions{Label: label, TakeOwnership: owned}); err != nil {
		undo()
		return s, err
	}
	if s.MountPoint, err = d.mount(ctx, s, mountOptions); err != nil {
		undo()
		return s, err
	}
	return d.refresh(ctx, s), nil
}

// Mount attaches the image, unlocks it with key and mounts its filesystem,
// taking up from wherever it is: an image already mounted is left as it is.
func (d *Disks) Mount(ctx context.Context, path string, key []byte, mountOptions string) (Status, error) {
	s, err := d.Status(ctx, path)
	if err != nil {
		return s, err
	}
	if s.Mounted() {
		return s, nil
	}
	undo := func() {}
	switch {
	case !s.Attached:
		if s, undo, err = d.attach(ctx, path, key); err != nil {
			return s, err
		}
	case !s.Unlocked:
		if s.cleartext, err = d.ud.Unlock(ctx, s.loop, key); err != nil {
			return s, err
		}
		s.Unlocked = true
		undo = func() {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			d.ud.Lock(ctx, s.loop)
		}
	}
	if s.MountPoint, err = d.mount(ctx, s, mountOptions); err != nil {
		undo()
		return s, err
	}
	return d.refresh(ctx, s), nil
}

// attach attaches and unlocks an image; undo takes both back.
func (d *Disks) attach(ctx context.Context, path string, key []byte) (Status, func(), error) {
	s := Status{Image: Canonical(path)}
	f, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return s, nil, err
	}
	s.loop, err = d.ud.LoopSetup(ctx, f)
	f.Close()
	if err != nil {
		return s, nil, err
	}
	s.Attached, s.ours = true, true
	if s.cleartext, err = d.ud.Unlock(ctx, s.loop, key); err != nil {
		d.teardown(s)
		return s, nil, err
	}
	s.Unlocked = true
	return s, func() { d.teardown(s) }, nil
}

// mount mounts the unlocked device. A desktop that automounts new disks
// (gvfs, udiskie) may have got there first: then where it mounted it is
// the answer.
func (d *Disks) mount(ctx context.Context, s Status, options string) (string, error) {
	mp, err := d.ud.Mount(ctx, s.cleartext, options)
	var ue *svudisks.Error
	if errors.As(err, &ue) && ue.Name == svudisks.ErrorAlreadyMounted {
		if now, serr := d.Status(ctx, s.Image); serr == nil && now.Mounted() {
			return now.MountPoint, nil
		}
	}
	return mp, err
}

// refresh fills in what UDisks2 knows after a change (the device name).
func (d *Disks) refresh(ctx context.Context, s Status) Status {
	if now, err := d.Status(ctx, s.Image); err == nil && now.Attached {
		return now
	}
	return s
}

// Unmount unmounts, locks and detaches an image named by its path or its
// mount point. Only images this user attached are touched.
func (d *Disks) Unmount(ctx context.Context, target string) (Status, error) {
	all, err := d.All(ctx)
	if err != nil {
		return Status{}, err
	}
	want := Canonical(target)
	i := slices.IndexFunc(all, func(s Status) bool {
		return s.ours && (s.Image == want || s.MountPoint != "" && (s.MountPoint == want || s.MountPoint == filepath.Clean(target)))
	})
	if i < 0 {
		return Status{Image: want}, ErrNotOpen
	}
	s := all[i]
	if s.Mounted() {
		if err := d.ud.Unmount(ctx, s.cleartext); err != nil {
			return s, err
		}
		s.MountPoint = ""
	}
	if s.Unlocked {
		if err := d.ud.Lock(ctx, s.loop); err != nil {
			return s, err
		}
		s.Unlocked, s.Device = false, ""
	}
	if err := d.ud.DeleteLoop(ctx, s.loop); err != nil {
		return s, err
	}
	s.Attached = false
	return s, nil
}

// teardown undoes a half-made attachment, on its own deadline: the
// request's may be what ran out.
func (d *Disks) teardown(s Status) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if s.Unlocked {
		d.ud.Lock(ctx, s.loop)
	}
	d.ud.DeleteLoop(ctx, s.loop)
}
