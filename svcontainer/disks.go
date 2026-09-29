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
	ours            bool   // attached by this user
	uuid            string // the LUKS UUID udev read from the attached image
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
		s := Status{Image: l.BackingFile, Attached: true, loop: l.Path, ours: l.SetupByUID == uid, uuid: l.IDUUID}
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
	ctx, cancel := patient(ctx)
	defer cancel()
	if err := CheckFormat(fstype, label); err != nil {
		return Status{}, err
	}
	s, f, done, err := d.prepare(ctx, path, key)
	if err != nil || done {
		if done {
			err = fmt.Errorf("%s is already open; a new container is never open", s.Image)
		}
		return s, err
	}
	defer f.Close()
	s, undo, err := d.attach(ctx, f, s.Image, key)
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
	ctx, cancel := patient(ctx)
	defer cancel()
	s, f, done, err := d.prepare(ctx, path, key)
	if err != nil || done {
		return s, err
	}
	defer f.Close()
	s, undo, err := d.attach(ctx, f, s.Image, key)
	if err != nil {
		return s, err
	}
	if s.MountPoint, err = d.mount(ctx, s, mountOptions); err != nil {
		undo()
		return s, err
	}
	return d.refresh(ctx, s), nil
}

// prepare opens and checks the image (see openChecked), and looks at what
// is attached already: the image itself, or another file with its LUKS
// UUID (a copy, a hard link, the same file through a bind mount).
//
//   - This image, attached by this user and mounted: done, it is open.
//   - This image attached by this user otherwise (locked, or unlocked but
//     not mounted, after a crash or an unmount done elsewhere): taken
//     down, to be attached again from the file just checked.
//   - Anything else with this UUID unlocked (by another user, or from
//     another path): refused, as two unlocked mappings of one filesystem
//     corrupt it.
//   - Other locked attachments are left alone: the kernel reads nothing
//     through them.
//
// Otherwise it returns the open file, which the caller attaches and closes.
func (d *Disks) prepare(ctx context.Context, path string, key []byte) (Status, *os.File, bool, error) {
	want := Canonical(path)
	f, h, err := openChecked(path, key)
	if err != nil {
		return Status{Image: want}, nil, false, err
	}
	all, err := d.All(ctx)
	if err != nil {
		f.Close()
		return Status{Image: want}, nil, false, err
	}
	// Mounted ones first, so that a stale attachment is never taken down
	// when this image is in fact open.
	slices.SortStableFunc(all, func(a, b Status) int { return boolRank(b.Mounted()) - boolRank(a.Mounted()) })
	for _, s := range all {
		same := s.Image == want
		switch {
		case same && s.ours && s.Mounted():
			f.Close()
			return s, nil, true, nil
		case same && s.ours:
			d.teardown(s)
			continue
		case !s.Unlocked || !same && s.uuid != h.UUID():
			continue
		case same:
			err = fmt.Errorf("%s is already unlocked by another user", want)
		default:
			err = fmt.Errorf("a container with the same LUKS UUID (%s) is already unlocked from %s; close it first", h.UUID(), s.Image)
		}
		f.Close()
		return s, nil, false, err
	}
	return Status{Image: want}, f, false, nil
}

// attach attaches the open image and unlocks it; undo takes both back.
// The descriptor handed to UDisks2 is the one whose header was checked,
// so the kernel reads the file that was checked, not whatever the path
// names by then.
func (d *Disks) attach(ctx context.Context, f *os.File, image string, key []byte) (Status, func(), error) {
	s := Status{Image: image}
	var err error
	if s.loop, err = d.ud.LoopSetup(ctx, f); err != nil {
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
	ctx, cancel := patient(ctx)
	defer cancel()
	all, err := d.All(ctx)
	if err != nil {
		return Status{}, err
	}
	want := Canonical(target)
	// Every attachment of ours the target names (a stale one may sit
	// beside the open one), the mounted first.
	var mine []Status
	for _, s := range all {
		if s.ours && (s.Image == want || s.MountPoint != "" && (s.MountPoint == want || s.MountPoint == filepath.Clean(target))) {
			mine = append(mine, s)
		}
	}
	if len(mine) == 0 {
		return Status{Image: want}, ErrNotOpen
	}
	slices.SortStableFunc(mine, func(a, b Status) int { return boolRank(b.Mounted()) - boolRank(a.Mounted()) })
	var closed Status
	for i, s := range mine {
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
		if i == 0 {
			closed = s
		}
	}
	return closed, nil
}

func boolRank(b bool) int {
	if b {
		return 1
	}
	return 0
}

// patient gives calls to UDisks2 room for a polkit password prompt, or
// for making a large filesystem: a context with no deadline would get
// svdbus's default of 25 seconds a call.
func patient(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, 5*time.Minute)
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
