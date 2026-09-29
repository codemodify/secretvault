package svstore

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Dir is a Backend on a local directory. Files are written with mode 0600
// and directories 0700. Writes go to a temporary file in the same
// directory, are synced, and are then linked (Create) or renamed (Write)
// into place, so a crash leaves either the old state or the new one.
type Dir struct {
	root string
}

// tmpPrefix marks files that are still being written. List skips them.
const tmpPrefix = ".tmp-"

// OpenDir uses root as a Backend, creating it (0700) if needed.
func OpenDir(root string) (*Dir, error) {
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	return &Dir{root: root}, nil
}

// Root is the directory the backend stores into.
func (d *Dir) Root() string { return d.root }

func (d *Dir) path(name string) (string, error) {
	if err := CheckName(name); err != nil {
		return "", err
	}
	return filepath.Join(d.root, filepath.FromSlash(name)), nil
}

// writeTemp writes data to a synced temporary file beside p.
func writeTemp(p string, data []byte) (string, error) {
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return "", err
	}
	f, err := os.CreateTemp(filepath.Dir(p), tmpPrefix+"*")
	if err != nil {
		return "", err
	}
	tmp := f.Name()
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Chmod(tmp, 0o600)
	}
	if err != nil {
		os.Remove(tmp)
		return "", err
	}
	return tmp, nil
}

func (d *Dir) Create(name string, data []byte) error {
	p, err := d.path(name)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(p); err == nil {
		return ErrExist
	}
	tmp, err := writeTemp(p, data)
	if err != nil {
		return err
	}
	defer os.Remove(tmp)
	// A hard link fails if the name is taken, which makes Create atomic and
	// exclusive at once.
	if err := os.Link(tmp, p); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return ErrExist
		}
		// Filesystems without hard links (FAT, some network mounts): fall
		// back to an exclusive create. Readers treat a torn file as a bad
		// checksum, never as data.
		return createExclusive(p, data)
	}
	syncDir(filepath.Dir(p))
	return nil
}

func createExclusive(p string, data []byte) error {
	f, err := os.OpenFile(p, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return ErrExist
	}
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}

func (d *Dir) Write(name string, data []byte) error {
	p, err := d.path(name)
	if err != nil {
		return err
	}
	tmp, err := writeTemp(p, data)
	if err != nil {
		return err
	}
	if err := os.Rename(tmp, p); err != nil {
		os.Remove(tmp)
		return err
	}
	syncDir(filepath.Dir(p))
	return nil
}

func (d *Dir) Read(name string) ([]byte, error) {
	p, err := d.path(name)
	if err != nil {
		return nil, err
	}
	b, err := os.ReadFile(p)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotExist
	}
	return b, err
}

func (d *Dir) List(dir string) ([]string, error) {
	start := d.root
	if dir != "" {
		p, err := d.path(dir)
		if err != nil {
			return nil, err
		}
		start = p
	}
	var names []string
	err := filepath.WalkDir(start, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) && p == start {
				return filepath.SkipAll
			}
			return err
		}
		if !e.Type().IsRegular() || strings.HasPrefix(e.Name(), ".") {
			return nil
		}
		rel, err := filepath.Rel(d.root, p)
		if err != nil {
			return err
		}
		names = append(names, filepath.ToSlash(rel))
		return nil
	})
	sort.Strings(names)
	return names, err
}

func (d *Dir) Remove(name string) error {
	p, err := d.path(name)
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	return nil
}
