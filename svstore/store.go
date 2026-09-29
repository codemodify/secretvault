// Package svstore is where a vault's files live. A Backend stores opaque,
// already-encrypted files by name; it never sees a key or a plaintext, so
// it may be a local directory, a synced folder, or (later) a remote server
// that is not trusted with the contents.
//
// Almost everything a vault writes is written once and never changed
// (keyslots and revisions), which is what Create is for. Only the vault
// descriptor is ever replaced, with Write.
package svstore

import (
	"errors"
	"fmt"
	"path"
	"strings"
)

// Backend stores a vault's files.
type Backend interface {
	// Create stores a new file, and fails with ErrExist if one is already
	// there. The file appears whole or not at all.
	Create(name string, data []byte) error

	// Write stores or replaces a file atomically.
	Write(name string, data []byte) error

	// Read returns a file's contents, or ErrNotExist.
	Read(name string) ([]byte, error)

	// List returns the names of all files under dir ("" for all), sorted.
	List(dir string) ([]string, error)

	// Remove deletes a file. Removing a missing file is not an error.
	Remove(name string) error
}

var (
	ErrExist    = errors.New("svstore: file already exists")
	ErrNotExist = errors.New("svstore: file does not exist")
	ErrName     = errors.New("svstore: invalid file name")
)

// CheckName accepts the names secretvault writes: slash-separated, relative,
// clean, and made of letters, digits, '.', '-' and '_'. Anything else is
// refused before it can reach a filesystem.
func CheckName(name string) error {
	if name == "" || strings.HasPrefix(name, "/") || path.Clean(name) != name {
		return fmt.Errorf("%w: %q", ErrName, name)
	}
	for _, part := range strings.Split(name, "/") {
		if part == "" || part == "." || part == ".." || strings.HasPrefix(part, ".") {
			return fmt.Errorf("%w: %q", ErrName, name)
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '.' || r == '-' || r == '_') {
				return fmt.Errorf("%w: %q", ErrName, name)
			}
		}
	}
	return nil
}
