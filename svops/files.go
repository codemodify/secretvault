package svops

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"mime"
	"os"
	"path/filepath"

	"github.com/codemodify/secretvault/svrpc"
)

// Files as every interface reads and writes them: secrets without their
// final newline, new files that never replace an old one, and results
// that appear only once they are whole.

// WriteNew creates a file that must not exist yet, mode 0600.
func WriteNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		// It was made here: a part of a secret is not left behind.
		os.Remove(path)
	}
	return err
}

// WriteReplacing writes a file through a temporary one beside it, so it
// is never seen half written.
func WriteReplacing(path string, data []byte, mode fs.FileMode) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".secretvault-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if err == nil {
		err = tmp.Chmod(mode)
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// ReadSecretFile reads a secret from a file, without its final newline.
func ReadSecretFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return TrimNewline(b), nil
}

// TrimNewline drops one final newline (\n or \r\n).
func TrimNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

// ReadFileLimit reads a file of at most max bytes.
func ReadFileLimit(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		clear(b)
		return nil, fmt.Errorf("%s is larger than %d MiB", path, max>>20)
	}
	return b, nil
}

// ReadAttachment reads a file to attach to an item (svrpc.FileAttachParams
// without its vault and item): from path, or from stdin when path is "-",
// which then needs a name. The name defaults to the file's own, and the
// media type to its extension's. The caller clears Data.
func ReadAttachment(path string, stdin io.Reader, name, typ string) (svrpc.FileAttachParams, error) {
	var data []byte
	var err error
	if path == "-" {
		if name == "" {
			return svrpc.FileAttachParams{}, errors.New("a file from standard input needs --name")
		}
		data, err = io.ReadAll(io.LimitReader(stdin, svrpc.MaxFileData+1))
	} else {
		if name == "" {
			name = filepath.Base(path)
		}
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return svrpc.FileAttachParams{}, err
	}
	if len(data) > svrpc.MaxFileData {
		clear(data)
		return svrpc.FileAttachParams{}, fmt.Errorf("that file is larger than the %d MiB secretvault takes in one piece", svrpc.MaxFileData>>20)
	}
	if typ == "" {
		typ = mime.TypeByExtension(filepath.Ext(name))
	}
	return svrpc.FileAttachParams{Name: name, Type: typ, Data: data}, nil
}

// SaveFile writes an attachment's data to path: a new file (mode 0600),
// or, with force, over one that is there.
func SaveFile(path string, data []byte, force bool) error {
	if force {
		return os.WriteFile(path, data, 0o600)
	}
	if err := WriteNew(path, data); errors.Is(err, os.ErrExist) {
		return fmt.Errorf("%s exists (use --force to overwrite it, or -o)", path)
	} else if err != nil {
		return err
	}
	return nil
}

// AtomicFile is a file that appears under its name only when the whole
// of it has been written (Commit), so that a failed decryption leaves
// neither part of the plaintext nor a clobbered file.
type AtomicFile struct {
	*os.File
	path string
	done bool
}

// CreateAtomic starts writing path, with mode, in a temporary file beside
// it.
func CreateAtomic(path string, mode os.FileMode) (*AtomicFile, error) {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return nil, err
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		os.Remove(f.Name())
		return nil, err
	}
	return &AtomicFile{File: f, path: path}, nil
}

// Commit puts the file in place.
func (a *AtomicFile) Commit() error {
	if a.done {
		return nil
	}
	a.done = true
	if err := a.File.Close(); err != nil {
		os.Remove(a.File.Name())
		return err
	}
	if err := os.Rename(a.File.Name(), a.path); err != nil {
		os.Remove(a.File.Name())
		return err
	}
	return nil
}

// CommitNew puts the file in place only if nothing is at its name: a file
// that appeared while it was being written is never replaced (Commit
// replaces one). It fails with an error satisfying errors.Is(err,
// fs.ErrExist) when something is there.
func (a *AtomicFile) CommitNew() error {
	if a.done {
		return nil
	}
	a.done = true
	tmp := a.File.Name()
	defer os.Remove(tmp)
	if err := a.File.Close(); err != nil {
		return err
	}
	err := os.Link(tmp, a.path)
	if err == nil || errors.Is(err, fs.ErrExist) {
		return err
	}
	// No hard links here: the next best, a check just before the rename.
	if _, lerr := os.Lstat(a.path); lerr == nil {
		return &fs.PathError{Op: "create", Path: a.path, Err: fs.ErrExist}
	}
	return os.Rename(tmp, a.path)
}

// Abort throws the file away, unless it was committed.
func (a *AtomicFile) Abort() {
	if !a.done {
		a.done = true
		a.File.Close()
		os.Remove(a.File.Name())
	}
}
