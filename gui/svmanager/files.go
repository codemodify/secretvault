package svmanager

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svrpc"
)

// Files attached to items: saving one to disk, attaching one, removing
// one. Contents go between the disk and the daemon in byte slices, which
// are wiped once written. The item shows its files as they are once the
// daemon says the item changed (item.changed), as it does for any change.

// pickFile asks for a file to save to (save) or to read, and calls done
// with its path, or "" for none. It returns a function that takes the
// question down unanswered, for a caller that goes away first.
func (m *Manager) pickFile(save bool, suggested string, done func(string)) (cancel func()) {
	if m.opts.PickFile != nil {
		m.opts.PickFile(save, suggested, done)
		return func() {}
	}
	home, _ := os.UserHomeDir()
	opts := widgets.FileDialogOptions{Path: home, OnPick: done, OnCancel: func() { done("") }}
	if save {
		opts.Mode = widgets.FileSave
		opts.Name = suggested
		opts.Title = "Save " + suggested
	} else {
		opts.Mode = widgets.FileOpen
		opts.Title = "Choose a file"
	}
	widgets.ShowFileDialog(m.root(), opts)
	shown := m.win.Overlay()
	return func() {
		if shown != nil && m.win.Overlay() == shown {
			widget.DismissOverlay(m.root())
		}
	}
}

// saveFile writes an item's file to disk, where the person says.
func (m *Manager) saveFile(item, name string) {
	vault := m.vault
	m.pickFile(true, name, func(path string) {
		if path == "" {
			return
		}
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			fd, err := c.File(ctx, vault, item, name)
			if err != nil {
				return err
			}
			defer clear(fd.Data)
			return writeFile(path, fd.Data)
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Saved %s to %s.", name, path)
		})
	})
}

// writeFile puts data at path in a file only its owner can read. It is
// written beside path under another name and then renamed over it, so a
// file that was there is replaced whole, mode and all, rather than
// truncated and left as readable as it was.
func writeFile(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	ok := false
	defer func() {
		if !ok {
			f.Close()
			os.Remove(tmp)
		}
	}()
	if err := f.Chmod(0o600); err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	ok = true
	return nil
}

// attachFile attaches a file from disk to an item, replacing one of the
// same name.
func (m *Manager) attachFile(item string) {
	vault := m.vault
	m.pickFile(false, "", func(path string) {
		if path == "" {
			return
		}
		data, err := readFile(path)
		if err != nil {
			m.fail(err)
			return
		}
		name := filepath.Base(path)
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			_, err := c.Attach(ctx, svrpc.FileAttachParams{Vault: vault, Item: item, Name: name, Data: data})
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Attached %s to %s.", name, item)
		}, data)
	})
}

// readFile reads a file, no larger than one message can carry, into bytes
// the caller wipes.
func readFile(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, svrpc.MaxFileData+1))
	if err != nil {
		clear(data)
		return nil, err
	}
	if len(data) > svrpc.MaxFileData {
		clear(data)
		return nil, fmt.Errorf("that file is larger than the %d MiB secretvault takes in one piece", svrpc.MaxFileData>>20)
	}
	return data, nil
}

// removeFile removes a file from an item, after asking.
func (m *Manager) removeFile(item, name string) {
	vault := m.vault
	m.confirm("Remove "+name+"?", fmt.Sprintf("Remove %s from %s?\n\nEarlier revisions of the item keep it.", name, item), "Remove", func() {
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			_, err := c.Detach(ctx, vault, item, name)
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Removed %s from %s.", name, item)
		})
	})
}
