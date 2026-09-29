package svmanager

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svrpc"
)

// Files attached to items: saving one to disk, attaching one, removing
// one. Contents go between the disk and the daemon in byte slices, which
// are wiped once written.

// pickFile asks for a file to save to (save) or to read, and calls done
// with its path, or "" for none.
func (m *Manager) pickFile(save bool, suggested string, done func(string)) {
	if m.opts.PickFile != nil {
		m.opts.PickFile(save, suggested, done)
		return
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

// writeFile writes data to a new file only its owner can read, replacing
// what was there.
func writeFile(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
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
			defer clear(data)
			_, err := c.Attach(ctx, svrpc.FileAttachParams{Vault: vault, Item: item, Name: name, Data: data})
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Attached %s to %s.", name, item)
			m.afterFiles(vault, item)
		})
	})
}

// readFile reads a file to attach, no larger than one message can carry.
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
			m.afterFiles(vault, item)
		})
	})
}

// afterFiles shows an item whose files changed as it is now. The daemon
// says item.changed too, but only once the list is current.
func (m *Manager) afterFiles(vault, item string) {
	if vault != m.vault {
		return
	}
	if m.cur != nil && m.cur.Item.Name == item {
		m.reopen()
	}
	m.loadItems()
}
