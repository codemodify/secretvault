package svmanager

import (
	"context"
	"fmt"
	"io"
	"os"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Files attached to items: saving one to disk, attaching one, removing
// one. Contents go between the disk and the daemon in byte slices, which
// are wiped once written. The item shows its files as they are once the
// daemon says the item changed (item.changed), as it does for any change.

// pickFile asks for a file to read, a file to save to, or a folder, and
// calls done with its path, or "" for none. It returns a function that
// takes the question down unanswered, for a caller that goes away first.
func (m *Manager) pickFile(mode PickMode, suggested string, done func(string)) (cancel func()) {
	if m.opts.PickFile != nil {
		m.opts.PickFile(mode, suggested, done)
		return func() {}
	}
	home, _ := os.UserHomeDir()
	opts := widgets.FileDialogOptions{Path: home, OnPick: done, OnCancel: func() { done("") }}
	switch mode {
	case PickSave:
		opts.Mode = widgets.FileSave
		opts.Name = suggested
		opts.Title = "Save " + suggested
	case PickFolder:
		opts.Mode = widgets.FileOpenFolder
		opts.Title = "Choose a folder"
	default:
		opts.Mode = widgets.FileOpen
		opts.Title = "Choose a file"
	}
	widgets.ShowFileDialog(m.root(), opts)
	shown := m.win.Overlay()
	return func() {
		// That dialog, wherever it is in the stack, and nothing else.
		if shown != nil {
			widget.DismissOverlay(shown)
		}
	}
}

// saveFile writes an item's file to disk, where the person says.
func (m *Manager) saveFile(item, name string) {
	vault := m.vault
	m.pickFile(PickSave, name, func(path string) {
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

// writeFile puts data at path in a file only its owner can read
// (svops.WriteReplacing, as the CLI writes what it must not leave half
// written). It is written beside path under another name and then renamed
// over it, so a file that was there is replaced whole, mode and all,
// rather than truncated and left as readable as it was. The file dialog
// has asked before a file is replaced.
func writeFile(path string, data []byte) error { return svops.WriteReplacing(path, data, 0o600) }

// attachFile attaches a file from disk to an item, replacing one of the
// same name. It is read as the CLI's attach reads it
// (svops.ReadAttachment): under its own name, with the media type of its
// extension.
func (m *Manager) attachFile(item string) {
	vault := m.vault
	m.pickFile(PickOpen, "", func(path string) {
		if path == "" {
			return
		}
		name := ""
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			p, err := svops.ReadAttachment(path, nil, "", "")
			if err != nil {
				return err
			}
			defer clear(p.Data)
			p.Vault, p.Item, name = vault, item, p.Name
			_, err = c.Attach(ctx, p)
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Attached %s to %s.", name, item)
		})
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
	m.confirm("Remove "+name+"?", svops.RemoveFileText(name, item), svops.RemoveFileAction, func() {
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
