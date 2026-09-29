package svd

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// Attachments: reading a file is reading its item, and attaching or
// removing one is changing it, with the same consent.

func fileInfo(f svcore.File) svrpc.FileInfo {
	return svrpc.FileInfo{Name: f.Name, Type: f.Type, Size: f.Size, SHA256: hex.EncodeToString(f.Hash)}
}

func fileErr(err error) error {
	if errors.Is(err, svcore.ErrNoFile) {
		return svrpc.Errorf(svrpc.CodeNotFound, "%s", strings.TrimPrefix(err.Error(), "svcore: "))
	}
	return err
}

func init() {
	registerMethod(svrpc.MFileAttach, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.FileAttachParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		defer clear(p.Data)
		mv, e, err := d.item(ctx, cl, p.Vault, p.Item, svbroker.OpWrite)
		if err != nil {
			return nil, err
		}
		e.Item.Wipe()
		out, err := mv.v.Attach(p.Item, p.Name, p.Type, p.Data)
		if err != nil {
			return nil, fileErr(err)
		}
		defer out.Item.Wipe()
		d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: p.Item})
		return toEntry(out, false), nil
	})
	registerMethod(svrpc.MFileGet, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.FileRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, e, err := d.item(ctx, cl, p.Vault, p.Item, svbroker.OpRead)
		if err != nil {
			return nil, err
		}
		e.Item.Wipe()
		f, data, err := mv.v.ReadFile(p.Item, p.Name)
		if err != nil {
			return nil, fileErr(err)
		}
		if len(data) > svrpc.MaxFileData {
			clear(data)
			return nil, svrpc.Errorf(svrpc.CodeFailed, "%s is too large to send in one piece (%d bytes)", p.Name, len(data))
		}
		return svrpc.FileData{FileInfo: fileInfo(f), Data: data}, nil
	})
	registerMethod(svrpc.MFileRemove, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.FileRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, e, err := d.item(ctx, cl, p.Vault, p.Item, svbroker.OpWrite)
		if err != nil {
			return nil, err
		}
		e.Item.Wipe()
		out, err := mv.v.Detach(p.Item, p.Name)
		if err != nil {
			return nil, fileErr(err)
		}
		defer out.Item.Wipe()
		d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: p.Item})
		return toEntry(out, false), nil
	})
}
