package svd

import (
	"context"
	"errors"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

func init() {
	registerMethod(svrpc.MItemRestore, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.RestoreParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		// A live item is changed, and asked about as that item; a deleted
		// one is made again, as a write to the vault.
		mv, e, err := d.item(ctx, cl, p.Vault, p.Name, svbroker.OpWrite)
		if errors.Is(err, svcore.ErrNotFound) {
			mv, err = d.managed(ctx, cl, p.Vault, "", p.Name, svbroker.OpWrite)
		} else if err == nil {
			e.Item.Wipe()
		}
		if err != nil {
			return nil, err
		}
		out, err := mv.v.Restore(p.Name, p.Rev)
		if err != nil {
			return nil, err
		}
		defer out.Item.Wipe()
		d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name, Item: out.Item.Name})
		return toEntry(out, false), nil
	})
	registerMethod(svrpc.MItemDeleted, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.ListParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpList)
		if err != nil {
			return nil, err
		}
		del, err := mv.v.Deleted(p.Prefix)
		if err != nil {
			return nil, err
		}
		out := []svrpc.DeletedItem{}
		for _, x := range del {
			out = append(out, svrpc.DeletedItem{ID: x.ID.String(), Name: x.Name, Kind: x.Kind, Rev: x.Rev.String(), Deleted: x.Deleted})
		}
		return out, nil
	})
}
