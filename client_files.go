package secretvault

import (
	"context"

	"github.com/codemodify/secretvault/svrpc"
)

// Attach attaches a file to an item, replacing one of the same name.
func (c *Client) Attach(ctx context.Context, p svrpc.FileAttachParams) (out svrpc.Entry, err error) {
	err = c.conn.Call(ctx, svrpc.MFileAttach, p, &out)
	return
}

// File returns an attached file and its contents.
func (c *Client) File(ctx context.Context, vault, item, name string) (out svrpc.FileData, err error) {
	err = c.conn.Call(ctx, svrpc.MFileGet, svrpc.FileRef{Vault: vault, Item: item, Name: name}, &out)
	return
}

// Detach removes an attached file from an item.
func (c *Client) Detach(ctx context.Context, vault, item, name string) (out svrpc.Entry, err error) {
	err = c.conn.Call(ctx, svrpc.MFileRemove, svrpc.FileRef{Vault: vault, Item: item, Name: name}, &out)
	return
}
