package secretvault

import (
	"context"

	"github.com/codemodify/secretvault/svrpc"
)

// SyncSetup makes a vault on a sync server from this device's copy, and
// keeps the two in step from then on.
func (c *Client) SyncSetup(ctx context.Context, p svrpc.SyncSetupParams) (out svrpc.SyncStatus, err error) {
	err = c.conn.Call(ctx, svrpc.MSyncSetup, p, &out)
	return
}

// SyncJoin fetches a vault from a sync server with an invite, and
// registers it on this device. It arrives locked.
func (c *Client) SyncJoin(ctx context.Context, p svrpc.SyncJoinParams) (out svrpc.VaultInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MSyncJoin, p, &out)
	return
}

// SyncInvite makes a one-time invite for another device to join a synced
// vault.
func (c *Client) SyncInvite(ctx context.Context, vault string) (out svrpc.SyncInvite, err error) {
	err = c.conn.Call(ctx, svrpc.MSyncInvite, svrpc.VaultRef{Vault: vault}, &out)
	return
}

// SyncStatus says how one synced vault, or ("") every one, is doing.
func (c *Client) SyncStatus(ctx context.Context, vault string) (out []svrpc.SyncStatus, err error) {
	err = c.conn.Call(ctx, svrpc.MSyncStatus, svrpc.VaultRef{Vault: vault}, &out)
	return
}

// SyncNow syncs a vault and waits for it.
func (c *Client) SyncNow(ctx context.Context, vault string) (out svrpc.SyncStatus, err error) {
	err = c.conn.Call(ctx, svrpc.MSyncNow, svrpc.VaultRef{Vault: vault}, &out)
	return
}

// SyncDevices lists the devices enrolled in a synced vault.
func (c *Client) SyncDevices(ctx context.Context, vault string) (out []svrpc.SyncDevice, err error) {
	err = c.conn.Call(ctx, svrpc.MSyncDevices, svrpc.VaultRef{Vault: vault}, &out)
	return
}

// SyncRemove removes another device from a synced vault on the server.
func (c *Client) SyncRemove(ctx context.Context, vault, key string) error {
	return c.conn.Call(ctx, svrpc.MSyncRemove, svrpc.SyncRemoveParams{Vault: vault, Key: key}, nil)
}

// SyncOff stops syncing a vault. The server's copy is left as it is.
func (c *Client) SyncOff(ctx context.Context, vault string) error {
	return c.conn.Call(ctx, svrpc.MSyncOff, svrpc.VaultRef{Vault: vault}, nil)
}
