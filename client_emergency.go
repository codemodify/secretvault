package secretvault

import (
	"context"

	"github.com/codemodify/secretvault/svrpc"
)

// EmergencyGrant lets a person you trust open a vault after a waiting
// period, unless you deny it first. It returns the invite to send them.
func (c *Client) EmergencyGrant(ctx context.Context, p svrpc.EmergencyGrantParams) (out svrpc.EmergencyGrantResult, err error) {
	err = c.conn.Call(ctx, svrpc.MEmergencyGrant, p, &out)
	return
}

// EmergencyList lists a vault's grants ("" for the default vault) and the
// access this device holds to other people's vaults.
func (c *Client) EmergencyList(ctx context.Context, vault string) (out svrpc.EmergencyList, err error) {
	err = c.conn.Call(ctx, svrpc.MEmergencyList, svrpc.VaultRef{Vault: vault}, &out)
	return
}

// EmergencyDeny refuses a pending request for emergency access.
func (c *Client) EmergencyDeny(ctx context.Context, vault, grant string) (out svrpc.EmergencyGrant, err error) {
	err = c.conn.Call(ctx, svrpc.MEmergencyDeny, svrpc.EmergencyRef{Vault: vault, Grant: grant}, &out)
	return
}

// EmergencyRevoke ends a grant: on the server, its keyslot, and the
// vault's record of it. It returns the grant as it was; if it had been
// released, rotate the vault key to cut the trustee off.
func (c *Client) EmergencyRevoke(ctx context.Context, vault, grant string) (out svrpc.EmergencyGrant, err error) {
	err = c.conn.Call(ctx, svrpc.MEmergencyRevoke, svrpc.EmergencyRef{Vault: vault, Grant: grant}, &out)
	return
}

// EmergencyAccept accepts an invite to emergency access, with the
// identity it was granted to.
func (c *Client) EmergencyAccept(ctx context.Context, p svrpc.EmergencyAcceptParams) (out svrpc.EmergencyAccess, err error) {
	err = c.conn.Call(ctx, svrpc.MEmergencyAccept, p, &out)
	return
}

// EmergencyRequest asks for emergency access: the wait starts.
func (c *Client) EmergencyRequest(ctx context.Context, name string) (out svrpc.EmergencyAccess, err error) {
	err = c.conn.Call(ctx, svrpc.MEmergencyRequest, svrpc.EmergencyAccessRef{Name: name}, &out)
	return
}

// EmergencyOpen fetches and opens a vault with emergency access, once
// the wait is over.
func (c *Client) EmergencyOpen(ctx context.Context, p svrpc.EmergencyOpenParams) (out svrpc.VaultInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MEmergencyOpen, p, &out)
	return
}
