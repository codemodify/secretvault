package secretvault

import (
	"context"

	"github.com/codemodify/secretvault/svrpc"
)

// Devices lists the devices registered in a vault.
func (c *Client) Devices(ctx context.Context, vault string) (out []svrpc.Device, err error) {
	err = c.conn.Call(ctx, svrpc.MDeviceList, svrpc.VaultRef{Vault: vault}, &out)
	return
}

// LabelDevice gives a device of a vault a new label; device "" is this
// one.
func (c *Client) LabelDevice(ctx context.Context, vault, device, label string) (out svrpc.Device, err error) {
	err = c.conn.Call(ctx, svrpc.MDeviceLabel, svrpc.DeviceLabelParams{Vault: vault, Device: device, Label: label}, &out)
	return
}

// RemoveDevice marks a device removed from a vault.
func (c *Client) RemoveDevice(ctx context.Context, vault, device string) (out svrpc.Device, err error) {
	err = c.conn.Call(ctx, svrpc.MDeviceRemove, svrpc.DeviceRef{Vault: vault, Device: device}, &out)
	return
}

// VouchDevice records that this device vouches for another of a vault's
// devices, or (withdraw) no longer does.
func (c *Client) VouchDevice(ctx context.Context, vault, device string, withdraw bool) (out svrpc.Device, err error) {
	err = c.conn.Call(ctx, svrpc.MDeviceVouch, svrpc.DeviceVouchParams{Vault: vault, Device: device, Withdraw: withdraw}, &out)
	return
}

// Signatures reads a vault's policy on signatures, or with require set,
// changes it.
func (c *Client) Signatures(ctx context.Context, vault string, require *bool) (out svrpc.SignaturePolicy, err error) {
	err = c.conn.Call(ctx, svrpc.MVaultSignatures, svrpc.SignaturesParams{Vault: vault, Require: require}, &out)
	return
}
