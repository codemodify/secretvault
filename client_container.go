package secretvault

import (
	"context"

	"github.com/codemodify/secretvault/svrpc"
)

// Encrypted containers (see svrpc.MContainerCreate). Mounting is on Linux
// only for now; elsewhere these calls say so.

// CreateContainer makes a container image, stores its key as an item, and
// mounts it.
func (c *Client) CreateContainer(ctx context.Context, p svrpc.ContainerCreateParams) (out svrpc.ContainerInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MContainerCreate, p, &out)
	return
}

// OpenContainer mounts a container with the key its item holds, and says
// where.
func (c *Client) OpenContainer(ctx context.Context, p svrpc.ContainerOpenParams) (out svrpc.ContainerInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MContainerOpen, p, &out)
	return
}

// CloseContainer unmounts a container, named by its image or mount point.
func (c *Client) CloseContainer(ctx context.Context, target string) (out svrpc.ContainerInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MContainerClose, svrpc.ContainerCloseParams{Target: target}, &out)
	return
}

// Containers lists a vault's containers and whether each is mounted.
func (c *Client) Containers(ctx context.Context, vault string) (out []svrpc.ContainerInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MContainerList, svrpc.VaultRef{Vault: vault}, &out)
	return
}

// ContainerPasswd adds or changes a container's passphrase keyslot, or
// removes it (see svrpc.ContainerPasswdParams).
func (c *Client) ContainerPasswd(ctx context.Context, p svrpc.ContainerPasswdParams) (out svrpc.ContainerInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MContainerPasswd, p, &out)
	return
}

// DeleteContainer deletes a container's image file, for good, and then
// its key's item, which goes to the vault's deleted items (see
// svrpc.ContainerDeleteParams). It is refused while the image is in use.
func (c *Client) DeleteContainer(ctx context.Context, p svrpc.ContainerDeleteParams) (out svrpc.ContainerInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MContainerDelete, p, &out)
	return
}

// KnownContainers lists the disks of every vault (svrpc.MContainerKnown):
// an unlocked vault's as Containers lists them, and a locked one's as the
// daemon remembers them, marked Locked, with their files and states but
// not their keys' items. It never unlocks a vault.
func (c *Client) KnownContainers(ctx context.Context) (out []svrpc.ContainerInfo, err error) {
	err = c.conn.Call(ctx, svrpc.MContainerKnown, struct{}{}, &out)
	return
}
