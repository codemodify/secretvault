package svrpc

// Encrypted containers: LUKS2 image files whose keys are vault items of
// kind "container" (the key in field "key"; the image's path and LUKS UUID
// in attributes "image" and "luks_uuid"). Creating one writes an item and
// opening one reads it, each with the person's consent like any other
// access. Mounting is on Linux only for now.
const (
	MContainerCreate = "container.create" // ContainerCreateParams -> ContainerInfo
	MContainerOpen   = "container.open"   // ContainerOpenParams -> ContainerInfo
	MContainerClose  = "container.close"  // ContainerCloseParams -> ContainerInfo
	MContainerList   = "container.list"   // VaultRef -> []ContainerInfo
	MContainerPasswd = "container.passwd" // ContainerPasswdParams -> ContainerInfo
)

// ContainerCreateParams make a container: a new image file at Path (an
// absolute path that must not exist yet) of Size bytes in all, with an FS
// filesystem inside, mounted; its key is stored as the item Item.
type ContainerCreateParams struct {
	Vault      string `json:"vault,omitempty"`
	Item       string `json:"item"`
	Path       string `json:"path"`
	Size       int64  `json:"size"`
	FS         string `json:"fs,omitempty"` // ext4 (the default), exfat, vfat or btrfs
	Label      string `json:"label,omitempty"`
	SectorSize int    `json:"sector_size,omitempty"` // 512 or 4096 (the default)

	// Passphrase, when set, opens a second keyslot, so the image also
	// opens with cryptsetup alone.
	Passphrase []byte `json:"passphrase,omitempty"`

	MountOptions string `json:"mount_options,omitempty"`
}

// ContainerOpenParams mount the container at Path. Item is the item that
// holds its key; when "" it is the container item whose luks_uuid is the
// image's.
type ContainerOpenParams struct {
	Vault        string `json:"vault,omitempty"`
	Item         string `json:"item,omitempty"`
	Path         string `json:"path"`
	MountOptions string `json:"mount_options,omitempty"`
}

// ContainerCloseParams unmount a container, named by its image file or
// its mount point.
type ContainerCloseParams struct {
	Target string `json:"target"`
}

// ContainerPasswdParams give the container at Path a passphrase keyslot,
// or change the one it has; with Remove, remove it.
type ContainerPasswdParams struct {
	Vault      string `json:"vault,omitempty"`
	Item       string `json:"item,omitempty"`
	Path       string `json:"path"`
	Passphrase []byte `json:"passphrase,omitempty"`
	Remove     bool   `json:"remove,omitempty"`
}

// ContainerInfo describes a container.
type ContainerInfo struct {
	Vault string `json:"vault,omitempty"`
	Item  string `json:"item,omitempty"`
	Path  string `json:"path"`
	UUID  string `json:"uuid,omitempty"`

	// State is "mounted", "closed", "unlocked" (attached and unlocked but
	// not mounted), "attached" (attached but locked), or "unknown" where
	// this system cannot tell.
	State      string `json:"state"`
	MountPoint string `json:"mount_point,omitempty"`
	Device     string `json:"device,omitempty"` // the decrypted device, /dev/dm-N

	// Passphrase says the image has a passphrase keyslot secretvault made.
	Passphrase bool `json:"passphrase,omitempty"`
}
