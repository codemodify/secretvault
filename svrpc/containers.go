package svrpc

// Encrypted containers: LUKS2 image files whose keys are vault items of
// kind "container" (the key in field "key"; the image's path and LUKS UUID
// in attributes "image" and "luks_uuid"). Creating one writes an item and
// opening one is the operation "mount" on it (not "read": the program never
// sees the key), each with the person's consent like any other access.
// Mounting is on Linux only for now.
const (
	MContainerCreate = "container.create" // ContainerCreateParams -> ContainerInfo
	MContainerOpen   = "container.open"   // ContainerOpenParams -> ContainerInfo
	MContainerClose  = "container.close"  // ContainerCloseParams -> ContainerInfo
	MContainerList   = "container.list"   // VaultRef -> []ContainerInfo
	MContainerPasswd = "container.passwd" // ContainerPasswdParams -> ContainerInfo
	MContainerDelete = "container.delete" // ContainerDeleteParams -> ContainerInfo

	// MContainerKnown lists the disks of every vault: an unlocked vault's
	// as container.list lists them, and a locked one's as the daemon
	// remembers them (every image it saw container.list, create, open or
	// passwd name, until container.delete or a list without it), marked
	// Locked, with only the vault, the file, its LUKS UUID and its state
	// (what can be told without the key: the header names the UUID). A
	// remembered file that is gone is still listed, its state "missing".
	// It never unlocks a vault, so never asks for a passphrase to open one.
	MContainerKnown = "container.known" // struct{} -> []ContainerInfo
)

// ContainerCreateParams make a container: a new image file at Path (an
// absolute path that must not exist yet) of Size bytes in all, with an FS
// filesystem inside, mounted; its key is stored as the item Item. With
// Item empty, the item is named for the file (svops.ContainerItemName),
// with "(disk)" or a number added if an item has that name: the reply
// says which.
type ContainerCreateParams struct {
	Vault      string `json:"vault,omitempty"`
	Item       string `json:"item,omitempty"`
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

// ContainerDeleteParams delete the container at Path: the image file,
// for good, and then its key's item, as item.delete does (it goes to the
// vault's deleted items, so a copy of the image kept elsewhere still
// opens once the item is brought back). Item is the item that holds its
// key; when "" it is the container item whose luks_uuid is the image's,
// as for container.open. The image must not be attached, unlocked or
// mounted, and must be a LUKS2 image whose UUID is the one the item
// records: a file an item merely names is never deleted. The result is
// what was deleted.
type ContainerDeleteParams struct {
	Vault string `json:"vault,omitempty"`
	Item  string `json:"item,omitempty"`
	Path  string `json:"path"`
}

// ContainerInfo describes a container.
type ContainerInfo struct {
	Vault string `json:"vault,omitempty"`
	Item  string `json:"item,omitempty"`
	Path  string `json:"path"`
	UUID  string `json:"uuid,omitempty"`

	// State is "mounted", "closed", "unlocked" (attached and unlocked but
	// not mounted), "attached" (attached but locked), "missing" (the image
	// file is not there), or "unknown" where this system cannot tell;
	// "deleted" in what container.delete answers.
	State      string `json:"state"`
	MountPoint string `json:"mount_point,omitempty"`
	Device     string `json:"device,omitempty"` // the decrypted device, /dev/dm-N

	// Passphrase says the image has a passphrase keyslot secretvault made.
	Passphrase bool `json:"passphrase,omitempty"`

	// Locked marks a disk of a locked vault, as container.known lists it:
	// the daemon remembers it, and its key's item (Item, Passphrase) is
	// not known until the vault is unlocked.
	Locked bool `json:"locked,omitempty"`
}
