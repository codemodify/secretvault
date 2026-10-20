package svops

import (
	"fmt"
	"path/filepath"
)

// What the managers (the GUI and the TUI) both say about items, their
// history, encrypted containers and the tools, in plain words
// (docs/wording.md): what a thing is, what pressing its button does, and
// whether that is safe. A face adds only what is its own (which button
// or key to press). The CLI keeps its own words.

// Items and their history.

// kindNames are the item kinds (svcore.Kinds, and a passkey) as the
// managers show them. The CLI's --kind and the stored item keep the
// short words.
var kindNames = map[string]string{
	"login":     "Login",
	"password":  "Password",
	"note":      "Note",
	"card":      "Payment card",
	"identity":  "Personal details",
	"ssh-key":   "SSH key",
	"api-key":   "API key",
	"key":       "Key",
	"kv":        "Key/value data",
	"otp":       "One-time code",
	"container": "Disk key",
	"generic":   "Other",
	"passkey":   "Passkey",
}

// KindText is the kind of an item as the managers show it; a kind of
// someone else's making is shown as it is.
func KindText(kind string) string {
	if s, ok := kindNames[kind]; ok {
		return s
	}
	return kind
}

// DeleteItemText is the confirmation of deleting an item; where is
// where the face lists deleted items ("Vault › Items › Deleted items").
func DeleteItemText(name, vault, where string) string {
	return fmt.Sprintf("%s goes from %s, and programs that read it will no longer find it. "+
		"You can bring it back as it was from the deleted items (%s).", name, VaultPhrase(vault), where)
}

// DeleteItemAction is that confirmation's button.
const DeleteItemAction = "Delete the item"

// RemoveFileText is the confirmation of removing an attached file.
func RemoveFileText(file, item string) string {
	return fmt.Sprintf("%s is taken off %s. Earlier versions of the item, in its history, still hold it.", file, item)
}

// RemoveFileAction is that confirmation's button.
const RemoveFileAction = "Remove the file"

// RestoreRevisionTitle, RestoreRevisionText and RestoreRevisionAction ask
// before making an earlier version of an item its current one: saved
// when, a time as the face shows it ("" when it has none to say).
const (
	RestoreRevisionTitle  = "Go back to this version?"
	RestoreRevisionAction = "Go back to this version"
)

func RestoreRevisionText(name, when string) string {
	if when != "" {
		when = ", from " + when
	}
	return fmt.Sprintf("%s becomes as it was in this version%s. What it holds now stays in its history, so you can come back to it.", name, when)
}

// KeepVersionTitle, KeepVersionText and KeepVersionAction ask before
// settling a conflict (one item changed on two devices at once) in one
// version's favour.
const (
	KeepVersionTitle  = "Keep this version?"
	KeepVersionAction = "Keep this version"
)

func KeepVersionText(name string) string {
	return fmt.Sprintf("This version becomes %s on every device, and the conflict is settled. The other versions stay in its history.", name)
}

// RestoreDeletedText asks before bringing a deleted item back.
func RestoreDeletedText(name string) string {
	return name + " comes back as it was before it was deleted."
}

// RestoreDeletedAction is that confirmation's button.
const RestoreDeletedAction = "Bring it back"

// ItemNameNeeded is the editor's problem with a name that is missing or
// that the vault does not take.
const ItemNameNeeded = "give the item a name, like github.com"

// BadItemName is a name the vault does not take, said with an example.
func BadItemName(name string) string {
	return fmt.Sprintf("%q cannot be an item's name: give it words, like github.com or Bank card, with any slash between two of them.", name)
}

// Encrypted disks (the CLI's containers): files on this computer's drive
// that hold files encrypted, opened like a USB drive with a key kept in a
// vault.

const (
	// ContainersAbout says what a disk is, over the list.
	ContainersAbout = "An encrypted disk is a file on this computer's drive that holds your files encrypted. " +
		"Opening it shows them like a USB drive; its key is kept in a vault, so opening it asks you first, as reading any item does."
	// ContainersNone is the list when it is empty.
	ContainersNone = "No encrypted disks yet. An encrypted disk is a file on this computer's drive that holds your files encrypted, and opens like a USB drive."
	// ContainerNewAbout heads the form that makes one.
	ContainerNewAbout = "A new disk file of the size you give, opened once it is made. Its key is made now and kept in a vault, as an item."
	// ContainerOpenAbout heads the form that opens one by its file.
	ContainerOpenAbout = "Its files appear like a USB drive, opened with the key kept in a vault."
	// ContainerCloseAbout heads the form that closes one.
	ContainerCloseAbout = "Its files go out of sight and stay in the disk file, encrypted. Save what is open in it first."
	// ContainerPassphraseAbout says what a disk's own passphrase is.
	ContainerPassphraseAbout = "A passphrase of the disk's own opens it without secretvault, with cryptsetup " +
		"(Linux's standard disk encryption tool). Without one, only the key kept in the vault opens it."
	// HeaderBackupAbout says what a header backup is.
	HeaderBackupAbout = "The header is the start of the disk file, where the ways to open it are kept. " +
		"If it is damaged, nothing opens the disk again, unless you have a copy of it."
	// HeaderBackupWarning says how to keep one.
	HeaderBackupWarning = "Keep the copy as safe as the key: whatever opens the disk today still opens it with this copy, " +
		"even after you remove that passphrase or key from the disk."
	// DisksLocked follows the list when some vaults are locked: the disks
	// whose keys they keep cannot be listed until they are unlocked.
	DisksLocked = "Locked, so their disks are not listed: "
	// DisksLockedSeen follows a list that has the disks of locked vaults
	// in it (every disk, as secretvault last saw them): only their files
	// are shown until the vaults are unlocked.
	DisksLockedSeen = "Locked, so their disks are shown by file only, as this computer last saw them: "
	// DiskMissing is the state of a disk whose file is not there.
	DiskMissing = "the file is not there: moved, or deleted"
)

// DiskVaultLocked says that the vault keeping a disk's key is locked: the
// disk is known by its file, and anything done with it asks for the
// vault's passphrase first.
func DiskVaultLocked(vault string) string {
	return fmt.Sprintf("%s keeps its key, and is locked: unlock it to see which item the key is in. "+
		"Mounting or deleting the disk asks for the vault's passphrase first.", SentenceStart(VaultPhrase(vault)))
}

// ContainerCreated says a disk was made: its file, its size and
// filesystem, where it is open, and the item its key is in.
func ContainerCreated(path, size, fs, mount, item string, withPassphrase bool) string {
	s := fmt.Sprintf("Made the disk %s (%s, %s); its files are in %s, and its key is in the item %s.", filepath.Base(path), size, fs, mount, item)
	if withPassphrase {
		s += " Its passphrase opens it without secretvault too."
	}
	return s
}

// ContainerOpened says a disk is mounted, and where its files are.
func ContainerOpened(path, mount string) string {
	return fmt.Sprintf("Mounted %s: its files are in %s.", filepath.Base(path), mount)
}

// ContainerClosed says a disk is unmounted.
func ContainerClosed(path string) string {
	return fmt.Sprintf("Unmounted %s: its files are locked away in it again.", filepath.Base(path))
}

// ContainerPassphraseDone says a disk's passphrase was set, or removed.
func ContainerPassphraseDone(path string, removed bool) string {
	if removed {
		return fmt.Sprintf("Removed the passphrase of %s: only the key in the vault opens it now.", filepath.Base(path))
	}
	return fmt.Sprintf("%s now opens with its new passphrase too, even without secretvault.", filepath.Base(path))
}

// HeaderBackedUp says where a disk's header was copied to.
func HeaderBackedUp(path, dst string) string {
	return fmt.Sprintf("Copied the header of %s to %s. Keep it as safe as the key.", filepath.Base(path), dst)
}

// DeleteDiskTitle asks whether to delete the disk at path.
func DeleteDiskTitle(path string) string {
	return fmt.Sprintf("Delete the disk %s?", filepath.Base(path))
}

// DeleteDiskText is the confirmation of deleting a disk whose key is in
// vault: its file goes for good, its key to the deleted items.
func DeleteDiskText(path, vault string) string {
	return fmt.Sprintf("The disk file %s and every file in it are deleted from this computer for good. "+
		"Its key goes to the deleted items of %s, so a copy of the disk file kept elsewhere can still be opened.",
		filepath.Base(path), VaultPhrase(vault))
}

// DeleteDiskAction is that confirmation's button.
const DeleteDiskAction = "Delete the disk"

// DiskDeleted says a disk was deleted, and where its key is now.
func DiskDeleted(path, vault string) string {
	return fmt.Sprintf("Deleted the disk %s; its key is in the deleted items of %s.", filepath.Base(path), VaultPhrase(vault))
}

// The tools.

const (
	SignFileAbout = "A signature lets others check that the file comes from you and has not changed since. " +
		"It is made with your OpenPGP key, which stays in the vault."
	CheckSignatureAbout = "Checks that a file is signed and has not changed since, and whether the signer is someone in your contacts you have verified."
	DecryptPGPAbout     = "Decrypts a file someone encrypted to your OpenPGP key. The key stays in the vault, and the decrypted file is written so that only you can read it."
	EncryptAgeAbout     = "Encrypts a file with age, so that only the people you choose can open it: add each one's public key " +
		"(age1… or ssh-…), or one of your own age keys, or use a passphrase instead."
	DecryptAgeAbout = "Decrypts an age file with one of your age keys: one kept in the vault, or one in a file. " +
		"With none chosen, you are asked for the passphrase the file was encrypted with."
	InspectMessageAbout = "Shows who signed an email and whether you have verified them, how it was encrypted, and its text. " +
		"Give the message as your mail program saves it (an .eml file)."
	ComposeMessageAbout = "Turns an email you wrote, saved as an .eml file with its From and To, into one signed with your key " +
		"and encrypted to everyone it is addressed to, ready to send."
	GeneratorAbout = "Makes a strong password, or a passphrase of words, to copy or to start a new item with. " +
		"Nothing it makes is kept until you save it."
	ResolveReferenceAbout = "A reference names a secret without holding it, for scripts and settings files to use. " +
		"This shows what a program given it would read; the value stays hidden until you show it. " +
		"Write it as sv://vault/item, or sv://vault/item#field for one field; sv://-/… is the default vault."
	CheckEnvFileAbout = "Checks that each reference to a secret in an env file can be read now, without showing any value. " +
		"secretvault run reads them the same way when it starts a command."
	CheckTemplateAbout = "A template is a file with references to secrets in it. This checks that each can be read now, " +
		"without showing any value, and can write a copy with the secrets filled in, which only you can read. " +
		"A reference in it is written {{sv://vault/item}}."
)

// ReferencesChecked says how many of n references can be read.
func ReferencesChecked(ok, n int) string {
	switch {
	case n == 0:
		return "There are no references to secrets in it."
	case ok == n && n == 1:
		return "The reference in it can be read."
	case ok == n:
		return fmt.Sprintf("All %d references in it can be read.", n)
	}
	return fmt.Sprintf("%d of %d references in it cannot be read; each is listed with why.", n-ok, n)
}

// Moving items in and out.

// ImportedText says how an import went.
func ImportedText(imported, files, skipped, warnings int) string {
	s := SentenceStart(countOf(imported, "item was", "items were")) + " imported"
	if imported == 0 {
		s = "No items were imported"
	}
	if files > 0 {
		s += ", with " + countOf(files, "attached file", "attached files")
	}
	s += "."
	if skipped > 0 {
		s += " " + SentenceStart(countOf(skipped, "item the vault had already was", "items the vault had already were")) + " skipped."
	}
	if warnings > 0 {
		s += " " + SentenceStart(countOf(warnings, "warning", "warnings")) + ": the details say what."
	}
	return s
}
