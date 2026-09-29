// Package svsync syncs a vault folder with a secretvault sync server
// (svserver). The folder is the vault as svcore keeps it, through any
// svstore.Backend; svsync copies its files to and from the server, and
// never opens the vault itself: what travels is ciphertext.
//
// A vault's files are only ever added, except keyslots, which can be
// removed (docs/format.md). So a sync is a union: each side gets every
// file the other has, and keyslot removals are carried across. Two
// devices that wrote at the same time end up with the same files, and
// svcore resolves any conflict between them the same way on each.
//
// The pieces:
//
//   - Identity is this device's Ed25519 key, kept in the data directory
//     (IdentityFile, 0600) and made on first use. It signs every request.
//   - Remote says where a vault is synced to: the server's URL, the
//     vault's name there, and optionally the server certificate's
//     SHA-256 fingerprint, for a server with a self-signed certificate.
//   - Client speaks the server's API: CreateVault, Enrol (an Invite for
//     another device), Join, Devices and RemoveDevice, and the file and
//     change-log calls the sync uses.
//   - State is what a device remembers between syncs (a cursor into the
//     server's change log, and the files it knows the server has), in a
//     file of its own outside the vault folder.
//   - Sync does one two-way sync; Clone fetches a vault into an empty
//     folder; Watch syncs whenever the server reports a change, when
//     triggered, and periodically, until cancelled.
//
// A new device is enrolled by one already enrolled: Enrol gives an
// Invite (its String form fits a QR code), the new device makes a Client
// from it, calls Join with the code, and then Clone. Being enrolled on
// the server gives a device the vault's ciphertext only; to open it, the
// device still needs a keyslot: the vault's passphrase, or a recipient
// keyslot for the device's own identity added from a device that has the
// vault open.
package svsync
