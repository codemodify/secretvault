// Package svserver is secretvault's own sync server: it keeps the files of
// many vaults and relays them between each vault's devices, and
// understands nothing inside them. A vault is a folder of files that are
// only ever added (docs/format.md), so the server is a store of named,
// immutable blobs with a change log beside each vault; keyslot removal is
// the one deletion the format has, and the only one the server performs.
//
// The server is an adversary in secretvault's threat model
// (docs/security.md): it is trusted to keep files, not to keep them
// secret or unchanged. Everything it holds is ciphertext, sealed on the
// devices under keys it never sees.
//
// # Storage
//
// Under the root directory, one directory per vault:
//
//	vaults/<vault>/devices.json   the enrolled device keys
//	vaults/<vault>/changes.log    every file created or removed, numbered
//	vaults/<vault>/files/...      the vault's files, as the devices have them
//
// The change log is appended to and synced line by line; after a crash
// the log is reconciled with the files on disk before anyone is served.
// One server process owns a root at a time.
//
// # API
//
// Every request is signed (below). File bodies are raw bytes; everything
// else is JSON, and errors are {"error": "..."}.
//
//	POST   /v1/vaults/{vault}                 make a vault; the signing key becomes its first device.
//	                                           Body CreateVaultRequest; needs the admin token unless
//	                                           registration is open. 201, or 200 if this device made it already.
//	PUT    /v1/vaults/{vault}/files/{name}    store a file: 201 when stored, 200 when the same bytes were
//	                                           there already (a retry), 409 when different bytes are, 410 for
//	                                           a keyslot that was removed. Answers PutResult.
//	GET    /v1/vaults/{vault}/files/{name}    the file.
//	DELETE /v1/vaults/{vault}/files/{name}    remove a keyslot (slots/*.json only); logged as a change.
//	GET    /v1/vaults/{vault}/changes?after=SEQ&wait=SECONDS&limit=N
//	                                           changes after SEQ, waiting up to wait (at most 60 s) for one
//	                                           when there are none. Answers Changes.
//	POST   /v1/vaults/{vault}/enrol           a one-time enrolment code for another device (Enrolment).
//	POST   /v1/vaults/{vault}/devices         join with a code: body JoinRequest, signed by the new key.
//	GET    /v1/vaults/{vault}/devices         the enrolled devices ([]Device).
//	DELETE /v1/vaults/{vault}/devices/{key}   remove a device (any device may; not the last one).
//
// Vault names are lowercase letters, digits, '-' and '_' (CheckVaultName);
// a vault's own ID is the natural choice. File names must be ones the
// vault format writes (ClassifyName): vault.json, slots/<id>.json,
// epochs/<n>.json, objects/<xx>/<object>/<rev>.svr, and checkpoints/...,
// reserved for later. A revision must hash to its name, so no one can
// plant bytes under a name the honest devices would later need; JSON
// files must be JSON; sizes are capped (64 KiB for JSON, 1 MiB for a
// checkpoint, 16 MiB by default for a revision).
//
// # Authentication
//
// Devices are Ed25519 keys, enrolled per vault. Every request carries
//
//	Authorization: SV1 device=<key>, time=<unix>, nonce=<16 bytes>, sig=<signature>
//
// with the key, nonce and signature in unpadded base64url, and the
// signature over SigningString:
//
//	"SV1\n" + method + "\n" + target + "\n" + time + "\n" + nonce + "\n" + hex(SHA-256(body))
//
// where target is the path from /v1/ on, plus "?" and the raw query when
// there is one. The server refuses a request whose time is more than five
// minutes from its own, and remembers every device and nonce it accepted
// for as long as their time stays acceptable, so a captured request
// cannot be sent again. Membership is checked before a body is read.
// Making a vault or joining one is signed by the new key too, which
// proves the device holds it.
//
// A device already enrolled asks for an enrolment code: 128 random bits,
// valid once, for ten minutes, kept in memory as a hash only. The new
// device presents it, signed with its own key, to be enrolled. Codes do
// not survive a restart. Any enrolled device can list the devices and
// remove any of them, itself included, but not the last one. Requests
// are rate limited per device and per IP address.
//
// Enrolling a device on the server gives it the vault's ciphertext, not
// its contents: it still needs a keyslot (a passphrase, or a recipient
// keyslot for its own identity) to open the vault.
//
// # What the server sees
//
// It sees, and could keep or disclose:
//   - every file's name, size and when it arrived: so the number of items,
//     the number and times of their revisions, their padded sizes, and
//     each vault's keyslots (their types, labels, KDF settings and
//     recipient public keys are in the clear in the slot files);
//   - which device wrote each revision (the device ID in its header);
//   - the device keys and labels enrolled in each vault, who enrolled
//     whom, and when each device was last seen;
//   - the IP address and timing of every request.
//
// It never sees a vault key, a passphrase, an item's name or any field.
// It cannot forge or alter a revision without detection. It can withhold
// or delete files, which rolls items back to older authentic versions;
// signed checkpoints (planned) will detect that.
package svserver
