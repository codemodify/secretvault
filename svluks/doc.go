// Package svluks reads and writes LUKS2, the disk encryption format of
// Linux's cryptsetup, in our own code: written from the LUKS2 On-Disk
// Format Specification (version 1.1) with the standard library and
// golang.org/x/crypto (XTS, Argon2) underneath, and checked against
// cryptsetup itself.
//
// secretvault's encrypted containers are LUKS2 image files. On Linux the
// kernel's dm-crypt decrypts them once UDisks2 has attached them (see
// svudisks and svcontainer); this package creates them, opens and changes
// their keyslots, backs up and restores their headers, and reads and
// writes their decrypted sectors in userspace, on every OS.
//
// # What it writes
//
// Format writes what `cryptsetup luksFormat --type luks2` does for an
// image file: a 16 KiB header (4 KiB binary header and 12 KiB of JSON)
// twice, with SHA-256 checksums, a 16 MiB metadata and keyslot area, one
// aes-xts-plain64 data segment with a 512-bit volume key and 512- or
// 4096-byte sectors, a PBKDF2-SHA256 digest of the volume key, and a
// keyslot of type luks2: the volume key split by the LUKS1
// anti-forensic splitter (SHA-256, 4000 stripes) and encrypted with
// aes-xts-plain64 under a key derived from the passphrase by Argon2id,
// Argon2i or PBKDF2.
//
// # What it reads
//
// Read takes any LUKS2 header whose data segment and keyslots use
// aes-xts-plain64, and refuses the rest in plain words: LUKS1, other
// ciphers, authenticated encryption (dm-integrity), detached headers, a
// re-encryption in progress, and anything in config.requirements. It
// treats the header as hostile: sizes are bounded before anything is read,
// both checksums are verified, the JSON must be what the specification
// says (decimal object names, string-encoded 64-bit numbers, known types),
// keyslot areas must lie inside the keyslot area without overlapping, the
// data must lie after it, and KDF costs beyond what cryptsetup itself would
// write (4 GiB of memory, and a bounded amount of work) are refused before
// any key is derived. Objects it does not interpret, such as tokens and
// unknown fields, are kept when the header is rewritten.
//
// # Keys in memory
//
// Volume keys live in svcrypto.Secret (locked memory, wiped by Destroy);
// derived keys and decrypted keyslot material are zeroed after use. The
// AES key schedules inside a Volume are Go heap memory, which cannot be
// wiped: a Volume holds the key in that form until it is dropped.
package svluks
