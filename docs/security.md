# secretvault security model

**Status: pre-release.**
- Nothing here has been independently audited yet. An external audit is part
  of the 1.0 milestone.
- The vault format may still change without migration.
- Do not yet keep anything in secretvault that exists nowhere else.

This document says what secretvault protects, from whom, and where it stops.
The byte-level details are in [format.md](format.md).

## What is protected

| Asset | Where it lives |
| --- | --- |
| Item contents: passwords, keys, notes, fields | vault revisions, encrypted |
| Item metadata: names, kinds, attributes, tags, labels | vault revisions, encrypted |
| The vault master key (VMK) | nowhere on disk in the clear; wrapped once per keyslot |
| Your private keys (identities, OpenPGP, SSH) | vault items, from M5; optionally a hardware token |
| Who accessed what (grants, audit log) | the vault, encrypted, from M1 |

## Adversaries, and what each can do

### Someone with a copy of the vault folder

This covers a stolen disk, a backup, the cloud drive or sync service the
folder lives in, and the operator of a secretvault sync server.

**They cannot:**
- Read any item, name, attribute or field. Everything is sealed with an AEAD
  under keys derived from a random 256-bit master key.
- Change anything without detection. Every revision is authenticated and
  named by its SHA-256, and parents are named by hash.
- Move a wrapped key or a header to another object.
- Relabel, re-scope or move a keyslot.
- Get anything by planting keyslots. A keyslot can only add a way in. A
  planted slot that opens to some other key is rejected by the descriptor's
  check value, and one with absurd KDF costs is refused before any work is
  done.
- Guess a passphrase cheaply. Each guess costs a full Argon2id run
  (64 MiB, 3 passes by default) or 600,000 PBKDF2 iterations for `sv1-nist`.
  A strong passphrase is still what makes this hold.

**They can:**
- See the number of items, the number and times of their revisions, and their
  sizes, rounded up by Padmé padding.
- See which device wrote each revision. The optional device ID in the
  revision header is in the clear.
- Delete revisions, or hold back new ones. This rolls an item back to an
  earlier authentic version, or hides a change. **This is not detected
  yet.** Signed checkpoints, planned for M6, will detect it.
- Delete the whole vault. Keep backups.

### Other users on the same computer

- Vault files are created 0600 in 0700 directories.
- From M1, the daemon's socket accepts only the same user, checked by the
  kernel (`SO_PEERCRED`, `LOCAL_PEERCRED`, the named pipe's owner-only DACL).
- Administrators (root) are out of scope: they own the machine.

### Programs running as you

This is the hard case, and it is worth being plain about it.

- **What prompts give.** From M1, every program's request for a secret goes
  through the consent broker. The first access is prompted, and your answer is
  remembered per program. That stops honest mistakes, sandboxed apps (Flatpak
  and Snap app IDs cannot be faked from inside the sandbox), and casual misuse.
- **Why that is not a wall on Linux.** A program running as you can read your
  files, attach to your other processes where Yama allows it, make its
  requests look like another program's, and on X11 read your keystrokes. The
  broker raises the bar; it cannot replace the OS's own isolation.
- **Windows and macOS** code signing makes the program identity sturdier, not
  perfect.

**What does help:**
- Short auto-lock times, so the vault is unlocked less of the time.
- Hardware tokens that need a touch per use, for keys that must not be
  stolen.
- Sandboxed apps.

### Someone who once held a key

- **Removing a keyslot is not revocation.** It stops that key opening this
  copy of the vault. It does not make the holder forget the master key, if
  they ever unlocked it, and they may have kept a copy of the slot file.
- **Cutting someone off for good** needs a new master-key epoch, which
  re-encrypts for the keys that remain. Planned for M6.
- **Until then**, treat a leaked passphrase as a reason to move the secrets
  that matter to a new vault.

### Other holders of the same vault

Everyone who can unlock a vault holds the same master key. In version 1
they can therefore write revisions that look like any device's. Optional
per-device signatures on revisions are planned for vaults shared between
people (M6).

### A future quantum computer

- Symmetric encryption uses 256-bit keys, and passphrase slots depend only on
  symmetric primitives.
- Recipient keyslots (devices, people, servers) use hybrid HPKE, ML-KEM-768
  combined with X25519 (or P-256 in `sv1-nist`). They stay sealed as long as
  either half holds.
- OpenPGP, S/MIME and SSH keys in the trust store are as quantum-safe as those
  ecosystems are, which today is mostly not.

### The network

In version 1 nothing leaves the machine. From M6 and M8, server traffic is
TLS and devices authenticate with their own keys. secretvault never phones
home: no telemetry and no crash reports. The only network traffic is what
you configure, such as sync and key lookups. An update check, if one is
added, can be turned off.

## Keys in memory

secretvault is written in Go, which moves and copies memory on its own.
Wiping keys in Go is therefore hygiene, not a guarantee. What it does:

- **Locked memory.** The master key and the keys derived from it live in
  `svcrypto.Secret`: their own mapping, locked into RAM (`mlock`,
  `VirtualLock`) so they never reach swap, excluded from core dumps on Linux
  (`MADV_DONTDUMP`), and zeroed on release.
- **Hardened processes.** Processes holding an unlocked vault call
  `svcrypto.HardenProcess`, which disables core dumps and, on Linux, makes the
  process undumpable. That also refuses debugger attachment from other
  processes of the same user where Yama allows it.
- **Wipe on lock.** Locking a vault destroys its keys and zeroes every
  decrypted field value it cached. Content keys and key-encryption keys are
  zeroed as soon as they have been used.
- **Where it stops.**
  - Item names, labels and attributes are Go strings, which cannot be zeroed.
    Secrets belong in fields, not names.
  - The `sv1-nist` PBKDF2 call takes the passphrase as a string.
  - The Go runtime may have copied anything before it was wiped.

## Cryptographic choices

- **Primitives.** Only well-studied ones, from Go's standard library and
  `golang.org/x/crypto`: Argon2id, PBKDF2-HMAC-SHA256, HKDF-SHA256,
  XChaCha20-Poly1305, ChaCha20-Poly1305, AES-256-GCM, SHA-256, and HPKE with
  ML-KEM-768 hybrids.
- **No hand-written cipher code.** secretvault implements no cipher or hash
  itself. Its own code is the constructions that combine them (documented in
  format.md) and Shamir sharing over GF(2⁸), written without tables or
  secret-dependent branches.
- **Nonces.** Every AEAD message gets a fresh random nonce. It is 192-bit for
  XChaCha20. For AES-GCM, a per-message key is derived from a 256-bit salt.
  Streams use counters under a per-stream key.
- **Test vectors.** Pinned against independent implementations (the reference
  Argon2 CLI and Python's hashlib), and golden revisions for each suite.

## Known gaps

| Gap | Planned fix |
| --- | --- |
| Rollback and withholding of revisions is not detected | signed checkpoints (M6) |
| Removing a keyslot does not revoke a key already used | epoch rotation (M6) |
| Revisions are not signed per device | device signatures (M6) |
| On Windows and macOS, screen lock and sleep do not lock vaults yet (idle time and explicit locks do) | session notifications on those platforms |
| Windows and macOS identify programs by path and hash, not by publisher signature | Authenticode and code-signing checks |
| Unknown JSON fields in an item are dropped when an older version rewrites it | fixed before the format freeze |
| The format is not frozen | format freeze (M10) |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository (Security →
Report a vulnerability). Please do not open a public issue for security
problems.
