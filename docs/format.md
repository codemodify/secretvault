# The secretvault vault format, version 1

Status: **draft**. The format is implemented and tested (milestone M0), but it
is not frozen: it may still change, without migration, until the 1.0 format
freeze (see [roadmap.md](roadmap.md)). The reference implementation is
[`svformat`](../svformat), on top of [`svcrypto`](../svcrypto) and
[`svcore`](../svcore). Where this document and the code disagree, that is a bug
in one of them.

This document says what is on disk and which bytes are authenticated by what.
Why the design is shaped this way is in [architecture.md](architecture.md),
and what it protects against is in [security.md](security.md).

## Overview

A vault is a folder of files. Almost all of them are written once and never
changed:

```
vault.json                                     descriptor: what the vault is
slots/<slot id>.json                           one file per keyslot
objects/<id[0:2]>/<object id>/<rev id>.svr     one file per revision of an item
```

- A random 256-bit **vault master key** (VMK) protects everything.
- **Keyslots** each recover the VMK from one kind of key: a passphrase, a
  printed recovery key, a keyfile, or an identity (a device, a person, a
  server).
- An **item** is stored as a chain of **revisions**. Each revision is sealed
  under its own random content key, which is wrapped under a key derived from
  the VMK. Each revision names the revisions it replaces, by hash.

Nothing about an item is stored in the clear: not its name, kind, attributes or
any field. What the folder reveals is the number of items, the number and times
of their revisions, and their sizes, rounded up (see [Padding](#padding)).

Because files are only ever added, a vault folder can be synchronised by
anything that copies files (Syncthing, Dropbox, iCloud Drive, git, rsync).
Two devices never edit the same file. Conflicting edits become two revisions
that every reader resolves the same way.

## Notation

- `||` is concatenation. Integers are big-endian and unsigned unless stated.
- IDs are 16 random bytes, written as 32 lowercase hex digits. Revision IDs are
  32 bytes, written as 64 lowercase hex digits.
- `HKDF(ikm, salt, info, L)` is HKDF-SHA256 (RFC 5869).
- `Derive(key, salt, label, L)` is `HKDF(key, salt, "secretvault " || label, L)`.
- Binary values inside JSON are base64 (standard alphabet, padded), which is
  how Go's `encoding/json` writes `[]byte`.

## Cipher suites

A vault uses one suite for everything, chosen when it is created. The suite's
number is written into every revision.

| # | Name | Passphrase KDF | Seal | Stream AEAD | Recipient (HPKE, RFC 9180) |
| --- | --- | --- | --- | --- | --- |
| 1 | `sv1-modern` | Argon2id | XChaCha20-Poly1305 | ChaCha20-Poly1305 | ML-KEM-768 + X25519 hybrid, HKDF-SHA256, ChaCha20-Poly1305 |
| 2 | `sv1-nist` | PBKDF2-HMAC-SHA256 | AES-256-GCM, derived key | AES-256-GCM | ML-KEM-768 + P-256 hybrid, HKDF-SHA256, AES-256-GCM |

`sv1-nist` uses only NIST-approved primitives, so a vault can be used by a
process running in Go's FIPS 140-3 mode. It is not a FIPS certification claim.

All symmetric keys are 32 bytes.

### Seal

`Seal(key, plaintext, aad)` produces `nonce || ciphertext || tag`, with a
fresh random nonce each time:

- **sv1-modern:** `nonce` is 24 random bytes. The output is
  `nonce || XChaCha20-Poly1305(key, nonce, plaintext, aad)`.
- **sv1-nist:** `salt` is 32 random bytes. It computes
  `okm = HKDF(key, salt, "secretvault sv1-nist message", 44)`, then
  `k = okm[0:32]` and `iv = okm[32:44]`. The output is
  `salt || AES-256-GCM(k, iv, plaintext, aad)`.
  - Every message gets its own key, so GCM's limit on random 96-bit nonces
    does not apply.

Overhead: 40 bytes (modern) or 48 bytes (nist). Any failure to open is
reported as one error that does not say which check failed.

### Recipients (SealTo)

`SealTo(pub, plaintext, info)` is single-shot HPKE base mode with the suite's
ciphersuite. It is encoded as `len(enc) (2 bytes) || enc || ciphertext`. The
public key is the KEM's `SerializePublicKey` output; the private key is its
`SerializePrivateKey` output.

### Streams

Streams encrypt data too large to hold in memory, such as attachments and
files. The construction is STREAM (Hoang–Reyhanitabar–Rogaway–Vizár), as age
uses it:

```
stream     = salt (16 random bytes) || chunk*
stream key = Derive(key, salt || aad, "stream", 32)
chunk i    = AEAD(stream key, nonce_i, plaintext_i)       (no associated data)
nonce_i    = 0x000000 || i (8 bytes) || last (1 byte: 0x01 on the final chunk)
```

- Every chunk except the last carries exactly 65,536 plaintext bytes.
- Only the final chunk has `last = 1`, so a stream cut at a chunk boundary fails
  to open rather than reading as shorter.
- The final chunk may be empty only if it is also the first (an empty stream).

## Passphrase key derivation

Keyslot files record their KDF as JSON:

```json
{"alg": "argon2id", "salt": "<16+ bytes>", "time": 3, "memory_kib": 65536, "threads": 4}
{"alg": "pbkdf2-sha256", "salt": "<16+ bytes>", "iterations": 600000}
```

- **Argon2id** (RFC 9106) derives a 32-byte key.
- **PBKDF2-HMAC-SHA256** derives a 32-byte key.
- **Defaults for new slots:**
  - Argon2id: t=3, m=64 MiB, p=4 (RFC 9106's second recommended setting);
  - PBKDF2: 600,000 iterations (OWASP).
- **Readers refuse** anything outside these bounds, so a planted slot cannot turn
  an unlock attempt into denial of service:
  - Argon2id: t ≤ 64, m ≤ 4 GiB, p ≤ 64;
  - PBKDF2: ≤ 50,000,000 iterations;
  - salts shorter than 16 bytes.

## Key hierarchy

```
VMK (32 random bytes, one per epoch)
 ├─ check = Derive(VMK, vault id, "sv1 check", 16)     stored in vault.json
 ├─ wrap  = Derive(VMK, vault id, "sv1 wrap", 32)      wraps revision content keys
 └─ (keyslots each hold VMK sealed under their own key-encryption key)

revision content key (32 random bytes, fresh for every revision)
 └─ seals the revision's payload
```

An **epoch** is one generation of the VMK. Every vault starts at epoch 1.
Rotating the VMK, needed to truly cut off someone who once held a key, adds an
epoch (see [Epoch records](#epochsnjson--key-rotation)). Keyslots open the
current epoch's VMK. Earlier VMKs are recovered down the chain, so old
revisions stay readable to holders of the current key.

## vault.json — the descriptor

```json
{
  "format": "secretvault/v1",
  "id": "<vault id>",
  "suite": "sv1-modern",
  "created": "2026-09-28T17:37:58.026906423Z",
  "epochs": [ { "n": 1, "check": "<16 bytes>" } ]
}
```

- `epochs[i].n` must equal `i + 1`.
- `check` lets an unlock tell "this keyslot opened, but to some other key" from
  success.
- The descriptor is the only file that is ever replaced, and only when an epoch
  is added.
- It is written last when a vault is created, so a crash never leaves a vault
  that no key opens.

## epochs/<n>.json — key rotation

Epoch 1 lives in the descriptor. Every later epoch is a record of its own,
written once:

```json
{
  "format": "secretvault/v1/epoch",
  "vault": "<vault id>",
  "n": 2,
  "created": "…",
  "check": "<16 bytes: CheckValue of epoch n's VMK>",
  "prev": "<Seal(Derive(VMK_n, vault id, \"sv1 epoch prev\", 32), VMK_n-1, prev_aad)>",
  "revisions": "<the revision IDs that existed when epoch n began: 32 bytes each, ascending, no repeats>",
  "auth": "<32 bytes: HMAC-SHA-256(Derive(VMK_n-1, vault id, \"sv1 epoch auth\", 32), auth_data)>"
}
prev_aad  = "secretvault sv1 epoch prev" || vault id || n (4)
auth_data = "secretvault sv1 epoch" || TLV(
              0x01 vault id
              0x02 n (4)
              0x03 created, RFC 3339 with nanoseconds, UTC
              0x04 check
              0x05 prev
              0x06 SHA-256(revisions))
```

- **Naming.** Records are named `epochs/%08d.json`. Only those that run 2,
  3, … with no gap count; one past a gap, or one that does not parse, is
  reported and ignored (it never stops the vault opening).
- **Authenticated by the previous key.** Anyone who can write to the folder
  can put a record there, so a record counts only if `auth` checks under
  the previous epoch's VMK, which only someone who could open the vault
  holds:
  - An unlock tries the key's slots from the newest epoch down, and walks
    the chain down from the one that opens: every `prev` must open and
    match the older epoch's `check`, and every `auth` must check.
  - When the key opens only an older epoch n-1, record n decides: if its
    `auth` checks under VMK_n-1, it is a real rotation the key was left
    out of, and the unlock fails ("this key was removed"). Otherwise the
    record is planted: it, and every record after it, is ignored and
    reported, and the vault opens at n-1.
  - Rotating with a planted record in the way fails until it is removed.
- **Revisions of earlier epochs.** Once epoch n exists, a revision sealed
  under epoch e < n counts only if its ID is in record e+1's `revisions`.
  Whoever was cut off at a rotation still holds the older key, and could
  otherwise go on writing revisions every holder would accept. A device
  that wrote under the old key before hearing of the rotation has those
  writes refused too; they are reported, not lost from the folder.
- **The commit point.** Writing the record is the rotation's commit point.
  Two devices rotating at once collide on its name (the store's
  create-if-absent), so the history never forks.
- **Rotation order.** A rotation proceeds in four steps:
  1. write the new epoch's keyslots, which are inert until the epoch exists;
  2. write the record;
  3. remove the older epochs' keyslots;
  4. write every live item and record again under the new key.

  A crash at any step leaves a vault that opens.
- **Seeing a rotation from elsewhere.** An open reader that finds a record
  for the next epoch locks itself if the record's `auth` checks under its
  current VMK: its key is no longer current. A record that does not check
  is reported and ignored.

## slots/<id>.json — keyslots

```json
{
  "format": "secretvault/v1/slot",
  "id": "<slot id>",
  "vault": "<vault id>",
  "epoch": 1,
  "type": "passphrase",
  "label": "passphrase",
  "created": "…",
  "grants": ["content"],
  "kdf": { … },               // passphrase slots
  "recipient": "<bytes>",     // recipient slots: the public key
  "wrapped": "<bytes>"        // the sealed VMK
}
```

The slot's associated data binds the wrapped key to the slot's identity:

```
slot_aad = "secretvault sv1 slot" || TLV {
    0x01 vault id
    0x02 slot id
    0x03 epoch (4 bytes)
    0x04 type
    0x05 label
    0x06 grants, joined with ","
}
```

A slot file cannot be relabelled, moved to another vault, or given wider
grants without failing to open.

| Type | Key-encryption key | `wrapped` |
| --- | --- | --- |
| `passphrase` | `KDF(passphrase)` | `Seal(kek, VMK, slot_aad)` |
| `recovery` | `Derive(recovery key, vault id, "sv1 recovery kek", 32)` | `Seal(kek, VMK, slot_aad)` |
| `keyfile` | `Derive(file contents, vault id, "sv1 keyfile kek", 32)`; the file must hold ≥ 32 bytes | `Seal(kek, VMK, slot_aad)` |
| `recipient` | the identity's HPKE private key | `SealTo(recipient, VMK, info = slot_aad)` |

**Unlocking.** A reader tries every slot of the key's type for the current
epoch. A slot counts only if it opens and the recovered key's `check` matches
the descriptor's.

**Bad slot files.** Files that do not parse, or that name another vault, are
skipped. A slot can only ever add a way in, so ignoring a bad one loses
nothing.

**Grants.** `grants` is always `["content"]` in version 1: the slot opens the
VMK and so everything. The field exists so narrower grants can be added without
a new format, for example a key that only allows searching a locked vault.

**Reserved slot types:** `shamir`, `tpm2`, `fido2`, `dpapi`, `keychain`,
`windows-hello`, `secure-enclave`.

## objects/…/<rev id>.svr — revisions

A revision is one immutable version of one object:

```
revision = prefix || body
prefix   = "SVR1" || suite (1) || 0x00 || header_len (2) || header
header   = TLV {
    0x01 vault id (16)
    0x02 object id (16)
    0x03 epoch (4)                 which VMK generation wrapped the content key
    0x04 time (8)                  hybrid logical clock, Unix nanoseconds
    0x05 parents (32 each)         sorted, unique revision IDs; absent for the first
    0x06 wrapped content key       Seal(wrap, content key, dek_aad)
    0x81 device id (16)            optional: which device wrote it
}
body     = Seal(content key, padded payload, aad = prefix)
dek_aad  = "secretvault sv1 dek" || vault id || object id || epoch (4)
rev id   = SHA-256(revision)
```

- **The whole prefix is the body's associated data.** No header field can be
  changed, and no header can be moved onto another body.
- **The wrapped key is bound to vault, object and epoch.** It cannot be moved
  to another object.
- **The file name is the revision's SHA-256.** Readers check it, so the name
  is also a checksum. Parents are named by hash, so history cannot be rewritten
  without every later name changing.
- **Readers refuse any revision that:**
  - names another vault, or an object other than its folder;
  - uses a suite or epoch other than the vault's;
  - is sealed under an epoch that has ended, and is not in the next epoch
    record's `revisions`;
  - fails its checksum or authentication.

  Refused revisions are skipped and reported, never trusted.

### TLV

A field is `tag (1) || length (2) || value`. The encoding is canonical:

- Fields appear in strictly increasing tag order, each at most once.
- Tags 0x00–0x7F are **critical**. A reader that does not know one must refuse
  the whole record.
- Tags 0x80–0xFF are **optional** and may be skipped.

### Padding

The payload is framed and padded before sealing:

```
padded = length (4) || payload || zero bytes
```

The total size is `Padmé(max(4 + len(payload), 256))`, after Nikitin et al.,
"Reducing Metadata Leakage from Encrypted Files and Communication with PURBs"
(2019). That leaks at most O(log log n) bits of the size, and costs at most
about 12% overhead. Readers refuse non-zero padding.

### Payload

The payload is JSON:

```json
{"type": "item", "item": {
    "kind": "login",
    "name": "web/github.com",
    "label": "GitHub",
    "attrs": {"service": "github.com", "username": "ada"},
    "tags": ["work"],
    "fields": [
        {"name": "username", "type": "text",      "value": "<bytes>"},
        {"name": "password", "type": "concealed", "value": "<bytes>"}
    ]
}}
{"type": "item", "deleted": true}                  a tombstone
```

- **Item names** are path-like: non-empty UTF-8 segments separated by `/`, with
  no `.` or `..` segments, no control characters, and at most 1,024 bytes.
- **Field types:**
  - `text`, `url`, `email` — ordinary values;
  - `concealed` — a secret, shown masked;
  - `otp` — an `otpauth://` URI or a TOTP seed;
  - `json`, `binary`, `key` — structured data, raw bytes, and private key
    material.
- **Kinds** are listed in [`svcore/item.go`](../svcore/item.go). Unknown kinds
  are kept as they are.
- **Unknown record types** are written by newer versions (access grants,
  contacts). A reader keeps and authenticates them but otherwise ignores them.
- **Known draft limitation:** unknown JSON fields inside an item are dropped
  when an older version rewrites it. This must be fixed before the format
  freeze.

### History and conflicts

- **The current state is the head.** An object's current state is its head:
  the revision that no other revision of it names as a parent.
- **Concurrent writes.** Two writers that did not see each other's change leave
  two heads, which is a conflict.
- **Everyone agrees on the winner.** It is the head with the greatest time, and
  on a tie the greater revision ID (compared bytewise). Every reader of the same
  files therefore agrees, without talking to anyone.
- **Merging.** The next write names every head as a parent, which merges them.
- **Deletion** writes a tombstone. Earlier revisions stay until pruned.
- **Duplicate names.** Two live objects with the same name are a duplicate. The
  name resolves to the one whose head is newest (on a tie, the greater object
  ID), and the clash is reported.
- **Writer clocks.** A writer's time is the wall clock, raised above the time of
  every parent and every revision that writer wrote before (a hybrid logical
  clock). A skewed clock can therefore make an old edit win a conflict, but
  cannot make it older than what it replaced.

## Text forms

| What | Form |
| --- | --- |
| Recovery key | `SVRK1-` + base32 (RFC 4648, no padding) of `key (32) || SHA-256(key)[0:2]`, in groups of 5 separated by `-` |
| Identity (private) | `SV-IDENTITY-1-MODERN-…` / `-NIST-…`, then base32 of the private key |
| Recipient (public) | `sv-recipient-1-modern-…` / `-nist-…`, then unpadded base64url of the public key |

The recovery key's reader forgives case, spaces, dashes, and the digits people
type for letters (0→O, 1→I, 8→B). Its 16-bit checksum catches a typo before
any decryption is tried.

## Test vectors

[`svformat/testdata`](../svformat/testdata) holds a golden revision for each
suite, as hex. They are sealed with `crypto/rand` made deterministic
(`testing/cryptotest.SetGlobalRandom(t, 1)`):

- wrap key: 32 × `0x11`
- content key: 32 × `0x22`
- header: vault `01 00…`, object `02 00…`, epoch 1, time 2026-09-28T12:00:00Z,
  parents `03 00…` and `09 00…`, device `04 00…`

Every version must still open them. Sealing must reproduce them byte for byte,
so an accidental change to the layout fails the build.

The passphrase KDFs are pinned against independent implementations: the
reference `argon2` CLI and Python's `hashlib.pbkdf2_hmac`.

## Reserved and future

- **Revision signatures.** An optional signature by the writing device's key,
  for vaults shared between people. Tag range 0x82+.
- **Rollback protection.** Signed checkpoints, so that removing the newest
  revisions from a synced folder is detected. Today it is not; see
  security.md.
- **Narrower keyslot grants.** For example, search while locked.
- **Pruning.** Rules for pruning old revisions.
- **Encrypted containers.** A separate format, specified when M7 starts.
