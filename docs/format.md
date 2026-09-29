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
epochs/<n>.json                                one file per rotation of the vault key
objects/<id[0:2]>/<object id>/<rev id>.svr     one file per revision of an item
blobs/<id[0:2]>/<blob id>.svb                  one file per attached file's contents
```

- A random 256-bit **vault master key** (VMK) protects everything.
- **Keyslots** each recover the VMK from one kind of key: a passphrase, a
  printed recovery key, a keyfile, an identity (a device, a person, a
  server), a FIDO2 security key, or a person's identity together with a
  release key a sync server escrows (emergency access).
- An **item** is stored as a chain of **revisions**. Each revision is sealed
  under its own random content key, which is wrapped under a key derived from
  the VMK. Each revision names the revisions it replaces, by hash.

Nothing about an item is stored in the clear: not its name, kind, attributes or
any field. What the folder reveals is the number of items, the number and times
of their revisions, their sizes, rounded up (see [Padding](#padding)), and
which device wrote each revision, and with which key it signed it (their IDs,
not their names; see [Signatures](#signatures)).

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
  "recipient": "<bytes>",     // recipient and emergency slots: the public key
  "fido2": { … },             // fido2 slots: the credential (below)
  "emergency": { … },         // emergency slots: the grant (below)
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
    0x07 fido2 rp_id                  fido2 slots only, from here on
    0x08 fido2 credential
    0x09 fido2 salt (32)
    0x0A fido2 uv (1 byte: 0x00 or 0x01)
    0x0B fido2 aaguid (16)
    0x0C emergency grant (16)         emergency slots only
}
```

A slot file cannot be relabelled, moved to another vault, or given wider
grants without failing to open; nor can a fido2 slot be pointed at another
credential, salt, relying party or setting, nor an emergency slot at
another grant. Tags 0x07–0x0B appear exactly when the slot is of type
`fido2`, and 0x0C exactly when it is of type `emergency`, so every other
slot's associated data is as it always was.

| Type | Key-encryption key | `wrapped` |
| --- | --- | --- |
| `passphrase` | `KDF(passphrase)` | `Seal(kek, VMK, slot_aad)` |
| `recovery` | `Derive(recovery key, vault id, "sv1 recovery kek", 32)` | `Seal(kek, VMK, slot_aad)` |
| `keyfile` | `Derive(file contents, vault id, "sv1 keyfile kek", 32)`; the file must hold ≥ 32 bytes | `Seal(kek, VMK, slot_aad)` |
| `recipient` | the identity's HPKE private key | `SealTo(recipient, VMK, info = slot_aad)` |
| `fido2` | `Derive(hmac-secret output, vault id, "sv1 fido2 kek", 32)` | `Seal(kek, VMK, slot_aad)` |
| `emergency` | the trustee's HPKE private key, then `Derive(release key, vault id, "sv1 emergency kek", 32)` | `SealTo(recipient, Seal(kek, VMK, slot_aad), info = slot_aad)` |

**Unlocking.** A reader tries every slot of the key's type for the current
epoch. A slot counts only if it opens and the recovered key's `check` matches
the descriptor's.

**Readers from before a type** skip its slots as files that do not parse
(below): a version without emergency access ignores emergency slots, and
a rotation it makes does not carry them over.

**Bad slot files.** Files that do not parse, or that name another vault, are
skipped. A slot can only ever add a way in, so ignoring a bad one loses
nothing.

**Grants.** `grants` is always `["content"]` in version 1: the slot opens the
VMK and so everything. The field exists so narrower grants can be added without
a new format, for example a key that only allows searching a locked vault.

**Reserved slot types:** `shamir`, `tpm2`, `dpapi`, `keychain`,
`windows-hello`, `secure-enclave`.

### fido2 slots

A fido2 slot is opened by a FIDO2 security key, through the `hmac-secret`
extension of CTAP 2.1 (§12.5; CTAP 2.2 is the same here). The key holds a
secret per credential that never leaves it, and turns a 32-byte salt into
`HMAC-SHA-256(CredRandom, salt)`.

```json
"fido2": {
  "rp_id": "secretvault:",
  "credential": "<bytes>",
  "salt": "<32 bytes>",
  "uv": true,
  "aaguid": "<16 bytes>"
}
```

- **`rp_id`** is the relying party the credential was made for. Writers use
  `secretvault:`: with the colon it is no domain, so no web origin can claim
  it, and a browser will never let a website ask a key for these
  credentials. (OpenSSH's `ssh:` works the same way.)
- **`credential`** is the credential ID, 1 to 1023 bytes. The credential is
  non-discoverable: the key keeps nothing, and the ID is the key's own
  sealed record of the credential, which only that key can use. It is made
  with `authenticatorMakeCredential`, the `hmac-secret` extension, ES256,
  and a random 16-byte user handle.
- **`salt`** is 32 random bytes. The key is asked to evaluate hmac-secret at
  `SHA-256("WebAuthn PRF" || 0x00 || salt)`, the transformation of WebAuthn's
  PRF extension, so that a platform WebAuthn API (which applies it itself)
  can open the same slot as a direct CTAP client does.
- **`uv`** says whether the key verifies the person (its PIN) when it is
  used. A key keeps two secrets per credential, `CredRandomWithUV` and
  `CredRandomWithoutUV`, and uses the first exactly when it verified the
  person, so the same credential and salt give a different output with the
  PIN than without. A reader must therefore use the PIN when `uv` is set,
  and must not when it is clear; a key that verifies anyway (`alwaysUv`)
  cannot open a slot made without it.
- **`aaguid`** is the key's model, as its authenticator data named it. It
  only helps people tell keys apart, but it is bound into the slot's
  associated data like the rest.
- **The key-encryption key** is `Derive(output, vault id, "sv1 fido2 kek",
  32)`, where `output` is the 32-byte hmac-secret output.

A reader with several fido2 slots and perhaps several keys plugged in asks
each key, with `authenticatorGetAssertion` and `up = false` (no touch), for
each slot's credential in turn; a key that does not hold it answers
`CTAP2_ERR_NO_CREDENTIALS`. It then asks the one key that holds one for its
PIN (if `uv`) and a touch, and opens that slot alone.

### emergency slots

An emergency slot lets a person the owner trusts (the trustee) open the
vault after a waiting period that the vault's sync server keeps, and any
of the owner's devices can cut short by refusing ([security.md](security.md#emergency-access)
says why it is built this way, and what it does not stop). It opens with
two things together: the trustee's identity, and a random 32-byte
**release key** that the server holds sealed to that identity until the
wait is over.

```json
"type": "emergency",
"label": "emergency",
"recipient": "<the trustee's public key>",
"emergency": { "grant": "<grant id>" },
"wrapped": "<SealTo(recipient, Seal(kek, VMK, slot_aad), info = slot_aad)>"

kek = Derive(release key, vault id, "sv1 emergency kek", 32)
```

- **`grant`** names the grant on the sync server that escrows the release
  key: an ID (16 random bytes) the owner's device makes. It is in the
  slot's associated data (tag 0x0C), so a slot cannot be moved to another
  grant.
- **Two layers.** The outer is HPKE to the trustee, with the slot's
  associated data as its info; the inner is `Seal` under a key derived
  from the release key. The trustee's identity alone opens the outer
  layer only; the release key alone opens nothing.
- **Unlocking.** The trustee's key is their identity with the release key
  of one grant: it tries the emergency slots of that grant whose
  `recipient` is the identity's own. The slot then counts as any other
  does: the recovered key must match the epoch's `check`.
- **The label** is `emergency`, and says nothing of who the trustee is:
  slot files are in the clear, on the server too.

**The escrow and the challenge.** The owner's device gives the sync
server the release key sealed to the trustee, bound to its vault and
grant; and a challenge, the seed of an Ed25519 key sealed to the trustee
too, with that key's public half:

```
escrow     = SealTo(recipient, release key, info = "secretvault sv1 emergency release" || vault id || grant id)
challenge  = SealTo(recipient, seed, info = "secretvault sv1 emergency challenge" || vault id || grant id)
accept key = the Ed25519 public key of seed (32 random bytes)
```

The trustee's device accepts the grant by opening the challenge with the
identity and signing, with the seed's key,

```
"secretvault sv1 emergency accept\n" + vault's name on the server + "\n" + grant id (hex) + "\n" + device key
```

where the device key is its own sync key as the server names it; the
request is signed by that device key too, which then becomes the grant's
trustee device. The server keeps only the public key, and the seed never
leaves the trustee's device, so a trustee tricked into accepting through
someone else's server gives it a signature good for the trustee's own
device alone. The two infos, the slot's associated data and every other
use of the identity differ, so none of them can be passed off as another
to get the trustee to open it. The server's side of it is in
[`svserver`](../svserver) (`emergency.go`).

**The owner's record.** The vault keeps a record of each grant it made, of
kind `emergency-grant`, encrypted like every record:

```json
{"grant": "<grant id>", "trustee": "Alice", "contact": "<contact id>",
 "recipient": "sv-recipient-1-modern-...", "level": "in-person",
 "wait": 604800, "release": "<the release key>", "created": "…"}
```

It names the trustee for the owner's devices, and holds the release key
so that a rotation can carry the grant over: the new epoch gets an
emergency slot for the same grant, recipient and release key, and the
server's escrow stays as it is. A rotation made to cut the trustee off
leaves the grant out, and the record is deleted with the grant. A slot
whose grant has no record cannot be carried over, and is named as dropped.

**The invite** the owner sends the trustee is a URI that holds no secret:

```
secretvault-emergency:?url=<server>&vault=<its name there>&fp=<certificate SHA-256>&grant=<grant id>
                       &id=<vault id>&check=<epoch 1's check value, hex>&name=<what the owner calls it>
```

`id` and `check` pin the vault: the trustee's device refuses a vault whose
descriptor does not match them, so a server cannot hand over a vault of
its own making (every later epoch is checked down to epoch 1 when the
vault opens).

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
    0x82 signature                 optional: that device's (see Signatures)
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
  - fails its checksum or authentication;
  - is signed but names no device (0x81).

  Refused revisions are skipped and reported, never trusted. A vault whose
  policy requires signatures also ignores those whose signature is missing
  or does not verify ([The policy record](#the-policy-record)).

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

### Signatures

Everyone who can open a vault holds the same master key, so the key alone
cannot say who wrote a revision. A revision may therefore carry a signature
by the device that wrote it, made with an Ed25519 key (RFC 8032) of that
device's own, in the optional header field 0x82:

```
0x82 signature  = alg (1) || key id (16) || signature
alg             = 0x01: Ed25519; the signature is 64 bytes
key id          = SHA-256("secretvault sv1 device key" || alg (1) || public key)[0:16]

signed          = "secretvault sv1 revision signature" || TLV {
                      0x01 alg (1)
                      0x02 key id (16)
                      0x03 SHA-256(unsigned prefix)
                      0x04 commit (32)
                  }
unsigned prefix = "SVR1" || suite (1) || 0x00 || header_len (2) || unsigned header
unsigned header = the header, with its 0x82 field left out
commit          = HMAC-SHA-256(Derive(content key, vault id, "sv1 revision commit", 32), payload)
signature       = Ed25519(device key, signed)
```

- **In the header, so the rules above still hold.** The prefix, signature
  included, is the body's associated data, and the file, signature
  included, is what the revision ID hashes. Someone without the vault key
  cannot strip, change or move a signature: the revision would fail to
  open and its ID would change. Tag 0x82 is optional, so a reader from
  before signatures skips it and opens a signed revision as any other.
- **What it covers.** The suite, every header field but itself (vault,
  object, epoch, time, parents, the wrapped content key, the device, and
  any field added later), and the payload. It cannot cover the body, which
  is sealed with the signature already in its associated data. Instead the
  wrapped content key, which it covers, pins the content key, and the
  commitment pins the payload under that key.
- **Why the commitment is keyed.** Checking a signature takes the content
  key, so only someone who can open the vault can check one. Someone who
  knows a device's public key but cannot open the vault (a person cut off
  by a rotation) cannot test guesses at a revision's contents against its
  signature, as a plain hash of the payload would let them.
- **The device is named.** A signed revision must name its device (0x81),
  which the signature covers, and it must be the device the key is
  registered for ([Device records](#device-records)).
- **Checking.** A reader opens the revision, computes `signed`, and looks
  the key id up in the vault's registry. A revision is then:
  - *unsigned*: it has no 0x82 field. Its 0x81, if any, is a claim;
  - *unverified*: signed by a key the registry does not hold (not synced
    here yet, or never registered), or with an alg it does not know;
  - *bad*: the registered key does not verify it, or it names a device
    other than the key's. Someone who can open the vault changed it, or
    made it posing as that device;
  - *verified*: a good signature by a registered device.
- **What it cannot stop.** Anyone who can open the vault can seal a
  verified revision's payload again under its content key, with a new
  nonce. The copy has another ID and still verifies, but says only what the
  device said: the same contents, parents and time. At most it shows as a
  conflict whose contents that device wrote.

Writers: the reference implementation signs every revision a daemon writes
(`svcore.Options.Signer`). Each device has one key for every vault, kept in
its data directory as `device-signing.key` (PKCS #8, PEM, mode 0600).

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
    ],
    "files": [
        {"name": "recovery.pdf", "type": "application/pdf", "size": 48213,
         "sha256": "<32 bytes>", "blob": "<blob id>", "key": "<32 bytes>"}
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
- **Records** are payloads of any other type: remembered access grants,
  contacts, browser associations, and the two below that the format itself
  reads, `device` and `policy`. A reader keeps and authenticates types it
  does not know, but otherwise ignores them.
- **Known draft limitation:** unknown JSON fields inside an item are dropped
  when an older version rewrites it. This must be fixed before the format
  freeze.

### History and conflicts

- **The current state is the head.** An object's current state is its head:
  the revision that no other revision of it names as a parent. Only
  revisions that count take part: in a vault that requires signatures, one
  that is ignored is not a head, and does not supersede the parents it
  names.
- **Concurrent writes.** Two writers that did not see each other's change leave
  two heads, which is a conflict.
- **Everyone agrees on the winner.** It is the head with the greatest time, and
  on a tie the greater revision ID (compared bytewise). Every reader of the same
  files therefore agrees, without talking to anyone.
- **Merging.** The next write names every head as a parent, which merges them.
  Restoring a revision (`secretvault restore`, or `resolve --keep`) writes its
  contents again with every head as a parent: the version kept wins, on
  every device. A deleted item's earlier revisions can be restored the same way.
- **Deletion** writes a tombstone. Earlier revisions stay until pruned.
- **Duplicate names.** Two live objects with the same name are a duplicate. The
  name resolves to the one whose head is newest (on a tie, the greater object
  ID), and the clash is reported.
- **Writer clocks.** A writer's time is the wall clock, raised above the time of
  every parent and every revision that writer wrote before (a hybrid logical
  clock). A skewed clock can therefore make an old edit win a conflict, but
  cannot make it older than what it replaced.

### Device records

The vault's registry of devices is records of type `device`:

```json
{"type": "device", "record": {
    "alg": "ed25519",
    "key": "<32 bytes: the public key>",
    "device": "<device id: what its revisions name in 0x81>",
    "label": "laptop",
    "removed": false,
    "vouches": ["<key id>", "…"]
}}
```

- **One object per key.** A key's records live in the object whose ID is
  its key id. A record there for any other key is ignored.
- **A key registers itself.** A key is registered when its object holds a
  record for it, signed by that key, from the device the record names (the
  revision's 0x81). That revision proves possession of the key: nobody can
  register a key they do not hold, or bind someone else's key to a device
  of theirs, and so claim that key's revisions. A key whose own records name
  two devices is registered for neither.
- **A registration is never undone.** Every such revision counts, whatever
  came after it, so what a key signed stays checkable whatever its record
  says now.
- **Label and removal** are read from the newest of the object's records
  for the key's device (its head among them), whoever wrote it: any device
  can rename or remove another, and its signature says which did. A badly
  signed record never counts. A removed device's signatures still verify;
  readers name it as removed. Removal cuts nobody off: that takes a
  rotation.
- **Vouches** are read only from the newest record the key itself signed.
  Each reader decides from its own device: a device is *vouched for* when
  the reader's device vouches for it, or a device vouched for does, and so
  on. A removed device vouches for nobody and is vouched for by nobody.
  There is no vault-wide root: nothing in a vault tells the device that
  made it from any other that can open it, while no one but a device can
  sign its own vouches.

### The policy record

A vault's policy is a record of type `policy`, in the one object whose ID
is `SHA-256("secretvault sv1 policy" || vault id)[0:16]`, so that every
device writes the same object:

```json
{"type": "policy", "record": {"require_signatures": true}}
```

- **Only a registered device sets it.** Only verified revisions of the
  object count, the newest (its head among them) winning. Without one,
  every revision counts.
- **`require_signatures`** makes a vault count only verified revisions.
  The rest (unsigned, unverified, bad) are reported and ignored: they are
  never heads, and do not supersede the parents they name, so they can
  neither hide nor delete a revision that counts. A device's registration
  is verified by its own signature, so a new device can always join.
- **Turning it on keeps what is there.** The reference implementation
  first writes again, signed, every object whose head is unsigned, and so
  adopts that state as the enabling device's; a head that is badly signed,
  or unverified, is not adopted, and the object falls back to its newest
  revision that counts.
- **Readers from before signatures** do not know the policy: they count,
  and write, unsigned revisions, which readers that know it ignore.

### Attachments: blobs/…/<blob id>.svb

An attached file's contents are a blob of their own, written once:

```
blob   = prefix || stream
prefix = "SVB1" || suite (1) || 0x00 || header_len (2, BE) || header
header = TLV(0x01 vault id, 0x02 blob id)
stream = STREAM(key, contents || zeros up to padme(size), aad = prefix)
```

- **The key is the item's.** Each blob has a random 256-bit key, held only
  in the `files` entry of the item it is attached to, with the file's name,
  media type, size and SHA-256. A blob opens for whoever can read that item,
  and for no one else.
- **Checked twice.** The stream authenticates every chunk and its end, and
  binds the vault and blob IDs (the prefix is the associated data), so a
  blob cannot be cut short, swapped for another, or moved; the contents
  must then match the item's SHA-256.
- **Rotation leaves blobs alone.** Items are written again under the new
  key, carrying their files' keys with them; a file attached afterwards
  gets a key that exists only under the new epoch.
- **Sizes.** At most 64 MiB of contents; padded with Padmé like revisions.
- **Garbage.** Replacing or removing a file leaves its blob, since earlier
  revisions refer to it. Pruning (below) will remove blobs no revision
  refers to.
- **Writes.** `item.put` never changes an item's `files`: only attaching
  and removing a file do, so a program that knows nothing of files cannot
  drop them.

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

A signed golden revision for each suite has the same header and payload,
signed with the Ed25519 key whose seed is 32 × `0x33` (public key
`17cb79fb…e18080ce`, key id `bb01ccccfed954348b5f424b1a95677e`). Every
version must still verify them; a reader that knows no tag above 0x81, as
readers before signatures, must still open them. The sv1-nist one is
checked against this document with Python's `cryptography`.

The passphrase KDFs are pinned against independent implementations: the
reference `argon2` CLI and Python's `hashlib.pbkdf2_hmac`.

## Reserved and future

- **Rollback protection.** Checkpoints signed with the device keys above,
  so that removing the newest revisions from a synced folder is detected.
  Today it is not; see security.md. Header tags 0x83 and up are free.
- **More signature algorithms.** `alg` values other than 0x01 are reserved
  (a post-quantum signature, when one is in the standard library).
- **Narrower keyslot grants.** For example, search while locked.
- **Pruning.** Rules for pruning old revisions.
- **Encrypted containers.** Not this format: they are LUKS2 images, as
  cryptsetup specifies them (see the `svluks` package).
