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
| Your private keys (identities, OpenPGP, SSH) | vault items, from M5; optionally a hardware token (later) |
| A security key's secret, for fido2 keyslots | inside the key; never leaves it |
| Who accessed what (grants, audit log) | the vault, encrypted, from M1 |
| Who you know: contacts, their keys, how you verified them, what mail they sent | vault records, encrypted, from M5 |
| Files in encrypted containers | LUKS2 image files, AES-256-XTS; their keys in vault items, from M7 |

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
- **Where vaults live is secretvault's own business.** Registering,
  forgetting or creating a vault, choosing the default, and setting up or
  joining sync are refused to every program but secretvault's own. A
  program that could register a folder of its own as the default would
  have the next secrets saved where it can read them.

**What does help:**
- Short auto-lock times, so the vault is unlocked less of the time.
- Hardware tokens that need a touch per use, for keys that must not be
  stolen.
- Sandboxed apps.

### Opening at login

A vault set to open at login (`vault login on`) has a keyfile slot whose
key the OS seals to the user on this machine. The key opens for any program
running as the user while they are logged in, which is the point; the
consent broker still stands between those programs and the items. Against a
stolen disk it holds on Windows (DPAPI) and macOS (the keychain), and on
Linux with a TPM2. Without a TPM2, systemd's host key lies on the same disk
as the sealed key, so only full-disk encryption protects it: use login
unlock on such machines only with full-disk encryption.

### The browser path

Browsers get logins through KeePassXC's extension, KeePassXC-Browser,
which talks to `secretvault-browser`, a relay the browser starts, which
talks to the daemon ([architecture.md](architecture.md#password-manager)).

- **The extension itself.** A malicious or compromised KeePassXC-Browser
  (a bad update, or on Chromium a developer-mode extension claiming its
  ID) can do what the real one can:
  - it must first be connected, which the person is asked about;
  - each login it asks for is still decided per item, prompted unless a
    decision is remembered, and audited;
  - but it names the page itself, so a prompt's "for github.com" is its
    word, and an item the browser is always allowed can be fetched
    silently, from any page. "Always" for a browser means "always, for
    anything the browser asks".
- **Another program pretending to be the relay.** The daemon opens a
  browser session only for its own binary, so a program that speaks the
  daemon's protocol itself gets nothing. A program can instead run
  `secretvault-browser` and feed it messages; the daemon then names that
  program, the relay's real parent, and asks about it, not about the
  browser. It cannot borrow the browser's decisions or its association,
  which is tied to the browser's identity. As everywhere on Linux, a
  program running as you can still impersonate another of yours
  ([Programs running as you](#programs-running-as-you)).
- **The association key.** The extension proves a later session with a
  public key it keeps in the browser profile. Whoever copies it from
  there still needs to be that browser, as above. Associations are
  encrypted vault records, per device; `secretvault browser rm` ends one
  at once, even mid-session.
- **The channel.** Messages are NaCl `crypto_box` (X25519,
  XSalsa20-Poly1305) under a key pair made for each session. A nonce is
  accepted once, for the last 32,768 messages of a session, so a message
  cannot be replayed, and one of our own answers sent back (the box key is
  the same both ways) is refused. A message whose answer would reuse a
  nonce is refused. The relay only moves bytes.
- **What the extension learns.** The database hash is an HMAC under a key
  derived from the vault key, different on each device; group IDs are
  likewise. A refused login and a missing one look the same.
- **Installing** changes only the per-user native-messaging manifests (on
  Windows, keys under HKEY_CURRENT_USER), records each change, and keeps
  the manifest it replaced, so `uninstall` puts KeePassXC's back exactly.

### Someone who once held a key

- **Removing a keyslot alone is not revocation.** It stops that key opening
  this copy of the vault. It does not make the holder forget the master key,
  if they ever unlocked it, and they may have kept a copy of the slot file.
- **Cutting someone off for good.** `secretvault unshare` (or `vault
  rotate`) makes a new master key that only the remaining keys open, and
  writes every item's current state again under it. What was written
  before stays readable to whoever could read it then; nothing written
  after is.
- **Writing with the old key.** Whoever was cut off still holds the old
  key, and could seal new revisions with it. They do not count: each
  rotation's record lists the revisions that existed when it was made, and
  a revision sealed under an older key counts only if it is on that list.
- **A leaked passphrase** calls for a rotation with a new passphrase.

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

Nothing leaves the machine unless you set up sync. Sync server traffic is
TLS (pinned by fingerprint for a self-signed server), and devices sign every
request with their own keys, so a captured request cannot be replayed. What
the sync server itself can see is listed in [`svserver`](../svserver)'s
documentation: file names, sizes and times, keyslot metadata, device keys and
labels, and IP addresses; never a key or anything inside an item.

secretvault never phones home: no telemetry and no crash reports. The only
network traffic is what you configure, such as sync and key lookups. An
update check, if one is added, can be turned off.

## Security keys

A vault can have a keyslot that a FIDO2 security key opens (`secretvault
slot add fido2`), through the key's `hmac-secret` extension: the key turns
the slot's salt into 32 bytes with a secret that never leaves it. The
format is in [format.md](format.md#fido2-slots).

**What a key adds:**
- **A copy of the vault folder is not enough.** Without the key there is
  nothing to guess: the slot's key-encryption key comes from a 256-bit
  secret inside the key, not from anything a person chose.
- **With `uv` (the default when the key has a PIN), the key is not enough
  either.** The key must be given its PIN, and it blocks its PIN after 8
  wrong tries (3 in a row until it is plugged in again), so a stolen key
  cannot be guessed into. secretvault says how many tries are left every
  time it asks, and stops after three wrong PINs.
- **Someone has to touch it.** Every unlock needs a touch, so a program
  cannot use a key that is plugged in without the person noticing, unless
  it catches a touch meant for something else.
- **The key finds its slot without a touch.** Unlocking asks each key
  plugged in, silently, whether it holds one of the vault's credentials;
  a key that does not is never asked for a PIN or a touch.
- **No website can reach these credentials.** They are made for the
  relying party `secretvault:`, which no web origin can claim, so a browser
  refuses to let a page ask for them.

**What it does not change:**
- **An unlocked vault is as before.** Its master key is in the daemon's
  memory whichever key opened it; the key protects the vault at rest, not
  a running session.
- **The output is the key to the slot.** Anything that sees the
  hmac-secret output once (the daemon's memory, while it unlocks) can open
  that slot from a copy of the folder forever after, without the key.
  The output travels from the key encrypted under an ECDH key agreement, so
  watching the USB bus shows nothing.
- **Programs running as you can use the key too.** On Linux the udev rule
  that lets secretvault open the key lets every program of yours open it.
  One that has a copy of the slot can ask the key for the output, which
  still takes the touch (and the PIN, with `uv`).
- **Without `uv`, possession is enough.** Whoever holds the key and a copy
  of the folder opens the vault with a touch.
- **The key is not checked to be genuine.** secretvault does not verify
  attestation: it trusts that the key you enrol is the hardware you think
  it is.
- **A lost key is a lost way in.** Keep the passphrase or a recovery key.
  Removing a fido2 slot is not revocation, as for any slot, and rotating
  the vault key does not carry fido2 slots over (the key would have to be
  touched to seal the new master key): `vault rotate` names them, to be
  added again.
- **The PIN goes where passphrases go.** It is typed into secretvault's
  own prompts (the CLI's terminal, the terminal agent, or the desktop's
  pinentry) and sent to the key encrypted, never stored.

## The host daemon

`secretvaultd --host` holds the keys of the vaults shared to its machine
for as long as it runs, and hands their values to the machine's services
by a policy only root can change. Nobody is asked: the policy is the
consent. How well it protects the vaults depends on where the host
identity lives.

| Who | Identity sealed to TPM2 and host key | Sealed to the host key alone | Plain root-only file |
| --- | --- | --- | --- |
| root on the running machine | everything | everything | everything |
| the disk alone (stolen, a backup, a snapshot) | nothing | everything | everything |
| the disk and the TPM2 (the machine, switched off) | see below | — | — |

- **root on the running machine** gets everything the host can open. It
  can use the admin socket, read the unit's `$CREDENTIALS_DIRECTORY`, have
  the TPM2 unseal the credential again (it does so for this machine's
  root), or read the daemon's memory. root owns the machine.
- **The disk alone.** With a TPM2, `systemd-creds` seals to both the TPM2
  and the host key (`/var/lib/systemd/credential.secret`) by default, so
  the disk opens nothing: the vault folders are ciphertext, and the
  credential needs this machine's TPM2. Without a TPM2 the host key is on
  the same disk, and so is everything needed; sealing then only helps
  against a copy of `/etc/credstore.encrypted` without
  `/var/lib/systemd`. A plain identity file is as good as the disk's own
  encryption: keep it out of backups.
- **The disk and the TPM2.** `systemd-creds` binds to no PCRs unless
  told, so anything booted on the machine (a live USB) can have the TPM2
  unseal the credential, and read the host key off the disk.
  `secretvault host init --seal --tpm2-pcrs 7` binds it to the Secure Boot
  state, which stops a boot with Secure Boot off or with other keys, but
  not another system signed by the same keys. More PCRs, or a signed PCR
  policy, bind it tighter, at the price of sealing again after firmware or
  kernel updates. Full-disk encryption bound to the same TPM2 is the other
  half of the answer.
- **Local users and services.** `credentials.sock` and `admin.sock` are
  root's alone (0600, and the kernel's word on the peer). Anyone may
  connect to `secretvaultd.sock`, and may only resolve the references the
  policy lists for their uid, which the kernel vouches for, and program.
  The program narrows a uid and is no boundary: anything running as that
  uid can pose as its programs, as in user mode. A service is sent the one
  value a reference names, never the rest of the item, and hears nothing
  of other vaults or items.
- **Units.** A unit's credential is readable by the unit's user, and by
  root. A glob (`app@*.service`) serves every unit whose name matches;
  only root can make units, but a glob is still wider than a name. A
  refused unit gets an empty credential and starts anyway (systemd cannot
  tell a refusal from an empty value), so a service should refuse to run
  on an empty secret.
- **In memory.** The identity stays in the daemon's memory while it runs,
  as a `crypto/hpke` key, which cannot be wiped, so that it can open a
  vault again after it locks; the vaults themselves stay unlocked (no idle
  lock) unless their `auto_lock` says otherwise. The process is
  undumpable and has no core dumps.
- **On disk, in the clear.** The policy (`host.json`) and the log
  (`host.log`) name units, programs, vaults and items, which the vault
  folders keep encrypted. Both are root's alone.
- **The unit** runs as root, which it needs to identify other users'
  programs and to serve them, with `ProtectSystem=strict` (only
  `/var/lib/secretvault` and `/run/secretvault` writable), `ProtectHome`,
  `PrivateTmp`, `PrivateDevices`, `NoNewPrivileges`, the kernel
  protections, and `RestrictAddressFamilies` to Unix and IP sockets.

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
  - An age identity used by `age-plugin-secretvault` or `secretvault age
    decrypt` becomes, in that process, a `crypto/ecdh` or `crypto/hpke` key,
    which cannot be zeroed. Its text is wiped once parsed, and the process
    exits when the file key is unwrapped.
  - The Go runtime may have copied anything before it was wiped.

## Cryptographic choices

- **Primitives.** Only well-studied ones, from Go's standard library and
  `golang.org/x/crypto`: Argon2id, PBKDF2-HMAC-SHA256, HKDF-SHA256,
  XChaCha20-Poly1305, ChaCha20-Poly1305, AES-256-GCM, SHA-256, and HPKE with
  ML-KEM-768 hybrids.
- **No hand-written cipher code.** secretvault implements no cipher or hash
  itself. Its own code is the constructions that combine them (documented in
  format.md) and Shamir sharing over GF(2⁸), written without tables or
  secret-dependent branches. For OpenPGP, `svpgp` also implements the modes
  the standard library lacks, on top of `crypto/aes`: OCB (RFC 7253), EAX,
  CFB and AES key wrap (RFC 3394), each checked against its published test
  vectors. For age, `svage` adds Bech32, and the two point conversions SSH
  and hardware-token recipients need (Ed25519 to X25519, and P-256
  decompression), which only ever see public keys. The browser path uses
  NaCl `box` from `golang.org/x/crypto`, because KeePassXC-Browser does.
  For security keys, `svfido` speaks CTAP's PIN/UV auth protocols, which
  the specification fixes to P-256 ECDH, SHA-256 or HKDF-SHA-256,
  AES-256-CBC and HMAC, all from the standard library; they only carry the
  PIN and hmac-secret values to and from the key, and are checked against
  Python's `cryptography`.
- **Nonces.** Every AEAD message gets a fresh random nonce. It is 192-bit for
  XChaCha20. For AES-GCM, a per-message key is derived from a 256-bit salt.
  Streams use counters under a per-stream key.
- **Test vectors.** Pinned against independent implementations (the reference
  Argon2 CLI and Python's hashlib), and golden revisions for each suite. The
  age implementation passes all of the C2SP CCTV age vectors, and reads what
  the reference age implementation writes for the types they leave out.

## OpenPGP

`svpgp` reads other people's keys, signatures and mail, so it is written to
refuse rather than guess:

- **Integrity before parsing.** An encrypted message is decrypted whole and
  its MDC or AEAD tags checked before anything inside it is parsed; nothing
  comes back from a message that fails. Every failure at that stage is the
  same error, so a decryption service cannot be used as an oracle. Messages
  without integrity protection (SED) are refused unless the caller asks.
- **Signatures mean something.** A signature is valid only if it verifies,
  its key was bound, unexpired, unrevoked and allowed to sign when it was
  made (a signing subkey also has to have signed its own binding), and its
  hash passes the policy. Signatures that name their intended recipients
  count only inside a message encrypted to one of them.
- **Policy.** SHA-1 is refused in signatures made from 2023 on, MD5 always;
  RSA under 2048 bits, Ed448, X448, the brainpool curves, IDEA and Camellia
  are refused. DSA is only verified and ElGamal only decrypted, for old
  data, with a warning. Revocations count whatever their hash (fail closed).
- **Bounded.** Packet sizes, nesting, decompressed size and ratio (no zip
  bombs), Argon2 cost and the number of packets and signatures are all
  limited; the parsers are fuzzed.
- **Where it stops.** SHA-1 cutoffs by date can be defeated by a forger who
  backdates a collision; old keys whose earlier self-signatures were
  stripped will not validate older signatures; timing is only as constant
  as Go's crypto (ElGamal and DSA use `math/big`, with the ElGamal exponent
  blinded); decrypted secret keys are in locked memory but Go's own copies
  of key objects cannot be wiped.

## The trust store

A verdict ("Signed by Alice Example's key, which you verified in person")
is only as good as the verification behind it, and says which that was.
What it rests on:

- **Consent.** Reading your contacts (listing them, checking a signer,
  verifying a signature) is asked about per program, like reading an
  item; changing them (adding, importing, recording a verification or a
  key seen in mail) is a write. A program allowed to change your contacts
  can record that it verified a key in person: every event says who
  recorded it, and `secretvault contact show` lists them.
- **Your keys stay in the daemon.** Signing asks as `sign` and decrypting
  as `decrypt` on the key's item; neither lets the program read the key,
  as a `read` grant would. `pgp export --secret` takes a key out, protected
  with a new passphrase unless you say otherwise.
- **Trust on first use** only notices change: the first key seen for an
  address is believed. A later, different key is kept apart and verdicts
  about it say "this may be an impostor"; it never replaces the first.
- **Lookups** go to the network only when asked, and tell the domain (WKD)
  or keyserver whose key you want. WKD answers are kept only when the key
  names the address, and bind the key to that address alone.
  keys.openpgp.org's answers are recorded as email-checked; plain HKP
  keyservers check nothing, and their keys carry no verification.
- **Organisations.** Marking a contact as an organisation makes its CA
  certificates vouch for every certificate they issue, within whatever
  constraints the CA certificate itself carries.
- **Where it stops.** An OpenPGP key found again (from a keyserver, or in
  mail) is not merged packet by packet: the new copy is taken only when it
  carries a revocation the old one lacks, or user IDs where the old one has
  none. S/MIME signatures are not verified here yet: `trust.check` takes
  the signer's certificate, and the caller checks the signature.

## Encrypted containers

A container is a LUKS2 image file ([`svluks`](../svluks)), mounted on Linux
by UDisks2 and the kernel's dm-crypt.

- **What it hides.** The files inside, their names and the filesystem's
  structure: AES-256 in XTS mode, per sector, under a random 512-bit volume
  key.
- **What it does not.** Someone with the image sees its size, its UUID and
  header (which KDFs its keyslots use), and, comparing two copies, which
  sectors changed. XTS does not authenticate: they can garble a 16-byte
  block without it being detected, or put back an older copy of the image.
  LUKS2 has no hidden volumes; a container is plainly a container.
- **Its keys.** Keyslot 0 opens with a random 256-bit key kept in a vault
  item (so the image is as safe as the vault), stretched only by PBKDF2's
  minimum, since stretching a random key adds nothing. An optional
  passphrase keyslot uses Argon2id (4 passes over 256 MiB); it is then as
  strong as that passphrase, and anyone with the image may guess at it
  offline. A header backup opens with every key the image opened with when
  it was taken, even after a keyslot is removed.
- **Consent.** Opening a container reads its key's item and creating one
  writes an item, each asked about as any other access. Closing needs no
  consent: a program running as you can already unmount your disks through
  UDisks2.
- **Where the key goes.** From the daemon over the system bus to udisksd
  (root), which hands it to cryptsetup and the kernel; never to a client.
  The kernel holds the volume key while the container is open, as for any
  dm-crypt disk, and whoever can read your files can read the mounted
  container's.
- **Hostile images.** Before the kernel sees a header, the daemon parses it
  itself: sizes and checksums, the JSON, keyslot and data areas that stay in
  bounds and apart, KDF costs within what cryptsetup writes, and a data
  cipher that is AES-XTS (a planted `cipher_null` header would otherwise
  have the kernel store files in the clear). The parser is fuzzed.
- **Locking leaves containers open.** A vault that locks (on idle, screen
  lock, sleep or `lock --all`) leaves its containers mounted, as VeraCrypt
  does: pulling a disk from under programs writing to it loses data. Set
  `"close_containers_on_lock": true` in the daemon's `config.json` to have
  a vault close its containers when it locks; a container still in use
  stays open, and the daemon's log says so.

## Known gaps

| Gap | Planned fix |
| --- | --- |
| Rollback and withholding of revisions is not detected | signed checkpoints (M6) |
| A planted epoch record is ignored, but blocks rotating until it is removed; on a sync server that keeps it, rotating stays blocked | epochs that name the one they follow, so a rotation can step over it |
| Changes a device made under the old key before it heard of a rotation are refused with the rest (reported by `verify`, still in the folder) | re-sealing a device's own set-aside changes, once revisions are signed per device |
| Revisions are not signed per device | device signatures (M6) |
| On Windows and macOS, screen lock and sleep do not lock vaults yet (idle time and explicit locks do) | session notifications on those platforms |
| Windows and macOS identify programs by path and hash, not by publisher signature | Authenticode and code-signing checks |
| Unknown JSON fields in an item are dropped when an older version rewrites it | fixed before the format freeze |
| The format is not frozen | format freeze (M10) |
| OpenPGP messages are read whole, into memory, up to a size limit | streaming decryption of v2 SEIPD, chunk by chunk |
| OpenPGP designated revokers (a deprecated mechanism) are not honoured | escrowed revocation signatures instead |
| OpenPGP version 6 interoperability is checked against the RFC's vectors only | Sequoia in the test suite |
| A browser in Flatpak or Snap starts its host through the desktop portal, which the daemon then names instead of the browser | identifying the app behind the portal |
| The browser extension names the page it asks for, and "always" for a browser covers any page | decisions that name the site as well as the item |
| An OpenPGP certificate seen again is not merged packet by packet with the copy held | certificate merging in `svpgp` |
| No transparency log is checked; the level is reserved | key transparency, when a log to check exists |
| A company directory (LDAP/AD) cannot be asked yet | an LDAP `Directory` |
| S/MIME (CMS) signatures are not verified by secretvault | `svcms` |
| Security keys work on Linux only, and have been tested against a software authenticator, not yet against real keys | webauthn.dll on Windows, IOKit on macOS; hardware testing |
| A security key's built-in verification (a fingerprint) is not used; its PIN is | getPinUvAuthTokenUsingUvWithPermissions |
| Host mode's TPM binding goes through `systemd-creds`, and binds to no PCRs unless asked | TPM code of our own (`svtpm`, M4), with a measured-boot policy |
| A unit refused a credential starts with an empty one | nothing within `LoadCredential=`; services should check |
| The host identity cannot be wiped from the daemon's memory (`crypto/hpke`) | an identity type of our own in locked memory |
| Container sectors are not authenticated (XTS garbles, it does not detect) | none planned: LUKS2's dm-integrity mode needs root to set up |
| Containers cannot be mounted on Windows and macOS yet | the mount layer (VHD or iSCSI, `hdiutil`) |
| The AES key schedule of a container opened in userspace cannot be wiped | none in Go |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository (Security →
Report a vulnerability). Please do not open a public issue for security
problems.
