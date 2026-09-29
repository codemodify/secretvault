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
| A delivery server's identities, policy and audit log | its delivery directory, sealed under a root key that only k unseal shares (or a TPM-sealed credential) open |
| An emergency grant's release key | the vault's record of the grant, encrypted; on the sync server only sealed to the trustee |

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
labels, emergency grants and their times, and IP addresses; never a key or
anything inside an item. For emergency access it is trusted with more than
that, time ([Emergency access](#emergency-access)).

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

## The delivery server

`secretvault-server` with `-delivery-dir` ([delivery.md](delivery.md),
[`svdeliver`](../svdeliver)) is the one place where secretvault holds
vaults open on a machine nobody is sitting at. Unlike the sync hub, it
**can read everything in its delivery vaults**: that is its job. Share a
vault with it only if every secret in the vault may be delivered; make a
vault per purpose.

**What it keeps, and how.**
- **At rest, everything is sealed.** The server's identities, its policy
  (vaults, issuers, the client CA, roles, token hashes and the admin
  token's hash) and its audit log are sealed under a root key. The root key
  is on disk only sealed under the unseal key, which exists only as Shamir
  shares, and optionally under a credential key sealed by systemd-creds.
  The policy is authenticated too, so writing to the delivery directory
  grants nothing.
- **Tokens are kept as SHA-256 hashes**, and are 256 random bits, so a hash
  gives nothing to guess from. Sessions live in memory only.
- **Unsealed, the keys are in memory**: the root key in locked memory, the
  identities as `crypto/hpke` keys (which cannot be wiped), and the opened
  vaults' items. Answers are built as Go strings, which cannot be wiped
  either. The process makes itself undumpable (`HardenProcess`).

**A compromised CI job** gets what its role allows, for as long as its
session lasts (15 minutes unless the role says otherwise), and nothing
else:
- A role is bound to claims its issuer asserts, not to anything the job
  says about itself. Bind deploy roles to the repository **and** the ref
  or environment (GitHub environments with required reviewers make a good
  gate), or to `job_workflow_ref` for a reusable workflow. A job on another
  branch cannot take a role bound to `refs/heads/main`.
- It can read the ID token it was given, and replay it until the token
  expires (minutes, for GitHub and GitLab). Token IDs (`jti`) are not
  remembered, so this is not stopped.
- It cannot learn what exists beyond its role: a secret it may not read
  and one that does not exist get the same answer, and the policy is
  decided before any vault is touched. Role names are not secret.

**A stolen token.**
- A token works until it expires or is revoked, from anywhere its CIDRs
  allow (they see the TCP peer, so behind a proxy they see the proxy). Give
  tokens an expiry and CIDRs, and prefer ID tokens, which need no stored
  secret.
- A session works until it expires, the server is sealed, or it restarts.
- **The admin token controls the policy**: whoever holds it can grant
  themselves any secret. It cannot unseal the server or replace the shares:
  rekeying takes k of the current shares. Keep it off CI, and rotate it
  (`admin-token rotate`).

**A malicious or compromised issuer.** An issuer vouches for its tokens'
claims, and the server believes it, for the roles bound to that issuer:
- A role is as trustworthy as its issuer. Whoever controls GitHub's,
  GitLab's or the cluster's signing keys (or the host serving their JWKS,
  or the DNS and TLS in front of it) can log in to every role on that
  issuer.
- Public issuers sign tokens for everyone, with whatever audience they ask
  for. The audience check stops tokens meant for another service; the role
  must pin whose tokens it takes (the repository, the project). A role
  whose claims are only wildcards is refused.
- Keys are fetched over HTTPS only, from the `jwks_uri` of a discovery
  document that names the issuer; a CA can be pinned per issuer. Keys can
  instead be configured, for a cluster with no public discovery.
- Only RS256, ES256 and EdDSA verify, a key only for its own algorithm, so
  neither `alg: none` nor HMAC with a public key gets through.

**A stolen disk, while sealed.** Nothing comes of it:
- Vault folders are vaults (above); `seal.json`, `policy.sealed` and
  `audit.log` are ciphertext; `config.json` holds no secret.
- Unsealing needs k shares, or the credential key. The credential file on
  disk is sealed by systemd-creds: with `--with-key=tpm2` it opens only on
  that machine's TPM. With the host key alone (`--with-key=host`), the key
  that opens it is on the same disk, and the thief has both.
- They learn sizes and times, and the number of vaults, roles and tokens,
  roughly.

**A stolen disk, or a snapshot, while unsealed.** The disk is as above:
keys are only in memory. **A memory snapshot** (a VM image, a hypervisor)
of an unsealed server gives everything it holds. So does root on the
machine. Seal it (`seal`) when it is not needed, and keep swap encrypted or
off.

**Someone who can write to the delivery directory** (shared storage, a
backup restored):
- cannot grant themselves anything: the policy is authenticated, and a
  vault's ID is pinned when it is added, so another vault put in its folder
  is refused;
- **can roll the policy back** to an older sealed copy, undoing a
  revocation. This is not detected yet;
- can cut the end off the audit log and append entries of their own,
  sealed to its public key: the chain shows lines removed or altered in the
  middle, not the end cut and replaced. Ship the log elsewhere (`audit
  --json`) if that matters.

**Operators.** Fewer than k shares reveal nothing about the key. Shares
travel over the API's TLS, are held in memory for ten minutes at most
(`unseal_timeout`), and are never logged. A share from another server or
an older split is caught, and every share given so far is forgotten. The
operator whose share completes a rekey sees all the new shares; hand them
out from there.

**Anyone who can reach a sealed server** can hold up its unsealing: the
unseal call needs no credential but a share (as it must: the shares are
the credential), so they can reset the progress, or spoil it with a share
of their own making, which fails the combination and starts it again.
They learn nothing by it. Keep the API where only operators and machines
reach it (`-deliver-listen` on an internal address), and requests are rate
limited per address.

## Emergency access

`secretvault emergency grant` lets a person you trust (the trustee: a
contact with a secretvault identity) open a vault of yours after a waiting
period, seven days unless you choose otherwise, during which any of your
devices can refuse. Like Bitwarden's and 1Password's, it is for when you
cannot open the vault yourself. The vault must sync with a server. The
format is in [format.md](format.md#emergency-slots), the server's side in
[`svserver`](../svserver).

**How it is built.**
- The vault gets an emergency keyslot that opens only with the trustee's
  identity and a random release key together.
- The release key goes to the vault's sync server sealed to the trustee
  (the escrow). The server keeps the escrow and the clock. When the
  trustee asks, every device of yours hears of it at once (an event in the
  vault's change log): the daemon writes it to the vault's audit log,
  shows a notice on the desktop, and lists it in `secretvault status`,
  and any device of yours can deny it. Once the wait has passed with no
  denial, the server gives the trustee the escrow, and lets the trustee's
  device read the vault's files, never write them.
- The trustee's device accepts the grant first, by opening the seed of a
  signing key sealed to the trustee's identity, and signing with it that
  this device, by its own key, accepts this grant of this vault; it
  becomes the one device that may ask. The invite you send them holds no
  secret, and nobody else can accept it in their place: the seed never
  leaves the trustee's device, so an invite altered to send them through
  another server gets that server a signature for the trustee's own
  device, which is no use to it.
- Your vault keeps an encrypted record of the grant (who, and the release
  key), so a rotation can carry the grant over without asking the server
  or the trustee for anything. The new keyslot is made from the record,
  never from the keyslot files, which anyone who can write to the folder
  could plant.

**Why a server keeps the wait.** A wait that you can refuse needs
something that is online while you may not be, counts time, and can be
told to stop. What else was weighed:
- **A time-lock without a server.** Time-lock puzzles (repeated squaring,
  verifiable delay functions) make a key cost an amount of computation,
  not an amount of time: a faster machine opens it early, the clock starts
  when the trustee gets the puzzle rather than when they ask, and nothing
  can stop it once it runs, so you could never refuse. Timelock encryption
  to a public randomness beacon (drand's tlock) opens on a date fixed when
  it is made, not a wait from a request, trusts the beacon's operators
  instead of yours, and cannot be refused either. Neither gives "ask, then
  wait, unless I say no". Without something trusted to keep time, it is
  not possible.
- **Your own devices as the clock.** They could refuse, but a release
  would need one of them online after the wait, which is exactly what may
  not be so when emergency access is needed.
- **The trustee's own device as the clock.** It would hold everything, and
  wait only as long as it chose to.
- **Shamir between the trustee and the server.** A 2-of-2 split of the key
  between the trustee and the server is what this design is: the escrowed
  release key is the server's share (sealed to the trustee, so the server
  holds nothing it can use), and the identity is the trustee's. Splitting
  among several servers instead, k of n, each keeping the wait, would stop
  a single lying server from releasing early; a vault syncs with one
  server today, so that is left for later (known gaps).

So the server is trusted with time, and with telling you, and with nothing
secret.

**A malicious or compromised server:**
- **can give the trustee access early.** A server whose clock lies, or
  whose code ignores the wait, releases the escrow when it likes: the
  trustee then reads the whole vault at once, and your denial comes too
  late. The wait is only as good as the server's word. This is the known
  limit of any wait a server keeps, and a test shows it
  (`TestALyingServerReleasesEarlyAndTheTrusteeGetsEverything`).
- **can keep a request from you**: hide it, so your devices never hear of
  it and cannot deny it, and then release it.
- can refuse to release, or lose the escrow, so the trustee gets nothing;
  and deny or revoke grants, like any of your devices.
- can hand the trustee a vault of its own making in place of yours, which
  the trustee's device refuses: the invite pins the vault's ID and its
  first key's check value.
- **cannot open anything**: it holds the release key only sealed to the
  trustee, and never the trustee's identity; nor can it accept a grant for
  the trustee in a way that gets it the key.

**A malicious trustee:**
- can ask again and again; each request starts the wait over and tells
  you again. Requests are rate limited, like every request.
- after the wait, reads everything in the vault as it is then, and what is
  written until you revoke, and keeps it. Revoke with `--rotate` to cut
  them off from what comes after.
- cannot open anything before the wait is over, or while a request is
  denied (unless the server lies), cannot write to the vault on the
  server, and cannot accept the grant for anyone else.

**Someone who steals the trustee's identity** can ask, and you are told.
Someone with only the invite can do nothing: accepting takes the identity.

**You, offline.** The wait runs whether or not any device of yours is on:
that is what makes it emergency access. If you are out of reach for longer
than the wait, a request you would have refused goes through. Choose a
wait longer than you are ever away, and read `secretvault status` when you
come back: a release is told too (the audit log, a notice), and stays in
the status until you revoke the grant.

**A compromised device of yours** holds the vault key already. It can
grant access to anyone, and deny every request so that emergency access
never happens (revoke and grant again from a device you trust). Granting,
denying and revoking are for secretvault's own programs only, and asked
about as managing the vault, which the CLI proves with the passphrase: a
program running as you needs the passphrase too (with the limits in
[Programs running as you](#programs-running-as-you)). Any device enrolled
in the vault on the server, even one with no keyslot, can deny and revoke
on the server: it is one of the vault's devices.

**What the server learns**: that a grant exists, its wait, when it was
asked for, denied and released, and the trustee's device key and the name
it gave. The emergency keyslot, in the clear like every slot file, holds
the trustee's public key and the grant's ID. The trustee's name is in
the vault's encrypted record only; the keyslot's label is `emergency`.
The trustee's device signs with the same key as for its own vaults, so a
trustee who syncs with the same server is recognisable as the same device.
Once released, the trustee reads the vault's change log as a device of
yours does, so they see the IDs of the vault's other grants, and when
those change (never whose they are).

**On your devices** the daemon keeps the trustees' names it read from the
records in memory, to name them in notices while the vault is locked; the
status that shows them is for secretvault's own programs only.

**Revoking** forgets the grant on the server (its escrow, and the trustee's
access to the files), removes its keyslot, and deletes the vault's record.
It ends access only as far as the server can be trusted to forget:
- Once the escrow was released, the trustee has had the vault key: revoke
  with `--rotate`, which cuts them off from everything written afterwards.
  What they read before, they keep.
- Before any release, a server that kept the escrow and the keyslot's file
  could still hand both to the trustee later. If you do not trust the
  server with that, rotate on every revoke.

**On the trustee's device** the vault is kept read-only, and follows your
copy (it only ever fetches). The escrow is kept there, sealed to the
trustee's identity; the identity itself is never kept, and is given again
(`unlock --identity`) whenever the vault is opened.

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
  Python's `cryptography`. For S/MIME, `svcms`
  adds AES key wrap and the X9.63 KDF, and one cipher: RC2 decryption
  (RFC 2268, against its vectors), only to read the certificates in old
  PKCS #12 files, where 40-bit RC2 protects nothing secret.
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
- **Directories.** A configured LDAP directory is believed about its own
  people: its answers are recorded as the organisation vouching for the
  key, for the address asked about. Only secretvault's own programs can
  configure one. Its connection is TLS (ldaps://, or StartTLS), except to
  this machine; the search is equality on the address, never a filter built
  from text; its bind password is a vault item, read with the asking
  program's consent.
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
- **Consent.** Opening a container is its own operation, `mount`, on its
  key's item, and the prompt names the image: a program allowed to open a
  container is not thereby allowed to read its key (`read`), which would
  let it open the image anywhere, for ever. Creating one writes an item;
  adding a passphrase keyslot is asked as reading the key and changing the
  item, since the passphrase then opens the image as the key does. Closing
  needs no consent: a program running as you can already unmount your
  disks through UDisks2.
- **Where the key goes.** From the daemon over the system bus to udisksd
  (root), which hands it to cryptsetup and the kernel; never to a client.
  The copies svdbus makes while encoding that message are ordinary Go
  memory and are not wiped. The kernel holds the volume key while the
  container is open, as for any dm-crypt disk, and whoever can read your
  files can read the mounted container's.
- **Hostile images.** Before the kernel sees a header, the daemon parses it
  itself: sizes and checksums, the JSON, keyslot and data areas that stay in
  bounds and apart, KDF and digest costs within what cryptsetup writes (and
  the container key is tried only on keyslots cheap enough to hold it), and
  a data cipher that is AES-XTS (a planted `cipher_null` header, whose
  keyslots our key still opens, would otherwise have the kernel store files
  in the clear). The parser is fuzzed. The header is checked on the very
  descriptor handed to UDisks2, so replacing the file at that path after
  the check changes nothing. What remains is someone who can write to the
  image file itself rewriting its header between the check and the kernel
  reading it; they can already destroy the container.
- **One filesystem, one mapping.** An image already unlocked (by another
  user, or as a copy or hard link with the same LUKS UUID) is not unlocked
  again: two mappings of one filesystem would corrupt it. An attachment of
  ours that is locked, or unlocked but not mounted, is taken down and made
  again from the checked file rather than reused.
- **Locking leaves containers open.** A vault that locks (on idle, screen
  lock, sleep or `lock --all`) leaves its containers mounted, as VeraCrypt
  does: pulling a disk from under programs writing to it loses data. Set
  `"close_containers_on_lock": true` in the daemon's `config.json` to have
  a vault close its containers when it locks; they are closed just after
  the lock, which does not wait for them, and one still in use stays open,
  as the daemon's log says.

## S/MIME and whole messages

`svcms` and `svmail` read other people's mail, so they refuse rather than
guess, like `svpgp`:

- **Signatures.** A CMS signature is valid only if it verifies over the
  content, its content-type and message-digest attributes are present once
  and match, CMS algorithm protection and the ESS signing-certificate
  attributes (when present) agree with what was used, and its hash passes
  the same policy as OpenPGP's (no MD5; SHA-1 only before 2023, and only
  with a signing time). Its certificate is judged separately: a chain to
  the roots given (never the operating system's), emailProtection, a key
  usage that allows signing, and the sender's address. Every failure is
  reported, not only the first.
- **Decryption.** Once a content key is in use every failure is one error;
  RSA PKCS #1 v1.5 key transport yields a random key on failure (RFC 3218)
  rather than an error. EnvelopedData with CBC has no integrity at all
  (EFAIL): it is decrypted, marked "integrity: none" and warned about; new
  messages use AuthEnvelopedData (AES-GCM) unless asked for the old form.
  Private keys stay behind an interface: the library hands over a
  recipient and gets back a content key.
- **What a signature covers.** A mail client is misled less by broken
  cryptography than by structure: a valid signature over one part of a
  message, next to unsigned text; text around an inline OpenPGP block;
  a From or Subject outside the signature that differs from the one
  inside. `svmail` verifies the exact bytes of each signed part (its own
  MIME reader keeps them), says for each layer whether it covers the whole
  message, and warns about each of these.
- **Trust.** Nothing in either package decides whom to believe: reports
  name keys and certificates, and the trust store maps them to people.
  OpenPGP keys a message carries (Autocrypt) are offered, never used to
  verify that same message; certificates an S/MIME signature carries
  count only through a chain to the roots given.
- **Where it stops.** Revocation of S/MIME certificates (CRLs, OCSP) is
  not checked; the SHA-1 cutoff trusts a signed signing time; timing is
  as constant as Go's crypto; parsed private keys cannot be wiped.

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
| S/MIME signatures are verified by `svmail`, but `trust.check` takes a certificate the caller checked | the daemon's `mail.inspect` |
| Security keys work on Linux only, and have been tested against a software authenticator, not yet against real keys | webauthn.dll on Windows, IOKit on macOS; hardware testing |
| A security key's built-in verification (a fingerprint) is not used; its PIN is | getPinUvAuthTokenUsingUvWithPermissions |
| Host mode's TPM binding goes through `systemd-creds`, and binds to no PCRs unless asked | TPM code of our own (`svtpm`, M4), with a measured-boot policy |
| A unit refused a credential starts with an empty one | nothing within `LoadCredential=`; services should check |
| The host identity cannot be wiped from the daemon's memory (`crypto/hpke`) | an identity type of our own in locked memory |
| Container sectors are not authenticated (XTS garbles, it does not detect) | none planned: LUKS2's dm-integrity mode needs root to set up |
| Containers cannot be mounted on Windows and macOS yet | the mount layer (VHD or iSCSI, `hdiutil`) |
| The AES key schedule of a container opened in userspace cannot be wiped | none in Go |
| The delivery server's policy can be rolled back to an older sealed copy by whoever can write its directory | a counter kept where they cannot write (the TPM) |
| The delivery server's audit log can be cut short and extended by whoever can write its directory | entries MACed while unsealed; shipping the log off the machine |
| An ID token can be replayed to the delivery server until it expires | remembering token IDs (`jti`) until then |
| The daemon's audit log shows lines removed from its middle, but whoever can write its files can cut it short and append entries that chain on | a signed checkpoint of the log's head, kept where they cannot write |
| Token CIDR limits see the TCP peer: behind a proxy, the proxy | trusted proxies' `X-Forwarded-For` |
| S/MIME certificate revocation (CRL, OCSP) is not checked | revocation in the trust store |
| The wait of emergency access is kept by the sync server: one that lies releases early, and one that hides a request keeps the owner from refusing it | escrow with several servers, k of n, each keeping the wait |
| Revoking emergency access that was never released relies on the server forgetting the escrow | rotating on every revoke (`emergency revoke --rotate`) does not |
| Emergency access is to read: the trustee cannot take the vault over, nor change it | a takeover grant, if it is wanted |

## Reporting a vulnerability

Use GitHub's private vulnerability reporting on this repository (Security →
Report a vulnerability). Please do not open a public issue for security
problems.
