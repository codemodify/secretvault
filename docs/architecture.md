# secretvault architecture

This is the design the milestones in [roadmap.md](roadmap.md) build towards.
Milestone 0 (the vault format and engine) exists; everything else here is
planned. When the code and this document disagree, the code wins and this
document is fixed.

## What secretvault is

One secret store for Linux, Windows and macOS. It serves four purposes:

1. **Password keeper and consent broker.** Programs such as a mail client, a
   browser or a database ask secretvault for a secret, and secretvault asks
   you: "Mail wants the password for imap.example.com: allow once, until I
   lock, always, or deny?". It also acts as the desktop keyring where the OS
   allows one to be replaced.
2. **Encrypted containers.** You pick a container file and mount it as a disk
   with the OS's own filesystem inside. It is encrypted and decrypted on the
   fly, as VeraCrypt does.
3. **Secret delivery for services.** Services on hosts, in Kubernetes, in
   CI/CD pipelines and in containers receive their secrets without storing
   them.
4. **Contacts and trust store.** You import people's public keys (OpenPGP,
   S/MIME, SSH, secretvault's own) and record how you verified them.
   Programs then ask "is this signature over this digest by Alice?" and get
   yes or no, and how sure. Your own private keys sign and decrypt inside
   secretvault and never leave it.

Around those four:

- YubiKeys can unlock vaults and can hold private keys.
- A built-in TOTP authenticator replaces Google Authenticator and Aegis.
- A phone companion that approves prompts comes later.

It is a public product.

- It never phones home: no telemetry and no crash reports. An update check,
  if added, can be turned off.
- It is distributed as signed binaries with install scripts.
- It is English only.

## One engine, many faces

```
 programs  ── mail client, browser, gpg, ssh, git, systemd, CI job, kubectl, mount ...
     │
     │  faces: Secret Service (D-Bus) · our JSON-RPC API · ssh-agent · gpg-agent ·
     │         pinentry/askpass · git/docker credential helpers · browser native messaging ·
     │         age plugin · systemd credential socket · HTTPS API · container mount
     ▼
 ┌──────────────────────────────── secretvaultd ────────────────────────────────┐
 │  consent broker: who is asking → remembered grant? → prompt → audit          │
 │  vault engine (svcore): keyslots, items, revisions, conflicts                │
 │  trust store · key operations · container server · sync client/server       │
 └───────────────┬──────────────────────────────────────────────┬───────────────┘
                 │ prompts (pinentry protocol)                   │ files
                 ▼                                               ▼
    secretvault-gui-prompt / -tui-prompt           vault folders: local, synced folder,
                                                  or a secretvaultd server (ciphertext only)
```

Every face is an adapter that turns its protocol's request into a vault
operation, which the broker then allows or refuses. An item written through
one face is visible through every other. For example, a password saved by
the browser is the same item that `secretvault get` prints, and that the
Secret Service returns to a GNOME application.

## Binaries

| Binary | Role |
| --- | --- |
| `secretvaultd` | The daemon. It holds the keys and is the only process that opens vaults. It runs in three modes (below). It links no UI code, which a test enforces. |
| `secretvault` | The CLI, a pure client of the daemon, which it starts if needed. In M0 only, it opens vault folders directly. |
| `secretvault-gui` | The desktop manager on [uitoolkit](https://github.com/codemodify/uitoolkit), with a tray icon. |
| `secretvault-tui` | The full-screen terminal manager, built on tview/tcell. |
| `secretvault-gui-prompt` | A small, focused window that asks for a passphrase or a decision. It is also a pinentry and askpass. |
| `secretvault-tui-prompt` | The same on a terminal, and a `pkttyagent`-style prompt agent for sessions without a display. |

Later, small helpers are the same binary under other names (dispatched on
`argv[0]`): `git-credential-secretvault`, `docker-credential-secretvault`,
`age-plugin-secretvault`, and the browser's native-messaging host.

### Daemon modes

| Mode | Runs as | Unlocked by | Serves |
| --- | --- | --- | --- |
| `user` (default) | the logged-in user, per session | the person: login, passphrase, fingerprint, YubiKey | every desktop face |
| `host` | a system service | TPM or a host key | systemd credentials, container unlock at boot, local services |
| `server` | a service on a server | Shamir key shares (k of n operators) or TPM | the HTTPS API: sync hub (ciphertext only) and secret delivery to services and CI |

## Talking to the daemon

Clients speak JSON-RPC 2.0, one object per line, as comms-mail and
comms-chat-lan do ([`svrpc`](../svrpc)). Methods are `noun.verb`, for example
`vault.unlock`, `item.get` and `grant.revoke`.

- **Both directions.** The daemon calls back into secretvault's own
  terminal programs, the CLI and `secretvault-tui` (`prompt.ask`), to
  prompt on their terminal.
- **Events.** Events are notifications without an id, for example
  `vault.locked` and `item.changed`.

| OS | Transport | Who may connect |
| --- | --- | --- |
| Linux, BSD | Unix socket `$XDG_RUNTIME_DIR/secretvault/secretvaultd.sock`, 0600 in a 0700 directory, with a lock file | same uid, checked with `SO_PEERCRED` |
| macOS | Unix socket `$TMPDIR/secretvault-<uid>/secretvaultd.sock`, 0600 | same uid, checked with `LOCAL_PEERCRED` and `LOCAL_PEERPID` |
| Windows | AF_UNIX socket `%LOCALAPPDATA%\secretvault\run\secretvaultd.sock`, with a lock file held by `LockFileEx` | same user SID, checked through `SIO_AF_UNIX_GETPEERPID` and the peer's token |

`SECRETVAULT_SOCK` overrides the path. A client that finds no daemon starts
the `secretvaultd` installed beside it, which logs to `secretvaultd.log`
beside the socket.

The Go client library is the root package, `secretvault`. comms-mail calls it
through its `keyringKey` hook; see [clients.md](clients.md).

## The consent broker

### Who is asking

Each face finds the calling process through the socket's peer credentials
or D-Bus `GetConnectionCredentials`. The kernel's word on the peer's user is
the boundary: a peer running as another user is refused. The daemon then
names the program ([`svpeer`](../svpeer)):

- **Windows.** The image path, and the Authenticode publisher if the file is
  signed.
- **macOS.** The executable path, and the code-signing identity (team ID and
  bundle ID) from the audit token.
- **Linux.** The executable path (`/proc/<pid>/exe`). Plus:
  - for Flatpak and Snap apps, the sandbox's app ID, which is the only
    identity a program there cannot fake;
  - for other programs, whether the file is owned by root in a system
    directory (installed by the package manager, identified by path) or is
    writable by the user (identified by path and content hash, so it is asked
    about again after it changes).

A remembered "always allow" matches on path plus publisher signature where a
signature exists. Anything else falls back to the Linux rules above. Two more
cases:

- **Interpreters.** For `python3`, `bash`, `node` and the like, the script
  is part of the identity: "tool.py run by python3", not "python3".
- **Unreadable programs.** A program that hides its executable (by making
  itself non-dumpable, as ssh-agent does) is known only by its process ID. It
  is asked every time, and no lasting decision can attach to it.

secretvault's own CLI on a terminal is a special case. It is known by its
**terminal session** (terminal device, session ID and the session leader's
start time), so "allowed until the vault locks" covers that terminal, not
every copy of the CLI. `secretvault-tui` is treated the same way.

### What is decided

A grant covers (program, item or whole vault, operation). The operation is
one of read, list, write, delete or manage. Sign and decrypt arrive with the
trust store in M5.

| Answer | Lasts |
| --- | --- |
| allow once | this request |
| allow until lock | until this vault next locks |
| always | until revoked in the manager |
| deny (optionally remembered) | this request, or until revoked |

Grants are stored in the vault as their own encrypted record type, tied to
the device (a program's identity only means something on one machine).
Grants can also be made ahead of time (`secretvault grant allow /usr/bin/backup
--item backup/key`), for programs that run where nobody can be asked.

**Audit log.** Every access, whether allowed or denied, goes to an audit log
on this device ([`svbroker`](../svbroker)):
- **Sealed to a public key.** Entries are sealed with HPKE to a key derived
  from the vault key. The daemon can therefore record refusals while the vault
  is locked, but only an unlocked vault can read them.
- **Chained.** Entries are chained by hash, so removing one shows.

The manager (and `secretvault audit`) shows the log, and offers "revoke"
next to each grant.

**Who may be asked for a passphrase.** Only secretvault's own programs: the
CLI and `secretvault-tui` on their terminal, and the prompt programs. Any
other program asked to collect a passphrase would learn it, so programs
never get one; the person is asked by the desktop prompt instead.

**How the CLI proves itself.** The CLI proves it is the person by taking the
vault's passphrase on its terminal, as sudo does. A "y" typed into a terminal
proves nothing: a program can create a terminal and type into it.

### Prompts

A prompt says which program is asking (name, path, publisher), for what item
and operation, and why, when the program gives a reason.

The daemon chooses a prompter in this order:

1. The terminal of the CLI (or `secretvault-tui`) that made the request,
   for its own requests only. The TUI asks in a dialog drawn inside it.
2. A registered `secretvault-tui-prompt --agent`.
3. The desktop prompt. Until `secretvault-gui-prompt` exists, this is the
   system's pinentry: pinentry-gnome3 on GNOME-like desktops, else
   pinentry-qt or pinentry-gtk. It is taken only from `/usr/bin`,
   `/usr/local/bin` and `/bin`, never looked up on `PATH`.
4. Later, the phone companion.

With nobody to ask, the answer is no, and the error says how to decide
ahead of time.

Prompters speak the **pinentry protocol** (Assuan, [`svprompt`](../svprompt)),
so they double as `pinentry` for gpg-agent and as askpass helpers.
secretvault's own prompters understand an extension (`ADDCHOICE`, `CHOOSE`)
for the four-way consent question. A plain pinentry gets three buttons:
allow once, allow until locked, and deny.

The GUI prompt needs work in uitoolkit first: see
[../uitoolkit-gaps.md](../uitoolkit-gaps.md). The main items:

- The password field must not copy plaintext.
- Secrets must be held in a buffer that can be wiped.
- The prompt needs a centred window that stays above others.
- The keyboard must be grabbed while typing.
- The prompt must be excluded from screenshots.

### What a prompt can and cannot stop

On Linux, any program running as you can impersonate another program of
yours, read your files, and on X11 read your keystrokes. Consent prompts stop
honest mistakes, sandboxed apps (Flatpak, Snap), and casual misuse. They are
not a wall against malware already running as you. Windows and macOS code
signing make the program identity sturdier, not perfect.
[security.md](security.md) spells out the threat model.

## Vaults and unlocking

- **Several vaults, one default** (for example Personal, Work, Family). Each
  has its own keys, sync and sharing. Folders are just path prefixes in item
  names, and tags are free.
- **Unlock method, chosen at setup:**
  - **OS login.** Your login unlocks the default vault, as GNOME Keyring and
    the login Keychain do:
    - Linux: a PAM hook (`pam_exec` with `expose_authtok`, or a small PAM
      module);
    - Windows: a DPAPI-bound keyslot;
    - macOS: a login-Keychain item.
  - **Separate passphrase.** Unlock independently of the OS login.

  Either way, quick unlock (fingerprint, Windows Hello, Touch ID, YubiKey,
  TPM) can be added as more keyslots.
- **Auto-lock is configurable per vault.** The defaults follow how the vault
  was unlocked:
  - a vault unlocked by the OS login locks at logout;
  - a vault unlocked by passphrase also locks on screen lock, sleep and
    idle.
- **Recovery.** A printed recovery key is offered at setup (a `recovery`
  keyslot).

## Storage and sync

The vault format ([format.md](format.md)) is a folder of files that are only
ever added. That gives three sync modes on one format:

1. **No sync.** One device, with backups.
2. **Synced folder.** Put the vault folder in Syncthing, Dropbox, iCloud Drive
   or git. Conflicting edits become two revisions that every device resolves
   the same way.
3. **Your own server.** `secretvault-server` ([`svserver`](../svserver))
   stores and relays the files, and only ever sees ciphertext. It keeps
   each vault's files with a change log that numbers every file created
   or removed, and answers long polls, so devices hear of a change at
   once. Devices sign every request with their own Ed25519 key; a new
   device is enrolled with a one-time code from one that is already
   trusted (an invite that fits a QR code). The client side
   ([`svsync`](../svsync)) syncs a vault folder both ways: files are only
   ever added, keyslot removals are carried across, and a file the two
   sides hold with different contents (a vault key rotated on two devices
   at once) stops the sync rather than being overwritten.

   secretvaultd runs the sync: for each vault whose config names a
   server, a watcher keeps the folder in step for as long as the daemon
   runs, locked or not (it moves ciphertext only). It syncs when the
   server reports a change, when the daemon itself writes to the vault,
   and once a minute; what it fetches is read into the open vault at once,
   and a vault rotated on another device locks itself here, since its key
   is no longer current. A rotation syncs first and is refused if it
   cannot, so that two devices never rotate apart. This device's key
   (`sync-device.key`) and what it knows of each server (`sync/`) live in
   the data directory, outside the vault folders. Only secretvault's own
   programs may set sync up, join, invite or turn it off.

   It later relays phone approvals. An official hosted service may come
   later; the design keeps it possible, and it would see no more than a
   self-hosted server does.

Sharing a vault with a person adds a `recipient` keyslot for their identity.
Removing them properly takes a new epoch (`secretvault unshare`, which
rotates the vault master key).

## The faces in detail

### Keyring

- **Linux: replaced, fully.**
  - **One provider for GNOME and KDE.** secretvaultd owns
    `org.freedesktop.secrets` (Secret Service API, over our own D-Bus
    implementation). KDE Plasma 6 also goes through Secret Service
    (ksecretd), so one provider serves both.
  - **Mapping.** Collections map to vaults, with the `default` alias pointing
    at the default vault. Secret Service attributes map to item attributes.
    The `session` collection is an in-memory vault.
  - **Portal.** The Flatpak portal backend (`org.freedesktop.impl.portal.Secret`)
    gives sandboxed apps their per-app secret.
  - **Take-over and undo.** `secretvault keyring takeover` imports what the
    current keyring holds, then changes only user files (recorded for
    `restore`):
    - a D-Bus activation file for `org.freedesktop.secrets`;
    - for gnome-keyring, its "secrets" autostart entry hidden and a systemd
      drop-in that keeps its pkcs11 component.

    The daemon queues for the bus name and takes it when the old keyring
    lets go. KWallet, KeePassXC and oo7 get the steps to do by hand.
  - **Consent in the protocol's terms.** To a program, an item it has not
    been allowed to read looks locked. Unlocking it returns a prompt object,
    whose Prompt shows the person the consent question (and the passphrase,
    if the vault is locked). The program that stores an item may read,
    change and delete it without asking again.
- **Windows: bridged.**
  - Credential Manager cannot be replaced. We import from it and can mirror
    chosen items into it (`CredRead`/`CredWrite`).
  - Later, register as the Windows 11 passkey provider, which needs a signed
    MSIX package.
- **macOS: bridged.**
  - Keychain cannot be replaced. We import and mirror.
  - Later, an AutoFill credential-provider extension for passwords and
    passkeys in Safari and apps. That is a signed app with a small Swift
    part, so it is outside pure Go.

### Password manager

- **Managers and item kinds.** The GUI and TUI managers work with these kinds:
  - login, password, note, card, identity;
  - SSH key, API key, key, KV data;
  - TOTP authenticator entries.
- **Everyday tools.** A password generator, attachments (stream-encrypted),
  history, and a conflict view.
- **Clipboard.** Copies clear themselves after a timeout and carry the
  "concealed" hints that clipboard managers respect.
- **Import.** From 1Password (1PUX), Bitwarden (JSON), KeePass (KDBX 4),
  Proton Pass, browser CSVs, pass, and Aegis / Google Authenticator, plus the
  FIDO Credential Exchange Format (CXF).
- **Export.** To CXF, KDBX, and encrypted JSON.
- **Browser autofill.** The browser's native-messaging host speaks the
  KeePassXC-Browser protocol, so KeePassXC's existing, reviewed browser
  extension works with secretvault.

### Trust store and identities

- **Keys.** Contacts hold public keys of four kinds:
  - **OpenPGP.** Our own implementation of RFC 9580 (`svpgp`), able to
    read RFC 4880 keys and messages. It is strict: integrity is checked
    before anything inside an encrypted message is parsed, a signature
    counts only if its key was valid and allowed to sign when it was made,
    SHA-1 signatures are refused from 2023, and everything read is bounded.
    Third-party certifications are kept for the trust store to judge;
    `svpgp` does not.
  - **X.509 / S/MIME.** Built on the standard library's `crypto/x509`, plus
    our own CMS.
  - **SSH.**
  - **secretvault identities.** Post-quantum hybrid (ML-KEM-768 + X25519).
- **How a key is verified.** Each key records its verification, from
  strongest to weakest:
  1. In person, by QR code or comparing a fingerprint face to face.
  2. Vouched for by an organisation's CA or directory.
  3. Checked against public logs or WKD.
  4. Trusted on first use, which flags any later change loudly.
- **Where keys come from.** Files, QR codes, paste, WKD and keyservers, a
  company directory (LDAP/AD, or an organisation's secretvault server), and
  incoming mail (Autocrypt headers, S/MIME signatures).
- **Using the keys.**
  - **Our API:** `verify(signature, digest, claimed signer)` → valid or not,
    which key, and its verification level. Also `sign`, `decrypt` and
    `encrypt-to`, each through the consent broker.
  - **Whole messages:** `mail.inspect(raw message)` recognises PGP/MIME,
    inline PGP and S/MIME (signed, encrypted, both, nested). It returns the
    decrypted body, with consent, and a verdict per signature, so a mail
    client needs one call and no crypto of its own.
  - **Agents:** a gpg-agent-compatible agent (so gpg, pass, git and
    Thunderbird's external-GnuPG mode work) and an SSH agent, which also
    covers git signing.
  - **OS certificate stores:** contacts' certificates are published to the
    Windows and macOS stores for Outlook and Apple Mail.
- **Your own private keys** live in the vault by default. With a YubiKey
  present, secretvault offers the usual split:
  - the signing key is made on the token;
  - the decryption key is made in the vault and copied to the token, with the
    vault copy kept as a backup, so old mail stays readable.

### Encrypted containers

- **The container file** carries its own header and keyslots, so it opens on
  a machine that has never seen your vault. Its keys can also live in a vault
  item, for one-click mounting. The header leaves room for a hidden volume
  later.
- **Data** is encrypted per sector with authentication. The sector format is
  specified when M7 starts.
- **Inside** is the OS's own filesystem (ext4, NTFS, APFS), for full native
  behaviour.
- **Mounting without kernel drivers of our own.** secretvaultd serves the
  decrypted container as a virtual disk image, and the OS attaches that image
  with its own tools:
  - Linux: a loop device or dm-crypt;
  - Windows: VHD attach, or iSCSI to a local target;
  - macOS: `hdiutil`.

  This needs admin rights once per machine. Each OS path gets a spike before
  the format is fixed.

### Secret delivery

- **Hosts.**
  - Host mode serves systemd's `LoadCredential=` over an AF_UNIX socket:
    systemd connects when the unit starts and reads the secret. The daemon is
    unlocked by TPM.
  - `secretvault run -- cmd` and `inject` resolve `sv://vault/item/field`
    references into environment variables or files.
- **Server API.** Our own HTTPS API only; there are no Vault or cloud
  compatibility layers.
  - Machine authentication:
    - tokens;
    - mTLS;
    - OIDC for CI (GitHub Actions and GitLab ID tokens) and for Kubernetes
      service accounts, so pipelines store no secrets.
  - Path-based policies, a hash-chained audit log, and Shamir unseal.
- **Kubernetes.** A provider for External Secrets Operator's webhook, and our
  own Secrets Store CSI driver provider.
- **SOPS and age.** `age-plugin-secretvault` makes vault-held keys usable by
  age, rage, SOPS, gopass and chezmoi.
  - **The key.** An item of kind `key`: the field `age_identity` holds an
    X25519 or post-quantum age identity, and `age_recipient` (a field and an
    attribute) its public half, a plain `age1...`/`age1pq1...` that anyone
    can encrypt to without secretvault. `secretvault age keygen` makes one.
  - **The identity string** is `AGE-PLUGIN-SECRETVAULT-1...`, Bech32 of
    `VAULT/ITEM`: it names the item and holds no key.
  - **The plugin** is the CLI under that name (multicall). For each file it
    asks the daemon for the item, which asks the person like any other
    request, then unwraps the file key in its own process and exits. It
    never prompts itself (its stdin and stdout belong to age), and it asks
    for nothing unless the file has an X25519 or post-quantum stanza. The
    key leaves the daemon for that process only, after consent.
  - **Our own code** (`svage`): the format, the recipient types (including
    SSH keys and scrypt, for `secretvault age encrypt|decrypt`), and both
    ends of the plugin protocol, checked against the C2SP CCTV vectors.

### Tokens and 2FA

- **YubiKey or FIDO2 key as an unlock factor.**
  - Via FIDO2 `hmac-secret`, speaking CTAP2 over HID in our own code, or
    challenge-response HMAC-SHA1 (as KeePassXC does).
  - It can be required on its own or together with the passphrase.
- **Keys on the token.** Through the PIV and OpenPGP card applets, over PC/SC:
  - Linux: the pcscd socket;
  - Windows: `winscard.dll`;
  - macOS: the PC/SC framework.
- **TOTP/HOTP authenticator.** Built in.
- **Phone approvals.** Later, relayed through your own server.

## Code layout and dependencies

Top-level packages follow the `<app><role>` naming used across these
projects, with `sv` as the prefix:

| Package | Holds | State |
| --- | --- | --- |
| `svcrypto` | every cryptographic primitive, nothing else | M0 |
| `svformat` | the v1 on-disk format | M0 |
| `svstore` | where vault files live | M0 |
| `svcore` | the vault engine | M0 |
| `svprompt` | the pinentry protocol, both directions | M1 |
| `svterm` | prompting on a terminal (kept out of the daemon) | M1 |
| `secretvault` (root) | the client library | M1 |
| `svd`, `svrpc` | the daemon, and the JSON-RPC wire protocol | M1 |
| `svpeer` | who is on the other end of a connection | M1 |
| `svbroker` | grants and the audit log | M1 |
| `svdbus` | our D-Bus implementation | M1 |
| `svsecretservice` | the Secret Service face | M3 |
| `svwayland`, `svx11`, `svclip` | the clipboard in our own protocol code | M2 |
| `svimport` | import from other password managers; export to KDBX and CXF | M2 |
| `svpgp` | OpenPGP, our own | M5 |
| `svcms`, `svtrust` | S/MIME, the trust store | M5 |
| `svfido`, `svpcsc`, `svtpm` | hardware tokens and TPM | M4 |
| `svsync`, `svserver` | sync, and the server API | M6, M8 |
| `svcontainer`, `svmount` | containers, and per-OS mounting | M7 |
| `svage` | age files and the age plugin protocol | M8 |
| `svgui`, `svtui` | the managers and prompts | M1–M2 |

**Dependencies:**
- **Allowed:**
  - the Go standard library;
  - `golang.org/x/crypto` (Argon2, ChaCha20-Poly1305, scrypt for age
    passphrases, `ssh` for SSH key formats; and for OpenPGP, CAST5,
    Blowfish and Twofish to read old data, and cryptobyte for ECDSA
    signatures), `golang.org/x/sys`,
    `golang.org/x/term`;
  - `github.com/codemodify/uitoolkit` in the GUI binaries only;
  - `tview`/`tcell` in the TUI only.
- **Everything else is our own code**, including D-Bus, OpenPGP, CTAP2, PC/SC,
  TPM2 and the Assuan protocol.
- **Adding a dependency** needs an entry in this section saying why.
- **cgo** is used only where an OS leaves no other way: uitoolkit's X11,
  Wayland and AppKit backends, and on macOS the code-signing and Keychain
  calls, behind build tags.

## Platforms

Supported:
- Windows 10 22H2 and 11.
- macOS 14 and later.
- Linux distributions from the last three years.

All on x86-64 and ARM64.

| Area | Linux | Windows | macOS |
| --- | --- | --- | --- |
| Daemon socket and caller identification | Unix socket, `SO_PEERCRED` | AF_UNIX socket, peer PID and token; Authenticode later | Unix socket, `LOCAL_PEERCRED`; code signature later |
| System keyring | replaced (Secret Service) | bridged; passkey provider later | bridged; AutoFill extension later |
| Login unlock | PAM | DPAPI slot | login Keychain item |
| Quick unlock | fingerprint via fprintd, YubiKey, TPM | Windows Hello, YubiKey, TPM | Touch ID, YubiKey, Secure Enclave |
| Containers | loop or dm-crypt | VHD attach or iSCSI | `hdiutil` |
| GUI | uitoolkit (X11, Wayland) | uitoolkit (Win32) | uitoolkit (AppKit, cgo) |
