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
| `secretvaultd` | The daemon. It holds the keys and is the only process on a machine of people's that opens vaults. It runs in user or host mode; server mode is `secretvault-server` (below). It links no UI code, which a test enforces. |
| `secretvault` | The CLI, a pure client of the daemon, which it starts if needed. In M0 only, it opens vault folders directly. |
| `secretvault-gui` | The desktop manager on [uitoolkit](https://github.com/codemodify/uitoolkit), with a tray icon. The daemon asks it for passphrases in a window of its own. |
| `secretvault-tui` | The full-screen terminal manager, built on tview/tcell. |
| `secretvault-gui-prompt` | A small, focused window that asks for a passphrase or a decision. It is also a pinentry and askpass. |
| `secretvault-tui-prompt` | The same on a terminal, and a `pkttyagent`-style prompt agent for sessions without a display. |
| `secretvault-server` | Server mode: the sync hub, and secret delivery to services and CI. |
| `secretvault-csi-provider` | The Secrets Store CSI driver's provider, on each Kubernetes node. |

Small helpers are the same binary under other names (dispatched on
`argv[0]`): `git-credential-secretvault`, `docker-credential-secretvault`,
`age-plugin-secretvault`, and `secretvault-browser`, the browser's
native-messaging host (which the CLI also recognises by the arguments a
browser starts a host with).

### Daemon modes

| Mode | Runs as | Unlocked by | Serves |
| --- | --- | --- | --- |
| `user` (default) | the logged-in user, per session | the person: login, passphrase, fingerprint, YubiKey | every desktop face |
| `host` (`--host`, Linux) | a system service, as root | the host identity: a systemd credential sealed to the TPM2 or the host key, or a root-only file | systemd credentials and local services, by policy; container unlock at boot later |
| `server` | a service on a server (`secretvault-server`) | Shamir key shares (k of n operators), or a TPM-sealed systemd credential | the HTTPS API: sync hub (ciphertext only) and secret delivery to services and CI |

Server mode is its own binary, `secretvault-server`, rather than a mode of
`secretvaultd`: it links none of the desktop faces, and its keys are the
server's own (a root key and identities), not a person's vaults.

The modes are one daemon with a switch (`svd.Options.Mode`), not forks.
The host daemon never prompts, and does not serve the Secret Service, the
SSH agent, the browser or the prompt protocol, nor open vaults at a
login; its vaults do not lock on idle unless their `auto_lock` says so. It is described under
[Secret delivery](#secret-delivery).

## Talking to the daemon

Clients speak JSON-RPC 2.0, one object per line, as comms-mail and
comms-chat-lan do ([`svrpc`](../svrpc)). Methods are `noun.verb`, for example
`vault.unlock`, `item.get` and `grant.revoke`.

- **Both directions.** The daemon calls back into secretvault's own
  programs (`prompt.ask`): the CLI and `secretvault-tui`, to prompt on
  their terminal, and `secretvault-gui`, to prompt in a window of its own.
- **Events.** Events are notifications without an id, for example
  `vault.locked` and `item.changed`.

| OS | Transport | Who may connect |
| --- | --- | --- |
| Linux, BSD | Unix socket `$XDG_RUNTIME_DIR/secretvault/secretvaultd.sock`, 0600 in a 0700 directory, with a lock file | same uid, checked with `SO_PEERCRED` |
| macOS | Unix socket `$TMPDIR/secretvault-<uid>/secretvaultd.sock`, 0600 | same uid, checked with `LOCAL_PEERCRED` and `LOCAL_PEERPID` |
| Windows | AF_UNIX socket `%LOCALAPPDATA%\secretvault\run\secretvaultd.sock`, with a lock file held by `LockFileEx` | same user SID, checked through `SIO_AF_UNIX_GETPEERPID` and the peer's token |
| Linux, host mode | three Unix sockets in `/run/secretvault` (0755): `admin.sock` 0600, `credentials.sock` 0600, `secretvaultd.sock` 0666 | root on the first; systemd (PID 1 or uid 0) on the second; any local service on the third, which gets only what the host policy lists for its uid and program |

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

`secretvault-gui` is one of secretvault's own programs too, and proves
itself the same way, with the passphrase, but in a window, not on a
terminal. So it is known by its **executable**, like any other program,
even when it was started from a terminal: what it proved in its window
says nothing about who types in that terminal, and the CLI there is still
asked. Proving covers the GUI's connection until the vault locks; nothing
is remembered for its executable unless someone decides so ahead of time
(`secretvault grant`), and it is never shown a consent question, since
every question the daemon puts to it is a passphrase.

### What is decided

A grant covers (program, item or whole vault, operation). The operation is
one of read, list, write, delete, manage, sign, decrypt or mount. Signing,
decrypting and opening a container with a key held in a vault are their
own operations, so a program allowed them still cannot read the key. The contacts are decided
about as an "item" of their own: a decision about them covers no item,
and one about an item covers no contacts.

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
CLI and `secretvault-tui` on their terminal, `secretvault-gui` in its own
window, and the prompt programs. Any
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
   for its own requests only. The TUI asks in a dialog drawn inside it;
   `secretvault-gui` asks in a dialog window of its own.
2. A registered `secretvault-tui-prompt --agent`.
3. The desktop prompt, when there is a desktop (a Wayland or X11 display on
   Linux; always on Windows and macOS). The daemon starts a fresh one for
   each question:
   - `prompt.program` in the config, when it names one (`none` turns desktop
     prompts off);
   - else `secretvault-gui-prompt`, when it is installed beside the daemon;
   - else the system's pinentry: pinentry-gnome3 on GNOME-like desktops,
     else pinentry-qt or pinentry-gtk, taken only from `/usr/bin`,
     `/usr/local/bin` and `/bin`, never looked up on `PATH`.
4. Later, the phone companion.

With nobody to ask, the answer is no, and the error says how to decide
ahead of time.

Prompters speak the **pinentry protocol** (Assuan, [`svprompt`](../svprompt)),
so they double as `pinentry` for gpg-agent and as askpass helpers.
secretvault's own prompters understand an extension (`ADDCHOICE`, `CHOOSE`)
for the four-way consent question. A plain pinentry gets three buttons:
allow once, allow until locked, and deny.

Security keys add two questions (`prompt.ask` kinds `pin` and `notice`).
A key's PIN is asked for like a passphrase, by the same prompters, saying
how many tries the key has left. "Touch your security key" is a notice:
the CLI and the terminal agent print it, `secretvault-tui` puts it in its
status line, and on the desktop it is a pinentry window with a Cancel
button (as gpg-agent does it), closed once the key is touched; Cancel
stops the key waiting and asks for the passphrase instead.

**The desktop prompt** (`secretvault-gui-prompt`, on
[uitoolkit](https://github.com/codemodify/uitoolkit)) is a small dialog
window:

- **It says whose it is.** Every dialog opens under the same secretvault
  band, with the title naming the vault. The program asking is set out on
  its own ("Program: /usr/bin/mail"). A prompt started by anything other than
  the daemon beside it also names the program that started it, so one
  started by a program imitating the daemon shows it.
- **The passphrase is never a string.** It is typed into a uitoolkit
  `SecretField`, which holds it in a `[]byte` and refuses copy, cut, drag
  and the X11 primary selection. It leaves as a copy of those bytes, which
  `svprompt` escapes into D lines on bytes and wipes, and the daemon reads
  them the same way. The field is wiped as the dialog closes, however it
  closes.
- **The keyboard is held** while a passphrase field has it (an X11 grab,
  Wayland's shortcut inhibitor, macOS secure input; Windows has nothing to
  offer), and input methods are off in the field.
- **The window is a dialog**: centred, above other windows, fixed in size,
  activated, and kept out of screenshots and screen shares where the
  platform can do that (Windows and macOS).
- **Consent** shows every answer the daemon offers. Deny is the default,
  and Escape, the close button and `SETTIMEOUT` all cancel, which the
  daemon takes as no.
- **Timeouts and errors.** A retry shows why the last try failed
  (`SETERROR`). A new passphrase is typed twice and must match
  (`SETREPEAT`).

It runs the protocol on stdin and stdout, or as an askpass helper when
given a prompt (`SSH_ASKPASS`, `SUDO_ASKPASS`). It has no `--agent` mode, as
the daemon starts it for each question. What uitoolkit provides for it,
and what it still lacks (such as a caps-lock state), is in
[../uitoolkit-gaps.md](../uitoolkit-gaps.md).

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
  - **OS login** (`secretvault vault login on`). The vault opens when you
    log in, as GNOME Keyring and the login Keychain do. It gets a keyfile
    slot labelled `login`, whose key the OS seals to you on this machine
    ([`svseal`](../svseal)), kept in the data directory; secretvaultd has
    the OS open it as it starts with your session:
    - Linux: `systemd-creds --user` (systemd 256 and later), under the
      host key and the TPM2 when there is one;
    - Windows: DPAPI, under your logon credentials;
    - macOS: an item in the login keychain.

    Programs still ask before they read anything; login unlock spares the
    passphrase, not the consent. (A PAM hook, which would take the key
    from the login password itself, may come later.)
  - **Separate passphrase.** Unlock independently of the OS login.

  Either way, quick unlock (fingerprint, Windows Hello, Touch ID, YubiKey,
  TPM) can be added as more keyslots.
- **Auto-lock is configurable per vault.** The defaults follow how the vault
  was unlocked:
  - a vault unlocked by the OS login locks at logout;
  - a vault unlocked by passphrase also locks on screen lock, sleep and
    idle.
- **Recovery.** A printed recovery key is offered at setup (a `recovery`
  keyslot). It can instead be printed as Shamir shares, any k of n of which
  rebuild it (`slot add recovery --split 5 --threshold 3`), to give to
  people or places none of which can open the vault alone; `unlock
  --shares` asks for them. The shares are made and combined by the CLI,
  and the whole key is never shown.

## Storage and sync

The vault format ([format.md](format.md)) is a folder of files that are only
ever added. That gives three sync modes on one format:

1. **No sync.** One device, with backups.
2. **Synced folder.** Put the vault folder in Syncthing, Dropbox, iCloud Drive
   or git. Conflicting edits become two revisions that every device resolves
   the same way. The daemon reads the folder again (at most once a second)
   before a request uses the vault, so what other devices wrote shows up,
   and a rotation made on one of them locks the vault here.
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
    gives sandboxed apps their per-app secret: a key of each app's own
    (`flatpak/<app id>` in the default vault, made on first use), under the
    usual per-app consent. It answers on the Secret Service's connection at
    `/org/freedesktop/portal/desktop`, which `gnome-keyring.portal` points
    at, and only to xdg-desktop-portal itself: anyone else on the bus could
    otherwise ask for any app's key.
  - **Take-over and undo.** `secretvault keyring takeover` imports what the
    current keyring holds, then changes only user files (recorded for
    `restore`):
    - a D-Bus activation file for `org.freedesktop.secrets`;
    - where the desktop's `portals.conf` picks another Secret portal backend
      (KDE picks kwallet), the user's copy of it choosing `gnome-keyring`,
      which then reaches secretvault;
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
- **Everyday tools.** A password generator, attachments (each a
  stream-encrypted blob under a key only its item holds),
  history, and a conflict view.
- **Clipboard.** Copies clear themselves after a timeout and carry the
  "concealed" hints that clipboard managers respect.
- **Import.** From 1Password (1PUX), Bitwarden (JSON), KeePass (KDBX 4),
  Proton Pass, browser CSVs, pass, and Aegis / Google Authenticator, plus the
  FIDO Credential Exchange Format (CXF).
- **Export.** To CXF, KDBX, and encrypted JSON.
- **Browser autofill.** secretvault stands in for KeePassXC behind
  KeePassXC's existing, reviewed browser extension, KeePassXC-Browser
  (Firefox, Chrome, Chromium, Brave, Edge, Vivaldi). We write no extension
  of our own.
  - **The host is a relay.** The browser starts `secretvault-browser` (the
    CLI) by the manifest named `org.keepassxc.keepassxc_browser`, and talks
    to it in native-messaging frames on stdin and stdout. The relay hands
    each frame to the daemon (`browser.open`, then `browser.message`) and
    the answers back. It holds no key and makes no decision.
  - **The protocol lives in the daemon** ([`svbrowser`](../svbrowser),
    `svd/browser.go`): `change-public-keys` swaps X25519 keys in the clear;
    everything after is NaCl `crypto_box` with the extension's random
    nonce, answered under that nonce plus one. A nonce is used once, so
    replays, and our own answers sent back, are refused.
  - **Who is asking is the browser.** The daemon accepts `browser.open`
    only from its own binary, then looks up the relay's parent process
    itself (`svpeer.Parent`) and names that in every prompt and audit
    entry: "firefox (/usr/lib/firefox/firefox) wants the login
    "web/github.com" for github.com".
  - **Connecting** (`associate`) asks the person once. The association (a
    name, the extension's identification key, the browser's identity) is
    a vault record of this device; `secretvault browser ls` and `rm` list
    and remove them, and a removed one stops working at once.
  - **Logins.** `get-logins` offers the login items whose URL fields
    (`url`, `url2`..., `website`, or of type `url`) or `url`/`*_url`
    attributes match the page: the same host, or a parent domain of it,
    never a bare top-level name; the scheme must match, and a stored port.
    Each one handed over is a read of that item, decided like any other
    program's (a remembered decision, else a prompt) and audited. A refusal
    looks like "no logins", so it tells the extension nothing.
  - **Saving** is a write (new logins go under `web/` unless a group is
    chosen, and the browser may read back what it saved); the extension's
    groups are the vault's folders (seeing them is listing the vault); the
    one-time code is a read. The database hash is an HMAC of the device's
    and vault's IDs under a key derived from the vault key.
  - **Locking.** The session is on one vault (the default); when it locks
    or unlocks, the extension is told. A locked vault is unlocked only when
    the extension asks for it (`triggerUnlock`), on the desktop prompt.
  - **Not served:** passkeys and auto-type, answered as KeePassXC before
    2.7.7 answers them; the host reports that version, so the extension
    leaves passkeys to the browser.
  - **Setting it up.** `secretvault browser install` writes the manifest
    in each browser's per-user place (Linux fully; macOS's Library paths
    and Windows' registry keys written but untested). A manifest already
    there (KeePassXC's) is kept, and `uninstall` puts it back exactly,
    recorded as `keyring takeover` records its changes.

#### The desktop manager

`secretvault-gui` ([`gui/svmanager`](../gui/svmanager)) is a client of the
daemon like the CLI and the TUI, and holds no keys. Everything that talks
to the daemon runs off the interface's goroutine, because the daemon may
answer only after asking the person, through the same program.

- **Selecting is not opening.** Selecting an item shows what the list
  already knows (kind, label, tags, attributes, files); its fields are
  fetched when it is opened (Enter), because every fetch is a read that the
  daemon records in the audit log.
- **Concealed values** stay in the byte slices they arrived in. uitoolkit's
  labels draw Go strings and keep each one shaped in the face's cache for
  the face's life, so a secret never goes into one: it is drawn straight
  from its bytes (`style.Font.DrawBytes`, which caches nothing), masked
  with a fixed-length mask until revealed, one field at a time, and told to
  assistive technology as "concealed" with no content. One-time codes and
  generated passwords are drawn the same way. Secrets are typed into
  uitoolkit's `SecretField`.
- **Wiping.** The open item's values are zeroed when the item is left, when
  its vault locks (the `vault.locked` event, or Ctrl+L, clears the screen at
  once), when the window is hidden in the tray, and on quit. So are the
  history's revisions, the editor's secret fields, a generated password and
  a new vault's recovery key, when they close.
- **Copies** go to uitoolkit's secret clipboard: CLIPBOARD only, marked for
  clipboard managers not to keep, cleared after 30 seconds and on quit, and
  taken back when the vault they came from locks.
- **Out of sight.** While a secret shows, the window asks to be left out of
  screenshots and screen sharing (honoured on Windows and macOS), and the
  passphrase dialog holds the keyboard where the platform allows.

Where a secret still becomes a Go string:
- a one-time password key, while svotp parses it, and the code svotp
  makes;
- a new vault's recovery key, which the daemon's answer carries as a string;
- the values of fields that are not secret (text, URLs, e-mail);
- what JSON encoding and decoding make on the way to and from the daemon,
  as for every client;
- on X11, the copy uitoolkit serves the clipboard from while it owns it.

A key of several lines (a PEM private key) does not fit a one-line
`SecretField` and uitoolkit has no secret text area, so the editor keeps it
as it is, or replaces it from a file read straight into bytes.

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
    our own CMS (`svcms`): signed data with its signed-attribute and ESS
    checks, enveloped and auth-enveloped data decrypted through an
    interface that keeps the private key in the vault, certificate chains
    with S/MIME's usage and address rules, and PKCS #12 import and export.
  - **SSH.**
  - **secretvault identities.** Post-quantum hybrid (ML-KEM-768 + X25519).
- **Contacts** ([`svtrust`](../svtrust)) are vault records of kind
  `contact`, so they are encrypted, keep their history and sync like
  items; a contact changed on two devices at once is merged when read
  (every address, key, verification and sighting of both). Their JSON
  keeps members a newer version adds. They live in the default vault, or
  a configured contacts vault (`secretvault contact vault NAME`).
- **How a key is verified.** Each key records its verification events:
  the level, the method, who recorded it, when, and where from. Levels,
  from strongest to weakest:
  1. In person, by QR code or comparing a fingerprint face to face.
  2. Vouched for by an organisation: a certificate that chains to the CA
     of a contact marked as an organisation, or its directory.
  3. Recorded in a transparency log (the level is reserved; nothing
     records it yet).
  4. Published: by the address's domain (WKD), or by a keyserver that
     checked the address by email (keys.openpgp.org).
  5. Trusted on first use. An event covers the key as a whole, or only
     the addresses it names: a key found by WKD is published for that one
     address.
- **Trust on first use** binds an address to the first key seen for it,
  and counts the messages (first seen, last seen, how many) per address
  and key. A different key for an address that already has one is kept
  apart, in a contact of its own, with the conflict recorded: it never
  quietly replaces the first, and verdicts about it warn of an impostor
  until you verify it.
- **Where keys come from.**
  - Files: OpenPGP (armored or binary, many at once), PEM or DER
    certificates (the chain becomes the certificate's intermediates), SSH
    public keys and authorized_keys lines, secretvault recipients.
  - QR codes: `openpgp4fpr:` and our own `secretvault-contact:` URI,
    which carries a name, addresses and fingerprints (not keys), so a
    scan verifies keys you have, or names the ones to fetch.
    `secretvault contact qr` draws yours on the terminal
    ([`svqr`](../svqr), our own encoder).
  - WKD (the advanced method, then the direct one when the `openpgpkey`
    subdomain does not exist), keeping only keys that name the address;
    keyservers by VKS, then HKP.
  - A company directory: the `Directory` interface, for LDAP/AD or an
    organisation's secretvault server, not yet implemented.
  - Incoming mail: `trust.seen` records a key that came with a message
    (the Autocrypt header's key, an S/MIME certificate); parsing the mail
    is the mail face's work.
- **Using the keys.**
  - **Our API:** `trust.check` takes the signer's fingerprint or
    certificate and the claimed From address, and returns the facts: the
    contact, the best verification for that address and for the key
    alone, whether the address is bound to the key, how often it was seen,
    other contacts' keys bound to the address, and reasons in plain words
    ("Signed by Alice Example's key, which you verified in person on
    2026-09-01."). A policy, which the caller may set, judges the facts:
    verified, unverified, suspicious or unknown. `pgp.sign`,
    `pgp.decrypt` and `pgp.verify` use your OpenPGP keys and your
    contacts, each through the consent broker. `encrypt-to` is to come.
  - **Whole messages:** `mail.inspect(raw message)` recognises PGP/MIME,
    inline PGP and S/MIME (signed, encrypted, both, nested). It returns the
    decrypted body, with consent, and a verdict per signature, so a mail
    client needs one call and no crypto of its own. The library under it
    (`svmail`) reads MIME itself, keeping the exact bytes each signature
    covers, and reports every layer, what it covers (a signature over one
    part is a warning), protected header fields (RFC 9788) that differ
    from the outer ones, and Autocrypt keys. It asks a `Keys` interface for
    public keys and for decryption, and states cryptographic facts only;
    the trust store maps keys to people.
  - **Agents:** a gpg-agent-compatible agent (so gpg, pass, git and
    Thunderbird's external-GnuPG mode work) and an SSH agent, which also
    covers git signing.
  - **OS certificate stores:** contacts' certificates are published to the
    Windows and macOS stores for Outlook and Apple Mail.
- **Your own private keys** live in the vault by default. An OpenPGP key
  is an item of kind `key` (the armored secret and public keys, the
  passphrase if it has one, the fingerprint and primary user ID as
  attributes), made in the daemon by `pgp.generate` (version 6, or 4 for
  GnuPG). Signing and decrypting happen in the daemon; the key leaves it
  only when you export it. With a YubiKey present, secretvault offers the
  usual split:
  - the signing key is made on the token;
  - the decryption key is made in the vault and copied to the token, with the
    vault copy kept as a backup, so old mail stays readable.

### Encrypted containers

- **A container is a LUKS2 image file**, the format of Linux's cryptsetup,
  written and read by our own code ([`svluks`](../svluks)): a 16 MiB header
  (two checksummed copies of the metadata, and the keyslots), then the data,
  AES-256-XTS per 512- or 4096-byte sector. The header carries its own
  keyslots, so the image opens on a machine that has never seen your vault,
  with any LUKS2 tool. Hidden volumes are not possible in LUKS2.
- **Its key is a vault item** of kind `container`
  ([`svcontainer`](../svcontainer)): 256 random bits as 64 hex digits, the
  passphrase of keyslot 0, with the image's path and LUKS UUID as
  attributes. `--passphrase` (or `container passwd`) adds a keyslot that
  opens with a passphrase, for opening it with cryptsetup alone.
- **Consent** is the vault's: creating a container writes an item;
  opening one is `mount` on its item, asked naming the image, and is not
  reading the key. Closing needs none.
- **Inside** is the OS's own filesystem: ext4 by default, or exFAT, FAT or
  btrfs.
- **Mounting with the OS's own tools, no kernel code of ours.**
  - **Linux:** through UDisks2 on the system bus ([`svudisks`](../svudisks)):
    `Manager.LoopSetup` with the image's descriptor, `Encrypted.Unlock` with
    the key as `keyfile_contents`, `Block.Format` (taking ownership) for a
    new one, and `Filesystem.Mount`; closing is the reverse. This is the
    route file managers take for USB drives, so polkit lets the person at
    an active session do it without an administrator's password. The daemon
    checks the header itself (sound, AES-XTS, opened by the key) before the
    kernel sees it.
  - **Windows and macOS:** `svluks` reads and writes the decrypted sectors in
    userspace; the mount layer that will serve them to the OS (VHD or
    iSCSI, `hdiutil`) comes later.
- **Locking** a vault leaves its containers mounted, as VeraCrypt does;
  `close_containers_on_lock` in the config closes them with the vault.

### Secret delivery

- **References.** `secretvault read`, `run -- cmd` and `inject` resolve
  `sv://VAULT/ITEM[#FIELD]` references (`-` for the default vault; no
  field means the item's secret) into output, environment variables or
  files.
- **Hosts** (`secretvaultd --host`, [`svd/host.go`](../svd/host.go)).
  - **systemd's `LoadCredential=`.** A unit says
    `LoadCredential=db-password:/run/secretvault/credentials.sock`. What we
    rely on, from systemd.exec(5): each time the unit starts, systemd
    connects to that stream socket once, from an abstract address
    `\0RANDOM/unit/UNIT/ID`, and reads until the connection ends; the
    process that connects is the one systemd forks to start the unit,
    still root (so the check is PID 1 or uid 0, by `SO_PEERCRED`); the
    data lands in `$CREDENTIALS_DIRECTORY/ID`, readable by the unit's user
    only, and a unit's credentials may total 1 MB. The daemon reads the
    address with `getpeername`, looks the unit and credential up in the
    policy, writes the value and closes. Anything else is closed with
    nothing written, which the unit sees as an empty credential: systemd
    cannot tell a refusal from an empty secret, so a service that must
    not start without one should check.
  - **Socket activation.** `secretvaultd install --host` writes
    `secretvaultd-host.socket`, which holds `credentials.sock` from early
    boot, and `secretvaultd-host.service`, which takes it
    (`LISTEN_FDS`). A unit that starts before the daemon waits for its
    credential instead of failing, so no unit orders itself after the
    daemon; a unit that runs before `basic.target` cannot use it.
  - **The policy**, `/var/lib/secretvault/host.json`, root's and 0600,
    lists everything served; anything it does not list is refused. It is
    read again when it changes (so it can be written by hand or by
    configuration management), and a file that does not parse, has an
    unknown field, or that anyone but root could have written refuses
    everything until it is fixed:

    ```json
    {
      "credentials": [
        {"unit": "postgresql.service", "credential": "db-password", "ref": "sv://prod/db/postgres#password"},
        {"unit": "app@*.service", "credential": "api-token", "ref": "sv://prod/app/token"}
      ],
      "clients": [
        {"user": "backup", "program": "/usr/local/bin/backup", "refs": ["sv://prod/backup/*"]}
      ]
    }
    ```

    A unit is named exactly or by a glob; the exact name wins, then the
    first glob. `secretvault host allow`, `deny` and `ls` edit and show it.
  - **Local services that are not units** (cron jobs, scripts run as a
    service user) use the client API on `/run/secretvault/secretvaultd.sock`
    (`secretvault --host read`, `run`, `inject`). They may call
    `host.resolve` and nothing else, and get the one value a reference
    names, if a `clients` entry lists it for their uid (a name or a
    number) and program (the executable, or the script an interpreter
    runs; any, when left out). Globs work in the item and the field.
  - **root** administers it on `/run/secretvault/admin.sock`: `secretvault
    host status | allow | deny | ls | audit`, and every other command with
    `--host` (`vault add`, `sync join`, `share`, `unlock`...).
  - **Unlocking at boot.** A vault for the host is made on an admin's
    machine, shared to the host's recipient (`secretvault share`), and
    copied or synced to `/var/lib/secretvault/vaults/`. The host identity
    that opens it is made by `secretvault host init --seal`, which hands
    it to `systemd-creds encrypt` on its standard input (sealed to the
    TPM2 and the host key where there is a TPM2, else to the host key)
    without writing it in the clear; the service loads it with
    `LoadCredentialEncrypted=` (systemd 250 and later), and the daemon
    reads it from `$CREDENTIALS_DIRECTORY` at start and opens every vault
    it can. Without systemd-creds, `host init` writes a root-only
    `/var/lib/secretvault/host.identity`, and `install --host
    --plain-identity` leaves the credential out. A vault that locks (by
    request, idle, or a rotation elsewhere) is opened again with the
    identity on its next use; one it does not open stays locked, and root
    can unlock it with a key.
  - **The log.** Every delivery and refusal goes to
    `/var/lib/secretvault/host.log` (one JSON object per line, moved
    aside at 8 MiB) and the journal; every read also goes to the vault's
    own audit log. `secretvault host audit` shows it.
- **Server API** ([`svdeliver`](../svdeliver), [delivery.md](delivery.md)).
  Our own HTTPS API only; there are no Vault or cloud compatibility layers.
  - **Delivery vaults.** `secretvault-server -delivery-dir DIR` holds vaults
    open with an identity of its own, through recipient keyslots their
    owners gave it (`secretvault share`). It only reads them; whatever
    syncs the folder (its own hub, where a vault is added by its sync name,
    or Syncthing and the like) brings changes, read at most once a second.
    Each vault's ID is pinned when it is added.
  - **Mounted beside the sync hub**, under `/v1/deliver/` on the same
    listener (which asks clients for a certificate they need not send), or
    on its own with `-deliver-listen`: say, an internal address while the
    hub faces the internet. The hub itself is unchanged; the two share a
    process and a certificate, not state.
  - **Sealed at start.** A root key seals everything (identities, policy,
    audit key); it is sealed under an unseal key split into Shamir shares
    (k of n), given one per request, held in memory with a timeout, never
    logged; and optionally under a credential key for systemd-creds and the
    TPM, for unattended start. `seal`, `status`, and `rekey`, which takes k
    of the current shares and makes new ones.
  - **Machine authentication**, no human logins:
    - tokens, kept as hashes, with an expiry and CIDRs;
    - mTLS: a client CA with subject and SAN globs, or pinned fingerprints;
    - OIDC ID tokens from GitHub Actions, GitLab CI and Kubernetes service
      accounts, verified in our own code (RS256, ES256, EdDSA; JWKS by
      discovery or configured), so pipelines store no secrets. A login
      gives a 15-minute session; an ID token can also be sent with each
      request.
  - **Path policies.** A role maps one identity (a token, a certificate
    match, or an issuer and claim globs) to rules of vault, item glob and
    capabilities (read, list). Deny by default; "not allowed" and "no such
    secret" read the same.
  - **A hash-chained audit log** of every request, each entry sealed to a
    key of the server's, written while sealed too, with no secret in it.
    svbroker's log was not reused: it is per vault and describes local
    programs, where the server's entries mostly concern no vault and need
    the caller's address and role.
  - The admin API (tokens, roles, vaults, issuers, the client CA, seal,
    rekey, audit) takes an admin token whose hash is in the sealed policy.
- **CI.** `secretvault ci fetch|run` finds the job's ID token (GitHub
  Actions, GitLab's `id_tokens`, a pod's service-account token), logs in,
  and prints, exports or injects the secrets; no daemon needed.
- **Kubernetes.** External Secrets Operator's webhook provider calls the
  API with a token (delivery.md has the ClusterSecretStore). Our own
  Secrets Store CSI driver provider ([`svcsi`](../svcsi),
  `secretvault-csi-provider`) logs in as each pod with the service-account
  token the driver passes; its gRPC and protobuf are our own, on the
  standard library's HTTP/2.
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
  - Via FIDO2 `hmac-secret`, speaking CTAP2 over HID in our own code
    ([`svfido`](../svfido); built on Linux), or challenge-response
    HMAC-SHA1 (as KeePassXC does).
  - The daemon enrols the key and uses it; `svcore` reaches keys through an
    interface and holds no device code. When a vault is to be unlocked,
    every key plugged in is asked without a touch which of the vault's
    credentials it holds, and only that key is asked for its PIN and a
    touch; the passphrase is asked for if no such key is there or it is
    not used.
  - It can be required on its own or (later) together with the passphrase.
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
| `svd` (`ss*.go`, `portal.go`), `svsecret` | the Secret Service face and the Flatpak portal; a Secret Service client, for importing | M3 |
| `svseal` | sealing a key to the user by the OS, to open vaults at login | M1 |
| `svotp` | HOTP, TOTP and Steam codes | M2 |
| `svbrowser` | the KeePassXC-Browser protocol, for browser autofill | M3 |
| `svwayland`, `svx11`, `svclip` | the clipboard in our own protocol code | M2 |
| `svimport` | import from other password managers; export to KDBX and CXF | M2 |
| `svpgp` | OpenPGP, our own | M5 |
| `svcms`, `svtrust` | S/MIME, the trust store | M5 (both built) |
| `svqr` | QR codes, for the terminal | M5 |
| `svmail` | whole mail messages, OpenPGP and S/MIME | M5 |
| `svfido`, `svpcsc`, `svtpm` | hardware tokens and TPM (`svfido`: FIDO2 on Linux) | M4 |
| `svluks`, `svcontainer`, `svudisks` | LUKS2, containers, and mounting them through UDisks2 (Linux) | M7 |
| `svsync`, `svserver` | sync, and the sync server | M6 |
| `svdeliver` | secret delivery: the server's API, seal, auth, policy, audit | M8 |
| `svcsi` | the Secrets Store CSI driver provider | M8 |
| `svage` | age files and the age plugin protocol | M8 |
| `gui/` (a module of its own), `svtui` | the desktop programs (`gui/svmanager` is the manager), with `gui/secretui` for what they share when asking about secrets; the terminal manager | M1–M2 |

**Dependencies:**
- **Allowed:**
  - the Go standard library;
  - `golang.org/x/crypto` (Argon2, ChaCha20-Poly1305, scrypt for age
    passphrases, `ssh` for SSH key formats; for OpenPGP, CAST5,
    Blowfish and Twofish to read old data, and cryptobyte for ECDSA
    signatures, and for CMS and PKCS #12; NaCl `box`, which KeePassXC-Browser
    speaks),
    `golang.org/x/sys`,
    `golang.org/x/term`;
  - `github.com/codemodify/uitoolkit` in the GUI binaries only, which are a
    Go module of their own (`gui/`), so nothing else can come to import it;
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
| Containers | LUKS2 through UDisks2 and dm-crypt, no root | LUKS2 in userspace; mounting later (VHD or iSCSI) | LUKS2 in userspace; mounting later (`hdiutil`) |
| GUI | uitoolkit (X11, Wayland) | uitoolkit (Win32) | uitoolkit (AppKit, cgo) |
