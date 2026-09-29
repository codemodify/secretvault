# secretvault roadmap

Every milestone ends in something a person can use, and each has a test that
proves it. Milestones after M1 depend mostly on M0 and M1, not on each other.
The order below is the planned order, and they can overlap.

[architecture.md](architecture.md) describes the design these build towards.

## M0: vault format and engine (done)

- **Crypto.** The `sv1-modern` and `sv1-nist` cipher suites, passphrase KDFs,
  hybrid post-quantum recipients, STREAM, Shamir, and locked memory
  (`svcrypto`).
- **Format and storage.** The v1 on-disk format with golden test vectors
  (`svformat`), and directory and memory backends (`svstore`).
- **Engine.** Keyslots (passphrase, recovery key, keyfile, recipient), items,
  revisions, conflicts and merge, verify (`svcore`).
- **CLI.** `secretvault` opening vault folders directly: `init`, `set`, `get`,
  `ls`, `mv`, `rm`, `history`, `gen`, `slot`, `passwd`, `identity`, `verify`.
- **Scaffold.** Stubs for the daemon, the TUI and GUI, and both prompts.

**Done when:** `go test -race ./...` passes, and the tree builds with
`CGO_ENABLED=0` for Linux, Windows and macOS on amd64 and arm64.

## M1: the daemon and consent broker (done on Linux)

- **`secretvaultd` user mode.**
  - Transport: the Unix socket, or a named pipe on Windows, with same-user
    checks, a lock file, and auto-start by clients.
  - JSON-RPC API (`svrpc`), with a Go client library in the root package.
- **Caller identification** on each OS: path and publisher signature;
  Flatpak and Snap app IDs.
- **Grants** (once, until lock, always, deny), stored as encrypted records,
  with revocation, and an encrypted audit log.
- **Auto-lock** on logout, screen lock, sleep and idle, configurable per
  vault, with defaults that follow the unlock method.
- **Prompts** over the pinentry protocol:
  - `secretvault-gui-prompt` (uitoolkit);
  - `secretvault-tui-prompt`, including askpass mode and `--agent`.
- **The CLI** becomes a pure client of the daemon.
- **Integration.** comms-mail's `keyringKey` hook is wired to secretvault.
- **Autostart.** A systemd user unit, a launchd agent, and a Windows per-user
  logon task. Installers come as scripts (`install.sh`, `install.ps1`).
- **Before the GUI prompt:** the uitoolkit gaps it depends on
  ([../uitoolkit-gaps.md](../uitoolkit-gaps.md)).

**Done when:**
- comms-mail gets its key through a prompt, and a second request is answered
  from the remembered grant.
- Locking the screen locks the vault.
- A process of another user is refused.

**Where it stands.**
- **Built and tested on Linux**, including locking on screen lock, sleep and
  logout. That follows logind and the screensaver over our own D-Bus library
  (`svdbus`), brought forward from M3.
- **The comms-mail wiring** is described in [clients.md](clients.md), and
  lands on comms-mail's side.
- **The desktop prompt** is the system's pinentry until
  `secretvault-gui-prompt` can be built (see uitoolkit-gaps.md).
- **Windows and macOS code compiles.** Caller identification there does not
  yet read publisher signatures.
- **Added along the way:**
  - `grant allow`, to decide for a program ahead of time;
  - an audit log sealed so it can be written while locked but read only
    when unlocked;
  - the clipboard in our own Wayland and X11 code (`get --clip`), from M2.

## M2: the desktop password manager

- **The managers.** `secretvault-gui` (uitoolkit, with a tray icon) and
  `secretvault-tui` (tview/tcell): vaults, search, items, generator, history,
  conflicts, grants and the audit log.
- **Built-in TOTP/HOTP authenticator.** Attachments are stream-encrypted.
- **Clipboard.** Copies clear after a timeout and carry "concealed" hints.
- **Import:**
  - 1Password (1PUX), Bitwarden JSON, KeePass KDBX 4, Proton Pass;
  - Chrome, Firefox and Safari CSV, pass;
  - Aegis and Google Authenticator;
  - FIDO CXF.
- **Export:** CXF, KDBX, and encrypted JSON.
- **Setup.** A first-run flow: choose the unlock method, get a recovery key,
  import.

**Done when:** a new user can install, import from each source, and find,
copy and edit a login without the CLI.

## M3: OS keyring and browser (Linux keyring done)

- **Linux.**
  - Our own D-Bus implementation (`svdbus`) and the Secret Service provider
    (`svsecretservice`), with collections mapped to vaults.
  - The Flatpak portal backend.
  - A take-over and restore tool for gnome-keyring, ksecretd, KWallet and
    oo7, which imports what they hold.
- **Windows.** Credential Manager import and mirroring.
- **macOS.** Keychain import and mirroring.
- **Browser autofill.** A native-messaging host that speaks the
  KeePassXC-Browser protocol.
- **Later in this track:** the Windows 11 passkey provider and a macOS
  AutoFill extension. Both need signed native packaging.

**Done when:**
- `secret-tool`, Chromium, VS Code and a KDE app all store and read through
  secretvault, with prompts.
- The browser fills a login.

**Where it stands.**
- **The Secret Service provider is built** and tested against real
  libsecret clients (`secret-tool`, and Python's libsecret bindings) on a
  private bus:
  - Diffie-Hellman sessions;
  - consent as the protocol's own prompt: to a program, an item it has not
    been allowed looks locked;
  - the program that stores an item may read it back;
  - unlocking a locked vault when a program looks.
- **The importer** reads everything out of the current keyring, tested
  against a real gnome-keyring.
- **Taking over.** `secretvault keyring takeover` (with `--dry-run`) makes
  the switch in user files only, and `restore` undoes it.
- **Still to do:** the Flatpak portal backend (it needs a system-wide
  portal file), CredMan and Keychain bridges, and browser autofill.

## M4: hardware

- **YubiKey or FIDO2 key as an unlock keyslot.**
  - FIDO2 `hmac-secret` over CTAP2 on HID, in our own code.
  - HMAC-SHA1 challenge-response.
  - Either alone, or combined with the passphrase.
- **Quick unlock.** TPM (Linux, Windows), Windows Hello, Touch ID and the
  Secure Enclave (cgo), fprintd.
- **Keys on the token.** Through the PIV and OpenPGP card applets over PC/SC,
  in our own code.

**Done when:** a vault unlocks with a touch, and an SSH signature is made on
the token.

## M5: trust store and identities

- **Contacts and verification.**
  - Contacts with keys and verification levels: in person (QR code or
    fingerprint), organisation, public logs or WKD, trust on first use.
  - Key discovery from files, QR, WKD and keyservers, LDAP/AD, and incoming
    mail (Autocrypt, S/MIME).
- **Key formats.**
  - **OpenPGP:** our own implementation (`svpgp`), writing RFC 9580 and
    reading RFC 4880 too. Its test suite checks against real GnuPG and
    Sequoia output.
  - **S/MIME:** built on `crypto/x509`, plus our own CMS (`svcms`).
- **The API.** `verify`, `sign`, `decrypt` and `encrypt-to`, all through the
  consent broker.
- **Mail messages, whole.** Hand over a raw email and get back what it is,
  for both OpenPGP and S/MIME:
  - its structure: PGP/MIME (RFC 3156), inline PGP, S/MIME detached,
    opaque and enveloped (RFC 8551), nested sign-and-encrypt, protected and
    Autocrypt headers;
  - the decrypted body, with consent;
  - each signature's verdict: valid or not, who signed, how well that
    person's key is verified, and whether the key changed since last seen.
- **Agents.** A gpg-agent-compatible agent and an SSH agent (including git
  signing).
- **OS certificate stores.** Contacts' certificates are published to the
  Windows and macOS stores.
- **Your own keys** live in the vault, with the token split offered when a
  YubiKey is present.

**Done when:** comms-mail signs, encrypts, decrypts and verifies OpenPGP and
S/MIME mail through secretvault, recognising every structure above from the
raw message,, and answers "is this signed by Alice?"
correctly across all four verification levels.

## M6: sync and sharing

- **Devices.**
  - Each device has its own identity.
  - Enrolment by QR code from a device that is already trusted.
  - Optional per-device signatures on revisions.
- **Own-server sync.** `secretvaultd --mode=server` as a zero-knowledge hub
  (it stores ciphertext files only), with push.
- **Synced-folder mode, hardened.** Signed checkpoints detect rollback.
- **Sharing with people.** Recipient keyslots. A new epoch (master-key
  rotation) when someone is removed.
- **Recovery.** Shamir recovery shares, and emergency access.

**Done when:**
- Two devices edit through each of the three sync modes and converge.
- A removed person cannot read anything written afterwards.
- A rolled-back folder is reported.

## M7: encrypted containers

- **Container format.** Its own header and keyslots (so it opens without a
  vault), with room for a hidden volume later. Authenticated per-sector
  encryption.
- **Spikes first,** one per OS: serve a decrypted virtual image and attach it
  natively (Linux loop or dm-crypt, Windows VHD or iSCSI, macOS `hdiutil`).
- **Create, format (OS-native filesystem), open, mount, unmount, resize,**
  and change keys. Keys can live in a vault item.

**Done when:** a container created on each OS mounts as a disk there, and
survives a crash during writes without corruption beyond the sectors in
flight.

## M8: secret delivery for services

- **Host mode.** TPM unlock, and a systemd `LoadCredential=` socket.
- **References.** `secretvault run` and `inject` with `sv://vault/item/field`
  references.
- **Server mode: our own HTTPS API.**
  - Auth: tokens, mTLS, and OIDC (GitHub Actions, GitLab, Kubernetes service
    accounts).
  - Path policies, a hash-chained audit log, and Shamir unseal.
- **Kubernetes.** A provider for External Secrets Operator's webhook, and our
  own CSI driver provider.
- **SOPS and age.** `age-plugin-secretvault`.

**Done when:** a systemd service, a Kubernetes pod and a GitHub Actions job
each receive a secret, and none of them stores a credential.

## M9: phone companion

Approve prompts, show TOTP codes, and view items, relayed through your own
server. The technology is decided when M9 starts; uitoolkit has no mobile
back end.

## M10: 1.0

- **Format.** Frozen, with a written migration policy.
- **Release.**
  - Signed binaries: Authenticode on Windows, notarization on macOS.
  - Reproducible builds.
  - Install and uninstall scripts for each OS.
- **Security.** An external security audit, and the fixes it calls for.
- **Documentation.** A user guide and an operator guide for server mode.

## Decisions log

Settled with the project owner on 2026-09-28. Change them here when they
change.

| Topic | Decision |
| --- | --- |
| Scope | All four purposes designed in from the start |
| Audience | A public product |
| Vault format | Our own (not built on age), interoperating with age and SOPS through a plugin |
| Dependencies | Minimal, our own code. Exceptions: `golang.org/x/{crypto,sys,term}`, uitoolkit (GUI), tview/tcell (TUI) |
| OpenPGP | Our own implementation |
| Engineering secrets | Delivery only; no StrongDM-style access gateway |
| Server API | Our own only; no Vault or cloud compatibility layers |
| Containers | Native disk with the OS's own filesystem, best route per OS; admin once is fine; hidden volumes later |
| Key types in the trust store | OpenPGP, S/MIME/X.509, SSH, secretvault identities |
| Verification levels | In person, organisation, public logs or WKD, trust on first use |
| Own private keys | In the vault by default; token split offered when a YubiKey is present |
| Tokens and 2FA | YubiKey unlock, keys on the token, built-in TOTP, phone approvals (later) |
| Sync | Own server (zero-knowledge), synced folder, or none. A hosted service possibly later |
| Unlock | Chosen at setup: OS login or a separate passphrase |
| Auto-lock | Configurable; defaults follow the unlock method |
| Prompting | Once per program, remembered, revocable |
| Program identity | Path plus publisher signature |
| Vaults | Several, one default |
| CLI | Daemon only (M0's direct mode is transitional) |
| Platforms | Windows 10 22H2 and 11, macOS 14+, Linux from the last ~3 years; amd64 and arm64 |
| Distribution | Downloadable signed binaries with install scripts |
| Language | English only |
| Telemetry | None; no crash reports. An update check, if added, can be turned off |
