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
  - `secretvault-gui-prompt` (uitoolkit), including askpass mode;
  - `secretvault-tui-prompt`, including askpass mode and `--agent`.
- **The CLI** becomes a pure client of the daemon.
- **Integration.** comms-mail's `keyringKey` hook is wired to secretvault.
- **Autostart.** A systemd user unit, a launchd agent, and a Windows per-user
  logon task. Installers come as scripts (`install.sh`, `install.ps1`).
- **Before the GUI prompt (done):** the uitoolkit gaps it depended on
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
- **The desktop prompt** is `secretvault-gui-prompt` wherever it is
  installed beside the daemon, and the system's pinentry elsewhere. It is
  tested headless, through the protocol, on Linux; it has not yet been run
  on Windows or macOS desktops. It shows no caps-lock warning until
  uitoolkit reports the lock keys (see uitoolkit-gaps.md).
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
- **Built-in TOTP/HOTP authenticator.**
- **Attachments (done).** Files attached to items, each a blob of its own
  sealed under a key the item holds; `secretvault attach`, `file ls|get|rm`;
  they sync, and KeePass attachments import. Files over one message
  (about 12 MiB) through the protocol, and exporting attachments, come
  later.
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

**Where it stands.**
- **`secretvault-tui` is built** (`svtui`): vaults with their lock state,
  a filtered item list, items with masked values and live TOTP codes, an
  editor with the generator, copy with auto-clear through the CLI's
  clipboard helper, history, grants and the audit log. The daemon asks it
  for passphrases in a dialog of its own. Concealed values are drawn and
  typed from byte slices rather than Go strings, and wiped on leaving an
  item, on lock and on quit.
- **`secretvault-gui` is built** (`gui/svmanager`, on uitoolkit):
  - vaults with their lock state and the default marked, the folders item
    names make, and instant search;
  - items with concealed values masked until revealed, one field at a
    time, and live TOTP codes with a countdown; files saved, attached and
    removed; history, with a conflict's winner and its other heads marked,
    each one viewable and copyable;
  - an editor with starter fields by kind, fields added and removed, and a
    generator of characters or words; rename, and delete after asking;
  - copies through uitoolkit's secret clipboard, cleared after 30 seconds
    and taken back when their vault locks, and "copy and minimise";
  - new vaults (either cipher suite, a recovery key shown once), unlock,
    lock, lock all, the default vault, sync status, grants (and revoking
    them) and the audit log;
  - a tray icon to open it, search, lock every vault and quit; closing the
    window hides it there.

  The daemon asks it for passphrases in a dialog window of its own (the
  prompt's, from `gui/secretui`), into a `SecretField`, and knows it by
  its executable. Secret values are drawn
  from byte slices rather than Go strings, kept out of screen captures
  where the platform allows, and wiped on leaving an item, on lock, on
  hiding to the tray and on quit.
- **Not yet in either manager:** resolving conflicts (they are shown, not
  merged), keyslots (a new passphrase, a recovery key later, rotation),
  import and export, setting sync up, the first-run flow, and settings
  (auto-lock, the clipboard's timeout). The TUI does not create vaults or
  handle attachments yet.

## M3: OS keyring and browser (Linux keyring done)

- **Linux.**
  - Our own D-Bus implementation (`svdbus`) and the Secret Service provider
    (in the daemon, `svd/ss*.go`), with collections mapped to vaults.
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
- **The Flatpak Secret portal backend is built.** It gives each app its
  own key under the usual per-app consent, and answers only
  xdg-desktop-portal itself. It needs no system-wide file: it answers on
  `org.freedesktop.secrets`, where `gnome-keyring.portal` points, and the
  takeover writes the user's copy of the desktop's `portals.conf` choosing
  that backend (on KDE, instead of kwallet).
- **Browser autofill is built** (`svbrowser`, `secretvault-browser`), as
  the backend of KeePassXC-Browser:
  - logins with per-item consent and audit, saving, TOTP codes, folders as
    groups, the password generator, and lock and unlock notices;
  - the browser, not the relay, is who asks: the daemon looks up the
    relay's parent itself;
  - connecting asks once, and associations are vault records
    (`secretvault browser ls`, `rm`);
  - `secretvault browser install` (with `--dry-run`) writes the manifests,
    keeping KeePassXC's, and `uninstall` puts them back exactly;
  - tested end to end by a Go test playing the extension through the
    relay, not yet with a real browser. Passkeys and auto-type are not
    served.
- **Still to do:** CredMan and Keychain bridges; browser autofill tried in
  real browsers, on Windows and macOS, and for browsers in Flatpak or Snap
  (their hosts start through the portal).

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

**Where it stands.**
- **FIDO2 unlock is built on Linux** (`svfido`, and the `fido2` keyslot in
  [format.md](format.md#fido2-slots)):
  - CTAPHID over hidraw, with keys found by their HID report descriptor;
    our own CBOR; CTAP 2.0 and 2.1 with PIN/UV auth protocols 1 and 2;
  - `secretvault slot add fido2 [--uv|--no-uv]`, `unlock --fido2`, and
    `fido2 list`;
  - a vault with a fido2 slot asks for the key before the passphrase
    whenever a key that holds one is plugged in, found without a touch;
  - the PIN is asked for through the usual prompts, which say how many
    tries are left; "touch your security key" is a notice.
- **Tested against a software authenticator** (`internal/fidotest`) with
  two keys, wrong keys, wrong and blocked PINs, cancelled touches and
  malformed frames. **Not yet against real keys.**
- **Still to do:**
  - Windows (webauthn.dll) and macOS (IOKit, which needs cgo);
  - a key's built-in verification (fingerprint) instead of its PIN;
  - a key combined with the passphrase, rather than instead of it;
  - HMAC-SHA1 challenge-response, quick unlock, and keys on the token.

## M5: trust store and identities

- **Contacts and verification.**
  - Contacts with keys and verification levels: in person (QR code or
    fingerprint), organisation, public logs or WKD, trust on first use.
  - Key discovery from files, QR, WKD and keyservers, LDAP/AD, and incoming
    mail (Autocrypt, S/MIME).
- **Key formats.**
  - **OpenPGP:** our own implementation (`svpgp`), writing RFC 9580 and
    reading RFC 4880 too. Done: its test suite checks the RFC 9580 vectors
    and real GnuPG 2.4, both ways. Sequoia, which also speaks version 6, is
    still to add.
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

**Where it stands.**
- **The trust store is built** (`svtrust`):
  - contacts with keys of all four types, in vault records that merge
    when two devices change one at once;
  - verification events at every level (the transparency log level is
    reserved), trust on first use per address and key, and a different key
    for an address kept apart as a conflict, never a replacement;
  - `trust.check`: the verdict on a signer for a From address, as facts
    and plain-words reasons, judged by a policy the caller may set;
  - discovery from files, `secretvault-contact:` and `openpgp4fpr:` QR
    URIs, WKD (both methods), keyservers (VKS, then HKP), and keys seen in
    mail (`trust.seen`); the company directory is an interface only;
  - the CLI: `secretvault contact`, `trust` and `pgp`, and `contact qr`
    on our own QR encoder (`svqr`).
- **Your OpenPGP keys** live in vault items and sign and decrypt inside
  the daemon (`pgp.sign`, `pgp.decrypt`, with `sign` and a new `decrypt`
  operation for consent); `pgp.verify` checks signatures against your
  contacts.
- **S/MIME, our own (`svcms`).** CMS signed data (RSA PKCS #1 v1.5 and
  PSS, ECDSA, Ed25519), enveloped and auth-enveloped data (RSA-OAEP, RSA
  PKCS #1 v1.5 to decrypt, ECDH with AES key wrap; AES-CBC and GCM),
  certificate checks, and PKCS #12 in and out, checked against OpenSSL 3
  both ways.
- **Mail messages, whole (`svmail`).** Every structure above, recognised
  from the raw message, verified and decrypted through a `Keys` interface
  the daemon will implement; protected headers and Autocrypt read; and
  outgoing PGP/MIME and S/MIME, signed, encrypted or both, with protected
  headers. Checked against GnuPG 2.4 and OpenSSL 3 both ways.
- **`mail.inspect` is built:** a mail client hands over a message as
  received and gets back svmail's report and the trust store's verdict on
  every signer; with `decrypt`, what is encrypted to your OpenPGP keys is
  decrypted in the daemon, asked about as decrypting (`secretvault mail
  inspect`).
- **Outgoing mail and your S/MIME keys are built:** `mail.compose` signs
  with your key for the From address (OpenPGP or S/MIME, asked about as
  signing) and encrypts to every recipient's key from your contacts and to
  your own, never to a key the trust store says may be an impostor's;
  `smime.import` keeps a PKCS #12 key and certificate in the vault, which
  then decrypts S/MIME mail in `mail.inspect` (`secretvault mail compose`,
  `secretvault smime import|ls`).
- **The company directory is built** (`svldap`): an LDAP or Active
  Directory directory is asked for a colleague's S/MIME certificates and
  OpenPGP keys, first, and what it gives is recorded as the organisation
  vouching for it (`secretvault contact directory add`, `contact lookup
  --directory`).
- **Still to do:**
  transparency logs, `encrypt-to`, the gpg-agent face, the OS certificate
  stores, and the token split.

**Brought forward and done:**
- **The SSH agent**, tested with OpenSSH's own `ssh-add` and `ssh-keygen -Y`:
  - keys live in vaults;
  - each program's first signature is asked about, and `ssh-add -c` keys
    on every use;
  - `ssh-add -D` deletes nothing.
- **The git and docker credential helpers.**

**Done when:** comms-mail signs, encrypts, decrypts and verifies OpenPGP and
S/MIME mail through secretvault, recognising every structure above from the
raw message, and answers "is this signed by Alice?"
correctly across all four verification levels.

## M6: sync and sharing

- **Devices.**
  - Each device has its own identity.
  - Enrolment by QR code from a device that is already trusted.
  - Optional per-device signatures on revisions.
- **Own-server sync (done).** `secretvault-server` is a zero-knowledge hub
  (it stores ciphertext files only) that tells devices of changes at once.
  The daemon keeps each synced vault in step, locked or not, and reads
  what arrives into the open vault; a rotation made elsewhere locks the
  vault here. `secretvault sync setup | invite | join | status | now |
  devices | rm-device | off`.
- **Synced-folder mode, hardened.** Signed checkpoints detect rollback.
- **Still to come for sync:** a hosted service. (`sync invite --qr` shows
  the invite as a QR code for the new device to scan.)
- **Sharing with people (done).** `share` and `unshare`, and `vault rotate`.
  Master-key rotation is crash-safe, and history stays readable down the
  epoch chain. Epoch records are authenticated under the previous key, so
  a planted one is ignored instead of locking everyone out, and each lists
  the revisions that existed when it was made, so someone cut off cannot
  go on writing with the old key.
- **Opening at login (done).** `secretvault vault login on`: a keyfile slot
  sealed by the OS (systemd-creds, DPAPI, the keychain), opened as the
  daemon starts with the session; the vault locks at logout.
- **Recovery.** Shamir recovery shares (done: `slot add recovery --split N
  --threshold K`, `unlock --shares`), and emergency access (done).
- **Emergency access (done).** A contact with a secretvault identity may
  open a vault after a wait any of the owner's devices can refuse
  (`secretvault emergency grant | ls | deny | revoke`, and on the other
  side `accept | request | open`):
  - an emergency keyslot opens with the trustee's identity and a release
    key together, and the sync server escrows the release key sealed to
    the trustee, keeps the wait on its own clock (across restarts), and
    releases it only after the wait with no denial;
  - the trustee's device accepts by opening a code sealed to their
    identity, so the invite holds no secret;
  - the owner's devices hear of a request at once (events in the change
    log): the audit log, a desktop notice, `secretvault status`, and an
    event to clients;
  - once released, the trustee gets a read-only copy that follows the
    owner's; rotations carry grants over, and `revoke --rotate` cuts the
    trustee off;
  - tested with a server in the test with its own clock, and two
    daemons: denied, released after the wait, revoked, and a server that
    lies about the time and releases early, which gives the trustee
    everything at once ([security.md](security.md#emergency-access) says
    so plainly).

  **Still to do:** escrow with several servers (k of n) so that one lying
  server cannot release early; showing grants and requests in the GUI and
  TUI (they get the `emergency.changed` event); a takeover grant, if
  wanted; approving a request early.

**Done when:**
- Two devices edit through each of the three sync modes and converge.
- A removed person cannot read anything written afterwards.
- A rolled-back folder is reported.

## M7: encrypted containers

- **Container format.** LUKS2 image files (decided 2026-09-29), with their
  own header and keyslots, so they open without a vault and with any LUKS2
  tool. No hidden volumes: LUKS2 has none.
- **Mounting per OS:** Linux through UDisks2 and dm-crypt; Windows (VHD or
  iSCSI) and macOS (`hdiutil`) from sectors decrypted in userspace.
- **Create, format (OS-native filesystem), open, mount, unmount, resize,**
  and change keys. Keys can live in a vault item.

**Done when:** a container created on each OS mounts as a disk there, and
survives a crash during writes without corruption beyond the sectors in
flight.

**Where it stands.**
- **LUKS2 in our own code** (`svluks`): create, open, add, change and
  remove keyslots (Argon2id, Argon2i, PBKDF2), back up and restore headers,
  and read and write the decrypted sectors on every OS. Checked against
  cryptsetup both ways and Python's `cryptography`, with hostile headers
  refused and the parser fuzzed.
- **Linux is done** (`svudisks`, `svcontainer`): `secretvault container
  create|open|close|ls|header-backup|passwd`, through UDisks2 without root.
  Keys are vault items of kind `container`, read and written with consent.
  Tested against a pretend UDisks2 on a private bus; not yet run against
  the real one.
- **Still to do:** the Windows and macOS mount layer, resizing, and the
  crash test in "done when".

## M8: secret delivery for services

- **Host mode (built on Linux).** `secretvaultd --host`, a switch in the
  one daemon:
  - systemd's `LoadCredential=` on `/run/secretvault/credentials.sock`,
    answered from the policy in `/var/lib/secretvault/host.json` (units by
    name or glob) to systemd alone, with a socket unit so units never wait
    on the daemon's start;
  - local services that are not units, by uid and program, read-only, on
    `secretvaultd.sock` (`secretvault --host read | run | inject`);
  - `secretvault host init | allow | deny | ls | status | audit`, and
    `secretvaultd install --host` (a hardened system unit);
  - vaults opened at boot by the host identity, which systemd passes as a
    credential sealed to the TPM2 by `systemd-creds` (or a root-only
    file); every delivery and refusal in the host's log.

  Tested by playing systemd's side on temporary sockets. **Still to do:**
  TPM unlock in our own code (`svtpm`, with a measured-boot policy),
  container unlock at boot (with M7), and a check on a real systemd host
  in CI.
- **References (done).** `secretvault read`, `run` and `inject` with
  `sv://VAULT/ITEM#FIELD` references (`-` for the default vault).
- **Server mode: our own HTTPS API (done).**
  - Auth: tokens, mTLS, and OIDC (GitHub Actions, GitLab, Kubernetes service
    accounts).
  - Path policies, a hash-chained audit log, and Shamir unseal.
- **Kubernetes (done).** A provider for External Secrets Operator's
  webhook, and our own CSI driver provider.
- **SOPS and age (done).** `age-plugin-secretvault`, and `secretvault age`
  (`keygen`, `recipient`, `identity`, `encrypt`, `decrypt`) on our own age
  implementation (`svage`), including the post-quantum recipients of age
  v1.3.

**Done when:** a systemd service, a Kubernetes pod and a GitHub Actions job
each receive a secret, and none of them stores a credential.

**Where it stands.**
- **Server mode is built** ([`svdeliver`](../svdeliver),
  [delivery.md](delivery.md)): `secretvault-server -delivery-dir` holds
  vaults open that their owners shared with its identity, and serves them
  under `/v1/deliver/`, beside the sync hub or on its own listener.
  - Sealed at start: Shamir unseal shares given one per request, or a
    credential key from systemd-creds and the TPM; `seal`, `status`, and
    `rekey` with k of the current shares.
  - Auth: tokens (hashed, with expiry and CIDRs), mTLS (a client CA with
    subject and SAN globs, or pinned fingerprints), and OIDC ID tokens from
    GitHub Actions, GitLab CI and Kubernetes, verified in our own code.
  - Path policies, deny by default; a hash-chained, sealed audit log of
    every request.
  - The admin CLI: `init`, `unseal`, `seal`, `status`, `rekey`, `token`,
    `role`, `deliver add-vault`, `issuer`, `client-ca`, `admin-token`,
    `audit`.
- **CI:** `secretvault ci fetch|run`, with the job's own ID token from
  GitHub Actions, GitLab's `id_tokens`, or a pod's service account.
- **Kubernetes:** our own Secrets Store CSI driver provider
  (`secretvault-csi-provider`, [`svcsi`](../svcsi)), and a documented
  External Secrets Operator webhook configuration.
- **Tested** against a fake OIDC issuer on localhost with RSA, EC and
  Ed25519 keys, including alg confusion, forged and expired tokens and
  claims that do not match; the CSI provider's protobuf against protoc.
- **Still to do:**
  - host mode (TPM unlock, and a systemd `LoadCredential=` socket);
  - a `write` capability, so jobs can rotate what they own;
  - trusted proxies' `X-Forwarded-For`, for CIDR limits behind a proxy;
  - remembering ID tokens' `jti` against replay, and detecting a rolled
    back policy or a cut audit log (security.md, known gaps);
  - `run`-style injection into files for the CI command (`ci inject`).

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
| Containers | LUKS2 image files with the OS's own filesystem inside (2026-09-29). Linux: dm-crypt through UDisks2, no root. Windows and macOS: decrypted in userspace, mount layer later. No hidden volumes (LUKS2 has none). Containers stay mounted when vaults lock, unless configured otherwise |
| Key types in the trust store | OpenPGP, S/MIME/X.509, SSH, secretvault identities |
| Verification levels | In person, organisation, public logs or WKD, trust on first use |
| Own private keys | In the vault by default; token split offered when a YubiKey is present |
| Tokens and 2FA | YubiKey unlock, keys on the token, built-in TOTP, phone approvals (later) |
| Sync | Own server (zero-knowledge), synced folder, or none. A hosted service possibly later |
| Unlock | Chosen at setup: OS login or a separate passphrase |
| Auto-lock | Configurable; defaults follow the unlock method |
| Prompting | Once per program, remembered, revocable |
| Program identity | Path plus publisher signature |
| Browser autofill | Behind KeePassXC's KeePassXC-Browser extension; no extension of our own |
| Vaults | Several, one default |
| CLI | Daemon only (M0's direct mode is transitional) |
| Platforms | Windows 10 22H2 and 11, macOS 14+, Linux from the last ~3 years; amd64 and arm64 |
| Distribution | Downloadable signed binaries with install scripts |
| Language | English only |
| Telemetry | None; no crash reports. An update check, if added, can be turned off |
