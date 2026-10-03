# The landscape secretvault enters

A study of the tools secretvault replaces or competes with, as of September
2026. For each: how it works, what secretvault takes from it, and where
secretvault deliberately differs. The decisions referred to are in
[roadmap.md](roadmap.md#decisions-log).

## At a glance

| Tool | What it is | Where secretvault meets it |
| --- | --- | --- |
| Secret Service (GNOME Keyring, ksecretd, oo7) | the Linux desktop keyring API | **replaced**: secretvaultd becomes the provider |
| macOS Keychain | the Apple system keyring | **bridged**: import and mirror; later an AutoFill extension |
| Windows Credential Manager | the Windows system keyring | **bridged**: import and mirror; later the passkey provider |
| KeePassXC | local password database | **competitor**: import and export KDBX |
| 1Password, Bitwarden, Proton Pass | cloud password managers | **competitors**: import from all three; own-server sync instead of their cloud |
| pass / gopass | GPG-encrypted files in git | **competitor**: import; our synced-folder mode is the same idea, encrypted better |
| systemd-creds | encrypted service credentials | **complemented**: we deliver credentials to units over systemd's socket interface |
| VeraCrypt | encrypted volumes | **competitor**: LUKS2 containers, mounted natively |
| HashiCorp Vault, OpenBao | infrastructure secrets servers | **competitors** for delivery; our own API, no compatibility layer |
| AWS, GCP, Azure secret managers | cloud-hosted secret stores | **competitors**; self-hosted instead |
| SOPS, age | encrypted files in repositories | **interoperate**: `age-plugin-secretvault` makes vault-held keys usable by both |

## OS keyrings

### Secret Service (Linux)

[Spec](https://specifications.freedesktop.org/secret-service/latest/): still
labelled "0.2 draft", yet the stable API every Linux desktop uses.

- **One provider per session.** A provider owns the bus name
  `org.freedesktop.secrets` and exposes `Service`, `Collection`, `Item`,
  `Session` and `Prompt` objects. Only one process can own the name, so
  providers compete for it (GNOME Keyring, KDE's ksecretd, KeePassXC, oo7).
- **Transfer.** Secrets cross the bus either in plain or encrypted with
  `dh-ietf1024-sha256-aes128-cbc-pkcs7`.
- **The portal.** Flatpak apps use the portal `org.freedesktop.portal.Secret`,
  whose backend (`org.freedesktop.impl.portal.Secret`) gives each app its own
  master secret through a file descriptor.
- **KDE.** KDE has moved onto Secret Service: kwalletd became ksecretd, and
  the old KWallet API is translated onto it. One Secret Service provider
  therefore serves GNOME and KDE applications alike.
- **oo7.** A Rust library, daemon, portal backend and PAM module. It is the
  closest existing "new keyring" project, and COSMIC's native provider.

**secretvault** implements the provider and the portal backend with its own
D-Bus code. On top of the spec it adds what no provider has today: a
per-program consent prompt and a remembered decision. Take-over from the
current provider, import of its items, and a clean restore are part of the
install.

### macOS Keychain

- **No replacement point.** The `SecItem*` calls go to securityd, which has
  no provider plug-in.
- **What an outsider can do:**
  - mirror items in and out, through `/usr/bin/security` or cgo;
  - ship an AutoFill credential-provider extension
    (`ASCredentialProviderViewController`) for passwords and passkeys;
  - use macOS 26 Credential Exchange to move data to and from Apple
    Passwords.
- **Signing is required.** The modern data-protection keychain and the
  AutoFill extension both need a signed app with entitlements.

**secretvault** bridges: it imports and mirrors, and ships the AutoFill
extension later. The extension needs a small Swift part outside pure Go.

### Windows Credential Manager

- **No replacement point.** `CredReadW` and `CredWriteW` store per-user
  blobs of up to 2,560 bytes under DPAPI, and cannot be taken over.
- **DPAPI.** `CryptProtectData` binds data to the user's logon. DPAPI-NG
  extends that to Active Directory principals.
- **Passkeys.** The one real plug-in point, since November 2025, is the
  Windows 11 passkey plug-in API. It needs an MSIX-packaged app;
  1Password and Bitwarden were the first to use it.

**secretvault** imports and mirrors, uses DPAPI for its "unlock with Windows
login" keyslot, and adopts the passkey plug-in later.

## Password managers

### KeePassXC

- **Format.** KDBX 4.x ([spec](https://keepass.info/help/kb/kdbx_4.1.html)):
  - an HMAC-authenticated outer header;
  - AES-256, ChaCha20 or Twofish;
  - Argon2d/id or AES-KDF;
  - an inner ChaCha20 stream protecting field values;
  - gzipped XML.

  The whole database is one file, re-encrypted on every save.
- **Beyond the file.** A Secret Service provider, an SSH agent, passkey
  storage, and a browser extension. The extension talks through
  `keepassxc-proxy` over native messaging, using NaCl `crypto_box`.

**secretvault** imports and exports KDBX 4. It has a browser extension of
its own ([browser.md](browser.md)).

Where we differ, deliberately:
- **Revisions, not one file.** A vault is many small immutable revisions, so
  two devices can edit through a synced folder without "conflicted copy"
  files.
- **Consent.** Every program's access goes through a prompt.

### 1Password

- **Key derivation.** Two secrets, the account password and a 128-bit
  Secret Key, are combined into the unlock key (PBKDF2 plus HKDF). Login uses
  SRP, and items are AES-256-GCM.
- **Developer tooling.** `op://vault/item/field` references with `op read`,
  `op run` and `op inject`, an SSH agent, Connect and service accounts.

**secretvault** takes `run`, `inject` and secret references
(`sv://vault/item/field`), and imports 1PUX. It does not copy the
account-plus-cloud model: sync goes through your own server or folder.

### Bitwarden and Vaultwarden

- **Crypto.** Client-side encryption: a master key from PBKDF2 (600,000
  iterations) or Argon2id, and items as AES-CBC plus HMAC strings.
  Organisations share keys with RSA-OAEP.
- **Self-hosting.** Vaultwarden reimplements the server, so its API is in
  effect the sync protocol.
- **Secrets Manager.** A separate product with the `bws` CLI and machine
  tokens.

**secretvault** imports Bitwarden JSON. Its own server plays Vaultwarden's
role, a server that never sees plaintext, for both people and machines.

### Proton Pass

- **Crypto and extras.** End-to-end encrypted with Proton's OpenPGP account
  keys, with email aliases.
- **CLI.** `pass-cli` offers `pass://` references, `run`, `inject`, an SSH
  agent, and tokens for scripts.

**secretvault** imports its export.

### pass and gopass

- **pass.** One GPG-encrypted file per entry, a `.gpg-id` recipient list per
  directory, and git for history and sync. passage is its age-based fork.
- **gopass.** Adds age, age plugins, an age agent, and an encrypted-filename
  store.

**secretvault** imports pass stores. Its synced-folder mode is the same idea:
one file per change, synced by any tool. It differs in two ways:
- **Names are encrypted.** pass leaks every entry name as a file name;
  secretvault encrypts names too.
- **Conflicts are handled.** They resolve deterministically, instead of
  surfacing as git merge conflicts in ciphertext.

### Moving between managers: FIDO CXF

The FIDO Alliance's Credential Exchange Format (CXF) became a v1.0 Proposed
Standard in August 2025. It is JSON covering passwords, passkeys, TOTP and
notes. The protocol for transferring it (CXP, HPKE-encrypted) is still a
draft. Apple, 1Password, Bitwarden and Dashlane already exchange data in CXF.

**secretvault** imports and exports CXF, and adopts CXP when it settles.

## Host credentials: systemd-creds

- **How credentials are sealed.** AES-256-GCM under a key from the TPM, the
  host key (`/var/lib/systemd/credential.secret`), or both. PCRs can
  optionally bind a credential to boot state.
- **How units get them.** `LoadCredentialEncrypted=` and related settings.
  Services read plaintext from `$CREDENTIALS_DIRECTORY`.
- **Integration points.** Unprivileged programs can use the
  `io.systemd.Credentials` Varlink API. `LoadCredential=` also accepts an
  AF_UNIX socket, which systemd connects to at unit start to read the
  credential.

**secretvault** complements rather than replaces it. Host mode serves
`LoadCredential=` over that socket, so a unit's secret comes from a vault,
with policy and audit, and never sits on disk.

## Encrypted volumes

### VeraCrypt

- **Format.** A 512-byte encrypted header, plus a backup copy, with no magic
  bytes. XTS mode with AES, Serpent, Twofish, Camellia or Kuznyechik, and
  cascades of them.
- **Hidden volumes** in the outer volume's free space. Version 1.26.29 (June
  2026) fixed a deniability flaw in hidden volumes inside file containers.
- **KDF.** Argon2id is now offered for non-system volumes.
- **Mounting.** A signed kernel driver on Windows, FUSE on Linux (or
  `cryptsetup --type tcrypt`), and macFUSE or FUSE-T on macOS.

### Cryptomator and gocryptfs

These encrypt each file and name separately (AES-GCM, and AES-SIV or EME for
names). That syncs well, but reveals file counts, sizes and the directory
shape.

**secretvault** follows your choice of VeraCrypt's shape:

- **One container file, mounted as a real disk** with the OS's own
  filesystem.
- **LUKS2, not a format of our own.** The image is what cryptsetup writes,
  so every LUKS2 tool opens it; our own code reads and writes it. Like
  VeraCrypt it is XTS, which garbles tampered sectors rather than detecting
  them.
- **No kernel driver of our own.** On Linux, UDisks2 and dm-crypt mount it,
  as they do USB drives, without root. Elsewhere we decrypt in userspace,
  and the OS will attach that with its own tools (VHD or iSCSI, `hdiutil`).
- **Keys in the vault, or not.** A container opens from a vault item, and
  still on its own with a passphrase keyslot.
- **No hidden volumes.** LUKS2 headers are in plain sight; this was
  accepted.

## Infrastructure secrets

### HashiCorp Vault and OpenBao

- **Licensing.** Vault 2.x is under the BSL, and HashiCorp is now part of
  IBM. OpenBao is the MPL-licensed Linux Foundation fork, wire-compatible,
  with namespaces and per-namespace sealing in the open-source edition.
- **Model.**
  - Secret engines: KV v2 with versions and check-and-set, transit
    (encryption as a service), PKI, SSH, and dynamic database and cloud
    credentials with leases.
  - Auth methods: token, AppRole, OIDC/JWT, Kubernetes, certificates, cloud
    IAM.
  - HCL path policies; audit devices that store HMACs of secrets.
  - Shamir unseal or KMS auto-unseal; Raft storage.

**secretvault** takes the model for its server mode:
- path policies;
- Shamir unseal;
- a hash-chained audit log that never contains secrets;
- OIDC for CI and Kubernetes, so no pipeline stores a secret.

It deliberately does **not** speak Vault's API (a decision). It has its own
API and its own integrations: an External Secrets Operator webhook provider,
a CSI driver provider, the age plugin, and a systemd socket. StrongDM-style
access proxying is out of scope; delivery only.

### AWS Secrets Manager, Google Secret Manager, Azure Key Vault

| Service | Model |
| --- | --- |
| AWS | versions with staging labels (`AWSCURRENT`, `AWSPENDING`, `AWSPREVIOUS`); four-step Lambda rotation; replication across regions |
| GCP | immutable numbered versions, addressed by number or alias; "rotation" is only a Pub/Sub reminder |
| Azure | GUID-versioned secrets with mandatory soft-delete; rotation built on Event Grid near-expiry events |

In Kubernetes, External Secrets Operator (v1.0, November 2025) and the
Secrets Store CSI driver are how clusters consume all three.

**secretvault** takes their version model: every write is a revision, and
labels such as "current" and "pending" can point at revisions for rotation.
It meets clusters through the same two integration points. It is
self-hosted, and it is not a compatibility endpoint for the clouds' APIs.

## Encrypted files: SOPS and age

- **age** ([spec](https://c2sp.org/age)):
  - **Header.** Recipient stanzas: X25519, scrypt, SSH keys, and since
    v1.3.0 (December 2025) the post-quantum hybrid `mlkem768x25519`.
  - **Payload.** STREAM-encrypted with ChaCha20-Poly1305 in 64 KiB chunks.
  - **Plugins** (`age-plugin-<name>`) speak a stanza protocol on stdin and
    stdout ([spec](https://c2sp.org/age-plugin)).
- **SOPS.**
  - **Per-value encryption.** Each value is encrypted separately
    (AES-256-GCM, with the key path as associated data), plus a MAC over all
    values.
  - **Data key.** Wrapped for age, PGP, cloud KMS or Vault transit, with key
    groups and Shamir thresholds.
  - **Status.** A CNCF sandbox project, currently under review because its
    MPL licence was never approved for the CNCF.

**secretvault** has its own format (a decision). Its stream construction is
age's STREAM, and its recipients are the same ML-KEM-768 + X25519 hybrid.
It meets both tools through `age-plugin-secretvault`: age, SOPS, gopass,
passage and chezmoi can then decrypt with keys kept in a vault, which leave
the daemon only for the plugin, and only after the person agrees. The age
format itself is implemented in our own code (`svage`), so `secretvault age`
encrypts and decrypts without age installed.

## Interfaces secretvault will speak

In roughly the order they arrive.

| Interface | Why | Milestone |
| --- | --- | --- |
| pinentry (Assuan) | our prompts double as pinentry and askpass | M1 |
| Secret Service D-Bus + portal backend | every Linux desktop app's keyring | M3 |
| Native messaging, with a protocol of our own | browser autofill with secretvault's own extension | M3 |
| KDBX 4, 1PUX, Bitwarden JSON, CSVs, Aegis, CXF | switching to us without loss | M2 |
| ssh-agent protocol | SSH, and git signing | M5 |
| gpg-agent protocol | gpg, pass, git, Thunderbird external GnuPG | M5 |
| PC/SC, CTAP2 | YubiKeys and FIDO2 keys | M4 |
| git and docker credential helpers | everyday developer credentials | M5 |
| age plugin protocol | age, SOPS, gopass, chezmoi | M8 |
| systemd `LoadCredential=` socket | service credentials on hosts | M8 |
| ESO webhook, CSI provider | Kubernetes | M8 |

## Sources

- [Secret Service API](https://specifications.freedesktop.org/secret-service/latest/),
  [Secret portal](https://flatpak.github.io/xdg-desktop-portal/docs/doc-org.freedesktop.impl.portal.Secret.html),
  [oo7](https://github.com/linux-credentials/oo7)
- [Windows 11 passkey manager support](https://techcommunity.microsoft.com/blog/windows-itpro-blog/windows-11-expands-passkey-manager-support/4467572)
- [KDBX 4.1](https://keepass.info/help/kb/kdbx_4.1.html),
  [1Password security design](https://agilebits.github.io/security-design/),
  [Proton pass-cli](https://protonpass.github.io/pass-cli/),
  [gopass releases](https://github.com/gopasspw/gopass/releases)
- [FIDO Credential Exchange specifications](https://fidoalliance.org/specifications-credential-exchange-specifications/)
- [systemd credentials](https://systemd.io/CREDENTIALS/)
- [VeraCrypt releases](https://github.com/veracrypt/VeraCrypt/releases)
- [Vault release notes](https://developer.hashicorp.com/vault/docs/updates/release-notes),
  [OpenBao release notes](https://openbao.org/community/release-notes/2-4-0/)
- [age spec](https://c2sp.org/age), [age plugin spec](https://c2sp.org/age-plugin),
  [age releases](https://github.com/FiloSottile/age/releases),
  [SOPS releases](https://github.com/getsops/sops/releases)
