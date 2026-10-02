# secretvault

One secret store for Linux, Windows and macOS, written in Go.

- **Password keeper.** Your programs ask it for secrets and it asks you
  first. On Linux it is also the system keyring.
- **Encrypted containers.** Files you mount as disks.
- **Secret delivery.** Services, Kubernetes and CI pipelines get their
  secrets from it.
- **Trust store.** It holds the people whose keys you have verified, so your
  mail client can ask whether a signature is really theirs.

It never phones home. Sync goes through your own server, a folder you
already sync, or nothing.

> **Status: pre-release.** On Linux, the vault engine, the daemon with its
> consent prompts, the CLI, and the terminal and desktop managers work, and
> so do the desktop keyring (Secret Service), the SSH agent, gpg's agent,
> sync, emergency access, import, OpenPGP, age, browser autofill, the
> trust store, encrypted containers, and host mode for a server's systemd
> units; Windows and macOS builds compile but are not yet exercised.
> Unlocking with a FIDO2 security key works on Linux, tested against a
> software key but not yet against real ones. What remains is in
> [docs/roadmap.md](docs/roadmap.md). The format may still change, and
> nothing has been audited: do not keep anything here that exists nowhere
> else yet.

## How it fits together

One engine sits under many faces. A program asks through whichever face it
already speaks:

- the Secret Service on D-Bus;
- ssh-agent or gpg-agent;
- a git credential helper, or the browser's native messaging;
- the age plugin protocol;
- systemd's credential socket;
- secretvault's own API.

The daemon works out which program is asking and checks for a remembered
decision. If there is none, it asks you.

| Binary | What it does |
| --- | --- |
| **`secretvaultd`** | The daemon: holds the keys, opens the vaults, brokers every access, keeps the audit log. It links no UI code. With `--host`, the machine's system service that hands its services their secrets. |
| **`secretvault`** | The CLI, a client of the daemon (which it starts when needed). |
| **`secretvault-gui`** | The desktop manager, on [uitoolkit](https://github.com/codemodify/uitoolkit): vaults and their folders, instant search, items masked until revealed, one-time codes, files, history and conflicts, the generator, grants and the audit log, and a tray icon to search and lock everything. It asks for passphrases in a window of its own. |
| **`secretvault-tui`** | The terminal manager: vaults, items, one-time codes, the generator, history, grants and the audit log, full-screen. |
| **`secretvault-tui-prompt`** | Asks you on a terminal, over the pinentry protocol: a pinentry for gpg-agent, an askpass helper, and (`--agent`) the daemon's prompter where there is no desktop. |
| **`secretvault-gui-prompt`** | The same in a small window: the desktop prompt secretvaultd starts for each question, a pinentry for gpg-agent, and an askpass helper. The passphrase field holds bytes, never a string, and the keyboard is held while you type. |
| **`secretvault-server`** | The sync server: keeps vaults' files for their devices and relays changes, seeing only ciphertext. Devices sign every request with their own keys. With `-delivery-dir`, also the secret-delivery server for services and CI, sealed until operators unseal it. |
| **`secretvault-csi-provider`** | The Kubernetes Secrets Store CSI driver's provider: pods get files from the delivery server, as their own service account. |

| Package | Holds |
| --- | --- |
| [`svcrypto`](svcrypto) | Every cryptographic primitive, and nothing else |
| [`svformat`](svformat) | The v1 on-disk format ([spec](docs/format.md)) |
| [`svstore`](svstore) | Where vault files live |
| [`svcore`](svcore) | The vault engine: keyslots, items, revisions, conflicts |
| [`svserver`](svserver) | The sync server: stores and relays vaults' files, and sees only ciphertext; escrows emergency grants and keeps their waits |
| [`svsync`](svsync) | Syncing a vault folder with the server: device keys, enrolment, Sync, Pull, Clone, Watch, emergency grants |
| [`svseal`](svseal) | Sealing a key to the user by the OS (systemd-creds, DPAPI, the keychain), to open vaults at login |
| [`svdeliver`](svdeliver) | Secret delivery: the server's API, unseal shares, tokens, mTLS and OIDC, policies, the audit log |
| [`svcsi`](svcsi) | The Secrets Store CSI driver provider, with our own gRPC and protobuf |
| [`svrpc`](svrpc) | The daemon protocol (JSON-RPC over a local socket) |
| [`svd`](svd) | The daemon, as a library |
| [`svpeer`](svpeer) | Who is on the other end of a connection |
| [`svbroker`](svbroker) | Remembered decisions, and the audit log |
| [`svprompt`](svprompt), [`svterm`](svterm) | Asking people: the pinentry protocol, and terminals |
| [`svpgp`](svpgp) | OpenPGP, our own: keys, signatures, encryption (RFC 9580, reading RFC 4880) |
| [`svgpgagent`](svgpgagent) | GnuPG's agent protocol, for gpg: keygrips, S-expressions, and what gpg asks of its agent |
| [`svtrust`](svtrust) | The trust store: contacts, how their keys were verified, and verdicts on signers; WKD and keyserver lookups |
| [`svqr`](svqr) | QR codes, our own, drawn on a terminal |
| [`svldap`](svldap) | An LDAP client of our own, to ask an organisation's directory for people's keys |
| [`svfido`](svfido) | FIDO2 security keys, our own: CTAPHID, CTAP2 and its PIN protocols, for hmac-secret |
| [`svcms`](svcms) | CMS and S/MIME, our own: signed and enveloped data (RFC 5652, 8551), certificate checks, PKCS #12 |
| [`svmail`](svmail) | Whole mail messages: PGP/MIME, inline OpenPGP and S/MIME taken apart, verified, decrypted and reported; and built |
| [`svage`](svage) | age files and the age plugin protocol, both ends |
| [`svbrowser`](svbrowser) | The KeePassXC-Browser protocol, for filling logins in browsers |
| [`svimport`](svimport) | Import from other password managers, export to KeePass and CXF |
| [`svluks`](svluks) | LUKS2, our own: headers, keyslots, and the encrypted sectors in userspace |
| [`svcontainer`](svcontainer), [`svudisks`](svudisks) | Encrypted containers, and mounting them through UDisks2 on Linux |
| [`svops`](svops) | What the CLI and the managers do in their own process (files, keys made before they are stored, desktop setup planned and applied), shared so that they stay interchangeable |
| [`secretvault`](client.go) | The Go client library |

A vault is a folder of files that are only ever added, never rewritten, so
anything that copies files can sync it without two devices editing the same
file. Nothing about an item is readable in the folder, including its name.

- **Keyslots.** A vault opens with any of its keyslots: a passphrase, a
  printed recovery key, a keyfile, an identity (a device, a person, a
  server), a FIDO2 security key (its `hmac-secret`, with a touch and
  its PIN), or emergency access (a person's identity, once a waiting
  period you could have refused is over).
- **Recipient keyslots** use post-quantum hybrid encryption (ML-KEM-768 with
  X25519).

## Build and try

Go 1.26 or newer. No cgo. Build the binaries into one directory; the CLI
starts the daemon beside it when needed:

```bash
git clone https://github.com/codemodify/secretvault
cd secretvault
go build -o bin/ ./cmd/secretvault ./cmd/secretvaultd ./cmd/secretvault-tui ./cmd/secretvault-tui-prompt
bin/secretvaultd install        # optional: start at every login (systemd user unit)
```

The desktop programs (`secretvault-gui`, `secretvault-gui-prompt`) are a Go
module of their own, [`gui/`](gui), so nothing else needs cgo or uitoolkit.
They build with cgo against a release of
[uitoolkit](https://github.com/codemodify/uitoolkit), which Go fetches like
any other module:

```bash
(cd gui && CGO_ENABLED=1 go build -o ../bin/ ./cmd/...)
```

With `secretvault-gui-prompt` in `bin/` beside the daemon, secretvaultd asks
you in its window rather than the system's pinentry. To see it on its own,
speak the pinentry protocol to it (it opens a window; Escape cancels):

```bash
printf 'SETTITLE Test\nSETDESC Type anything.\nGETPIN\n' | bin/secretvault-gui-prompt
```

No build tags are needed: both use uitoolkit's default theme engine. With
no look chosen in uitoolkit's Settings, both follow the desktop's light or
dark mode. Keep it in the same directory as
`secretvaultd`: that is how the daemon knows it for one of secretvault's
own programs, which it asks for passphrases.

Or install it for your user, into `~/.local/bin` with the git, docker and
age helper links, and secretvaultd started at login (run it again to
update; `--uninstall` removes the programs, never your vaults):

```bash
scripts/install.sh              # [--prefix DIR] [--no-service] [--uninstall]
```

```console
$ bin/secretvault init --recovery            # asks for a new passphrase, prints a recovery key
$ bin/secretvault set web/github.com --kind login --field username=ada   # asks for the password
$ bin/secretvault get web/github.com         # first use in this terminal asks for the passphrase
hunter2
$ bin/secretvault set api/token --generate 32   # generate, store, and print a secret
$ bin/secretvault ls -l
$ bin/secretvault history web/github.com     # every revision, and which device signed it
$ bin/secretvault restore web/github.com 3f2a9c   # an earlier revision back; or a deleted item (ls --deleted)
$ bin/secretvault resolve web/github.com     # changed on two devices at once: see both, --keep one
$ bin/secretvault device ls                  # the devices that write to the vault, and their keys
$ bin/secretvault attach bank ~/scans/card.pdf   # files go into the vault too
$ bin/secretvault file get bank card.pdf -o -    # and come back out
$ bin/secretvault import auto ~/Downloads/passwords.kdbx --prefix imported/keepass   # or Bitwarden, 1Password, CSV...
$ bin/secretvault export kdbx backup.kdbx    # asks for the new file's passphrase
$ bin/secretvault grant list                 # what programs may do
$ bin/secretvault audit                      # who accessed what
$ bin/secretvault vault login on            # open it when you log in, like a login keyring
$ bin/secretvault lock --all
$ bin/secretvault status
$ bin/secretvault-tui                        # the same, full-screen: ? lists the keys
$ bin/secretvault-gui                        # and in a window, with a tray icon: F1 lists the keys

$ export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/secretvault/ssh-agent.sock
$ ssh-add ~/.ssh/id_ed25519                  # the key moves into the vault
$ bin/secretvault run --env-file app.env -- ./server   # API_KEY=sv://-/prod/api in app.env
$ bin/secretvault keyring takeover --dry-run # become the desktop's keyring (Linux)

$ bin/secretvault sync setup https://sync.example.com:8443 --fingerprint FP --admin-token-file token
$ bin/secretvault sync invite                # then, on the other device:
$ bin/secretvault sync join 'secretvault-sync:?...' --name personal
```

Emergency access, for a vault that syncs: a contact you trust can get into
it if you cannot, after a wait during which you are told, and can refuse.

```console
$ bin/secretvault emergency grant Alice --wait 7d    # prints an invite for Alice (it holds no secret)
    ... Alice: secretvault emergency accept 'secretvault-emergency:?...' --identity alice.id --as ada
    ... Alice, when she needs it: secretvault emergency request ada
$ bin/secretvault status                     # "Alice asked for emergency access to vault ..."
$ bin/secretvault emergency deny 3f2a        # or, if you do not, after 7 days:
    ... Alice: secretvault emergency open ada --identity alice.id   (read-only)
$ bin/secretvault emergency revoke 3f2a --rotate
```

Contacts, and your own OpenPGP key:

```console
$ bin/secretvault pgp new --name "Ada Lovelace" --email ada@example.org   # made in the daemon, kept in the vault
$ bin/secretvault contact qr                 # your key's fingerprint as a QR code, for someone to scan
$ bin/secretvault contact add alice.asc      # OpenPGP, an S/MIME certificate, SSH, or a secretvault recipient
$ bin/secretvault contact verify "Alice Example" --fingerprint "1A2B 3C4D ..." --in-person
$ bin/secretvault contact import 'openpgp4fpr:1A2B3C4D...'   # a QR code you scanned from their screen
$ bin/secretvault contact lookup bob@example.org --add       # WKD, then keys.openpgp.org
$ bin/secretvault trust check --fingerprint 1A2B3C4D... --from alice@example.org
verified
  Signed by Alice Example's key, which you verified in person on 2026-09-01.
$ bin/secretvault pgp sign --clear notes.txt  # the key signs inside the daemon
$ bin/secretvault mail inspect message.eml --decrypt   # who signed it, judged against your contacts; its text
$ bin/secretvault mail compose reply.eml --sign --encrypt -o out.eml   # your key signs; their keys encrypt
$ bin/secretvault smime import me.p12       # your S/MIME key, kept in the vault, used in the daemon
```

- **Verification levels**, strongest first: in person (fingerprint or QR
  code), an organisation (its CA or directory), a transparency log
  (reserved), published (WKD, or keys.openpgp.org's email check), and
  trust on first use.
- **Mail clients** tell secretvault the keys that come with messages
  (`trust.seen`), and ask about each signer (`trust.check`). A different
  key for an address that already has one is a warning, never a quiet
  replacement.
- **Who you know is private**: a program is asked about reading your
  contacts as it is about reading an item.

GnuPG's own gpg can use those keys too, with secretvaultd as its agent:

```console
$ bin/secretvault pgp new --name "Ada Lovelace" --email ada@example.org --v4   # GnuPG 2.4 reads version 4 keys
$ bin/secretvault pgp gpg-setup --dry-run    # what it would change
$ bin/secretvault pgp gpg-setup              # a GnuPG home of secretvault's own, pointed at the daemon
$ export GNUPGHOME=~/.local/share/secretvault/gnupg
$ gpg --clearsign notes.txt                  # asked about as any program is; the key stays in the daemon
$ gpg --decrypt message.asc
```

- **What it sets up.** The GnuPG home (or the one `--gnupghome` names:
  `~/.gnupg` only if you name it) gets the vault's public keys, trusted
  as your own, and gpg's agent socket there (`gpgconf --list-dirs
  agent-socket`) becomes a link to the daemon's, which the daemon makes
  again whenever it starts. gpg.conf names secretvault as the
  `agent-program`, so a gpg that finds no agent starts the daemon rather
  than GnuPG's own gpg-agent. `--remove` undoes it. For `~/.gnupg`, mask
  systemd's `gpg-agent*.socket` units first, as gpg-setup says.
- **Consent.** Each signature is asked about as signing with the key's
  item, and each decryption as decrypting, naming gpg; "always" covers
  everything that runs gpg. A key whose item says `confirm=always`
  (`secretvault set ITEM --attr confirm=always --no-secret`) is asked about
  every time.
- **Nothing secret goes through it.** gpg cannot export, import, make or
  delete secret keys this way (use `secretvault pgp`), and secretvault
  never asks you for a passphrase on gpg's behalf.
- Not on Windows yet, where gpg reaches its agent through a TCP socket
  emulation.

Encrypted containers are LUKS2 image files whose keys are vault items:

```console
$ bin/secretvault container create ~/work.img --size 2G --label Work   # prints the mount point
/run/media/ada/Work
$ bin/secretvault container close ~/work.img
$ bin/secretvault container open ~/work.img     # asked about as "mount", not as reading the key
$ bin/secretvault container ls
$ bin/secretvault container passwd ~/work.img   # a passphrase keyslot: cryptsetup opens it alone
$ bin/secretvault container header-backup ~/work.img ~/work.header
```

- **On Linux** UDisks2 attaches the image and the kernel's dm-crypt decrypts
  it, as the desktop mounts a USB drive: no root, from your desktop
  session. Inside is ext4, or `--fs exfat|vfat|btrfs`.
- **On Windows and macOS** the images are read and written in userspace;
  mounting them there comes later.

For services and CI, the server delivers secrets from vaults shared with
it ([docs/delivery.md](docs/delivery.md)). Pipelines log in with their own
ID token (GitHub Actions, GitLab CI, Kubernetes), so they store no secret:

```console
$ secretvault-server init --delivery-dir /var/lib/secretvault/deliver   # prints the unseal shares
$ secretvault-server -self-signed -delivery-dir /var/lib/secretvault/deliver
$ secretvault-server unseal                  # k operators, one share each
$ secretvault-server deliver add-vault prod --sync VAULT-ID   # prints the server's recipient
$ bin/secretvault share sv-recipient-1-modern-... --label delivery-server   # on your device
$ secretvault-server issuer set github --url https://token.actions.githubusercontent.com --audience https://secrets.example.com:8443
$ secretvault-server role set deploy --oidc github --claim repository=acme/app --claim ref=refs/heads/main --allow 'prod:app/*'

# in the workflow (permissions: id-token: write):
$ secretvault ci run --server https://secrets.example.com:8443 --role deploy --env DB_PASSWORD=sv://prod/app/db#password -- ./deploy.sh
$ curl -H "Authorization: Bearer $TOKEN" 'https://secrets.example.com:8443/v1/deliver/secret/prod/app/db?field=password&raw=true'
```

For git, docker and age, the CLI sets up their helpers: it links itself
beside itself as `git-credential-secretvault`,
`docker-credential-secretvault` and `age-plugin-secretvault`, adds
secretvault to git's `credential.helper`, and makes it docker's
`credsStore` (the managers do the same from Desktop › Program helpers):

```console
$ bin/secretvault helpers setup --dry-run   # what would change
$ bin/secretvault helpers setup
$ bin/secretvault helpers status            # the links, git's helpers, docker's credsStore
$ bin/secretvault helpers undo              # only what is secretvault's; docker's old store goes back
```

For browsers, secretvault stands in for KeePassXC behind KeePassXC's own
extension, [KeePassXC-Browser](https://github.com/keepassxreboot/keepassxc-browser)
(Firefox, Chrome, Chromium, Brave, Edge, Vivaldi):

```console
$ ln -s secretvault bin/secretvault-browser   # optional: the host's name in process lists
$ bin/secretvault browser install --dry-run   # what would change: KeePassXC's manifest is kept
$ bin/secretvault browser install             # then restart the browser, and press Connect in the extension
$ bin/secretvault browser status              # which host each browser starts
$ bin/secretvault browser ls                  # connected extensions; 'rm NAME' disconnects one
$ bin/secretvault browser uninstall           # put KeePassXC's manifest back, exactly
```

- **Connecting** asks you once. After that, each login the browser asks
  for is asked about like any program's request, naming the browser and
  the site; "always" stops the asking for that login.
- **Which logins.** Login items (`--kind login`) whose `url` field (or
  `url2`..., `website`) has the page's host, or a parent domain of it,
  with the same scheme: `--field url=https://github.com`.
- **Saving** a login from the browser puts it under `web/`, or in the
  folder you pick (the extension calls folders groups).
- **KeePassXC** writes its own manifest back each time it starts with
  browser integration on: turn that off in KeePassXC first.

For age and SOPS, its plugin must be on `PATH` (`helpers setup` links it
beside the CLI, as above):

```console
$ bin/secretvault helpers setup             # or: ln -s secretvault bin/age-plugin-secretvault
$ bin/secretvault age keygen --name age/sops >> ~/.config/sops/age/keys.txt
$ tail -2 ~/.config/sops/age/keys.txt
# recipient: age1...
AGE-PLUGIN-SECRETVAULT-1...
$ sops encrypt --age age1... secrets.yaml > secrets.enc.yaml   # or age: in .sops.yaml
$ sops decrypt secrets.enc.yaml    # the plugin asks secretvaultd for the key
$ age -d -i ~/.config/sops/age/keys.txt file.age               # age and rage alike
$ bin/secretvault age decrypt -i sv://-/age/sops file.age      # or no age at all
```

- **The recipient is a plain age key** (`age1...`, or `age1pq1...` with
  `--pq`): anyone can encrypt to it without secretvault.
- **The identity line names the item**, not the key. Decrypting runs
  `age-plugin-secretvault`, which asks the daemon for the item (the daemon
  asks you, as for any program), unwraps the file key, and exits.
- **SOPS** takes plugin identities from version 3.10, through
  `SOPS_AGE_KEY_FILE`, `SOPS_AGE_KEY` or its keys file. Encrypting to
  `age1pq1...` needs a SOPS built with age 1.3 or later; decrypting works
  with any, since the plugin unwraps post-quantum stanzas itself.

For a server's own services (Linux, systemd), `secretvaultd --host` runs
as a system service and hands each unit the credentials a policy lists
for it, with nobody to ask. As root:

```console
# secretvault host init --seal       # the host identity, sealed to the TPM2 (or host key) by systemd-creds
# secretvaultd install --host        # secretvaultd-host.service and .socket
    ... where the vault lives: secretvault --vault prod share sv-recipient-1-... --label web1
    ... and bring it here: copy it to /var/lib/secretvault/vaults/prod, or 'sync join'
# secretvault --host vault add prod /var/lib/secretvault/vaults/prod
# secretvault host allow postgresql.service db-password 'sv://prod/db/postgres#password'
# secretvault host status
```

and in the unit, `LoadCredential=db-password:/run/secretvault/credentials.sock`
puts the password in `$CREDENTIALS_DIRECTORY/db-password` when it starts.

- **Only what the policy lists is served.** A unit is named exactly or by
  a glob (`app@*.service`); anything else is refused, and `host audit`
  shows every delivery and refusal.
- **Services that are not units** (cron jobs, scripts) are allowed by
  user and program: `host allow --user backup --program
  /usr/local/bin/backup 'sv://prod/backup/*'`, then `secretvault --host
  read` or `run` as that user.
- **The host identity** reaches the daemon as a systemd credential, so a
  stolen disk alone opens nothing where there is a TPM2. Without
  systemd-creds, a root-only file does (`--plain-identity`).
  [docs/security.md](docs/security.md#the-host-daemon) says what each
  choice protects.

- **The daemon owns the vaults.** Vaults live under
  `~/.local/share/secretvault/vaults/` (macOS: `~/Library/Application
  Support/secretvault/…`; Windows: `%LOCALAPPDATA%\secretvault\…`), or
  anywhere with `init --path DIR`. `vault add NAME DIR` registers an
  existing one, and `--vault NAME` picks one.
- **Proving it is you.** The first command in a terminal asks for the vault's
  passphrase there (or its security key, if one is plugged in), which allows
  that terminal until the vault locks. Or pass `--passphrase-file`,
  `--keyfile`, `--identity`, `--recovery` or `--fido2`.
- **Other programs** asking for a secret get a desktop prompt
  (`secretvault-gui-prompt` when it is installed beside the daemon, else your
  system's pinentry): allow once, until locked, always, or deny.
  [docs/clients.md](docs/clients.md) is for their authors.

### A security key (Linux)

A FIDO2 key with `hmac-secret` (a YubiKey 5, a Solo, a Nitrokey 3, a Titan
and most others) can open a vault. Your user needs access to it first:
systemd 244 and later tag FIDO keys for the logged-in user
(`60-fido-id.rules`); elsewhere install your distribution's `libfido2` or
`u2f-udev` package, then plug the key in again.

```console
$ bin/secretvault fido2                  # the keys secretvaultd sees, and what each can do
$ bin/secretvault slot add fido2         # enrol it: its PIN if it has one, then two touches
$ bin/secretvault slot add fido2 --no-uv # or: a touch alone opens the vault
$ bin/secretvault lock
$ bin/secretvault unlock --fido2         # the PIN (if the slot needs it) and a touch
$ bin/secretvault get web/github.com     # with the key plugged in, it is asked for before the passphrase
```

- **The PIN** is asked for wherever a passphrase would be, saying how many
  tries the key has left; after three wrong ones the key wants to be
  plugged in again, and after eight it blocks.
- **Several keys** can each have a keyslot, and several can be plugged in:
  each is asked, without a touch, whether it holds one of the vault's, and
  only that one blinks.
- **Keep the passphrase or a recovery key**: a lost key is a lost way in.
  `vault rotate` does not carry keys over; it names them, to be added
  again.
- Windows and macOS say "not yet".

## Security: read this

[docs/security.md](docs/security.md) says what is protected, from whom, and
where it stops. In short:

- **Someone with a copy of your vault folder** sees how many items there are,
  when they changed, and roughly how big they are, and nothing else.
  - They cannot change anything without detection.
  - They *can* roll an item back to an older authentic version, which is not
    detected until signed checkpoints arrive (M6).
- **Everyone who can open a vault holds its key**, so each device signs what
  it writes with a key of its own, and `history` says which device signed
  what. A signature names a device key, not a person: anyone who can open
  the vault can register a device under any name, so compare key IDs
  (`device ls`) before vouching for one.
- **Removing a keyslot is not revocation**: cut someone off with `secretvault unshare`, which also rotates the vault key.
- **Keys in memory** are kept in locked, non-dumpable memory and wiped on
  lock. Go's runtime makes that best effort, not a guarantee.
- **A delivery server reads every vault shared with it**, by design. Its
  own keys and policy are sealed on disk until k operators unseal it, but
  an unsealed server's memory holds them all.
- **The wait of emergency access is your sync server's word.** The server
  holds nothing that opens the vault, but one that lies (about the time,
  or by releasing early) gives the trustee access early, and one that
  hides a request keeps you from refusing it.

## Documentation

| Document | What's in it |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | The design: processes, the consent broker, vaults, sync, every face |
| [docs/clients.md](docs/clients.md) | Using secretvault from a program: Go and the raw protocol |
| [docs/interfaces.md](docs/interfaces.md) | Every command, the operation behind it, and where it lives in the terminal and desktop managers |
| [docs/delivery.md](docs/delivery.md) | The secret-delivery server: setup, unsealing, the API, auth, policies; GitHub Actions, GitLab CI, Kubernetes and External Secrets Operator |
| [docs/format.md](docs/format.md) | The v1 vault format, byte by byte |
| [docs/security.md](docs/security.md) | The threat model and known gaps |
| [docs/roadmap.md](docs/roadmap.md) | Milestones M0–M10, and the decisions log |
| [docs/landscape.md](docs/landscape.md) | The tools secretvault replaces or meets, and what it takes from each |
| [uitoolkit-gaps.md](uitoolkit-gaps.md) | What the GUI toolkit provides for the prompt and manager, and what it still lacks |

## Built on

| Dependency | For | Licence |
| --- | --- | --- |
| Go standard library | nearly everything, including HPKE, ML-KEM, HKDF, PBKDF2, AES-GCM | BSD-3-Clause |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | Argon2id, BLAKE2b, XChaCha20-Poly1305, scrypt, SSH key formats, NaCl box (the KeePassXC-Browser protocol), cryptobyte (ASN.1 for CMS and PKCS #12); for reading other managers' files and old OpenPGP data, Salsa20, CAST5, Blowfish and Twofish | BSD-3-Clause |
| [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | locked memory, process hardening | BSD-3-Clause |
| [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) | passphrase entry without echo | BSD-3-Clause |
| [tview](https://github.com/rivo/tview), [tcell](https://github.com/gdamore/tcell) | `secretvault-tui` only | MIT, Apache-2.0 |
| [uitoolkit](https://github.com/codemodify/uitoolkit), [paintengine2d](https://github.com/codemodify/paintengine2d) | the desktop programs only, a module of their own ([`gui/`](gui)) | The Free License |

Everything else, including D-Bus, LUKS2, OpenPGP, CMS, MIME, CTAP2 and PC/SC, is
written here.
The policy is in [docs/architecture.md](docs/architecture.md#code-layout-and-dependencies).

## Testing

```bash
go vet ./... && go test -race ./...
```

The tests include:
- tampering with every byte of a revision;
- keyslots planted by someone with write access;
- two devices editing one item at once, and the merge that follows;
- a scan proving that no secret, name or attribute reaches the disk in the
  clear;
- golden revisions for each cipher suite;
- key derivation pinned against independent implementations (the reference
  Argon2 CLI and Python's hashlib);
- OpenPGP against the RFC 9580 test vectors and GnuPG 2.4, both ways, with
  every byte of signatures and ciphertexts tampered with, and fuzzing;
- gpg itself signing (detached, inline, cleartext) and decrypting with
  Ed25519/Curve25519, P-256, P-384, P-521 and RSA keys held in the vault,
  through the gpg-agent face, with consent allowed, denied, remembered and
  asked every time; keygrips against gpg's own for every kind of key it
  makes; and the protocol fed junk and fuzzed;
- CMS, S/MIME and PKCS #12 against OpenSSL 3, both ways: its signatures
  (detached, opaque, streamed, RSA-PSS, ECDSA, Ed25519), enveloped messages
  to RSA and EC keys, and PKCS #12 files (default, legacy, PBMAC1), and
  OpenSSL reading ours;
- whole messages against GnuPG and OpenSSL both ways, including nested,
  partly signed, and protected-header messages changed in transit.
- all 147 C2SP CCTV age test vectors, and files the reference age
  implementation wrote;
- KeePassXC-Browser's side of its protocol, played through the relay
  against the daemon: consent, saving, codes, locking, replays, bad
  nonces and bad frames; and browser installs in a home of the test's own;
- QR codes module for module against qrencode at every version and
  level, and read back by zbar;
- WKD hashes against GnuPG's own client, and lookups against a fake
  internet (httptest, with its own CA);
- FIDO2 against a software authenticator of our own (CTAP 2.0 and 2.1, PIN
  protocols 1 and 2, retries and blocking), its PIN protocols checked
  against Python's `cryptography`, and the CBOR and HID parsers fuzzed. No
  test opens a real device.
- LUKS2 against cryptsetup both ways (images each writes open in the
  other, with the same volume key), the encrypted sectors against Python's
  cryptography, hostile headers, and fuzzing; mounting against a pretend
  UDisks2 on a private bus, so no test ever mounts anything.
- the delivery server's ID token checks against a fake OIDC issuer on
  localhost, with RSA, EC and Ed25519 keys: algorithm confusion, `none`,
  forged, tampered, expired and wrong-audience tokens, unknown keys and
  claims that do not match; and the CSI provider's protobuf against
  protoc.
- emergency access between two daemons and a sync server with a clock of
  the test's own: a request denied, one released after the wait, grants
  revoked and carried over by rotations, and a server that lies about
  the time, which gives the trustee everything early.

## Licence

[The Free License](LICENSE).
