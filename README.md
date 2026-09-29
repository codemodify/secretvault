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
> consent prompts, the CLI and the terminal manager work, and so do the
> desktop keyring (Secret Service), the SSH agent, sync, import, OpenPGP,
> age, browser autofill and the trust store; Windows and macOS builds
> compile but are not yet exercised. What remains is in
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
| **`secretvaultd`** | The daemon: holds the keys, opens the vaults, brokers every access, keeps the audit log. It links no UI code. |
| **`secretvault`** | The CLI, a client of the daemon (which it starts when needed). |
| **`secretvault-gui`** | The desktop manager, on [uitoolkit](https://github.com/codemodify/uitoolkit), with a tray icon. *(stub)* |
| **`secretvault-tui`** | The terminal manager: vaults, items, one-time codes, the generator, history, grants and the audit log, full-screen. |
| **`secretvault-tui-prompt`** | Asks you on a terminal, over the pinentry protocol: a pinentry for gpg-agent, an askpass helper, and (`--agent`) the daemon's prompter where there is no desktop. |
| **`secretvault-gui-prompt`** | The same as a window. *(stub; until then the desktop's own pinentry asks)* |
| **`secretvault-server`** | The sync server: keeps vaults' files for their devices and relays changes, seeing only ciphertext. Devices sign every request with their own keys. |

| Package | Holds |
| --- | --- |
| [`svcrypto`](svcrypto) | Every cryptographic primitive, and nothing else |
| [`svformat`](svformat) | The v1 on-disk format ([spec](docs/format.md)) |
| [`svstore`](svstore) | Where vault files live |
| [`svcore`](svcore) | The vault engine: keyslots, items, revisions, conflicts |
| [`svserver`](svserver) | The sync server: stores and relays vaults' files, and sees only ciphertext |
| [`svsync`](svsync) | Syncing a vault folder with the server: device keys, enrolment, Sync, Clone, Watch |
| [`svseal`](svseal) | Sealing a key to the user by the OS (systemd-creds, DPAPI, the keychain), to open vaults at login |
| [`svrpc`](svrpc) | The daemon protocol (JSON-RPC over a local socket) |
| [`svd`](svd) | The daemon, as a library |
| [`svpeer`](svpeer) | Who is on the other end of a connection |
| [`svbroker`](svbroker) | Remembered decisions, and the audit log |
| [`svprompt`](svprompt), [`svterm`](svterm) | Asking people: the pinentry protocol, and terminals |
| [`svpgp`](svpgp) | OpenPGP, our own: keys, signatures, encryption (RFC 9580, reading RFC 4880) |
| [`svtrust`](svtrust) | The trust store: contacts, how their keys were verified, and verdicts on signers; WKD and keyserver lookups |
| [`svqr`](svqr) | QR codes, our own, drawn on a terminal |
| [`svage`](svage) | age files and the age plugin protocol, both ends |
| [`svbrowser`](svbrowser) | The KeePassXC-Browser protocol, for filling logins in browsers |
| [`svimport`](svimport) | Import from other password managers, export to KeePass and CXF |
| [`secretvault`](client.go) | The Go client library |

A vault is a folder of files that are only ever added, never rewritten, so
anything that copies files can sync it without two devices editing the same
file. Nothing about an item is readable in the folder, including its name.

- **Keyslots.** A vault opens with any of its keyslots: a passphrase, a
  printed recovery key, a keyfile, or an identity (a device, a person, a
  server).
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
They build with cgo against [uitoolkit](https://github.com/codemodify/uitoolkit)
checked out beside this repository:

```bash
(cd gui && CGO_ENABLED=1 go build -o ../bin/ ./cmd/...)
```

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
$ bin/secretvault history web/github.com
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

$ export SSH_AUTH_SOCK=$XDG_RUNTIME_DIR/secretvault/ssh-agent.sock
$ ssh-add ~/.ssh/id_ed25519                  # the key moves into the vault
$ bin/secretvault run --env-file app.env -- ./server   # API_KEY=sv://-/prod/api in app.env
$ bin/secretvault keyring takeover --dry-run # become the desktop's keyring (Linux)

$ bin/secretvault sync setup https://sync.example.com:8443 --fingerprint FP --admin-token-file token
$ bin/secretvault sync invite                # then, on the other device:
$ bin/secretvault sync join 'secretvault-sync:?...' --name personal
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

For git and docker, link the CLI under their helper names:
`ln -s secretvault bin/git-credential-secretvault`, then
`git config --global credential.helper secretvault`; likewise
`docker-credential-secretvault` with `"credsStore": "secretvault"`.

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

For age and SOPS, link it as their plugin, somewhere on `PATH`:

```console
$ ln -s secretvault bin/age-plugin-secretvault
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

- **The daemon owns the vaults.** Vaults live under
  `~/.local/share/secretvault/vaults/` (macOS: `~/Library/Application
  Support/secretvault/…`; Windows: `%LOCALAPPDATA%\secretvault\…`), or
  anywhere with `init --path DIR`. `vault add NAME DIR` registers an
  existing one, and `--vault NAME` picks one.
- **Proving it is you.** The first command in a terminal asks for the vault's
  passphrase there, which allows that terminal until the vault locks. Or pass
  `--passphrase-file`, `--keyfile`, `--identity` or `--recovery`.
- **Other programs** asking for a secret get a desktop prompt (your system's
  pinentry, until secretvault's own window exists): allow once, until
  locked, always, or deny. [docs/clients.md](docs/clients.md) is for their
  authors.

## Security: read this

[docs/security.md](docs/security.md) says what is protected, from whom, and
where it stops. In short:

- **Someone with a copy of your vault folder** sees how many items there are,
  when they changed, and roughly how big they are, and nothing else.
  - They cannot change anything without detection.
  - They *can* roll an item back to an older authentic version, which is not
    detected until signed checkpoints arrive (M6).
- **Removing a keyslot is not revocation** until key rotation arrives (M6).
- **Keys in memory** are kept in locked, non-dumpable memory and wiped on
  lock. Go's runtime makes that best effort, not a guarantee.

## Documentation

| Document | What's in it |
| --- | --- |
| [docs/architecture.md](docs/architecture.md) | The design: processes, the consent broker, vaults, sync, every face |
| [docs/clients.md](docs/clients.md) | Using secretvault from a program: Go and the raw protocol |
| [docs/format.md](docs/format.md) | The v1 vault format, byte by byte |
| [docs/security.md](docs/security.md) | The threat model and known gaps |
| [docs/roadmap.md](docs/roadmap.md) | Milestones M0–M10, and the decisions log |
| [docs/landscape.md](docs/landscape.md) | The tools secretvault replaces or meets, and what it takes from each |
| [uitoolkit-gaps.md](uitoolkit-gaps.md) | What the GUI toolkit needs before the prompt and manager can be built |

## Built on

| Dependency | For | Licence |
| --- | --- | --- |
| Go standard library | nearly everything, including HPKE, ML-KEM, HKDF, PBKDF2, AES-GCM | BSD-3-Clause |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | Argon2id, BLAKE2b, XChaCha20-Poly1305, scrypt, SSH key formats, NaCl box (the KeePassXC-Browser protocol); for reading other managers' files and old OpenPGP data, Salsa20, CAST5, Blowfish and Twofish | BSD-3-Clause |
| [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | locked memory, process hardening | BSD-3-Clause |
| [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) | passphrase entry without echo | BSD-3-Clause |
| [tview](https://github.com/rivo/tview), [tcell](https://github.com/gdamore/tcell) | `secretvault-tui` only | MIT, Apache-2.0 |

Planned: [uitoolkit](https://github.com/codemodify/uitoolkit) in the GUI
binaries only.

Everything else, including D-Bus, OpenPGP, CTAP2 and PC/SC, is written here.
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
- all 147 C2SP CCTV age test vectors, and files the reference age
  implementation wrote;
- KeePassXC-Browser's side of its protocol, played through the relay
  against the daemon: consent, saving, codes, locking, replays, bad
  nonces and bad frames; and browser installs in a home of the test's own;
- QR codes module for module against qrencode at every version and
  level, and read back by zbar;
- WKD hashes against GnuPG's own client, and lookups against a fake
  internet (httptest, with its own CA).

## Licence

[The Free License](LICENSE).
