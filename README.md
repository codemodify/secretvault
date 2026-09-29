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

> **Status: pre-release (milestone 0).** The vault format and engine exist
> and are tested, and a CLI drives them. The daemon, the consent prompts,
> the desktop app and everything else are planned in
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
| **`secretvaultd`** | The daemon: holds the keys, opens the vaults, brokers every access. It links no UI code. *(stub)* |
| **`secretvault`** | The CLI. In M0 it opens vault folders directly; from M1 it is a client of the daemon. |
| **`secretvault-gui`** | The desktop manager, on [uitoolkit](https://github.com/codemodify/uitoolkit), with a tray icon. *(stub)* |
| **`secretvault-tui`** | The terminal manager. *(stub)* |
| **`secretvault-gui-prompt`**, **`secretvault-tui-prompt`** | The windows that ask you, over the pinentry protocol, so they double as pinentry and askpass. *(stubs)* |

| Package | Holds |
| --- | --- |
| [`svcrypto`](svcrypto) | Every cryptographic primitive, and nothing else |
| [`svformat`](svformat) | The v1 on-disk format ([spec](docs/format.md)) |
| [`svstore`](svstore) | Where vault files live |
| [`svcore`](svcore) | The vault engine: keyslots, items, revisions, conflicts |
| [`svprompt`](svprompt) | Asking people for secrets |

A vault is a folder of files that are only ever added, never rewritten, so
anything that copies files can sync it without two devices editing the same
file. Nothing about an item is readable in the folder, including its name.

- **Keyslots.** A vault opens with any of its keyslots: a passphrase, a
  printed recovery key, a keyfile, or an identity (a device, a person, a
  server).
- **Recipient keyslots** use post-quantum hybrid encryption (ML-KEM-768 with
  X25519).

## Build and try

Go 1.26 or newer. No cgo:

```bash
git clone https://github.com/codemodify/secretvault
cd secretvault
go build ./cmd/secretvault
```

```console
$ ./secretvault init --recovery            # asks for a new passphrase, prints a recovery key
$ ./secretvault set web/github.com --kind login --field username=ada   # asks for the password
$ ./secretvault get web/github.com
hunter2
$ ./secretvault set api/token --generate 32   # generate, store, and print a secret
$ ./secretvault ls -l
$ ./secretvault history web/github.com
$ ./secretvault slot add keyfile ~/usb/vault.key --create   # another way in
$ ./secretvault verify                       # re-authenticate every file
```

- **Default vault location:**
  - Linux: `~/.local/share/secretvault/vaults/default`;
  - macOS: `~/Library/Application Support/secretvault/…`;
  - Windows: `%LOCALAPPDATA%\secretvault\…`.
- **Overrides:** `--vault DIR` or `SECRETVAULT_VAULT`.
- **Unlocking:** every command asks for the passphrase on the terminal, or
  takes `--passphrase-file`, `--keyfile`, `--identity` or `--recovery`.

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
| [docs/format.md](docs/format.md) | The v1 vault format, byte by byte |
| [docs/security.md](docs/security.md) | The threat model and known gaps |
| [docs/roadmap.md](docs/roadmap.md) | Milestones M0–M10, and the decisions log |
| [docs/landscape.md](docs/landscape.md) | The tools secretvault replaces or meets, and what it takes from each |
| [uitoolkit-gaps.md](uitoolkit-gaps.md) | What the GUI toolkit needs before the prompt and manager can be built |

## Built on

| Dependency | For | Licence |
| --- | --- | --- |
| Go standard library | nearly everything, including HPKE, ML-KEM, HKDF, PBKDF2, AES-GCM | BSD-3-Clause |
| [golang.org/x/crypto](https://pkg.go.dev/golang.org/x/crypto) | Argon2id, XChaCha20-Poly1305 | BSD-3-Clause |
| [golang.org/x/sys](https://pkg.go.dev/golang.org/x/sys) | locked memory, process hardening | BSD-3-Clause |
| [golang.org/x/term](https://pkg.go.dev/golang.org/x/term) | passphrase entry without echo | BSD-3-Clause |

Planned:
- [uitoolkit](https://github.com/codemodify/uitoolkit) in the GUI binaries
  only;
- tview and tcell in the TUI only.

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
  Argon2 CLI and Python's hashlib).

## Licence

[The Free License](LICENSE).
