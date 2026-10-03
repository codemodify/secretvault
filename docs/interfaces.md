# The interfaces, and what each can do

secretvault has three interfaces for people:

- the command line, `secretvault` ([`cmd/secretvault`](../cmd/secretvault));
- the terminal manager, `secretvault-tui` ([`svtui`](../svtui));
- the desktop manager, `secretvault-gui` ([`gui/svmanager`](../gui/svmanager)).

They are only faces of the same functionality, and must be
interchangeable: whatever can be done from one can be done from the
others. This page maps every command of the CLI to the operation behind
it, and to its place in the two managers, with how far each has got.

## Where the work is done

Every operation is one of:

- **a daemon method**, when it touches vaults or the daemon's state. The
  interfaces reach it through the client library
  ([`secretvault.Client`](../client.go)); its wire name is in
  [`svrpc/methods.go`](../svrpc/methods.go) (`item.put`, `vault.rotate`).
- **a function of [`svops`](../svops)**, when it is local work every
  interface does in its own process: reading and writing files, making
  keys before they are stored, planning changes to the desktop and
  carrying them out. svops takes its inputs and returns results or a
  plan; it never asks, prints or confirms. Asking for passphrases,
  showing a plan and confirming it are each interface's own.
- **a library package** of the domain, when one already does it whole
  (`svcrypto.Password`, `svcontainer.BackupHeader`, `svqr`).

Nothing an interface does may live only in that interface: a CLI command
that does local work calls svops for it, and a manager that offers the
same calls the same function. The table's "Operation" column names it.

## Reading the table

- **CLI**: the command, its spellings, and its flags. `UNLOCK` stands for
  the flags that present a key up front: `--passphrase-file`, `--keyfile`,
  `--identity`, `--recovery`, `--shares`, `--fido2`. Every command also
  takes `--vault NAME` and `--host`.
- **GUI**: where it lives in the desktop manager. The window has a menu bar
  (File, Edit, Vault, Keys, Contacts, Tools, Desktop, Help), the vaults
  down the left, the items and the open item, and pages that take the
  items' place, each a row of tabs filled from the daemon as they are
  shown ([`tabbed.go`](../gui/svmanager/tabbed.go)): the vault's page
  (Keyslots, Devices, Sharing, Sync, Containers, Grants, Audit log,
  Settings; [`consent.go`](../gui/svmanager/consent.go)), the keys' page,
  the contacts' page and the desktop's page. Every tab is also reached
  from its menu. A change to the desktop is a plan shown first, and a
  secret shown once is drawn from its bytes and wiped with its dialog
  ([`kit.go`](../gui/svmanager/kit.go)).
- **TUI**: the key, panel or dialog in the terminal manager. Its keys are
  listed under `?` ([`svtui/help.go`](../svtui/help.go)). Its panels have
  capital letters (`V` the vaults, `N` a new vault, `K` keyslots, `D`
  devices, `S` sync, `E` sharing and emergency access, `C` contacts, `P`
  keys, `M` containers, `G` grants, `A` the audit log, `I` import, `X`
  export, `R` deleted items, `Y` the system keyring, `B` browsers, `H` the
  host daemon), `f` is the item's files and `y` copies an item's
  reference. A panel lists its own keys at its foot, and Enter on a row
  offers what can be done to it. `:` opens the action menu of every
  operation, grouped as the GUI's menus are (File, Edit, Vault, Keys,
  Contacts, Tools, Desktop, Help) and found by typing, so that nothing
  needs a key to be reachable ([`svtui/menu.go`](../svtui/menu.go)). A
  change to the desktop is a plan shown first, in the CLI's --dry-run
  words; a secret shown once is drawn from its bytes, waits its turn
  behind another, and is wiped when it closes
  ([`svtui/once.go`](../svtui/once.go)).
- **State**, for each manager: **done** (it does what the command does),
  **partial** (some of it: the cell says what is missing), or **missing**.

### For programs

Some commands exist for other programs, not people: `read`, `run`,
`inject`, `git-credential`, `docker-credential`, `age-plugin`,
`browser-host`, `__clip` and `ci` (and gpg starting the CLI as its
agent-program). A manager does not speak git's or a browser's protocol;
its equivalent is the side a person sees: setting the program up (the
helper's link, its configuration, the browser's manifest), and seeing
what a reference resolves to. Their rows are marked **for programs**, and
their GUI and TUI cells say what that side is; the state is that side's.

The parity test ([`cmd/secretvault/interfaces_test.go`](../cmd/secretvault/interfaces_test.go))
fails when a command or subcommand of the CLI has no row here, when a row
names one that does not exist, and when a row lacks a GUI place, a TUI
place, or a state.

## Vaults

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault init`, `secretvault vault create`, `secretvault vault init` --name --path --suite --recovery --passphrase-file | `vault.create` | File › New vault… (name, suite, passphrase, a folder of one's own or the data folder, the recovery key shown once) | done | `N`, `:` File › New vault…: name, a folder of one's own, suite, the passphrase twice, a recovery key (shown once, copyable) | done |
| `secretvault unlock [VAULT]` UNLOCK | `vault.unlock`; shares: `svops.ShareCollector`; key files: `svops.KeyFromFile` | Vault › Unlock (Ctrl+U), the locked vault's "Unlock…": the daemon asks for the passphrase or a security key's PIN, in a window of its own; Vault › Unlock with…: the recovery key, recovery shares typed one at a time (`svops.ShareCollector`), a keyfile, an identity file, the security key plugged in | done | `U` (the daemon asks for the passphrase); `V` panel `u`, `:` Vault › Unlock with…: a security key, a keyfile, an identity file, the recovery key, recovery shares (one at a time, `svops.ShareCollector`), a passphrase file (`svops.KeyFromFile`) | done |
| `secretvault lock [VAULT]` --all | `vault.lock` | Vault › Lock (Ctrl+L), Lock all vaults (Ctrl+Shift+L), the tray's Lock all vaults | done | `l`, `L` | done |
| `secretvault status` | `daemon.status` | Help › About secretvault: the daemon's version, process, data and socket, the prompter, the keyring, the SSH and gpg agents, emergency requests, and every vault with its state, when it locks and its folder; emergency requests also in the status bar (`emergency.changed`) | done | `?` help: the versions at its head, the daemon's status at its foot; `:` Help › About; emergency requests on the status line | done |
| `secretvault vault list`, `secretvault vault ls` | `vault.list` | The vaults list on the left (name, state, the default starred); the folder and when it locks on Vault page › Settings, and for every vault in Help › About secretvault | done | The vaults pane; `V` vaults panel: each vault's state, when it locks, and its path | done |
| `secretvault vault add NAME DIR` | `vault.add` | File › Add vault folder… (a folder chooser and a name) | done | `V` panel `a`, `:` File › Add a vault folder… | done |
| `secretvault vault forget NAME` | `vault.forget` | Vault page › Settings tab: Forget this vault… (the folder stays) | done | `V` panel `x`, `:` Vault › Forget this vault… (asks first; the folder stays) | done |
| `secretvault vault default NAME` | `vault.default` | Vault › Make default; Vault page › Settings tab: Make default | done | `V` panel `d`, `:` Vault › Make this vault the default | done |
| `secretvault vault rotate` --new-recovery --new-passphrase-file UNLOCK | `vault.rotate` | Vault page › Keyslots tab: Rotate the key… (proves itself first, as the CLI does; the passphrase, a new recovery key shown once, and a report of what opens it now) | done | `K` keyslots panel `r`, `:` Vault › Rotate the vault key…: the passphrase twice (it may be the same), a new recovery key (shown once); what opens it now, and what no longer does | done |
| `secretvault vault signatures [required\|optional]` UNLOCK | `vault.signatures` | Vault page › Devices tab: "Count only signed revisions" | done | `D` devices panel: the policy at its head, `s` changes it (asks first) | done |
| `secretvault vault login on\|off` UNLOCK | `vault.login` | Vault page › Settings tab: "Open when I log in" (asks first, as it adds a key that needs no passphrase) | done | `V` panel `o`, `:` Vault › Open this vault when I log in… (asks first) | done |
| `secretvault verify` UNLOCK | `vault.verify` | Vault page › Settings tab: Verify every file… (the report) | done | `V` panel `v`, `:` Vault › Verify every file of this vault: the report | done |
| `secretvault passwd` --new-passphrase-file UNLOCK | `vault.passwd` | Vault page › Keyslots tab: Change the passphrase… (proves itself first, then asks for the new one) | done | `K` keyslots panel `p`, `:` Vault › Change the passphrase… (the daemon asks for the current one first) | done |
| `secretvault version` | `secretvault.Version`; `daemon.status` for the daemon's | Help › About secretvault: this program's version and the daemon's | done | `?` help, at its head; `:` Help › About | done |

## Items

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault set NAME` --kind --label --attr --tag --field --secret-field --generate --no-secret --replace UNLOCK | `item.get`, `item.put`; `svops.SetField`, `svops.GeneratePassword` | File › New item (Ctrl+N), Edit › Edit item (Ctrl+E): the editor, with its generator | done | `n`, `e`: the editor (Ctrl+G generates) | done |
| `secretvault get NAME` --field --json --clip --clip-seconds UNLOCK | `item.get`; `svops.SecretField`, `svops.Field` | Open (Enter), Copy password (Ctrl+C), Copy username (Ctrl+B), each field's Copy | done | Enter, `c`, `u`, `c` on a field | done |
| `secretvault ls [PREFIX]` -l UNLOCK | `item.list` | The items list, the folders, the search (Ctrl+F) | done | The items pane, `/` filter | done |
| `secretvault ls --deleted` | `item.deleted` | Edit › Deleted items (each with Restore) | done | `R` deleted items panel, `:` Edit › Deleted items: Enter (or `r`) brings one back | done |
| `secretvault mv FROM TO` UNLOCK | `item.rename` | Edit › Rename… (F2) | done | `m` | done |
| `secretvault rm NAME` UNLOCK | `item.delete` | Edit › Delete… (Delete) | done | `d` | done |
| `secretvault history NAME` --show UNLOCK | `item.history`; `svops.Author` | Edit › History (Ctrl+H): every revision, viewable, with who signed each (`svops.Author`) and the revisions a vault that requires signatures ignores; the item page's foot says who signed it | done | `h`: every revision, who signed each (`svops.Author`), whether it was ignored; Enter views one (`r` reveals its secrets, `c` copies) | done |
| `secretvault restore NAME [REV]` UNLOCK | `item.restore` | History page: "Make this revision current…" under the revision shown; Edit › Deleted items: Restore | done | History panel: `R` makes a revision current (asks first); deleted items panel: Enter | done |
| `secretvault resolve NAME` --keep UNLOCK | `svops.Conflicts`, `item.restore` | History page: conflicting versions are marked (from the item's conflicts, as the CLI's history marks them) and viewable; "Keep this version on every device…" under each of them (`item.restore`) | done | `h` marks the conflicting versions, `k` keeps one on every device; `:` Edit › Resolve a conflict…: the versions (`svops.Conflicts`), each viewable, `k` keeps one | done |
| `secretvault attach ITEM FILE\|-` --name --type UNLOCK | `svops.ReadAttachment`, `file.attach` | Item page › Files: Add file… (read with `svops.ReadAttachment`: its own name, and its extension's media type) | done | `f` files panel: `a` (a file, its name and media type: `svops.ReadAttachment`); standard input is the CLI's | done |
| `secretvault file list ITEM`, `secretvault file ls ITEM` UNLOCK | `item.get` (the item's files) | Item page › Files | done | `f` files panel, `:` Edit › Files of the item | done |
| `secretvault file get ITEM NAME` -o --force UNLOCK | `file.get`; `svops.SaveFile` | Item page › Files: Save… (the file dialog asks before replacing a file; written with `svops.WriteReplacing`, mode 0600, as a replaced file must not stay as readable as it was) | done | `f` files panel: `s` saves it (`svops.SaveFile`; replacing a file only when ticked); standard output is the CLI's | done |
| `secretvault file rm ITEM NAME`, `secretvault file remove ITEM NAME` UNLOCK | `file.remove` | Item page › Files: Remove… | done | `f` files panel: `x` (asks first) | done |
| `secretvault gen` --length --no-symbols --clip | `svops.GeneratePassword` (`svcrypto.Password`) | File › Password generator… (Ctrl+G): characters or words | done | `g`, `:` Tools › Password generator (`svops.GeneratePassword`): its length and symbols; copied, or a new item made with it | done |

## Import and export

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault import SOURCE\|FORMAT FILE` --prefix --dry-run --overwrite --source-passphrase-file --source-keyfile UNLOCK | `svops.FindImportSource`, `svops.ReadImportFile`, `svops.ImportFormat` (a source's name for its format), `svimport.Import` (asking again while `svops.NeedsPassphrase`), `svops.StoreImport`; for an export that was not encrypted (`svimport.Result.Encrypted`), `svops.RemoveExport` | File › Import…, in steps: where the passwords are now (`svops.ImportSources`, Firefox first); that program's numbered steps, Choose the export file…, and only what its export needs (its password, a KeePass key file), with the folder and replacing what exists under More options, and Back to the list; then the names it would make and its warnings (the dry run), and only then the import, with the warnings in the GUI's words (`ImportOptions.Skipped`); then, for an export that was not encrypted, the offer to delete it (`svops.DeleteExportNote`, a plain delete) | done | `I`, `:` File › Import from a browser or another password manager…: the sources (`svops.ImportSources`); that program's steps, the file's path and only what its export needs, Back to the list; its passphrase asked again while it needs one; the names to import first (the dry run), then stored, with the warnings; then, for an export that was not encrypted, the offer to delete it | done |
| `secretvault import sources`, `secretvault import SOURCE` | `svops.ImportSources`, `svops.FindImportSource`, `ImportSource.NumberedSteps` | File › Import…: the list of sources, then the chosen one's numbered steps, in the same words | done | `I`: the list of sources, then the chosen one's numbered steps, in the same words | done |
| `secretvault export cxf\|kdbx FILE` --prefix --new-passphrase-file UNLOCK | `svops.CheckExport`, `svops.ReadForExport`, `svops.EncodeExport`, `svops.WriteNew` | File › Export…: the format, a new file, a folder of the items, the KeePass file's passphrase, the warning that CXF is not encrypted; and the items in conflict or badly signed | done | `X`, `:` File › Export…: format, a new file, a folder, the KDBX passphrase twice; CXF is confirmed as not encrypted | done |

## Keyslots and security keys

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault slot list`, `secretvault slot ls` | `slot.list` | Vault page › Keyslots tab | done | `K` keyslots panel, `:` Vault › Keyslots | done |
| `secretvault slot add passphrase\|recovery\|keyfile\|recipient\|fido2` --label --new-passphrase-file --create --split --threshold --uv --no-uv UNLOCK | `slot.add`; `svops.CreateKeyfile`, `svops.RecipientArg`, `svops.SplitThreshold`, `svops.SplitLabel`, `svops.SplitRecoveryKey` | Keyslots tab: Add…: the kind, and under it what that kind takes: a passphrase; a recovery key shown once, or split into shares shown once; a keyfile, made there or chosen; a recipient, its file or an identity file; the security key plugged in (its PIN with every touch, always, or a touch alone; the PIN asked in its own window, the touches in the status bar) | done | `K` panel `a`, `:` Vault › Add a keyslot…: a passphrase (twice), a recovery key (shown once, or split into shares with a threshold, each shown once), a keyfile (made here or chosen), a recipient or identity file, the security key plugged in (its PIN with every touch, always, or never) | done |
| `secretvault slot rm ID`, `secretvault slot remove ID` UNLOCK | `slot.remove` | Keyslots tab: Remove… (asks first, and says it is not revocation; an emergency access keyslot is sent to Sharing › Emergency access › Revoke…, as the daemon requires) | done | `K` panel `x` (asks first) | done |
| `secretvault fido2 list`, `secretvault fido2 ls` | `fido2.list` | Keys › Security keys: those plugged in, and what each can do (its PIN and the tries left, hmac-secret, a problem); Refresh | done | `K` keyslots panel: the security keys plugged in; `i` says what one can do | done |

## Sharing and emergency access

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault share RECIPIENT\|FILE` --label UNLOCK | `svops.RecipientArg`, `slot.add` (a recipient keyslot) | Vault page › Sharing tab: Share with…: a contact's secretvault key, or a recipient, a file holding one, or an identity file (all through `svops.RecipientArg`); never both | done | `E` sharing panel `s`, `:` Vault › Share this vault…: a recipient, a file holding one, or an identity file (`svops.RecipientArg`), and a label | done |
| `secretvault unshare SLOT-ID...` --new-recovery --new-passphrase-file UNLOCK | `vault.rotate` (dropping the slots) | Sharing tab: Cut off… (the keyslot chosen; the key rotated without it, a new recovery key if asked, and what opens it now) | done | `E` panel `c` on a person: Cut off… (the key is rotated without their keyslot: the passphrase twice, a new recovery key if asked; what opens it now). One person per rotation: cutting off several rotates once each | done |
| `secretvault emergency grant CONTACT\|RECIPIENT` --wait --fingerprint --name UNLOCK | `svops.ParseWait`, `emergency.grant` | Sharing tab › Emergency access: Grant… (a contact, or a recipient, never both; the wait read by `svops.ParseWait`), then the invite to send, to copy or as a QR code | done | `E` panel `g`, `:` Vault › Grant emergency access…: who, the wait (`svops.ParseWait`), the key's fingerprint, the invite's name; the invite shown once, copyable, with its QR code | done |
| `secretvault emergency list`, `secretvault emergency ls` UNLOCK | `emergency.list`; `svops.WaitText`, `svops.GrantState` | Sharing tab › Emergency access: the grants given and the access held here; requests also in the status bar, in the GUI's own words | done | `E` panel: the grants given (`svops.GrantState`, `svops.WaitText`) and the access held; requests also on the status line | done |
| `secretvault emergency deny GRANT` UNLOCK | `emergency.deny` | Emergency access: Deny… | done | `E` panel `d` on a requested grant (asks first) | done |
| `secretvault emergency revoke GRANT` --rotate --new-recovery --new-passphrase-file UNLOCK | `emergency.revoke`, then `vault.rotate` | Emergency access: Revoke… (with "rotate the key too", ticked when they were given it) | done | `E` panel `v`: Revoke…, with "rotate the vault key too" (then the rotation's form) | done |
| `secretvault emergency accept INVITE\|-` --identity --as --label | `emergency.accept` | File › Emergency access › Accept an invite… (the invite pasted, the identity file chosen, its name here, this device's label) | done | `E` panel `a`, `:` File › Emergency access: accept an invite… (the invite pasted, the identity file, its name here, this device's name) | done |
| `secretvault emergency request NAME` | `emergency.request` | File › Emergency access › Ask for access… (the access held chosen, or its name typed when it cannot be listed) | done | `E` panel `r` on access held, `:` File › Emergency access: ask for a vault… (asks first) | done |
| `secretvault emergency open NAME` --identity --path | `emergency.open` | File › Emergency access › Open the vault… (after the wait; the identity file, and a folder of one's own if wanted) | done | `E` panel `o` on access held, `:` File › Emergency access: open a vault after the wait… (the identity file, a folder of one's own) | done |

## Sync

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault sync setup URL` --fingerprint --admin-token-file --label UNLOCK | `sync.setup` | Vault page › Sync tab: Set up… (the server, its fingerprint, the admin token, this device's label) | done | `S` sync panel `u`, `:` Vault › Sync this vault with a server…: the server, its fingerprint, an admin token file, this device's name | done |
| `secretvault sync join INVITE\|-` --name --path --label | `sync.join` | File › Join a synced vault… (the invite pasted into a secret field, the name here, a folder of one's own, this device's label) | done | `S` panel `j`, `:` File › Join a synced vault… (the invite pasted, its name here, a folder, this device's name) | done |
| `secretvault sync invite` --qr --light UNLOCK | `sync.invite`; `svqr` | Sync tab: Invite a device… (the invite shown once, to copy, and its QR code under it; both wiped when the dialog closes) | done | `S` panel `i`, `:` Vault › Invite a device…: the invite shown once, copyable, with its QR code | done |
| `secretvault sync status`, `secretvault sync st` | `sync.status` | Vault page › Sync tab, and the status bar, for the vault shown | done | `S` sync panel: every synced vault, its server, last sync, what was sent and fetched, its state | done |
| `secretvault sync now` UNLOCK | `sync.now` | Sync tab: Sync now | done | `S` panel `n` | done |
| `secretvault sync devices` UNLOCK | `sync.devices` | Sync tab: the devices that sync (once the vault is unlocked) | done | `S` panel: the shown vault's devices, with when each was last seen | done |
| `secretvault sync rm-device KEY` UNLOCK | `sync.remove` | Sync tab: Remove a device… | done | `S` panel `x` on a device (asks first) | done |
| `secretvault sync off` UNLOCK | `sync.off` | Sync tab: Stop syncing… | done | `S` panel `o` (asks first) | done |

## Devices

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault device list`, `secretvault device ls` UNLOCK | `device.list`; `svops.DeviceStanding` | Vault page › Devices tab: each device, its key ID, its label, when it registered, its standing (`svops.DeviceStanding`) | done | `D` devices panel, `:` Vault › Devices: each device, its key ID, its standing (`svops.DeviceStanding`) | done |
| `secretvault device label [DEVICE] NAME` UNLOCK | `device.label` | Devices tab: Rename… | done | `D` panel `l` on a device (this one, or another) | done |
| `secretvault device rm DEVICE`, `secretvault device remove DEVICE` UNLOCK | `device.remove` | Devices tab: Remove… (says it does not cut the device off) | done | `D` panel `x` (asks first) | done |
| `secretvault device vouch DEVICE` --withdraw UNLOCK | `device.vouch` | Devices tab: Vouch for it (asks first, showing the key to compare) / Withdraw | done | `D` panel `v`: vouch for it, or withdraw (asks first) | done |

## Grants and the audit log

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault grant list`, `secretvault grant ls` UNLOCK | `grant.list` | Vault › Grants and audit log (Ctrl+Shift+G) › Grants tab | done | `G` | done |
| `secretvault grant allow PROGRAM`, `secretvault grant deny PROGRAM` --item --contacts --ops --until-lock UNLOCK | `grant.add` | Grants tab: Allow a program… / Deny a program… (the program chosen or typed as flatpak:APP or snap:NAME; the whole vault, an item or the contacts; the operations; allow until the vault locks) | done | `G` panel `a` and `n`, `:` Vault › Allow / Deny a program ahead of time…: the program, an item or the contacts, the operations, until the vault locks | done |
| `secretvault grant revoke ID`, `secretvault grant rm ID` UNLOCK | `grant.revoke` | Grants tab: Revoke… (Delete) | done | `G` panel: `x` or Delete (asks first) | done |
| `secretvault audit` --limit UNLOCK | `audit.list` | Vault page › Audit log tab (the newest 500) | done | `A` | done |

## Keys and identities

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault identity new` --out --suite | `svops.NewIdentity`, `svops.WriteNew` | Keys › Identity files: New… (the cipher suite, a new file only its owner reads; its recipient shown) | done | `P` keys panel `f`, `:` Keys › New identity file…: a new file (mode 0600), the suite; its recipient shown, copyable | done |
| `secretvault identity pub FILE` | `svops.IdentityRecipient` | Keys › Identity files: Show the recipient of a file… | done | `P` panel `p`, `:` Keys › The recipient of an identity file… | done |
| `secretvault pgp list`, `secretvault pgp ls` UNLOCK | `item.list`; `svops.PGPKeyEntries` | Keys › OpenPGP keys (`svops.PGPKeyEntries`): item, fingerprint, user ID | done | `P` keys panel › OpenPGP keys, `:` Keys › Keys | done |
| `secretvault pgp new` --name --email --v4 --item --expires UNLOCK | `pgp.generate` | OpenPGP keys: New… (name, addresses, item, expiry, version 4 or 6) | done | `P` panel `n`, `:` Keys › New OpenPGP key…: name, addresses, version 6 or 4, item, days to expiry | done |
| `secretvault pgp import FILE\|-` --item --key-passphrase-file UNLOCK | `svops.PGPImportItem`, `svops.StorePGPKey` | OpenPGP keys: Import… (a key file; its passphrase asked for in a dialog when `svops.PGPImportItem` finds it protected; a name taken said in the GUI's words, `svops.ErrKeyExists`) | done | `P` panel `i`, `:` Keys › Import an OpenPGP key… (its passphrase asked for, masked, when it has one); standard input is the CLI's | done |
| `secretvault pgp export [KEY]` --secret --unprotected --new-passphrase-file -o UNLOCK | `pgp.public`; with --secret `item.get`, `svops.ProtectPGPKey`; `svops.CreateAtomic` | OpenPGP keys: Export… (the public key, the secret key under a new passphrase asked for when `svops.ProtectPGPKey` needs it, or the secret key as kept), to a file that appears whole, mode 0600 | done | `P` panel `e` on a key: the public key, or the secret key under a new passphrase (typed twice) or unprotected, to a file (written whole, replacing one only when ticked) | done |
| `secretvault pgp pub [KEY]` -o UNLOCK | `pgp.public` | OpenPGP keys: Copy the public key | done | `P` panel `c` copies the public key; `e` writes it to a file | done |
| `secretvault pgp sign [IN]` --key --inline --clear -a --text -o UNLOCK | `pgp.sign` | Tools › Sign a file… (the key, detached, inline or cleartext, armored, a text signature, where it goes) | done | `:` Tools › Sign a file…: the key, detached, inline or cleartext, armored, a text signature, where to write it | done |
| `secretvault pgp decrypt [IN]` --key --verify --from -o UNLOCK | `pgp.decrypt`; `svops.SignatureLines` | Tools › Decrypt a file (OpenPGP)… (the key, or the one it is for; its signatures checked if asked, with From), into a file only yours to read; one there is replaced only when you say so | done | `:` Tools › Decrypt a file (OpenPGP)…: the key, checking the signatures inside and the From address, where to write it (mode 0600); the signatures' verdicts (`svops.SignatureLines`) | done |
| `secretvault pgp verify [IN]` --signature --from -o UNLOCK | `pgp.verify`; `svops.SignatureLines` | Tools › Check a signature… (a detached signature or a signed message, From, its text written if asked): the verdict against the contacts | done | `:` Tools › Check a signature…: a signed message, or a file and its detached signature, the From address; the verdict (`svops.SignatureLines`); the message's text written if asked | done |
| `secretvault smime import FILE.p12` --password-file --item UNLOCK | `smime.import` | Keys › S/MIME keys: Import… (the .p12 file, its password, the item) | done | `P` panel `m`, `:` Keys › Import an S/MIME key…: the file, its password (masked), the item | done |
| `secretvault smime list`, `secretvault smime ls` UNLOCK | `smime.list` | Keys › S/MIME keys: item, addresses, certificate, expiry | done | `P` keys panel › S/MIME keys | done |
| `secretvault age keygen` --name --pq -o UNLOCK | `svops.GenerateAgeIdentity`, `svops.StoreAgeIdentity` (both: `svops.AgeKeygen`) | Keys › age identities: New… (the item, post-quantum or not, and a file for the identity line if wanted); its recipient and identity line shown | done | `P` panel `k`, `:` Keys › New age identity…: the item, post-quantum, a file for the identity line; the recipient and the identity line shown, copyable | done |
| `secretvault age recipient ITEM` UNLOCK | `svops.AgeItemRecipient` | age identities (`svops.AgeKeyEntries`): Copy the recipient | done | `P` panel `r` on an age identity copies its recipient | done |
| `secretvault age identity ITEM` UNLOCK | `svops.VaultName`, `svops.AgePluginIdentity` | age identities: Copy the identity line (for age and SOPS) | done | `P` panel `l` on an age identity copies its identity line | done |
| `secretvault age encrypt [IN]` -r -R -p -a -o --allow-mixed-pq UNLOCK | `svops.AgeRecipient`, `svops.EachKeyLine`, `svops.AgeEncrypt`, `svops.CreateAtomic` | Tools › Encrypt a file (age)… (recipients typed, or added from the vault's identities and the contacts' SSH keys, a recipients file; or a passphrase asked for twice; armor, mixed post-quantum); another plugin talks to the person in dialogs | done | `:` Tools › Encrypt a file (age)…: recipients (one per line, `sv://` ones too), a recipients file, or a passphrase (typed twice), armored, mixing post-quantum; other plugins talk to the person in dialogs | done |
| `secretvault age decrypt [IN]` -i -o UNLOCK | `svops.AgeIdentities`, `svops.VaultIdentity`, `svops.PassphraseIdentity`, `svops.AgeDecrypt` | Tools › Decrypt a file (age)… (any of the vault's identities, any identity files or SSH keys, whose passphrases are asked for; with none, the file's passphrase), into a new file only yours to read | done | `:` Tools › Decrypt a file (age)…: identities (`sv://` ones, files of identities, SSH keys, their passphrases asked for), or the passphrase asked for when the file needs it | done |

## Contacts and trust

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault contact list [QUERY]`, `secretvault contact ls [QUERY]` UNLOCK | `contact.list` | Contacts › Contacts (Ctrl+Shift+K), its page: the list (name, addresses, keys, how well verified), with a search | done | `C` contacts panel, `:` Contacts › Contacts; `/` finds by name or address, `*` lists all | done |
| `secretvault contact show NAME` --json UNLOCK | `contact.get`; `svops.GroupFingerprint`, `svops.LevelText` | Contacts page: the contact chosen, below the list: its keys and fingerprints, how each was verified, where each was seen, its warnings | done | `C` panel: Enter: the contact (its addresses, notes, origin, warnings) and its keys; Enter on a key: its verifications and sightings. The JSON is the CLI's | done |
| `secretvault contact add FILE...` --name --email --notes --org UNLOCK | `contact.add` | Contacts › Add… (key files chosen, name, addresses, notes, organisation) | done | `C` panel `a`, `:` Contacts › Add a contact…: key files (one per line), name, addresses, notes, organisation | done |
| `secretvault contact import FILE\|URI` --to --name --fetch --keyserver UNLOCK | `svops.IsContactURI`, `contact.import` | Contacts › Import… (a file of keys, or the text of a scanned QR code, which verifies its keys; into a contact, a name, fetching from a keyserver) | done | `C` panel `m`, `:` Contacts › Import…: a file, or a scanned code's text (`svops.IsContactURI`); into a contact, new contacts' name, fetching from a keyserver | done |
| `secretvault contact rm NAME`, `secretvault contact remove NAME` --fingerprint UNLOCK | `contact.remove` | Contacts page: Remove… (the contact, or one of its keys) | done | `C` panel `x` (the contact), its keys' panel `x` (one key); both ask first | done |
| `secretvault contact verify [NAME]` --fingerprint --in-person --qr --org --tofu --email --note UNLOCK | `contact.verify` | Contacts page: Verify… (the key; its fingerprint typed as it was compared, and checked against the key's; in person, their QR code, an organisation, or accepted as it is; addresses; a note) | done | The contact's keys' panel: `v` on a key (its fingerprint filled in), `V` by a fingerprint typed: how (in person, a QR code, an organisation, as it is), for which addresses, a note | done |
| `secretvault contact lookup ADDRESS\|FPR` --wkd --keyserver --directory --add --name UNLOCK | `contact.lookup` | Contacts › Look up… (everywhere, WKD only, a keyserver, or one directory; keep what is found) | done | `C` panel `l`, `:` Contacts › Look up keys…: everywhere, or WKD, a keyserver or a directory only; keeping what is found | done |
| `secretvault contact qr` --key --recipient --name --email --uri --light UNLOCK | `svops.OwnCard`, `svtrust.Card.URI`, `svqr` | Contacts › Show my QR code… (the key items chosen, OpenPGP or SSH, else every OpenPGP key; a recipient or identity file; the name and addresses): the code under its text, in one dialog | done | `C` panel `c`, `:` Contacts › Show my QR code…: key items, recipients, name, addresses; the code drawn in blocks, its URI copyable | done |
| `secretvault contact vault [VAULT\|-]` | `contact.vault` | Contacts › Keep contacts in… (says where they are now; a vault chosen, or the default) | done | `C` panel `v`, `:` Contacts › Keep contacts in… (a vault, or the default); the panel's title says where they are | done |
| `secretvault contact directory add NAME URL` --base --bind-dn --password --ca | `directory.add` | Contacts › Directories: Add… (name, address, where people are, bind DN, its password as an sv:// reference, a CA file) | done | `C` panel `d`, `:` Contacts › Directories: `a` (name, URL, base, bind DN, the password's `sv://` reference, a CA file) | done |
| `secretvault contact directory list`, `secretvault contact directory ls` | `directory.list` | Contacts › Directories | done | `C` panel `d`, `:` Contacts › Directories | done |
| `secretvault contact directory rm NAME`, `secretvault contact directory remove NAME` | `directory.remove` | Contacts › Directories: Remove… | done | Directories panel `x` (asks first) | done |
| `secretvault trust check` --fingerprint --key --cert --from --min-level --json UNLOCK | `trust.check` | Contacts › Check a signer… (a fingerprint or a key file, the From address, the weakest verification that counts): the verdict and its reasons | done | `C` panel `t`, `:` Contacts › Check a signer…: a fingerprint or a key file, the From address, the weakest verification that counts; the verdict and its reasons. The JSON and the exit code are the CLI's | done |
| `secretvault trust seen` --key --from --at --source --name UNLOCK | `trust.seen` | Contacts › Record a key seen in mail… (the key, the address, when, what it was, a name) | done | `C` panel `s`, `:` Contacts › Record a key seen in mail…: the key file, the address, when, what it was, the sender's name | done |

## Mail

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault mail inspect FILE\|-` --decrypt --json --min-level --contacts UNLOCK | `svops.ReadMessage`, `mail.inspect`, `svops.MailText` | Tools › Inspect a message… (decrypted if asked, the weakest verification that counts, the contacts vault): its headers, layers, signers judged against the contacts, warnings, and its text parts, each masked until shown, as are the header fields an encryption protects | done | `:` Tools › Inspect a message…: decrypting, the weakest verification that counts, the contacts vault; the report (`svops.MailText`). The JSON and standard input are the CLI's | done |
| `secretvault mail compose FILE\|-` --sign --encrypt --format --key -o UNLOCK | `svops.ReadMessage`, `mail.compose`, `svops.WriteMessage` | Tools › Sign and encrypt a message… (sign, encrypt, OpenPGP or S/MIME, your key, where it goes) | done | `:` Tools › Sign and encrypt a message…: signing, encrypting, the format, the key, where to write it (`svops.WriteMessage`) | done |

## Encrypted containers

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault container create FILE` --size --fs --label --item --passphrase --new-passphrase-file --sector-size --mount-options UNLOCK | `svops.MountsHere`, `svops.ParseSize`, `svops.ContainerItemName`, `container.create` | Vault page › Containers tab: New container… (the image, its size read by `svops.ParseSize`, the filesystem, its label, the key item, the sector size, mount options, and a passphrase of its own if wanted) | done | `M` containers panel `n`, `:` Vault › New encrypted container…: the file, its size (`svops.ParseSize`), filesystem, label, item (`svops.ContainerItemName`), its own passphrase (typed twice), sector size, mount options | done |
| `secretvault container open FILE` --item --mount-options UNLOCK | `svops.ExistingImage`, `container.open` | Containers tab: Open (the one chosen), Open another file… (any image, with the item and mount options); Copy the folder's path | done | `M` panel `o` on a closed one, `O` any image (`svops.ExistingImage`), `:` Vault › Open an encrypted container…: the item, mount options | done |
| `secretvault container close FILE\|MOUNTPOINT` | `container.close` | Containers tab: Close… (the one chosen, or any image or folder named) | done | `M` panel `c` on an open one; `C`, `:` Vault › Close an encrypted container…: by its file or mount point | done |
| `secretvault container list`, `secretvault container ls` UNLOCK | `container.list` | Vault page › Containers tab | done | `M` containers panel: each one's item, file and state, where it is mounted | done |
| `secretvault container header-backup FILE OUT` | `svcontainer.BackupHeader` | Containers tab: Back up the header… (the one chosen, or any image named, to a new file; no vault needed) | done | `M` panel `b`: to a new file (`svcontainer.BackupHeader`) | done |
| `secretvault container passwd FILE` --item --remove --new-passphrase-file UNLOCK | `svops.ExistingImage`, `container.passwd` | Containers tab: Passphrase… (the one chosen, or any image and item named: set, change or remove its own passphrase) | done | `M` panel `p`: set or change its own passphrase (typed twice), or remove it | done |

## The desktop

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault keyring status` | `svops.KeyringHolderNow`, `daemon.status`, `svops.LoadTakeover` | Desktop › System keyring: who holds it (or that there is no session bus), whether secretvault serves it, and the takeover's record | done | `Y` keyring panel, `:` Desktop › System keyring: who holds it, whether secretvault serves it, when it was taken over | done |
| `secretvault keyring import` --prefix --dry-run UNLOCK | `svops.ReadKeyring`, `svops.ImportKeyring` (a dry run with no client) | System keyring: Import its secrets… (a folder; the names first, read by `svops.ImportKeyring` with no client, as the dry run lists them; then the import) | done | `Y` panel `i`, `:` Desktop › Import the system keyring's secrets…: the folder, then the names (the dry run), then stored | done |
| `secretvault keyring takeover` --dry-run --no-import --prefix UNLOCK | `svops.PlanTakeover`, `svops.ImportKeyring`, `svops.ApplyTakeover`, `keyring.serve`, `svops.RestartUnits` | System keyring: Become the keyring… (import first, or not; the plan of `svops.PlanTakeover`, as the dry run says it: the files, the units, the Secret Service, what is left by hand; then applied in the CLI's order, and what was done reported) | done | `Y` panel `t`, `:` Desktop › Become the system keyring…: the plan (`svops.TakeoverLines`), then, confirmed, its secrets imported (into imported/), the files written, the daemon's Secret Service on, the units restarted, what is left to do by hand. Importing is not optional here: Y › i reads it alone | done |
| `secretvault keyring restore` --dry-run | `svops.LoadTakeover`, `keyring.serve`, `svops.UndoTakeover` | System keyring: Give it back… (what it would remove and restart, then undone) | done | `Y` panel `r`, `:` Desktop › Give the system keyring back…: the plan (`svops.RestoreLines`), then undone | done |
| `secretvault browser install` --browser --keepassxc --dry-run | `svops.PlanBrowserInstall` (`svops.ExtensionHost`; `svops.KeePassXCHost` with --keepassxc), `BrowserInstallPlan.Apply` (the managers pass `svops.CLIProgram()`) | Desktop › Browsers: under secretvault's own extension, Set up… (the browsers, those used here ticked; the plan per browser, then each applied), naming `svops.CLIProgram()`; under the legacy link, Set up the legacy link…, the same for KeePassXC-Browser; with no CLI beside the manager, it says so and offers neither | done | `B` browsers panel `i` (the extension's host) and `k` (the legacy link), `:` Desktop › Set the browsers up for the secretvault extension… and Set up the legacy KeePassXC-Browser link…: every browser used here, or one; the plan (`svops.HostPlanLines`, naming the CLI: `svops.CLIProgram()`), then applied | done |
| `secretvault browser uninstall` --keepassxc --extension --dry-run | `svops.UninstallBrowsers` (nil for both hosts; `&svops.KeePassXCHost` with --keepassxc, `&svops.ExtensionHost` with --extension) | Browsers: Undo… under secretvault's own extension, and Undo the legacy link… under the legacy link (what `svops.UninstallBrowsers(host, true)` would do, then done) | done | `B` panel `u` (the extension's host) and `l` (the legacy link), `:` Desktop › Undo the browsers' setup for the secretvault extension… and Undo the legacy KeePassXC-Browser link…: the plan (`svops.UndoLines`), then undone (`svops.UninstalledLines`) | done |
| `secretvault browser status` | `svops.BrowserStatus`, `svops.StatesOf`, `svops.NativeHostHeading` | Browsers: which program each browser starts, for secretvault's own extension first, then for the legacy KeePassXC-Browser link, and the install's record | done | `B` browsers panel: the same two lists (`svops.BrowserStateLine`, under each host's title), and when it was set up | done |
| `secretvault browser extension` --out --dir --force | `svops.WriteExtension`, `svops.WriteExtensionDir`, `svops.ExtensionFileName`, `svops.ExtensionWrittenLines` (the extension embedded by package `browser`) | Browsers: Save the extension… (a .zip for Firefox, or a folder for Chromium's Load unpacked; a file already there replaced only when said yes to; then how to load it) | done | `B` panel `e`, `:` Desktop › Write out the browser extension…: a .zip or a folder, and where; then how to load it | done |
| `secretvault browser list`, `secretvault browser ls` UNLOCK | `browser.list` | Browsers: under the legacy link, the KeePassXC-Browser extensions connected to the vault shown | done | `B` panel: the KeePassXC-Browser extensions connected to the vault shown | done |
| `secretvault browser rm NAME...`, `secretvault browser remove NAME...` UNLOCK | `browser.remove` | Browsers: Disconnect… | done | `B` panel `x` on an extension (asks first; one at a time) | done |
| `secretvault pgp gpg-setup` --gnupghome --dry-run --remove --gpg UNLOCK | `svops.GnuPGHere`, `svops.GnuPGHome`, `svops.PlanGnuPGSetup`, `svops.ApplyGnuPGSetup`, `svops.GnuPGPointed`, `svops.RemoveGnuPG` (the managers pass `svops.CLIProgram()`) | Desktop › GnuPG: Let gpg use the vault's keys… (the home, the gpg program; the plan of `svops.PlanGnuPGSetup` naming `svops.CLIProgram()`, discarded when said no to; then applied); Stop… (said first, then removed) | done | `P` keys panel `g`, `:` Desktop › GnuPG…: the home, the gpg program, or stopping; the plan (`svops.GnuPGPlanLines`, naming the CLI: `svops.CLIProgram()`), then applied | done |
| `secretvault helpers status` | `svops.PlanHelpers`, `HelpersPlan.StatusRows` (the managers pass `svops.CLIProgram()`) | Desktop › Program helpers: git's credential helpers and docker's credsStore (`HelpersPlan.StatusRows`), and each link beside the CLI, whether PATH finds it, and how it is used (`svops.HelperLinks`); with no CLI beside the manager, it says so and offers nothing | done | `:` Desktop › Program helpers: each link, git's credential helpers and docker's credsStore (`HelpersPlan.StatusRows`) | done |
| `secretvault helpers setup` --dry-run | `svops.PlanHelpers`, `svops.HelpersSetupIntro`, `HelpersPlan.SetupLines`, `HelpersPlan.Apply` (the managers pass `svops.CLIProgram()`) | Program helpers: Set up… (the plan, in the dry run's words; applied only when said yes to, what was done reported, and the tab filled again) | done | `:` Desktop › Program helpers `s`: the plan (`svops.HelpersSetupIntro`, `HelpersPlan.SetupLines`), then applied, and the panel filled again | done |
| `secretvault helpers undo` --dry-run | `svops.PlanHelpers`, `HelpersPlan.Undoable`, `svops.HelpersUndoIntro`, `HelpersPlan.UndoLines`, `HelpersPlan.Undo` | Program helpers: Undo… (offered when something is secretvault's; the plan, then undone, and the tab filled again) | done | `:` Desktop › Program helpers `u`: the plan (`svops.HelpersUndoIntro`, `HelpersPlan.UndoLines`), then undone, and the panel filled again | done |

## The host daemon (servers, as root)

The host commands are root's, on a server; the managers reach the host
daemon the same way the CLI does (its admin socket, as root). The GUI's
is the Desktop page's Host daemon tab, which anywhere else says that its
admin socket does not answer (making the host identity works on files,
as the CLI's `host init` does).

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault host init` --seal --out --credstore --tpm2-pcrs --suite | `svops.HostInit` | Desktop › Host daemon: Make the host identity… (the suite; in a root-only file, or sealed with systemd-creds, with its PCRs and where), and the steps after it | done | `H` host panel `i`, `:` Desktop › Make the host identity…: the suite, sealing it (systemd-creds, TPM2 PCRs) or a plain file; its recipient shown, copyable, and the next steps | done |
| `secretvault host allow UNIT CREDENTIAL REF`, `secretvault host allow --user USER` --program | `host.allow` | Host daemon: Allow… (a unit's credential, or a local service's references; the unit's LoadCredential= line, and the warnings) | done | `H` panel `a` (a unit's credential: unit, credential, reference), `l` (a local service: user, program, references); `:` Desktop › Allow…; the line for the unit, and the warnings | done |
| `secretvault host deny UNIT CREDENTIAL`, `secretvault host deny --user USER` --program | `host.deny` | Host daemon: Deny… | done | `H` panel `x` on a credential or a local service (asks first); `d`, `:` Desktop › Deny a local service's references… (some of them, or all) | done |
| `secretvault host list`, `secretvault host ls` | `host.list` | Host daemon: the policy (credentials, local services) | done | `H` host panel: the credentials served to units, the local services and what each may read | done |
| `secretvault host status` | `host.status` | Desktop › Host daemon: the daemon, its sockets, its identity and recipient, its policy's state, and its vaults; away from a server's root, where its admin socket does not answer, the tab says so, and still makes the host identity | done | `H` host panel: its version, sockets, identity and recipient (`c` copies it), policy, counts, and its vaults and whether each opens with the host identity | done |
| `secretvault host audit` -n | `host.audit`; `svops.HostEventColumns` | Host daemon: deliveries and refusals, newest first | done | `H` panel `v`, `:` Desktop › What the host delivered and refused (`svops.HostEventColumns`) | done |

## For programs

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault read REF` UNLOCK | `svops.Resolve` (`host.resolve` with --host) | **for programs**: Edit › Copy reference… and the item page's Copy reference… (the `sv://` reference of the item's secret or a field, the vault named or the default), and Tools › Resolve a reference… (what it names, masked until shown, copied from its bytes) | done | **for programs**: `y` copies the item's reference, or the selected field's; `:` Tools › Resolve a reference… (`svops.Resolve`: the value masked until revealed, copyable). The host daemon's resolving (--host) is the CLI's | done |
| `secretvault run` --env-file --env UNLOCK -- COMMAND | `svops.NewEnviron`, `Environ.LoadFiles`, `Environ.SetPairs`, `Environ.Resolve` | **for programs**: Tools › Check an env file… (each `sv://` reference in it, read as run reads it, and whether it resolves; no value shown) | done | **for programs**: `:` Tools › Check an env file's references… (env files and KEY=VALUE lines through `svops.Environ`: each `sv://` reference and whether it resolves, the values never shown). Running a command is the CLI's | done |
| `secretvault inject` -i -o UNLOCK | `svops.Inject`, `svops.TemplateRefs` | **for programs**: Tools › Check a template… (each reference, and whether it resolves; and the template filled into a new file only yours to read, if asked) | done | **for programs**: `:` Tools › Check a template's references, or fill it… (`svops.TemplateRefs`, each checked; filled with `svops.Inject` into a new file, mode 0600) | done |
| `secretvault git-credential get`, `secretvault git-credential store`, `secretvault git-credential erase` UNLOCK | `svops.GitMatches`, `svops.GitItem`, `item.list`, `item.get`, `item.put`, `item.delete`; setting it up: `svops.PlanHelpers` | **for programs**: git's logins are items under `git/`, listed and edited as any other; Desktop › Program helpers: where the `git-credential-secretvault` link is beside the CLI, whether git finds it, and git's `credential.helper` setting to copy; Set up… and Undo… make the link and add secretvault to git's `credential.helper` (`svops.PlanHelpers`, shown first, as `secretvault helpers setup` and `undo` do), and take them away; Show git's logins | done | **for programs**: the items under `git/` (done); `:` Desktop › Program helpers: the `git-credential-secretvault` link beside the CLI and git's `credential.helper` (`svops.PlanHelpers`, shown first, and undone the same way) | done |
| `secretvault docker-credential get`, `secretvault docker-credential store`, `secretvault docker-credential erase`, `secretvault docker-credential list`, `secretvault docker-credential version` UNLOCK | `svops.DockerItemName`, `svops.DockerItem`, `item.list`, `item.get`, `item.put`, `item.delete`; setting it up: `svops.PlanHelpers` | **for programs**: the registries' logins are items under `docker/`; Program helpers: the `docker-credential-secretvault` link, whether docker finds it, and `credsStore`; Set up… and Undo… make the link and set `credsStore` (`svops.PlanHelpers`, shown first; undoing puts back the store it replaced), and take them away; Show the registries' logins | done | **for programs**: the items under `docker/` (done); `:` Desktop › Program helpers: the `docker-credential-secretvault` link and docker's `credsStore` (`svops.PlanHelpers`) | done |
| `secretvault age-plugin` --age-plugin | `svops.ItemOfPluginIdentity`, `svops.VaultIdentity`, `svops.AgeItemRecipient`, `svage.Plugin`; its link: `svops.PlanHelpers` | **for programs**: Keys › age identities (the identity line age and SOPS read), and Program helpers: the `age-plugin-secretvault` link, and whether age finds it; Set up… and Undo… make it and take it away (`svops.PlanHelpers`, shown first) | done | **for programs**: `P` › age identities (copying the identity line), and `:` Desktop › Program helpers: the `age-plugin-secretvault` link | done |
| `secretvault browser-host` | for secretvault's own extension: `svext.ParseRequest`, `svext.GenerateReply` (with `svops.GeneratePassword`), `browser.open` (Protocol `svext.Protocol`), `browser.message` (`svext.Session` in the daemon, `svd/browser_ext.go`); for KeePassXC-Browser: `browser.open`, `browser.message` (a relay; `svbrowser` in the daemon) | **for programs**: Desktop › Browsers (the manifests that start it, the extension to load, and the KeePassXC-Browser extensions connected) | done | **for programs**: `B` browsers panel (the manifests that start it, the extension to write out, and the KeePassXC-Browser extensions connected) | done |
| `secretvault __clip SECONDS` | `svclip.Copy` | **for programs**: copying from an item; the GUI copies through uitoolkit's secret clipboard, cleared after 30 seconds | done | **for programs**: copying from an item (`c`, `u`, `o`), through this helper | done |
| `secretvault ci fetch REF...`, `secretvault ci run` --server --fingerprint --ca --role --audience --token-file --cert --key --id-token-file --id-token-env --timeout --github-env --env-file --env -- COMMAND | `svops.DeliveryClient`, `svops.IDToken`, `svops.DeliveryRef`, `svops.Environ`, `svdeliver.Client` | **for programs**: a pipeline's side; a person's is sharing the vault with the delivery server's recipient (Vault page › Sharing tab: Share with…) | done | **for programs**: `E` sharing panel `s`: sharing the vault with the delivery server's recipient | done |

gpg also starts the CLI as its agent-program
(`secretvault --homedir HOME --use-standard-socket --secretvault-gpg-agent --daemon`,
which `pgp gpg-setup` wrote into gpg.conf): it has the daemon link the
home's agent socket again (`svops.RelinkGnuPG`). Its person's side is
Desktop › GnuPG, above.

## For phase 2

What the managers need to know, beyond the table:

- **Call svops, and nothing like it of your own.** The CLI's behaviour is
  the reference: its tests (`cmd/secretvault/*_test.go`) say what each
  operation does, and its code shows the order the steps go in (for the
  keyring takeover: plan; import; `ApplyTakeover`; `ServeKeyring(true)`;
  `RestartUnits`). Where a manager already has its own copy, replace it:
  the GUI's attach uses `svops.ReadAttachment` and its history says who
  signed each revision with `svops.Author`; the terminal manager's
  history should do the same.
- **Programs named to other programs are the CLI.** The browsers' manifest
  (`PlanBrowserInstall`, `BrowserStatus`) and gpg.conf's agent-program
  (`GnuPGOptions.CLI`) must name the `secretvault` CLI, not the manager:
  pass `svops.CLIProgram()`. They refuse "" (`svops.ErrNoCLI`), which is
  what `CLIProgram` returns when no CLI is installed beside the manager:
  say so, and offer neither.
- **Dry runs are plans.** `PlanTakeover`, `PlanBrowserInstall`,
  `PlanGnuPGSetup`, `PlanHelpers` and `UninstallBrowsers(true)` change
  nothing (but for the socket directory gpgconf makes, which
  `GnuPGOptions.DryRun` removes, as `GnuPGPlan.Discard` does for a plan
  not carried out); show them, ask, then apply.
  `BrowserInstallPlan.Apply` refuses a manifest, and `HelpersPlan.Apply`
  and `Undo` a docker config, that changed while the plan was shown:
  make the plan again.
- **Some messages name the CLI's flags** ("--overwrite replaces it", "use
  --force"), as the CLI has always said them. A manager shows its own
  words where they would mislead: the errors are plain values
  (`svops.StoreError` keeps the daemon's in `Err`), or the condition is
  one the manager checks first. Those a manager tells apart are named,
  their texts unchanged: `ErrNoOwnKeys`, `ErrNoDefaultVault`,
  `ErrNoAgeIdentity`, `ErrNotOneSecretKey`, `ErrKeyExists`,
  `ErrNoGnuPGKey`, `ErrUninstallFirst` (with `errors.Is`), and
  `SkipAlreadyDone` and `SkipChanged` (a browser plan's `Skip`);
  `ImportOptions.Skipped` words the warning for an item that exists. The
  GUI's words for them are in `Manager.describe`
  ([`manager.go`](../gui/svmanager/manager.go)).
- **Asking stays with you.** svops takes passphrases already asked for, or
  a callback for the one it finds it needs (`PGPImportItem`,
  `ProtectPGPKey`, `PassphraseIdentity`, `AgeIdentityOptions`), and
  `ShareCollector` takes recovery shares one at a time as they are typed.
  Wipe what they return as the managers wipe everything else.
- **Off the interface's goroutine.** Everything that talks to the daemon
  may wait for a person; so may `ReadKeyring` (the old keyring may ask to
  be unlocked) and the gpg calls.
- **Tests never touch the system.** Point `HOME`, `XDG_CONFIG_HOME`,
  `XDG_DATA_HOME` and `SECRETVAULT_HOME` at a temporary directory (as
  `cmd/secretvault`'s browser and keyring tests do), replace
  `svops.CommandRunner`, give `HostInitOptions.SystemdCreds`, and never
  run an install or a takeover for real. The GUI's harness
  ([`harness_test.go`](../gui/svmanager/harness_test.go)) does all of
  that for every test, and points both buses, `SECRETVAULT_HOST_DATA` and
  `SECRETVAULT_HOST_RUNTIME` nowhere real; its daemon has software
  security keys (`internal/fidotest`), a sealer of its own and no network.
  Containers run against `internal/udiskstest` on a private bus. The
  TUI's harness ([`svtui_test.go`](../svtui/svtui_test.go)) does the
  same, with the keyring's tests on `internal/dbustest`'s private bus,
  fake gpg and git, and `svtui.Options` naming the CLI, secretvaultd, the
  host daemon's socket and systemd-creds.
- **Keep this page true.** A command added to the CLI fails the parity
  test until it has a row; when a manager gains an operation, change its
  state here in the same commit.
