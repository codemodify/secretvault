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
- **TUI**: the key, panel or dialog in the terminal manager. Its keys today
  are listed under `?` ([`svtui/ui.go`](../svtui/ui.go)). New panels get
  capital letters that are free (`K` keyslots, `D` devices, `S` sync, `E`
  sharing and emergency access, `C` contacts, `P` keys, `B` browsers, `M`
  containers, `V` the vault's settings, `N` new vault, `I` import, `X`
  export, `R` deleted items, `Y` the system keyring, `H` the host daemon),
  `f` the item's files and `y` copying an item's reference; and `:` opens
  an action menu of every operation, grouped as the GUI's menus are, so
  that nothing needs a key to be reachable.
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
| `secretvault init`, `secretvault vault create`, `secretvault vault init` --name --path --suite --recovery --passphrase-file | `vault.create` | File › New vault… (name, suite, passphrase, a folder of one's own or the data folder, the recovery key shown once) | done | `N` New vault dialog | missing |
| `secretvault unlock [VAULT]` UNLOCK | `vault.unlock`; shares: `svops.ShareCollector` | Vault › Unlock (Ctrl+U), the locked vault's "Unlock…": the daemon asks for the passphrase or a security key's PIN, in a window of its own; Vault › Unlock with…: the recovery key, recovery shares typed one at a time (`svops.ShareCollector`), a keyfile, an identity file, the security key plugged in | done | `U`, passphrase only; `U` then "with…" for the rest | partial |
| `secretvault lock [VAULT]` --all | `vault.lock` | Vault › Lock (Ctrl+L), Lock all vaults (Ctrl+Shift+L), the tray's Lock all vaults | done | `l`, `L` | done |
| `secretvault status` | `daemon.status` | Help › About secretvault: the daemon's version, process, data and socket, the prompter, the keyring, the SSH and gpg agents, emergency requests, and every vault with its state, when it locks and its folder; emergency requests also in the status bar (`emergency.changed`) | done | `?` help shows the daemon's status; emergency requests on the status line. Today only the vaults pane | partial |
| `secretvault vault list`, `secretvault vault ls` | `vault.list` | The vaults list on the left (name, state, the default starred); the folder and when it locks on Vault page › Settings, and for every vault in Help › About secretvault | done | The vaults pane; the path and when it locks are missing | partial |
| `secretvault vault add NAME DIR` | `vault.add` | File › Add vault folder… (a folder chooser and a name) | done | `V` vault panel: add | missing |
| `secretvault vault forget NAME` | `vault.forget` | Vault page › Settings tab: Forget this vault… (the folder stays) | done | `V` vault panel: forget | missing |
| `secretvault vault default NAME` | `vault.default` | Vault › Make default; Vault page › Settings tab: Make default | done | `V` vault panel: make default | missing |
| `secretvault vault rotate` --new-recovery --new-passphrase-file UNLOCK | `vault.rotate` | Vault page › Keyslots tab: Rotate the key… (proves itself first, as the CLI does; the passphrase, a new recovery key shown once, and a report of what opens it now) | done | `K` keyslots panel: rotate | missing |
| `secretvault vault signatures [required\|optional]` UNLOCK | `vault.signatures` | Vault page › Devices tab: "Count only signed revisions" | done | `D` devices panel: signatures | missing |
| `secretvault vault login on\|off` UNLOCK | `vault.login` | Vault page › Settings tab: "Open when I log in" | done | `V` vault panel: login | missing |
| `secretvault verify` UNLOCK | `vault.verify` | Vault page › Settings tab: Verify every file… (the report) | done | `V` vault panel: verify | missing |
| `secretvault passwd` --new-passphrase-file UNLOCK | `vault.passwd` | Vault page › Keyslots tab: Change the passphrase… (proves itself first, then asks for the new one) | done | `K` keyslots panel: passphrase | missing |
| `secretvault version` | `secretvault.Version`; `daemon.status` for the daemon's | Help › About secretvault: this program's version and the daemon's | done | `?` help, at its head | missing |

## Items

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault set NAME` --kind --label --attr --tag --field --secret-field --generate --no-secret --replace UNLOCK | `item.get`, `item.put`; `svops.SetField`, `svops.GeneratePassword` | File › New item (Ctrl+N), Edit › Edit item (Ctrl+E): the editor, with its generator | done | `n`, `e`: the editor (Ctrl+G generates) | done |
| `secretvault get NAME` --field --json --clip --clip-seconds UNLOCK | `item.get`; `svops.SecretField`, `svops.Field` | Open (Enter), Copy password (Ctrl+C), Copy username (Ctrl+B), each field's Copy | done | Enter, `c`, `u`, `c` on a field | done |
| `secretvault ls [PREFIX]` -l UNLOCK | `item.list` | The items list, the folders, the search (Ctrl+F) | done | The items pane, `/` filter | done |
| `secretvault ls --deleted` | `item.deleted` | Edit › Deleted items (each with Restore) | done | `R` deleted items panel | missing |
| `secretvault mv FROM TO` UNLOCK | `item.rename` | Edit › Rename… (F2) | done | `m` | done |
| `secretvault rm NAME` UNLOCK | `item.delete` | Edit › Delete… (Delete) | done | `d` | done |
| `secretvault history NAME` --show UNLOCK | `item.history`; `svops.Author` | Edit › History (Ctrl+H): every revision, viewable, with who signed each (`svops.Author`) and the revisions a vault that requires signatures ignores; the item page's foot says who signed it | done | `h`: every revision, viewable; who signed each is missing | partial |
| `secretvault restore NAME [REV]` UNLOCK | `item.restore` | History page: "Make this revision current…" under the revision shown; Edit › Deleted items: Restore | done | History panel: `R` on a revision; deleted items panel: Enter | missing |
| `secretvault resolve NAME` --keep UNLOCK | `svops.Conflicts`, `item.restore` | History page: conflicting versions are marked, and viewable; "Keep this version on every device…" under each of them | done | `h` marks them; `k` keeps one is missing | partial |
| `secretvault attach ITEM FILE\|-` --name --type UNLOCK | `svops.ReadAttachment`, `file.attach` | Item page › Files: Add file… (read with `svops.ReadAttachment`: its own name, and its extension's media type) | done | `f` files panel: attach | missing |
| `secretvault file list ITEM`, `secretvault file ls ITEM` UNLOCK | `item.get` (the item's files) | Item page › Files | done | `f` files panel | missing |
| `secretvault file get ITEM NAME` -o --force UNLOCK | `file.get`; `svops.SaveFile` | Item page › Files: Save… (the file dialog asks before replacing a file; written with `svops.WriteReplacing`, mode 0600, as a replaced file must not stay as readable as it was) | done | `f` files panel: save | missing |
| `secretvault file rm ITEM NAME`, `secretvault file remove ITEM NAME` UNLOCK | `file.remove` | Item page › Files: Remove… | done | `f` files panel: remove | missing |
| `secretvault gen` --length --no-symbols --clip | `svops.GeneratePassword` (`svcrypto.Password`) | File › Password generator… (Ctrl+G): characters or words | done | `g` | done |

## Import and export

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault import FORMAT FILE` --prefix --dry-run --overwrite --source-passphrase-file --source-keyfile UNLOCK | `svops.ReadImportFile`, `svops.ImportFormat`, `svimport.Import` (asking again while `svops.NeedsPassphrase`), `svops.StoreImport` | File › Import…: the file (the format guessed, or chosen), a folder to put it under, its passphrase or KeePass key file if it needs one, whether to replace what exists; then the names it would make and its warnings (the dry run), and only then the import, with the warnings in the GUI's words (`ImportOptions.Skipped`) | done | `I` import dialog | missing |
| `secretvault export cxf\|kdbx FILE` --prefix --new-passphrase-file UNLOCK | `svops.CheckExport`, `svops.ReadForExport`, `svops.EncodeExport`, `svops.WriteNew` | File › Export…: the format, a new file, a folder of the items, the KeePass file's passphrase, the warning that CXF is not encrypted; and the items in conflict or badly signed | done | `X` export dialog | missing |

## Keyslots and security keys

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault slot list`, `secretvault slot ls` | `slot.list` | Vault page › Keyslots tab | done | `K` keyslots panel | missing |
| `secretvault slot add passphrase\|recovery\|keyfile\|recipient\|fido2` --label --new-passphrase-file --create --split --threshold --uv --no-uv UNLOCK | `slot.add`; `svops.CreateKeyfile`, `svops.RecipientArg`, `svops.SplitThreshold`, `svops.SplitLabel`, `svops.SplitRecoveryKey` | Keyslots tab: Add…: the kind, then what it takes: a passphrase; a recovery key shown once, or split into shares shown once; a keyfile, made there or chosen; a recipient, its file or an identity file; the security key plugged in (its PIN with every touch, always, or a touch alone; the PIN asked in its own window, the touches in the status bar) | done | `K` keyslots panel: `a` | missing |
| `secretvault slot rm ID`, `secretvault slot remove ID` UNLOCK | `slot.remove` | Keyslots tab: Remove… (asks first, and says it is not revocation) | done | `K` keyslots panel: `x` | missing |
| `secretvault fido2 list`, `secretvault fido2 ls` | `fido2.list` | Keys › Security keys: those plugged in, and what each can do (its PIN and the tries left, hmac-secret, a problem); Refresh | done | `K` keyslots panel: the security keys plugged in | missing |

## Sharing and emergency access

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault share RECIPIENT\|FILE` --label UNLOCK | `svops.RecipientArg`, `slot.add` (a recipient keyslot) | Vault page › Sharing tab: Share with…: a contact's secretvault key, a recipient, a file holding one, or an identity file (all through `svops.RecipientArg`) | done | `E` sharing panel: share | missing |
| `secretvault unshare SLOT-ID...` --new-recovery --new-passphrase-file UNLOCK | `vault.rotate` (dropping the slots) | Sharing tab: Cut off… (the keyslot chosen; the key rotated without it, a new recovery key if asked, and what opens it now) | done | `E` sharing panel: cut off | missing |
| `secretvault emergency grant CONTACT\|RECIPIENT` --wait --fingerprint --name UNLOCK | `svops.ParseWait`, `emergency.grant` | Sharing tab › Emergency access: Grant… (a contact, or a recipient; the wait read by `svops.ParseWait`), then the invite to send, to copy or as a QR code | done | `E` panel: grant | missing |
| `secretvault emergency list`, `secretvault emergency ls` UNLOCK | `emergency.list`; `svops.WaitText` | Sharing tab › Emergency access: the grants given and the access held here; requests also in the status bar, in the GUI's own words | done | `E` panel | missing |
| `secretvault emergency deny GRANT` UNLOCK | `emergency.deny` | Emergency access: Deny… | done | `E` panel: deny | missing |
| `secretvault emergency revoke GRANT` --rotate --new-recovery --new-passphrase-file UNLOCK | `emergency.revoke`, then `vault.rotate` | Emergency access: Revoke… (with "rotate the key too", ticked when they were given it) | done | `E` panel: revoke | missing |
| `secretvault emergency accept INVITE\|-` --identity --as --label | `emergency.accept` | File › Emergency access › Accept an invite… (the invite pasted, the identity file chosen, its name here, this device's label) | done | `E` panel: accept | missing |
| `secretvault emergency request NAME` | `emergency.request` | File › Emergency access › Ask for access… (the access held chosen, or its name typed when it cannot be listed) | done | `E` panel: request | missing |
| `secretvault emergency open NAME` --identity --path | `emergency.open` | File › Emergency access › Open the vault… (after the wait; the identity file, and a folder of one's own if wanted) | done | `E` panel: open | missing |

## Sync

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault sync setup URL` --fingerprint --admin-token-file --label UNLOCK | `sync.setup` | Vault page › Sync tab: Set up… (the server, its fingerprint, the admin token, this device's label) | done | `S` sync panel: set up | missing |
| `secretvault sync join INVITE\|-` --name --path --label | `sync.join` | File › Join a synced vault… (the invite pasted into a secret field, the name here, a folder of one's own, this device's label) | done | `S` sync panel: join | missing |
| `secretvault sync invite` --qr --light UNLOCK | `sync.invite`; `svqr` | Sync tab: Invite a device… (the invite shown once, to copy, and its QR code in a dialog of its own; both wiped when they close) | done | `S` sync panel: invite (with the QR code) | missing |
| `secretvault sync status`, `secretvault sync st` | `sync.status` | Vault page › Sync tab, and the status bar, for the vault shown | done | `S` sync panel | missing |
| `secretvault sync now` UNLOCK | `sync.now` | Sync tab: Sync now | done | `S` sync panel: now | missing |
| `secretvault sync devices` UNLOCK | `sync.devices` | Sync tab: the devices that sync (once the vault is unlocked) | done | `S` sync panel: devices | missing |
| `secretvault sync rm-device KEY` UNLOCK | `sync.remove` | Sync tab: Remove a device… | done | `S` sync panel: remove a device | missing |
| `secretvault sync off` UNLOCK | `sync.off` | Sync tab: Stop syncing… | done | `S` sync panel: off | missing |

## Devices

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault device list`, `secretvault device ls` UNLOCK | `device.list`; `svops.DeviceStanding` | Vault page › Devices tab: each device, its key ID, its label, when it registered, its standing (`svops.DeviceStanding`) | done | `D` devices panel | missing |
| `secretvault device label [DEVICE] NAME` UNLOCK | `device.label` | Devices tab: Rename… | done | `D` panel: label | missing |
| `secretvault device rm DEVICE`, `secretvault device remove DEVICE` UNLOCK | `device.remove` | Devices tab: Remove… (says it does not cut the device off) | done | `D` panel: remove | missing |
| `secretvault device vouch DEVICE` --withdraw UNLOCK | `device.vouch` | Devices tab: Vouch for it (asks first, showing the key to compare) / Withdraw | done | `D` panel: vouch | missing |

## Grants and the audit log

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault grant list`, `secretvault grant ls` UNLOCK | `grant.list` | Vault › Grants and audit log (Ctrl+Shift+G) › Grants tab | done | `G` | done |
| `secretvault grant allow PROGRAM`, `secretvault grant deny PROGRAM` --item --contacts --ops --until-lock UNLOCK | `grant.add` | Grants tab: Allow a program… / Deny a program… (the program chosen or typed as flatpak:APP or snap:NAME; the whole vault, an item or the contacts; the operations; allow until the vault locks) | done | `G` panel: allow, deny | missing |
| `secretvault grant revoke ID`, `secretvault grant rm ID` UNLOCK | `grant.revoke` | Grants tab: Revoke… (Delete) | done | `G` panel: `x` or Delete | done |
| `secretvault audit` --limit UNLOCK | `audit.list` | Vault page › Audit log tab (the newest 500) | done | `A` | done |

## Keys and identities

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault identity new` --out --suite | `svops.NewIdentity`, `svops.WriteNew` | Keys › Identity files: New… (the cipher suite, a new file only its owner reads; its recipient shown) | done | `P` keys panel: new identity | missing |
| `secretvault identity pub FILE` | `svops.IdentityRecipient` | Keys › Identity files: Show the recipient of a file… | done | `P` keys panel: recipient of a file | missing |
| `secretvault pgp list`, `secretvault pgp ls` UNLOCK | `item.list`; `svops.PGPKeyEntries` | Keys › OpenPGP keys (`svops.PGPKeyEntries`): item, fingerprint, user ID | done | `P` keys panel › OpenPGP | missing |
| `secretvault pgp new` --name --email --v4 --item --expires UNLOCK | `pgp.generate` | OpenPGP keys: New… (name, addresses, item, expiry, version 4 or 6) | done | `P` › OpenPGP: new | missing |
| `secretvault pgp import FILE\|-` --item --key-passphrase-file UNLOCK | `svops.PGPImportItem`, `svops.StorePGPKey` | OpenPGP keys: Import… (a key file; its passphrase asked for in a dialog when `svops.PGPImportItem` finds it protected; a name taken said in the GUI's words, `svops.ErrKeyExists`) | done | `P` › OpenPGP: import | missing |
| `secretvault pgp export [KEY]` --secret --unprotected --new-passphrase-file -o UNLOCK | `pgp.public`; with --secret `item.get`, `svops.ProtectPGPKey`; `svops.CreateAtomic` | OpenPGP keys: Export… (the public key, the secret key under a new passphrase asked for when `svops.ProtectPGPKey` needs it, or the secret key as kept), to a file that appears whole, mode 0600 | done | `P` › OpenPGP: export | missing |
| `secretvault pgp pub [KEY]` -o UNLOCK | `pgp.public` | OpenPGP keys: Copy the public key | done | `P` › OpenPGP: `c` copies the public key | missing |
| `secretvault pgp sign [IN]` --key --inline --clear -a --text -o UNLOCK | `pgp.sign` | Tools › Sign a file… (the key, detached, inline or cleartext, armored, a text signature, where it goes) | done | `:` Sign a file | missing |
| `secretvault pgp decrypt [IN]` --key --verify --from -o UNLOCK | `pgp.decrypt` | Tools › Decrypt a file (OpenPGP)… (the key, or the one it is for; its signatures checked if asked, with From), into a new file only yours to read | done | `:` Decrypt a file | missing |
| `secretvault pgp verify [IN]` --signature --from -o UNLOCK | `pgp.verify` | Tools › Check a signature… (a detached signature or a signed message, From, its text written if asked): the verdict against the contacts | done | `:` Check a signature | missing |
| `secretvault smime import FILE.p12` --password-file --item UNLOCK | `smime.import` | Keys › S/MIME keys: Import… (the .p12 file, its password, the item) | done | `P` › S/MIME: import | missing |
| `secretvault smime list`, `secretvault smime ls` UNLOCK | `smime.list` | Keys › S/MIME keys: item, addresses, certificate, expiry | done | `P` › S/MIME | missing |
| `secretvault age keygen` --name --pq -o UNLOCK | `svops.GenerateAgeIdentity`, `svops.StoreAgeIdentity` (both: `svops.AgeKeygen`) | Keys › age identities: New… (the item, post-quantum or not, and a file for the identity line if wanted); its recipient and identity line shown | done | `P` › age: new | missing |
| `secretvault age recipient ITEM` UNLOCK | `svops.AgeItemRecipient` | age identities (`svops.AgeKeyEntries`): Copy the recipient | done | `P` › age: copy the recipient | missing |
| `secretvault age identity ITEM` UNLOCK | `svops.VaultName`, `svops.AgePluginIdentity` | age identities: Copy the identity line (for age and SOPS) | done | `P` › age: copy the identity line | missing |
| `secretvault age encrypt [IN]` -r -R -p -a -o --allow-mixed-pq UNLOCK | `svops.AgeRecipient`, `svops.EachKeyLine`, `svops.AgeEncrypt`, `svops.CreateAtomic` | Tools › Encrypt a file (age)… (recipients typed, or added from the vault's identities and the contacts' SSH keys, a recipients file; or a passphrase asked for twice; armor, mixed post-quantum); another plugin talks to the person in dialogs | done | `:` Encrypt a file | missing |
| `secretvault age decrypt [IN]` -i -o UNLOCK | `svops.AgeIdentities`, `svops.VaultIdentity`, `svops.PassphraseIdentity`, `svops.AgeDecrypt` | Tools › Decrypt a file (age)… (one of the vault's identities, an identity file or SSH key, whose passphrase is asked for; with none, the file's passphrase), into a new file only yours to read | done | `:` Decrypt a file | missing |

## Contacts and trust

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault contact list [QUERY]`, `secretvault contact ls [QUERY]` UNLOCK | `contact.list` | Contacts › Contacts (Ctrl+Shift+K), its page: the list (name, addresses, keys, how well verified), with a search | done | `C` contacts panel, `/` filter | missing |
| `secretvault contact show NAME` --json UNLOCK | `contact.get`; `svops.GroupFingerprint`, `svops.LevelText` | Contacts page: the contact chosen, below the list: its keys and fingerprints, how each was verified, where each was seen, its warnings | done | `C` panel: Enter | missing |
| `secretvault contact add FILE...` --name --email --notes --org UNLOCK | `contact.add` | Contacts › Add… (key files chosen, name, addresses, notes, organisation) | done | `C` panel: add | missing |
| `secretvault contact import FILE\|URI` --to --name --fetch --keyserver UNLOCK | `svops.IsContactURI`, `contact.import` | Contacts › Import… (a file of keys, or the text of a scanned QR code, which verifies its keys; into a contact, a name, fetching from a keyserver) | done | `C` panel: import | missing |
| `secretvault contact rm NAME`, `secretvault contact remove NAME` --fingerprint UNLOCK | `contact.remove` | Contacts page: Remove… (the contact, or one of its keys) | done | `C` panel: remove | missing |
| `secretvault contact verify [NAME]` --fingerprint --in-person --qr --org --tofu --email --note UNLOCK | `contact.verify` | Contacts page: Verify… (the key; its fingerprint typed as it was compared, and checked against the key's; in person, their QR code, an organisation, or accepted as it is; addresses; a note) | done | `C` panel: verify | missing |
| `secretvault contact lookup ADDRESS\|FPR` --wkd --keyserver --directory --add --name UNLOCK | `contact.lookup` | Contacts › Look up… (everywhere, WKD only, a keyserver, or one directory; keep what is found) | done | `C` panel: look up | missing |
| `secretvault contact qr` --key --recipient --name --email --uri --light UNLOCK | `svops.OwnCard`, `svtrust.Card.URI`, `svqr` | Contacts › Show my QR code… (your OpenPGP keys, and a recipient or identity file; the name and addresses): the code, and its text | done | `C` panel: my QR code | missing |
| `secretvault contact vault [VAULT\|-]` | `contact.vault` | Contacts › Keep contacts in… (says where they are now; a vault chosen, or the default) | done | `C` panel: vault | missing |
| `secretvault contact directory add NAME URL` --base --bind-dn --password --ca | `directory.add` | Contacts › Directories: Add… (name, address, where people are, bind DN, its password as an sv:// reference, a CA file) | done | `C` panel › directories: add | missing |
| `secretvault contact directory list`, `secretvault contact directory ls` | `directory.list` | Contacts › Directories | done | `C` panel › directories | missing |
| `secretvault contact directory rm NAME`, `secretvault contact directory remove NAME` | `directory.remove` | Contacts › Directories: Remove… | done | `C` panel › directories: remove | missing |
| `secretvault trust check` --fingerprint --key --cert --from --min-level --json UNLOCK | `trust.check` | Contacts › Check a signer… (a fingerprint or a key file, the From address, the weakest verification that counts): the verdict and its reasons | done | `C` panel: check a signer | missing |
| `secretvault trust seen` --key --from --at --source --name UNLOCK | `trust.seen` | Contacts › Record a key seen in mail… (the key, the address, when, what it was, a name) | done | `C` panel: record a key seen | missing |

## Mail

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault mail inspect FILE\|-` --decrypt --json --min-level --contacts UNLOCK | `svops.ReadMessage`, `mail.inspect` | Tools › Inspect a message… (decrypted if asked, the weakest verification that counts): its headers, layers, signers judged against the contacts, warnings, and its text parts, each masked until shown | done | `:` Inspect a message | missing |
| `secretvault mail compose FILE\|-` --sign --encrypt --format --key -o UNLOCK | `svops.ReadMessage`, `mail.compose`, `svops.WriteMessage` | Tools › Sign and encrypt a message… (sign, encrypt, OpenPGP or S/MIME, your key, where it goes) | done | `:` Compose a message | missing |

## Encrypted containers

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault container create FILE` --size --fs --label --item --passphrase --new-passphrase-file --sector-size --mount-options UNLOCK | `svops.MountsHere`, `svops.ParseSize`, `svops.ContainerItemName`, `container.create` | Vault page › Containers tab: New container… (the image, its size read by `svops.ParseSize`, the filesystem, its label, the key item, the sector size, mount options, and a passphrase of its own if wanted) | done | `M` containers panel: new | missing |
| `secretvault container open FILE` --item --mount-options UNLOCK | `svops.ExistingImage`, `container.open` | Containers tab: Open (the one chosen), Open another file… (any image, with the item and mount options); Copy the folder's path | done | `M` panel: open | missing |
| `secretvault container close FILE\|MOUNTPOINT` | `container.close` | Containers tab: Close | done | `M` panel: close | missing |
| `secretvault container list`, `secretvault container ls` UNLOCK | `container.list` | Vault page › Containers tab | done | `M` panel | missing |
| `secretvault container header-backup FILE OUT` | `svcontainer.BackupHeader` | Containers tab: Back up the header… (where, chosen) | done | `M` panel: header backup | missing |
| `secretvault container passwd FILE` --item --remove --new-passphrase-file UNLOCK | `svops.ExistingImage`, `container.passwd` | Containers tab: Passphrase… (set, change or remove its own passphrase) | done | `M` panel: passphrase | missing |

## The desktop

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault keyring status` | `svops.KeyringHolderNow`, `daemon.status`, `svops.LoadTakeover` | Desktop › System keyring: who holds it (or that there is no session bus), whether secretvault serves it, and the takeover's record | done | `Y` keyring panel | missing |
| `secretvault keyring import` --prefix --dry-run UNLOCK | `svops.ReadKeyring`, `svops.ImportKeyring` (a dry run with no client) | System keyring: Import its secrets… (a folder; the names first, read by `svops.ImportKeyring` with no client, as the dry run lists them; then the import) | done | `Y` panel: import | missing |
| `secretvault keyring takeover` --dry-run --no-import --prefix UNLOCK | `svops.PlanTakeover`, `svops.ImportKeyring`, `svops.ApplyTakeover`, `keyring.serve`, `svops.RestartUnits` | System keyring: Become the keyring… (import first, or not; the plan of `svops.PlanTakeover`, as the dry run says it: the files, the units, the Secret Service, what is left by hand; then applied in the CLI's order, and what was done reported) | done | `Y` panel: take over (the plan, then confirm) | missing |
| `secretvault keyring restore` --dry-run | `svops.LoadTakeover`, `keyring.serve`, `svops.UndoTakeover` | System keyring: Give it back… (what it would remove and restart, then undone) | done | `Y` panel: restore | missing |
| `secretvault browser install` --browser --dry-run | `svops.PlanBrowserInstall`, `BrowserInstallPlan.Apply` (the managers pass `svops.CLIProgram()`) | Desktop › Browsers: Set up… (the browsers, those used here ticked; the plan per browser, then each applied), naming `svops.CLIProgram()`; with no CLI beside the manager, it says so and offers nothing | done | `B` browsers panel: install | missing |
| `secretvault browser uninstall` --dry-run | `svops.UninstallBrowsers` | Browsers: Undo… (what `svops.UninstallBrowsers(true)` would do, then done) | done | `B` panel: uninstall | missing |
| `secretvault browser status` | `svops.BrowserStatus` | Browsers: which host each browser starts, and the install's record | done | `B` panel | missing |
| `secretvault browser list`, `secretvault browser ls` UNLOCK | `browser.list` | Browsers: the extensions connected to the vault shown | done | `B` panel: connected | missing |
| `secretvault browser rm NAME...`, `secretvault browser remove NAME...` UNLOCK | `browser.remove` | Browsers: Disconnect… | done | `B` panel: disconnect | missing |
| `secretvault pgp gpg-setup` --gnupghome --dry-run --remove --gpg UNLOCK | `svops.GnuPGHere`, `svops.GnuPGHome`, `svops.PlanGnuPGSetup`, `svops.ApplyGnuPGSetup`, `svops.GnuPGPointed`, `svops.RemoveGnuPG` (the managers pass `svops.CLIProgram()`) | Desktop › GnuPG: Let gpg use the vault's keys… (the home, the gpg program; the plan of `svops.PlanGnuPGSetup` naming `svops.CLIProgram()`, discarded when said no to; then applied); Stop… (said first, then removed) | done | `P` keys panel › OpenPGP: gpg setup | missing |

## The host daemon (servers, as root)

The host commands are root's, on a server; the managers reach the host
daemon the same way the CLI does (its admin socket, as root), from a
Host page that shows only there.

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault host init` --seal --out --credstore --tpm2-pcrs --suite | `svops.HostInit` | Desktop › Host daemon: Make the host identity… (the suite; in a root-only file, or sealed with systemd-creds, with its PCRs and where), and the steps after it | done | `H` host panel: init | missing |
| `secretvault host allow UNIT CREDENTIAL REF`, `secretvault host allow --user USER` --program | `host.allow` | Host daemon: Allow… (a unit's credential, or a local service's references; the unit's LoadCredential= line, and the warnings) | done | `H` panel: allow | missing |
| `secretvault host deny UNIT CREDENTIAL`, `secretvault host deny --user USER` --program | `host.deny` | Host daemon: Deny… | done | `H` panel: deny | missing |
| `secretvault host list`, `secretvault host ls` | `host.list` | Host daemon: the policy (credentials, local services) | done | `H` panel | missing |
| `secretvault host status` | `host.status` | Host daemon: the daemon, its sockets, its identity and recipient, its policy's state, and its vaults; when its admin socket does not answer (not root, not a server), it says so | done | `H` panel: status | missing |
| `secretvault host audit` -n | `host.audit` | Host daemon: deliveries and refusals, newest first | done | `H` panel: audit | missing |

## For programs

| CLI | Operation | GUI | GUI state | TUI | TUI state |
| --- | --- | --- | --- | --- | --- |
| `secretvault read REF` UNLOCK | `svops.Resolve` (`host.resolve` with --host) | **for programs**: Edit › Copy reference… and the item page's Copy reference… (the `sv://` reference of the item's secret or a field, the vault named or the default), and Tools › Resolve a reference… (what it names, masked until shown, copied from its bytes) | done | **for programs**: `y` copies the item's reference; `:` Resolve a reference | missing |
| `secretvault run` --env-file --env UNLOCK -- COMMAND | `svops.NewEnviron`, `Environ.LoadFiles`, `Environ.SetPairs`, `Environ.Resolve` | **for programs**: Tools › Check an env file… (each `sv://` reference in it, read as run reads it, and whether it resolves; no value shown) | done | **for programs**: `:` Check an env file | missing |
| `secretvault inject` -i -o UNLOCK | `svops.Inject`, `svops.TemplateRefs` | **for programs**: Tools › Check a template… (each reference, and whether it resolves; and the template filled into a new file only yours to read, if asked) | done | **for programs**: `:` Check a template | missing |
| `secretvault git-credential get`, `secretvault git-credential store`, `secretvault git-credential erase` UNLOCK | `svops.GitMatches`, `svops.GitItem`, `item.list`, `item.get`, `item.put`, `item.delete` | **for programs**: git's logins are items under `git/`, listed and edited as any other; Desktop › Program helpers: where the `git-credential-secretvault` link is (the installer makes it beside the CLI, as for the CLI), whether git finds it, and git's `credential.helper` setting to copy; Show git's logins | done | **for programs**: the items under `git/` (done); `:` Program helpers (missing) | partial |
| `secretvault docker-credential get`, `secretvault docker-credential store`, `secretvault docker-credential erase`, `secretvault docker-credential list`, `secretvault docker-credential version` UNLOCK | `svops.DockerItemName`, `svops.DockerItem`, `item.list`, `item.get`, `item.put`, `item.delete` | **for programs**: the registries' logins are items under `docker/`; Program helpers: the `docker-credential-secretvault` link, whether docker finds it, and `credsStore`; Show the registries' logins | done | **for programs**: the items under `docker/` (done); `:` Program helpers (missing) | partial |
| `secretvault age-plugin` --age-plugin | `svops.ItemOfPluginIdentity`, `svops.VaultIdentity`, `svops.AgeItemRecipient`, `svage.Plugin` | **for programs**: Keys › age identities (the identity line age and SOPS read), and Program helpers: the `age-plugin-secretvault` link, and whether age finds it | done | **for programs**: `P` › age, and `:` Program helpers | missing |
| `secretvault browser-host` | `browser.open`, `browser.message` (a relay; `svbrowser` in the daemon) | **for programs**: Desktop › Browsers (the manifests that start it, and the extensions connected) | done | **for programs**: `B` browsers panel | missing |
| `secretvault __clip SECONDS` | `svclip.Copy` | **for programs**: copying from an item; the GUI copies through uitoolkit's secret clipboard, cleared after 30 seconds | done | **for programs**: copying from an item (`c`, `u`, `o`), through this helper | done |
| `secretvault ci fetch REF...`, `secretvault ci run` --server --fingerprint --ca --role --audience --token-file --cert --key --id-token-file --id-token-env --timeout --github-env --env-file --env -- COMMAND | `svops.DeliveryClient`, `svops.IDToken`, `svops.DeliveryRef`, `svops.Environ`, `svdeliver.Client` | **for programs**: a pipeline's side; a person's is sharing the vault with the delivery server's recipient (Vault page › Sharing tab: Share with…) | done | **for programs**: `E` sharing panel: share | missing |

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
  `PlanGnuPGSetup` and `UninstallBrowsers(true)` change nothing (but for
  the socket directory gpgconf makes, which `GnuPGOptions.DryRun`
  removes, as `GnuPGPlan.Discard` does for a plan not carried out); show
  them, ask, then apply. `BrowserInstallPlan.Apply` refuses a manifest
  that changed while the plan was shown: make the plan again.
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
  Containers run against `internal/udiskstest` on a private bus.
- **Keep this page true.** A command added to the CLI fails the parity
  test until it has a row; when a manager gains an operation, change its
  state here in the same commit.
