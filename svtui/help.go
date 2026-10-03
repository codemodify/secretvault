package svtui

import (
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svrpc"
)

// helpKeys is the help's list of keys. ':' reaches everything too.
var helpKeys = strings.TrimSpace(`
[::b]Everything[::-]
  :                      the action menu: every operation, by menu; type to find one

[::b]Moving around[::-]
  Tab, Shift+Tab, ← →    move between the vaults, the items and the open item
  ↑ ↓ PgUp PgDn          move in a list
  Enter                  open the vault or the item under the cursor
  /                      filter the items as you type (Esc clears it)

[::b]The item[::-]  (the one under the cursor in the list, else the open one)
  c                      copy its secret, or the field selected in the item
  u                      copy its username
  o                      copy its current one-time code
  r                      reveal or hide its concealed values
  e                      edit it                 n    make a new item
  d                      delete it (asks first)  m    rename it
  h                      its history: every revision, who signed it, each
                         viewable; R makes one current, k keeps a
                         conflicting version on every device
  f                      its files: attach, save, remove
  y                      copy its reference (sv://VAULT/ITEM), or the
                         selected field's, for env files and templates
  g                      the password generator

[::b]Vaults[::-]
  l                      lock this vault         L    lock every vault
  U                      unlock the vault (asks for its passphrase)
  N                      a new vault
  K                      keyslots: the ways the vault opens; adding a
                         passphrase, recovery key (or shares), keyfile,
                         recipient or security key; removing one; changing
                         the passphrase; rotating the key; the security
                         keys plugged in
  R                      the deleted items: bring one back
  I                      import from a browser or another password manager
  X                      export to KeePass (KDBX) or CXF
  V                      the vaults: paths, when each locks, the default,
                         forgetting one, opening at login, verifying,
                         unlocking with a keyfile, recovery key or security key
  E                      sharing: who the vault is shared with, cutting
                         someone off; emergency access given (granting,
                         denying, revoking) and held (accepting an invite,
                         asking, opening)
  S                      sync: every synced vault, this one's devices;
                         setting up, inviting a device, syncing now,
                         removing a device, stopping; joining a vault
  D                      devices: who signs what is written; naming,
                         vouching for and removing one; whether only
                         signed revisions count
  M                      containers: encrypted disk images whose keys the
                         vault keeps; making, opening, closing one, backing
                         its header up, its own passphrase
  Y                      the system keyring: importing its secrets, taking
                         it over, giving it back (each shown first)
  B                      browsers: which host each starts, installing and
                         uninstalling (shown first), the extensions
                         connected, disconnecting one
  P                      keys: your OpenPGP keys (new, import, export, copy
                         the public key), S/MIME keys, age identities,
                         identity files; letting gpg use them
  C                      contacts: people and their keys; adding, importing
                         (a scanned QR code too), looking up, verifying,
                         removing; my QR code; checking a signer; keys seen
                         in mail; the directories; where contacts live
  H                      the host daemon (as root): its identity, what it
                         serves to units and local services, its vaults,
                         its log
  G                      grants: what programs may do; allowing or denying
                         one ahead of time, revoking a decision
  A                      the audit log: who accessed what

  ?                      this help               q    quit

[::b]In a panel[::-]
  the keys at its foot   act on the row selected, or on the panel
  Enter                  what can be done to the row selected
  Esc                    close it

[::b]In the editor[::-]
  Tab, Shift+Tab         move between fields     Ctrl+S  save
  Ctrl+R                 show or hide secrets    Ctrl+G  generate a password
  Esc                    close without saving

Copies clear themselves from the clipboard after 30 seconds. Secrets are
wiped from this program's memory when you leave the item, when the vault
locks, and when you quit.`)

// showHelp shows the versions ('secretvault version'), the keys, and the
// daemon's status ('secretvault status').
func (u *UI) showHelp() {
	u.fetchStatus(func(st svrpc.Status, err error) {
		head := "secretvault-tui " + secretvault.Version
		if err == nil {
			head += " · secretvaultd " + st.Version
		}
		u.showText("Help", "[gray]"+tview.Escape(head)+"[-]\n\n"+helpKeys+"\n\n[::b]Status[::-]  (Help › About in the : menu)\n"+statusText(st, err))
	})
}
