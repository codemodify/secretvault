package svtui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/codemodify/secretvault/svops"
)

// The action menu (':'): every operation, grouped as the desktop
// manager's menus are, found by typing part of its name. Nothing needs a
// key to be reachable; the keys are shortcuts, shown beside each entry.

type menuEntry struct {
	group string
	label string
	key   string // its shortcut on the main screen, if any
	do    func()
}

// menuGroups are the menus, in the desktop manager's order.
var menuGroups = []string{"File", "Edit", "Vault", "Keys", "Contacts", "Tools", "Desktop", "Help"}

// menu is every entry.
func (u *UI) menu() []menuEntry {
	return []menuEntry{
		{"File", "New vault…", "N", u.newVault},
		{"File", "Add an existing vault…", "", u.addVault},
		{"File", "Import from a browser or another password manager…", "I", u.importFile},
		{"File", "Export to KeePass (KDBX) or CXF…", "X", u.exportFile},
		{"File", "Join a synced vault…", "", u.syncJoin},
		{"File", "Emergency access: accept an invite…", "", func() { u.acceptEmergency(nil) }},
		{"File", "Emergency access: ask for a vault you hold access to…", "", func() {
			u.askTo("Ask for emergency access", "The vault's name here:", "", "Ask for access", func(name string) { u.requestEmergency(name, nil) })
		}},
		{"File", "Emergency access: open a vault after the wait…", "", func() {
			u.askTo("Open with emergency access", "The vault's name here:", "", "Open the vault", func(name string) { u.openEmergency(name, nil) })
		}},
		{"File", "Quit", "q", u.quit},

		{"Edit", "New item…", "n", func() { u.newItem(nil) }},
		{"Edit", "Edit the item…", "e", u.editItem},
		{"Edit", "Rename the item…", "m", u.renameItem},
		{"Edit", "Delete the item…", "d", u.deleteItem},
		{"Edit", "History of the item: every revision, who signed it, restoring one", "h", u.showHistory},
		{"Edit", "Resolve a conflict: keep one version on every device…", "", u.showResolve},
		{"Edit", "Files of the item: attach, save, remove", "f", u.showFiles},
		{"Edit", "Deleted items: bring one back", "R", u.showDeleted},
		{"Edit", "Copy the secret", "c", u.copySecret},
		{"Edit", "Copy the username", "u", u.copyUsername},
		{"Edit", "Copy the one-time code", "o", u.copyCode},
		{"Edit", "Copy the item's reference (sv://…), or the selected field's", "y", u.copyReference},
		{"Edit", "Reveal or hide the item's secrets", "r", u.toggleReveal},
		{"Edit", "Filter the items", "/", u.startFilter},

		{"Vault", "Unlock", "U", u.unlockVault},
		{"Vault", "Unlock with a keyfile, identity, recovery key or security key…", "", u.unlockWith},
		{"Vault", "Lock", "l", func() { u.lockVault(false) }},
		{"Vault", "Lock every vault", "L", func() { u.lockVault(true) }},
		{"Vault", "Vaults: list, default, forget, open at login, check", "V", u.showVaults},
		{"Vault", "Make this vault the default", "", u.makeDefault},
		{"Vault", "Forget this vault…", "", u.forgetVault},
		{"Vault", "Open this vault when I log in (on or off)…", "", u.toggleLogin},
		{"Vault", "Check every file of this vault", "", u.verifyVault},
		{"Vault", "Keyslots: the ways this vault opens; adding, removing one", "K", u.showSlots},
		{"Vault", "Add a way to open this vault: passphrase, recovery key, keyfile, person's key, security key…", "", func() {
			if u.needVault() {
				u.addSlot(u.vault, nil)
			}
		}},
		{"Vault", "Change the passphrase…", "", func() {
			if u.needVault() {
				u.changePassphrase(u.vault)
			}
		}},
		{"Vault", "Give this vault a new key (rotate it)…", "", func() {
			if u.needVault() {
				u.rotateKey(u.vault, nil, nil)
			}
		}},
		{"Vault", "Devices: who signs what is written; naming, vouching, removing", "D", u.showDevices},
		{"Vault", "Count only signed revisions (on or off)…", "", func() {
			if u.needVault() {
				u.showDevices()
			}
		}},
		{"Vault", "Containers: encrypted disk images; open, close, back up, passphrase", "M", u.showContainers},
		{"Vault", "New encrypted container…", "", func() {
			if u.needVault() {
				u.newContainer(u.vault, nil)
			}
		}},
		{"Vault", "Open an encrypted container…", "", func() {
			if u.needVault() {
				u.openContainer(u.vault, "", "", nil)
			}
		}},
		{"Vault", "Close an encrypted container…", "", func() { u.closeContainerAsk(nil) }},
		{"Vault", "Grants: what programs may do; forgetting a decision", "G", u.showGrants},
		{"Vault", "Allow a program ahead of time…", "", func() {
			if u.needVault() {
				u.decideProgram(u.vault, true, nil)
			}
		}},
		{"Vault", "Deny a program ahead of time…", "", func() {
			if u.needVault() {
				u.decideProgram(u.vault, false, nil)
			}
		}},
		{"Vault", "Audit log", "A", u.showAudit},

		{"Keys", "Keys: OpenPGP, S/MIME, age identities", "P", u.showKeys},
		{"Keys", "New OpenPGP key…", "", func() {
			if u.needVault() {
				u.newPGPKey(u.vault, nil)
			}
		}},
		{"Keys", "Import an OpenPGP key…", "", func() {
			if u.needVault() {
				u.importPGPKey(u.vault, nil)
			}
		}},
		{"Keys", "Export an OpenPGP key, or copy its public key", "P", u.showKeys},
		{"Keys", "Import an S/MIME key (.p12)…", "", func() {
			if u.needVault() {
				u.importSMIME(u.vault, nil)
			}
		}},
		{"Keys", "New age identity…", "", func() {
			if u.needVault() {
				u.newAgeIdentity(u.vault, nil)
			}
		}},
		{"Keys", "Copy an age identity's public key or identity line", "P", u.showKeys},
		{"Keys", "New identity file…", "", u.newIdentityFile},
		{"Keys", "Show an identity file's public key…", "", u.identityFileRecipient},
		{"Keys", "Security keys plugged in, and what each can do", "K", u.showSlots},
		{"Vault", "Sharing and emergency access: who opens this vault", "E", u.showSharing},
		{"Vault", "Share this vault with a person, by their public key…", "", func() {
			if u.needVault() {
				u.shareWith(u.vault, nil)
			}
		}},
		{"Vault", "Cut someone off (gives the vault a new key)…", "E", u.showSharing},
		{"Vault", "Grant emergency access…", "", func() {
			if u.needVault() {
				u.grantEmergency(u.vault, nil)
			}
		}},
		{"Vault", "Emergency access given: deny a request, revoke a grant", "E", u.showSharing},
		{"Vault", "Sync: status, devices, now, stop", "S", u.showSync},
		{"Vault", "Sync this vault with a server…", "", func() {
			if u.needVault() {
				u.syncSetup(u.vault, nil)
			}
		}},
		{"Vault", "Invite a device to this synced vault…", "", func() {
			if u.needVault() {
				u.syncInvite(u.vault)
			}
		}},
		{"Contacts", "Contacts: people, their keys, how each was verified", "C", u.showContacts},
		{"Contacts", "Add a contact…", "", func() { u.addContact(nil) }},
		{"Contacts", "Import keys, or a QR code you scanned…", "", func() { u.importContacts(nil) }},
		{"Contacts", "Look up keys (WKD, keyservers, directories)…", "", func() { u.lookupContact(nil) }},
		{"Contacts", "Show my QR code…", "", u.showMyCard},
		{"Contacts", "Keep contacts in…", "", func() { u.chooseContactsVault(nil) }},
		{"Contacts", "Directories: add, remove", "", u.showDirectories},
		{"Contacts", "Check a signer…", "", u.checkSigner},
		{"Contacts", "Record a key seen in mail…", "", func() { u.keySeen(nil) }},
		{"Tools", "Password generator", "g", func() { u.showGenerator(nil) }},
		{"Tools", "Resolve a reference (sv://…)…", "", u.resolveReference},
		{"Tools", "Check an env file's references…", "", u.checkEnvFile},
		{"Tools", "Check a template's references, or fill it…", "", u.checkTemplate},
		{"Tools", "Sign a file (OpenPGP)…", "", u.signFile},
		{"Tools", "Decrypt a file (OpenPGP)…", "", u.decryptPGPFile},
		{"Tools", "Check a signature (OpenPGP)…", "", u.verifyPGPFile},
		{"Tools", "Encrypt a file (age)…", "", u.encryptAge},
		{"Tools", "Decrypt a file (age)…", "", u.decryptAge},
		{"Tools", "Inspect a message…", "", u.inspectMail},
		{"Tools", "Sign and encrypt a message…", "", u.composeMail},
		{"Desktop", "System keyring: who holds it; import, take over, give back", "Y", u.showKeyring},
		{"Desktop", "Import the system keyring's secrets…", "", func() { u.keyringImport(nil) }},
		{"Desktop", "Become the system keyring…", "", func() { u.keyringTakeover(nil) }},
		{"Desktop", "Give the system keyring back…", "", func() { u.keyringRestore(nil) }},
		{"Desktop", "Browsers: which host each starts, the extensions connected", "B", u.showBrowsers},
		{"Desktop", "Set the browsers up for the secretvault extension…", "", func() { u.browserInstall(svops.ExtensionHost, nil) }},
		{"Desktop", "Undo the browsers' setup for the secretvault extension…", "", func() { u.browserUninstall(&svops.ExtensionHost, nil) }},
		{"Desktop", "Write out the browser extension…", "", u.browserExtension},
		{"Desktop", "GnuPG: let gpg use the vault's keys, or stop…", "", func() {
			if u.needVault() {
				u.gpgSetup(u.vault)
			}
		}},
		{"Desktop", "Program helpers: git, docker, age", "", u.showHelpers},
		{"Desktop", "Open this vault when I log in (on or off)…", "", u.toggleLogin},
		{"Desktop", "Host daemon: its identity, policy and vaults (as root)", "H", u.showHost},
		{"Desktop", "Make the host identity…", "", func() { u.hostInit(nil) }},
		{"Desktop", "Allow a unit's credential…", "", func() { u.hostAllowUnit(nil) }},
		{"Desktop", "Allow a local service…", "", func() { u.hostAllowService(nil) }},
		{"Desktop", "Deny a local service's references…", "", func() { u.hostDenyRefs(nil) }},
		{"Desktop", "What the host delivered and refused", "", u.showHostAudit},
		{"Help", "Keyboard shortcuts and status", "?", u.showHelp},
		{"Help", "About secretvault: versions, the background service's status", "", u.showStatus},
	}
}

// showMenu opens the action menu.
func (u *UI) showMenu() {
	entries := u.menu()
	find := tview.NewInputField().SetLabel("Find: ").SetFieldWidth(0).SetPlaceholder("type part of an action's name")
	t := tview.NewTable().SetSelectable(true, false)
	var shown []menuEntry
	fill := func() {
		t.Clear()
		shown = shown[:0]
		words := strings.Fields(strings.ToLower(find.GetText()))
		row := 0
		for _, g := range menuGroups {
			first := true
			for _, e := range entries {
				if e.group != g {
					continue
				}
				hay := strings.ToLower(e.group + " " + e.label)
				ok := true
				for _, w := range words {
					if !strings.Contains(hay, w) {
						ok = false
					}
				}
				if !ok {
					continue
				}
				if first {
					t.SetCell(row, 0, tview.NewTableCell("[::b]"+g).SetTextColor(tview.Styles.TertiaryTextColor).SetSelectable(false))
					t.SetCell(row, 1, tview.NewTableCell("").SetSelectable(false))
					row++
					first = false
				}
				t.SetCell(row, 0, tview.NewTableCell("  "+tview.Escape(e.label)).SetReference(len(shown)).SetExpansion(1))
				key := ""
				if e.key != "" {
					key = tview.Escape(e.key)
				}
				t.SetCell(row, 1, tview.NewTableCell(key).SetTextColor(tcell.ColorYellow).SetAlign(tview.AlignRight))
				shown = append(shown, e)
				row++
			}
		}
		if len(shown) == 0 {
			t.SetCell(0, 0, tview.NewTableCell("Nothing matches.").SetTextColor(tcell.ColorGray).SetSelectable(false))
			return
		}
		for r := 0; r < t.GetRowCount(); r++ {
			if !t.GetCell(r, 0).NotSelectable {
				t.Select(r, 0)
				break
			}
		}
	}
	run := func() {
		row, _ := t.GetSelection()
		i, ok := t.GetCell(row, 0).GetReference().(int)
		if !ok || i >= len(shown) {
			return
		}
		e := shown[i]
		u.closePage(pageDialog)
		e.do()
	}
	step := func(dir int) {
		row, _ := t.GetSelection()
		for r := row + dir; r >= 0 && r < t.GetRowCount(); r += dir {
			if !t.GetCell(r, 0).NotSelectable {
				t.Select(r, 0)
				return
			}
		}
	}
	find.SetChangedFunc(func(string) { fill() })
	find.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Key() {
		case tcell.KeyEscape:
			u.closePage(pageDialog)
		case tcell.KeyEnter:
			run()
		case tcell.KeyDown, tcell.KeyTab:
			step(1)
		case tcell.KeyUp, tcell.KeyBacktab:
			step(-1)
		case tcell.KeyPgDn:
			for range 10 {
				step(1)
			}
		case tcell.KeyPgUp:
			for range 10 {
				step(-1)
			}
		default:
			return ev
		}
		return nil
	})
	fill()
	frame := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(find, 1, 0, true).
		AddItem(tview.NewBox(), 1, 0, false).
		AddItem(t, 0, 1, false)
	// The padding is the children's own: a Flex does not clear its own.
	find.SetBorderPadding(0, 0, 1, 1)
	t.SetBorderPadding(0, 0, 1, 1)
	frame.SetBorder(true).SetTitle(" Actions — type to find · ↑↓ choose · Enter does it · Esc closes ")
	_, _, _, h := u.pages.GetRect()
	u.openDialog(centred(frame, 84, max(10, min(h-2, 40))), find, nil)
}

// startFilter puts the cursor in the item filter.
func (u *UI) startFilter() {
	u.middle.ResizeItem(u.filter, 1, 0)
	u.app.SetFocus(u.filter)
}
