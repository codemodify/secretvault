package svtui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
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
var menuGroups = []string{"File", "Edit", "Vault", "Keys", "Sharing", "Contacts", "Tools", "Desktop", "Host", "Help"}

// menu is every entry.
func (u *UI) menu() []menuEntry {
	return []menuEntry{
		{"File", "New vault…", "N", u.newVault},
		{"File", "Add a vault folder…", "", u.addVault},
		{"File", "Import another password manager's export…", "I", u.importFile},
		{"File", "Export to KeePass (KDBX) or CXF…", "X", u.exportFile},
		{"File", "Join a synced vault…", "", u.syncJoin},
		{"File", "Emergency access: accept an invite…", "", func() { u.acceptEmergency(nil) }},
		{"File", "Emergency access: ask for a vault you hold access to…", "", func() {
			u.ask("Ask for emergency access", "Its name here:", "", func(name string) { u.requestEmergency(name, nil) })
		}},
		{"File", "Emergency access: open a vault after the wait…", "", func() {
			u.ask("Open with emergency access", "Its name here:", "", func(name string) { u.openEmergency(name, nil) })
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
		{"Edit", "Reveal or hide the item's secrets", "r", u.toggleReveal},
		{"Edit", "Filter the items", "/", u.startFilter},

		{"Vault", "Unlock", "U", u.unlockVault},
		{"Vault", "Unlock with a keyfile, identity, recovery key or security key…", "", u.unlockWith},
		{"Vault", "Lock", "l", func() { u.lockVault(false) }},
		{"Vault", "Lock every vault", "L", func() { u.lockVault(true) }},
		{"Vault", "Vaults: list, default, forget, open at login, verify", "V", u.showVaults},
		{"Vault", "Make this vault the default", "", u.makeDefault},
		{"Vault", "Forget this vault…", "", u.forgetVault},
		{"Vault", "Open this vault when I log in (on or off)…", "", u.toggleLogin},
		{"Vault", "Verify every file of this vault", "", u.verifyVault},
		{"Vault", "Keyslots: the ways this vault opens; adding, removing one", "K", u.showSlots},
		{"Vault", "Add a keyslot: passphrase, recovery key, keyfile, recipient, security key…", "", func() {
			if u.needVault() {
				u.addSlot(u.vault, nil)
			}
		}},
		{"Vault", "Change the passphrase…", "", func() {
			if u.needVault() {
				u.changePassphrase(u.vault)
			}
		}},
		{"Vault", "Rotate the vault key…", "", func() {
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
		{"Vault", "Grants: what programs may do", "G", u.showGrants},
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

		{"Keys", "Security keys plugged in, and what each can do", "K", u.showSlots},
		{"Sharing", "Sharing and emergency access: who opens this vault", "E", u.showSharing},
		{"Sharing", "Share this vault with a person's identity…", "", func() {
			if u.needVault() {
				u.shareWith(u.vault, nil)
			}
		}},
		{"Sharing", "Cut someone off (rotates the key)…", "E", u.showSharing},
		{"Sharing", "Grant emergency access…", "", func() {
			if u.needVault() {
				u.grantEmergency(u.vault, nil)
			}
		}},
		{"Sharing", "Emergency access given: deny a request, revoke a grant", "E", u.showSharing},
		{"Sharing", "Sync: status, devices, now, stop", "S", u.showSync},
		{"Sharing", "Sync this vault with a server…", "", func() {
			if u.needVault() {
				u.syncSetup(u.vault, nil)
			}
		}},
		{"Sharing", "Invite a device to this synced vault…", "", func() {
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
		{"Help", "Keys", "?", u.showHelp},
		{"Help", "About secretvault: versions, the daemon's status", "", u.showStatus},
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
	frame.SetBorder(true).SetBorderPadding(0, 0, 1, 1).SetTitle(" Actions — type to find · ↑↓ choose · Enter does it · Esc closes ")
	_, _, _, h := u.pages.GetRect()
	u.openPage(pageDialog, centred(frame, 84, max(10, min(h-2, 40))), find)
}

// startFilter puts the cursor in the item filter.
func (u *UI) startFilter() {
	u.middle.ResizeItem(u.filter, 1, 0)
	u.app.SetFocus(u.filter)
}
