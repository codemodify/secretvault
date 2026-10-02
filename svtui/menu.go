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
		{"File", "Quit", "q", u.quit},

		{"Edit", "New item…", "n", func() { u.newItem(nil) }},
		{"Edit", "Edit the item…", "e", u.editItem},
		{"Edit", "Rename the item…", "m", u.renameItem},
		{"Edit", "Delete the item…", "d", u.deleteItem},
		{"Edit", "History of the item (restore, resolve)", "h", u.showHistory},
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
		{"Vault", "Grants: what programs may do", "G", u.showGrants},
		{"Vault", "Audit log", "A", u.showAudit},

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
