package svtui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/codemodify/secretvault/svops"
)

// The main screen's tabs, as the desktop manager's (gui/svmanager):
// Vault (the vaults, their items and the open item), Disk (every
// encrypted disk of the unlocked vaults beside the one selected,
// containers.go) and Tools (every tool, by what it works on). 1, 2 and 3
// bring each forward, on the main screen and never while text is being
// typed; Esc on Disk or Tools goes back to Vault. The tabs are a line of
// their own at the top.

// The tabs, in the order of their keys.
const (
	tabVaults = iota
	tabDisks
	tabTools
)

// tabNames are the tabs' names, as the strip and u.tabs know them.
var tabNames = []string{"Vault", "Disk", "Tools"}

// The hints at the right of the status line, for the Vault tab and the
// others, and at the right of the tabs' names.
const (
	vaultsHints = "? help  / filter  q quit "
	otherHints  = "Esc Vault  ? help  q quit "
	tabsHint    = "1 2 3 switch tabs "
)

// drawStrip draws the tabs' names, the one shown highlighted, and notes
// where each is for the mouse.
func (u *UI) drawStrip() {
	var b strings.Builder
	b.WriteString(" ")
	x := 1
	u.stripAt = u.stripAt[:0]
	for i, name := range tabNames {
		if i > 0 {
			b.WriteString(" ")
			x++
		}
		if i == u.tab {
			b.WriteString("[::rb] " + name + " [::-]")
		} else {
			b.WriteString(" " + name + " ")
		}
		u.stripAt = append(u.stripAt, [2]int{x, x + len(name) + 2})
		x += len(name) + 2
	}
	u.strip.SetText(b.String())
}

// stripMouse brings forward the tab clicked. The line of the tabs never
// takes the focus.
func (u *UI) stripMouse(action tview.MouseAction, ev *tcell.EventMouse) (tview.MouseAction, *tcell.EventMouse) {
	x, y := ev.Position()
	if !u.top.InRect(x, y) {
		return action, ev
	}
	if action == tview.MouseLeftClick {
		if front, _ := u.pages.GetFrontPage(); front == pageMain {
			sx, _, _, _ := u.strip.GetInnerRect()
			for i, at := range u.stripAt {
				if x-sx >= at[0] && x-sx < at[1] {
					u.showTab(i)
				}
			}
		}
	}
	return tview.MouseConsumed, nil
}

// showTab brings tab i forward (the Disk tab asks for its disks again).
// Panels over the main screen go first, so that it is seen; a dialog, the
// editor, something shown once or the daemon's question stays, and the
// tab is there when they close.
func (u *UI) showTab(i int) {
	u.uncover()
	front, _ := u.pages.GetFrontPage()
	onMain := front == pageMain
	if i != u.tab && u.tab == tabVaults {
		if onMain {
			u.vaultFocus = u.app.GetFocus()
		} else {
			u.vaultFocus = u.resume[pageMain]
		}
	}
	u.tab = i
	u.tabs.SwitchToPage(tabNames[i])
	var focus tview.Primitive
	switch i {
	case tabDisks:
		focus = u.disks.t
		u.disks.refresh()
	case tabTools:
		focus = u.tools.t
	default:
		focus = u.itemList
		switch f := u.vaultFocus; {
		case f == u.filter && u.filter.GetText() != "", f == u.vaultList, f == u.detail:
			focus = f
		}
	}
	if onMain {
		u.app.SetFocus(focus)
	} else {
		u.resume[pageMain] = focus
	}
	u.drawStrip()
	hints := vaultsHints
	if i != tabVaults {
		hints = otherHints
	}
	u.hints.SetText("[gray]" + hints)
	u.bar.ResizeItem(u.hints, len(hints), 0)
}

// uncover takes down the panels over the main screen (and a revision over
// the history), when one of them is in front.
func (u *UI) uncover() {
	switch front, _ := u.pages.GetFrontPage(); front {
	case pagePanel, pageSub, pageRev:
	default:
		return
	}
	for _, name := range []string{pageSub, pagePanel} {
		if p := u.panels[name]; p != nil {
			p.close()
		} else {
			u.closePage(name)
		}
	}
	u.closePage(pageRev)
}

// tabKeys handles the keys of the Disk and Tools tabs: the tab's own
// first (its table runs them), then those that work on every tab. A key
// of the tab's own that does nothing to the row selected (U, on a disk
// whose vault is not locked) does what it does on every tab. The keys of
// the items are the Vault tab's alone.
func (u *UI) tabKeys(ev *tcell.EventKey) *tcell.EventKey {
	p := u.disks
	if u.tab == tabTools {
		p = u.tools
	}
	switch {
	case ev.Key() == tcell.KeyEscape:
		u.showTab(tabVaults)
		return nil
	case ev.Key() != tcell.KeyRune, ev.Modifiers()&(tcell.ModAlt|tcell.ModCtrl) != 0:
		return ev
	case p.applies(ev.Rune()):
		return ev
	case u.everyTabKey(ev.Rune()):
		return nil
	}
	// The tab's own, for a row it does not apply to: the table says so.
	return ev
}

// everyTabKey does what key does on any tab of the main screen, and says
// whether it did anything: the tabs, the help, the menu, quitting, and
// what opens a panel or a dialog of its own. The panels act on the vault
// chosen in the Vault tab.
func (u *UI) everyTabKey(key rune) bool {
	switch key {
	case '1', '2', '3':
		u.showTab(int(key - '1'))
	case '?':
		u.showHelp()
	case 'q':
		u.quit()
	case ':':
		u.showMenu()
	case 'g':
		u.showGenerator(nil)
	case 'l':
		u.lockVault(false)
	case 'L':
		u.lockVault(true)
	case 'U':
		u.unlockVault()
	case 'G':
		u.showGrants()
	case 'A':
		u.showAudit()
	case 'N':
		u.newVault()
	case 'V':
		u.showVaults()
	case 'R':
		u.showDeleted()
	case 'K':
		u.showSlots()
	case 'E':
		u.showSharing()
	case 'D':
		u.showDevices()
	case 'C':
		u.showContacts()
	case 'P':
		u.showKeys()
	case 'M':
		u.showDisks()
	case 'Y':
		u.showKeyring()
	case 'B':
		u.showBrowsers()
	case 'H':
		u.showHost()
	case 'S':
		u.showSync()
	case 'I':
		u.importFile()
	case 'X':
		u.exportFile()
	default:
		return false
	}
	return true
}

// tool is a row of the Tools tab.
type tool struct {
	label string
	about string // what it does, in one line
	key   string // its key on the main screen, if any
	do    func()
}

// toolGroup is a heading of the Tools tab, and its tools.
type toolGroup struct {
	name  string
	tools []tool
}

// toolGroups are the Tools tab's rows. Each does what its entry in the
// ':' menu does; the other programs' panels have the rest of what can be
// done to them (becoming the system keyring...).
func (u *UI) toolGroups() []toolGroup {
	return []toolGroup{
		{"Files and mail", []tool{
			{"Sign a file (OpenPGP)…", firstSentence(svops.SignFileAbout), "", u.signFile},
			{"Check a signature (OpenPGP)…", firstSentence(svops.CheckSignatureAbout), "", u.verifyPGPFile},
			{"Decrypt a file (OpenPGP)…", firstSentence(svops.DecryptPGPAbout), "", u.decryptPGPFile},
			{"Encrypt a file (age)…", firstSentence(svops.EncryptAgeAbout), "", u.encryptAge},
			{"Decrypt a file (age)…", firstSentence(svops.DecryptAgeAbout), "", u.decryptAge},
			{"Inspect a message…", firstSentence(svops.InspectMessageAbout), "", u.inspectMail},
			{"Sign and encrypt a message…", firstSentence(svops.ComposeMessageAbout), "", u.composeMail},
		}},
		{"References", []tool{
			{"Resolve a reference (sv://…)…", firstSentence(svops.ResolveReferenceAbout), "", u.resolveReference},
			{"Check an env file's references…", firstSentence(svops.CheckEnvFileAbout), "", u.checkEnvFile},
			{"Check a template's references, or fill it…", firstSentence(svops.CheckTemplateAbout), "", u.checkTemplate},
		}},
		{"Password generator", []tool{
			{"Password generator", firstSentence(svops.GeneratorAbout), "g", func() { u.showGenerator(nil) }},
		}},
		{"Identity files", []tool{
			{"New identity file…", firstSentence(svops.IdentityFileNote), "", u.newIdentityFile},
			{"Show an identity file's public key…", "Shows the public key in an identity file, to give to people who share vaults with you.", "", u.identityFileRecipient},
		}},
		{"Security keys", []tool{
			{"Security keys plugged in", "Lists the security keys plugged in, and what each can do.", "", u.showSecurityKeys},
		}},
		{"Other programs", []tool{
			{"Browsers", "Sets your browsers up for the secretvault extension, and shows the extensions connected.", "B", u.showBrowsers},
			{"System keyring", "Copies the system keyring's passwords into a vault, or takes its place so that apps ask you first.", "Y", u.showKeyring},
			{"GnuPG…", "Lets gpg sign and decrypt with the OpenPGP keys kept in the vault, or stops it.", "", func() {
				if u.needVault() {
					u.gpgSetup(u.vault)
				}
			}},
			{"Program helpers", "Lets git and docker keep their logins in a vault, and age and SOPS decrypt with its keys.", "", u.showHelpers},
			{"Host daemon", "The machine's own service, set up as root, that hands secrets to system services.", "H", u.showHost},
		}},
		{"secretvault itself", []tool{
			{"Where things are kept", "Every folder and file secretvault keeps, and what it changed in other programs, with what each holds.", "", u.showWhere},
		}},
	}
}

// firstSentence is s up to its first full stop, as the desktop manager's
// Tools tab says it.
func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}

// newToolsTab makes the Tools tab's panel: every tool under its heading,
// Enter running the one selected.
func (u *UI) newToolsTab() *panel {
	p := u.newPanel("Tools", "TOOL", "WHAT IT DOES")
	for _, g := range u.toolGroups() {
		p.heading(g.name)
		for _, t := range g.tools {
			label := tview.Escape(t.label)
			if t.key != "" {
				label += "  [yellow]" + tview.Escape(t.key) + "[-]"
			}
			p.row(t, tagged(label), t.about)
			p.t.GetCell(p.t.GetRowCount()-1, 1).SetMaxWidth(0) // as wide as the screen lets it be
		}
	}
	p.done()
	p.enter = func(ref any) { ref.(tool).do() }
	p.enterIs = "runs it"
	p.embed()
	return p
}
