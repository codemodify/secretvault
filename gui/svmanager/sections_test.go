package svmanager

import (
	"slices"
	"strings"
	"testing"

	"github.com/codemodify/uitoolkit/platform"

	"github.com/codemodify/secretvault/svops"
)

// The Vault tab's tabs show what each kind of thing in the vault is,
// however they were brought forward, and Escape goes back to the items.
func TestTheVaultTabsShowWhatIsPicked(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	tabs, sub := h.m.ui.vaultTabs, h.m.ui.vaultSub
	if h.m.section() != secVaults || tabs.Selected() != vtLogins || vaultTabTitles[0] != "Logins" {
		t.Fatalf("starts in tab %d, at %q", h.m.section(), vaultTabTitles[tabs.Selected()])
	}

	h.m.showVaultPage(tabSharing)
	h.idle()
	if tabs.Selected() != vtVault || sub.Selected() != tabSharing || h.m.vpage == nil || h.m.page != h.m.vpage.tabbedPage {
		t.Fatalf("Sharing: at %q, %d", vaultTabTitles[tabs.Selected()], sub.Selected())
	}
	sub.Select(tabDevices) // as a click does
	h.idle()
	if h.m.page.selected() != tabDevices {
		t.Fatalf("Devices picked shows %d", h.m.page.selected())
	}
	h.m.showKeysPage(tabSMIME)
	h.idle()
	if tabs.Selected() != vtMyKeys || h.m.kpage == nil || h.m.kpage.selected() != tabSMIME {
		t.Fatalf("the keys' page: at %q", vaultTabTitles[tabs.Selected()])
	}
	h.menu("&Vault", "Grants")
	if tabs.Selected() != vtVault || sub.Selected() != tabGrants || h.m.page.selected() != tabGrants {
		t.Fatalf("Vault › Grants: at %q, %d", vaultTabTitles[tabs.Selected()], sub.Selected())
	}
	h.escape()
	if h.m.showingVaultPage() || tabs.Selected() != vtLogins {
		t.Fatal("Escape left a page up")
	}
	h.open("web/github.com")
	if h.m.showingVaultPage() || h.m.cursor != "web/github.com" {
		t.Fatalf("the item: page up %v, cursor %q", h.m.showingVaultPage(), h.m.cursor)
	}
}

// Each kind of item has a tab of its own, which shows those alone, and
// makes new ones of that kind; the keys of My keys are in none of them,
// and every other item is in one. There is no All.
func TestEachKindHasATab(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.prove()
	if _, err := h.admin.GeneratePGP(h.ctx(), svrpcPGP("Ada", "ada@example.org")); err != nil {
		t.Fatal(err)
	}
	h.m.loadItems()
	h.idle()
	if slices.Contains(vaultTabTitles, "All") {
		t.Fatal("there is an All tab")
	}
	tabs := h.m.ui.vaultTabs
	seen := 0
	for _, e := range h.m.entries {
		if tab := tabOf(&e); tab >= 0 {
			seen++
		} else if !strings.Contains(e.Item.Name, "ada@example.org") {
			t.Errorf("%s is in no tab", e.Item.Name)
		}
	}
	if seen != 4 {
		t.Fatalf("%d items in the tabs of items, want 4", seen)
	}
	tabs.Select(vtLogins)
	h.idle()
	if got := h.listItems(); !slices.Equal(got, []string{"mail/fastmail", "web/github.com", "web/gitlab.com"}) {
		t.Fatalf("Logins shows %v", got)
	}
	tabs.Select(vtCodes)
	h.idle()
	if got := h.listItems(); !slices.Equal(got, []string{"2fa/example"}) {
		t.Fatalf("One-time codes shows %v", got)
	}
	if !strings.Contains(h.text(), "1 item in vault personal") {
		t.Fatalf("the pane beside the list does not say what the tab holds:\n%s", h.text())
	}
	tabs.Select(vtKeyItems)
	h.idle()
	if got := h.listItems(); len(got) != 0 {
		t.Fatalf("Keys shows %v, a key of My keys among them", got)
	}
	tabs.Select(vtCodes)
	h.idle()
	h.pressTool("New item")
	h.waitFor("the editor", func() bool { return h.m.editor != nil })
	if ed := h.m.editor; ed.kinds[ed.kind.Selected] != "otp" {
		t.Fatalf("a new item in One-time codes is a %s", ed.kinds[ed.kind.Selected])
	}
}

// What acts on an item waits while the Disk or the Tools tab is shown,
// so a shortcut there cannot copy a password nobody sees; Find brings the
// items back, and Ctrl+Page Down and Up step through the tabs.
func TestItemActionsWaitOutsideTheVaultTab(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.open("web/github.com")
	copyPassword := menuEntry(h, "Copy password")
	if copyPassword.Disabled {
		t.Fatal("Copy password is greyed out beside the item")
	}

	h.m.showTools(tabReferences)
	h.idle()
	if h.m.section() != secTools || !copyPassword.Disabled {
		t.Fatalf("in the Tools tab (%d), Copy password is enabled: %v", h.m.section(), !copyPassword.Disabled)
	}
	h.win().Press(platform.KeyPageUp, platform.ModCtrl)
	h.pump()
	if h.m.section() != secDisks {
		t.Fatalf("Ctrl+Page Up from Tools shows tab %d", h.m.section())
	}
	h.win().Press(platform.KeyPageDown, platform.ModCtrl)
	h.pump()
	if h.m.section() != secTools {
		t.Fatalf("Ctrl+Page Down from Disk shows tab %d", h.m.section())
	}
	h.win().Press(platform.KeyF, platform.ModCtrl)
	h.pump()
	if h.m.section() != secVaults || copyPassword.Disabled {
		t.Fatalf("Find shows tab %d; Copy password greyed out: %v", h.m.section(), copyPassword.Disabled)
	}
}

// Settings say where everything is kept, as the daemon keeps it.
func TestSettingsSayWhereThingsAreKept(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	h.m.showSettings(tabSetWhere)
	h.waitText("config.json")
	for _, want := range []string{"SETTINGS", "DATA", "WHILE RUNNING", "vaults"} {
		if !strings.Contains(h.text(), want) {
			t.Errorf("Where things are kept lacks %q:\n%s", want, h.text())
		}
	}
}

// An item opened from elsewhere than its tab (one just saved, one brought
// back) brings its kind's tab forward, where the list shows it.
func TestAnItemOpenedBringsItsTabForward(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	if h.m.itemTab != vtLogins {
		t.Fatalf("starts in %q", vaultTabTitles[h.m.itemTab])
	}
	h.m.openItem("2fa/example", false)
	h.waitFor("the code open", func() bool { return h.m.cur != nil && h.m.cur.Item.Name == "2fa/example" })
	h.idle()
	if h.m.itemTab != vtCodes || h.m.ui.vaultTabs.Selected() != vtCodes || h.m.ui.content.Selected != h.m.rowOf("2fa/example") {
		t.Fatalf("in tab %q, row %d", vaultTabTitles[h.m.itemTab], h.m.ui.content.Selected)
	}
}

// The rows under a vault are svops.KindRows, as the TUI's, then the pages.
func TestTheKindsAreTheTUIs(t *testing.T) {
	if lastItemTab+1 != len(svops.KindRows) || vaultTabTitles[vtDiskKeys] != "Disk keys" || vaultTabTitles[vtOther] != "Other" ||
		tabKinds[vtCodes] != "otp" || vaultTabTitles[vtVault] != svops.AboutVaultRow {
		t.Fatalf("the rows are %q", vaultTabTitles)
	}
}

// The rail down the left shows the window's parts, a bar beside the one
// shown, whichever way it was brought forward.
func TestTheRailShowsTheParts(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	r := h.m.ui.rail
	marked := func() (on []int) {
		for i, p := range r.parts {
			if p.on {
				on = append(on, i)
			}
		}
		return on
	}
	if got := marked(); !slices.Equal(got, []int{secVaults}) {
		t.Fatalf("the rail marks %v at the start", got)
	}
	h.pressTool("Disk")
	if h.m.section() != secDisks || !slices.Equal(marked(), []int{secDisks}) {
		t.Fatalf("Disk pressed: part %d, marked %v", h.m.section(), marked())
	}
	h.m.showSection(secTools) // as Ctrl+Page Down does
	if !slices.Equal(marked(), []int{secTools}) {
		t.Fatalf("Tools shown: marked %v", marked())
	}
	h.pressTool("Vault")
	if h.m.section() != secVaults {
		t.Fatalf("Vault pressed: part %d", h.m.section())
	}
}
