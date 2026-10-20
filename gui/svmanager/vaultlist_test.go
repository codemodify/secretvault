package svmanager

import (
	"slices"
	"testing"

	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// A vault's row unlocks it (asking for its passphrase) and locks it, with
// its icon buttons; Down and Enter in the list do what a click does.
func TestTheVaultListUnlocksAndLocksFromItsRows(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	h.pressTool("Unlock personal")
	d := h.asking()
	d.win.Type(pass)
	d.win.Press(platform.KeyReturn)
	h.waitFor("the items", func() bool { return h.m.listed && len(h.m.entries) == 4 })
	h.pressTool("Lock personal")
	h.waitFor("personal to lock", func() bool { v := h.m.vaultInfo("personal"); return v != nil && v.Locked })
	if r := h.m.ui.vaultList.Selected; r != h.vaultRow("personal") {
		t.Fatalf("row %d picked", r)
	}
}

// The vault's breadcrumbs say where the window is, and pick what it
// shows: the vault's opens every vault, the kind's every kind with its
// count, which follows the filter, then My keys, Contacts and About this
// vault, whose tabs a breadcrumb of their own picks.
func TestTheTitleBarPicksWhatTheVaultShows(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	if got := h.crumbTexts(); !slices.Equal(got, []string{"Vault", "personal"}) {
		t.Fatalf("a locked vault's breadcrumbs are %q: it shows nothing of what it holds", got)
	}
	if c, _ := h.crumb("Vault"); c == nil || c.Menu != nil || c.OnClick != nil {
		t.Fatal("the Vault breadcrumb opens something: the vault's own opens the vaults")
	}
	h.unlock()
	if got := h.crumbTexts(); !slices.Equal(got, []string{"Vault", "personal", "Logins"}) {
		t.Fatalf("the breadcrumbs are %q", got)
	}
	h.openCrumb("Logins")
	want := []string{"Logins 3", "Passwords 0", "Passkeys 0", "One-time codes 1", "Cards 0", "Personal details 0", "Notes 0",
		"SSH keys 0", "API keys 0", "Key/value 0", "Keys 0", "Disk keys 0", "Other 0", "My keys", "Contacts", "About this vault"}
	if got := h.dropRows(); !slices.Equal(got, want) {
		t.Fatalf("the kinds are %q", got)
	}
	h.pickDrop("One-time codes")
	if h.m.ui.vaultTabs.Selected() != vtCodes || !slices.Equal(h.listItems(), []string{"2fa/example"}) || h.dropUp() != nil {
		t.Fatalf("One-time codes picked: showing %q, %v", vaultTabTitles[h.m.ui.vaultTabs.Selected()], h.listItems())
	}
	if got := h.crumbTexts(); !slices.Equal(got, []string{"Vault", "personal", "One-time codes"}) {
		t.Fatalf("the breadcrumbs are %q", got)
	}
	// About this vault: its tabs are a breadcrumb of their own.
	h.openCrumb("One-time codes")
	h.pickDrop("About this vault")
	h.idle()
	if !h.m.showingVaultPage() || !slices.Equal(h.crumbTexts(), []string{"Vault", "personal", "About this vault", "Ways to unlock"}) {
		t.Fatalf("About this vault: %q", h.crumbTexts())
	}
	h.openCrumb("Ways to unlock")
	h.pickDrop("Grants")
	if h.m.ui.vaultSub.Selected() != tabGrants || h.crumbTexts()[3] != "Grants" {
		t.Fatalf("Grants picked: %d, %q", h.m.ui.vaultSub.Selected(), h.crumbTexts())
	}
	// The counts are of what the filter lets through.
	h.m.showVaultTab(vtLogins)
	h.m.ui.filter.SetText("git")
	h.openCrumb("Logins")
	if got := h.dropRows(); got[vtLogins] != "Logins 2" || got[vtCodes] != "One-time codes 0" {
		t.Fatalf("filtering git, the kinds say %q", got)
	}
	h.closeDrop()
	// The vault's opens the vaults, with their padlocks.
	h.openCrumb("personal")
	if h.toolButton("Lock personal") == nil || h.toolButton("New vault") == nil {
		t.Fatal("the vaults' drop-down has no padlock, or no New")
	}
}

// The vaults' drop-down is as wide and as tall as what it holds at the
// window's scale (measured before it had the window's look, it came out too small
// on a scaled screen: the names cut short, the last rows cut off); where
// the window is too short for it, End brings the last row into sight.
func TestADropDownHoldsAllOfItsRowsAtEveryScale(t *testing.T) {
	h := newHarness(t)
	h.start(Options{App: uitoolkit.New(uitoolkit.Options{Look: style.DarkLook(), Headless: true, Scale: 2, DisableLookWatch: true})})
	h.unlock()
	whole := func(what string, l *widgets.Label) {
		t.Helper()
		if need := l.Measure(layout.Unbounded()).X; l.Bounds().Dx() < need-0.5 {
			t.Errorf("%s %q is cut short: %.0f of %.0f", what, l.Text, l.Bounds().Dx(), need)
		}
	}
	inSight := func(what string, c widget.Component) {
		t.Helper()
		d, r := widget.DeviceBounds(h.dropUp()), widget.DeviceBounds(c)
		if r.Min.Y < d.Min.Y-0.5 || r.Max.Y > d.Max.Y+0.5 {
			t.Errorf("%s is out of the drop-down: %v in %v", what, r, d)
		}
	}
	h.openCrumb("personal")
	for _, r := range h.m.ui.vaultList.rows {
		whole("the vault", r.name)
		inSight("the vault "+r.name.Text, r)
	}
	inSight("New vault", h.toolButton("New vault"))
	h.closeDrop()
	// The kinds are the toolkit's menu, which sizes itself.
}

// The mark at the title bar's top left, over the rail, locks every vault.
func TestTheLogoLocksEveryVault(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.pressTool("Lock every vault")
	h.waitFor("personal to lock", func() bool { v := h.m.vaultInfo("personal"); return v != nil && v.Locked })
	h.said("Locked every vault.")
}
