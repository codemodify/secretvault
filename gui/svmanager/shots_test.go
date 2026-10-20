package svmanager

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/app"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widgets"
)

// TestScreenshots draws the manager's windows to PNG files, for people to
// look at: SVGUI_SHOTS=DIR go test -run Screenshots ./svmanager. It is
// skipped otherwise; nothing is drawn anywhere but into those files.
func TestScreenshots(t *testing.T) {
	dir := os.Getenv("SVGUI_SHOTS")
	if dir == "" {
		t.Skip("SVGUI_SHOTS is not set")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	shoot := func(w *app.Window, name string) {
		t.Helper()
		w.App().PumpOnce()
		if err := w.WritePNG(filepath.Join(dir, name+".png")); err != nil {
			t.Fatal(err)
		}
	}
	for _, scheme := range []string{"dark", "light"} {
		// The look the program starts in, in a desktop of each mode.
		suffix := "-" + scheme
		t.Setenv("UITK_COLOR_SCHEME", scheme)
		t.Setenv("XDG_CONFIG_HOME", t.TempDir())
		a := uitoolkit.New(uitoolkit.Options{Headless: true, Scale: 1, DisableLookWatch: true})
		secretui.UseLook(a) // as the program does
		h := newHarness(t)
		h.start(Options{App: a})
		h.waitText("Vault personal is locked")
		h.idle()
		shoot(h.win(), "01-locked"+suffix)

		h.win().Press(platform.KeyU, platform.ModCtrl)
		d := h.asking()
		d.win.Type("not it")
		shoot(d.win, "02-prompt"+suffix)
		d.win.Press(platform.KeyReturn)
		h.waitFor("the second question", func() bool { return h.m.asking != nil && h.m.asking.id != d.id })
		d = h.asking()
		capsLock(d.win, true, h.pump) // the usual reason for a refusal
		shoot(d.win, "03-prompt-again"+suffix)
		capsLock(d.win, false, h.pump)
		d.win.Type(pass)
		d.win.Press(platform.KeyReturn)
		h.waitFor("the items", func() bool { return h.m.listed && len(h.m.entries) == 4 })
		h.idle()
		h.selectItem("web/github.com")
		shoot(h.win(), "04-selected"+suffix)

		h.open("web/github.com")
		shoot(h.win(), "05-open"+suffix)
		h.openCrumb("Logins")
		shoot(h.win(), "05-kinds"+suffix)
		h.closeDrop()
		h.openCrumb("personal")
		shoot(h.win(), "05-vaults"+suffix)
		h.closeDrop()
		h.win().Press(platform.KeyR, platform.ModCtrl)
		shoot(h.win(), "06-revealed"+suffix)

		h.open("2fa/example")
		shoot(h.win(), "07-otp"+suffix)

		h.win().FocusOn(h.m.ui.filter)
		h.win().Type("git")
		h.idle()
		shoot(h.win(), "08-search"+suffix)
		h.win().Press(platform.KeyEscape)

		h.selectItem("web/github.com")
		h.win().Press(platform.KeyE, platform.ModCtrl)
		h.waitFor("the editor", func() bool { return h.m.editor != nil })
		h.idle()
		shoot(h.win(), "09-editor"+suffix)
		h.win().Press(platform.KeyG, platform.ModCtrl)
		shoot(h.win(), "10-generator"+suffix)
		h.win().Press(platform.KeyEscape)
		h.win().Press(platform.KeyEscape)

		// Two remembered decisions, as a person might have made them.
		h.prove()
		for _, g := range []svrpc.GrantAddParams{
			{Program: "/usr/bin/git", Item: "web/github.com", Decision: "allow-always"},
			{Program: "/usr/bin/curl", Decision: "deny-always"},
		} {
			if _, err := h.admin.Grant(h.ctx(), g); err != nil {
				t.Logf("grant %s: %v", g.Program, err)
			}
		}
		h.win().Press(platform.KeyG, platform.ModCtrl|platform.ModShift)
		h.waitFor("the vault page", h.m.showingVaultPage)
		h.idle()
		shoot(h.win(), "11-grants"+suffix)
		h.m.showSettings(tabSetAppearance)
		h.idle()
		shoot(h.win(), "11-appearance"+suffix)
		h.m.showSection(secVaults)
		h.m.selectTab(h.m.vpage.tabbedPage, tabAudit)
		h.idle()
		shoot(h.win(), "12-audit"+suffix)
		h.win().Press(platform.KeyEscape)

		h.selectItem("web/github.com")
		h.win().Press(platform.KeyH, platform.ModCtrl)
		h.waitFor("the history", h.m.showingHistory)
		h.idle()
		shoot(h.win(), "13-history"+suffix)
		h.win().Press(platform.KeyEscape)

		h.m.newVault()
		shoot(h.win(), "14-new-vault"+suffix)
		d2 := h.overlay()
		name := find(d2, func(f *widgets.TextField) bool { return f.Placeholder == "personal, work…" })
		h.win().FocusOn(name)
		h.win().Type("work")
		for _, ph := range []string{"At least 8 characters", "The same again"} {
			h.win().FocusOn(find(d2, func(f *widgets.SecretField) bool { return f.Placeholder == ph }))
			h.win().Type("work passphrase 1")
		}
		h.win().Press(platform.KeyReturn)
		h.waitText("Recovery key for work")
		shoot(h.win(), "15-recovery-key"+suffix)
		h.click(h.win(), button(h.overlay(), "I have written it down"))
		h.idle()

		h.m.showVault("personal", false)
		h.idle()
		h.selectItem("web/gitlab.com")
		h.win().FocusOn(h.m.ui.content)
		h.win().Press(platform.KeyDelete)
		shoot(h.win(), "16-delete"+suffix)
		h.win().Press(platform.KeyEscape)

		h.win().Press(platform.KeyF1)
		shoot(h.win(), "17-keys"+suffix)
		h.win().Press(platform.KeyEscape)

		// The Tools and the Disks tabs.
		h.m.showTools(tabFiles)
		h.idle()
		shoot(h.win(), "17-tools"+suffix)
		h.m.showTools(tabBrowsers)
		h.idle()
		shoot(h.win(), "17-tools-browsers"+suffix)
		h.m.showDisks()
		h.waitFor("the disks", func() bool { return h.m.disks != nil && h.m.disks.ctable != nil })
		h.idle()
		shoot(h.win(), "17-disks"+suffix)
		h.m.showSection(secVaults)
		h.idle()

		// A new name refused where it was typed.
		h.selectItem("web/github.com")
		h.win().FocusOn(h.m.ui.content)
		h.win().Press(platform.KeyF2)
		h.win().Press(platform.KeyA, platform.ModCtrl)
		h.win().Type("web//github")
		h.win().Press(platform.KeyReturn)
		shoot(h.win(), "21-rename-refused"+suffix)
		h.win().Press(platform.KeyEscape)

		// A dialog over another, which is there as it was underneath.
		h.m.newVault()
		d3 := h.overlay()
		h.win().FocusOn(find(d3, func(f *widgets.TextField) bool { return f.Placeholder == "personal, work…" }))
		h.win().Type("travel")
		h.win().FocusOn(find(d3, func(f *widgets.SecretField) bool { return f.Placeholder == "At least 8 characters" }))
		h.win().Type("half a pass")
		capsLock(h.win(), true, h.pump)
		shoot(h.win(), "22-new-vault-caps"+suffix)
		capsLock(h.win(), false, h.pump)
		h.m.showKeys()
		shoot(h.win(), "23-stacked"+suffix)
		h.win().Press(platform.KeyEscape)
		h.win().Press(platform.KeyEscape)

		// A private key, in a secret area.
		h.prove()
		key := svrpc.Item{Kind: "ssh-key", Name: "ssh/laptop", Fields: []svrpc.Field{
			{Name: "private-key", Type: "key", Value: []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\nQyNTUxOQAAACDpX2e+eXAMPLEeXAMPLEeXAMPLEeXAMPLEeXAMPLEeXAMPLEAAAAJ\n-----END OPENSSH PRIVATE KEY-----\n")},
			{Name: "public-key", Type: "text", Value: []byte("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOlfZ75 ada@laptop")}}}
		if _, err := h.admin.Put(h.ctx(), "", key); err != nil {
			t.Fatal(err)
		}
		h.waitFor("ssh/laptop", func() bool { return h.m.entry("ssh/laptop") != nil })
		h.open("ssh/laptop")
		h.win().Press(platform.KeyE, platform.ModCtrl)
		h.waitFor("the editor", func() bool { return h.m.editor != nil })
		h.idle()
		shoot(h.win(), "24-key-editor"+suffix)
		h.win().Press(platform.KeyR, platform.ModCtrl)
		shoot(h.win(), "25-key-editor-shown"+suffix)
		h.win().Press(platform.KeyR, platform.ModCtrl)
		// The narrowest the window may be.
		narrowest, _ := h.win().MinSize()
		h.win().SetSize(int(narrowest), 700)
		h.pump()
		shoot(h.win(), "26-key-editor-narrow"+suffix)
		h.win().SetSize(1120, 700)
		h.pump()
		h.win().Press(platform.KeyEscape)

		// The key revealed in the item: its lines wrap to the values'
		// column, at the narrowest the window may be.
		h.open("ssh/laptop")
		h.win().Press(platform.KeyR, platform.ModCtrl)
		narrowest, _ = h.win().MinSize()
		h.win().SetSize(int(narrowest), 700)
		h.pump()
		shoot(h.win(), "27-key-wrapped-narrow"+suffix)
		h.win().SetSize(1120, 700)
		h.win().Press(platform.KeyR, platform.ModCtrl)
		h.pump()

		// A keyslot added in one step: the kind at the head, and only
		// what it takes under it.
		h.openVaultPage(tabKeyslots)
		h.pressOn("Add a way to unlock…")
		shoot(h.win(), "28-keyslot-passphrase"+suffix)
		h.choose("Opens with", 1)
		h.pump()
		shoot(h.win(), "29-keyslot-recovery"+suffix)
		h.choose("Opens with", 4)
		h.pump()
		shoot(h.win(), "30-keyslot-security-key"+suffix)
		h.win().Press(platform.KeyEscape)
		h.win().Press(platform.KeyEscape)

		// The import, in steps: where the passwords are now, then how to
		// export them from there and only what that export needs; then
		// the offer to delete an export that held them in the clear.
		h.m.importItems()
		h.pump()
		shoot(h.win(), "33-import-sources"+suffix)
		h.press("Next")
		shoot(h.win(), "34-import-firefox"+suffix)
		h.expand("More options")
		shoot(h.win(), "35-import-more-options"+suffix)
		h.press("Back")
		h.choose(importQuestion, sourceIndex(t, "keepass"))
		h.press("Next")
		shoot(h.win(), "36-import-keepass"+suffix)
		h.escape()
		h.m.offerDeleteExport(filepath.Join(h.dir, "logins.csv"), "personal")
		shoot(h.win(), "37-import-delete"+suffix)
		h.escape()

		// An invite and its QR code in one dialog; in a window too short
		// for both it scrolls, its button in view.
		invite := []byte("svsync1:" + strings.Repeat("Qm9vdHN0cmFwIGludml0ZSBmb3IgYSBkZXZpY2U", 4))
		d4 := h.m.showSecrets("Invite a device to personal", "On the new device: Vault › Join a synced vault…, and paste this invite, or scan it.",
			[]secretShown{{label: "Invite", value: invite}}, true, "Done")
		h.pump()
		shoot(h.win(), "31-invite-qr"+suffix)
		h.win().SetSize(1120, minWindowHeight)
		h.pump()
		shoot(h.win(), "32-invite-qr-short"+suffix)
		d4.Close()
		h.win().SetSize(1120, 700)
		h.pump()

		h.stopDaemon()
		h.waitText("Not connected")
		shoot(h.win(), "18-gone"+suffix)
	}

	// A conflict, and its history.
	h := newHarness(t)
	h.addConflicted()
	h.start(Options{Vault: "shared"})
	h.waitText("Vault shared is locked")
	h.unlockAgain()
	h.open("site")
	shoot(h.win(), "19-conflict-dark")
	h.win().Press(platform.KeyH, platform.ModCtrl)
	h.waitFor("the history", h.m.showingHistory)
	h.idle()
	for i, e := range h.m.hist.entries {
		if h.m.hist.heads[e.Rev] {
			h.m.hist.table.Selected = i
			h.m.openRevision(i)
		}
	}
	shoot(h.win(), "20-conflict-history-dark")
}
