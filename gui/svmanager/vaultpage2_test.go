package svmanager

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svserver"
)

func TestDevicesAreNamedAndSignaturesRequired(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	p := h.openVaultPage(tabDevices)
	if len(p.devices) != 1 || p.dtable.CellText(0, 4) != "this device" {
		t.Fatalf("devices: %+v", p.devices)
	}
	h.pressOn("Rename…")
	h.waitText("Rename the device")
	box := find(h.overlay(), func(*widgets.TextField) bool { return true })
	box.SetText("")
	h.win().FocusOn(box)
	h.win().Type("laptop")
	h.press("Rename")
	h.said(`is now "laptop"`)
	h.idle()
	if p.devices[0].Label != "laptop" {
		t.Fatalf("the tab shows %+v", p.devices[0])
	}

	h.prove()
	signed := find(h.area(), func(c *widgets.Checkbox) bool { return c.Text == "Count only signed changes" })
	h.win().ClickComponent(signed)
	h.said("counts only changes signed")
	if pol, err := h.admin.Signatures(h.ctx(), "", nil); err != nil || !pol.Require {
		t.Fatalf("the policy is %+v, %v", pol, err)
	}

	// The history says who signed each revision (svops.Author).
	h.escape()
	h.selectItem("web/github.com")
	h.m.showHistory()
	h.waitFor("the history", h.m.showingHistory)
	h.idle()
	if got := h.m.hist.table.CellText(0, 2); got == "" || got == "-" {
		t.Fatalf("the history's author column says %q", got)
	}
}

func TestTheVaultsSettings(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.openVaultPage(tabSettings)
	for _, want := range []string{"Folder", filepath.Join(h.dir, "home"), "after 15 idle minutes"} {
		if !strings.Contains(h.text(), want) {
			t.Errorf("the settings lack %q", want)
		}
	}
	login := find(h.area(), func(c *widgets.Checkbox) bool { return c.Text == "Open when I log in" })
	h.win().ClickComponent(login)
	h.waitText("Open vault personal when you log in?")
	h.press("Open it at login")
	h.said("opens when you log in")
	h.waitFor("the vault to open at login", func() bool { v := h.m.vaultInfo("personal"); return v != nil && v.LoginUnlock })

	h.pressOn("Check every file…")
	h.waitText("Vault personal is sound")
	if !strings.Contains(h.text(), "Every file of vault personal is as secretvault wrote it") {
		t.Fatalf("the report:\n%s", h.text())
	}
	h.press("Close")

	path := h.m.vaultInfo("personal").Path
	h.pressOn("Forget this vault…")
	h.press("Forget the vault")
	h.said("Forgot vault personal")
	h.waitFor("no vaults", func() bool { return len(h.m.vaults) == 0 })
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the folder went with it")
	}

	// Vault › Add an existing vault… brings it back.
	h.m.addVaultFolder()
	h.pump()
	h.fill("Its folder", path)
	h.fill("Name it", "again")
	h.press("Add the vault")
	h.said("Added vault again")
	h.waitFor("the vault back", func() bool { return h.m.vaultInfo("again") != nil })
}

func TestANewVaultInAFolderOfItsOwn(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	dir := filepath.Join(h.dir, "synced", "work")
	h.m.newVault()
	h.pump()
	h.fill("Name", "work")
	h.fill("Passphrase", "work passphrase 1")
	h.fill("Repeat", "work passphrase 1")
	h.fill("Folder", dir)
	h.tick("Make a recovery key", false)
	h.press("Create the vault")
	h.said("Created vault work.")
	h.waitFor("work", func() bool { v := h.m.vaultInfo("work"); return v != nil && v.Path == dir })
}

func TestAboutSaysWhatTheDaemonSays(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	h.m.showAbout()
	if h.m.section() != secSettings || h.m.spage.selected() != tabSetAbout {
		t.Fatalf("About is not shown in Settings: part %d", h.m.section())
	}
	h.waitText("secretvault-gui 0.")
	for _, want := range []string{"secretvault-gui 0.", "process", filepath.Join(h.dir, "home"), "personal", "locked"} {
		if !strings.Contains(h.text(), want) {
			t.Errorf("About lacks %q:\n%s", want, h.text())
		}
	}
}

// syncServer is a sync server in this process.
func syncServer(t *testing.T, now func() time.Time) (*httptest.Server, string) {
	s, err := svserver.New(svserver.Config{Root: t.TempDir(), AdminToken: "let-me-in", Rate: -1, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(s)
	t.Cleanup(func() { s.Close(); srv.Close() })
	return srv, svserver.Fingerprint(srv.Certificate().Raw)
}

func TestSyncIsSetUpAndADeviceJoins(t *testing.T) {
	srv, fp := syncServer(t, nil)
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.openVaultPage(tabSync)
	h.pressOn("Set up syncing…")
	h.fill("Server", srv.URL)
	h.fill("Fingerprint", fp)
	h.fill("Admin token", "let-me-in")
	h.fill("This device", "laptop")
	h.press("Start syncing")
	h.said("now syncs with " + srv.URL)
	h.waitText("Last good sync")
	h.waitFor("this device in the list", func() bool { return h.m.vpage.sdtable != nil && h.m.vpage.sdtable.RowCount == 1 })
	h.pressOn("Sync now")
	h.said("Synced personal")

	h.pressOn("Invite a device…")
	h.waitText("Invite a device to personal")
	shown := h.secrets()
	if len(shown) != 1 {
		t.Fatal("the invite is not shown")
	}
	invite := string(shown[0].value)
	held := shown[0].value
	// Its QR code is under it, in the same dialog.
	code := find(h.overlay(), func(*qrView) bool { return true })
	if code == nil || code.code == nil {
		t.Fatal("no QR code under the invite")
	}
	h.press("Done")
	if !allZero(held) || code.code != nil {
		t.Fatal("the invite, or its QR code, outlived its dialog")
	}

	// Another device joins with it.
	other := newHarness(t)
	other.start(Options{})
	other.waitText("Vault personal is locked")
	other.m.joinSynced()
	other.pump()
	other.fill("Invite", invite)
	other.fill("Name here", "shared")
	other.fill("This device", "desktop")
	other.press("Join")
	other.said("Fetched vault shared")
	other.waitFor("the joined vault", func() bool { return other.m.vaultInfo("shared") != nil })

	// The first sees it, and stops syncing.
	h.m.vpage.panes[tabSync].refresh()
	h.waitFor("two devices", func() bool { return h.m.vpage.sdtable != nil && h.m.vpage.sdtable.RowCount == 2 })
	h.pressOn("Stop syncing…")
	h.press("Stop syncing")
	h.said("no longer syncs")
	h.waitText("This vault is only on this device.")
}

func TestSharingWithAnIdentityAndCuttingItOff(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	rcpt, id, err := svops.NewIdentity("modern", "identity")
	if err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(h.dir, "bob.id")
	if err := svops.WriteNew(idFile, id); err != nil {
		t.Fatal(err)
	}
	p := h.openVaultPage(tabSharing)
	h.pressOn("Share with…")
	h.waitText("Share vault personal")
	h.choose("With", 0)
	h.fill("Their public key", idFile)
	h.fill("Name", "bob")
	h.press("Share the vault")
	h.said("Shared vault personal with bob")
	h.idle()
	if len(p.shared) != 1 || p.shared[0].Recipient != rcpt {
		t.Fatalf("shared with %+v", p.shared)
	}
	// The identity opens it.
	h.admin.Lock(h.ctx(), "", false)
	if _, err := h.admin.Unlock(h.ctx(), "", &svrpc.Key{Type: "identity", Secret: id}); err != nil {
		t.Fatalf("bob's identity does not open it: %v", err)
	}

	h.waitFor("the page closing on the lock", func() bool { return !h.m.showingVaultPage() })
	h.m.showVaultPage(tabSharing)
	h.until("bob", pass, func() bool { return h.m.vpage != nil && len(h.m.vpage.shared) == 1 && h.m.busy == 0 })
	h.pressOn("Cut off…")
	h.until("the rotation's form", pass, func() bool { return strings.Contains(h.text(), "bob can no longer open vault personal") })
	h.fill("Passphrase", pass)
	h.fill("Repeat", pass)
	h.press(svops.RotateAction(true))
	h.until("the rotation", pass, func() bool { return strings.Contains(h.text(), "The vault has a new key") })
	h.press("Close")
	h.admin.Lock(h.ctx(), "", false)
	if _, err := h.admin.Unlock(h.ctx(), "", &svrpc.Key{Type: "identity", Secret: id}); err == nil {
		t.Fatal("bob's identity still opens it")
	}
}

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *testClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// Emergency access, both sides in the GUI: the owner grants it, the
// trustee accepts and asks, the owner is told and denies; the trustee asks
// again and opens the vault after the wait; the owner revokes it.
func TestEmergencyAccessBothSides(t *testing.T) {
	clock := &testClock{t: time.Now().UTC()}
	srv, fp := syncServer(t, clock.now)
	withClock := func(o *svd.Options) { o.Now = clock.now }
	owner := newHarness(t, withClock)
	owner.prove()
	if _, err := owner.admin.SyncSetup(owner.ctx(), svrpc.SyncSetupParams{URL: srv.URL, AdminToken: "let-me-in", Fingerprint: fp}); err != nil {
		t.Fatal(err)
	}
	owner.admin.Lock(owner.ctx(), "", true)
	trustee := newHarness(t, withClock)
	rcpt, id, err := svops.NewIdentity("modern", "identity")
	if err != nil {
		t.Fatal(err)
	}
	idFile := filepath.Join(trustee.dir, "alice.id")
	if err := svops.WriteNew(idFile, id); err != nil {
		t.Fatal(err)
	}

	owner.start(Options{})
	owner.unlock()
	owner.openVaultPage(tabSharing)
	owner.pressOn("Grant…")
	owner.waitText("Give emergency access to personal")
	owner.choose("Who", 0)
	owner.fill("Their public key", rcpt)
	owner.fill("Wait", "2 days")
	owner.press("Give access")
	if !strings.Contains(owner.problem(), "is not a wait") {
		t.Fatalf("a wrong wait: %q", owner.problem())
	}
	owner.fill("Wait", "2d")
	owner.fill("Name they see", "ada")
	owner.press("Give access")
	owner.waitText("Emergency access invite")
	invite := string(owner.secrets()[0].value)
	if !strings.Contains(owner.text(), "2 days") {
		t.Fatalf("the wait is not said:\n%s", owner.text())
	}
	owner.press("Done")
	owner.idle()
	if len(owner.m.vpage.emergency.Given) != 1 {
		t.Fatal("the grant is not listed")
	}

	trustee.start(Options{})
	trustee.waitText("Vault personal is locked")
	trustee.m.acceptEmergency()
	trustee.pump()
	trustee.fill("Invite", invite)
	trustee.fill("Identity file", idFile)
	trustee.press("Accept the invite")
	trustee.waitText(`Accepted, as "ada"`)
	trustee.press("Close")
	trustee.m.requestEmergency()
	trustee.waitText("Ask for emergency access")
	trustee.press("Ask for access")
	trustee.said("Asked.")

	// The owner is told, in a note that stays while the request does.
	owner.waitFor("the request in a note", func() bool {
		owner.m.loadEmergency()
		owner.idle()
		return strings.Contains(owner.m.ui.notes.stay, "asked for emergency access to personal")
	})
	owner.m.vpage.panes[tabSharing].refresh()
	owner.idle()
	owner.pressOn("Deny…")
	owner.press("Deny the request")
	owner.said("Denied")

	trustee.m.requestEmergency()
	trustee.waitText("Ask for emergency access")
	trustee.m.ui.message = "" // the first request's
	trustee.press("Ask for access")
	trustee.said("Asked.")
	trustee.waitFor("the request's dialog to go", func() bool { return trustee.m.topDialog() == nil })
	clock.add(49 * time.Hour)
	trustee.m.openEmergency()
	trustee.waitText("Open a vault by emergency access")
	trustee.fill("Identity file", idFile)
	trustee.press("Open the vault")
	trustee.said("Opened vault ada")
	trustee.waitFor("the vault ada", func() bool { return trustee.m.vaultInfo("ada") != nil })

	owner.m.vpage.panes[tabSharing].refresh()
	owner.idle()
	owner.pressOn("Revoke…")
	owner.waitText("'s emergency access")
	owner.tick("Also give the vault a new key", false)
	owner.press("Revoke access")
	owner.said("Revoked")
	owner.idle()
	if len(owner.m.vpage.emergency.Given) != 0 {
		t.Fatal("the grant is still listed")
	}
}

func TestGrantsAreDecidedAheadOfTime(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	p := h.openVaultPage(tabGrants)
	h.pressOn("Allow a program…")
	h.fill("Program", "/usr/bin/git")
	h.choose("Applies to", 1)
	h.fill("Item", "web/github.com")
	h.tick("list", true)
	h.tick("Only until the vault next locks", true)
	h.press("Allow the program")
	h.said("git (/usr/bin/git) may read and list item web/github.com until the vault locks.")
	h.pressOn("Deny a program…")
	h.fill("Program", "flatpak:org.example.Spy")
	h.press("Deny the program")
	h.said("may never read the whole vault.")
	h.idle()
	if len(p.grants) != 2 {
		t.Fatalf("grants: %+v", p.grants)
	}
}
