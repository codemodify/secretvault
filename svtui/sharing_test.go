package svtui

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gdamore/tcell/v2"

	"github.com/codemodify/secretvault/svd"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svserver"
)

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

// syncServer is a sync server of the test's own.
func syncServer(t *testing.T, clock *testClock) (url, fingerprint string) {
	t.Helper()
	cfg := svserver.Config{Root: t.TempDir(), OpenRegistration: true, Rate: -1}
	if clock != nil {
		cfg.Now = clock.now
	}
	s, err := svserver.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewTLSServer(s)
	t.Cleanup(func() { s.Close(); srv.Close() })
	return srv.URL, svserver.Fingerprint(srv.Certificate().Raw)
}

// setupSync syncs the vault with the server, through the S panel.
func (h *harness) setupSync(url, fp string) {
	h.t.Helper()
	h.typeText("S")
	h.waitFor("Synced vaults")
	h.typeText("u")
	h.waitFor("Sync personal with a server")
	h.typeText(url)
	h.tabs(1)
	h.typeText(fp)
	h.tabs(2)
	h.typeText("laptop")
	h.tabs(1)
	h.key(tcell.KeyEnter)
	h.waitFor("Vault personal now syncs with " + url)
}

func TestSyncSetUpInviteAndJoin(t *testing.T) {
	url, fp := syncServer(t, nil)
	h := newHarness(t)
	h.start(Options{}, "")
	h.unlock()
	h.setupSync(url, fp)
	h.waitFor("Devices of personal")
	h.waitFor("laptop (this device)")

	h.typeText("n")
	h.waitFor("Synced personal: ok")

	h.typeText("i")
	h.waitFor("Invite a device to personal")
	h.waitFor("▀")
	invites := h.onceSecrets()
	if len(invites) != 1 || !strings.HasPrefix(invites[0], "secretvault-sync:") {
		t.Fatalf("invite %q", invites)
	}
	invite := invites[0]
	h.closeOnce()

	// Another device joins with it.
	other := newHarness(t)
	other.start(Options{}, "")
	other.waitFor("Locked: Enter unlocks")
	other.menu("join a synced")
	other.waitFor("Join a synced vault")
	other.typeText(invite)
	other.tabs(1)
	other.typeText("shared")
	other.tabs(3)
	other.key(tcell.KeyEnter)
	other.waitFor("Fetched vault shared")
	other.unlockAdmin("shared")
	if e, err := other.admin.Get(other.ctx(), "shared", "web/github.com"); err != nil || field(e, "password") != "hunter2-github" {
		t.Fatalf("the joined vault: %v", err)
	}

	// The first device sees it, and removes it again; then stops syncing.
	h.key(tcell.KeyEscape)
	h.typeText("S")
	h.waitFor("Devices of personal")
	h.eventually("two devices", func() bool {
		n := 0
		p := h.u.panels[pagePanel]
		if p == nil {
			return false
		}
		for r := 1; r < p.t.GetRowCount(); r++ {
			if _, ok := p.t.GetCell(r, 0).GetReference().(syncDeviceRef); ok {
				n++
			}
		}
		if n < 2 {
			p.refresh()
		}
		return n == 2
	})
	h.do(func() {
		p := h.u.panels[pagePanel]
		for r := 1; r < p.t.GetRowCount(); r++ {
			if d, ok := p.t.GetCell(r, 0).GetReference().(syncDeviceRef); ok && !d.This {
				p.t.Select(r, 0)
			}
		}
	})
	h.typeText("x")
	h.waitFor("syncing?")
	h.tabs(2) // Cancel, then Stop it syncing
	h.key(tcell.KeyEnter)
	h.waitFor("no longer syncs personal")
	h.typeText("o")
	h.waitFor("Stop syncing vault personal?")
	h.typeText("y")
	h.waitFor("personal no longer syncs")
	h.waitFor("None (u sets this one up)")
}

func TestSharingAndEmergencyAccess(t *testing.T) {
	clock := &testClock{t: time.Now().UTC()}
	url, fp := syncServer(t, clock)
	withClock := func(o *svd.Options) { o.Now = clock.now }
	owner := newHarness(t, withClock)
	trustee := newHarness(t, withClock)
	idFile := filepath.Join(trustee.dir, "alice.id")
	recipient, id, err := svops.NewIdentity("modern", "identity")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(idFile, id, 0o600); err != nil {
		t.Fatal(err)
	}

	owner.start(Options{}, "")
	owner.unlock()

	// Shared with her identity, then cut off: the key is rotated.
	owner.typeText("E")
	owner.waitFor("Sharing and emergency access · personal")
	owner.waitFor("Nobody (s shares)")
	owner.typeText("s")
	owner.waitFor("Share vault personal")
	owner.typeText(recipient)
	owner.tabs(1)
	owner.typeText("alice")
	owner.tabs(1)
	owner.key(tcell.KeyEnter)
	owner.waitFor("Shared vault personal with alice")
	owner.waitFor("alice")
	if _, err := owner.admin.Unlock(owner.ctx(), "", &svrpc.Key{Type: "identity", Secret: id}); err != nil {
		t.Fatalf("her identity does not open the vault: %v", err)
	}
	owner.do(func() {
		p := owner.u.panels[pagePanel]
		for r := 1; r < p.t.GetRowCount(); r++ {
			if _, ok := p.t.GetCell(r, 0).GetReference().(svrpc.SlotInfo); ok {
				p.t.Select(r, 0)
			}
		}
	})
	owner.typeText("c")
	owner.waitFor("vault personal a new key")
	owner.waitFor("except the one being cut off")
	owner.typeText(pass)
	owner.tabs(1)
	owner.typeText(pass)
	owner.tabs(2)
	owner.key(tcell.KeyEnter)
	owner.waitFor("Vault personal has a new key")
	if !strings.Contains(owner.onceText(), "The one cut off can no longer open it") {
		t.Fatalf("the rotation does not say she was cut off: %s", owner.onceText())
	}
	owner.key(tcell.KeyEscape) // nothing secret: closes at once
	owner.waitGone("Rotated personal")
	owner.lockAll()
	if _, err := owner.admin.Unlock(owner.ctx(), "", &svrpc.Key{Type: "identity", Secret: id}); err == nil {
		t.Fatal("her identity still opens the vault")
	}

	// Emergency access: the vault syncs; she is granted it.
	owner.key(tcell.KeyEscape)
	owner.waitFor("Locked: Enter unlocks")
	owner.unlock()
	owner.setupSync(url, fp)
	owner.key(tcell.KeyEscape)
	owner.typeText("E")
	owner.waitFor("Nobody (g grants it)")
	owner.typeText("g")
	owner.waitFor("Grant emergency access to personal")
	owner.typeText(recipient)
	owner.tabs(1)
	owner.ctrl(tcell.KeyCtrlU)
	owner.typeText("2d")
	owner.tabs(2)
	owner.typeText("ada")
	owner.tabs(1)
	owner.key(tcell.KeyEnter)
	owner.waitFor("within 2 days of their asking")
	owner.waitFor("not one of your contacts")
	invites := owner.onceSecrets()
	if len(invites) != 1 {
		t.Fatalf("invites %q", invites)
	}
	owner.closeOnce()
	owner.waitFor("not accepted yet")

	// She accepts, and asks.
	trustee.start(Options{}, "")
	trustee.unlock()
	trustee.menu("accept an invite")
	trustee.waitFor("Accept an emergency access invite")
	trustee.typeText(invites[0])
	trustee.tabs(1)
	trustee.typeText(idFile)
	trustee.tabs(3)
	trustee.key(tcell.KeyEnter)
	trustee.waitFor("Accepted, as ada")
	trustee.typeText("E")
	trustee.waitFor("Emergency access held")
	trustee.waitFor("accepted; r asks for it")
	selectRef[svrpc.EmergencyAccess](trustee)
	trustee.typeText("r")
	trustee.waitFor("Ask for emergency access to ada?")
	trustee.typeText("y")
	trustee.waitFor("Asked.")

	// The owner is told, and denies it.
	owner.eventually("the request showing", func() bool {
		p := owner.u.panels[pagePanel]
		if p == nil {
			return false
		}
		for r := 1; r < p.t.GetRowCount(); r++ {
			if g, ok := p.t.GetCell(r, 0).GetReference().(svrpc.EmergencyGrant); ok && g.State == svrpc.GrantRequested {
				p.t.Select(r, 0)
				return true
			}
		}
		p.refresh()
		return false
	})
	owner.waitFor("REQUESTED")
	owner.typeText("d")
	owner.waitFor("Denying it")
	owner.typeText("y")
	owner.waitFor("Denied")

	// She asks again; the wait passes; she opens it.
	trustee.do(func() { trustee.u.say("") })
	trustee.typeText("r")
	trustee.waitFor("Ask for emergency access to ada?")
	trustee.typeText("y")
	trustee.waitFor("Asked.")
	clock.add(49 * time.Hour)
	selectRef[svrpc.EmergencyAccess](trustee)
	trustee.typeText("o")
	trustee.waitFor("Open ada")
	trustee.typeText(idFile)
	trustee.tabs(2)
	trustee.key(tcell.KeyEnter)
	trustee.waitFor("Opened vault ada")
	if _, err := trustee.admin.Unlock(trustee.ctx(), "ada", &svrpc.Key{Type: "identity", Secret: id}); err != nil {
		t.Fatal(err)
	}
	if e, err := trustee.admin.Get(trustee.ctx(), "ada", "web/github.com"); err != nil || field(e, "password") != "hunter2-github" {
		t.Fatalf("the opened vault: %v", err)
	}

	// The owner revokes it, rotating the key.
	owner.eventually("the release showing", func() bool {
		p := owner.u.panels[pagePanel]
		if p == nil {
			return false
		}
		for r := 1; r < p.t.GetRowCount(); r++ {
			if g, ok := p.t.GetCell(r, 0).GetReference().(svrpc.EmergencyGrant); ok && g.State == svrpc.GrantReleased {
				p.t.Select(r, 0)
				return true
			}
		}
		p.refresh()
		return false
	})
	owner.typeText("v")
	owner.waitFor("Revoke emergency access")
	owner.tabs(1)
	owner.key(tcell.KeyEnter)
	owner.waitFor("Give vault personal a new key")
	owner.typeText(pass)
	owner.tabs(1)
	owner.typeText(pass)
	owner.tabs(2)
	owner.key(tcell.KeyEnter)
	owner.waitFor("Key epoch:")
}

// onceText is the once view's text, unwrapped.
func (h *harness) onceText() string {
	var b strings.Builder
	h.do(func() {
		if h.u.once != nil {
			for _, l := range h.u.once.lines {
				b.WriteString(strings.TrimSpace(l.text) + " ")
			}
		}
	})
	return b.String()
}

// selectRef selects the panel's first row whose reference is a T.
func selectRef[T any](h *harness) {
	h.t.Helper()
	h.eventually("a row to select", func() bool {
		p := h.u.panels[pagePanel]
		if p == nil {
			return false
		}
		for r := 1; r < p.t.GetRowCount(); r++ {
			if _, ok := p.t.GetCell(r, 0).GetReference().(T); ok {
				p.t.Select(r, 0)
				return true
			}
		}
		return false
	})
}
