package svd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svserver"
)

const week = 7 * 24 * time.Hour

// fakeClock is a clock that moves when the test says.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// emergencyWorld is a sync server in this process and two daemons: the
// owner's, whose vault "personal" syncs with the server and holds
// mail/imap, and Alice's, who is one of the owner's contacts (verified in
// person) and holds no vault of her own.
type emergencyWorld struct {
	t        *testing.T
	clock    *fakeClock // the daemons'; the server's, unless it lies
	server   *fakeClock // the server's
	owner    *harness
	trustee  *harness
	co, ct   *secretvault.Client
	identity string // Alice's identity file
}

// newEmergencyWorld sets the world up. A lying server keeps a clock of
// its own, which the test moves, and takes requests from any time.
func newEmergencyWorld(t *testing.T, lying bool) *emergencyWorld {
	t.Helper()
	w := &emergencyWorld{t: t, clock: &fakeClock{t: time.Now().UTC()}}
	w.server = w.clock
	cfg := svserver.Config{Root: t.TempDir(), AdminToken: adminToken, Rate: -1, Now: w.clock.now}
	if lying {
		w.server = &fakeClock{t: w.clock.now()}
		cfg.Now, cfg.ClockSkew = w.server.now, 30*24*time.Hour
	}
	s, err := svserver.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	hs := httptest.NewTLSServer(s)
	t.Cleanup(func() {
		s.Close()
		hs.Close()
	})
	withClock := func(o *Options) { o.Now = w.clock.now }
	w.owner, w.trustee = newHarness(t, withClock), newHarness(t, withClock)
	w.co = w.owner.setup()
	if _, err := w.co.SyncSetup(ctx(t), svrpc.SyncSetupParams{URL: hs.URL, Fingerprint: svserver.Fingerprint(hs.Certificate().Raw), AdminToken: adminToken, Label: "laptop"}); err != nil {
		t.Fatal(err)
	}
	id, _ := svcrypto.Modern.NewIdentity()
	priv, _ := id.Bytes()
	w.identity = "# Alice's identity\n" + svformat.EncodeIdentity(svcrypto.Modern, priv) + "\n"
	recipient := svformat.EncodeRecipient(svcrypto.Modern, id.Recipient())
	c, err := w.co.AddContact(ctx(t), svrpc.ContactAddParams{Name: "Alice", Keys: [][]byte{[]byte(recipient)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.co.VerifyContact(ctx(t), svrpc.ContactVerifyParams{Ref: "Alice", Fingerprint: c.Contact.Keys[0].Fingerprint, Method: "fingerprint"}); err != nil {
		t.Fatal(err)
	}
	w.ct = w.trustee.connect("/usr/bin/secretvault", &scripted{})
	return w
}

// grant gives Alice emergency access to the owner's vault.
func (w *emergencyWorld) grant(wait time.Duration) svrpc.EmergencyGrantResult {
	w.t.Helper()
	res, err := w.co.EmergencyGrant(ctx(w.t), svrpc.EmergencyGrantParams{Contact: "Alice", Wait: int64(wait / time.Second), Name: "Ada's vault"})
	if err != nil {
		w.t.Fatal(err)
	}
	return res
}

// accept has Alice accept the invite on her device, as name.
func (w *emergencyWorld) accept(invite, name string) svrpc.EmergencyAccess {
	w.t.Helper()
	a, err := w.ct.EmergencyAccept(ctx(w.t), svrpc.EmergencyAcceptParams{Invite: invite, Identity: []byte(w.identity), Name: name, Label: "alice-laptop"})
	if err != nil {
		w.t.Fatal(err)
	}
	return a
}

func (w *emergencyWorld) open(name string) (svrpc.VaultInfo, error) {
	return w.ct.EmergencyOpen(ctx(w.t), svrpc.EmergencyOpenParams{Name: name, Identity: []byte(w.identity)})
}

// ownerSees waits until the owner's daemon lists a notice about the grant
// in the given state, and returns it.
func (w *emergencyWorld) ownerSees(grant, state string) svrpc.EmergencyNotice {
	w.t.Helper()
	var found svrpc.EmergencyNotice
	eventually(w.t, "the owner told of "+state, func() error {
		st, err := w.co.Status(context.Background())
		if err != nil {
			return err
		}
		for _, n := range st.Emergency {
			if n.Grant == grant && n.State == state && !n.Held {
				found = n
				return nil
			}
		}
		return fmt.Errorf("status: %+v", st.Emergency)
	})
	return found
}

// audited reports whether the owner's audit log holds an entry of emergency
// access with this outcome.
func (w *emergencyWorld) audited(outcome string) bool {
	w.t.Helper()
	entries, err := w.co.Audit(ctx(w.t), "", 100)
	if err != nil {
		w.t.Fatal(err)
	}
	for _, e := range entries {
		if e.Program == "emergency access" && e.Outcome == outcome {
			return true
		}
	}
	return false
}

// listen connects a client that hears the daemon's emergency.changed
// notifications.
func (h *harness) listen() <-chan string {
	h.t.Helper()
	ch := make(chan string, 32)
	h.procs <- &svpeer.Process{PID: 4343, Exe: "/usr/bin/secretvault-gui", SystemOwned: true}
	c, err := secretvault.Connect(secretvault.Options{Socket: h.sock, NoStart: true, OnEvent: func(method string, ev svrpc.VaultEvent) {
		if method == svrpc.EEmergency {
			select {
			case ch <- ev.Vault:
			default:
			}
		}
	}})
	if err != nil {
		h.t.Fatal(err)
	}
	h.t.Cleanup(func() { c.Close() })
	return ch
}

func TestARequestForEmergencyAccessIsToldToTheOwnerWhoCanDenyIt(t *testing.T) {
	w := newEmergencyWorld(t, false)
	events := w.owner.listen()
	res := w.grant(week)
	g := res.Grant
	if res.Warning != "" || g.Trustee != "Alice" || g.Level != "in-person" || g.Wait != int64(week/time.Second) || g.State != svrpc.GrantInvited {
		t.Fatalf("granted: %+v", res)
	}
	if !strings.HasPrefix(res.Invite, "secretvault-emergency:?") {
		t.Fatalf("invite %q", res.Invite)
	}
	slots, _ := w.co.Slots(ctx(t), "")
	emergency := 0
	for _, s := range slots {
		if s.Type == svformat.SlotEmergency && strings.Contains(s.Detail, g.ID) && s.Label == "emergency" {
			emergency++
		}
	}
	if emergency != 1 {
		t.Fatalf("keyslots: %+v", slots)
	}

	// Only the identity the grant was made for accepts it.
	other, _ := svcrypto.Modern.NewIdentity()
	priv, _ := other.Bytes()
	if _, err := w.ct.EmergencyAccept(ctx(t), svrpc.EmergencyAcceptParams{Invite: res.Invite, Identity: []byte(svformat.EncodeIdentity(svcrypto.Modern, priv))}); err == nil || !strings.Contains(err.Error(), "not the one the grant was made for") {
		t.Fatalf("another identity accepted: %v", err)
	}
	a := w.accept(res.Invite, "ada")
	if a.State != svrpc.GrantAccepted || a.Owner != "Ada's vault" || a.Grant != g.ID {
		t.Fatalf("accepted: %+v", a)
	}
	list, err := w.co.EmergencyList(ctx(t), "")
	if err != nil || len(list.Given) != 1 || list.Given[0].Device != "alice-laptop" || len(list.Given[0].Problems) != 0 {
		t.Fatalf("the owner's list: %+v, %v", list, err)
	}

	// A request: the owner is told at once, on the desktop, in the audit
	// log, in the status and to clients; and it cannot be opened before
	// the wait is over.
	a, err = w.ct.EmergencyRequest(ctx(t), "ada")
	if err != nil || a.State != svrpc.GrantRequested || a.ReleasesAt == nil || !a.ReleasesAt.Equal(a.Requested.Add(week)) {
		t.Fatalf("request: %+v, %v", a, err)
	}
	n := w.ownerSees(g.ID, svrpc.GrantRequested)
	if n.Trustee != "Alice" || !strings.Contains(n.Text, "deny") || !strings.Contains(n.Text, "alice-laptop") {
		t.Fatalf("the notice: %+v", n)
	}
	eventually(t, "the desktop notice", func() error {
		for _, q := range w.owner.desk.told() {
			if q.Kind == svrpc.PromptNotice && strings.Contains(q.Title, "requested") && strings.Contains(q.Description, "Alice") {
				return nil
			}
		}
		return errors.New("none yet")
	})
	if !w.audited("requested") {
		t.Fatal("the request is not in the audit log")
	}
	select {
	case v := <-events:
		if v != "personal" {
			t.Fatalf("an event about %q", v)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("no emergency.changed event")
	}
	st, _ := w.ct.Status(ctx(t))
	if len(st.Emergency) != 1 || !st.Emergency[0].Held || !strings.Contains(st.Emergency[0].Text, "emergency open ada") {
		t.Fatalf("the trustee's status: %+v", st.Emergency)
	}
	if _, err := w.open("ada"); !errors.Is(err, svrpc.ErrDenied) || !strings.Contains(err.Error(), "wait ends") {
		t.Fatalf("opened before the wait: %v", err)
	}

	// Denied: nothing is released, even long after.
	d, err := w.co.EmergencyDeny(ctx(t), "", g.ID[:6])
	if err != nil || d.State != svrpc.GrantAccepted || d.Denied == nil {
		t.Fatalf("deny: %+v, %v", d, err)
	}
	w.clock.add(2 * week)
	if _, err := w.open("ada"); !errors.Is(err, svrpc.ErrDenied) || !strings.Contains(err.Error(), "denied") {
		t.Fatalf("opened after a denial: %v", err)
	}
	eventually(t, "the notice going", func() error {
		st, _ := w.co.Status(context.Background())
		if len(st.Emergency) != 0 {
			return fmt.Errorf("still %+v", st.Emergency)
		}
		return nil
	})
	if !w.audited("denied") {
		t.Fatal("the denial is not in the audit log")
	}
}

func TestAfterTheWaitTheTrusteeOpensTheVaultReadOnlyAndARotationKeepsTheGrant(t *testing.T) {
	w := newEmergencyWorld(t, false)
	res := w.grant(week)
	w.accept(res.Invite, "ada")
	if _, err := w.ct.EmergencyRequest(ctx(t), "ada"); err != nil {
		t.Fatal(err)
	}
	w.ownerSees(res.Grant.ID, svrpc.GrantRequested)
	w.clock.add(week + time.Minute)

	v, err := w.open("ada")
	if err != nil {
		t.Fatal(err)
	}
	if v.Name != "ada" || v.Locked {
		t.Fatalf("opened: %+v", v)
	}
	if s, err := getSecret(w.ct, "ada", "mail/imap"); err != nil || s != "hunter2" {
		t.Fatalf("read with emergency access: %q, %v", s, err)
	}
	if _, err := w.ct.Put(ctx(t), "ada", login("from/alice", "x")); err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("a write to someone else's vault: %v", err)
	}
	n := w.ownerSees(res.Grant.ID, svrpc.GrantReleased)
	if !strings.Contains(n.Text, "revoke") || !w.audited("released") {
		t.Fatalf("the release, told: %+v", n)
	}

	// The copy follows the owner's writes.
	if _, err := w.co.Put(ctx(t), "", login("web/bank", "after-release")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the owner's write reaching the trustee", func() error {
		s, err := getSecret(w.ct, "ada", "web/bank")
		if err == nil && s != "after-release" {
			err = errors.New(s)
		}
		return err
	})

	// After a restart the identity opens it again; nothing else does.
	w.trustee.restart()
	w.ct = w.trustee.connect("/usr/bin/secretvault", &scripted{})
	if _, err := w.ct.Unlock(ctx(t), "ada", nil); !errors.Is(err, svrpc.ErrLocked) || !strings.Contains(err.Error(), "--identity") {
		t.Fatalf("unlocking without the identity: %v", err)
	}
	if _, err := w.ct.Unlock(ctx(t), "ada", &svrpc.Key{Type: "identity", Secret: []byte(w.identity)}); err != nil {
		t.Fatal(err)
	}

	// A rotation (to cut someone else off) keeps the grant: the copy locks,
	// and the same identity opens the new key.
	rot, err := w.co.Rotate(ctx(t), svrpc.RotateParams{Passphrase: pass})
	if err != nil {
		t.Fatal(err)
	}
	carried := false
	for _, s := range rot.Slots {
		carried = carried || s.Type == svformat.SlotEmergency
	}
	if !carried || len(rot.Dropped) != 0 {
		t.Fatalf("rotated: %+v", rot)
	}
	if _, err := w.co.Put(ctx(t), "", login("web/after-rotation", "still-readable")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the copy locking", func() error {
		vs, _ := w.ct.Vaults(context.Background())
		for _, v := range vs {
			if v.Name == "ada" && !v.Locked {
				return errors.New("still unlocked")
			}
		}
		return nil
	})
	eventually(t, "the identity opening the new key", func() error {
		if _, err := w.ct.Unlock(context.Background(), "ada", &svrpc.Key{Type: "identity", Secret: []byte(w.identity)}); err != nil {
			return err
		}
		_, err := getSecret(w.ct, "ada", "web/after-rotation")
		return err
	})
}

func TestRevokingCutsTheTrusteeOff(t *testing.T) {
	w := newEmergencyWorld(t, false)

	// Before any request: she can no longer ask, and the vault keeps no
	// trace of the grant.
	res := w.grant(week)
	w.accept(res.Invite, "ada")
	if _, err := w.co.EmergencyRevoke(ctx(t), "", res.Grant.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := w.ct.EmergencyRequest(ctx(t), "ada"); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("a request after revoking: %v", err)
	}
	slots, _ := w.co.Slots(ctx(t), "")
	for _, s := range slots {
		if s.Type == svformat.SlotEmergency {
			t.Fatalf("a keyslot is left: %+v", s)
		}
	}
	if l, _ := w.co.EmergencyList(ctx(t), ""); len(l.Given) != 0 {
		t.Fatalf("grants left: %+v", l.Given)
	}

	// Once released, revoking and rotating: she keeps the copy she had,
	// and gets nothing written afterwards.
	res = w.grant(24 * time.Hour)
	w.accept(res.Invite, "ada2")
	w.ct.EmergencyRequest(ctx(t), "ada2")
	w.clock.add(25 * time.Hour)
	if _, err := w.open("ada2"); err != nil {
		t.Fatal(err)
	}
	g, err := w.co.EmergencyRevoke(ctx(t), "", res.Grant.ID)
	if err != nil || g.Released == nil {
		t.Fatalf("revoked: %+v, %v", g, err)
	}
	if _, err := w.co.Rotate(ctx(t), svrpc.RotateParams{Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.co.Put(ctx(t), "", login("web/after-revoking", "not for alice")); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the trustee's sync refused", func() error {
		_, err := w.ct.SyncNow(context.Background(), "ada2")
		if err == nil || !strings.Contains(err.Error(), "not enrolled") {
			return fmt.Errorf("a sync after revoking: %v", err)
		}
		return nil
	})
	if _, err := getSecret(w.ct, "ada2", "web/after-revoking"); err == nil {
		t.Fatal("the trustee read what was written after revoking")
	}
	if s, err := getSecret(w.ct, "ada2", "mail/imap"); err != nil || s != "hunter2" {
		t.Fatalf("what she had: %q, %v", s, err)
	}
}

// A server that lies (here about the time; one whose code ignores the
// wait does the same) releases the escrow early: the trustee gets the
// whole vault at once, long before the owner could have refused. This is
// the known limit of a wait the server keeps (docs/security.md). What
// the owner still has: the request and the release are told (by this
// server; one that hid them would leave nothing to see), and revoking and
// rotating keeps what is written afterwards from the trustee.
func TestALyingServerReleasesEarlyAndTheTrusteeGetsEverything(t *testing.T) {
	w := newEmergencyWorld(t, true)
	res := w.grant(week)
	w.accept(res.Invite, "ada")
	if _, err := w.ct.EmergencyRequest(ctx(t), "ada"); err != nil {
		t.Fatal(err)
	}
	// A minute later by everyone's clock, a week later by the server's.
	w.clock.add(time.Minute)
	w.server.add(week)
	if _, err := w.open("ada"); err != nil {
		t.Fatalf("the lying server's early release: %v", err)
	}
	if s, err := getSecret(w.ct, "ada", "mail/imap"); err != nil || s != "hunter2" {
		t.Fatalf("what the trustee got: %q, %v", s, err)
	}
	// Too late to deny.
	if _, err := w.co.EmergencyDeny(ctx(t), "", res.Grant.ID); err == nil || !strings.Contains(err.Error(), "revoke") {
		t.Fatalf("denying after the release: %v", err)
	}
	n := w.ownerSees(res.Grant.ID, svrpc.GrantReleased)
	if n.Released == nil || n.Released.Sub(w.clock.now()) < 6*24*time.Hour {
		t.Fatalf("the release, as told: %+v", n)
	}
}

// Emergency keyslots are the grant's business: they are not removed or
// left out of a rotation on their own, and a rotation makes the grant's
// keyslot again from the vault's record, so one planted beside it (by
// anyone who can write to the folder) is not carried over.
func TestAGrantsKeyslotIsMadeFromTheVaultsRecordAlone(t *testing.T) {
	w := newEmergencyWorld(t, false)
	res := w.grant(week)
	var slot svrpc.SlotInfo
	slots, _ := w.co.Slots(ctx(t), "")
	for _, s := range slots {
		if s.Type == svformat.SlotEmergency {
			slot = s
		}
	}
	if err := w.co.RemoveSlot(ctx(t), "", slot.ID); err == nil || !strings.Contains(err.Error(), "emergency revoke") {
		t.Fatalf("removing the grant's keyslot alone: %v", err)
	}
	if _, err := w.co.Rotate(ctx(t), svrpc.RotateParams{Passphrase: pass, Drop: []string{slot.ID}}); err == nil || !strings.Contains(err.Error(), "emergency revoke") {
		t.Fatalf("dropping the grant's keyslot from a rotation: %v", err)
	}

	// A keyslot planted for the grant, to someone else.
	vs, _ := w.co.Vaults(ctx(t))
	vid, _ := svformat.ParseID(vs[0].ID)
	stranger, _ := svcrypto.Modern.NewIdentity()
	grant, _ := svformat.ParseID(res.Grant.ID)
	planted := svformat.Slot{Format: svformat.SlotFormat, ID: svformat.NewID(), Vault: vid, Epoch: 1, Type: svformat.SlotEmergency,
		Label: "emergency", Created: time.Now().UTC(), Grants: []string{svformat.GrantContent}, Recipient: stranger.Recipient(),
		Emergency: &svformat.Emergency{Grant: grant}, Wrapped: []byte("planted")}
	b, _ := json.Marshal(planted)
	if err := os.WriteFile(filepath.Join(vs[0].Path, filepath.FromSlash(svformat.SlotName(planted.ID))), b, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.co.Rotate(ctx(t), svrpc.RotateParams{Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	slots, _ = w.co.Slots(ctx(t), "")
	var kept []svrpc.SlotInfo
	for _, s := range slots {
		if s.Type == svformat.SlotEmergency {
			kept = append(kept, s)
		}
	}
	if len(kept) != 1 || kept[0].Recipient != slot.Recipient {
		t.Fatalf("after the rotation: %+v (the grant's recipient is %s)", kept, slot.Recipient)
	}
}

// Who may get into your vaults is not for every program to learn.
func TestEmergencyNoticesAreForSecretvaultsOwnProgramsOnly(t *testing.T) {
	w := newEmergencyWorld(t, false)
	res := w.grant(week)
	w.accept(res.Invite, "ada")
	w.ct.EmergencyRequest(ctx(t), "ada")
	w.ownerSees(res.Grant.ID, svrpc.GrantRequested)
	app := w.owner.connect("/usr/bin/some-app", nil)
	st, err := app.Status(ctx(t))
	if err != nil || len(st.Emergency) != 0 {
		t.Fatalf("another program's status: %+v, %v", st.Emergency, err)
	}
	if _, err := app.EmergencyList(ctx(t), ""); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("another program's list: %v", err)
	}
	if _, err := w.co.EmergencyGrant(ctx(t), svrpc.EmergencyGrantParams{Contact: "Alice", Name: "ada\x1b[2J"}); err == nil {
		t.Fatal("an invite name that drives a terminal")
	}
}
