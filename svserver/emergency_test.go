package svserver

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
)

const week = 7 * 24 * time.Hour

// grantee is the person a grant is for: their identity, and the release
// key and accepting key's seed the owner's device sealed to it.
type grantee struct {
	id      *svcrypto.Identity
	vault   svformat.ID
	grant   svformat.ID
	release []byte
	seed    []byte
}

// newGrant seals a release key and an accepting key's seed to a new
// trustee identity, as the owner's device does, and returns the body that
// makes the grant.
func newGrant(t *testing.T, vault svformat.ID, wait time.Duration) (grantee, []byte) {
	t.Helper()
	id, err := svcrypto.Modern.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	g := grantee{id: id, vault: vault, grant: svformat.NewID(), release: make([]byte, 32), seed: make([]byte, ed25519.SeedSize)}
	rand.Read(g.release)
	rand.Read(g.seed)
	escrow, _ := svcrypto.Modern.SealTo(id.Recipient(), g.release, svformat.EmergencyReleaseInfo(vault, g.grant))
	challenge, _ := svcrypto.Modern.SealTo(id.Recipient(), g.seed, svformat.EmergencyChallengeInfo(vault, g.grant))
	pub := ed25519.NewKeyFromSeed(g.seed).Public().(ed25519.PublicKey)
	body, _ := json.Marshal(EmergencyCreate{ID: g.grant.String(), Wait: int64(wait / time.Second), Escrow: escrow, Challenge: challenge, AcceptKey: pub})
	return g, body
}

// proof is what a device signs to accept the grant on vault name.
func (g grantee) proof(name string, d device) []byte {
	return ed25519.Sign(ed25519.NewKeyFromSeed(g.seed), EmergencyAcceptMessage(name, g.grant.String(), d.id()))
}

func (f *fixture) grant(d device, path string) EmergencyGrant {
	f.t.Helper()
	var g EmergencyGrant
	f.expect(f.send(d, "GET", path, nil), http.StatusOK).json(f.t, &g)
	return g
}

// accept has the trustee's device open the challenge with the identity
// and sign that it accepts, on vault "v".
func (f *fixture) accept(d device, path string, g grantee) response {
	f.t.Helper()
	var ch EmergencyChallenge
	f.expect(f.send(d, "GET", path+"/challenge", nil), http.StatusOK).json(f.t, &ch)
	seed, err := g.id.Open(ch.Challenge, svformat.EmergencyChallengeInfo(g.vault, g.grant))
	if err != nil || !bytes.Equal(seed, g.seed) {
		f.t.Fatalf("the challenge: %v", err)
	}
	body, _ := json.Marshal(EmergencyAccept{Proof: g.proof("v", d), Label: "alice-laptop"})
	return f.send(d, "POST", path+"/trustee", body)
}

func TestAnEmergencyGrantIsReleasedOnlyAfterItsWaitAndNotIfDenied(t *testing.T) {
	f := newFixture(t, Config{})
	owner, other, trustee, stranger := newDevice(), newDevice(), newDevice(), newDevice()
	f.newVault("v", owner)
	f.expect(f.join(other, "v", f.enrol(owner, "v").Code), http.StatusCreated)
	slot := slotName()
	f.expect(f.put(owner, "v", slot, []byte(`{}`)), http.StatusCreated)
	vaultID := svformat.NewID()
	g, body := newGrant(t, vaultID, week)
	path := "/v1/vaults/v/emergency/" + g.grant.String()

	f.expect(f.send(stranger, "POST", "/v1/vaults/v/emergency", body), http.StatusForbidden)
	var made EmergencyGrant
	f.expect(f.send(owner, "POST", "/v1/vaults/v/emergency", body), http.StatusCreated).json(t, &made)
	f.expect(f.send(owner, "POST", "/v1/vaults/v/emergency", body), http.StatusOK) // a retry
	if made.State != GrantInvited || made.Wait != int64(week/time.Second) || made.CreatedBy != owner.id() {
		t.Fatalf("made %+v", made)
	}
	// Every device of the vault hears of it through the change log.
	cs := f.changes(other, "v", 0, "")
	if last := cs.Changes[len(cs.Changes)-1]; last.Op != OpEvent || last.Name != EmergencyEvent+g.grant.String() {
		t.Fatalf("no event for the grant: %+v", cs.Changes)
	}

	// Accepting takes the identity, and what it signs is good for its own
	// device alone: a trustee tricked into accepting through a stranger's
	// server hands the stranger a proof that is no use to them.
	bad, _ := json.Marshal(EmergencyAccept{Proof: make([]byte, ed25519.SignatureSize)})
	f.expect(f.send(trustee, "POST", path+"/trustee", bad), http.StatusForbidden)
	relayed, _ := json.Marshal(EmergencyAccept{Proof: g.proof("v", trustee)})
	f.expect(f.send(stranger, "POST", path+"/trustee", relayed), http.StatusForbidden)
	otherVault, _ := json.Marshal(EmergencyAccept{Proof: g.proof("w", trustee)})
	f.expect(f.send(trustee, "POST", path+"/trustee", otherVault), http.StatusForbidden)
	f.expect(f.send(trustee, "POST", path+"/request", nil), http.StatusForbidden)
	f.expect(f.accept(trustee, path, g), http.StatusCreated)
	f.expect(f.send(trustee, "POST", path+"/trustee", relayed), http.StatusOK) // a retry
	late, _ := json.Marshal(EmergencyAccept{Proof: g.proof("v", stranger)})
	f.expect(f.send(stranger, "POST", path+"/trustee", late), http.StatusConflict)
	f.expect(f.send(stranger, "GET", path+"/challenge", nil), http.StatusConflict)
	if st := f.grant(other, path); st.State != GrantAccepted || st.Trustee == nil || st.Trustee.Key != trustee.id() || st.Trustee.Label != "alice-laptop" {
		t.Fatalf("after accepting: %+v", st)
	}

	// Before a release, the trustee sees its grant and nothing else.
	f.expect(f.send(trustee, "GET", "/v1/vaults/v/files/"+slot, nil), http.StatusForbidden)
	f.expect(f.send(trustee, "GET", "/v1/vaults/v/changes", nil), http.StatusForbidden)
	f.expect(f.send(trustee, "GET", "/v1/vaults/v/emergency", nil), http.StatusForbidden)
	f.expect(f.send(trustee, "POST", path+"/deny", nil), http.StatusForbidden)
	f.expect(f.send(stranger, "GET", path, nil), http.StatusForbidden)
	if st := f.grant(trustee, path); st.CreatedBy != "" || st.State != GrantAccepted {
		t.Fatalf("the trustee's view names the owner's device: %+v", st)
	}

	// A request starts the wait; asking again does not start it over.
	f.expect(f.send(trustee, "POST", path+"/release", nil), http.StatusConflict)
	var req EmergencyGrant
	f.expect(f.send(trustee, "POST", path+"/request", nil), http.StatusOK).json(t, &req)
	if req.State != GrantRequested || req.ReleasesAt == nil || !req.ReleasesAt.Equal(req.Requested.Add(week)) {
		t.Fatalf("requested %+v", req)
	}
	f.clock.add(time.Hour)
	var again EmergencyGrant
	f.expect(f.send(trustee, "POST", path+"/request", nil), http.StatusOK).json(t, &again)
	if !again.Requested.Equal(*req.Requested) {
		t.Fatal("asking again started the wait over")
	}

	// Denied: nothing is released, even after the wait.
	var denied EmergencyGrant
	f.expect(f.send(other, "POST", path+"/deny", nil), http.StatusOK).json(t, &denied)
	if denied.State != GrantAccepted || denied.Denied == nil || denied.DeniedBy != other.id() {
		t.Fatalf("denied %+v", denied)
	}
	f.expect(f.send(other, "POST", path+"/deny", nil), http.StatusConflict)
	f.clock.add(2 * week)
	if r := f.expect(f.send(trustee, "POST", path+"/release", nil), http.StatusConflict); !strings.Contains(string(r.body), "denied") {
		t.Fatalf("release after a denial: %s", r.body)
	}

	// Asked again: released once the whole wait has passed, and not before.
	f.expect(f.send(trustee, "POST", path+"/request", nil), http.StatusOK)
	f.clock.add(week - time.Second)
	f.expect(f.send(trustee, "POST", path+"/release", nil), http.StatusConflict)
	f.clock.add(2 * time.Second)
	var rel EmergencyRelease
	f.expect(f.send(trustee, "POST", path+"/release", nil), http.StatusOK).json(t, &rel)
	release, err := g.id.Open(rel.Escrow, svformat.EmergencyReleaseInfo(vaultID, g.grant))
	if err != nil || !bytes.Equal(release, g.release) {
		t.Fatalf("the escrow: %v", err)
	}
	f.expect(f.send(trustee, "POST", path+"/release", nil), http.StatusOK) // again
	if st := f.grant(owner, path); st.State != GrantReleased || st.Released == nil {
		t.Fatalf("after the release: %+v", st)
	}
	f.expect(f.send(owner, "POST", path+"/deny", nil), http.StatusConflict)

	// Released: the trustee reads the vault, and writes nothing.
	f.expect(f.send(trustee, "GET", "/v1/vaults/v/files/"+slot, nil), http.StatusOK)
	f.changes(trustee, "v", 0, "")
	f.expect(f.put(trustee, "v", slotName(), []byte(`{}`)), http.StatusForbidden)
	f.expect(f.send(trustee, "DELETE", "/v1/vaults/v/files/"+slot, nil), http.StatusForbidden)
	f.expect(f.send(trustee, "POST", "/v1/vaults/v/enrol", nil), http.StatusForbidden)
	f.expect(f.send(trustee, "GET", "/v1/vaults/v/devices", nil), http.StatusForbidden)

	// Revoked: the grant, its escrow and the trustee's access are gone.
	f.expect(f.send(trustee, "DELETE", path, nil), http.StatusForbidden)
	f.expect(f.send(owner, "DELETE", path, nil), http.StatusNoContent)
	f.expect(f.send(trustee, "GET", "/v1/vaults/v/files/"+slot, nil), http.StatusForbidden)
	f.expect(f.send(trustee, "POST", path+"/release", nil), http.StatusForbidden)
	f.expect(f.send(owner, "GET", path, nil), http.StatusNotFound)
	var list []EmergencyGrant
	f.expect(f.send(owner, "GET", "/v1/vaults/v/emergency", nil), http.StatusOK).json(t, &list)
	if len(list) != 0 {
		t.Fatalf("after revoking: %+v", list)
	}
}

// Grants, and the clock of a pending request, are on disk: a restart
// neither forgets a grant nor starts a wait over.
func TestEmergencyGrantsAndTheirWaitsSurviveARestart(t *testing.T) {
	f := newFixture(t, Config{})
	owner, trustee := newDevice(), newDevice()
	f.newVault("v", owner)
	vaultID := svformat.NewID()
	g, body := newGrant(t, vaultID, week)
	path := "/v1/vaults/v/emergency/" + g.grant.String()
	f.expect(f.send(owner, "POST", "/v1/vaults/v/emergency", body), http.StatusCreated)
	f.expect(f.accept(trustee, path, g), http.StatusCreated)
	var req EmergencyGrant
	f.expect(f.send(trustee, "POST", path+"/request", nil), http.StatusOK).json(t, &req)
	events := len(f.changes(owner, "v", 0, "").Changes)
	f.srv.Close()

	g2 := newFixture(t, Config{Root: f.root})
	g2.clock.t = f.clock.now().Add(week / 2)
	st := g2.grant(owner, path)
	if st.State != GrantRequested || !st.Requested.Equal(*req.Requested) || st.Trustee.Key != trustee.id() {
		t.Fatalf("after the restart: %+v", st)
	}
	if cs := g2.changes(owner, "v", 0, ""); len(cs.Changes) != events {
		t.Fatalf("the events were not kept: %d, want %d", len(cs.Changes), events)
	}
	g2.expect(g2.send(trustee, "POST", path+"/release", nil), http.StatusConflict)
	g2.clock.add(week / 2)
	g2.expect(g2.send(trustee, "POST", path+"/release", nil), http.StatusOK)
	if _, err := os.Stat(filepath.Join(f.root, "vaults", "v", emergencyFile)); err != nil {
		t.Fatal(err)
	}
}

func TestAGrantIsCheckedBeforeItIsKept(t *testing.T) {
	f := newFixture(t, Config{})
	owner, other := newDevice(), newDevice()
	f.newVault("v", owner)
	f.expect(f.join(other, "v", f.enrol(owner, "v").Code), http.StatusCreated)
	vaultID := svformat.NewID()
	variant := func(change func(*EmergencyCreate)) []byte {
		_, body := newGrant(t, vaultID, week)
		var c EmergencyCreate
		json.Unmarshal(body, &c)
		change(&c)
		b, _ := json.Marshal(c)
		return b
	}
	for name, body := range map[string][]byte{
		"an upper-case ID":      variant(func(c *EmergencyCreate) { c.ID = strings.ToUpper(c.ID) }),
		"a short ID":            variant(func(c *EmergencyCreate) { c.ID = c.ID[:30] }),
		"a negative wait":       variant(func(c *EmergencyCreate) { c.Wait = -1 }),
		"a wait over a year":    variant(func(c *EmergencyCreate) { c.Wait = int64(MaxEmergencyWait/time.Second) + 1 }),
		"a wait that overflows": variant(func(c *EmergencyCreate) { c.Wait = 18446744074 }),
		"no escrow":             variant(func(c *EmergencyCreate) { c.Escrow = nil }),
		"a huge challenge":      variant(func(c *EmergencyCreate) { c.Challenge = make([]byte, maxSealed+1) }),
		"no accepting key":      variant(func(c *EmergencyCreate) { c.AcceptKey = nil }),
		"not JSON":              []byte("grant"),
	} {
		if r := f.send(owner, "POST", "/v1/vaults/v/emergency", body); r.status != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, r.status, r.body)
		}
	}
	f.expect(f.send(owner, "GET", "/v1/vaults/v/emergency/"+strings.Repeat("A", 32), nil), http.StatusBadRequest)

	// One ID, one grant: the same again is a retry, anything else a clash.
	_, body := newGrant(t, vaultID, week)
	f.expect(f.send(owner, "POST", "/v1/vaults/v/emergency", body), http.StatusCreated)
	var c EmergencyCreate
	json.Unmarshal(body, &c)
	c.Wait = 60
	changed, _ := json.Marshal(c)
	f.expect(f.send(owner, "POST", "/v1/vaults/v/emergency", changed), http.StatusConflict)
	f.expect(f.send(other, "POST", "/v1/vaults/v/emergency", body), http.StatusConflict)

	for range MaxGrants - 1 {
		_, body := newGrant(t, vaultID, time.Hour)
		f.expect(f.send(owner, "POST", "/v1/vaults/v/emergency", body), http.StatusCreated)
	}
	_, body = newGrant(t, vaultID, time.Hour)
	f.expect(f.send(owner, "POST", "/v1/vaults/v/emergency", body), http.StatusConflict)
}
