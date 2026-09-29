package svsync

import (
	"context"
	"crypto/sha256"
	"errors"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svserver"
	"github.com/codemodify/secretvault/svstore"
)

// The trustee's side of a grant, through the client: accepting with the
// identity, asking, and, released (here with no wait), pulling a copy of
// the vault that sends nothing back. The owner's devices hear of each
// step as events in their syncs.
func TestATrusteePullsTheVaultOnceReleasedAndSendsNothing(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	a := s.founder("v", nil)
	fv := newFakeVault(t, a.store)
	fv.revision(t, a.store, "before")
	a.mustSync()

	id, _ := svcrypto.Modern.NewIdentity()
	grant := svformat.NewID()
	code := []byte("a code of thirty-two bytes, here")
	release := svcrypto.RandomKey()
	escrow, _ := svcrypto.Modern.SealTo(id.Recipient(), release, svformat.EmergencyReleaseInfo(fv.id, grant))
	challenge, _ := svcrypto.Modern.SealTo(id.Recipient(), code, svformat.EmergencyChallengeInfo(grant))
	sum := sha256.Sum256(code)
	if _, err := a.client.CreateGrant(ctx, svserver.EmergencyCreate{ID: grant.String(), Wait: 0, Escrow: escrow, Challenge: challenge, CodeHash: sum[:]}); err != nil {
		t.Fatal(err)
	}
	if rep := a.mustSync(); rep.Events != 1 {
		t.Fatalf("the grant's event: %+v", rep)
	}

	tr := newDevice(t, s.remote("v"), svstore.NewMem())
	if _, err := tr.clone(); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("a trustee cloned before any release: %v", err)
	}
	ch, err := tr.client.GrantChallenge(ctx, grant.String())
	if err != nil {
		t.Fatal(err)
	}
	opened, err := id.Open(ch, svformat.EmergencyChallengeInfo(grant))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tr.client.AcceptGrant(ctx, grant.String(), opened, "trustee"); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.client.ReleaseAccess(ctx, grant.String()); !errors.Is(err, ErrConflict) {
		t.Fatalf("released without a request: %v", err)
	}
	g, err := tr.client.RequestAccess(ctx, grant.String())
	if err != nil || g.State != svserver.GrantRequested {
		t.Fatalf("request: %+v, %v", g, err)
	}
	rel, err := tr.client.ReleaseAccess(ctx, grant.String())
	if err != nil {
		t.Fatal(err)
	}
	if got, err := id.Open(rel.Escrow, svformat.EmergencyReleaseInfo(fv.id, grant)); err != nil || string(got) != string(release) {
		t.Fatalf("the escrow: %v", err)
	}
	if rep := a.mustSync(); rep.Events != 3 {
		t.Fatalf("the owner heard of %d events, want the acceptance, the request and the release", rep.Events)
	}

	// Released: a copy, kept up to date, that sends nothing back.
	if _, err := tr.clone(); err != nil {
		t.Fatal(err)
	}
	sameFiles(t, "the trustee's copy", files(t, tr.store), s.files("v"))
	fv.revision(t, a.store, "after")
	a.mustSync()
	local := fv.revision(t, tr.store, "the trustee's own")
	rep, err := Pull(ctx, tr.store, tr.client, tr.loadState())
	if err != nil || rep.Pulled != 1 || rep.Pushed != 0 {
		t.Fatalf("pull: %+v, %v", rep, err)
	}
	if _, ok := s.files("v")[local]; ok {
		t.Fatal("a pull sent a file")
	}
	// A pull never sends a keyslot's removal either: a copy that lost a
	// keyslot fetches it again.
	var slot string
	for n := range files(t, tr.store) {
		if strings.HasPrefix(n, svformat.SlotsDir+"/") {
			slot = n
		}
	}
	tr.store.Remove(slot)
	if _, err := Pull(ctx, tr.store, tr.client, tr.loadState()); err != nil {
		t.Fatal(err)
	}
	if _, err := tr.store.Read(slot); err != nil {
		t.Fatalf("the lost keyslot: %v", err)
	}
	if _, ok := s.files("v")[slot]; !ok {
		t.Fatal("the keyslot was removed from the server")
	}

	// Revoked: the trustee's device reads nothing more.
	if err := a.client.RevokeGrant(ctx, grant.String()); err != nil {
		t.Fatal(err)
	}
	if _, err := Pull(ctx, tr.store, tr.client, tr.loadState()); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("a pull after revoking: %v", err)
	}
}

func TestEmergencyInvitesRoundTripAndAreChecked(t *testing.T) {
	inv := EmergencyInvite{
		Remote:  Remote{URL: "https://sync.example.com:8443", Vault: "v1", Fingerprint: strings.Repeat("ab", 32)},
		Grant:   svformat.NewID().String(),
		VaultID: svformat.NewID().String(),
		Check:   strings.Repeat("0f", 16),
		Name:    "Ada's personal vault",
	}
	got, err := ParseEmergencyInvite(inv.String())
	if err != nil || got != inv {
		t.Fatalf("round trip: %+v, %v", got, err)
	}
	for name, change := range map[string]func(i *EmergencyInvite){
		"no grant":         func(i *EmergencyInvite) { i.Grant = "" },
		"an upper grant":   func(i *EmergencyInvite) { i.Grant = strings.ToUpper(i.Grant) },
		"no vault ID":      func(i *EmergencyInvite) { i.VaultID = "" },
		"a short check":    func(i *EmergencyInvite) { i.Check = "0f0f" },
		"plain HTTP":       func(i *EmergencyInvite) { i.URL = "http://sync.example.com" },
		"a bad vault name": func(i *EmergencyInvite) { i.Vault = "V!" },
	} {
		bad := inv
		change(&bad)
		if _, err := ParseEmergencyInvite(bad.String()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := ParseEmergencyInvite("secretvault-sync:?url=x"); err == nil {
		t.Error("a sync invite was taken for an emergency one")
	}
}
