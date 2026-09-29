package svtrust

import (
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svstore"
)

func check(t *testing.T, s *Store, fp, from string) *Verdict {
	t.Helper()
	v, err := s.Check(Query{Fingerprint: fp, From: from})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func wantReasons(t *testing.T, v *Verdict, want ...string) {
	t.Helper()
	if !slices.Equal(v.Reasons, want) {
		t.Fatalf("reasons:\n  %s\nwant:\n  %s", strings.Join(v.Reasons, "\n  "), strings.Join(want, "\n  "))
	}
}

func TestAddFindAndVerifyInPerson(t *testing.T) {
	s, clock := newStore(t)
	alice := pgpKey(t, 6, "Alice Example <alice@example.org>")
	c, warnings, err := s.Add(&Contact{Keys: []*Key{keyOf(t, armored(t, alice, false))}, Notes: "met at FOSDEM"})
	if err != nil || len(warnings) != 0 {
		t.Fatalf("Add: %v %v", warnings, err)
	}
	if c.Name != "Alice Example" || !slices.Equal(c.Emails, []string{"alice@example.org"}) || c.Origin != OriginAdded || c.ID == "" {
		t.Fatalf("contact = %+v", c)
	}
	fp := fpOf(alice)
	sub := alice.Subkeys()[0]
	for _, ref := range []string{c.ID, "alice example", "ALICE@example.org", fp, strings.ToLower(fp[:16]), hexFP(sub.Fingerprint), keyIDOf(hexFP(sub.Fingerprint))} {
		if got, err := s.Get(ref); err != nil || got.ID != c.ID {
			t.Errorf("Get(%q) = %v, %v", ref, got, err)
		}
	}
	if _, err := s.Get("bob"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("Get(bob): %v", err)
	}
	if _, _, err := s.Add(&Contact{Name: "Again", Keys: []*Key{keyOf(t, armored(t, alice, false))}}); !errors.Is(err, ErrKeyHeld) {
		t.Fatalf("the same key twice: %v", err)
	}

	v := check(t, s, fp, "Alice <alice@example.org>")
	wantReasons(t, v, "Signed by Alice Example's key, which you have not verified.")
	if !v.Bound || v.Level != None || DefaultPolicy.Judge(v).Status != "unverified" {
		t.Fatalf("unverified verdict = %+v", v)
	}

	*clock = clock.Add(24 * time.Hour)
	if _, err := s.Verify("Alice Example", fp, Event{Method: MethodFingerprint, By: "you"}); err != nil {
		t.Fatal(err)
	}
	v = check(t, s, hexFP(sub.Fingerprint), "alice@example.org")
	wantReasons(t, v, "Signed by Alice Example's key, which you verified in person on 2026-09-02.")
	if v.Level != InPerson || v.KeyLevel != InPerson || v.Contact.ID != c.ID || !DefaultPolicy.Judge(v).Trusted {
		t.Fatalf("verified verdict = %+v", v)
	}

	// The same key, from an address that is not its own.
	v = check(t, s, fp, "alice@elsewhere.example")
	wantReasons(t, v, "Signed by Alice Example's key, which you verified in person on 2026-09-02.",
		"The key does not name alice@elsewhere.example, and it is not one of its addresses.")
	if v.Bound || v.Level != None || v.KeyLevel != InPerson || DefaultPolicy.Judge(v).Trusted {
		t.Fatalf("other address = %+v", v)
	}
	// A key nobody has.
	v = check(t, s, fpOf(pgpKey(t, 6, "x <x@example.org>")), "")
	wantReasons(t, v, "Signed by a key you do not have.")
	if DefaultPolicy.Judge(v).Status != "unknown" {
		t.Fatal("an unknown key was judged", DefaultPolicy.Judge(v))
	}
	if _, err := s.Verify("", fp, Event{Method: "vibes"}); err == nil {
		t.Fatal("an unknown method was recorded")
	}
}

// Trust on first use: three messages, then a different key for the same
// address, which is kept apart and called what it may be.
func TestTOFUCountsAndAnotherKeyIsAWarning(t *testing.T) {
	s, clock := newStore(t)
	*clock = time.Date(2026, 8, 1, 9, 0, 0, 0, time.UTC)
	k1 := pgpKey(t, 4, "Alice <alice@example.org>")
	key1 := keyOf(t, armored(t, k1, false))
	start := *clock
	for i := range 3 {
		*clock = start.Add(time.Duration(i) * 24 * time.Hour)
		res, err := s.Seen(key1, "Alice <alice@example.org>", *clock, "", "comms-mail", "Alice")
		if err != nil {
			t.Fatal(err)
		}
		if res.New != (i == 0) || !res.Bound || len(res.Conflicts) != 0 || len(res.Warnings) != 0 {
			t.Fatalf("sighting %d: %+v", i, res)
		}
	}
	c, _ := s.Get("alice@example.org")
	if c.Origin != OriginMail || c.Name != "Alice" || len(c.Keys) != 1 {
		t.Fatalf("contact from mail = %+v", c)
	}
	seen := c.Keys[0].Seen[0]
	if seen.Count != 3 || !seen.First.Equal(start) || !seen.Last.Equal(start.Add(48*time.Hour)) || seen.Source != "mail from alice@example.org on 2026-08-01" {
		t.Fatalf("sighting = %+v", seen)
	}
	v := check(t, s, fpOf(k1), "alice@example.org")
	wantReasons(t, v, "Signed by a key you have seen 3 times from alice@example.org since 2026-08-01 (not verified).")
	if v.Level != TOFU || DefaultPolicy.Judge(v).Status != "unverified" || !(Policy{MinLevel: TOFU}).Judge(v).Trusted {
		t.Fatalf("TOFU verdict = %+v", v)
	}

	// A different key for the address: never a silent replacement.
	*clock = time.Date(2026, 9, 10, 9, 0, 0, 0, time.UTC)
	k2 := pgpKey(t, 6, "Alice <alice@example.org>")
	res, err := s.Seen(keyOf(t, armored(t, k2, false)), "alice@example.org", time.Time{}, "", "comms-mail", "Alice")
	if err != nil {
		t.Fatal(err)
	}
	if !res.New || res.Bound || len(res.Conflicts) != 1 || res.Conflicts[0].Key.Fingerprint != fpOf(k1) || len(res.Warnings) != 1 {
		t.Fatalf("second key: %+v", res)
	}
	if res.Contact.ID == c.ID || res.Key.Seen[0].Conflicts[0] != fpOf(k1) {
		t.Fatalf("the second key was not kept apart: %+v", res.Contact)
	}
	v = check(t, s, fpOf(k2), "alice@example.org")
	wantReasons(t, v, "Signed by a key first seen from alice@example.org on 2026-09-10 (not verified).",
		"The address alice@example.org belongs to a different key, seen 3 times since 2026-08-01 (not verified). The sender may have a new key, or this may be an impostor.")
	if DefaultPolicy.Judge(v).Status != "suspicious" {
		t.Fatalf("judged %+v", DefaultPolicy.Judge(v))
	}
	// The first key's verdict is unchanged.
	if v := check(t, s, fpOf(k1), "alice@example.org"); v.Level != TOFU || len(v.Others) != 0 {
		t.Fatalf("the first key's verdict changed: %+v", v)
	}
	if w, _ := s.Warnings(res.Contact); len(w) != 1 || !strings.Contains(w[0], "belongs to a key "+keyIDOf(fpOf(k1))) {
		t.Fatalf("Warnings = %q", w)
	}
}

// A key you verified, then another for the same address: an impostor,
// until you verify the new one as the person's, which moves it to them.
func TestImpostorUntilVerifiedThenItMoves(t *testing.T) {
	s, _ := newStore(t)
	k1 := pgpKey(t, 6, "Alice Example <alice@example.org>")
	alice, _, err := s.Add(&Contact{Keys: []*Key{keyOf(t, armored(t, k1, false))}})
	if err != nil {
		t.Fatal(err)
	}
	s.Verify("Alice Example", fpOf(k1), Event{Method: MethodQR, By: "you"})

	k2 := pgpKey(t, 6, "Alice Example <alice@example.org>")
	res, err := s.Seen(keyOf(t, armored(t, k2, false)), "alice@example.org", time.Time{}, "", "comms-mail", "Alice Example")
	if err != nil || res.Bound || res.Contact.Name != "alice@example.org" {
		t.Fatalf("Seen: %+v, %v", res, err)
	}
	v := check(t, s, fpOf(k2), "alice@example.org")
	wantReasons(t, v, "Signed by a key first seen from alice@example.org on 2026-09-01 (not verified).",
		"The address alice@example.org belongs to a different key you verified (Alice Example's, in person, by scanning their QR code, on 2026-09-01). This may be an impostor.")
	if len(v.Others) != 1 || v.Others[0].Contact.ID != alice.ID {
		t.Fatalf("others = %+v", v.Others)
	}

	// The unknown key with no address at all is still just unknown.
	if v := check(t, s, fpOf(pgpKey(t, 6)), "alice@example.org"); !strings.Contains(v.Reasons[1], "may be an impostor") {
		t.Fatalf("an unknown key from alice: %q", v.Reasons)
	}

	if cs, _ := s.ByEmail("alice@example.org"); len(cs) != 2 {
		t.Fatalf("ByEmail found %d contacts", len(cs))
	}
	if _, err := s.Get("Alice <alice@example.org>"); !errors.Is(err, ErrAmbiguous) {
		t.Fatalf("an address two contacts have: %v", err)
	}
	c, err := s.Verify(alice.ID, fpOf(k2), Event{Method: MethodFingerprint, By: "you", Source: "at the office"})
	if err != nil || c.ID != alice.ID || len(c.Keys) != 2 {
		t.Fatalf("Verify: %+v, %v", c, err)
	}
	if all, _ := s.Contacts(); len(all) != 1 {
		t.Fatalf("the contact made from mail was not dropped: %d contacts", len(all))
	}
	v = check(t, s, fpOf(k2), "alice@example.org")
	if !v.Bound || v.Level != InPerson || len(v.Others) != 0 || !DefaultPolicy.Judge(v).Trusted {
		t.Fatalf("after verifying: %+v", v)
	}
}

func TestVerdictsForEachWayOfVerifying(t *testing.T) {
	s, _ := newStore(t)
	add := func(k *Key) *Contact {
		c, _, err := s.Add(&Contact{Keys: []*Key{k}})
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// WKD and a keyserver's email check, both recorded on import.
	wkd := keyOf(t, armored(t, pgpKey(t, 6, "Wanda <wanda@example.org>"), false))
	wkd.Events = []Event{{Level: Published, Method: MethodWKD, At: day0, Source: "https://openpgpkey.example.org/...", Addresses: []string{"wanda@example.org"}}}
	add(wkd)
	wantReasons(t, check(t, s, wkd.Fingerprint, "wanda@example.org"),
		"Signed by Wanda's key, which example.org publishes for wanda@example.org (WKD, checked on 2026-09-01).")

	vks := keyOf(t, armored(t, pgpKey(t, 6, "Victor <victor@example.org>"), false))
	vks.Events = []Event{{Level: Published, Method: MethodKeyserver, At: day0, Source: "https://keys.openpgp.org/vks/v1/by-email/victor%40example.org", Addresses: []string{"victor@example.org"}}}
	add(vks)
	v := check(t, s, vks.Fingerprint, "victor@example.org")
	wantReasons(t, v, "Signed by Victor's key, whose address keys.openpgp.org checked by email (on 2026-09-01).")
	if !DefaultPolicy.Judge(v).Trusted || (Policy{MinLevel: Organisation}).Judge(v).Trusted {
		t.Fatal("the policy's level is not what decides")
	}

	// An organisation's CA vouches for the certificates it issues.
	org := newCA(t, "Example Root")
	carol := add(keyOf(t, pemOf(org.issue(t, "Carol Example", "carol@example.org"), org.cert)))
	v = check(t, s, carol.Keys[0].Fingerprint, "carol@example.org")
	wantReasons(t, v, "Signed by Carol Example's key, which you have not verified.")
	if _, _, err := s.Add(&Contact{Name: "Example Corp", Organisation: true, Keys: []*Key{keyOf(t, pemOf(org.cert))}}); err != nil {
		t.Fatal(err)
	}
	v, err := s.Check(Query{Key: pemOf(org.issue(t, "x", "x@example.org"))})
	if err != nil || v.Key != nil {
		t.Fatalf("a certificate nobody has: %+v, %v", v, err)
	}
	v, err = s.Check(Query{Key: carol.Keys[0].Material, From: "carol@example.org"})
	if err != nil {
		t.Fatal(err)
	}
	wantReasons(t, v, `Signed by Carol Example's key, which Example Corp's CA "Example Root" vouches for.`)
	if v.Level != Organisation {
		t.Fatalf("level %v", v.Level)
	}
	// A CA of a contact that is not an organisation vouches for nothing.
	other := newCA(t, "Somebody's CA")
	dave := add(keyOf(t, pemOf(other.issue(t, "Dave", "dave@example.org"), other.cert)))
	add(keyOf(t, pemOf(other.cert)))
	if v := check(t, s, dave.Keys[0].Fingerprint, "dave@example.org"); v.Level != None {
		t.Fatalf("a person's CA vouched: %v", v.Level)
	}

	// SSH keys and recipients name no address: an event covering the key
	// covers the addresses bound to it.
	line, _ := sshLine(t, "erin@laptop")
	erin := add(keyOf(t, []byte(line)))
	s.Edit(erin.ID, func(c *Contact) error { c.Name = "Erin"; return nil })
	s.Verify("Erin", erin.Keys[0].Fingerprint, Event{Method: MethodFingerprint, Addresses: []string{"erin@example.org"}})
	wantReasons(t, check(t, s, erin.Keys[0].Fingerprint, "erin@example.org"), "Signed by Erin's key, which you verified in person on 2026-09-01.")

	// A revoked key says so.
	revoked := pgpKey(t, 6, "Rita <rita@example.org>")
	revoked.Revoke(0, "", time.Time{})
	rita := add(keyOf(t, armored(t, revoked, false)))
	s.Verify("", rita.Keys[0].Fingerprint, Event{Method: MethodFingerprint})
	v = check(t, s, rita.Keys[0].Fingerprint, "rita@example.org")
	if v.State != "revoked" || v.Reasons[len(v.Reasons)-1] != "The key has been revoked." || DefaultPolicy.Judge(v).Trusted {
		t.Fatalf("revoked: %+v", v)
	}
}

func TestImportUpdatesKeysAndKeepsAddressesApart(t *testing.T) {
	s, _ := newStore(t)
	pk := pgpKey(t, 6, "Alice <alice@example.org>")
	s.Add(&Contact{Name: "Alice", Emails: []string{"alice@example.org"}})

	// A new key goes to the contact that has its address and no key for it.
	k := keyOf(t, armored(t, pk, false))
	k.Events = []Event{{Level: Published, Method: MethodWKD, At: day0, Source: "u", Addresses: []string{"alice@example.org"}}}
	got, err := s.Import([]*Key{k}, ImportOptions{By: "comms-mail", Origin: OriginLookup})
	if err != nil || len(got) != 1 || !got[0].New || got[0].Contact.Name != "Alice" || got[0].Key.Events[0].By != "comms-mail" {
		t.Fatalf("Import: %+v, %v", got, err)
	}
	// Again: nothing new, the same event not added twice.
	got, _ = s.Import([]*Key{k}, ImportOptions{})
	if got[0].New || len(got[0].Key.Events) != 1 {
		t.Fatalf("second Import: %+v", got[0])
	}
	// A revoked copy of the key replaces the one held.
	pk.Revoke(0, "", time.Time{})
	s.Import([]*Key{keyOf(t, armored(t, pk, false))}, ImportOptions{})
	if _, held, _ := s.ByFingerprint(fpOf(pk)); held.State(day0) != "revoked" {
		t.Fatal("the revocation was not taken")
	}
	// Another key for the address, not put in Alice's place.
	other := keyOf(t, armored(t, pgpKey(t, 6, "Mallory <alice@example.org>"), false))
	got, _ = s.Import([]*Key{other}, ImportOptions{})
	if got[0].Contact.Name != "Mallory" || len(got[0].Key.Addresses) != 0 || len(got[0].Warnings) != 1 {
		t.Fatalf("a second key for alice: %+v", got[0])
	}
	// Unless you say whose it is.
	got, _ = s.Import([]*Key{keyOf(t, armored(t, pgpKey(t, 4, "Alice <alice@example.org>"), false))}, ImportOptions{Contact: "Alice"})
	if got[0].Contact.Name != "Alice" || !got[0].Key.Bound("alice@example.org") {
		t.Fatalf("into Alice: %+v", got[0])
	}
	if cs, _ := s.ByEmail("alice@example.org"); len(cs) != 1 {
		t.Fatalf("ByEmail = %d contacts", len(cs))
	}
}

func TestRemoving(t *testing.T) {
	s, _ := newStore(t)
	a, b := pgpKey(t, 6, "A <a@example.org>"), pgpKey(t, 6, "B <b@example.org>")
	c, _, _ := s.Add(&Contact{Name: "Both", Keys: []*Key{keyOf(t, armored(t, a, false)), keyOf(t, armored(t, b, false))}})
	if _, err := s.RemoveKey("Both", fpOf(a)); err != nil {
		t.Fatal(err)
	}
	if got, _ := s.Get("Both"); len(got.Keys) != 1 || got.Keys[0].Fingerprint != fpOf(b) {
		t.Fatalf("after RemoveKey: %+v", got)
	}
	if _, err := s.Remove(c.ID); err != nil {
		t.Fatal(err)
	}
	if all, _ := s.Contacts(); len(all) != 0 {
		t.Fatal("the contact is still there")
	}
}

// Two devices change one contact without seeing each other: the next read
// has both changes, and the next write keeps them.
func TestConcurrentChangesMerge(t *testing.T) {
	cheapKDF(t)
	dir, _ := svstore.OpenDir(filepath.Join(t.TempDir(), "v"))
	clockA, clockB := day0, day0.Add(time.Hour)
	va := newVault(t, dir, 0xA, func() time.Time { return clockA })
	a := NewStore(va)
	a.Now = func() time.Time { return clockA }
	pk := pgpKey(t, 6, "Alice <alice@example.org>")
	key := keyOf(t, armored(t, pk, false))
	c, _, _ := a.Add(&Contact{Keys: []*Key{key}})

	vb, err := svcore.Open(dir, svcore.Options{Device: [16]byte{0xB}, Now: func() time.Time { return clockB }})
	if err != nil {
		t.Fatal(err)
	}
	if err := vb.Unlock(svcore.Passphrase([]byte("correct horse"))); err != nil {
		t.Fatal(err)
	}
	b := NewStore(vb)
	b.Now = func() time.Time { return clockB }
	if _, err := a.Verify(c.ID, fpOf(pk), Event{Method: MethodFingerprint, By: "A"}); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Seen(key, "alice@example.org", clockB, "", "B", ""); err != nil {
		t.Fatal(err)
	}
	if err := va.Refresh(); err != nil {
		t.Fatal(err)
	}
	got, err := a.Get(c.ID)
	if err != nil {
		t.Fatal(err)
	}
	// B's version wins (its clock is later); A's verification is merged in.
	k := got.Keys[0]
	if len(k.Events) != 1 || k.Events[0].By != "A" || len(k.Seen) != 1 || k.Seen[0].Count != 1 {
		t.Fatalf("merged key: events %+v, sightings %+v", k.Events, k.Seen)
	}
	if _, err := a.Edit(c.ID, func(c *Contact) error { c.Notes = "merged"; return nil }); err != nil {
		t.Fatal(err)
	}
	vb.Refresh()
	got, _ = b.Get(c.ID)
	if got.Notes != "merged" || len(got.Keys[0].Events) != 1 || len(got.Keys[0].Seen) != 1 {
		t.Fatalf("after the merge was written: %+v", got.Keys[0])
	}
}
