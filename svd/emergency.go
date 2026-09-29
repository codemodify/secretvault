package svd

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svserver"
	"github.com/codemodify/secretvault/svstore"
	"github.com/codemodify/secretvault/svsync"
	"github.com/codemodify/secretvault/svtrust"
)

// Emergency access (docs/architecture.md, "Emergency access"; what it
// protects, and where it stops, is in docs/security.md).
//
// The owner's side. For a vault that syncs with a server, 'emergency
// grant' makes
//   - a grant on the server: a random release key sealed to the trustee's
//     recipient key (the escrow), the seed of a signing key sealed to it
//     too (the challenge) with the key's public half, and the wait;
//   - a record of kind "emergency-grant" in the vault, holding who the
//     trustee is and the release key, so any of the owner's devices can
//     name the trustee, and a rotation can make the grant's keyslot again;
//   - an emergency keyslot, which opens with the trustee's identity and
//     the release key together (svformat/emergency.go);
// and hands back the invite for the trustee, which holds no secret. The
// vault's watcher hears of every change to its grants (events in the
// server's change log): on a request the daemon writes it to the vault's
// audit log, shows a notice on the desktop (or the terminal agent), tells
// clients (emergency.changed), and lists it in daemon.status until it is
// denied or released; a release is told the same way, and listed until
// the grant is revoked.
//
// The trustee's side (emergency_access.go). 'emergency accept' opens the
// invite's challenge with the trustee's identity and signs with it for
// this device, which becomes the grant's trustee device on the server,
// and keeps the access in the config.
// 'request' starts the wait. 'open', once the wait is over, takes the
// escrowed release key (sealed to the identity, and kept so), fetches the
// vault, checks it is the vault the invite named, registers it read-only
// (its copy only ever pulls: VaultConfig.Emergency) and unlocks it. The
// identity is never kept: 'unlock --identity' opens the vault again.

const (
	// grantKind is the kind of the records a vault keeps of the grants
	// it made.
	grantKind = "emergency-grant"

	// Waits: the default, and the shortest a grant may have. (The
	// longest is the server's, svserver.MaxEmergencyWait.)
	defaultWait = 7 * 24 * time.Hour
	minWait     = time.Hour

	// emergencyRecheck is how often a vault's grants are looked at when
	// no event says one changed: events are logged after a change is
	// saved, so a server that failed between the two is caught up with.
	emergencyRecheck = 15 * time.Minute
)

func init() {
	registerMethod(svrpc.MEmergencyGrant, trustErrors((*Daemon).emergencyGrant))
	registerMethod(svrpc.MEmergencyList, (*Daemon).emergencyList)
	registerMethod(svrpc.MEmergencyDeny, (*Daemon).emergencyDeny)
	registerMethod(svrpc.MEmergencyRevoke, (*Daemon).emergencyRevoke)
	registerMethod(svrpc.MEmergencyAccept, (*Daemon).emergencyAccept)
	registerMethod(svrpc.MEmergencyRequest, (*Daemon).emergencyRequest)
	registerMethod(svrpc.MEmergencyOpen, (*Daemon).emergencyOpen)
	for _, m := range []string{svrpc.MEmergencyGrant, svrpc.MEmergencyList, svrpc.MEmergencyDeny, svrpc.MEmergencyRevoke,
		svrpc.MEmergencyAccept, svrpc.MEmergencyRequest, svrpc.MEmergencyOpen} {
		personOnly[m] = "gives and holds emergency access for people, not for a machine"
	}
}

// grantRecord is a vault's record of a grant it made.
type grantRecord struct {
	Grant     string    `json:"grant"`
	Trustee   string    `json:"trustee"`           // the contact's name, when it was made
	Contact   string    `json:"contact,omitempty"` // the contact's ID
	Recipient string    `json:"recipient"`         // the trustee's recipient text
	Level     string    `json:"level,omitempty"`   // how well their key was verified, when it was made
	Wait      int64     `json:"wait"`              // seconds
	Release   []byte    `json:"release"`           // the release key itself (the server holds it sealed to the trustee)
	Created   time.Time `json:"created"`
}

type grantEntry struct {
	record svformat.ID // the record's own ID
	grantRecord
}

// grantRecords reads a vault's records of the grants it made, by grant
// ID. The vault must be open. They hold release keys: wipeGrants them.
func grantRecords(v *svcore.Vault) (map[string]*grantEntry, error) {
	recs, err := v.Records(grantKind)
	if err != nil {
		return nil, err
	}
	out := map[string]*grantEntry{}
	for _, r := range recs {
		var g grantRecord
		err := json.Unmarshal(r.Data, &g)
		clear(r.Data)
		for _, c := range r.Conflicts {
			clear(c)
		}
		if err != nil || g.Grant == "" {
			continue
		}
		out[g.Grant] = &grantEntry{r.ID, g}
	}
	return out, nil
}

func wipeGrants(m map[string]*grantEntry) {
	for _, e := range m {
		clear(e.Release)
	}
}

// errTheirs refuses to manage someone else's vault as its owner.
func errTheirs(mv *managedVault) error {
	return svrpc.Errorf(svrpc.CodeDenied, "vault %q is someone else's, opened with emergency access: it is read-only here", mv.cfg.Name)
}

// Waits in words.

func waitWords(d time.Duration) string {
	switch {
	case d%(24*time.Hour) == 0:
		n := int(d / (24 * time.Hour))
		if n == 1 {
			return "1 day"
		}
		return fmt.Sprintf("%d days", n)
	case d%time.Hour == 0:
		n := int(d / time.Hour)
		if n == 1 {
			return "1 hour"
		}
		return fmt.Sprintf("%d hours", n)
	}
	return d.String()
}

func when(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.Local().Format("2006-01-02 15:04")
}

// The owner's side.

// trusteeKey is whom a grant is for.
type trusteeKey struct {
	name, contact string
	recipient     string // text
	pub           []byte
	level         svtrust.Level
	warning       string
}

// trustee resolves who a grant is for: a contact with a secretvault key
// for the vault's suite (or the one fp names), or a recipient's text.
func (d *Daemon) trustee(ctx context.Context, cl *client, mv *managedVault, ref, fp string) (trusteeKey, error) {
	suite := mv.v.Suite()
	if strings.TrimSpace(ref) == "" {
		return trusteeKey{}, svrpc.Errorf(svrpc.CodeInvalidParams, "whom? name a contact with a secretvault key, or give a recipient")
	}
	if strings.HasPrefix(ref, "sv-recipient-") {
		s, pub, err := svformat.ParseRecipient(ref)
		if err != nil {
			return trusteeKey{}, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
		}
		if s != suite {
			return trusteeKey{}, svrpc.Errorf(svrpc.CodeInvalidParams, "that recipient is for %v; vault %q uses %v", s, mv.cfg.Name, suite)
		}
		return trusteeKey{name: "recipient " + ref[:min(len(ref), 40)] + "...", recipient: ref, pub: pub,
			warning: "That recipient is not one of your contacts, so nothing says whose it is: whoever holds its identity gets the vault after the wait."}, nil
	}
	_, store, err := d.contacts(ctx, cl, "", svbroker.OpRead)
	if err != nil {
		return trusteeKey{}, err
	}
	c, err := store.Get(ref)
	if err != nil {
		return trusteeKey{}, err
	}
	want := strings.ToUpper(strings.NewReplacer(" ", "", ":", "").Replace(fp))
	var keys []*svtrust.Key
	for _, k := range c.Keys {
		if k.Type != svtrust.Secretvault {
			continue
		}
		if s, _, err := svformat.ParseRecipient(string(k.Material)); err != nil || s != suite {
			continue
		}
		if want != "" && !strings.EqualFold(k.Fingerprint, want) {
			continue
		}
		keys = append(keys, k)
	}
	switch len(keys) {
	case 0:
		return trusteeKey{}, svrpc.Errorf(svrpc.CodeInvalidParams,
			"%s has no secretvault key for vault %q's cipher suite (%v): add their recipient with 'secretvault contact add'", c.Name, mv.cfg.Name, suite)
	case 1:
	default:
		var fps []string
		for _, k := range keys {
			fps = append(fps, k.Fingerprint)
		}
		return trusteeKey{}, svrpc.Errorf(svrpc.CodeInvalidParams, "%s has %d secretvault keys: pick one with --fingerprint (%s)", c.Name, len(keys), strings.Join(fps, ", "))
	}
	k := keys[0]
	_, pub, _ := svformat.ParseRecipient(string(k.Material))
	level, _ := k.Best()
	t := trusteeKey{name: c.Name, contact: c.ID, recipient: string(k.Material), pub: pub, level: level}
	if level.Rank() < svtrust.Organisation.Rank() {
		t.warning = fmt.Sprintf("%s's key is %s, not verified in person: whoever holds its identity gets the vault after the wait. "+
			"Compare fingerprints with them ('secretvault contact verify').", c.Name, level)
	}
	return t, nil
}

// ownerVault resolves a vault of the person's own that syncs, for an
// owner's method, after consent to manage it.
func (d *Daemon) ownerVault(ctx context.Context, cl *client, vault string) (*managedVault, *vaultSync, error) {
	if !cl.cli {
		return nil, nil, errOwnPrograms
	}
	mv, err := d.managed(ctx, cl, vault, "", "", svbroker.OpManage)
	if err != nil {
		return nil, nil, err
	}
	if mv.cfg.Emergency != "" {
		return nil, nil, errTheirs(mv)
	}
	return mv, mv.syncer(), nil
}

func (d *Daemon) emergencyGrant(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.EmergencyGrantParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	// In seconds, before any Duration: a huge count would overflow one.
	if p.Wait == 0 {
		p.Wait = int64(defaultWait / time.Second)
	}
	if p.Wait < int64(minWait/time.Second) || p.Wait > int64(svserver.MaxEmergencyWait/time.Second) {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the wait is from an hour to a year")
	}
	wait := time.Duration(p.Wait) * time.Second
	mv, s, err := d.ownerVault(ctx, cl, p.Vault)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "emergency access needs vault %q to sync with a server, which keeps the wait: set that up with 'secretvault sync setup URL'", mv.cfg.Name)
	}
	desc, err := descriptor(mv.store)
	if err != nil {
		return nil, err
	}
	suite, vid := mv.v.Suite(), mv.v.ID()
	grant := svformat.NewID()
	name := p.Name
	if name == "" {
		name = mv.cfg.Name
	}
	inv := svsync.EmergencyInvite{Remote: s.client.Remote(), Grant: grant.String(), VaultID: vid.String(),
		Check: hex.EncodeToString(desc.Epochs[0].Check), Name: name}
	if _, err := svsync.ParseEmergencyInvite(inv.String()); err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%s", syncWords(err))
	}
	who, err := d.trustee(ctx, cl, mv, p.Contact, p.Fingerprint)
	if err != nil {
		return nil, err
	}
	// The release key, sealed to the trustee, is the escrow; the seed of
	// the key that accepting takes, sealed to them too, is the challenge.
	release, seed := svcrypto.RandomKey(), svcrypto.RandomKey()
	defer clear(release)
	defer clear(seed)
	escrow, err := suite.SealTo(who.pub, release, svformat.EmergencyReleaseInfo(vid, grant))
	if err != nil {
		return nil, err
	}
	challenge, err := suite.SealTo(who.pub, seed, svformat.EmergencyChallengeInfo(vid, grant))
	if err != nil {
		return nil, err
	}
	acceptKey := ed25519.NewKeyFromSeed(seed)
	acceptPub := acceptKey.Public().(ed25519.PublicKey)
	clear(acceptKey)

	// The server first: until the keyslot exists the grant opens nothing,
	// and should the keyslot not be written, it is revoked again.
	sg, err := s.client.CreateGrant(ctx, svserver.EmergencyCreate{ID: grant.String(), Wait: p.Wait,
		Escrow: escrow, Challenge: challenge, AcceptKey: acceptPub})
	switch {
	case errors.Is(err, svsync.ErrNotFound):
		return nil, svrpc.Errorf(svrpc.CodeFailed, "the server %s does not offer emergency access: it is older than this version", s.client.Remote().URL)
	case err != nil:
		return nil, serverRefused(err, svrpc.CodeFailed)
	}
	undo := func() {
		c, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		if err := s.client.RevokeGrant(c, grant.String()); err != nil {
			d.opts.Log(fmt.Sprintf("emergency grant %s of %s: taking it back from the server: %v", grant, mv.cfg.Name, err))
		}
	}
	rec := grantRecord{Grant: grant.String(), Trustee: who.name, Contact: who.contact, Recipient: who.recipient, Level: string(who.level),
		Wait: p.Wait, Release: release, Created: d.opts.Now().UTC()}
	r, err := mv.v.PutRecord(grantKind, svformat.ID{}, rec)
	if err != nil {
		undo()
		return nil, err
	}
	if _, err := mv.v.AddSlot(svcore.NewSlot{Type: svformat.SlotEmergency, Label: "emergency", Recipient: who.pub, Grant: grant, ReleaseKey: release}); err != nil {
		mv.v.DeleteRecord(r.ID)
		undo()
		return nil, err
	}
	s.em.named(grant.String(), who.name)
	d.recorder(cl, mv, "", svbroker.OpManage)("allowed",
		fmt.Sprintf("gave %s emergency access (grant %s), released after %s unless denied", who.name, grant, waitWords(wait)))
	out := svrpc.EmergencyGrantResult{Grant: grantInfo(mv, sg.ID, &rec, &sg), Invite: inv.String(), Warning: who.warning}
	return out, nil
}

// descriptor reads a vault's descriptor from its folder.
func descriptor(store svstore.Backend) (svformat.Descriptor, error) {
	b, err := store.Read(svformat.DescriptorName)
	if err != nil {
		return svformat.Descriptor{}, err
	}
	desc, _, err := svformat.ParseDescriptor(b)
	return desc, err
}

// grantInfo describes a grant from what the vault's record and the
// server say of it (either may be nil).
func grantInfo(mv *managedVault, id string, rec *grantRecord, sg *svsync.Grant) svrpc.EmergencyGrant {
	g := svrpc.EmergencyGrant{ID: id, Vault: mv.cfg.Name}
	if rec != nil {
		g.Trustee, g.Recipient, g.Level, g.Wait, g.Created = rec.Trustee, rec.Recipient, rec.Level, rec.Wait, rec.Created
	}
	if sg != nil {
		g.State, g.Wait, g.Requested, g.ReleasesAt, g.Denied, g.Released = sg.State, sg.Wait, sg.Requested, sg.ReleasesAt, sg.Denied, sg.Released
		if g.Created.IsZero() {
			g.Created = sg.Created
		}
		if sg.Trustee != nil {
			g.Device = sg.Trustee.Label
			at := sg.Trustee.Accepted
			g.Accepted = &at
		}
	}
	return g
}

// grantsOf describes every grant of a vault: those it has a record of,
// those its server holds, and those a keyslot names. The vault is open.
func (d *Daemon) grantsOf(ctx context.Context, mv *managedVault) ([]svrpc.EmergencyGrant, error) {
	recs, err := grantRecords(mv.v)
	if err != nil {
		return nil, err
	}
	defer wipeGrants(recs)
	slots, err := mv.v.Slots()
	if err != nil {
		return nil, err
	}
	epoch := mv.v.Epoch()
	keyed := map[string]bool{}
	for _, s := range slots {
		if s.Type == svformat.SlotEmergency && s.Epoch == epoch {
			keyed[s.Grant.String()] = true
		}
	}
	server := map[string]*svsync.Grant{}
	var serr error
	s := mv.syncer()
	if s != nil {
		c, cancel := context.WithTimeout(ctx, 30*time.Second)
		list, err := s.client.Grants(c)
		cancel()
		serr = err
		for i := range list {
			server[list[i].ID] = &list[i]
		}
	}
	ids := map[string]bool{}
	for id := range recs {
		ids[id] = true
	}
	for id := range server {
		ids[id] = true
	}
	for id := range keyed {
		ids[id] = true
	}
	out := []svrpc.EmergencyGrant{}
	for id := range ids {
		var rec *grantRecord
		if e := recs[id]; e != nil {
			rec = &e.grantRecord
			if s != nil {
				s.em.named(id, rec.Trustee)
			}
		}
		g := grantInfo(mv, id, rec, server[id])
		switch {
		case rec == nil:
			g.Problems = append(g.Problems, "the vault has no record of it (it was never finished, or its record was removed): revoke it")
		case !keyed[id]:
			g.Problems = append(g.Problems, "no keyslot opens the vault with it now (the key was rotated without it): revoke it, and grant it again")
		}
		switch {
		case s == nil:
			g.Problems = append(g.Problems, "the vault does not sync, so nobody can ask for it: revoke it")
		case serr != nil:
			g.Problems = append(g.Problems, "the server could not be asked about it: "+syncWords(serr))
		case server[id] == nil:
			g.Problems = append(g.Problems, "the server does not hold it, so nobody can ask for it: revoke it")
		}
		out = append(out, g)
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].Created.Equal(out[j].Created) {
			return out[i].Created.Before(out[j].Created)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// findGrant picks the grant ref names (its ID, or the start of one that
// no other has) among a vault's.
func findGrant(grants []svrpc.EmergencyGrant, ref string) (svrpc.EmergencyGrant, error) {
	ref = strings.ToLower(strings.TrimSpace(ref))
	var hits []svrpc.EmergencyGrant
	for _, g := range grants {
		if g.ID == ref {
			return g, nil
		}
		if len(ref) >= 4 && strings.HasPrefix(g.ID, ref) {
			hits = append(hits, g)
		}
	}
	switch len(hits) {
	case 0:
		return svrpc.EmergencyGrant{}, svrpc.Errorf(svrpc.CodeNotFound, "no emergency grant %q ('secretvault emergency ls' lists them)", ref)
	case 1:
		return hits[0], nil
	}
	return svrpc.EmergencyGrant{}, svrpc.Errorf(svrpc.CodeInvalidParams, "%q is the start of %d grants: give more of it", ref, len(hits))
}

func (d *Daemon) emergencyList(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.VaultRef
	if err := decode(&p); err != nil {
		return nil, err
	}
	if !cl.cli {
		return nil, errOwnPrograms
	}
	out := svrpc.EmergencyList{Given: []svrpc.EmergencyGrant{}}
	// The grants of the vault (the default, or the one named), when it is
	// the person's own and syncs: someone who only holds access to other
	// people's vaults is not asked for a passphrase.
	mv, err := d.vault(p.Vault)
	switch {
	case err != nil && p.Vault != "":
		return nil, err
	case err == nil && mv.cfg.Emergency == "" && (mv.syncer() != nil || p.Vault != ""):
		mv, _, err := d.ownerVault(ctx, cl, p.Vault)
		if err != nil {
			return nil, err
		}
		if out.Given, err = d.grantsOf(ctx, mv); err != nil {
			return nil, err
		}
	}
	out.Held = d.heldAccess(ctx)
	return out, nil
}

func (d *Daemon) emergencyDeny(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.EmergencyRef
	if err := decode(&p); err != nil {
		return nil, err
	}
	mv, s, err := d.ownerVault(ctx, cl, p.Vault)
	if err != nil {
		return nil, err
	}
	if s == nil {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "vault %q does not sync, so nobody can ask for emergency access to it", mv.cfg.Name)
	}
	grants, err := d.grantsOf(ctx, mv)
	if err != nil {
		return nil, err
	}
	g, err := findGrant(grants, p.Grant)
	if err != nil {
		return nil, err
	}
	sg, err := s.client.DenyGrant(ctx, g.ID)
	if err != nil {
		// Nothing pending, or released already: the server says which.
		return nil, serverRefused(err, svrpc.CodeFailed)
	}
	who := g.Trustee
	if who == "" {
		who = "the trustee"
	}
	d.recorder(cl, mv, "", svbroker.OpManage)("allowed", fmt.Sprintf("denied %s's request for emergency access (grant %s)", who, g.ID))
	s.em.check(d, mv, s) // the notice goes at once, not at the next sync
	out := g
	out.State, out.Requested, out.ReleasesAt, out.Denied = sg.State, sg.Requested, sg.ReleasesAt, sg.Denied
	return out, nil
}

func (d *Daemon) emergencyRevoke(ctx context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.EmergencyRef
	if err := decode(&p); err != nil {
		return nil, err
	}
	mv, s, err := d.ownerVault(ctx, cl, p.Vault)
	if err != nil {
		return nil, err
	}
	grants, err := d.grantsOf(ctx, mv)
	if err != nil {
		return nil, err
	}
	g, err := findGrant(grants, p.Grant)
	if err != nil {
		return nil, err
	}
	// The server first: its escrow is what the trustee could still get.
	// If it cannot be told, nothing is changed here.
	if s != nil {
		if err := s.client.RevokeGrant(ctx, g.ID); err != nil && !errors.Is(err, svsync.ErrNotFound) {
			return nil, syncErr(err)
		}
	} else {
		g.Problems = append(g.Problems, "the vault no longer syncs, so its server was not told: it may still hold the grant")
	}
	slots, err := mv.v.Slots()
	if err != nil {
		return nil, err
	}
	for _, sl := range slots {
		if sl.Type == svformat.SlotEmergency && sl.Grant.String() == g.ID {
			if err := mv.v.RemoveSlot(sl.ID); err != nil {
				return nil, fmt.Errorf("the grant was revoked on the server, but its keyslot could not be removed: %w", err)
			}
		}
	}
	recs, err := grantRecords(mv.v)
	if err != nil {
		return nil, err
	}
	wipeGrants(recs)
	if e := recs[g.ID]; e != nil {
		if err := mv.v.DeleteRecord(e.record); err != nil {
			return nil, err
		}
	}
	who := g.Trustee
	if who == "" {
		who = "the trustee"
	}
	d.recorder(cl, mv, "", svbroker.OpManage)("allowed", fmt.Sprintf("revoked %s's emergency access (grant %s)", who, g.ID))
	if s != nil {
		s.em.check(d, mv, s)
	}
	return g, nil
}

// emergencyCarry is what a rotation of mv needs to keep its emergency
// grants: one keyslot for the new epoch for each grant that a keyslot of
// the current epoch names and the vault has a record of. The new slot is
// made from the record (its recipient and release key), never from the
// slot files, which anyone who can write to the folder could have
// planted. Slots naming a grant with no record are returned as lost.
// Wipe the specs' release keys when done.
func emergencyCarry(mv *managedVault) (specs []svcore.NewSlot, lost []svcore.SlotInfo, err error) {
	slots, err := mv.v.Slots()
	if err != nil {
		return nil, nil, err
	}
	recs, err := grantRecords(mv.v)
	if err != nil {
		return nil, nil, err
	}
	defer wipeGrants(recs)
	epoch := mv.v.Epoch()
	carried := map[svformat.ID]bool{}
	for _, s := range slots {
		if s.Type != svformat.SlotEmergency || s.Epoch != epoch || carried[s.Grant] {
			continue
		}
		e := recs[s.Grant.String()]
		var pub []byte
		if e != nil {
			var suite svcrypto.Suite
			if suite, pub, err = svformat.ParseRecipient(e.Recipient); err != nil || suite != mv.v.Suite() {
				pub = nil
			}
		}
		if pub == nil || len(e.Release) != svformat.ReleaseKeySize {
			lost = append(lost, s)
			continue
		}
		carried[s.Grant] = true
		specs = append(specs, svcore.NewSlot{Type: svformat.SlotEmergency, Label: "emergency", Recipient: pub, Grant: s.Grant,
			ReleaseKey: slices.Clone(e.Release)})
	}
	return specs, lost, nil
}

// notEmergency refuses to remove or leave out keyslots of emergency
// access on their own: that ends a grant only half (the server would
// still hold it, and the vault's record could bring it back), which is
// what 'emergency revoke' is for.
func notEmergency(mv *managedVault, ids []string) error {
	slots, err := mv.v.Slots()
	if err != nil {
		return err
	}
	for _, s := range slots {
		if s.Type == svformat.SlotEmergency && slices.Contains(ids, s.ID.String()) {
			return svrpc.Errorf(svrpc.CodeInvalidParams,
				"keyslot %s is emergency access (grant %s): end it with 'secretvault emergency revoke %s', with --rotate to cut the trustee off",
				s.ID, s.Grant, short(s.Grant.String()))
		}
	}
	return nil
}

// Hearing of requests: every synced vault of the person's own keeps an
// emergencyWatch.

// emergencyWatch is what a vault's grants were when last looked at.
type emergencyWatch struct {
	ctx  context.Context
	url  string // the server's
	path string // where seen is kept

	mu       sync.Mutex
	seen     map[string]string       // grant → what was last told of it ("requested <time>", ...)
	pending  map[string]svsync.Grant // grants requested or released, as the server last said: for daemon.status
	names    map[string]string       // grant → the trustee, from the vault's records
	stops    map[string]func()       // grant → takes down the notice showing
	last     time.Time               // when the grants were last looked at
	checking bool                    // a look is under way
	again    bool                    // and another is due after it
	loaded   bool                    // seen was read from disk
}

func (d *Daemon) newEmergencyWatch(ctx context.Context, r svsync.Remote) *emergencyWatch {
	return &emergencyWatch{
		ctx:  ctx,
		url:  r.URL,
		path: strings.TrimSuffix(d.syncStatePath(r), ".json") + ".emergency.json",
		seen: map[string]string{}, pending: map[string]svsync.Grant{}, names: map[string]string{}, stops: map[string]func(){},
	}
}

// named remembers a grant's trustee, from the vault's record of it.
func (w *emergencyWatch) named(grant, name string) {
	if w == nil || name == "" {
		return
	}
	w.mu.Lock()
	w.names[grant] = name
	w.mu.Unlock()
}

// emergencySynced looks at a synced vault's grants after a sync that saw
// them change, the first after the daemon started, and now and then:
// after failed syncs too (a vault that cannot sync, for a reason of its
// own, must still hear of requests). The watcher calls it at least every
// few minutes, failing or not.
func (d *Daemon) emergencySynced(mv *managedVault, s *vaultSync, rep svsync.Report, _ error) {
	if mv.cfg.Emergency != "" || s.em == nil {
		return
	}
	w := s.em
	w.mu.Lock()
	due := rep.Events > 0 || w.last.IsZero() || time.Since(w.last) >= emergencyRecheck
	w.mu.Unlock()
	if due {
		go w.check(d, mv, s)
	}
}

// check asks the server for the vault's grants and tells the person what
// changed. Looks do not overlap: one asked for during another follows it.
func (w *emergencyWatch) check(d *Daemon, mv *managedVault, s *vaultSync) {
	w.mu.Lock()
	if w.checking {
		w.again = true
		w.mu.Unlock()
		return
	}
	w.checking = true
	w.mu.Unlock()
	for {
		ctx, cancel := context.WithTimeout(w.ctx, time.Minute)
		grants, err := s.client.Grants(ctx)
		cancel()
		switch {
		case err == nil:
			d.emergencySeen(mv, w, grants)
		case errors.Is(err, svsync.ErrNotFound):
			// A server from before emergency access: nothing to hear.
		case w.ctx.Err() == nil:
			d.opts.Log(fmt.Sprintf("emergency grants of %s: %v", mv.cfg.Name, err))
		}
		w.mu.Lock()
		w.last = time.Now()
		if !w.again || w.ctx.Err() != nil {
			w.checking = false
			w.mu.Unlock()
			return
		}
		w.again = false
		w.mu.Unlock()
	}
}

// stateOf is what about a grant the person is told of, once: a request,
// a release, a denial. "" for nothing.
func stateOf(g svsync.Grant) string {
	switch {
	case g.State == svserver.GrantReleased && g.Released != nil:
		return "released " + g.Released.UTC().Format(time.RFC3339Nano)
	case g.State == svserver.GrantRequested && g.Requested != nil:
		return "requested " + g.Requested.UTC().Format(time.RFC3339Nano)
	case g.Denied != nil:
		return "denied " + g.Denied.UTC().Format(time.RFC3339Nano)
	}
	return ""
}

type seenDoc struct {
	Format string            `json:"format"`
	Seen   map[string]string `json:"seen"`
}

const seenFormat = "secretvault/v1/emergency-seen"

// emergencySeen compares the server's grants with what the person was
// last told, and tells them what changed: in the audit log, as a notice
// on the desktop, to clients, and in daemon.status. What was told is kept
// on disk, so a restart does not tell it again.
func (d *Daemon) emergencySeen(mv *managedVault, w *emergencyWatch, grants []svsync.Grant) {
	if !mv.v.Locked() {
		if recs, err := grantRecords(mv.v); err == nil {
			for id, e := range recs {
				w.named(id, e.Trustee)
			}
			wipeGrants(recs)
		}
	}
	w.mu.Lock()
	if !w.loaded {
		w.loaded = true
		if b, err := os.ReadFile(w.path); err == nil {
			var doc seenDoc
			if json.Unmarshal(b, &doc) == nil && doc.Format == seenFormat && doc.Seen != nil {
				w.seen = doc.Seen
			}
		}
	}
	current := map[string]svsync.Grant{}
	type told struct {
		g     svsync.Grant
		state string
	}
	var news []told
	for _, g := range grants {
		current[g.ID] = g
		st := stateOf(g)
		if st != "" && w.seen[g.ID] != st {
			w.seen[g.ID] = st
			news = append(news, told{g, strings.Fields(st)[0]})
		}
	}
	forgot := false
	for id := range w.seen {
		if _, ok := current[id]; !ok {
			delete(w.seen, id) // revoked
			forgot = true
		}
	}
	// A notice of a request goes once the request is settled; one of a
	// release stays until dismissed.
	var stop []func()
	for id, f := range w.stops {
		if g, ok := current[id]; !ok || g.State == svserver.GrantAccepted {
			stop = append(stop, f)
			delete(w.stops, id)
		}
	}
	w.pending = map[string]svsync.Grant{}
	for id, g := range current {
		if g.State == svserver.GrantRequested || g.State == svserver.GrantReleased {
			w.pending[id] = g
		}
	}
	names := maps.Clone(w.names)
	var save []byte
	if len(news) > 0 || forgot {
		save, _ = json.Marshal(seenDoc{Format: seenFormat, Seen: w.seen})
	}
	w.mu.Unlock()

	for _, f := range stop {
		f()
	}
	// Told first, then remembered as told: a crash between tells it
	// twice, never not at all.
	defer func() {
		if save != nil {
			if err := writeAtomic(w.path, save); err != nil {
				d.opts.Log(fmt.Sprintf("emergency grants of %s: %v", mv.cfg.Name, err))
			}
		}
	}()
	for _, n := range news {
		who := names[n.g.ID]
		text := grantNotice(mv.cfg.Name, who, n.g)
		d.audit.Record(mv.v, svbroker.Entry{Time: d.opts.Now().UTC(), Program: "emergency access", Identity: "server:" + w.url,
			Op: svbroker.OpManage, Outcome: n.state, Reason: text})
		d.opts.Log(fmt.Sprintf("vault %s: emergency grant %s %s", mv.cfg.Name, n.g.ID, n.state))
		switch n.state {
		case "requested":
			d.showNotice(w, n.g.ID, svrpc.PromptAsk{Kind: svrpc.PromptNotice, Title: "Emergency access to vault " + mv.cfg.Name + " was requested",
				Description: text, OK: "Dismiss"})
		case "released":
			d.showNotice(w, n.g.ID, svrpc.PromptAsk{Kind: svrpc.PromptNotice, Title: "Emergency access to vault " + mv.cfg.Name + " was given",
				Description: text, OK: "Dismiss"})
		}
	}
	if len(news) > 0 {
		d.notify(svrpc.EEmergency, svrpc.VaultEvent{Vault: mv.cfg.Name})
	}
}

// short is the start of a grant's ID, for people to type.
func short(id string) string { return id[:min(len(id), 8)] }

// grantNotice says what happened to a grant, and what the owner can do.
func grantNotice(vault, who string, g svsync.Grant) string {
	if who == "" {
		who = "The person you gave emergency access (grant " + short(g.ID) + ")"
	}
	from := ""
	if g.Trustee != nil && g.Trustee.Label != "" {
		from = fmt.Sprintf(", from their device %q", g.Trustee.Label)
	}
	switch {
	case g.State == svserver.GrantReleased && g.Released != nil:
		return fmt.Sprintf("%s was given the key to vault %q on %s%s, after the wait. "+
			"If they were not meant to have it, revoke it and rotate the vault key: 'secretvault --vault %s emergency revoke %s --rotate'.",
			who, vault, when(g.Released), from, vault, short(g.ID))
	case g.State == svserver.GrantRequested && g.Requested != nil:
		return fmt.Sprintf("%s asked for emergency access to vault %q on %s%s. Unless you deny it, they get the vault's key on %s: "+
			"'secretvault --vault %s emergency deny %s'.", who, vault, when(g.Requested), from, when(g.ReleasesAt), vault, short(g.ID))
	case g.Denied != nil:
		return fmt.Sprintf("%s's request for emergency access to vault %q was denied on %s.", who, vault, when(g.Denied))
	}
	return fmt.Sprintf("%s's emergency access to vault %q changed.", who, vault)
}

// showNotice puts a notice about a grant on the desktop (or the terminal
// agent), replacing any about it already showing. It shows until the
// person dismisses it or the request is settled.
func (d *Daemon) showNotice(w *emergencyWatch, grant string, q svrpc.PromptAsk) {
	n, ok := d.consentPrompter(nil).(noticer)
	if !ok {
		return
	}
	ctx, cancel := context.WithCancel(w.ctx)
	done := make(chan struct{})
	w.mu.Lock()
	old := w.stops[grant]
	w.stops[grant] = func() { cancel(); <-done }
	w.mu.Unlock()
	if old != nil {
		old()
	}
	go func() {
		defer close(done)
		stop := n.Notice(ctx, q, cancel)
		<-ctx.Done()
		stop()
	}()
}

// emergencyNotices are what daemon.status says about emergency access.
func (d *Daemon) emergencyNotices() []svrpc.EmergencyNotice {
	var out []svrpc.EmergencyNotice
	d.mu.Lock()
	var all []*managedVault
	for _, mv := range d.vaults {
		all = append(all, mv)
	}
	held := slices.Clone(d.cfg.Emergency)
	d.mu.Unlock()
	for _, mv := range all {
		s := mv.syncer()
		if s == nil || s.em == nil || mv.cfg.Emergency != "" {
			continue
		}
		if mv.v != nil && !mv.v.Locked() {
			if recs, err := grantRecords(mv.v); err == nil {
				for id, e := range recs {
					s.em.named(id, e.Trustee)
				}
				wipeGrants(recs)
			}
		}
		w := s.em
		w.mu.Lock()
		for id, g := range w.pending {
			who := w.names[id]
			out = append(out, svrpc.EmergencyNotice{Vault: mv.cfg.Name, Grant: id, Trustee: who, State: g.State,
				ReleasesAt: g.ReleasesAt, Released: g.Released, Text: grantNotice(mv.cfg.Name, who, g)})
		}
		w.mu.Unlock()
	}
	for _, a := range held {
		switch {
		case a.State == svserver.GrantRequested:
			out = append(out, svrpc.EmergencyNotice{Vault: a.Name, Grant: a.Grant, State: a.State, ReleasesAt: a.ReleasesAt, Held: true,
				Text: fmt.Sprintf("You asked for emergency access to %s on %s. Unless its owner denies it, it is yours on %s: "+
					"then 'secretvault emergency open %s --identity FILE'.", a.label(), when(a.Requested), when(a.ReleasesAt), a.Name)})
		case a.State == svserver.GrantReleased && a.Vault == "":
			out = append(out, svrpc.EmergencyNotice{Vault: a.Name, Grant: a.Grant, State: a.State, Held: true,
				Text: fmt.Sprintf("Emergency access to %s is yours: 'secretvault emergency open %s --identity FILE'.", a.label(), a.Name)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Vault != out[j].Vault {
			return out[i].Vault < out[j].Vault
		}
		return out[i].Grant < out[j].Grant
	})
	return out
}
