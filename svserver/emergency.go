package svserver

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/codemodify/secretvault/svstore"
)

// Emergency access: the server's half.
//
// A vault's owner can let a person they trust (the trustee) into the
// vault after a waiting period, during which any of the owner's devices
// can refuse. The owner's device makes an emergency keyslot that opens
// only with the trustee's identity and a random release key together
// (docs/format.md), and gives the server a grant: the release key sealed
// to the trustee (the escrow), the wait, and the seed of a signing key
// sealed to the trustee (the challenge) with the key's public half. The
// server keeps the escrow, and the clock:
//
//  1. The trustee's device accepts the grant by opening the challenge
//     (the seed of an Ed25519 key, sealed to the trustee) with the
//     trustee's identity, and signing EmergencyAcceptMessage with that
//     key: the vault, the grant, and the device's own key, which becomes
//     the grant's trustee device. The server keeps only the public key.
//     Only the holder of the identity can accept, and what it signs is
//     good for its own device alone, so the invite the owner sends the
//     trustee (where the vault is, and the grant's ID) holds no secret,
//     and a trustee tricked into accepting through someone else's
//     server gives that server nothing it can accept with.
//  2. The trustee's device asks for access: the wait starts, on the
//     server's clock, and every device of the vault hears of it through
//     the change log (an OpEvent).
//  3. Any device of the vault can deny it, which ends the request; the
//     trustee may ask again, and each time the wait starts over.
//  4. Once the wait has passed with no denial, the trustee's device can
//     take the escrow, and from then on read the vault's files and
//     change log (never write them).
//
// Revoking a grant forgets it, its escrow and its trustee's access.
//
// The server never holds the release key in the clear, only sealed to the
// trustee, and never the trustee's identity: nothing it keeps opens
// anything. What it is trusted with is time. A server that lies (about
// the clock, or by giving the escrow early) gives the trustee access
// early, and one that hides a request keeps the owner from refusing it:
// docs/security.md says so plainly.
//
// Grants are kept in emergency.json beside devices.json, replaced whole
// on each change, so they and their clocks survive a restart.

// States of a grant, as EmergencyGrant.State says them.
const (
	GrantInvited   = "invited"   // no trustee's device has accepted it yet
	GrantAccepted  = "accepted"  // accepted; no request is pending
	GrantRequested = "requested" // the trustee asked; the wait is running
	GrantReleased  = "released"  // the escrow was given to the trustee
)

// Limits on grants.
const (
	// MaxGrants is how many grants a vault may have at once.
	MaxGrants = 32

	// MaxEmergencyWait is the longest waiting period a grant may have.
	MaxEmergencyWait = 366 * 24 * time.Hour

	// maxSealed caps an escrow or a challenge: an HPKE message to a
	// hybrid recipient of 32 bytes is about 1.2 KiB.
	maxSealed = 4 << 10
)

// EmergencyCreate is the body of POST /v1/vaults/{vault}/emergency.
type EmergencyCreate struct {
	// ID names the grant: 32 lowercase hex digits, chosen by the owner's
	// device, since the keyslot names it too.
	ID string `json:"id"`

	// Wait is the waiting period, in seconds.
	Wait int64 `json:"wait"`

	// Escrow is the release key, sealed to the trustee.
	Escrow []byte `json:"escrow"`

	// Challenge is the seed of an Ed25519 key, sealed to the trustee, and
	// AcceptKey its public key: the trustee's device accepts the grant by
	// signing EmergencyAcceptMessage with it.
	Challenge []byte `json:"challenge"`
	AcceptKey []byte `json:"accept_key"`
}

// EmergencyTrustee is the device that accepted a grant.
type EmergencyTrustee struct {
	Key      string    `json:"key"` // its Ed25519 key, as devices are named
	Label    string    `json:"label,omitempty"`
	Accepted time.Time `json:"accepted"`
}

// EmergencyGrant is a grant as the server reports it: never its escrow.
type EmergencyGrant struct {
	ID        string            `json:"id"`
	Created   time.Time         `json:"created"`
	CreatedBy string            `json:"created_by,omitempty"` // the device that made it
	Wait      int64             `json:"wait"`                 // seconds
	State     string            `json:"state"`                // GrantInvited, ...
	Trustee   *EmergencyTrustee `json:"trustee,omitempty"`

	// Requested is when the pending request was made, and ReleasesAt when
	// its wait ends (both only while one is pending, or once released).
	Requested  *time.Time `json:"requested,omitempty"`
	ReleasesAt *time.Time `json:"releases_at,omitempty"`

	// Denied is when a request was last refused, and by which device.
	Denied   *time.Time `json:"denied,omitempty"`
	DeniedBy string     `json:"denied_by,omitempty"`

	Released *time.Time `json:"released,omitempty"`

	// Now is the server's clock as it answered: waits run on it.
	Now time.Time `json:"now"`
}

// EmergencyChallenge answers GET .../emergency/{grant}/challenge.
type EmergencyChallenge struct {
	Challenge []byte `json:"challenge"`
}

// EmergencyAccept is the body of POST .../emergency/{grant}/trustee.
type EmergencyAccept struct {
	// Proof is EmergencyAcceptMessage for this vault, grant and signing
	// device, signed with the key whose seed the challenge holds.
	Proof []byte `json:"proof"`
	Label string `json:"label,omitempty"` // the trustee's device, for the owner to see
}

// EmergencyAcceptMessage is what a trustee's device signs to accept a
// grant: the vault's name on the server, the grant, and its own device
// key, as the server names them.
//
//	"secretvault sv1 emergency accept\n" + vault + "\n" + grant + "\n" + device
func EmergencyAcceptMessage(vault, grant, device string) []byte {
	return []byte("secretvault sv1 emergency accept\n" + vault + "\n" + grant + "\n" + device)
}

// EmergencyRelease answers POST .../emergency/{grant}/release.
type EmergencyRelease struct {
	Escrow   []byte    `json:"escrow"`
	Released time.Time `json:"released"`
}

const (
	emergencyFile   = "emergency.json"
	emergencyFormat = "secretvault-server/v1/emergency"
)

// grantRec is a grant as it is kept.
type grantRec struct {
	ID        string            `json:"id"`
	Created   time.Time         `json:"created"`
	CreatedBy string            `json:"created_by"`
	Wait      int64             `json:"wait"`
	Escrow    []byte            `json:"escrow"`
	Challenge []byte            `json:"challenge,omitempty"`  // until accepted
	AcceptKey []byte            `json:"accept_key,omitempty"` // until accepted
	Trustee   *EmergencyTrustee `json:"trustee,omitempty"`
	Requested *time.Time        `json:"requested,omitempty"`
	Denied    *time.Time        `json:"denied,omitempty"`
	DeniedBy  string            `json:"denied_by,omitempty"`
	Released  *time.Time        `json:"released,omitempty"`
}

type grantsDoc struct {
	Format string      `json:"format"`
	Grants []*grantRec `json:"grants"`
}

func (g *grantRec) clone() *grantRec {
	c := *g
	return &c
}

func (g *grantRec) releasesAt() time.Time {
	return g.Requested.Add(time.Duration(g.Wait) * time.Second)
}

func (g *grantRec) view(now time.Time) EmergencyGrant {
	out := EmergencyGrant{ID: g.ID, Created: g.Created, CreatedBy: g.CreatedBy, Wait: g.Wait, Trustee: g.Trustee,
		Requested: g.Requested, Denied: g.Denied, DeniedBy: g.DeniedBy, Released: g.Released, Now: now.UTC()}
	switch {
	case g.Released != nil:
		out.State = GrantReleased
	case g.Requested != nil:
		out.State = GrantRequested
	case g.Trustee != nil:
		out.State = GrantAccepted
	default:
		out.State = GrantInvited
	}
	if g.Requested != nil {
		at := g.releasesAt().UTC()
		out.ReleasesAt = &at
	}
	return out
}

// validGrantID accepts the canonical form of a grant's ID: 32 lowercase
// hex digits.
func validGrantID(s string) bool {
	if len(s) != 32 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func loadGrants(meta *svstore.Dir, dir string) ([]*grantRec, error) {
	b, err := meta.Read(emergencyFile)
	if errors.Is(err, svstore.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var doc grantsDoc
	if err := json.Unmarshal(b, &doc); err != nil || doc.Format != emergencyFormat {
		return nil, fmt.Errorf("svserver: %s/%s is damaged", dir, emergencyFile)
	}
	return doc.Grants, nil
}

// saveGrants writes emergency.json; on failure the old grants are kept.
// The caller holds v.mu.
func (v *vault) saveGrants(grants []*grantRec) error {
	b, err := json.MarshalIndent(grantsDoc{Format: emergencyFormat, Grants: grants}, "", "  ")
	if err != nil {
		return err
	}
	if err := v.meta.Write(emergencyFile, append(b, '\n')); err != nil {
		return err
	}
	v.grants = grants
	return nil
}

func (v *vault) findGrant(id string) int {
	return slices.IndexFunc(v.grants, func(g *grantRec) bool { return g.ID == id })
}

// isTrustee reports whether device accepted grant id.
func (v *vault) isTrustee(id, device string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	i := v.findGrant(id)
	return i >= 0 && v.grants[i].Trustee != nil && v.grants[i].Trustee.Key == device
}

// releasedTo reports whether device is the trustee of a grant released
// to it: it may then read the vault's files.
func (v *vault) releasedTo(device string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	for _, g := range v.grants {
		if g.Released != nil && g.Trustee != nil && g.Trustee.Key == device {
			return true
		}
	}
	return false
}

var (
	errNoGrant       = errors.New("no such grant")
	errGrantExists   = errors.New("a different grant of that ID exists")
	errTooManyGrants = fmt.Errorf("a vault has at most %d emergency grants", MaxGrants)
)

// statusError is a refusal with the HTTP status to answer it with.
type statusError struct {
	status int
	msg    string
}

func (e *statusError) Error() string { return e.msg }

func refuse(status int, format string, args ...any) error {
	return &statusError{status, fmt.Sprintf(format, args...)}
}

// changeGrant applies change to a copy of grant id, saves it, and logs
// the event every device of the vault hears of. The caller holds v.mu.
func (v *vault) changeGrant(id string, change func(g *grantRec) error) (*grantRec, error) {
	i := v.findGrant(id)
	if i < 0 {
		return nil, errNoGrant
	}
	g := v.grants[i].clone()
	if err := change(g); err != nil {
		return nil, err
	}
	next := slices.Clone(v.grants)
	next[i] = g
	if err := v.saveGrants(next); err != nil {
		return nil, err
	}
	v.grantEvent(id)
	return g, nil
}

// grantEvent tells the vault's devices that grant id changed. It is
// logged after the change is saved, so a device that asks finds it; if
// logging fails, devices learn of it at their next periodic look.
func (v *vault) grantEvent(id string) {
	v.logChange(Change{Op: OpEvent, Name: EmergencyEvent + id})
}

func (s *Server) createGrant(w http.ResponseWriter, r *http.Request, req *request) {
	var in EmergencyCreate
	if err := json.Unmarshal(req.body, &in); err != nil {
		fail(w, http.StatusBadRequest, "the body is not a grant")
		return
	}
	switch {
	case !validGrantID(in.ID):
		fail(w, http.StatusBadRequest, "a grant is named by 32 lowercase hex digits")
		return
	case in.Wait < 0 || in.Wait > int64(MaxEmergencyWait/time.Second): // in seconds: a Duration would overflow
		fail(w, http.StatusBadRequest, fmt.Sprintf("the wait is from 0 to %d seconds", int64(MaxEmergencyWait/time.Second)))
		return
	case len(in.Escrow) == 0 || len(in.Escrow) > maxSealed || len(in.Challenge) == 0 || len(in.Challenge) > maxSealed || len(in.AcceptKey) != ed25519.PublicKeySize:
		fail(w, http.StatusBadRequest, "a grant needs its escrow, its challenge and the key accepting it takes")
		return
	}
	v := req.vault
	v.mu.Lock()
	defer v.mu.Unlock()
	if i := v.findGrant(in.ID); i >= 0 {
		g := v.grants[i]
		if g.Wait == in.Wait && bytes.Equal(g.Escrow, in.Escrow) && g.CreatedBy == req.device {
			reply(w, http.StatusOK, g.view(req.now)) // a retry
			return
		}
		fail(w, http.StatusConflict, errGrantExists.Error())
		return
	}
	if len(v.grants) >= MaxGrants {
		fail(w, http.StatusConflict, errTooManyGrants.Error())
		return
	}
	g := &grantRec{ID: in.ID, Created: req.now.UTC(), CreatedBy: req.device, Wait: in.Wait,
		Escrow: in.Escrow, Challenge: in.Challenge, AcceptKey: in.AcceptKey}
	if err := v.saveGrants(append(slices.Clone(v.grants), g)); err != nil {
		s.internal(w, err)
		return
	}
	v.grantEvent(g.ID)
	s.cfg.Log(fmt.Sprintf("vault %s: emergency grant %s made by device %s (wait %v)", req.name, g.ID, req.device, time.Duration(g.Wait)*time.Second))
	reply(w, http.StatusCreated, g.view(req.now))
}

func (s *Server) listGrants(w http.ResponseWriter, r *http.Request, req *request) {
	v := req.vault
	v.mu.Lock()
	out := make([]EmergencyGrant, 0, len(v.grants))
	for _, g := range v.grants {
		out = append(out, g.view(req.now))
	}
	v.mu.Unlock()
	reply(w, http.StatusOK, out)
}

func (s *Server) getGrant(w http.ResponseWriter, r *http.Request, req *request) {
	v := req.vault
	v.mu.Lock()
	defer v.mu.Unlock()
	i := v.findGrant(req.grant)
	if i < 0 {
		fail(w, http.StatusNotFound, errNoGrant.Error())
		return
	}
	g := v.grants[i].view(req.now)
	if v.findDevice(req.device) < 0 {
		// The trustee: the owner's devices are not theirs to know.
		g.CreatedBy, g.DeniedBy = "", ""
	}
	reply(w, http.StatusOK, g)
}

func (s *Server) revokeGrant(w http.ResponseWriter, r *http.Request, req *request) {
	v := req.vault
	v.mu.Lock()
	defer v.mu.Unlock()
	i := v.findGrant(req.grant)
	if i < 0 {
		fail(w, http.StatusNotFound, errNoGrant.Error())
		return
	}
	if err := v.saveGrants(slices.Delete(slices.Clone(v.grants), i, i+1)); err != nil {
		s.internal(w, err)
		return
	}
	v.grantEvent(req.grant)
	s.cfg.Log(fmt.Sprintf("vault %s: emergency grant %s revoked by device %s", req.name, req.grant, req.device))
	w.WriteHeader(http.StatusNoContent)
}

// answerGrant answers the outcome of changeGrant.
func (s *Server) answerGrant(w http.ResponseWriter, g *grantRec, now time.Time, err error) {
	var se *statusError
	switch {
	case errors.As(err, &se):
		fail(w, se.status, se.msg)
	case errors.Is(err, errNoGrant):
		fail(w, http.StatusNotFound, err.Error())
	case err != nil:
		s.internal(w, err)
	default:
		reply(w, http.StatusOK, g.view(now))
	}
}

func (s *Server) denyGrant(w http.ResponseWriter, r *http.Request, req *request) {
	v := req.vault
	v.mu.Lock()
	defer v.mu.Unlock()
	g, err := v.changeGrant(req.grant, func(g *grantRec) error {
		switch {
		case g.Released != nil:
			return refuse(http.StatusConflict, "the release key was given to the trustee on %s: revoke the grant and rotate the vault key", g.Released.UTC().Format(time.RFC3339))
		case g.Requested == nil:
			return refuse(http.StatusConflict, "no request for that grant is pending")
		}
		now := req.now.UTC()
		g.Requested, g.Denied, g.DeniedBy = nil, &now, req.device
		return nil
	})
	if err == nil {
		s.cfg.Log(fmt.Sprintf("vault %s: emergency grant %s: request denied by device %s", req.name, req.grant, req.device))
	}
	s.answerGrant(w, g, req.now, err)
}

// lookupGrant finds the vault and grant of an anyKey route, answering
// for itself when there is none.
func (s *Server) lookupGrant(w http.ResponseWriter, req *request) (*vault, bool) {
	v, err := s.lookup(req.name)
	if err != nil && !errors.Is(err, errNoVault) {
		s.internal(w, err)
		return nil, false
	}
	if v == nil || req.grant == "" {
		fail(w, http.StatusNotFound, "no such grant")
		return nil, false
	}
	return v, true
}

func (s *Server) grantChallenge(w http.ResponseWriter, r *http.Request, req *request) {
	v, ok := s.lookupGrant(w, req)
	if !ok {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	i := v.findGrant(req.grant)
	switch {
	case i < 0:
		fail(w, http.StatusNotFound, "no such grant")
	case v.grants[i].Trustee != nil:
		fail(w, http.StatusConflict, "that grant was accepted already")
	default:
		reply(w, http.StatusOK, EmergencyChallenge{Challenge: v.grants[i].Challenge})
	}
}

func (s *Server) acceptGrant(w http.ResponseWriter, r *http.Request, req *request) {
	var in EmergencyAccept
	if err := json.Unmarshal(req.body, &in); err != nil {
		fail(w, http.StatusBadRequest, "the body is not an acceptance")
		return
	}
	if err := checkLabel(in.Label); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	v, ok := s.lookupGrant(w, req)
	if !ok {
		return
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	i := v.findGrant(req.grant)
	if i < 0 {
		fail(w, http.StatusNotFound, "no such grant")
		return
	}
	if t := v.grants[i].Trustee; t != nil {
		if t.Key == req.device {
			reply(w, http.StatusOK, v.grants[i].view(req.now)) // a retry
			return
		}
		fail(w, http.StatusConflict, "that grant was accepted already, by another device")
		return
	}
	// Signed for this vault, grant and device, with the key only the
	// trustee's identity opens: good for nobody else's device.
	if key := v.grants[i].AcceptKey; len(key) != ed25519.PublicKeySize || len(in.Proof) != ed25519.SignatureSize ||
		!ed25519.Verify(key, EmergencyAcceptMessage(req.name, req.grant, req.device), in.Proof) {
		fail(w, http.StatusForbidden, "that does not prove the identity the grant was made for, on this device")
		return
	}
	g, err := v.changeGrant(req.grant, func(g *grantRec) error {
		g.Trustee = &EmergencyTrustee{Key: req.device, Label: in.Label, Accepted: req.now.UTC()}
		g.Challenge, g.AcceptKey = nil, nil
		return nil
	})
	if err != nil {
		s.answerGrant(w, nil, req.now, err)
		return
	}
	s.cfg.Log(fmt.Sprintf("vault %s: emergency grant %s accepted by device %s from %s", req.name, req.grant, req.device, clientIP(r)))
	reply(w, http.StatusCreated, g.view(req.now))
}

func (s *Server) requestGrant(w http.ResponseWriter, r *http.Request, req *request) {
	v := req.vault
	v.mu.Lock()
	defer v.mu.Unlock()
	i := v.findGrant(req.grant)
	if i >= 0 && (v.grants[i].Requested != nil || v.grants[i].Released != nil) {
		// Asking again changes nothing: the wait already running is not
		// started over.
		reply(w, http.StatusOK, v.grants[i].view(req.now))
		return
	}
	g, err := v.changeGrant(req.grant, func(g *grantRec) error {
		now := req.now.UTC()
		g.Requested = &now
		return nil
	})
	if err == nil {
		s.cfg.Log(fmt.Sprintf("vault %s: emergency grant %s: access requested by its trustee %s; released at %s unless denied",
			req.name, req.grant, req.device, g.releasesAt().UTC().Format(time.RFC3339)))
	}
	s.answerGrant(w, g, req.now, err)
}

func (s *Server) releaseGrant(w http.ResponseWriter, r *http.Request, req *request) {
	v := req.vault
	v.mu.Lock()
	defer v.mu.Unlock()
	i := v.findGrant(req.grant)
	if i < 0 {
		fail(w, http.StatusNotFound, errNoGrant.Error())
		return
	}
	if g := v.grants[i]; g.Released != nil {
		reply(w, http.StatusOK, EmergencyRelease{Escrow: g.Escrow, Released: *g.Released})
		return
	}
	g, err := v.changeGrant(req.grant, func(g *grantRec) error {
		switch {
		case g.Requested == nil && g.Denied != nil:
			return refuse(http.StatusConflict, "the last request was denied on %s; ask again to start a new wait", g.Denied.UTC().Format(time.RFC3339))
		case g.Requested == nil:
			return refuse(http.StatusConflict, "no request is pending: ask for access first")
		case req.now.Before(g.releasesAt()):
			return refuse(http.StatusConflict, "the wait ends at %s (the server's clock); unless the owner denies the request, the key is released then",
				g.releasesAt().UTC().Format(time.RFC3339))
		}
		now := req.now.UTC()
		g.Released = &now
		return nil
	})
	if err != nil {
		s.answerGrant(w, nil, req.now, err)
		return
	}
	s.cfg.Log(fmt.Sprintf("vault %s: emergency grant %s: released to its trustee %s", req.name, req.grant, req.device))
	reply(w, http.StatusOK, EmergencyRelease{Escrow: g.Escrow, Released: *g.Released})
}
