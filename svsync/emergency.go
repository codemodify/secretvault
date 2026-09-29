package svsync

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svserver"
)

// Emergency access on the server (svserver/emergency.go): the owner's
// devices make, list, deny and revoke grants; the trustee's device
// accepts one, asks for access, and takes the escrowed release key once
// the wait is over.

// Grant is an emergency grant as the server reports it.
type Grant = svserver.EmergencyGrant

// ErrBadGrant is an answer about a grant that is not one: a malformed ID,
// or another grant than the one asked about. What a server says is
// checked before anything acts on it.
var ErrBadGrant = errors.New("svsync: the server's answer about an emergency grant does not make sense")

// validGrantID accepts a grant's ID as the format writes it: 32
// lowercase hex digits.
func validGrantID(s string) bool {
	id, err := svformat.ParseID(s)
	return err == nil && id.String() == s
}

// grantCall makes a call that answers one grant, and checks the answer is
// about grant id.
func (c *Client) grantCall(ctx context.Context, method, suffix, id string, body []byte) (Grant, error) {
	if !validGrantID(id) {
		return Grant{}, fmt.Errorf("svsync: %q is not a grant's ID", id)
	}
	var out Grant
	if _, _, err := c.do(ctx, method, "/emergency"+suffix, "", body, &out); err != nil {
		return Grant{}, err
	}
	if out.ID != id {
		return Grant{}, ErrBadGrant
	}
	return out, nil
}

// CreateGrant makes an emergency grant on the server. Making the same
// grant again is not an error.
func (c *Client) CreateGrant(ctx context.Context, g svserver.EmergencyCreate) (Grant, error) {
	body, _ := json.Marshal(g)
	return c.grantCall(ctx, "POST", "", g.ID, body)
}

// Grants lists the vault's emergency grants. Any the server lists with an
// ID that is not one are left out, as are any beyond the most a vault can
// have.
func (c *Client) Grants(ctx context.Context) ([]Grant, error) {
	var list []Grant
	if _, _, err := c.do(ctx, "GET", "/emergency", "", nil, &list); err != nil {
		return nil, err
	}
	out := []Grant{}
	seen := map[string]bool{}
	for _, g := range list {
		if validGrantID(g.ID) && !seen[g.ID] && len(out) < svserver.MaxGrants {
			seen[g.ID] = true
			out = append(out, g)
		}
	}
	return out, nil
}

// Grant reports one grant: to a device of the vault, or to its trustee.
func (c *Client) Grant(ctx context.Context, id string) (Grant, error) {
	return c.grantCall(ctx, "GET", "/"+id, id, nil)
}

// DenyGrant refuses a grant's pending request.
func (c *Client) DenyGrant(ctx context.Context, id string) (Grant, error) {
	return c.grantCall(ctx, "POST", "/"+id+"/deny", id, nil)
}

// RevokeGrant forgets a grant on the server, with its escrow and its
// trustee's access. ErrNotFound means there was none.
func (c *Client) RevokeGrant(ctx context.Context, id string) error {
	if !validGrantID(id) {
		return fmt.Errorf("svsync: %q is not a grant's ID", id)
	}
	_, _, err := c.do(ctx, "DELETE", "/emergency/"+id, "", nil, nil)
	return err
}

// GrantChallenge fetches what a grant's owner sealed to its trustee for
// accepting it: the seed of a signing key (svformat.EmergencyChallengeInfo).
func (c *Client) GrantChallenge(ctx context.Context, id string) ([]byte, error) {
	if !validGrantID(id) {
		return nil, fmt.Errorf("svsync: %q is not a grant's ID", id)
	}
	var out svserver.EmergencyChallenge
	_, _, err := c.do(ctx, "GET", "/emergency/"+id+"/challenge", "", nil, &out)
	return out.Challenge, err
}

// AcceptGrant makes this device the grant's trustee device, with the seed
// opened from its challenge: it signs, with the key the seed makes, that
// this device accepts this grant of this vault
// (svserver.EmergencyAcceptMessage). The seed never leaves this device.
// Accepting again is not an error, and needs no seed.
func (c *Client) AcceptGrant(ctx context.Context, id string, seed []byte, label string) (Grant, error) {
	var proof []byte
	if len(seed) == ed25519.SeedSize {
		key := ed25519.NewKeyFromSeed(seed)
		proof = ed25519.Sign(key, svserver.EmergencyAcceptMessage(c.remote.Vault, id, c.id.Key()))
		clear(key)
	}
	body, _ := json.Marshal(svserver.EmergencyAccept{Proof: proof, Label: label})
	return c.grantCall(ctx, "POST", "/"+id+"/trustee", id, body)
}

// RequestAccess asks for access with a grant this device accepted: the
// wait starts, unless a request is already pending.
func (c *Client) RequestAccess(ctx context.Context, id string) (Grant, error) {
	return c.grantCall(ctx, "POST", "/"+id+"/request", id, nil)
}

// ReleaseAccess takes a grant's escrowed release key (sealed to the
// trustee), once the wait has passed with no denial. Before that the
// server answers ErrConflict, saying when.
func (c *Client) ReleaseAccess(ctx context.Context, id string) (svserver.EmergencyRelease, error) {
	if !validGrantID(id) {
		return svserver.EmergencyRelease{}, fmt.Errorf("svsync: %q is not a grant's ID", id)
	}
	var out svserver.EmergencyRelease
	_, _, err := c.do(ctx, "POST", "/emergency/"+id+"/release", "", nil, &out)
	return out, err
}

// EmergencyInvite is what a vault's owner sends the person they grant
// emergency access: where the vault is, which grant, and what the vault
// is, so the trustee's device can tell it gets the vault it was granted
// and not another a server made up. It holds no secret: accepting the
// grant takes the trustee's identity.
type EmergencyInvite struct {
	Remote

	// Grant is the grant's ID.
	Grant string

	// VaultID is the vault's own ID, and Check its first epoch's check
	// value (vault.json), in hex.
	VaultID string
	Check   string

	// Name is what the owner calls the vault, for people.
	Name string
}

const emergencyScheme = "secretvault-emergency"

// String writes the invite as a URI:
//
//	secretvault-emergency:?url=...&vault=...&fp=...&grant=...&id=...&check=...&name=...
func (i EmergencyInvite) String() string {
	q := url.Values{}
	q.Set("url", i.URL)
	q.Set("vault", i.Vault)
	if i.Fingerprint != "" {
		q.Set("fp", i.Fingerprint)
	}
	q.Set("grant", i.Grant)
	q.Set("id", i.VaultID)
	q.Set("check", i.Check)
	if i.Name != "" {
		q.Set("name", i.Name)
	}
	return emergencyScheme + ":?" + q.Encode()
}

// ParseEmergencyInvite reads an invite as String writes it.
func ParseEmergencyInvite(s string) (EmergencyInvite, error) {
	rest, ok := strings.CutPrefix(strings.TrimSpace(s), emergencyScheme+":?")
	if !ok {
		return EmergencyInvite{}, errors.New("svsync: not an emergency access invite")
	}
	q, err := url.ParseQuery(rest)
	if err != nil {
		return EmergencyInvite{}, fmt.Errorf("svsync: not an emergency access invite: %w", err)
	}
	i := EmergencyInvite{
		Remote: Remote{URL: q.Get("url"), Vault: q.Get("vault"), Fingerprint: q.Get("fp")},
		Grant:  q.Get("grant"), VaultID: q.Get("id"), Check: q.Get("check"), Name: q.Get("name"),
	}
	if _, err := i.base(); err != nil {
		return EmergencyInvite{}, err
	}
	if !validGrantID(i.Grant) {
		return EmergencyInvite{}, errors.New("svsync: the invite's grant is not 32 lowercase hex digits")
	}
	if id, err := svformat.ParseID(i.VaultID); err != nil || id.String() != i.VaultID {
		return EmergencyInvite{}, errors.New("svsync: the invite's vault ID is not 32 lowercase hex digits")
	}
	if b, err := hex.DecodeString(i.Check); err != nil || len(b) != 16 {
		return EmergencyInvite{}, errors.New("svsync: the invite's check value is not 16 bytes in hex")
	}
	if err := checkInviteName(i.Name); err != nil {
		return EmergencyInvite{}, err
	}
	return i, nil
}

// checkInviteName accepts what an invite may call a vault: it is shown to
// people, so it is short, and holds no control characters (nothing that
// could drive a terminal).
func checkInviteName(s string) error {
	if len(s) > 128 || !utf8.ValidString(s) || strings.ContainsFunc(s, unicode.IsControl) {
		return errors.New("svsync: the invite's name is at most 128 bytes of text, with no control characters")
	}
	return nil
}
