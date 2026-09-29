package svsync

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svserver"
)

// Emergency access on the server (svserver/emergency.go): the owner's
// devices make, list, deny and revoke grants; the trustee's device
// accepts one, asks for access, and takes the escrowed release key once
// the wait is over.

// Grant is an emergency grant as the server reports it.
type Grant = svserver.EmergencyGrant

// CreateGrant makes an emergency grant on the server. Making the same
// grant again is not an error.
func (c *Client) CreateGrant(ctx context.Context, g svserver.EmergencyCreate) (Grant, error) {
	body, _ := json.Marshal(g)
	var out Grant
	_, _, err := c.do(ctx, "POST", "/emergency", "", body, &out)
	return out, err
}

// Grants lists the vault's emergency grants.
func (c *Client) Grants(ctx context.Context) ([]Grant, error) {
	var out []Grant
	_, _, err := c.do(ctx, "GET", "/emergency", "", nil, &out)
	return out, err
}

// Grant reports one grant: to a device of the vault, or to its trustee.
func (c *Client) Grant(ctx context.Context, id string) (Grant, error) {
	var out Grant
	_, _, err := c.do(ctx, "GET", "/emergency/"+id, "", nil, &out)
	return out, err
}

// DenyGrant refuses a grant's pending request.
func (c *Client) DenyGrant(ctx context.Context, id string) (Grant, error) {
	var out Grant
	_, _, err := c.do(ctx, "POST", "/emergency/"+id+"/deny", "", nil, &out)
	return out, err
}

// RevokeGrant forgets a grant on the server, with its escrow and its
// trustee's access. ErrNotFound means there was none.
func (c *Client) RevokeGrant(ctx context.Context, id string) error {
	_, _, err := c.do(ctx, "DELETE", "/emergency/"+id, "", nil, nil)
	return err
}

// GrantChallenge fetches the code a grant's owner sealed to its trustee,
// which accepting it takes.
func (c *Client) GrantChallenge(ctx context.Context, id string) ([]byte, error) {
	var out svserver.EmergencyChallenge
	_, _, err := c.do(ctx, "GET", "/emergency/"+id+"/challenge", "", nil, &out)
	return out.Challenge, err
}

// AcceptGrant makes this device the grant's trustee device, with the code
// opened from its challenge. Accepting again is not an error.
func (c *Client) AcceptGrant(ctx context.Context, id string, code []byte, label string) (Grant, error) {
	body, _ := json.Marshal(svserver.EmergencyAccept{Code: code, Label: label})
	var out Grant
	_, _, err := c.do(ctx, "POST", "/emergency/"+id+"/trustee", "", body, &out)
	return out, err
}

// RequestAccess asks for access with a grant this device accepted: the
// wait starts, unless a request is already pending.
func (c *Client) RequestAccess(ctx context.Context, id string) (Grant, error) {
	var out Grant
	_, _, err := c.do(ctx, "POST", "/emergency/"+id+"/request", "", nil, &out)
	return out, err
}

// ReleaseAccess takes a grant's escrowed release key (sealed to the
// trustee), once the wait has passed with no denial. Before that the
// server answers ErrConflict, saying when.
func (c *Client) ReleaseAccess(ctx context.Context, id string) (svserver.EmergencyRelease, error) {
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
	if id, err := svformat.ParseID(i.Grant); err != nil || id.String() != i.Grant {
		return EmergencyInvite{}, errors.New("svsync: the invite's grant is not 32 lowercase hex digits")
	}
	if id, err := svformat.ParseID(i.VaultID); err != nil || id.String() != i.VaultID {
		return EmergencyInvite{}, errors.New("svsync: the invite's vault ID is not 32 lowercase hex digits")
	}
	if b, err := hex.DecodeString(i.Check); err != nil || len(b) != 16 {
		return EmergencyInvite{}, errors.New("svsync: the invite's check value is not 16 bytes in hex")
	}
	return i, nil
}
