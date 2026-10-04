package svext

import (
	"errors"
	"fmt"
	"time"

	"github.com/codemodify/secretvault/svcore"
)

// A passkey is kept as a vault item of kind "passkey", like any other
// item: listed, renamed, deleted, synced, exported and audited as items
// are. Its fields:
//
//	rp_id          the relying party's ID ("github.com")
//	url            https:// and the rpId, for people and for exports
//	username       the account's name (user.name)
//	display_name   its display name (user.displayName)
//	credential_id  the credential's ID, base64url
//	user_handle    the RP's user handle (user.id), base64url
//	algorithm      ES256 or EdDSA
//	private_key    the private key, PKCS #8 DER in base64url (a key field)
//	created        when it was made, RFC 3339
//
// There is no signature count: a passkey that is synced keeps it at 0
// (webauthn.go). The faces show the site, the user name and when it was
// made, never the key; only the daemon signs with it.

// PasskeyKind is a passkey item's kind.
const PasskeyKind = svcore.KindPasskey

// Passkey item fields.
const (
	PasskeyRPID         = "rp_id"
	PasskeyURL          = "url"
	PasskeyUserName     = "username"
	PasskeyDisplayName  = "display_name"
	PasskeyCredentialID = "credential_id"
	PasskeyUserHandle   = "user_handle"
	PasskeyAlgorithm    = "algorithm"
	PasskeyPrivateKey   = "private_key"
	PasskeyCreatedField = "created"
)

// PasskeyRecord is a passkey item's contents.
type PasskeyRecord struct {
	RPID         string
	UserName     string
	DisplayName  string
	CredentialID []byte
	UserHandle   []byte
	Alg          int
	PrivateKey   []byte // PKCS #8 DER; the caller wipes it
	Created      time.Time
}

// Wipe zeroes the private key.
func (r *PasskeyRecord) Wipe() {
	clear(r.PrivateKey)
}

// Fields are the record as an item's fields; private_key's value is new
// bytes the item owns.
func (r *PasskeyRecord) Fields() []svcore.Field {
	f := func(name, typ, v string) svcore.Field { return svcore.Field{Name: name, Type: typ, Value: []byte(v)} }
	out := []svcore.Field{
		f(PasskeyRPID, svcore.FieldText, r.RPID),
		f(PasskeyURL, svcore.FieldURL, "https://"+r.RPID),
	}
	if r.UserName != "" {
		out = append(out, f(PasskeyUserName, svcore.FieldText, r.UserName))
	}
	if r.DisplayName != "" {
		out = append(out, f(PasskeyDisplayName, svcore.FieldText, r.DisplayName))
	}
	key := make([]byte, B64.EncodedLen(len(r.PrivateKey)))
	B64.Encode(key, r.PrivateKey)
	out = append(out,
		f(PasskeyCredentialID, svcore.FieldText, B64.EncodeToString(r.CredentialID)),
		f(PasskeyUserHandle, svcore.FieldText, B64.EncodeToString(r.UserHandle)),
		f(PasskeyAlgorithm, svcore.FieldText, AlgName(r.Alg)),
		svcore.Field{Name: PasskeyPrivateKey, Type: svcore.FieldKey, Value: key},
	)
	if !r.Created.IsZero() {
		out = append(out, f(PasskeyCreatedField, svcore.FieldText, r.Created.UTC().Format(time.RFC3339)))
	}
	return out
}

// ErrNotPasskey is an item that is not a usable passkey.
var ErrNotPasskey = errors.New("not a passkey secretvault can use")

// ReadPasskey reads a passkey item's fields, by name (field returns a
// field's value, and whether there is one). With key false, the private
// key is not read (listing, showing).
func ReadPasskey(field func(name string) ([]byte, bool), key bool) (*PasskeyRecord, error) {
	s := func(n string) string {
		v, _ := field(n)
		return string(v)
	}
	r := &PasskeyRecord{RPID: s(PasskeyRPID), UserName: s(PasskeyUserName), DisplayName: s(PasskeyDisplayName)}
	if r.RPID == "" {
		return nil, fmt.Errorf("%w: no %s", ErrNotPasskey, PasskeyRPID)
	}
	var err error
	if r.CredentialID, err = UnB64(s(PasskeyCredentialID)); err != nil || len(r.CredentialID) == 0 || len(r.CredentialID) > MaxCredentialID {
		return nil, fmt.Errorf("%w: a bad %s", ErrNotPasskey, PasskeyCredentialID)
	}
	if r.UserHandle, err = UnB64(s(PasskeyUserHandle)); err != nil || len(r.UserHandle) > MaxUserHandle {
		return nil, fmt.Errorf("%w: a bad %s", ErrNotPasskey, PasskeyUserHandle)
	}
	if t, err := time.Parse(time.RFC3339, s(PasskeyCreatedField)); err == nil {
		r.Created = t
	}
	alg, algOK := AlgOf(s(PasskeyAlgorithm))
	if !key {
		r.Alg = alg
		return r, nil
	}
	v, ok := field(PasskeyPrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: no %s", ErrNotPasskey, PasskeyPrivateKey)
	}
	r.PrivateKey = make([]byte, B64.DecodedLen(len(v)))
	n, err := B64.Decode(r.PrivateKey, trimPad(v))
	r.PrivateKey = r.PrivateKey[:n]
	if err != nil {
		r.Wipe()
		return nil, fmt.Errorf("%w: a bad %s", ErrNotPasskey, PasskeyPrivateKey)
	}
	pub, err := PublicOf(r.PrivateKey)
	if err != nil || algOK && pub.Alg != alg {
		r.Wipe()
		return nil, fmt.Errorf("%w: its key is not one it says", ErrNotPasskey)
	}
	r.Alg = pub.Alg
	return r, nil
}

func trimPad(b []byte) []byte {
	for len(b) > 0 && b[len(b)-1] == '=' {
		b = b[:len(b)-1]
	}
	return b
}

// ItemField makes field for ReadPasskey from an svcore item.
func ItemField(it *svcore.Item) func(string) ([]byte, bool) {
	return func(n string) ([]byte, bool) {
		f, ok := it.Field(n)
		return f.Value, ok
	}
}
