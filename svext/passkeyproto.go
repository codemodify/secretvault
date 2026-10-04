package svext

import (
	"bytes"
	"encoding/json"
	"net"
)

// The passkey members of a request, as the extension sends them
// (lib/webauthn.js builds them):
//
//	rpId             the relying party's ID: an ASCII host name in lower case
//	rpName           its name, for people (passkey-create)
//	user             the user handle, base64url, 1 to 64 bytes
//	userName         the account's name, for people
//	userDisplayName  its display name
//	algorithms       COSE algorithm numbers, the RP's preference first
//	exclude, allow   credential IDs, base64url, at most 64 of at most 1023 bytes
//	clientData       clientDataJSON, base64url, at most 8 KiB
//	uv               userVerification: "required", "preferred" or "discouraged"

// Limits of the passkey members people read.
const (
	MaxRPName   = 256
	MaxUserName = 256
)

// UV values.
const (
	UVRequired    = "required"
	UVPreferred   = "preferred"
	UVDiscouraged = "discouraged"
)

// ValidRPID reports whether s is an rpId as browsers write hosts: a host
// name (not an address) in ASCII and lower case.
func ValidRPID(s string) bool {
	if s == "" || len(s) > MaxRPID || net.ParseIP(s) != nil {
		return false
	}
	a, ok := asciiHost(s)
	return ok && a == s
}

func (r *Request) readPasskey(m map[string]json.RawMessage) error {
	if _, ok := m["rpId"]; ok {
		if err := str(m, "rpId", &r.RPID, MaxRPID); err != nil {
			return err
		}
		if !ValidRPID(r.RPID) {
			return Errorf(CodeBadRequest, "rpId: a host name, in ASCII and lower case")
		}
	}
	if _, ok := m["rpName"]; ok {
		if err := text(m, "rpName", &r.RPName, MaxRPName); err != nil {
			return err
		}
	}
	if _, ok := m["userName"]; ok {
		if err := text(m, "userName", &r.UserName, MaxUserName); err != nil {
			return err
		}
	}
	if _, ok := m["userDisplayName"]; ok {
		if err := text(m, "userDisplayName", &r.UserDisplayName, MaxUserName); err != nil {
			return err
		}
	}
	if _, ok := m["user"]; ok {
		b, err := b64Member(m, "user", MaxUserHandle)
		if err != nil {
			return err
		}
		r.UserHandle = b
	}
	if _, ok := m["clientData"]; ok {
		b, err := b64Member(m, "clientData", MaxClientData)
		if err != nil {
			return err
		}
		r.ClientData = b
	}
	for _, k := range []string{"exclude", "allow"} {
		raw, ok := m[k]
		if !ok {
			continue
		}
		var list []json.RawMessage
		if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) || json.Unmarshal(raw, &list) != nil || len(list) > MaxCredentialIDs {
			return Errorf(CodeBadRequest, "%s: a list of at most %d credential IDs", k, MaxCredentialIDs)
		}
		ids := make([][]byte, 0, len(list))
		for _, e := range list {
			var s string
			if len(e) == 0 || e[0] != '"' || json.Unmarshal(e, &s) != nil {
				return Errorf(CodeBadRequest, "%s: credential IDs, base64url", k)
			}
			b, err := UnB64(s)
			if err != nil || len(b) == 0 || len(b) > MaxCredentialID {
				return Errorf(CodeBadRequest, "%s: credential IDs, base64url, 1 to %d bytes", k, MaxCredentialID)
			}
			ids = append(ids, b)
		}
		if k == "exclude" {
			r.Exclude = ids
		} else {
			r.Allow = ids
		}
	}
	if raw, ok := m["algorithms"]; ok {
		var list []json.RawMessage
		if !bytes.HasPrefix(bytes.TrimSpace(raw), []byte("[")) || json.Unmarshal(raw, &list) != nil || len(list) > MaxAlgorithms {
			return Errorf(CodeBadRequest, "algorithms: a list of at most %d COSE algorithms", MaxAlgorithms)
		}
		for _, e := range list {
			var n int
			if err := num(map[string]json.RawMessage{"a": e}, "a", &n); err != nil {
				return Errorf(CodeBadRequest, "algorithms: whole numbers")
			}
			r.Algorithms = append(r.Algorithms, n)
		}
	}
	if _, ok := m["uv"]; ok {
		if err := str(m, "uv", &r.UV, 16); err != nil {
			return err
		}
		if r.UV != UVRequired && r.UV != UVPreferred && r.UV != UVDiscouraged {
			return Errorf(CodeBadRequest, "uv: required, preferred or discouraged")
		}
	}
	if r.UV == "" {
		r.UV = UVPreferred
	}
	return nil
}

// b64Member reads a base64url member of 1 to max bytes.
func b64Member(m map[string]json.RawMessage, k string, max int) ([]byte, error) {
	var s string
	if err := str(m, k, &s, max*4/3+4); err != nil {
		return nil, err
	}
	b, err := UnB64(s)
	if err != nil || len(b) == 0 || len(b) > max {
		return nil, Errorf(CodeBadRequest, "%s: base64url, 1 to %d bytes", k, max)
	}
	return b, nil
}
