package svmail

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svpgp"
)

// Autocrypt (Autocrypt Level 1): keys senders put in their messages'
// headers, and the keys of other recipients they gossip inside encrypted
// ones. They are reported as discovered, never trusted.

type autocryptHeader struct {
	addr, preferEncrypt string
	keydata             []byte
}

// parseAutocrypt reads one Autocrypt or Autocrypt-Gossip value:
// attributes separated by ";", addr and keydata required, unknown
// attributes allowed only when they start with "_".
func parseAutocrypt(v string) (*autocryptHeader, error) {
	h := &autocryptHeader{}
	for _, attr := range strings.Split(v, ";") {
		k, val, ok := strings.Cut(strings.TrimSpace(attr), "=")
		if !ok {
			if strings.TrimSpace(attr) == "" {
				continue
			}
			return nil, fmt.Errorf("an attribute without a value: %q", truncate(attr, 30))
		}
		k = strings.ToLower(strings.TrimSpace(k))
		switch {
		case k == "addr":
			h.addr = strings.TrimSpace(val)
		case k == "prefer-encrypt":
			h.preferEncrypt = strings.TrimSpace(val)
		case k == "keydata":
			data, err := decodeBase64([]byte(val))
			if err != nil {
				return nil, fmt.Errorf("keydata: %v", err)
			}
			h.keydata = data
		case strings.HasPrefix(k, "_"):
		default:
			return nil, fmt.Errorf("an unknown critical attribute %q", k)
		}
	}
	if h.addr == "" || len(h.keydata) == 0 {
		return nil, fmt.Errorf("no addr or no keydata")
	}
	if h.preferEncrypt != "mutual" {
		h.preferEncrypt = "nopreference"
	}
	return h, nil
}

// autocrypt reads the message's own Autocrypt headers: the one for the
// sender counts, and only if there is exactly one.
func (in *inspector) autocrypt(h Header) {
	values := h.Values("Autocrypt")
	if len(values) == 0 {
		return
	}
	if len(values) > maxAutocrypt {
		values = values[:maxAutocrypt]
	}
	var found []*autocryptHeader
	for _, v := range values {
		ah, err := parseAutocrypt(v)
		if err != nil {
			in.warn(WarnKeys, "an Autocrypt header was ignored: "+err.Error(), 0)
			continue
		}
		if !strings.EqualFold(ah.addr, in.from) {
			in.warn(WarnKeys, fmt.Sprintf("an Autocrypt header for %s, who is not the sender, was ignored", ah.addr), 0)
			continue
		}
		found = append(found, ah)
	}
	switch len(found) {
	case 0:
	case 1:
		in.discover(pgpDiscovered("autocrypt", found[0], false, in))
	default:
		in.warn(WarnKeys, "the message has more than one Autocrypt header for its sender; all were ignored", 0)
	}
}

// gossip reads Autocrypt-Gossip headers from the payload's header, which
// count only inside an encrypted message and only for its recipients.
func (in *inspector) gossip(h Header, c walkCtx) {
	values := h.Values("Autocrypt-Gossip")
	if len(values) == 0 {
		return
	}
	if len(c.encryptedBy) == 0 {
		in.warn(WarnKeys, "Autocrypt-Gossip headers outside an encrypted message were ignored", 0)
		return
	}
	if len(values) > maxAutocrypt {
		values = values[:maxAutocrypt]
	}
	recipients := map[string]bool{}
	for _, hdr := range []Header{h, in.outer} {
		for _, name := range []string{"To", "Cc"} {
			for _, v := range hdr.Values(name) {
				if list, err := addressParser.ParseList(v); err == nil {
					for _, a := range list {
						recipients[strings.ToLower(a.Address)] = true
					}
				}
			}
		}
	}
	for _, v := range values {
		ah, err := parseAutocrypt(v)
		if err != nil {
			in.warn(WarnKeys, "an Autocrypt-Gossip header was ignored: "+err.Error(), 0)
			continue
		}
		if !recipients[strings.ToLower(ah.addr)] {
			in.warn(WarnKeys, fmt.Sprintf("an Autocrypt-Gossip header for %s, who is not a recipient, was ignored", ah.addr), 0)
			continue
		}
		in.discover(pgpDiscovered("autocrypt-gossip", ah, true, in))
	}
}

func pgpDiscovered(source string, ah *autocryptHeader, protected bool, in *inspector) *DiscoveredKey {
	d := &DiscoveredKey{Source: source, Type: "openpgp", Address: ah.addr, PreferEncrypt: ah.preferEncrypt, Protected: protected, Data: ah.keydata}
	k, err := svpgp.ReadKey(bytes.NewReader(ah.keydata))
	if err != nil {
		d.Error = err.Error()
		d.Data = nil
		return d
	}
	d.Fingerprint = hexUpper(k.Fingerprint())
	d.UserIDs = k.UserIDs()
	if k.HasSecret() {
		d.Error = "the key data holds a secret key"
		d.Data = nil
		return d
	}
	if err := k.Valid(in.now); err != nil {
		d.Error = "the key is not valid: " + err.Error()
	}
	return d
}
