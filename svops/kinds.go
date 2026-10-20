package svops

import "github.com/codemodify/secretvault/svrpc"

// What a vault holds, as both managers list it under the vault's name: a
// row for each kind of item (KindRows, in their order, Other last, for
// the kinds of no row of their own), then My keys, Contacts and About
// this vault. Every item is in one kind's row, but the keys of My keys
// (InMyKeys), which are only there.

// KindRow is one kind of item's row: its name, and the kind it holds.
type KindRow struct{ Title, Kind string }

// KindRows are the kinds' rows, in the order they are listed.
var KindRows = []KindRow{
	{"Logins", "login"}, {"Passwords", "password"}, {"Passkeys", "passkey"}, {"One-time codes", "otp"},
	{"Cards", "card"}, {"Personal details", "identity"}, {"Notes", "note"}, {"SSH keys", "ssh-key"},
	{"API keys", "api-key"}, {"Key/value", "kv"}, {"Keys", "key"}, {"Disk keys", "container"},
	{"Other", "generic"},
}

// The rows after the kinds'.
const (
	MyKeysRow     = "My keys"
	ContactsRow   = "Contacts"
	AboutVaultRow = "About this vault"
)

// KindRowOf is the row of KindRows an item is listed in: its kind's, else
// Other's; -1 for a key of My keys.
func KindRowOf(it *svrpc.Item) int {
	if InMyKeys(it) {
		return -1
	}
	for i, r := range KindRows {
		if r.Kind == it.Kind {
			return i
		}
	}
	return len(KindRows) - 1
}

// InMyKeys reports whether an item is a key of yours that My keys shows,
// and no kind's row: an OpenPGP or S/MIME key, or an age identity.
func InMyKeys(it *svrpc.Item) bool {
	if it.Kind != "key" {
		return false
	}
	a := it.Attrs
	return a[svrpc.PGPFingerprint] != "" || a[svrpc.SMIMEFingerprint] != "" || a[AgeRecipientName] != ""
}
