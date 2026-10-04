package svops

import (
	"time"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svrpc"
)

// Passkeys as the faces show them (svext/passkeyitem.go has the item's
// fields). A passkey shows its site, its account and when it was made;
// its private key is never shown or copied: only the daemon signs with
// it, for the browser extension. It is renamed and deleted like any item,
// and not edited: what it holds came from the site that made it.

// IsPasskey reports whether an item is a passkey.
func IsPasskey(it *svrpc.Item) bool { return it.Kind == svext.PasskeyKind }

// PasskeyHidden reports whether a field of it is kept from view: a
// passkey's private key.
func PasskeyHidden(it *svrpc.Item, f svrpc.Field) bool {
	return IsPasskey(it) && (f.Name == svext.PasskeyPrivateKey || f.Type == svcore.FieldKey)
}

// PasskeyKeyNote says where a passkey's key is, under its summary.
const PasskeyKeyNote = "Its private key stays inside secretvault, which signs you in with it when the browser extension asks; it is never shown or copied."

// PasskeyEditNote says why a passkey is not edited.
const PasskeyEditNote = "A passkey holds what the site that made it gave it, so it is not edited: rename it, or delete it."

// PasskeyRow is one line of a passkey's summary.
type PasskeyRow struct{ Label, Value string }

// PasskeySummary is what a face shows of a passkey: the site, the account
// and when it was made.
func PasskeySummary(it *svrpc.Item) []PasskeyRow {
	get := func(n string) string {
		f, _ := Field(it, n)
		return string(f.Value)
	}
	rows := []PasskeyRow{{"Site", get(svext.PasskeyRPID)}}
	if v := get(svext.PasskeyUserName); v != "" {
		rows = append(rows, PasskeyRow{"User name", v})
	}
	if v := get(svext.PasskeyDisplayName); v != "" {
		rows = append(rows, PasskeyRow{"Shown as", v})
	}
	if t, err := time.Parse(time.RFC3339, get(svext.PasskeyCreatedField)); err == nil {
		rows = append(rows, PasskeyRow{"Created", t.Local().Format("2006-01-02 15:04")})
	}
	return rows
}
