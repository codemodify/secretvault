package svops

import (
	"fmt"

	"github.com/codemodify/secretvault/svrpc"
)

// What the managers (the GUI and the TUI) both say about sharing a vault,
// emergency access, syncing, a vault's devices and contacts, in plain
// words (docs/wording.md). Each face adds only what is its own: which
// button or key does what. The CLI says its own.

// The jargon these pages cannot do without, said once where it first
// appears.
const (
	RecipientMeans   = "recipient (the public key people share vaults with)"
	FingerprintMeans = "fingerprint (a short code to compare)"
)

// Sharing a vault, and emergency access to it.
const (
	SharingAbout = "Share this vault with a person or another device: they open it with their own key, not your passphrase. " +
		"Cutting one off gives the vault a new key, so nothing written after that opens for them."
	EmergencyAbout = "Emergency access lets someone you trust into this vault if something happens to you: they ask, you are told, " +
		"and unless you deny it within the wait you set, they get it. The vault must sync with a server, which keeps the time."
	ShareLead = "Give a person or another device their own way into this vault. " +
		"They open it with their own key, and you can cut them off later."
	EmergencyGrantLead = "Choose someone you trust. They can ask for this vault at any time: " +
		"you are told, and unless you deny it within the wait, they get it."
	InviteHoldsNoSecret = "The invite holds no secret: it works only with their own key, so any way of sending it will do."
	AcceptEmergencyLead = "Someone gave you emergency access to their vault. Paste the invite they sent, " +
		"and choose your identity file (the private key the invite was made for)."
	RotateToo = "Also give the vault a new key, so that a copy they kept cannot open what is written from now on"
)

// SharedText says a vault shared with who ("" when they have no name).
func SharedText(vault, who string) string {
	if who == "" {
		return fmt.Sprintf("Shared vault %s: the person or device opens it with their own key.", vault)
	}
	return fmt.Sprintf("Shared vault %s with %s: they open it with their own key.", vault, who)
}

// EmergencyGrantedText says what a grant of emergency access now lets
// who do.
func EmergencyGrantedText(who, vault string, wait int64) string {
	return fmt.Sprintf("From now on %s can ask for vault %s, and gets it unless you deny it within %s of their asking.", who, vault, WaitText(wait))
}

// DenyEmergencyPlain asks before denying who's request for vault.
func DenyEmergencyPlain(who, vault string) Plain {
	return Plain{
		Title: "Deny " + who + "'s request?",
		Summary: SentenceStart(who) + " asked for emergency access to vault " + vault + ". Denying it gives them nothing now. " +
			"They keep their access: if they ask again, the wait starts over, and you are told again.",
		Action: "Deny the request",
	}
}

// RevokeEmergencyText says what revoking who's emergency access to vault
// does.
func RevokeEmergencyText(who, vault string) string {
	return fmt.Sprintf("%s can no longer ask for vault %s, and the copy of its key kept for them on the server is deleted.", SentenceStart(who), vault)
}

// RevokedText says it is done.
func RevokedText(who, vault string) string {
	return fmt.Sprintf("Revoked: %s can no longer ask for vault %s.", who, vault)
}

// KeptACopyText says that who was given the vault, and what to do.
func KeptACopyText(when string) string {
	return "They were given the vault on " + when + " and may have kept a copy: give the vault a new key, so that nothing written afterwards opens for them."
}

// Syncing.
const (
	SyncOffAbout = "This vault is only on this device. Syncing keeps it up to date on your other devices, " +
		"through a sync server you run (secretvault-server), which only ever holds it encrypted."
	SyncAbout     = "A synced vault is kept up to date on your other devices through a sync server, which only ever holds it encrypted."
	SyncSetupLead = "The vault is copied to your sync server encrypted: the server never sees your passphrase or what is inside."
	SyncJoinLead  = "Get a vault you sync on another device onto this one, with an invite made on that device. It stays in step from then on."
)

// SyncInviteNote says what an invite to join a synced vault does, and
// that it is safe: it works once, until expires.
func SyncInviteNote(expires string) string {
	return "It works once, until " + expires + ". The other device gets the vault encrypted: opening it still takes the passphrase, " +
		"or another way in (a keyslot) you add for it."
}

// RemoveSyncDevicePlain asks before taking a device off vault's sync
// server.
func RemoveSyncDevicePlain(vault, label, key string) Plain {
	name := label
	if name == "" {
		name = "The device"
	}
	return Plain{
		Title: "Stop " + orDevice(label) + " syncing?",
		Summary: name + " stops getting vault " + vault + " from the sync server. It keeps the copy it has, and can still open it: " +
			"to lock it out for good, also cut it off under Sharing, which gives the vault a new key.",
		Action:  "Stop it syncing",
		Details: []string{"Device key: " + key},
	}
}

// StopSyncPlain asks before vault stops syncing.
func StopSyncPlain(vault string) Plain {
	return Plain{
		Title: "Stop syncing vault " + vault + "?",
		Summary: "This device keeps its copy of vault " + vault + ", but no longer sends or gets changes. " +
			"The server and your other devices keep theirs, and you can set syncing up again later.",
		Action: "Stop syncing",
	}
}

// KeptKeyslotsText says the sync refused n changes that would have left
// the vault with no way to open it.
func KeptKeyslotsText(n int) string {
	return fmt.Sprintf("Refused %s from other devices that would have left the vault with no way to open it.", countOf(n, "change", "changes"))
}

// A vault's devices, and the signatures on what they write.
const (
	DevicesAbout = "Each device that opens this vault signs the changes it makes, so the history shows which device made each. " +
		"A device names itself, so before you vouch for one (say you trust it), check on that device that it shows the same key as \"this device\"."
)

func orDevice(label string) string {
	if label == "" {
		return "the device"
	}
	return label
}

// VouchPlain asks before vouching for the device of label and key.
func VouchPlain(label, key string) Plain {
	name := orDevice(label)
	return Plain{
		Title: "Vouch for " + name + "?",
		Summary: "Vouching says you trust this device: what it signs, and what the devices it vouches for sign, then counts as yours. " +
			"Anyone who can open the vault can add a device under any name, so check first that " + name +
			"'s own devices list shows this key as \"this device\": " + key,
		Action: "Vouch for it",
	}
}

// WithdrawPlain asks before no longer vouching for a device.
func WithdrawPlain(label string) Plain {
	return Plain{
		Title:   "Stop vouching for " + orDevice(label) + "?",
		Summary: "What it signs no longer counts as yours here, unless another device you vouch for vouches for it.",
		Action:  "Stop vouching",
	}
}

// RemoveDevicePlain asks before marking a device of the vault removed.
func RemoveDevicePlain(label, key string) Plain {
	return Plain{
		Title: "Remove " + orDevice(label) + "?",
		Summary: "It is marked removed, and what it signed stays in the history as a removed device's. " +
			"It can still open the vault and change it until the vault gets a new key without it: " +
			"Cut off… under Sharing, or a new key under Keyslots.",
		Action:  "Remove the device",
		Details: []string{"Device key: " + key},
	}
}

// Contacts, verifying their keys, and the organisations' directories.
const (
	ContactsAbout = "A contact is a person and their public keys, kept to check who signed a message and to share vaults with them."
	VerifyLead    = "Verifying proves a key really is theirs, and not someone pretending: compare its fingerprint (a short code) with them, " +
		"face to face or on a call, or scan their QR code."
	AddContactLead = "Add a person from their public key files: OpenPGP keys, X.509 certificates, SSH public keys, or their " +
		RecipientMeans + "."
	ImportContactsLead = "Add many keys at once from a file, or record a QR code you scanned from someone's screen: " +
		"a scanned code also verifies the keys it names, since you saw it on their own device."
	LookupLead = "Find someone's public key by their email address, or by a fingerprint they gave you. " +
		"Nothing found is verified until you compare its fingerprint with them."
	MyCodeLead = "Your public keys as a QR code, for someone to scan from your screen: it adds and verifies your keys for them in one go. " +
		"It holds no secret."
	CheckSignerLead = "Check whether a signed message comes from who it claims, as far as your contacts tell: " +
		"give the signer's key fingerprint, or the key itself, and the address the message is from."
	KeySeenLead = "Remember a key that came with an email (in an Autocrypt header, or an S/MIME signature), " +
		"so that a later message from that address with another key stands out."
	DirectoriesAbout = "An organisation's people directory (LDAP), once added, is asked first when you look up an address there, " +
		"and a key it lists counts as vouched for by the organisation."
	DirectoryPasswordNote = "Its password is not typed here: it stays in a vault item, read only when the directory is asked."
	NotTheFingerprint     = "That is not this key's fingerprint. Compare it again with them: if it really differs, the key may not be theirs."
)

// VerifyWays are the ways a key is verified, as contact.verify takes
// them, said as the person did it.
var VerifyWays = []struct{ Method, Text string }{
	{svrpc.VerifyFingerprint, "I compared the fingerprint with them"},
	{svrpc.VerifyQR, "I scanned their QR code"},
	{svrpc.VerifyOrgDirectory, "An organisation vouches for it"},
	{svrpc.VerifyTOFU, "I accept it without verifying it"},
}

// TrustLevels are the weakest verifications a check of a signer counts,
// as trust.check takes them ("": the default).
var TrustLevels = []struct{ Level, Text string }{
	{"", "published by the address's provider or a keyserver that checks addresses (the default)"},
	{"tofu", "accepted as it was, or seen before"},
	{"logged", "logged"},
	{"organisation", "vouched for by an organisation"},
	{"in-person", "compared in person"},
}

// RemoveDirectoryPlain asks before no longer asking a directory.
func RemoveDirectoryPlain(name string) Plain {
	return Plain{
		Title:   "Remove the directory " + name + "?",
		Summary: "Lookups stop asking " + name + " for people's keys. What it vouched for until now stays as it is.",
		Action:  "Remove the directory",
	}
}
