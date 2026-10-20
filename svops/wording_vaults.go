package svops

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// Words both managers (secretvault-gui and secretvault-tui) say about
// vaults: making and adding one, forgetting it, checking its files, the
// ways it opens (its keyslots), unlocking it, the keys kept in it,
// programs' remembered decisions, and the daemon's questions. They follow
// docs/wording.md; each face adds only which button or key to press.

// Suite is a cipher suite as people are offered it.
type Suite struct {
	Name string // as the daemon takes it
	Text string // as people choose it
}

// SuiteLabel is the label of a choice of cipher suite.
const SuiteLabel = "Encryption"

// VaultSuites are the cipher suites a new vault can use, the usual one
// first.
var VaultSuites = []Suite{
	{"sv1-modern", "Modern (recommended)"},
	{"sv1-nist", "FIPS 140-3 (AES-256-GCM, PBKDF2)"},
}

// IdentitySuites are the cipher suites a new identity file can use.
var IdentitySuites = []Suite{
	{"modern", "Modern (recommended)"},
	{"nist", "FIPS 140-3 (P-256)"},
}

// SuiteText says a vault's cipher suite for people: "Modern
// (XChaCha20-Poly1305, Argon2id)".
func SuiteText(name string) string {
	switch name {
	case "sv1-modern", "modern":
		return "Modern (XChaCha20-Poly1305, Argon2id)"
	case "sv1-nist", "nist":
		return "FIPS 140-3 (AES-256-GCM, PBKDF2)"
	}
	return name
}

// Making a vault.
const (
	NewVaultIntro = "A vault keeps your passwords and keys, encrypted with its passphrase. " +
		"If the passphrase is lost, only a recovery key opens the vault: it is shown once, for you to write down."
	VaultFolderPlaceholder = "Leave empty for secretvault's own folder"
	CreateVaultAction      = "Create the vault"
)

// RecoveryKeyNote is said over a new recovery key, shown once.
func RecoveryKeyNote(vault string) string {
	return "Write this recovery key down and keep it somewhere safe. It opens vault " + vault +
		" if the passphrase is lost, and it is shown only now: it is stored nowhere."
}

// Adding a vault that is already in a folder.
const (
	AddVaultTitle  = "Add an existing vault"
	AddVaultIntro  = "Use a vault that is already in a folder: a synced folder, a backup, or one you forgot here. Nothing in the folder changes."
	AddVaultAction = "Add the vault"
)

// Forgetting a vault: its folder stays.
const ForgetVaultAction = "Forget the vault"

// ForgetVaultTitle asks whether to forget vault.
func ForgetVaultTitle(vault string) string { return "Forget vault " + vault + "?" }

// ForgetVaultText says what forgetting vault does; the face adds how to
// bring it back.
func ForgetVaultText(vault string) string {
	return "Vault " + vault + " leaves the list here. Nothing is deleted: its folder and everything in it stay as they are."
}

// VerifyReport says what checking every file of vault found: a title, a
// summary, the technical lines (the CLI's verify), and whether all is
// well.
func VerifyReport(vault string, rep svrpc.VerifyResult) (title, summary string, details []string, ok bool) {
	details = append(details, fmt.Sprintf("%s checked: %s, %s", countOf(rep.Live, "item", "items"),
		countOf(rep.Objects, "object", "objects"), countOf(rep.Revisions, "revision", "revisions")))
	for _, p := range rep.Problems {
		details = append(details, "problem: "+p)
	}
	for _, c := range rep.Conflicts {
		details = append(details, "conflict: "+c+" (its history settles it)")
	}
	for _, name := range slices.Sorted(maps.Keys(rep.Duplicates)) {
		details = append(details, fmt.Sprintf("duplicate: %d items are named %s", len(rep.Duplicates[name]), name))
	}
	var wrong []string
	if len(rep.Problems) > 0 {
		wrong = append(wrong, "some files are damaged, or were changed outside secretvault")
	}
	if len(rep.Conflicts) > 0 {
		wrong = append(wrong, "some items were changed on two devices at once, and their history lets you keep one version")
	}
	if len(rep.Duplicates) > 0 {
		wrong = append(wrong, "some names are used by more than one item")
	}
	if len(wrong) == 0 {
		return "Vault " + vault + " is sound",
			fmt.Sprintf("Every file of vault %s is as secretvault wrote it (%s).", vault, countOf(rep.Live, "item", "items")),
			details, true
	}
	return "Vault " + vault + " needs attention",
		"Checking vault " + vault + " found that " + strings.Join(wrong, "; ") + ". The details say which.",
		details, false
}

// VerifyStatus is the status line's short form of VerifyReport.
func VerifyStatus(vault string, ok bool) string {
	if ok {
		return "Vault " + vault + ": every file checked, nothing wrong."
	}
	return "Vault " + vault + " needs attention."
}

// KeyslotsNote explains keyslots, the ways to unlock a vault, where they
// are listed.
const KeyslotsNote = "Each of these unlocks the vault on its own: a passphrase, a recovery key, a keyfile, " +
	"a security key, or a person's or device's key."

// SlotTypeName names a keyslot's type for people.
func SlotTypeName(typ string) string {
	switch typ {
	case svformat.SlotRecovery:
		return "recovery key"
	case svformat.SlotRecipient:
		return "person or device"
	case svformat.SlotFIDO2:
		return "security key"
	case svformat.SlotEmergency:
		return "emergency access"
	}
	return typ // passphrase, keyfile
}

// SlotPhrase names a keyslot in a sentence: `the keyfile "backup"`, "the
// passphrase".
func SlotPhrase(s svrpc.SlotInfo) string {
	what := "the " + SlotTypeName(s.Type)
	if s.Type == svformat.SlotRecipient {
		what = "the key of a person or device"
	}
	if s.Label != "" {
		what += fmt.Sprintf(" %q", s.Label)
	}
	return what
}

// SlotKind is a keyslot that can be added, as people are offered it.
type SlotKind struct {
	Type string // as slot.add takes it
	Text string
}

// SlotKinds are the keyslots that can be added.
var SlotKinds = []SlotKind{
	{svformat.SlotPassphrase, "Another passphrase"},
	{svformat.SlotRecovery, "A recovery key to write down, or its shares"},
	{svformat.SlotKeyfile, "A keyfile: any file whose bytes open it"},
	{svformat.SlotRecipient, "A person's or device's public key (recipient)"},
	{svformat.SlotFIDO2, "The security key plugged in"},
}

// SlotAddAction is the button that adds a keyslot of type typ.
func SlotAddAction(typ string) string {
	switch typ {
	case svformat.SlotPassphrase:
		return "Add the passphrase"
	case svformat.SlotRecovery:
		return "Make the recovery key"
	case svformat.SlotKeyfile:
		return "Add the keyfile"
	case svformat.SlotRecipient:
		return "Add their key"
	case svformat.SlotFIDO2:
		return "Add the security key"
	}
	return "Add it"
}

// AddSlotTitle heads adding a keyslot to vault.
func AddSlotTitle(vault string) string { return "Add a way to unlock " + vault }

// What adding each kind of keyslot says.
const (
	SlotLabelPlaceholder = "Optional: whose it is, or what for"
	RecoveryKeyIntro     = "A recovery key opens the vault on its own, like the passphrase. It is shown once, for you to write down, and kept nowhere."
	RecoverySplitIntro   = "Split into shares, it goes to several people instead: enough of them together open the vault, fewer reveal nothing."
	KeyfileIntro         = "Any file can be a keyfile: its bytes open the vault, so keep it as safe as a passphrase. One made here is 64 random bytes only you can read."
	FIDO2SlotIntro       = "Touch the security key plugged in when it blinks, and type its PIN if it asks."
	FIDO2PINLabel        = "Opening asks"
)

// FIDO2PINChoices are when a security key's keyslot asks for its PIN: as
// the key decides, always, or never.
var FIDO2PINChoices = []string{
	"for its PIN with every touch, if it has one",
	"for its PIN, always (it must have one)",
	"for a touch alone, never its PIN",
}

// SlotAdded says, for the status line, that vault opens with s too.
func SlotAdded(vault string, s svrpc.SlotInfo) string {
	return "Vault " + vault + " now also opens with " + SlotPhrase(s) + "."
}

// Removing a keyslot.
const (
	RemoveSlotTitle  = "Remove this way to unlock?"
	RemoveSlotAction = "Remove the way to unlock"
)

// RemoveSlotText says what removing s from vault does; the face adds
// where rotating the key is.
func RemoveSlotText(vault string, s svrpc.SlotInfo) string {
	return SentenceStart(SlotPhrase(s)) + " will no longer open vault " + vault + ". " +
		"Anyone who already opened the vault with it may have kept the vault key: giving the vault a new key shuts them out."
}

// SlotRemoved says, for the status line, that s no longer opens vault.
func SlotRemoved(vault string, s svrpc.SlotInfo) string {
	return "Vault " + vault + " no longer opens with " + SlotPhrase(s) + "."
}

// Changing the passphrase.
const (
	ChangePassphraseIntro = "The passphrase you unlocked the vault with is replaced by the new one. " +
		"Other ways to open it (another passphrase, a recovery key, a keyfile) keep working."
	ChangePassphraseAction = "Change the passphrase"
)

// ChangePassphraseTitle heads changing vault's passphrase.
func ChangePassphraseTitle(vault string) string { return "Change the passphrase of " + vault }

// PassphraseChanged says, for the status line, that it was changed.
func PassphraseChanged(vault string) string { return "Changed the passphrase of vault " + vault + "." }

// Giving a vault a new key (rotating it), and cutting people off with it.

// RotateTitle heads rotating vault's key, cutting people off when cut.
func RotateTitle(vault string, cut bool) string {
	if cut {
		return "Cut them off: give vault " + vault + " a new key"
	}
	return "Give vault " + vault + " a new key"
}

// RotateIntro says what rotating does, cutting off cut people's
// keyslots.
func RotateIntro(cut int) string {
	s := "Every item is encrypted again under a new key, so a key kept from before cannot read anything written from now on. " +
		"Afterwards the vault opens with the passphrase you type here (the current one is fine) and with everyone it is shared with"
	switch {
	case cut == 1:
		s += ", except the one being cut off"
	case cut > 1:
		s += fmt.Sprintf(", except the %d being cut off", cut)
	}
	return s + ". Keyfiles and security keys have to be added again."
}

// RotateAction is the button that rotates the key.
func RotateAction(cut bool) string {
	if cut {
		return "Cut off and make a new key"
	}
	return "Make a new key"
}

// RotateRecoveryCheck asks for a new recovery key with the new vault key.
const RotateRecoveryCheck = "Make a new recovery key too (the old one stops working)"

// RotateDone says what rotating did, in a sentence or two, cut people
// having been cut off.
func RotateDone(vault string, res svrpc.RotateResult, cut int) string {
	s := "Vault " + vault + " has a new key: a key kept from before cannot read anything written from now on."
	switch {
	case cut == 1:
		s += " The one cut off can no longer open it."
	case cut > 1:
		s += fmt.Sprintf(" The %d cut off can no longer open it.", cut)
	}
	if len(res.Dropped) > 0 {
		s += " " + SentenceStart(countOf(len(res.Dropped), "way to unlock", "ways to unlock")) + " no longer " + opens(len(res.Dropped)) +
			" it; the details say which, to add again if you want them."
	}
	return s
}

func opens(n int) string {
	if n == 1 {
		return "opens"
	}
	return "open"
}

// RotateDetails are what opens the vault after its key was rotated, and
// what no longer does, as the CLI says them.
func RotateDetails(res svrpc.RotateResult) []string {
	out := []string{"It opens with:"}
	for _, s := range res.Slots {
		label := s.Label
		if label == "" {
			label = SlotTypeName(s.Type)
		}
		out = append(out, "  "+s.ID+"  "+label)
	}
	if len(res.Dropped) > 0 {
		out = append(out, "No longer opening it (add them again under Ways to unlock, or grant emergency access again):")
		for _, s := range res.Dropped {
			out = append(out, fmt.Sprintf("  %s  %s (%s)", s.ID, s.Label, SlotTypeName(s.Type)))
		}
	}
	return append(out, fmt.Sprintf("Key epoch: %d", res.Epoch))
}

// RotateStatus says, for the status line, that vault has a new key.
func RotateStatus(vault string) string { return "Vault " + vault + " has a new key." }

// SecurityKeyCan says whether a security key can open a vault.
func SecurityKeyCan(k svrpc.FIDO2Device) string {
	if k.HMACSecret {
		return "can open a vault"
	}
	return "cannot open a vault (it lacks hmac-secret)"
}

// SecurityKeyFacts are what is known of a security key plugged in, a row
// each.
func SecurityKeyFacts(k svrpc.FIDO2Device) [][2]string {
	var rows [][2]string
	if k.Path != "" {
		rows = append(rows, [2]string{"Device", k.Path})
	}
	if len(k.Versions) > 0 {
		pin := "cannot have one"
		switch k.PIN {
		case "set":
			pin = fmt.Sprintf("set, %d tries left", k.Retries)
		case "not set":
			pin = "not set"
		}
		rows = append(rows, [2]string{"Protocols", strings.Join(k.Versions, ", ")}, [2]string{"Model", k.AAGUID},
			[2]string{"PIN", pin}, [2]string{"Opens a vault", SecurityKeyCan(k)})
	}
	if k.Problem != "" {
		rows = append(rows, [2]string{"Problem", k.Problem})
	}
	return rows
}

// UnlockKindText are the keys a vault can be unlocked with, as people are
// offered them, by svrpc.Key's type ("shares" for recovery shares,
// "identity" for an identity file).
var UnlockKindText = map[string]string{
	svformat.SlotRecovery:   "The recovery key you wrote down",
	"shares":                "Recovery shares, from the people who hold them",
	svformat.SlotKeyfile:    "A keyfile",
	"identity":              "An identity file (a key of yours the vault was shared with)",
	svformat.SlotFIDO2:      "The security key plugged in",
	"passphrase-file":       "A passphrase kept in a file",
	svformat.SlotPassphrase: "The passphrase",
}

// SharesIntro is said over typing recovery shares.
const SharesIntro = "Type the shares one at a time; the first says how many it takes."

// Keys kept in the vault.
const (
	KeysInVaultNote = "Your keys stay in the vault: secretvault signs and decrypts with them for you, asking first " +
		"as it does for passwords, and they leave the vault only if you export them."
	PGPVersionNote  = "Version 6 is the default; GnuPG 2.4 and older read only version 4."
	FingerprintNote = "Its fingerprint (a short code people compare to be sure a key is yours), and who it is for:"
	AgeNote         = "age encrypts files to a public key (a recipient); the identity, its private half, stays in the vault and decrypts them. " +
		"age and SOPS reach it through its identity line (a line that names the key for them; it holds no secret)."
	IdentityFileNote = "An identity file holds a private key of yours. Its public half (the recipient) is what you give people " +
		"so they can share a vault with you or grant you emergency access, and the file then opens it. Keep the file as safe as a passphrase."
	IdentityMadeNote = "Only you can read the new file. Its public key (recipient), to give to people who share vaults with you:"
)

// Programs' remembered decisions about a vault (grants).

// DecisionText says a decision for people: "always allowed".
func DecisionText(d string) string {
	switch d {
	case "allow-always":
		return "always allowed"
	case "allow-until-lock":
		return "allowed until the vault locks"
	case "allow-once":
		return "allowed once"
	case "deny-once":
		return "denied once"
	case "deny-always":
		return "always denied"
	}
	return d
}

// Forgetting a decision.
const (
	RevokeGrantTitle  = "Forget this decision?"
	RevokeGrantAction = "Forget the decision"
	GrantsEmpty       = "No program has a remembered decision about this vault: you are asked when one first wants it."
)

// RevokeGrantText says the decision g, and what forgetting it does.
func RevokeGrantText(g svrpc.Grant) string {
	return GrantDecided(g) + " Once the decision is forgotten, you are asked again the next time it wants to."
}

// NewVaultsScope is what a decision about a program asking for new
// vaults is about, where a grant's item is shown (svrpc.Grant.NewVaults).
const NewVaultsScope = "asking for new vaults"

// GrantScope is what the decision g is about, as a grants list shows it:
// an item, the whole vault (whole), or asking for new vaults.
func GrantScope(g svrpc.Grant, whole string) string {
	switch {
	case g.NewVaults:
		return NewVaultsScope
	case g.Item == "":
		return whole
	}
	return g.Item
}

// GrantDecided says the decision g in a sentence: "/usr/bin/foo may read
// and list the whole vault, always."
func GrantDecided(g svrpc.Grant) string {
	if g.NewVaults {
		return fmt.Sprintf("%s may not ask for new vaults: you chose not to be asked again.", g.Program)
	}
	what := "the whole vault"
	if g.Item != "" {
		what = "item " + g.Item
	}
	switch g.Decision {
	case "allow-always":
		return fmt.Sprintf("%s may %s %s, always.", g.Program, andList(g.Ops), what)
	case "allow-until-lock":
		return fmt.Sprintf("%s may %s %s until the vault locks.", g.Program, andList(g.Ops), what)
	case "deny-always":
		ops := andList(g.Ops)
		if n := len(g.Ops); n > 1 {
			ops = strings.Join(g.Ops[:n-1], ", ") + " or " + g.Ops[n-1]
		}
		return fmt.Sprintf("%s may never %s %s.", g.Program, ops, what)
	}
	return fmt.Sprintf("%s: %s, to %s %s.", g.Program, DecisionText(g.Decision), andList(g.Ops), what)
}

// PromptAction is the button that answers the daemon's question q.
func PromptAction(q svrpc.PromptAsk) string {
	switch q.Kind {
	case svrpc.PromptNewPassphrase:
		return "Set the passphrase"
	case svrpc.PromptPassphrase:
		switch {
		case strings.HasPrefix(q.Title, "Unlock"):
			return "Unlock"
		case strings.HasPrefix(q.Title, "Allow"):
			return "Allow"
		}
	}
	return "Continue"
}

// The daemon, when it cannot be reached.
const (
	DaemonNotRunning   = "secretvault's background service (secretvaultd) is not running."
	DaemonNotAnswering = "secretvault's background service (secretvaultd) is not answering."
	DaemonTooSlow      = "secretvault's background service took too long to answer."
)
