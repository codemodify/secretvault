package svmanager

import (
	"regexp"
	"strings"
)

// The daemon's messages, like svops', were written for the CLI: some tell
// the person to run a command ('secretvault emergency revoke …') or use a
// flag. Said here, the command is replaced by where the same is done in
// this program.

// guiPlaces are the CLI's commands, by their first words, and where this
// program does each. The longest that begins a command wins.
var guiPlaces = map[string]string{
	"init":                    "File › New vault…",
	"vault add":               "File › Add vault folder…",
	"unlock":                  "Vault › Unlock with…",
	"rm":                      "Edit › Delete…",
	"gen":                     "File › Password generator…",
	"share":                   "Vault › Sharing › Share with…",
	"slot add":                "Vault › Keyslots › Add…",
	"device ls":               "Vault › Devices",
	"sync setup":              "Vault › Sync › Set up…",
	"sync off":                "Vault › Sync › Stop syncing…",
	"grant allow":             "Vault › Grants and audit log › Allow a program…",
	"emergency ls":            "Vault › Sharing and emergency access",
	"emergency revoke":        "Vault › Sharing › Emergency access › Revoke… (with the key rotated)",
	"emergency deny":          "Vault › Sharing › Emergency access › Deny…",
	"emergency open":          "File › Emergency access › Open the vault…",
	"emergency request":       "File › Emergency access › Ask for access…",
	"pgp":                     "Keys › OpenPGP keys",
	"pgp new":                 "Keys › OpenPGP keys › New…",
	"pgp import":              "Keys › OpenPGP keys › Import…",
	"pgp gpg-setup":           "Desktop › GnuPG",
	"age keygen":              "Keys › age identities › New…",
	"contact add":             "Contacts › Add…",
	"contact verify":          "Contacts › Verify…",
	"contact directory ls":    "Contacts › Directories",
	"browser uninstall":       "Desktop › Browsers › Undo…",
	"keyring restore":         "Desktop › System keyring › Give it back…",
	"host":                    "Desktop › Host daemon",
	"host init":               "Desktop › Host daemon › Make the host identity…",
	"host status":             "Desktop › Host daemon",
	"vault rotate":            "Vault › Keyslots › Rotate the key…",
	"unshare":                 "Vault › Sharing › Cut off…",
	"keyring takeover":        "Desktop › System keyring › Become the keyring…",
	"contact import":          "Contacts › Import…",
	"identity new":            "Keys › Identity files › New…",
	"container create":        "Vault › Containers › New container…",
	"sync join":               "File › Join a synced vault…",
	"sync invite":             "Vault › Sync › Invite a device…",
	"import":                  "File › Import…",
	"export":                  "File › Export…",
	"history":                 "Edit › History",
	"restore":                 "Edit › History, or Edit › Deleted items",
	"resolve":                 "Edit › History",
	"contact directory add":   "Contacts › Directories › Add…",
	"emergency grant":         "Vault › Sharing › Emergency access › Grant…",
	"emergency accept":        "File › Emergency access › Accept an invite…",
	"browser install":         "Desktop › Browsers › Set up…",
	"slot rm":                 "Vault › Keyslots › Remove…",
	"passwd":                  "Vault › Keyslots › Change the passphrase…",
	"verify":                  "Vault › Settings › Verify every file…",
	"vault login":             "Vault › Settings: Open when I log in",
	"vault signatures":        "Vault › Devices: Count only signed revisions",
	"contact vault":           "Contacts › Keep contacts in…",
	"smime import":            "Keys › S/MIME keys › Import…",
	"contact lookup":          "Contacts › Look up…",
	"contact qr":              "Contacts › Show my QR code…",
	"trust check":             "Contacts › Check a signer…",
	"device vouch":            "Vault › Devices › Vouch for it",
	"pgp export":              "Keys › OpenPGP keys › Export…",
	"pgp pub":                 "Keys › OpenPGP keys › Copy the public key",
	"container passwd":        "Vault › Containers › Passphrase…",
	"container header-backup": "Vault › Containers › Back up the header…",
}

// cliCommand is a CLI command quoted in a message: 'secretvault …'.
var cliCommand = regexp.MustCompile(`'secretvault ([^']*)'`)

// cliFlag is advice, in brackets, that names a flag of the CLI.
var cliFlag = regexp.MustCompile(` \([^()]*--[a-z][a-z0-9-]*[^()]*\)`)

// guiWords says a message in this program's words: each CLI command it
// quotes becomes where the same is done here, and advice to use a flag
// goes. A command with no place here is left as it is.
func guiWords(msg string) string {
	msg = cliCommand.ReplaceAllStringFunc(msg, func(quoted string) string {
		// The command's words, up to its first flag; those after its
		// name (a vault's, a grant's ID) only make the match shorter.
		fields := strings.Fields(cliCommand.FindStringSubmatch(quoted)[1])
		var words []string
		for i := 0; i < len(fields); i++ {
			w := fields[i]
			if w == "--vault" {
				i++ // and its value
				continue
			}
			if strings.HasPrefix(w, "--vault=") || w == "--host" {
				continue
			}
			if strings.HasPrefix(w, "-") {
				break
			}
			words = append(words, w)
		}
		for n := len(words); n > 0; n-- {
			if place, ok := guiPlaces[strings.Join(words[:n], " ")]; ok {
				return place
			}
		}
		return quoted
	})
	return cliFlag.ReplaceAllString(msg, "")
}
