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
	"init":                    "Vault › New vault…",
	"vault add":               "Vault › Add an existing vault…",
	"unlock":                  "Vault › Unlock with…",
	"rm":                      "Vault › Items › Delete…",
	"gen":                     "Tools › Password generator…",
	"share":                   "Vault › Sharing › Share with…",
	"slot add":                "Vault › Ways to unlock › Add a way to unlock…",
	"device ls":               "Vault › Devices",
	"sync setup":              "Vault › Sync › Set up syncing…",
	"sync off":                "Vault › Sync › Stop syncing…",
	"grant allow":             "Vault › Grants › Allow a program…",
	"emergency ls":            "Vault › Sharing and emergency access",
	"emergency revoke":        "Vault › Sharing › Emergency access › Revoke… (with the key rotated)",
	"emergency deny":          "Vault › Sharing › Emergency access › Deny…",
	"emergency open":          "Vault › Emergency access given to me › Open the vault…",
	"emergency request":       "Vault › Emergency access given to me › Ask for access…",
	"pgp":                     "Vault › My keys › OpenPGP keys",
	"pgp new":                 "Vault › My keys › OpenPGP keys › New…",
	"pgp import":              "Vault › My keys › OpenPGP keys › Import…",
	"pgp gpg-setup":           "Tools › GnuPG",
	"age keygen":              "Vault › My keys › age identities › New…",
	"contact add":             "Vault › Contacts › Add…",
	"contact verify":          "Vault › Contacts › All contacts › Verify…",
	"contact directory ls":    "Vault › Contacts › Directories",
	"browser uninstall":       "Tools › Browsers › Take the permission back…",
	"keyring restore":         "Tools › System keyring › Give the keyring back…",
	"host":                    "Tools › Host daemon",
	"host init":               "Tools › Host daemon › Make the host identity…",
	"host status":             "Tools › Host daemon",
	"vault rotate":            "Vault › Ways to unlock › Give the vault a new key…",
	"unshare":                 "Vault › Sharing › Cut off…",
	"keyring takeover":        "Tools › System keyring › Take over the keyring…",
	"contact import":          "Vault › Contacts › Import…",
	"identity new":            "Tools › Identity files › New identity file…",
	"container create":        "Disk › New disk…",
	"container open":          "Disk › Mount",
	"container close":         "Disk › Unmount…",
	"container delete":        "Disk › Delete…",
	"sync join":               "Vault › Join a synced vault…",
	"sync invite":             "Vault › Sync › Invite a device…",
	"import":                  "Vault › Import…",
	"export":                  "Vault › Export…",
	"history":                 "Vault › Items › History",
	"restore":                 "Vault › Items › History, or Vault › Items › Deleted items",
	"resolve":                 "Vault › Items › History",
	"contact directory add":   "Vault › Contacts › Directories › Add…",
	"emergency grant":         "Vault › Sharing › Emergency access › Grant…",
	"emergency accept":        "Vault › Emergency access given to me › Accept an invite…",
	"browser install":         "Tools › Browsers › Let browsers use secretvault…",
	"slot rm":                 "Vault › Ways to unlock › Remove…",
	"passwd":                  "Vault › Ways to unlock › Change the passphrase…",
	"verify":                  "Vault › Settings › Check every file…",
	"vault login":             "Vault › Settings: Open when I log in",
	"vault signatures":        "Vault › Devices: Count only signed changes",
	"contact vault":           "Vault › Contacts › Keep contacts in…",
	"smime import":            "Vault › My keys › S/MIME keys › Import…",
	"contact lookup":          "Vault › Contacts › Look up…",
	"contact qr":              "Vault › Contacts › Show my QR code…",
	"trust check":             "Vault › Contacts › Check a signer…",
	"device vouch":            "Vault › Devices › Vouch for it…",
	"pgp export":              "Vault › My keys › OpenPGP keys › Export…",
	"pgp pub":                 "Vault › My keys › OpenPGP keys › Copy the public key",
	"container passwd":        "Disk › Its own passphrase…",
	"container header-backup": "Disk › Back up the header…",
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
