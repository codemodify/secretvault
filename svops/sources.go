package svops

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codemodify/secretvault/svimport"
)

// The programs people bring their passwords from, and how to make the
// file each gives secretvault: the CLI's 'import sources' and 'import
// SOURCE', the GUI's File › Import… and the TUI's I all show these words,
// and nothing else. Browsers' own stores are never read: every program
// imports through the export file it makes.

// ImportSource is a program to import from.
type ImportSource struct {
	Name    string   // what the CLI takes in place of a format: firefox
	Aliases []string // other names the CLI takes for it: edge, brave
	Label   string   // what people call it: Firefox
	Program string   // the program, in a sentence: "What to do in your browser"
	Format  svimport.Format

	// Steps make the export in that program, in plain words, one step
	// each, in order.
	Steps []string

	// File is what the program calls its export, for the file dialog.
	File string

	// Passphrase names the export's own passphrase when the export can
	// be encrypted ("" when it never is), and PassphraseHint says when it
	// is needed.
	Passphrase, PassphraseHint string

	// Keyfile says a KeePass key file may be needed too.
	Keyfile bool

	// Unencrypted says the export the steps make holds every secret in
	// the clear (Result.Encrypted says what a file turned out to be).
	Unencrypted bool
}

// ImportSources are the programs to import from, the most common first.
var ImportSources = []ImportSource{
	{
		Name: "firefox", Label: "Firefox", Program: "Firefox", Format: svimport.FormatCSV, File: "logins.csv", Unencrypted: true,
		Steps: []string{
			"In Firefox, type about:logins in the address bar and press Enter (or open the menu of three lines at the top right, and choose Passwords).",
			"Open the three-dot menu at the top right of the page, and choose Export Passwords…",
			"Click Export…, and type your computer's password if Firefox asks for it.",
			"Save the file. Firefox calls it logins.csv.",
		},
	},
	{
		Name: "chrome", Aliases: []string{"edge", "brave", "chromium", "opera", "vivaldi"},
		Label: "Chrome, Edge, Brave or another Chromium browser", Program: "your browser", Format: svimport.FormatCSV,
		File: "Chrome Passwords.csv", Unencrypted: true,
		Steps: []string{
			"In Chrome, type chrome://password-manager/settings in the address bar and press Enter " +
				"(or open the three-dot menu › Passwords and autofill › Google Password Manager › Settings). " +
				"In Brave, type brave://password-manager/settings; in Edge, edge://settings/passwords; " +
				"in other browsers, open the browser's password settings.",
			"Beside Export passwords, click Download file (in Edge: the three-dot menu › Export passwords).",
			"Type your computer's password if the browser asks for it.",
			"Save the file. Chrome calls it Chrome Passwords.csv.",
		},
	},
	{
		Name: "safari", Aliases: []string{"apple", "icloud", "passwords-app"},
		Label: "Safari, or Apple's Passwords app", Program: "Passwords or Safari", Format: svimport.FormatCSV, File: "Passwords.csv", Unencrypted: true,
		Steps: []string{
			"On a Mac with macOS 15 Sequoia or later, open the Passwords app. " +
				"(With macOS 14 Sonoma or earlier, open Safari and choose File › Export › Passwords…, then go on at step 3.)",
			"Choose File › Export All Passwords to File…, and click Export Passwords.",
			"Unlock with Touch ID or your Mac's password if it asks.",
			"Save the file. It is called Passwords.csv.",
		},
	},
	{
		Name: "bitwarden", Aliases: []string{"vaultwarden"}, Label: "Bitwarden", Program: "Bitwarden", Format: svimport.FormatBitwarden,
		File: "bitwarden_export.json", Unencrypted: true,
		Passphrase: "File password", PassphraseHint: "Only for a password-protected export",
		Steps: []string{
			"Sign in to the Bitwarden web vault (vault.bitwarden.com, or your own server), or open the Bitwarden desktop app.",
			"Choose Tools › Export vault (in the desktop app: File › Export vault).",
			"As the file format, choose .json. (Or .json (Encrypted) with Password protected, and give secretvault that password too. " +
				"Not Account restricted: only Bitwarden can read that.)",
			"Click Confirm format, type your master password, and save the file. Bitwarden calls it bitwarden_export_ and the date, .json.",
		},
	},
	{
		Name: "1password", Aliases: []string{"1pux"}, Label: "1Password", Program: "1Password", Format: svimport.Format1PUX,
		File: "1PasswordExport.1pux", Unencrypted: true,
		Steps: []string{
			"Open the 1Password app on a Mac or a Windows PC. (The browser extension and the phone apps cannot export.)",
			"Choose File › Export, and your account (on Windows: the three-dot menu beside your account's name › Export).",
			"Type your 1Password account password.",
			"Choose the 1PUX format, click Export Data, and save the file. It ends in .1pux.",
		},
	},
	{
		Name: "keepass", Aliases: []string{"keepassxc", "keepassx", "kdbx"}, Label: "KeePass or KeePassXC", Program: "KeePass or KeePassXC",
		Format: svimport.FormatKDBX, File: "Passwords.kdbx", Keyfile: true,
		Passphrase: "Master password", PassphraseHint: "The database's master password",
		Steps: []string{
			"There is nothing to export: the database file KeePass or KeePassXC opens is the file to choose. Its name ends in .kdbx.",
			"If you do not know where it is, open KeePass or KeePassXC: the recent databases they list show where each is kept.",
			"Type the database's master password, and choose its key file too if you use one.",
		},
	},
	{
		Name: "protonpass", Aliases: []string{"proton"}, Label: "Proton Pass", Program: "Proton Pass", Format: svimport.FormatProtonPass,
		File: "Proton Pass_export.zip", Unencrypted: true,
		Steps: []string{
			"Open Proton Pass (the web app at pass.proton.me, the desktop app or the browser extension) and sign in.",
			"Open Settings › Export.",
			"Choose the format JSON. (Not PGP-encrypted JSON: secretvault cannot read that yet.)",
			"Click Export, type your Proton password if it asks, and save the file. It ends in .zip.",
		},
	},
	{
		Name: "aegis", Label: "Aegis Authenticator", Program: "Aegis", Format: svimport.FormatAegis, File: "aegis-export.json",
		Passphrase: "Aegis password", PassphraseHint: "Only if the export is encrypted",
		Steps: []string{
			"In Aegis on your phone, open the three-dot menu › Settings › Import & Export, and tap Export.",
			"Choose Aegis (.JSON), and leave Encrypt the vault ticked, so that your Aegis password protects the file.",
			"Tap OK, save the file, and copy it to this computer.",
			"Type your Aegis password with it.",
		},
	},
	{
		Name: "google-authenticator", Aliases: []string{"gauth", "google"}, Label: "Google Authenticator", Program: "Google Authenticator",
		Format: svimport.FormatGoogleAuthenticator, File: "google-authenticator.txt", Unencrypted: true,
		Steps: []string{
			"In Google Authenticator on your phone, open the menu › Transfer accounts › Export accounts, and pick the accounts to bring.",
			"It shows one or more QR codes. Scan each with a QR code scanner that shows the text it holds: a line that starts otpauth-migration://.",
			"Put those lines in a text file on this computer, one per line, and save it.",
		},
	},
	{
		Name: "cxf", Label: "Another password manager (Credential Exchange Format)", Program: "the other password manager", Format: svimport.FormatCXF,
		File: "export.json", Unencrypted: true,
		Steps: []string{
			"In the other password manager, choose its export to the Credential Exchange Format (CXF), which some call an export to another app.",
			"Save the export as a file on this computer.",
		},
	},
	{
		Name: "csv", Label: "A CSV file from any other program", Program: "the other program", Format: svimport.FormatCSV, File: "passwords.csv", Unencrypted: true,
		Steps: []string{
			"In the program that holds your passwords, export them as a CSV file (a spreadsheet file). LastPass, Dashlane, NordPass, Keeper and most others can.",
			"Its first line names the columns: one called password (or totp), and others such as name, url, username and notes.",
			"Save the file.",
		},
	},
}

// FindImportSource is the source called name (or one of its aliases),
// whatever its case.
func FindImportSource(name string) (ImportSource, bool) {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, s := range ImportSources {
		if s.Name == name {
			return s, true
		}
		for _, a := range s.Aliases {
			if a == name {
				return s, true
			}
		}
	}
	return ImportSource{}, false
}

// SourceNames lists the sources' names, for help texts.
func SourceNames() string {
	s := make([]string, len(ImportSources))
	for i, src := range ImportSources {
		s[i] = src.Name
	}
	return strings.Join(s, ", ")
}

// NumberedSteps are the steps, each numbered: "1. In Firefox, …".
func (s ImportSource) NumberedSteps() []string {
	out := make([]string, len(s.Steps))
	for i, st := range s.Steps {
		out[i] = fmt.Sprintf("%d. %s", i+1, st)
	}
	return out
}

// UnencryptedNote says, when the export holds every secret in the clear,
// to keep it no longer than it takes to import it ("" when it does not).
func (s ImportSource) UnencryptedNote() string {
	if !s.Unencrypted {
		return ""
	}
	return "The file holds your passwords unencrypted. Keep it only until they are imported, then delete it."
}

// DeleteExportNote says that an export which was not encrypted can go,
// now that it is imported into vault, and what deleting it does and does
// not do.
func DeleteExportNote(path, vault string) string {
	return fmt.Sprintf("%s still holds the passwords you imported, unencrypted: anyone who can read the file can read them. "+
		"They are in vault %s now, so you can delete it from %s.\n\n"+
		"Deleting removes the file as deleting any file does: it is not overwritten first, "+
		"and copies of it (backups, the trash, a download folder) are not touched.", filepath.Base(path), vault, filepath.Dir(path))
}

// RemoveExport deletes an export once it is imported: a plain remove,
// not a secure erase (the file's blocks are not overwritten).
func RemoveExport(path string) error { return os.Remove(path) }
