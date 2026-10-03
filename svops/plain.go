package svops

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/codemodify/secretvault/svrpc"
)

// Plain is a change said for a person before it is made: every face that
// asks before changing something shows its title and summary first, and
// its technical details only when asked (the managers' "Show details").
// The CLI's --dry-run prints the title and summary over the details,
// which are its own lines, unchanged.
//
// The words follow docs/wording.md: what happens, why, what does not
// change, and how to undo it, in one to three sentences, with no file
// path, internal name or command in them; those are the details'.
type Plain struct {
	Title   string   // a few words: "Let Firefox use secretvault"
	Summary string   // one to three sentences
	Notes   []string // what the person has to know or do besides, said plainly; often none
	Action  string   // the confirm button: "Allow Firefox"; "" when there is nothing to do
	Details []string // the technical lines, as the CLI's --dry-run prints them
}

// Text is the plan as the CLI prints it over its details: the title, the
// summary and the notes, a paragraph each.
func (p Plain) Text() string {
	parts := []string{p.Title, p.Summary}
	parts = append(parts, p.Notes...)
	return strings.Join(parts, "\n\n")
}

// andList joins names as a sentence does: "a", "a and b", "a, b and c".
func andList(names []string) string {
	switch len(names) {
	case 0:
		return ""
	case 1:
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

// VaultPhrase names a vault in a sentence: "vault work", or, for "", the
// default vault, which the CLI uses when none is named.
func VaultPhrase(vault string) string {
	if vault == "" {
		return "your default vault"
	}
	return "vault " + vault
}

// countOf says n things: "1 password", "3 passwords".
func countOf(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

// browserTitles are the browsers' names for people, by --browser's names.
var browserTitles = map[string]string{
	"firefox": "Firefox", "chrome": "Google Chrome", "chromium": "Chromium",
	"brave": "Brave", "edge": "Microsoft Edge", "vivaldi": "Vivaldi",
}

// BrowserTitle names a browser for people ("firefox": "Firefox").
func BrowserTitle(name string) string {
	if t, ok := browserTitles[name]; ok {
		return t
	}
	return name
}

func browserTitlesOf(names []string) []string {
	var out []string
	for _, n := range names {
		out = append(out, BrowserTitle(n))
	}
	return out
}

// Todo are the manifests the plan writes: those it does not skip.
func (plan *BrowserInstallPlan) Todo() []*HostPlan {
	var out []*HostPlan
	for _, p := range plan.Hosts {
		if p.Skip == "" {
			out = append(out, p)
		}
	}
	return out
}

// BrowserInstallDetails are the CLI's --dry-run lines of the plan, from
// "The browsers would start" on: a manifest's, or why it is skipped.
func BrowserInstallDetails(plan *BrowserInstallPlan) []string {
	out := []string{fmt.Sprintf("The browsers would start %s for %s:", plan.Host, plan.Native.Title)}
	for _, p := range plan.Hosts {
		if p.Skip != "" {
			out = append(out, fmt.Sprintf("  %s: nothing to do: %s", p.Label(), p.Skip))
			continue
		}
		for _, l := range HostPlanLines(p, plan.Host) {
			out = append(out, "  "+l)
		}
	}
	return out
}

// AndList joins names as a sentence does: "a", "a and b", "a, b and c".
func AndList(names []string) string { return andList(names) }

// BrowserCanUse says whether a browser can start secretvault for the
// extension, for a person (the CLI's browser status says it in its own
// words, BrowserStateLine); host is the program secretvault's manifests
// name.
func BrowserCanUse(b BrowserState, host string) string {
	switch {
	case b.NoKey:
		return "Not yet"
	case b.Err != nil:
		return "Not known: its settings file cannot be read"
	case !b.Current.Exists && b.Spot.Used():
		return "Not yet"
	case !b.Current.Exists:
		return "Not yet (not found on this computer)"
	case b.Changed:
		return "Its file was changed since it was set up: take the permission back, then set it up again"
	case b.Current.Host == host:
		return "Yes"
	case b.Current.Host == "":
		return "No: a settings file naming no program is there"
	}
	return "No: another program's settings file is there"
}

// BrowserSetUpWhen says when the browsers were set up.
func BrowserSetUpWhen(state *BrowserInstall) string {
	return "Set up on " + state.When.Local().Format("2006-01-02") + " at " + state.When.Local().Format("15:04") + "."
}

// ExtensionSaveAbout says, over the managers' saving of the extension,
// what it is for and what to expect.
const ExtensionSaveAbout = "This saves the secretvault extension for you to add to your browser: Firefox takes the .zip file; " +
	"Chrome, Chromium, Brave, Edge and Vivaldi take a folder. In Firefox it lasts until Firefox restarts, and has to be added again after that."

// ExtensionAddedLines are the steps to add the extension written to
// file (a folder when dir), as the managers say them: the CLI's
// ExtensionWrittenLines, but for its commands and its pointer to the
// docs, which a manager's own button replaces.
func ExtensionAddedLines(file string, dir bool) []string {
	var out []string
	for _, l := range ExtensionWrittenLines(file, dir) {
		switch {
		case strings.Contains(l, "secretvault browser install"):
		case strings.Contains(l, "docs/browser.md"):
			out = append(out, "Firefox keeps only extensions Mozilla has signed: this one has to be added again after each restart.")
		default:
			out = append(out, l)
		}
	}
	return out
}

// BrowserInstallPlain says a browser install for a person.
func BrowserInstallPlain(plan *BrowserInstallPlan) Plain {
	var names, done, changed, other []string
	registry := false
	for _, p := range plan.Hosts {
		titles := browserTitlesOf(p.Browsers)
		switch p.Skip {
		case "":
			names = append(names, titles...)
			registry = registry || p.Spot.RegKey != ""
		case SkipAlreadyDone:
			done = append(done, titles...)
		case SkipOther:
			other = append(other, titles...)
		default:
			changed = append(changed, titles...)
		}
	}
	who := andList(names)
	pl := Plain{Details: BrowserInstallDetails(plan)}
	switch {
	case len(names) > 0:
		file, needs := "one small settings file in its folder", "needs"
		if len(names) > 1 {
			file, needs = "one small settings file in each browser's folder", "need"
		}
		if registry {
			file += ", and points a registry entry at it"
		}
		pl.Title = "Let " + who + " use secretvault"
		pl.Summary = fmt.Sprintf("%s %s your permission to start secretvault when the secretvault extension asks for a login. "+
			"This writes %s. No passwords move, nothing else in the browser changes, and undoing it removes the file again.", who, needs, file)
		pl.Action = "Allow " + who
		if len(names) > 2 {
			pl.Action = fmt.Sprintf("Allow %d browsers", len(names))
		}
	case len(done) > 0:
		pl.Title = "Nothing to set up"
		pl.Summary = andList(done) + " can already use secretvault, so there is nothing to change."
	default:
		pl.Title = "Nothing to set up"
		pl.Summary = "secretvault cannot set up this browser now; the note says why. Nothing is changed."
	}
	if len(done) > 0 && len(names) > 0 {
		pl.Notes = append(pl.Notes, andList(done)+" can already use secretvault, and is left as it is.")
	}
	if len(other) > 0 {
		pl.Notes = append(pl.Notes, andList(other)+" already has this kind of file from another program, so secretvault leaves it alone. "+
			"To use secretvault there instead, remove that program's browser connection first, then set this up again.")
	}
	if len(changed) > 0 {
		pl.Notes = append(pl.Notes, andList(changed)+": the file secretvault wrote was changed since, so it is left alone. "+
			"Take the permission back first, then set it up again.")
	}
	return pl
}

// BrowserUninstallDetails are the CLI's uninstall --dry-run lines.
func BrowserUninstallDetails(would []Uninstalled) []string {
	var out []string
	for _, u := range would {
		if u.Changed {
			out = append(out, UninstalledLines(u)...)
		} else {
			out = append(out, UndoLines(u.InstalledHost)...)
		}
	}
	return out
}

// BrowserUninstallPlain says undoing the browsers' setup (as an
// uninstall's dry run found it) for a person.
func BrowserUninstallPlain(would []Uninstalled) Plain {
	var names, changed []string
	for _, u := range would {
		if u.Changed {
			changed = append(changed, browserTitlesOf(u.Browsers)...)
			continue
		}
		names = append(names, browserTitlesOf(u.Browsers)...)
	}
	who := andList(names)
	pl := Plain{Details: BrowserUninstallDetails(would)}
	if len(names) == 0 {
		pl.Title = "Nothing to undo"
		pl.Summary = "Nothing will be removed."
	} else {
		pl.Title = "Stop " + who + " using secretvault"
		pl.Summary = who + " will no longer start secretvault, so the secretvault extension cannot fill logins there. " +
			"The settings file secretvault wrote is removed. Your passwords stay in the vault."
		pl.Action = "Remove access"
	}
	if len(changed) > 0 {
		pl.Notes = append(pl.Notes, andList(changed)+": the file secretvault wrote was changed since, so it is left as it is.")
	}
	return pl
}

// ImportPlain says storing what an import read from file (its names, and
// its warnings) in vault: the managers' preview, after the CLI's
// --dry-run.
func ImportPlain(file, vault string, names, warnings []string, overwrite bool) Plain {
	base := filepath.Base(file)
	pl := Plain{Details: append([]string(nil), names...)}
	for _, w := range warnings {
		pl.Details = append(pl.Details, "warning: "+w)
	}
	if len(names) == 0 {
		pl.Title = "Nothing to import"
		pl.Summary = base + " holds nothing secretvault can import."
		return pl
	}
	n := countOf(len(names), "item", "items")
	pl.Title = "Import into vault " + vault
	pl.Summary = fmt.Sprintf("%s from %s will be added to vault %s. Items that are there already are skipped. The file itself is not changed.", SentenceStart(n), base, vault)
	if overwrite {
		pl.Summary = strings.Replace(pl.Summary, "are skipped", "are replaced", 1)
	}
	if len(warnings) > 0 {
		pl.Notes = append(pl.Notes, SentenceStart(countOf(len(warnings), "warning", "warnings"))+": the details say what.")
	}
	pl.Action = "Import " + n
	return pl
}

// KeyringName names the program that holds the keyring for people:
// "GNOME Keyring", "KWallet"; "the current keyring" when it is not known.
func KeyringName(exe string) string {
	base := filepath.Base(exe)
	switch {
	case exe == "":
		return "the current keyring"
	case strings.HasPrefix(base, "gnome-keyring"):
		return "GNOME Keyring"
	case strings.HasPrefix(base, "ksecretd"), strings.HasPrefix(base, "kwalletd"):
		return "KWallet"
	case strings.HasPrefix(base, "keepassxc"):
		return "KeePassXC"
	case strings.HasPrefix(base, "oo7"):
		return "oo7"
	case strings.HasPrefix(base, "secretvault"):
		return "secretvault"
	}
	return base
}

// KeyringImportPlain says copying the keyring's secrets (names, as
// ImportKeyring without a client says them) into vault under prefix.
func KeyringImportPlain(exe, vault, prefix string, names, warnings []string) Plain {
	from := KeyringName(exe)
	pl := Plain{Details: append([]string(nil), names...)}
	for _, w := range warnings {
		pl.Details = append(pl.Details, "warning: "+w)
	}
	if len(names) == 0 {
		pl.Title = "Nothing to copy"
		pl.Summary = SentenceStart(from) + " holds no passwords to copy."
		return pl
	}
	n := countOf(len(names), "password", "passwords")
	pl.Title = "Copy the keyring's passwords into " + vault
	pl.Summary = fmt.Sprintf("%s from %s %s copied into vault %s, in the folder %s. %s keeps its own copies, and nothing changes for your apps.",
		SentenceStart(n), from, isAre(len(names)), vault, strings.TrimSuffix(prefix, "/")+"/", SentenceStart(from))
	if len(warnings) > 0 {
		pl.Notes = append(pl.Notes, "Some could not be read as they are; the details say which.")
	}
	pl.Action = "Copy " + n
	return pl
}

func isAre(n int) string {
	if n == 1 {
		return "is"
	}
	return "are"
}

// SentenceStart capitalises the first letter, for a sentence that starts
// with a name ("the current keyring").
func SentenceStart(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// TakeoverPlain says a keyring takeover for a person: from the keyring
// at exe, first importing its secrets into vault (the default one when
// "") when importFirst.
func TakeoverPlain(p *TakeoverPlan, exe string, importFirst bool, vault string) Plain {
	from := KeyringName(exe)
	pl := Plain{
		Title:   "Make secretvault your system keyring",
		Action:  "Take over the keyring",
		Details: TakeoverLines(p, exe, importFirst),
	}
	if exe == "" {
		pl.Summary = "No program is the system keyring now, so apps cannot keep passwords such as Wi-Fi, mail and chat logins there. " +
			"secretvault becomes the system keyring: apps keep their passwords in your vault and must ask you before they read one."
	} else {
		pl.Summary = "Apps keep passwords such as Wi-Fi, mail and chat logins in the system keyring, now " + from +
			"; secretvault takes its place, so an app has to ask you before it reads a password."
		if importFirst {
			pl.Summary += " First, its passwords are copied into " + VaultPhrase(vault) + ", and " + from + " keeps its own copies."
		}
	}
	pl.Summary += " Giving the keyring back undoes every change."
	for _, n := range p.Notes {
		pl.Notes = append(pl.Notes, takeoverNote(n, exe))
	}
	return pl
}

// takeoverNote says a step of a takeover left to the person (a
// TakeoverPlan's note, which the details keep as it is) in plain words.
func takeoverNote(n, exe string) string {
	switch {
	case strings.HasPrefix(n, "gnome-keyring runs only its secrets component"):
		return "GNOME Keyring would keep starting by itself: one command stops it for good, and the details have it."
	case strings.HasPrefix(n, "gnome-keyring is not a systemd user service"):
		return "Log out and back in afterwards, so that GNOME Keyring stops."
	case strings.HasPrefix(n, "KWallet serves"):
		return "Turn off KWallet's password service in System Settings › KWallet, then log out and back in."
	case strings.HasPrefix(n, "KeePassXC serves"):
		return "Turn off Secret Service Integration in KeePassXC's settings."
	case strings.HasPrefix(n, "oo7 serves"):
		return "Stop oo7's background service, and keep it from starting again."
	case strings.HasPrefix(n, "no Secret portal backend"):
		return "Apps installed as Flatpaks keep their own passwords, and will not ask secretvault."
	case strings.HasPrefix(n, "for Flatpak apps"):
		return "For apps installed as Flatpaks to use secretvault, one line in a settings file has to change; the details say which."
	case strings.HasSuffix(n, "holds the keyring: turn off its Secret Service integration"):
		return "Turn off the password service (Secret Service integration) in " + KeyringName(exe) + "."
	}
	return "Left for you to do: " + n + "."
}

// RestorePlain says giving the keyring back for a person.
func RestorePlain(s *TakeoverState) Plain {
	to := KeyringName(s.Previous)
	pl := Plain{
		Title:   "Give the keyring back",
		Action:  "Give the keyring back",
		Details: RestoreLines(s),
	}
	if s.Previous == "" {
		pl.Title, pl.Action = "Stop being the system keyring", "Stop being the keyring"
		pl.Summary = "secretvault stops being the system keyring, and what it changed is put back as it was. No program held the keyring before, " +
			"so apps have nowhere to keep passwords until one starts. Passwords in your vault stay there."
		return pl
	}
	pl.Title = "Give the keyring back to " + to
	pl.Summary = SentenceStart(to) + " becomes the system keyring again, and what secretvault changed is put back as it was. " +
		"Passwords apps saved while secretvault was the keyring stay only in your vault; " + to + " will not have them, so those apps may ask you to sign in again."
	return pl
}

// RestoredText says, as a done dialog's title and summary, that the
// keyring was given back to the program at previous ("" when none held
// it before).
func RestoredText(previous string) (title, summary string) {
	if previous == "" {
		return "Keyring given back", "secretvault is no longer the system keyring."
	}
	return "Keyring given back", SentenceStart(KeyringName(previous)) + " is your system keyring again."
}

// GnuPGSetupPlain says pointing a GnuPG home at secretvault, for vault's
// keys, for a person.
func GnuPGSetupPlain(p *GnuPGPlan, vault string) Plain {
	pl := Plain{
		Title:  "Let gpg use the keys in " + VaultPhrase(vault),
		Action: "Let gpg use the keys",
	}
	if p.OwnHome {
		pl.Details = append(pl.Details, strings.Split(GnuPGOwnHomeNote(p.Home), "\n")...)
	}
	pl.Details = append(pl.Details, GnuPGPlanLines(p)...)
	if p.OwnHome {
		pl.Summary = fmt.Sprintf("Your usual gpg will sign and decrypt with the OpenPGP keys in %s; the private keys stay inside secretvault, "+
			"and you are asked the first time each program uses one. Stopping it gives gpg its own agent back.", VaultPhrase(vault))
	} else {
		folder := "this GnuPG folder"
		if def, err := GnuPGHome(""); err == nil && sameDir(p.Home, def) {
			folder = "secretvault's own GnuPG folder"
		}
		pl.Summary = fmt.Sprintf("gpg run with %s will sign and decrypt with the OpenPGP keys in %s; the private keys stay inside secretvault, "+
			"and you are asked the first time each program uses one. Your usual gpg is not changed: to use these keys, gpg must be pointed at "+
			"this folder, which the next window shows how to do. Stopping it puts the folder back.", folder, VaultPhrase(vault))
	}
	if p.OwnHome {
		pl.Notes = append(pl.Notes, "gpg stops using its own agent for this folder. If systemd starts gpg-agent for you, stop that first: the details say how.")
	}
	if p.Unreachable > 0 {
		pl.Notes = append(pl.Notes, fmt.Sprintf("%s in this folder %s GnuPG's own, and gpg cannot use %s while secretvault is its agent. Move %s into the vault first.",
			SentenceStart(countOf(p.Unreachable, "private key", "private keys")), isAre(p.Unreachable), them(p.Unreachable), them(p.Unreachable)))
	}
	if len(p.Skipped) > 0 {
		pl.Notes = append(pl.Notes, SentenceStart(countOf(len(p.Skipped), "key is", "keys are"))+" left out; the details say why.")
	}
	return pl
}

func them(n int) string {
	if n == 1 {
		return "it"
	}
	return "them"
}

// GnuPGRemovePlain says no longer pointing a GnuPG home at secretvault.
func GnuPGRemovePlain(home string) Plain {
	return Plain{
		Title: "Stop gpg using the vault's keys",
		Summary: "gpg goes back to its own agent and its own keys for this GnuPG folder. The public keys secretvault gave it stay, " +
			"and nothing in the vault changes.",
		Action:  "Stop using the vault's keys",
		Details: []string{"GnuPG folder: " + home, GnuPGRemoveText(home)},
	}
}

// HelpersSetupPlain says setting the helpers up for a person.
func HelpersSetupPlain(p *HelpersPlan) Plain {
	return Plain{
		Title: "Let git, docker and age use secretvault",
		Summary: "git and docker will keep their logins in your vault, and age can decrypt with the vault's keys; each read is asked about, as any app's is. " +
			"This adds three small links next to secretvault, and one setting each to git and docker. What secretvault did not add is left alone, and undoing it removes only what it added.",
		Action:  "Set up git, docker and age",
		Details: append([]string{HelpersSetupIntro(p.CLI)}, p.SetupLines()...),
	}
}

// PlainRows say, for a person, whether git and docker keep their logins
// with secretvault: StatusRows' last two, which the CLI prints, in plain
// words.
func (p *HelpersPlan) PlainRows() [][2]string {
	git := "does not use secretvault yet"
	switch {
	case p.GitErr != nil:
		git = "not known: " + p.GitErr.Error()
	case p.GitHas:
		git = "keeps its logins in your vault"
	}
	docker := "keeps its logins in its own settings file"
	switch {
	case p.DockerErr != nil:
		docker = "not known: " + p.DockerErr.Error()
	case p.DockerStore == helperStore:
		docker = "keeps its logins in your vault"
	case p.DockerStore != "":
		docker = "keeps its logins with " + p.DockerStore
	}
	return [][2]string{{"git", git}, {"docker", docker}}
}

// HelpersUndoPlain says undoing the helpers' setup for a person.
func HelpersUndoPlain(p *HelpersPlan) Plain {
	pl := Plain{
		Title:   "Stop git, docker and age using secretvault",
		Summary: "git and docker go back to keeping their logins as they did before, and only what secretvault added is removed. Logins already in your vault stay there.",
		Action:  "Remove the setup",
		Details: append([]string{HelpersUndoIntro}, p.UndoLines()...),
	}
	if !p.Undoable() {
		pl.Title, pl.Summary, pl.Action = "Nothing to undo", "git, docker and age are not set up to use secretvault.", ""
	}
	return pl
}

// LoginUnlockPlain says having vault open at login, for a person.
func LoginUnlockPlain(vault string) Plain {
	return Plain{
		Title: "Open vault " + vault + " when you log in?",
		Summary: "Your computer will keep a key that opens vault " + vault + " whenever you log in, so you will not need its passphrase. " +
			"It locks when you log out, not after a few idle minutes. Apps still ask you before they read a password, and you can turn this off at any time.",
		Notes:  []string{"Anyone who can use your logged-in account can then open this vault."},
		Action: "Open it at login",
		Details: []string{
			"adds a keyslot (another way to open the vault) whose key the operating system seals to you, on this machine",
			"the vault locks when you log out, and no longer after idle minutes, on screen lock or on sleep",
			"turning it off removes that keyslot",
		},
	}
}

// HostInitPlain says making the host identity, for a person: the form
// that asks how is the confirmation.
func HostInitPlain() Plain {
	return Plain{
		Title: "Make this server's identity",
		Summary: "The host daemon needs its own key to open the vaults shared with this server. Make it once: a new one means sharing those vaults with it again. " +
			"Sealed, it is tied to this machine's security chip and never written out unencrypted; otherwise it is a file only root can read.",
		Action: "Make the identity",
	}
}

// HostRulePlain says allowing (or denying) r on the host daemon.
func HostRulePlain(r svrpc.HostRule, allow bool) Plain {
	var who string
	switch {
	case r.Unit != "":
		who = "the service " + r.Unit
	case r.Program != "":
		who = filepath.Base(r.Program) + ", run by " + r.User
	default:
		who = "programs run by " + r.User
	}
	pl := Plain{}
	for _, kv := range [][2]string{{"unit", r.Unit}, {"credential", r.Credential}, {"user", r.User}, {"program", r.Program}, {"reference", r.Ref}} {
		if kv[1] != "" {
			pl.Details = append(pl.Details, kv[0]+": "+kv[1])
		}
	}
	if len(r.Refs) > 0 {
		pl.Details = append(pl.Details, "references: "+strings.Join(r.Refs, " "))
	}
	what := "the secrets it was allowed"
	switch {
	case r.Credential != "":
		what = "its credential " + r.Credential
	case len(r.Refs) > 0:
		what = countOf(len(r.Refs), "secret", "secrets") + " named in the details"
	}
	if allow {
		pl.Title = "Let " + who + " read secrets"
		pl.Summary = SentenceStart(who) + " will get " + what + " from the host daemon, without anyone being asked. Denying it takes that back."
		pl.Action = "Let it read secrets"
		return pl
	}
	pl.Title = "Stop " + who + " reading secrets"
	pl.Summary = SentenceStart(who) + " will no longer get " + what + " from the host daemon. The secrets themselves do not change."
	pl.Action = "Stop it reading secrets"
	return pl
}
