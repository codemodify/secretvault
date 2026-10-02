package svops

import (
	"fmt"
	"path/filepath"
	"strings"
)

// What every interface shows of a change to the desktop before making it
// (the CLI's --dry-run, the managers' plans), and of the state the change
// left: the same words in each.

// HostPlanLines say what installing for one browser's place would do.
func HostPlanLines(p *HostPlan, host string) []string {
	label := p.Label()
	switch {
	case p.Spot.RegKey != "":
		out := []string{fmt.Sprintf("%s: write %s", label, p.Spot.Manifest)}
		if p.RegPrev != nil {
			return append(out, fmt.Sprintf("    point HKEY_CURRENT_USER\\%s at it; it names %s now, to put back on uninstall",
				p.Spot.RegKey, DescribeHost(p.Current.Host, host)))
		}
		return append(out, fmt.Sprintf("    make HKEY_CURRENT_USER\\%s, naming it", p.Spot.RegKey))
	case p.Current.Exists:
		return []string{fmt.Sprintf("%s: replace %s", label, p.Spot.Manifest),
			fmt.Sprintf("    it names %s now; a copy is kept, to put back on uninstall", DescribeHost(p.Current.Host, host))}
	}
	out := []string{fmt.Sprintf("%s: write %s", label, p.Spot.Manifest)}
	if made := p.MakesDirs(); len(made) > 0 {
		out = append(out, fmt.Sprintf("    making %s", strings.Join(made, ", ")))
	}
	return out
}

// UndoLines say what uninstalling one browser's place would do.
func UndoLines(rec InstalledHost) []string {
	label := strings.Join(rec.Browsers, ", ")
	var out []string
	switch {
	case rec.RegKey != "" && rec.RegPrev != nil:
		out = append(out, fmt.Sprintf("%s: point HKEY_CURRENT_USER\\%s back at %s, and remove %s", label, rec.RegKey, *rec.RegPrev, rec.Manifest))
	case rec.RegKey != "":
		out = append(out, fmt.Sprintf("%s: remove HKEY_CURRENT_USER\\%s and %s", label, rec.RegKey, rec.Manifest))
	case rec.Backup != nil && rec.Backup.Link != "":
		out = append(out, fmt.Sprintf("%s: make %s a link to %s again", label, rec.Manifest, rec.Backup.Link))
	case rec.Backup != nil:
		out = append(out, fmt.Sprintf("%s: put back %s as it was, from %s", label, rec.Manifest, rec.Backup.Copy))
	default:
		out = append(out, fmt.Sprintf("%s: remove %s", label, rec.Manifest))
	}
	for i := len(rec.MadeDirs) - 1; i >= 0; i-- {
		out = append(out, fmt.Sprintf("  and %s, if empty", rec.MadeDirs[i]))
	}
	return out
}

// UninstalledLines say what uninstalling did for one browser's place.
func UninstalledLines(u Uninstalled) []string {
	label := u.Label()
	switch {
	case u.Changed:
		out := []string{fmt.Sprintf("%s: %s changed since secretvault installed it: left as it is", label, u.Manifest)}
		if u.Backup != nil && u.Backup.Copy != "" {
			out = append(out, fmt.Sprintf("  the manifest it replaced is still in %s", u.Backup.Copy))
		}
		return out
	case u.RegKey != "" && u.RegPrev != nil:
		return []string{fmt.Sprintf("%s: HKEY_CURRENT_USER\\%s names %s again", label, u.RegKey, *u.RegPrev)}
	case u.RegKey != "":
		return []string{fmt.Sprintf("%s: removed HKEY_CURRENT_USER\\%s", label, u.RegKey)}
	case u.Backup != nil:
		return []string{fmt.Sprintf("%s: put back the manifest naming %s, at %s", label, DescribeHost(u.Backup.Host, u.Host), u.Manifest)}
	}
	return []string{fmt.Sprintf("%s: removed %s", label, u.Manifest)}
}

// BrowserStateLine says which host a browser starts.
func BrowserStateLine(b BrowserState, host string) string {
	s := b.Spot
	switch {
	case b.NoKey:
		return fmt.Sprintf("%-9s no host (no HKEY_CURRENT_USER\\%s)", s.Name, s.RegKey)
	case b.Err != nil:
		return fmt.Sprintf("%-9s %s: %v", s.Name, b.Path, b.Err)
	}
	line := fmt.Sprintf("%-9s ", s.Name)
	switch {
	case !b.Current.Exists:
		used := "not used here"
		if s.Used() {
			used = "used here"
		}
		line += "no host (" + used + ")"
	default:
		line += DescribeHost(b.Current.Host, host)
	}
	switch {
	case b.Changed:
		line += "; changed since secretvault installed it"
	case b.Ours && b.Backup != nil:
		line += "; " + DescribeHost(b.Backup.Host, host) + " kept, to put back"
	}
	return line
}

// TakeoverLines say what a takeover would do: importing the keyring's
// secrets first (when importFirst and exe holds the keyring), then the
// plan.
func TakeoverLines(p *TakeoverPlan, exe string, importFirst bool) []string {
	out := []string{"The keyring now: " + DescribeExe(exe), ""}
	if importFirst && exe != "" {
		out = append(out, "1. Import its secrets (see 'secretvault keyring import --dry-run').")
	}
	for _, f := range p.Order {
		out = append(out, "- write "+f)
	}
	for _, r := range p.Restart {
		out = append(out, "- restart "+r+" (systemctl --user)")
	}
	out = append(out, "- turn on secretvaultd's Secret Service")
	for _, n := range p.Notes {
		out = append(out, "- by hand: "+n)
	}
	return out
}

// RestoreLines say what undoing the takeover would do.
func RestoreLines(s *TakeoverState) []string {
	var out []string
	for _, f := range s.Created {
		out = append(out, "- remove "+f)
	}
	for _, r := range s.Restart {
		out = append(out, "- restart "+r+" (systemctl --user)")
	}
	return append(out, "- turn off secretvaultd's Secret Service")
}

// GnuPGOwnHomeNote is said when the home set up is the person's own.
func GnuPGOwnHomeNote(home string) string {
	return fmt.Sprintf("%s is your own GnuPG home: gpg will use secretvault's keys, and no longer gpg-agent's.\n"+
		"Where systemd starts gpg-agent by its sockets, stop that first: systemctl --user mask --now gpg-agent.socket gpg-agent-ssh.socket gpg-agent-extra.socket gpg-agent-browser.socket", home)
}

// GnuPGPlanLines say what setting a GnuPG home up would do.
func GnuPGPlanLines(p *GnuPGPlan) []string {
	out := []string{fmt.Sprintf("Pointing the GnuPG home %s at secretvault would:", p.Home)}
	if !p.HomeExists {
		out = append(out, fmt.Sprintf("- make the directory %s (0700)", p.Home))
	}
	out = append(out, fmt.Sprintf("- link %s (where gpg looks for its agent) to %s", p.Socket, p.Agent))
	if p.SSHSocket != "" && p.SSHAgent != "" {
		out = append(out, fmt.Sprintf("- link %s (its SSH agent) to %s", p.SSHSocket, p.SSHAgent))
	}
	for _, k := range p.Keys {
		out = append(out, fmt.Sprintf("- import the public key %s  %s (%s), trusted as your own", GroupFingerprint(k.Fingerprint), FirstUserID(k), k.Item))
	}
	out = append(out, fmt.Sprintf("- add to %s: %s", filepath.Join(p.Home, "gpg.conf"), p.AgentProgram))
	return append(out, GnuPGNotes(p.Skipped, p.Unreachable, p.Home)...)
}

// GnuPGNotes say what gpg will not get.
func GnuPGNotes(skipped []string, unreachable int, home string) []string {
	var out []string
	for _, s := range skipped {
		out = append(out, "Left out: "+s)
	}
	if unreachable > 0 {
		out = append(out, fmt.Sprintf("Note: %d secret keys in %s are GnuPG's own, which gpg cannot use while secretvault is its agent;\n"+
			"take them into the vault first ('gpg --export-secret-keys KEY | secretvault pgp import -').",
			unreachable, filepath.Join(home, "private-keys-v1.d")))
	}
	return out
}

// GnuPGRemoveText says what removing a home's setup would do.
func GnuPGRemoveText(home string) string {
	return fmt.Sprintf("Removing would take away the links to secretvaultd in %s's socket directory, and secretvault's agent-program line from %s; the public keys stay.", home, filepath.Join(home, "gpg.conf"))
}
