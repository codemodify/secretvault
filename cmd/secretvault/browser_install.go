package main

import (
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svops"
)

// `secretvault browser install|uninstall|status`: making browsers start
// secretvault's host for KeePassXC-Browser, where they would start
// KeePassXC's keepassxc-proxy, and undoing it exactly. What is written
// where, and how it is undone, is svops' (browser.go); here are the
// flags, the dry runs and what is said.

func (c *cli) browserInstall(args []string) error {
	fs := c.flags("browser install")
	var names multi
	fs.Var(&names, "browser", "install for `NAME` (repeatable; default: every browser used here): "+strings.Join(svops.BrowserNames, ", "))
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--browser NAME]... [--dry-run]"); err != nil {
		return err
	}
	plan, err := svops.PlanBrowserInstall(names, "")
	if err != nil {
		return err
	}
	host := plan.Host
	if *dryRun {
		fmt.Fprintf(c.stdout, "The browsers would start %s for KeePassXC-Browser:\n", host)
	}
	for _, p := range plan.Hosts {
		label := p.Label()
		if p.Skip != "" {
			fmt.Fprintf(c.stdout, "  %s: nothing to do: %s\n", label, p.Skip)
			continue
		}
		if *dryRun {
			c.printHostPlan(p, host)
			continue
		}
		rec, err := plan.Apply(p)
		if err != nil {
			return fmt.Errorf("%s: %w (undo what was done with 'secretvault browser uninstall')", label, err)
		}
		fmt.Fprintf(c.stdout, "%s: wrote %s\n", label, p.Spot.Manifest)
		if rec.Backup != nil {
			fmt.Fprintf(c.stdout, "  the manifest it replaced, %s, is kept to put back\n", svops.DescribeHost(rec.Backup.Host, host))
		}
	}
	if plan.KeePassXC {
		fmt.Fprintln(c.stdout, "\nKeePassXC writes its manifests back each time it starts with browser integration on.")
		fmt.Fprintln(c.stdout, "Turn that off in KeePassXC (Settings > Browser Integration), or its advanced option to")
		fmt.Fprintln(c.stdout, "update the manifest files at startup. 'secretvault browser status' shows which host each browser starts.")
	}
	if *dryRun {
		fmt.Fprintln(c.stdout, "\nNothing was changed. Undo an install with 'secretvault browser uninstall'.")
		return nil
	}
	fmt.Fprintln(c.stdout, "\nRestart the browsers, then connect KeePassXC-Browser from its toolbar button.")
	fmt.Fprintln(c.stdout, "Undo with 'secretvault browser uninstall'.")
	return nil
}

func (c *cli) printHostPlan(p *svops.HostPlan, host string) {
	label := p.Label()
	switch {
	case p.Spot.RegKey != "":
		fmt.Fprintf(c.stdout, "  %s: write %s\n", label, p.Spot.Manifest)
		if p.RegPrev != nil {
			fmt.Fprintf(c.stdout, "      point HKEY_CURRENT_USER\\%s at it; it names %s now, to put back on uninstall\n",
				p.Spot.RegKey, svops.DescribeHost(p.Current.Host, host))
		} else {
			fmt.Fprintf(c.stdout, "      make HKEY_CURRENT_USER\\%s, naming it\n", p.Spot.RegKey)
		}
	case p.Current.Exists:
		fmt.Fprintf(c.stdout, "  %s: replace %s\n", label, p.Spot.Manifest)
		fmt.Fprintf(c.stdout, "      it names %s now; a copy is kept, to put back on uninstall\n", svops.DescribeHost(p.Current.Host, host))
	default:
		fmt.Fprintf(c.stdout, "  %s: write %s\n", label, p.Spot.Manifest)
		if made := p.MakesDirs(); len(made) > 0 {
			fmt.Fprintf(c.stdout, "      making %s\n", strings.Join(made, ", "))
		}
	}
}

func (c *cli) browserUninstall(args []string) error {
	fs := c.flags("browser uninstall")
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--dry-run]"); err != nil {
		return err
	}
	done, err := svops.UninstallBrowsers(*dryRun)
	for _, u := range done {
		label := u.Label()
		switch {
		case u.Changed:
			// Someone else's now: it is forgotten, and its backup left
			// where it is for the person to decide.
			fmt.Fprintf(c.stdout, "%s: %s changed since secretvault installed it: left as it is\n", label, u.Manifest)
			if u.Backup != nil && u.Backup.Copy != "" {
				fmt.Fprintf(c.stdout, "  the manifest it replaced is still in %s\n", u.Backup.Copy)
			}
		case *dryRun:
			c.printUndo(u.InstalledHost)
		case u.RegKey != "" && u.RegPrev != nil:
			fmt.Fprintf(c.stdout, "%s: HKEY_CURRENT_USER\\%s names %s again\n", label, u.RegKey, *u.RegPrev)
		case u.RegKey != "":
			fmt.Fprintf(c.stdout, "%s: removed HKEY_CURRENT_USER\\%s\n", label, u.RegKey)
		case u.Backup != nil:
			fmt.Fprintf(c.stdout, "%s: put back the manifest naming %s, at %s\n", label, svops.DescribeHost(u.Backup.Host, u.Host), u.Manifest)
		default:
			fmt.Fprintf(c.stdout, "%s: removed %s\n", label, u.Manifest)
		}
	}
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintln(c.stdout, "Nothing was changed.")
	}
	return nil
}

func (c *cli) printUndo(rec svops.InstalledHost) {
	label := strings.Join(rec.Browsers, ", ")
	switch {
	case rec.RegKey != "" && rec.RegPrev != nil:
		fmt.Fprintf(c.stdout, "%s: point HKEY_CURRENT_USER\\%s back at %s, and remove %s\n", label, rec.RegKey, *rec.RegPrev, rec.Manifest)
	case rec.RegKey != "":
		fmt.Fprintf(c.stdout, "%s: remove HKEY_CURRENT_USER\\%s and %s\n", label, rec.RegKey, rec.Manifest)
	case rec.Backup != nil && rec.Backup.Link != "":
		fmt.Fprintf(c.stdout, "%s: make %s a link to %s again\n", label, rec.Manifest, rec.Backup.Link)
	case rec.Backup != nil:
		fmt.Fprintf(c.stdout, "%s: put back %s as it was, from %s\n", label, rec.Manifest, rec.Backup.Copy)
	default:
		fmt.Fprintf(c.stdout, "%s: remove %s\n", label, rec.Manifest)
	}
	for i := len(rec.MadeDirs) - 1; i >= 0; i-- {
		fmt.Fprintf(c.stdout, "  and %s, if empty\n", rec.MadeDirs[i])
	}
}

func (c *cli) browserStatus(args []string) error {
	if _, err := parse(c.flags("browser status"), args, 0, 0, ""); err != nil {
		return err
	}
	state, host, browsers, err := svops.BrowserStatus("")
	if err != nil {
		return err
	}
	if state != nil {
		fmt.Fprintf(c.stdout, "Installed %s, starting %s (undo with 'secretvault browser uninstall').\n\n",
			state.When.Local().Format("2006-01-02 15:04"), state.Host)
	}
	for _, b := range browsers {
		s := b.Spot
		switch {
		case b.NoKey:
			fmt.Fprintf(c.stdout, "%-9s no host (no HKEY_CURRENT_USER\\%s)\n", s.Name, s.RegKey)
			continue
		case b.Err != nil:
			fmt.Fprintf(c.stdout, "%-9s %s: %v\n", s.Name, b.Path, b.Err)
			continue
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
			line += svops.DescribeHost(b.Current.Host, host)
		}
		switch {
		case b.Changed:
			line += "; changed since secretvault installed it"
		case b.Ours && b.Backup != nil:
			line += "; " + svops.DescribeHost(b.Backup.Host, host) + " kept, to put back"
		}
		fmt.Fprintln(c.stdout, line)
	}
	return nil
}
