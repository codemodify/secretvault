package main

import (
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svops"
)

// `secretvault browser install|uninstall|status`: making browsers start
// secretvault's native-messaging host, for its own extension, and undoing
// it exactly. What is written where, and how it is undone, is svops'
// (browser.go); here are the flags, the dry runs and what is said.

func (c *cli) browserInstall(args []string) error {
	fs := c.flags("browser install")
	var names multi
	fs.Var(&names, "browser", "install for `NAME` (repeatable; default: every browser used here): "+strings.Join(svops.BrowserNames, ", "))
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--browser NAME]... [--dry-run]"); err != nil {
		return err
	}
	exe, err := svops.Executable() // the browsers start this program
	if err != nil {
		return err
	}
	native := svops.ExtensionHost
	plan, err := svops.PlanBrowserInstall(native, names, exe)
	if err != nil {
		return err
	}
	host := plan.Host
	if *dryRun {
		fmt.Fprintf(c.stdout, "The browsers would start %s for %s:\n", host, native.Title)
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
		if _, err := plan.Apply(p); err != nil {
			return fmt.Errorf("%s: %w (undo what was done with 'secretvault browser uninstall')", label, err)
		}
		fmt.Fprintf(c.stdout, "%s: wrote %s\n", label, p.Spot.Manifest)
	}
	if *dryRun {
		fmt.Fprintln(c.stdout, "\nNothing was changed. Undo an install with 'secretvault browser uninstall'.")
		return nil
	}
	fmt.Fprintln(c.stdout, "\nRestart the browsers, then load the extension: 'secretvault browser extension' writes it,")
	fmt.Fprintln(c.stdout, "and says how. Undo with 'secretvault browser uninstall'.")
	return nil
}

func (c *cli) printHostPlan(p *svops.HostPlan, host string) {
	for _, l := range svops.HostPlanLines(p, host) {
		fmt.Fprintln(c.stdout, "  "+l)
	}
}

func (c *cli) browserUninstall(args []string) error {
	fs := c.flags("browser uninstall")
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--dry-run]"); err != nil {
		return err
	}
	done, err := svops.UninstallBrowsers(nil, *dryRun)
	for _, u := range done {
		lines := svops.UninstalledLines(u)
		if *dryRun && !u.Changed {
			lines = svops.UndoLines(u.InstalledHost)
		}
		for _, l := range lines {
			fmt.Fprintln(c.stdout, l)
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

func (c *cli) browserStatus(args []string) error {
	if _, err := parse(c.flags("browser status"), args, 0, 0, ""); err != nil {
		return err
	}
	exe, err := svops.Executable()
	if err != nil {
		return err
	}
	// What was found is said even when a browser's place could not be
	// read, which ends the list.
	state, host, browsers, err := svops.BrowserStatus(exe)
	if state != nil {
		fmt.Fprintf(c.stdout, "Installed %s, starting %s (undo with 'secretvault browser uninstall').\n",
			state.When.Local().Format("2006-01-02 15:04"), state.Host)
	}
	for _, h := range svops.NativeHosts {
		fmt.Fprintf(c.stdout, "\n%s:\n", svops.NativeHostHeading(h))
		for _, b := range svops.StatesOf(browsers, h) {
			fmt.Fprintln(c.stdout, "  "+svops.BrowserStateLine(b, host))
		}
	}
	return err
}
