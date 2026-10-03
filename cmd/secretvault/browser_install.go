package main

import (
	"errors"
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svops"
)

// `secretvault browser install|uninstall|status`: making browsers start
// secretvault's native-messaging hosts, and undoing it exactly. install
// sets up secretvault's own extension's host; with --keepassxc, the
// legacy link, where the browsers would start KeePassXC's keepassxc-proxy
// for KeePassXC-Browser. What is written where, and how it is undone, is
// svops' (browser.go); here are the flags, the dry runs and what is said.

func (c *cli) browserInstall(args []string) error {
	fs := c.flags("browser install")
	var names multi
	fs.Var(&names, "browser", "install for `NAME` (repeatable; default: every browser used here): "+strings.Join(svops.BrowserNames, ", "))
	legacy := fs.Bool("keepassxc", false, "set up the legacy link for KeePassXC-Browser, not secretvault's own extension")
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--browser NAME]... [--keepassxc] [--dry-run]"); err != nil {
		return err
	}
	exe, err := svops.Executable() // the browsers start this program
	if err != nil {
		return err
	}
	native := svops.ExtensionHost
	if *legacy {
		native = svops.KeePassXCHost
	}
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
	if *legacy {
		fmt.Fprintln(c.stdout, "\nRestart the browsers, then connect KeePassXC-Browser from its toolbar button.")
		fmt.Fprintln(c.stdout, "Undo with 'secretvault browser uninstall --keepassxc'.")
		return nil
	}
	fmt.Fprintln(c.stdout, "\nRestart the browsers, then load the extension: 'secretvault browser extension' writes it,")
	fmt.Fprintln(c.stdout, "and says how. Undo with 'secretvault browser uninstall --extension'.")
	return nil
}

func (c *cli) printHostPlan(p *svops.HostPlan, host string) {
	for _, l := range svops.HostPlanLines(p, host) {
		fmt.Fprintln(c.stdout, "  "+l)
	}
}

func (c *cli) browserUninstall(args []string) error {
	fs := c.flags("browser uninstall")
	legacy := fs.Bool("keepassxc", false, "undo only the legacy link for KeePassXC-Browser")
	extension := fs.Bool("extension", false, "undo only secretvault's own extension's host")
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--keepassxc | --extension] [--dry-run]"); err != nil {
		return err
	}
	var only *svops.NativeHost
	switch {
	case *legacy && *extension:
		return errors.New("--keepassxc and --extension: one, or neither for both")
	case *legacy:
		only = &svops.KeePassXCHost
	case *extension:
		only = &svops.ExtensionHost
	}
	done, err := svops.UninstallBrowsers(only, *dryRun)
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
		if only != nil && errors.Is(err, svops.ErrNoBrowserInstall) {
			return fmt.Errorf("%s is not installed in any browser", only.Title)
		}
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
