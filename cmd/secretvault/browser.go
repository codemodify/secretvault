package main

import (
	"fmt"
	"strings"

	"github.com/codemodify/secretvault/svext"
)

// Browsers: secretvault's own extension (svext, browser_ext.go,
// svd/browser_ext.go).
//
//	secretvault-browser             the native-messaging host the browser starts
//	secretvault browser install     make the browsers start it (browser_install.go)
//	secretvault browser uninstall   undo install exactly
//	secretvault browser status      which host each browser starts
//	secretvault browser extension   write the extension out, to load it
//
// The host is this program, named secretvault-browser (a link to it) or
// recognised by the arguments browsers start hosts with, which say which
// extension it was started for: it serves secretvault's own, and refuses
// any other. The daemon works out which browser started it.

// browserOrigin is the extension a browser started the host for, from
// the host's arguments: Chrome and its kin pass the extension's origin
// (chrome-extension://ID/, and on Windows --parent-window=N), Firefox the
// manifest's path and the extension's ID.
func browserOrigin(args []string) (string, bool) {
	switch {
	case len(args) == 0:
		return "", false
	case strings.HasPrefix(args[0], "chrome-extension://"):
		return args[0], true
	case strings.HasSuffix(args[0], ".json") && len(args) >= 2:
		return args[1], true
	}
	return "", false
}

// cmdBrowserHost is the host a browser starts: for secretvault's
// extension, and nothing else.
func (c *cli) cmdBrowserHost(args []string) error {
	origin, _ := browserOrigin(args)
	if !svext.Ours(origin) {
		// The manifest lets only secretvault's extension start the host;
		// this says so again (Chromium does not say which manifest started
		// it).
		return fmt.Errorf("the host %s serves the secretvault extension only, not %q", svext.HostName, origin)
	}
	return c.extensionHost(origin)
}

func (c *cli) cmdBrowser(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "install":
		return c.browserInstall(args[1:])
	case "uninstall":
		return c.browserUninstall(args[1:])
	case "status":
		return c.browserStatus(args[1:])
	case "extension":
		return c.browserExtension(args[1:])
	}
	fmt.Fprintf(c.stderr, "secretvault browser: unknown subcommand %q (install, uninstall, status, extension)\n", args[0])
	return errUsage
}
