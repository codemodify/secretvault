package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"text/tabwriter"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svbrowser"
	"github.com/codemodify/secretvault/svext"
	"github.com/codemodify/secretvault/svrpc"
)

// Browsers: secretvault's own extension (svext, browser_ext.go,
// svd/browser_ext.go), and the legacy link, secretvault in KeePassXC's
// place behind the KeePassXC-Browser extension (svbrowser,
// svd/browser.go), which goes once the extension has replaced it.
//
//	secretvault-browser             the native-messaging host the browser starts
//	secretvault browser install     make the browsers start it (browser_install.go)
//	secretvault browser uninstall   undo install exactly
//	secretvault browser status      which host each browser starts
//	secretvault browser extension   write the extension out, to load it
//	secretvault browser ls | rm     the KeePassXC-Browser extensions connected to a vault
//
// The host is this program, named secretvault-browser (a link to it) or
// recognised by the arguments browsers start hosts with, which say which
// extension it was started for: secretvault's own gets its protocol, and
// any other KeePassXC's. For KeePassXC-Browser it is a relay and nothing
// else: it passes each message to secretvaultd and the answers back, and
// holds no key. Either way, the daemon works out which browser started it.

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

// cmdBrowserHost relays between the extension (stdin and stdout) and the
// daemon. Messages go on as they come: one waiting for a person to answer
// a prompt does not hold up the others.
func (c *cli) cmdBrowserHost(args []string) error {
	origin, _ := browserOrigin(args)
	switch {
	case svext.Ours(origin):
		return c.extensionHost(origin)
	case ourManifest(args):
		// secretvault's host serves secretvault's extension alone; the
		// manifest says so to the browser, and this says it again.
		return fmt.Errorf("the host %s serves the secretvault extension only, not %q", svext.HostName, origin)
	}
	var wmu sync.Mutex
	write := func(frame []byte) {
		wmu.Lock()
		defer wmu.Unlock()
		svbrowser.WriteFrame(c.stdout, frame)
	}
	// No prompter: stdin and stdout belong to the browser, and the daemon
	// asks the person itself.
	cl, err := c.connect(secretvault.Options{
		Name: "secretvault-browser",
		OnNotify: func(method string, params json.RawMessage) {
			var f svrpc.BrowserFrame
			if method == svrpc.EBrowserFrame && json.Unmarshal(params, &f) == nil && len(f.Frame) > 0 {
				write(f.Frame)
			}
		},
	})
	if err != nil {
		return err
	}
	c.client = cl
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var opened svrpc.BrowserOpenResult
	if err := cl.Call(ctx, svrpc.MBrowserOpen, svrpc.BrowserOpenParams{Vault: c.vault, Origin: origin}, &opened); err != nil {
		return err
	}
	read := make(chan error, 1)
	go func() {
		for {
			frame, err := svbrowser.ReadFrame(c.stdin)
			if err != nil {
				read <- err
				return
			}
			go func() {
				var reply svrpc.BrowserFrame
				if err := cl.Call(ctx, svrpc.MBrowserMessage, svrpc.BrowserFrame{Frame: frame}, &reply); err != nil {
					if ctx.Err() == nil {
						fmt.Fprintln(c.stderr, "secretvault-browser:", describe(err))
					}
					return
				}
				if len(reply.Frame) > 0 {
					write(reply.Frame)
				}
			}()
		}
	}()
	select {
	case err := <-read:
		if errors.Is(err, io.EOF) {
			return nil // the browser closed the connection
		}
		return fmt.Errorf("reading from the browser: %w", err)
	case <-cl.Done():
		return errors.New("secretvaultd went away")
	}
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
	case "ls", "list":
		return c.browserList(args[1:])
	case "rm", "remove":
		return c.browserRemove(args[1:])
	}
	fmt.Fprintf(c.stderr, "secretvault browser: unknown subcommand %q (install, uninstall, status, extension, ls, rm)\n", args[0])
	return errUsage
}

func (c *cli) browserList(args []string) error {
	fs := c.flags("browser ls")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, ""); err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	list, err := cl.BrowserAssociations(ctx, c.vault)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(c.stderr, "No browser is connected. KeePassXC-Browser's Connect button asks to be.")
		return nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tVAULT\tCONNECTED\tBROWSER\tEXTENSION")
	for _, a := range list {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", a.Name, a.Vault, a.Created.Local().Format("2006-01-02 15:04"), a.Program, a.Extension)
	}
	return tw.Flush()
}

func (c *cli) browserRemove(args []string) error {
	fs := c.flags("browser rm")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, -1, "NAME...")
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	for _, name := range pos {
		if err := cl.RemoveBrowserAssociation(ctx, c.vault, name); err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Disconnected %s. Its extension must ask to connect again.\n", name)
	}
	return nil
}
