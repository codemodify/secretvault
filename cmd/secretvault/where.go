package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// cmdWhere is 'secretvault where': every place secretvault keeps or
// changes anything, as the daemon uses them, or, when none runs, as this
// program's environment says (svops.WhereHere).
func (c *cli) cmdWhere(args []string) error {
	fs := c.flags("where")
	asJSON := fs.Bool("json", false, "print the list as JSON")
	if _, err := parse(fs, args, 0, 0, "[--json]"); err != nil {
		return err
	}
	places, why, err := c.wherePlaces()
	if err != nil {
		return err
	}
	if why != "" {
		fmt.Fprintln(c.stderr, why)
	}
	if *asJSON {
		enc := json.NewEncoder(c.stdout)
		enc.SetIndent("", "  ")
		if places == nil {
			places = []svrpc.Place{}
		}
		return enc.Encode(places)
	}
	fmt.Fprintln(c.stdout, svops.WhereAbout)
	for _, group := range svops.WhereGroups(places) {
		fmt.Fprintf(c.stdout, "\n%s\n", group[0].Group)
		for _, p := range group {
			path := p.Path
			if p.Dir && !strings.HasSuffix(path, string(filepath.Separator)) {
				path += string(filepath.Separator)
			}
			if !p.Exists {
				path += "  (" + svops.WhereMissing + ")"
			}
			fmt.Fprintf(c.stdout, "  %s\n      %s\n", path, p.What)
		}
	}
	return nil
}

// wherePlaces asks the daemon where it keeps things, without starting
// one; with none running (or one too old to say), it lists them as this
// program would place them, and says so.
func (c *cli) wherePlaces() ([]svrpc.Place, string, error) {
	var cl *secretvault.Client
	var err error
	if c.host || c.hostAdmin {
		cl, err = c.daemon()
	} else {
		cl, err = c.connect(secretvault.Options{Name: "secretvault", NoStart: true})
		if err == nil {
			defer cl.Close()
		}
	}
	local := func(why string) ([]svrpc.Place, string, error) {
		places, err := svops.WhereHere()
		return places, why, err
	}
	if errors.Is(err, secretvault.ErrNoDaemon) && !c.host {
		return local("secretvaultd is not running: these are the places it would use.")
	}
	if err != nil {
		return nil, "", err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	places, err := cl.Where(ctx)
	var e *svrpc.Error
	if errors.As(err, &e) && e.Code == svrpc.CodeMethodNotFound && !c.host {
		return local("The secretvaultd running is older than this program, and cannot say: these are the places this program would use.")
	}
	return places, "", err
}

// moveOldFolder moves the files of the folder secretvault used to keep
// everything in to the settings and data folders, unless a daemon runs
// (which moves them as it starts), and says so on stderr when it did.
func moveOldFolder() {
	mv, err := svops.MoveOldFolderUnlessRunning(svrpc.DefaultSocket(), nil)
	if err == nil && mv.Summary() != "" {
		fmt.Fprintln(os.Stderr, mv.Summary())
	}
}
