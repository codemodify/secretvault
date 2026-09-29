package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/codemodify/secretvault/svrpc"
)

// Emergency access: a person you trust can open a vault of yours after a
// waiting period, unless you deny it first. The vault must sync with a
// server, which keeps the wait.
//
//	secretvault emergency grant CONTACT [--wait 7d] [--name TEXT]   give it; prints the invite to send them
//	secretvault emergency ls                                         grants of the vault, and access held here
//	secretvault emergency deny GRANT                                 refuse a request
//	secretvault emergency revoke GRANT [--rotate]                    end a grant (and cut them off)
//
// and on the trustee's device:
//
//	secretvault emergency accept INVITE --identity FILE [--as NAME]  take the invite, with the identity it names
//	secretvault emergency request NAME                               ask: the wait starts, and the owner is told
//	secretvault emergency open NAME --identity FILE                  after the wait: fetch and open the vault, read-only

func (c *cli) cmdEmergency(args []string) error {
	if len(args) == 0 {
		args = []string{"ls"}
	}
	fs := c.flags("emergency " + args[0])
	switch args[0] {
	case "grant":
		var u unlockFlags
		u.register(fs)
		wait := fs.String("wait", "7d", "how long they wait, during which you can deny it: like 48h, 7d or 2w (an hour to a year)")
		fp := fs.String("fingerprint", "", "which of the contact's secretvault keys, if they have several")
		name := fs.String("name", "", "what the invite calls the vault (default: its name here)")
		pos, err := parse(fs, args[1:], 1, 1, "CONTACT|RECIPIENT [--wait 7d] [--fingerprint FP] [--name TEXT]")
		if err != nil {
			return err
		}
		d, err := parseWait(*wait)
		if err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		res, err := cl.EmergencyGrant(ctx, svrpc.EmergencyGrantParams{Vault: c.vault, Contact: pos[0], Fingerprint: *fp,
			Wait: int64(d / time.Second), Name: *name})
		if err != nil {
			return err
		}
		g := res.Grant
		fmt.Fprintf(c.stdout, "%s may now ask for vault %q. Unless you deny it within %s of their asking, they get it.\n",
			g.Trustee, g.Vault, waitText(g.Wait))
		if res.Warning != "" {
			fmt.Fprintln(c.stderr, "Warning: "+res.Warning)
		}
		fmt.Fprintln(c.stdout, "Send them this invite (it holds no secret: accepting it takes their identity):")
		fmt.Fprintln(c.stdout)
		fmt.Fprintln(c.stdout, "    secretvault emergency accept '"+res.Invite+"' --identity FILE")
		fmt.Fprintln(c.stdout)
		fmt.Fprintf(c.stdout, "Grant %s. You are told when they ask ('secretvault status'); deny with 'secretvault emergency deny %s',\n", g.ID, g.ID[:8])
		fmt.Fprintf(c.stdout, "end it with 'secretvault emergency revoke %s'.\n", g.ID[:8])
		return nil

	case "ls", "list":
		var u unlockFlags
		u.register(fs)
		if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		l, err := cl.EmergencyList(ctx, c.vault)
		if err != nil {
			return err
		}
		return c.printEmergency(l)

	case "deny":
		var u unlockFlags
		u.register(fs)
		pos, err := parse(fs, args[1:], 1, 1, "GRANT   (its ID, or the start of it: 'secretvault emergency ls')")
		if err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		g, err := cl.EmergencyDeny(ctx, c.vault, pos[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Denied: %s gets nothing from that request. They can ask again, which starts the wait over, and you are told again.\n", trusteeName(g))
		return nil

	case "revoke":
		var u unlockFlags
		u.register(fs)
		rotate := fs.Bool("rotate", false, "also rotate the vault key, which cuts them off from all that is written afterwards (needed once they were given it)")
		recovery := fs.Bool("new-recovery", false, "with --rotate: also make a new recovery key (the old one stops working)")
		newPassFile := fs.String("new-passphrase-file", "", "with --rotate: the passphrase for the new key, from `FILE` (default: asked)")
		pos, err := parse(fs, args[1:], 1, 1, "GRANT [--rotate]")
		if err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		g, err := cl.EmergencyRevoke(ctx, c.vault, pos[0])
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Revoked: %s's emergency access to vault %q is gone, with its keyslot and the server's escrow.\n", trusteeName(g), g.Vault)
		for _, p := range g.Problems {
			fmt.Fprintln(c.stderr, "Note: "+p)
		}
		if *rotate {
			return c.rotateWith(ctx, cl, *newPassFile, *recovery, nil)
		}
		if g.Released != nil {
			fmt.Fprintf(c.stdout, "They were given the vault's key on %s, and may have kept it: rotate the key now to cut them off\n", g.Released.Local().Format("2006-01-02 15:04"))
			fmt.Fprintln(c.stdout, "from all that is written afterwards ('secretvault vault rotate').")
		}
		return nil

	case "accept":
		identity := fs.String("identity", "", "the identity `FILE` the grant was made for")
		as := fs.String("as", "", "what to call it here, and the vault once opened (default: the invite's name)")
		label := fs.String("label", "", "this device's name to the owner (default: the host name)")
		pos, err := parse(fs, args[1:], 1, 1, "INVITE|- --identity FILE [--as NAME] [--label L]   (- reads the invite from standard input)")
		if err != nil {
			return err
		}
		invite := pos[0]
		if invite == "-" {
			line, err := bufio.NewReader(c.stdin).ReadString('\n')
			if err != nil && line == "" {
				return errors.New("no invite on standard input")
			}
			invite = strings.TrimSpace(line)
		}
		id, err := identityFile(*identity)
		if err != nil {
			return err
		}
		defer clear(id)
		cl, err := c.daemon()
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		a, err := cl.EmergencyAccept(ctx, svrpc.EmergencyAcceptParams{Invite: invite, Identity: id, Name: *as, Label: *label})
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Accepted, as %q. Should you need it, ask with 'secretvault emergency request %s': its owner is told,\n", a.Name, a.Name)
		fmt.Fprintf(c.stdout, "and unless they deny it within %s, 'secretvault emergency open %s --identity FILE' opens it then.\n", waitText(a.Wait), a.Name)
		return nil

	case "request":
		pos, err := parse(fs, args[1:], 1, 1, "NAME   (as accepted: 'secretvault emergency ls')")
		if err != nil {
			return err
		}
		cl, err := c.daemon()
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		a, err := cl.EmergencyRequest(ctx, pos[0])
		if err != nil {
			return err
		}
		if a.State == svrpc.GrantReleased {
			fmt.Fprintf(c.stdout, "It is yours already: 'secretvault emergency open %s --identity FILE'.\n", a.Name)
			return nil
		}
		fmt.Fprintf(c.stdout, "Asked. Its owner is told; unless they deny it, it is yours on %s:\n", when(a.ReleasesAt))
		fmt.Fprintf(c.stdout, "then 'secretvault emergency open %s --identity FILE'.\n", a.Name)
		return nil

	case "open":
		identity := fs.String("identity", "", "the identity `FILE` the grant was made for")
		path := fs.String("path", "", "keep the vault in `DIR` instead of the data directory")
		pos, err := parse(fs, args[1:], 1, 1, "NAME --identity FILE [--path DIR]")
		if err != nil {
			return err
		}
		id, err := identityFile(*identity)
		if err != nil {
			return err
		}
		defer clear(id)
		if *path != "" {
			abs, err := filepath.Abs(*path)
			if err != nil {
				return err
			}
			*path = abs
		}
		cl, err := c.daemon()
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		v, err := cl.EmergencyOpen(ctx, svrpc.EmergencyOpenParams{Name: pos[0], Identity: id, Path: *path})
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Opened vault %q (%s) in %s, read-only: it follows its owner's copy.\n", v.Name, v.ID, v.Path)
		fmt.Fprintf(c.stdout, "Read it with 'secretvault --vault %s ls'; once it locks, 'secretvault unlock %s --identity FILE' opens it again.\n", v.Name, v.Name)
		return nil
	}
	fmt.Fprintf(c.stderr, "secretvault emergency: unknown subcommand %q (grant, ls, deny, revoke, accept, request, open)\n", args[0])
	return errUsage
}

// identityFile reads the identity file a trustee's command needs.
func identityFile(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("this needs --identity FILE: the identity the grant was made for")
	}
	return os.ReadFile(path)
}

// parseWait reads a waiting period: a Go duration (48h, 90m), or a number
// of days (7d) or weeks (2w).
func parseWait(s string) (time.Duration, error) {
	unit := time.Duration(0)
	switch {
	case strings.HasSuffix(s, "d"):
		unit = 24 * time.Hour
	case strings.HasSuffix(s, "w"):
		unit = 7 * 24 * time.Hour
	}
	if unit != 0 {
		n, err := strconv.Atoi(strings.TrimRight(s, "dw"))
		if err != nil || n <= 0 {
			return 0, fmt.Errorf("%q is not a wait (like 48h, 7d or 2w)", s)
		}
		return time.Duration(n) * unit, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%q is not a wait (like 48h, 7d or 2w)", s)
	}
	return d, nil
}

// waitText says a wait in seconds as people do.
func waitText(secs int64) string {
	d := time.Duration(secs) * time.Second
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		if n := d / (24 * time.Hour); n != 1 {
			return fmt.Sprintf("%d days", n)
		}
		return "a day"
	case d >= time.Hour && d%time.Hour == 0:
		if n := d / time.Hour; n != 1 {
			return fmt.Sprintf("%d hours", n)
		}
		return "an hour"
	}
	return d.String()
}

func when(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Local().Format("2006-01-02 15:04")
}

func trusteeName(g svrpc.EmergencyGrant) string {
	if g.Trustee != "" {
		return g.Trustee
	}
	return "the trustee"
}

// printEmergency lists the grants of a vault and the access held here.
func (c *cli) printEmergency(l svrpc.EmergencyList) error {
	if len(l.Given) == 0 && len(l.Held) == 0 {
		fmt.Fprintln(c.stdout, "No emergency access, given or held. Give it with 'secretvault emergency grant CONTACT'.")
		return nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	if len(l.Given) > 0 {
		fmt.Fprintln(tw, "GRANT\tVAULT\tTRUSTEE\tWAIT\tSTATE")
		for _, g := range l.Given {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", g.ID[:12], g.Vault, trusteeName(g), waitText(g.Wait), grantState(g))
		}
		tw.Flush()
		for _, g := range l.Given {
			for _, p := range g.Problems {
				fmt.Fprintf(c.stdout, "  %s: %s\n", g.ID[:12], p)
			}
		}
	}
	if len(l.Held) > 0 {
		if len(l.Given) > 0 {
			fmt.Fprintln(c.stdout)
		}
		fmt.Fprintln(tw, "HELD\tOWNER'S NAME\tSERVER\tSTATE")
		for _, a := range l.Held {
			state := accessState(a)
			if a.Error != "" {
				state = a.Error
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a.Name, a.Owner, a.URL, state)
		}
	}
	return tw.Flush()
}

func grantState(g svrpc.EmergencyGrant) string {
	switch g.State {
	case svrpc.GrantInvited:
		return "not accepted yet"
	case svrpc.GrantAccepted:
		s := "accepted"
		if g.Device != "" {
			s += " on " + g.Device
		}
		if g.Denied != nil {
			s += "; last request denied " + when(g.Denied)
		}
		return s
	case svrpc.GrantRequested:
		return "REQUESTED " + when(g.Requested) + "; released " + when(g.ReleasesAt) + " unless denied"
	case svrpc.GrantReleased:
		return "RELEASED " + when(g.Released)
	}
	return "unknown to the server"
}

func accessState(a svrpc.EmergencyAccess) string {
	switch a.State {
	case svrpc.GrantAccepted:
		s := "accepted; ask with 'emergency request " + a.Name + "'"
		if a.Denied != nil {
			s = "last request denied " + when(a.Denied) + "; you may ask again"
		}
		return s
	case svrpc.GrantRequested:
		return "requested; yours " + when(a.ReleasesAt) + " unless denied"
	case svrpc.GrantReleased:
		if a.Vault != "" {
			return "opened, as vault " + a.Vault
		}
		return "released: 'emergency open " + a.Name + " --identity FILE'"
	}
	return a.State
}
