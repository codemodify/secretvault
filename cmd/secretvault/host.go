package main

import (
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Setting up the host daemon (secretvaultd --host), as root:
//
//	secretvault host init [--seal [--tpm2-pcrs PCRS]] [--suite S] [--out FILE]
//	secretvault host allow UNIT CREDENTIAL sv://VAULT/ITEM[#FIELD]
//	secretvault host allow --user USER [--program PATH] sv://...
//	secretvault host deny UNIT CREDENTIAL
//	secretvault host deny --user USER [--program PATH] [sv://...]
//	secretvault host ls
//	secretvault host status
//	secretvault host audit [-n N]
//
// init works on files: it runs before the service is installed, and
// systemd-creds writes where the hardened service cannot. The rest talk
// to the host daemon's admin socket.

const hostUsage = `usage: secretvault host <command>

  init [--seal]              make the host identity (sealed with systemd-creds, with --seal)
  allow UNIT CREDENTIAL sv://VAULT/ITEM[#FIELD]
                             serve a unit's LoadCredential= (UNIT may be a glob: app@*.service)
  allow --user USER [--program PATH] sv://...
                             let a local service that is not a unit read references
  deny UNIT CREDENTIAL | --user USER [--program PATH] [sv://...]
  ls                         list what is served, and to whom
  status                     show the host daemon, its identity and its vaults
  audit [-n N]               show what was delivered and refused`

func (c *cli) cmdHost(args []string) error {
	if len(args) == 0 {
		fmt.Fprintln(c.stderr, hostUsage)
		return errUsage
	}
	switch args[0] {
	case "init":
		return c.hostInit(args[1:])
	case "allow", "deny":
		return c.hostRule(args[0], args[1:])
	case "ls", "list", "status", "audit":
	default:
		fmt.Fprintf(c.stderr, "secretvault host: unknown command %q\n\n%s\n", args[0], hostUsage)
		return errUsage
	}
	fs := c.flags("host " + args[0])
	limit := 0
	if args[0] == "audit" {
		fs.IntVar(&limit, "n", 50, "show the newest `N` lines (0 for all)")
	}
	if _, err := parse(fs, args[1:], 0, 0, ""); err != nil {
		return err
	}
	c.hostAdmin = true
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	switch args[0] {
	case "status":
		st, err := cl.HostStatus(ctx)
		if err != nil {
			return err
		}
		return c.printHostStatus(st)
	case "audit":
		events, err := cl.HostAudit(ctx, limit)
		if err != nil {
			return err
		}
		return c.printHostEvents(events)
	}
	pol, err := cl.HostPolicy(ctx)
	if err != nil {
		return err
	}
	return c.printHostPolicy(pol)
}

// hostInit makes the host identity.
func (c *cli) hostInit(args []string) error {
	fs := c.flags("host init")
	seal := fs.Bool("seal", false, "seal the identity with systemd-creds (to the TPM2, and the host key) instead of writing it in the clear")
	out := fs.String("out", "", "write the plain identity to `FILE` (default "+svrpc.HostIdentityFile()+")")
	credstore := fs.String("credstore", svrpc.HostCredstore, "with --seal: write the sealed identity to `FILE`")
	pcrs := fs.String("tpm2-pcrs", "", "with --seal: also bind it to these TPM2 `PCRS`, such as 7 (see systemd-creds)")
	suiteName := fs.String("suite", "modern", "cipher suite: modern or nist")
	if _, err := parse(fs, args, 0, 0, "[--seal [--tpm2-pcrs PCRS]] [--suite modern|nist] [--out FILE]"); err != nil {
		return err
	}
	if *out == "" {
		*out = svrpc.HostIdentityFile()
	}
	res, err := svops.HostInit(svops.HostInitOptions{Suite: *suiteName, Seal: *seal, Out: *out, Credstore: *credstore, PCRs: *pcrs,
		SystemdCreds: c.systemdCreds})
	if err != nil {
		return err
	}
	rcpt := res.Recipient
	if res.Sealed {
		fmt.Fprintf(c.stdout, "Made the host identity, sealed in %s: systemd passes it to secretvaultd-host.service, and it was never written in the clear.\n", res.Path)
	} else {
		fmt.Fprintf(c.stdout, "Made the host identity, in %s, readable by root only.\n", res.Path)
	}
	fmt.Fprintf(c.stdout, "Its recipient, which vaults are shared to:\n\n    %s\n\n", rcpt)
	install := "secretvaultd install --host"
	if !*seal {
		fmt.Fprintln(c.stdout, "To seal it to this machine instead (its TPM2 if it has one, and its host key), and remove the plain copy:")
		fmt.Fprintln(c.stdout)
		fmt.Fprintf(c.stdout, "    systemd-creds encrypt --name=%s %s %s\n", svrpc.HostIdentityCredential, *out, svrpc.HostCredstore)
		fmt.Fprintf(c.stdout, "    shred -u %s\n\n", *out)
		install += "    (add --plain-identity to keep the plain file instead)"
	}
	fmt.Fprintf(c.stdout, `Then:
  1. %s
  2. On the machine that holds a vault for this host:
         secretvault --vault NAME share %s --label HOSTNAME
     and bring the vault here: copy its folder to %s, then
         secretvault --host vault add NAME %s
     or join its sync server: secretvault --host sync join INVITE --name NAME
  3. secretvault host allow UNIT CREDENTIAL sv://NAME/ITEM[#FIELD]
     and in the unit: LoadCredential=CREDENTIAL:%s
`, install, rcpt, filepath.Join(svrpc.HostDataDir(), "vaults", "NAME"), filepath.Join(svrpc.HostDataDir(), "vaults", "NAME"), svrpc.HostCredentialSocket())
	return nil
}

// hostRule runs host allow and host deny.
func (c *cli) hostRule(verb string, args []string) error {
	fs := c.flags("host " + verb)
	userName := fs.String("user", "", "a local service that is not a unit: the `USER` (a name or a uid) it runs as")
	program := fs.String("program", "", "with --user: the program it must be (its `PATH`, or the script an interpreter runs)")
	usage := "UNIT CREDENTIAL sv://VAULT/ITEM[#FIELD] | --user USER [--program PATH] sv://..."
	if verb == "deny" {
		usage = "UNIT CREDENTIAL | --user USER [--program PATH] [sv://...]"
	}
	pos, err := parse(fs, args, 0, -1, usage)
	if err != nil {
		return err
	}
	var r svrpc.HostRule
	switch {
	case *userName != "" && (verb == "deny" || len(pos) > 0):
		r = svrpc.HostRule{User: *userName, Program: *program, Refs: pos}
		if r.Program != "" {
			if r.Program, err = filepath.Abs(r.Program); err != nil {
				return err
			}
		}
	case *userName == "" && *program == "" && verb == "allow" && len(pos) == 3:
		r = svrpc.HostRule{Unit: pos[0], Credential: pos[1], Ref: pos[2]}
	case *userName == "" && *program == "" && verb == "deny" && len(pos) == 2:
		r = svrpc.HostRule{Unit: pos[0], Credential: pos[1]}
	default:
		fmt.Fprintf(c.stderr, "usage: secretvault host %s %s\n", verb, usage)
		return errUsage
	}
	c.hostAdmin = true
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if verb == "deny" {
		if err := cl.HostDeny(ctx, r); err != nil {
			return err
		}
		fmt.Fprintln(c.stdout, "Removed from the host policy.")
		return nil
	}
	res, err := cl.HostAllow(ctx, r)
	if err != nil {
		return err
	}
	if r.Unit != "" {
		fmt.Fprintf(c.stdout, "%s now gets its credential %s from %s. In the unit:\n\n    LoadCredential=%s:%s\n",
			r.Unit, r.Credential, r.Ref, r.Credential, svrpc.HostCredentialSocket())
	} else {
		fmt.Fprintf(c.stdout, "%s may now read %s, with 'secretvault --host read', run or inject (or the client library, on %s).\n",
			hostClientName(r.User, r.Program), strings.Join(r.Refs, ", "), svrpc.HostSocket())
	}
	for _, w := range res.Warnings {
		fmt.Fprintln(c.stderr, "warning:", w)
	}
	return nil
}

// count says "1 thing" or "2 things".
func count(n int, thing string) string {
	if n == 1 {
		return "1 " + thing
	}
	return fmt.Sprintf("%d %ss", n, thing)
}

func hostClientName(userName, program string) string {
	if program == "" {
		return "User " + userName
	}
	return program + ", run by user " + userName + ","
}

func (c *cli) printHostPolicy(pol svrpc.HostPolicy) error {
	if len(pol.Credentials) == 0 && len(pol.Clients) == 0 {
		fmt.Fprintln(c.stdout, "Nothing is served yet: 'secretvault host allow UNIT CREDENTIAL sv://VAULT/ITEM' says what a unit gets.")
		return nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	if len(pol.Credentials) > 0 {
		fmt.Fprintf(tw, "Credentials (LoadCredential=CREDENTIAL:%s):\n", svrpc.HostCredentialSocket())
		fmt.Fprintln(tw, "  UNIT\tCREDENTIAL\tREFERENCE")
		for _, r := range pol.Credentials {
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", r.Unit, r.Credential, r.Ref)
		}
	}
	if len(pol.Clients) > 0 {
		if len(pol.Credentials) > 0 {
			fmt.Fprintln(tw)
		}
		fmt.Fprintf(tw, "Local services (on %s):\n", svrpc.HostSocket())
		fmt.Fprintln(tw, "  USER\tPROGRAM\tREFERENCES")
		for _, cl := range pol.Clients {
			prog := cl.Program
			if prog == "" {
				prog = "any"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\n", cl.User, prog, strings.Join(cl.Refs, " "))
		}
	}
	return tw.Flush()
}

func (c *cli) printHostStatus(st svrpc.HostStatus) error {
	fmt.Fprintf(c.stdout, "secretvaultd --host %s, process %d\n", st.Version, st.PID)
	fmt.Fprintf(c.stdout, "data:        %s\n", st.Data)
	fmt.Fprintf(c.stdout, "credentials: %s\n", st.CredentialSocket)
	fmt.Fprintf(c.stdout, "services:    %s\n", st.ServiceSocket)
	fmt.Fprintf(c.stdout, "admin:       %s\n", st.AdminSocket)
	switch {
	case st.Identity != "":
		fmt.Fprintf(c.stdout, "identity:    %s\n", st.Identity)
		fmt.Fprintf(c.stdout, "recipient:   %s\n", st.Recipient)
	case st.IdentityError != "":
		fmt.Fprintf(c.stdout, "identity:    none: %s\n", st.IdentityError)
	default:
		fmt.Fprintln(c.stdout, "identity:    none ('secretvault host init' makes one)")
	}
	if st.PolicyError != "" {
		fmt.Fprintf(c.stdout, "policy:      %s: %s; everything is refused until it is fixed\n", st.Policy, st.PolicyError)
	} else {
		fmt.Fprintf(c.stdout, "policy:      %s (%s, %s)\n", st.Policy, count(st.Credentials, "credential"), count(st.Clients, "local service"))
	}
	fmt.Fprintf(c.stdout, "since start: %d delivered, %d refused or failed\n", st.Delivered, st.Refused)
	fmt.Fprintln(c.stdout)
	if len(st.Vaults) == 0 {
		fmt.Fprintln(c.stdout, "No vaults yet: share one to the recipient above, and bring it here ('secretvault host init' says how).")
		return nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "VAULT\tSTATE\tOPENS WITH THE HOST IDENTITY")
	for _, v := range st.Vaults {
		state := "unlocked"
		switch {
		case v.Missing:
			state = "missing"
		case v.Locked:
			state = "locked"
		}
		opens := "yes"
		if !v.HostSlot {
			opens = "no: share it to the host's recipient"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", v.Name, state, opens)
	}
	return tw.Flush()
}

func (c *cli) printHostEvents(events []svrpc.HostEvent) error {
	if len(events) == 0 {
		fmt.Fprintln(c.stdout, "Nothing yet.")
		return nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tOUTCOME\tWHO\tWHAT\tDETAIL")
	for _, ev := range events {
		who, what, detail := ev.Program, ev.Ref, ev.Reason
		switch {
		case ev.Outcome == "changed":
			what = "the policy"
		case ev.Unit != "":
			who, what = ev.Unit, "credential "+ev.Credential
			if detail == "" {
				detail = ev.Ref
			}
		default:
			who = fmt.Sprintf("%s, uid %d", ev.Program, ev.UID)
		}
		if who == "" || ev.Unit == "" && ev.Program == "" {
			who = fmt.Sprintf("process %d (uid %d)", ev.PID, ev.UID)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n", ev.Time.Local().Format("2006-01-02 15:04:05"), ev.Outcome, who, what, detail)
	}
	return tw.Flush()
}
