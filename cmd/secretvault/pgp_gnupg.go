package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
)

// `secretvault pgp gpg-setup`: a GnuPG home whose gpg signs and decrypts
// with the OpenPGP keys in a vault, through secretvaultd's gpg-agent
// face, the keys never leaving the daemon. What it changes, and how
// --remove undoes it, is svops' (gnupg.go); here are the flags, the dry
// run and what is said.

// gpgAgentProgramFlag is what gpg passes secretvault as its agent-program.
const gpgAgentProgramFlag = svops.GPGAgentProgramFlag

func (c *cli) pgpGnuPGSetup(args []string) error {
	fs := c.flags("pgp gpg-setup")
	homeFlag := fs.String("gnupghome", "", "the GnuPG home to point at secretvault (default: secretvault's data directory/gnupg)")
	dryRun := fs.Bool("dry-run", false, "say what would change, and change nothing")
	remove := fs.Bool("remove", false, "stop pointing the home at secretvault (its public keys stay)")
	gpgFlag := fs.String("gpg", "", "the gpg program (default: gpg on PATH)")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "[--gnupghome DIR] [--dry-run] [--remove] [--gpg PATH]"); err != nil {
		return err
	}
	if err := svops.GnuPGHere(); err != nil {
		return err
	}
	home, err := svops.GnuPGHome(*homeFlag)
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if *remove {
		return c.gnupgRemove(cl, home, *dryRun)
	}
	p, err := svops.PlanGnuPGSetup(ctx, cl, svops.GnuPGOptions{Vault: c.vault, Home: home, GPG: *gpgFlag, DryRun: *dryRun})
	if err != nil {
		return err
	}
	if p.OwnHome {
		fmt.Fprintf(c.stdout, "%s is your own GnuPG home: gpg will use secretvault's keys, and no longer gpg-agent's.\n"+
			"Where systemd starts gpg-agent by its sockets, stop that first: systemctl --user mask --now gpg-agent.socket gpg-agent-ssh.socket gpg-agent-extra.socket gpg-agent-browser.socket\n", home)
	}

	if *dryRun {
		fmt.Fprintf(c.stdout, "Pointing the GnuPG home %s at secretvault would:\n", home)
		if !p.HomeExists {
			fmt.Fprintf(c.stdout, "- make the directory %s (0700)\n", home)
		}
		fmt.Fprintf(c.stdout, "- link %s (where gpg looks for its agent) to %s\n", p.Socket, p.Agent)
		if p.SSHSocket != "" && p.SSHAgent != "" {
			fmt.Fprintf(c.stdout, "- link %s (its SSH agent) to %s\n", p.SSHSocket, p.SSHAgent)
		}
		for _, k := range p.Keys {
			fmt.Fprintf(c.stdout, "- import the public key %s  %s (%s), trusted as your own\n", svops.GroupFingerprint(k.Fingerprint), svops.FirstUserID(k), k.Item)
		}
		fmt.Fprintf(c.stdout, "- add to %s: %s\n", filepath.Join(home, "gpg.conf"), p.AgentProgram)
		c.gnupgNotes(p.Skipped, p.Unreachable, home)
		fmt.Fprintln(c.stdout, "Nothing was changed.")
		return nil
	}

	res, note, err := svops.ApplyGnuPGSetup(ctx, cl, p)
	if err != nil {
		return err
	}
	if note != "" {
		fmt.Fprintln(c.stderr, "warning:", note)
	}
	fmt.Fprintf(c.stdout, "The GnuPG home %s signs and decrypts with secretvault's keys:\n", home)
	for _, k := range p.Keys {
		fmt.Fprintf(c.stdout, "  %s  %s\n", svops.GroupFingerprint(k.Fingerprint), svops.FirstUserID(k))
	}
	fmt.Fprintf(c.stdout, "Its agent is secretvaultd: %s -> %s\n", p.Socket, res.Agent)
	if res.SSHAgent != "" {
		fmt.Fprintf(c.stdout, "and so is its SSH agent: %s -> %s\n", p.SSHSocket, res.SSHAgent)
	}
	c.gnupgNotes(p.Skipped, p.Unreachable, home)
	fmt.Fprintf(c.stdout, "Use it with: export GNUPGHOME=%s\n", home)
	fmt.Fprintln(c.stdout, "Each program's first signature or decryption with a key is asked about.")
	return nil
}

// gnupgNotes says what gpg will not get.
func (c *cli) gnupgNotes(skipped []string, unreachable int, home string) {
	for _, s := range skipped {
		fmt.Fprintf(c.stdout, "Left out: %s\n", s)
	}
	if unreachable > 0 {
		fmt.Fprintf(c.stdout, "Note: %d secret keys in %s are GnuPG's own, which gpg cannot use while secretvault is its agent;\n"+
			"take them into the vault first ('gpg --export-secret-keys KEY | secretvault pgp import -').\n",
			unreachable, filepath.Join(home, "private-keys-v1.d"))
	}
}

func (c *cli) gnupgRemove(cl *secretvault.Client, home string, dryRun bool) error {
	ctx, cancel := c.ctx()
	defer cancel()
	if dryRun {
		pointed, err := svops.GnuPGPointed(ctx, cl, home)
		if err != nil {
			return err
		}
		if !pointed {
			fmt.Fprintf(c.stdout, "%s is not pointed at secretvault.\n", home)
			return nil
		}
		fmt.Fprintf(c.stdout, "Removing would take away the links to secretvaultd in %s's socket directory, and secretvault's agent-program line from %s; the public keys stay.\nNothing was changed.\n", home, filepath.Join(home, "gpg.conf"))
		return nil
	}
	if err := svops.RemoveGnuPG(ctx, cl, home); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "The GnuPG home %s is no longer pointed at secretvault; the public keys stay in its keyring.\n", home)
	return nil
}

// gpgAgentStart is secretvault run by gpg as its agent-program, when it
// finds no agent: it has the daemon (which it starts if need be) link the
// home's agent socket again, and exits, as gpg expects of an agent that
// daemonizes. gpg then connects.
func (c *cli) gpgAgentStart(args []string) int {
	var home string
	for i, a := range args {
		if a == "--homedir" && i+1 < len(args) {
			home = args[i+1]
		} else if h, ok := strings.CutPrefix(a, "--homedir="); ok {
			home = h
		}
	}
	if home == "" {
		fmt.Fprintln(c.stderr, "secretvault: started as gpg's agent without --homedir")
		return 2
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if err := svops.RelinkGnuPG(ctx, c.daemon, home); err != nil {
		fmt.Fprintln(c.stderr, "secretvault:", describe(err))
		return 1
	}
	return 0
}
