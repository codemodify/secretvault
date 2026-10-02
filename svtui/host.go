package svtui

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The host panel (H): the host daemon (secretvaultd --host), the
// machine's service that hands secrets to its units and services, as root
// sets it up ('secretvault host'). It is reached as the CLI reaches it,
// on its admin socket, which is root's alone; the identity is made on
// files (svops.HostInit), before the service is installed.

// hostSocket is the host daemon's admin socket.
func (u *UI) hostSocket() string {
	if u.opts.HostSocket != "" {
		return u.opts.HostSocket
	}
	return svrpc.HostAdminSocket()
}

// hostCall runs fn against the host daemon, off the interface's
// goroutine, connecting the first time.
func (u *UI) hostCall(fn func(ctx context.Context, c *secretvault.Client) error, then func(error)) {
	sock := u.hostSocket()
	u.call(func(ctx context.Context, _ *secretvault.Client) error {
		u.hostMu.Lock()
		c := u.host
		u.hostMu.Unlock()
		if c == nil {
			var err error
			c, err = secretvault.Connect(secretvault.Options{Socket: sock, NoStart: true, Name: "secretvault-tui"})
			if err != nil {
				return fmt.Errorf("the host daemon does not answer on %s: %v; is secretvaultd-host.service running? Its admin socket is root's alone", sock, err)
			}
			u.hostMu.Lock()
			if u.host != nil {
				c.Close()
				c = u.host
			} else {
				u.host = c
			}
			u.hostMu.Unlock()
		}
		err := fn(ctx, c)
		if errors.Is(err, secretvault.ErrNoDaemon) {
			u.hostMu.Lock()
			if u.host == c {
				u.host = nil
			}
			u.hostMu.Unlock()
			c.Close()
		}
		return err
	}, then)
}

// closeHost closes the connection to the host daemon.
func (u *UI) closeHost() {
	u.hostMu.Lock()
	defer u.hostMu.Unlock()
	if u.host != nil {
		u.host.Close()
		u.host = nil
	}
}

// hostVaultRef is a vault row of the host panel.
type hostVaultRef struct{ svrpc.HostVault }

func (u *UI) showHost() {
	p := u.newPanel("Host daemon", "WHO", "WHAT", "FROM")
	p.reload = func() {
		var st svrpc.HostStatus
		var pol svrpc.HostPolicy
		u.hostCall(func(ctx context.Context, c *secretvault.Client) (err error) {
			if st, err = c.HostStatus(ctx); err != nil {
				return err
			}
			pol, err = c.HostPolicy(ctx)
			return err
		}, func(err error) {
			p.clear()
			if err != nil {
				p.setHead("[red]" + tview.Escape(sentence(u.describe(err))) + "[-]\n\nThe identity is made on files all the same (i), before the service is installed.")
				p.none("Not reachable.")
				p.done()
				return
			}
			p.setHead(hostStatusText(st))
			p.heading("Credentials (units)")
			if len(pol.Credentials) == 0 {
				p.none("None (a allows one).")
			}
			for _, r := range pol.Credentials {
				p.row(r, r.Unit, "credential "+r.Credential, r.Ref)
			}
			p.heading("Local services")
			if len(pol.Clients) == 0 {
				p.none("None (l allows one).")
			}
			for _, cl := range pol.Clients {
				prog := cl.Program
				if prog == "" {
					prog = "any program"
				}
				p.row(cl, "user "+cl.User, prog, strings.Join(cl.Refs, " "))
			}
			p.heading("Vaults")
			if len(st.Vaults) == 0 {
				p.none("None yet.")
			}
			for _, v := range st.Vaults {
				state := "unlocked"
				switch {
				case v.Missing:
					state = "missing"
				case v.Locked:
					state = "locked"
				}
				opens := "opens with the host identity"
				if !v.HostSlot {
					opens = "no keyslot for the host: share it to its recipient"
				}
				p.row(hostVaultRef{v}, v.Name, state, opens)
			}
			p.done()
			u.hostRecipient = st.Recipient
		})
	}
	p.act('i', "Make the host identity…", func() { u.hostInit(p.refresh) })
	p.act('a', "Allow a unit's credential…", func() { u.hostAllowUnit(p.refresh) })
	p.act('l', "Allow a local service…", func() { u.hostAllowService(p.refresh) })
	p.rowAct('x', "Deny it…", func(ref any) bool {
		return is[svrpc.HostCredential](ref) || is[svrpc.HostClient](ref)
	}, func(ref any) {
		var r svrpc.HostRule
		var what string
		switch x := ref.(type) {
		case svrpc.HostCredential:
			r, what = svrpc.HostRule{Unit: x.Unit, Credential: x.Credential}, fmt.Sprintf("%s's credential %s", x.Unit, x.Credential)
		case svrpc.HostClient:
			r, what = svrpc.HostRule{User: x.User, Program: x.Program}, svops.HostClientName(x.User, x.Program)+" and every reference it may read"
		}
		u.confirm("Deny?", "Take "+strings.TrimSuffix(what, ",")+" out of the host's policy?", "Deny", func() {
			u.hostDeny(r, p.refresh)
		})
	})
	p.act('d', "Deny some of a local service's references…", func() { u.hostDenyRefs(p.refresh) })
	p.act('c', "Copy the host's recipient", func() {
		if u.hostRecipient == "" {
			u.say("The host has no identity yet: i makes one.")
			return
		}
		u.copyValue([]byte(u.hostRecipient))
	})
	p.act('v', "What was delivered and refused", u.showHostAudit)
	p.show()
}

// hostStatusText is 'secretvault host status', but for its vaults.
func hostStatusText(st svrpc.HostStatus) string {
	var b strings.Builder
	fmt.Fprintf(&b, "secretvaultd --host %s, process %d · data %s\n", tview.Escape(st.Version), st.PID, tview.Escape(st.Data))
	fmt.Fprintf(&b, "credentials %s · services %s · admin %s\n", tview.Escape(st.CredentialSocket), tview.Escape(st.ServiceSocket), tview.Escape(st.AdminSocket))
	switch {
	case st.Identity != "":
		fmt.Fprintf(&b, "identity: %s · recipient %s\n", tview.Escape(st.Identity), tview.Escape(st.Recipient))
	case st.IdentityError != "":
		fmt.Fprintf(&b, "identity: [red]none: %s[-]\n", tview.Escape(st.IdentityError))
	default:
		b.WriteString("identity: none (i makes one)\n")
	}
	if st.PolicyError != "" {
		fmt.Fprintf(&b, "policy: [red]%s: %s; everything is refused until it is fixed[-]\n", tview.Escape(st.Policy), tview.Escape(st.PolicyError))
	} else {
		fmt.Fprintf(&b, "policy: %s (%d credentials, %d local services)\n", tview.Escape(st.Policy), st.Credentials, st.Clients)
	}
	fmt.Fprintf(&b, "since start: %d delivered, %d refused or failed", st.Delivered, st.Refused)
	return b.String()
}

// hostInit is 'secretvault host init'.
func (u *UI) hostInit(then func()) {
	f := u.newForm("Make the host identity", "The host daemon opens the vaults shared to its identity. Sealed, systemd-creds keeps it (to the TPM2, and the host key), and it is never written in the clear; else it is a file root alone reads.")
	suite := f.choice("Cipher suite", []string{"modern", "nist"}, 0)
	seal := f.check("Seal it with systemd-creds", false)
	out := f.path("Plain file", svrpc.HostIdentityFile(), "")
	credstore := f.path("Sealed file", svrpc.HostCredstore, "")
	pcrs := f.text("TPM2 PCRs", "", "with sealing: also bind it to these, such as 7 (optional)")
	f.show("Make it", func() string {
		o := svops.HostInitOptions{Suite: option(suite), Seal: seal.IsChecked(), Out: filePath(out), Credstore: filePath(credstore), PCRs: trimmed(pcrs), SystemdCreds: u.opts.SystemdCreds}
		var res *svops.HostInitResult
		u.call(func(context.Context, *secretvault.Client) (err error) {
			res, err = svops.HostInit(o)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			where := fmt.Sprintf("Made the host identity, in %s, readable by root only.", res.Path)
			if res.Sealed {
				where = fmt.Sprintf("Made the host identity, sealed in %s: systemd passes it to secretvaultd-host.service, and it was never written in the clear.", res.Path)
			}
			lines := []onceLine{{text: where}, {}, {text: "Its recipient, which vaults are shared to:"}, {secret: []byte(res.Recipient)}, {}}
			if !res.Sealed {
				lines = append(lines,
					onceLine{text: "To seal it to this machine instead, and remove the plain copy:"},
					onceLine{text: fmt.Sprintf("  systemd-creds encrypt --name=%s %s %s", svrpc.HostIdentityCredential, o.Out, svrpc.HostCredstore)},
					onceLine{text: "  shred -u " + o.Out}, onceLine{})
			}
			lines = append(lines,
				onceLine{text: "Then: install the service (secretvaultd install --host); share a vault to the recipient (Sharing › Share, on the machine that holds it), and bring it here (its folder to " + filepath.Join(svrpc.HostDataDir(), "vaults", "NAME") + ", added to the host daemon); allow a unit's credential here (a), and in the unit: LoadCredential=CREDENTIAL:" + svrpc.HostCredentialSocket()})
			u.showCode("Host identity", lines, nil)
			if then != nil {
				then()
			}
		})
		return ""
	})
}

// hostAllowUnit is 'secretvault host allow UNIT CREDENTIAL REF'.
func (u *UI) hostAllowUnit(then func()) {
	f := u.newForm("Allow a unit's credential", "systemd's LoadCredential= gets the value the reference names, for the units the name matches.")
	unit := f.text("Unit", "", "app.service, or a glob: app@*.service")
	cred := f.text("Credential", "", "its name in the unit")
	ref := f.text("Reference", "", "sv://VAULT/ITEM[#FIELD]")
	f.show("Allow", func() string {
		r := svrpc.HostRule{Unit: trimmed(unit), Credential: trimmed(cred), Ref: trimmed(ref)}
		if r.Unit == "" || r.Credential == "" || r.Ref == "" {
			return "Give the unit, the credential's name, and the reference."
		}
		u.hostAllow(r, then)
		return ""
	})
}

// hostAllowService is 'secretvault host allow --user USER [--program
// PATH] REF...'.
func (u *UI) hostAllowService(then func()) {
	f := u.newForm("Allow a local service", "A service that is not a unit reads references over the host's services socket, as the user it runs as, and (if named) as the program it must be.")
	user := f.text("User", "", "a name or a uid")
	program := f.path("Program", "", "its path, or the script an interpreter runs (optional)")
	refs := f.text("References", "", "sv://VAULT/ITEM[#FIELD], space-separated; globs allowed")
	f.show("Allow", func() string {
		r := svrpc.HostRule{User: trimmed(user), Refs: strings.Fields(trimmed(refs))}
		if r.User == "" || len(r.Refs) == 0 {
			return "Give the user, and the references."
		}
		if prog := filePath(program); prog != "" {
			abs, err := filepath.Abs(prog)
			if err != nil {
				return err.Error()
			}
			r.Program = abs
		}
		u.hostAllow(r, then)
		return ""
	})
}

func (u *UI) hostAllow(r svrpc.HostRule, then func()) {
	var res svrpc.HostAllowResult
	u.hostCall(func(ctx context.Context, c *secretvault.Client) (err error) {
		res, err = c.HostAllow(ctx, r)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		var text string
		if r.Unit != "" {
			text = fmt.Sprintf("%s now gets its credential %s from %s. In the unit:\n\n    LoadCredential=%s:%s", r.Unit, r.Credential, r.Ref, r.Credential, svrpc.HostCredentialSocket())
			u.say("%s now gets its credential %s", r.Unit, r.Credential)
		} else {
			text = fmt.Sprintf("%s may now read %s, with 'secretvault --host read', run or inject (or the client library, on %s).", svops.HostClientName(r.User, r.Program), strings.Join(r.Refs, ", "), svrpc.HostSocket())
			u.say("%s may now read %s", strings.TrimSuffix(svops.HostClientName(r.User, r.Program), ","), strings.Join(r.Refs, ", "))
		}
		for _, w := range res.Warnings {
			text += "\n\nwarning: " + w
		}
		if then != nil {
			then()
		}
		u.showText("Allowed", tview.Escape(text))
	})
}

// hostDenyRefs is 'secretvault host deny --user USER [--program PATH]
// [REF...]'.
func (u *UI) hostDenyRefs(then func()) {
	f := u.newForm("Deny a local service", "Take some of its references out of the policy, or (none given) the whole of it.")
	user := f.text("User", "", "a name or a uid")
	program := f.path("Program", "", "as it was allowed (optional)")
	refs := f.text("References", "", "space-separated (none: all of them)")
	f.show("Deny", func() string {
		r := svrpc.HostRule{User: trimmed(user), Refs: strings.Fields(trimmed(refs))}
		if r.User == "" {
			return "Give the user."
		}
		if prog := filePath(program); prog != "" {
			abs, err := filepath.Abs(prog)
			if err != nil {
				return err.Error()
			}
			r.Program = abs
		}
		u.hostDeny(r, then)
		return ""
	})
}

func (u *UI) hostDeny(r svrpc.HostRule, then func()) {
	u.hostCall(func(ctx context.Context, c *secretvault.Client) error {
		return c.HostDeny(ctx, r)
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		u.say("Removed from the host policy")
		if then != nil {
			then()
		}
	})
}

// showHostAudit is 'secretvault host audit'.
func (u *UI) showHostAudit() {
	p := u.newPanel("Host log", "TIME", "OUTCOME", "WHO", "WHAT", "DETAIL")
	p.page = pageSub
	p.reload = func() {
		var events []svrpc.HostEvent
		u.hostCall(func(ctx context.Context, c *secretvault.Client) (err error) {
			events, err = c.HostAudit(ctx, 500)
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				p.close()
				return
			}
			p.clear()
			if len(events) == 0 {
				p.none("Nothing yet.")
			}
			for _, ev := range events {
				who, what, detail := svops.HostEventColumns(ev)
				colour := "green"
				if ev.Outcome == "refused" || ev.Outcome == "failed" {
					colour = "red"
				}
				p.row(ev, ev.Time.Local().Format("2006-01-02 15:04:05"), tagged("["+colour+"]"+tview.Escape(ev.Outcome)+"[-]"), who, what, detail)
			}
			p.done()
		})
	}
	p.show()
}
