package svmanager

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svsecret"
)

// The desktop's setup: secretvault as the system keyring (Linux), the
// browsers starting secretvault for KeePassXC-Browser, gpg using the
// vault's OpenPGP keys, the helper programs git, docker and age start,
// and the host daemon on a server. Everything that changes the desktop is
// shown first as the plan svops makes of it, as the CLI's --dry-run shows
// it, and carried out only when the person says so. What other programs
// are told to start is the secretvault CLI (svops.CLIProgram), never this
// program.

// The desktop page's tabs.
const (
	tabKeyring = iota
	tabBrowsers
	tabGnuPG
	tabHelpers
	tabHost
)

// desktopPage is the desktop page's state.
type desktopPage struct {
	*tabbedPage
	assoc  []svrpc.BrowserAssociation
	atable *widgets.TableView
}

// showDesktopPage shows the desktop page, open at tab.
func (m *Manager) showDesktopPage(tab int) {
	if m.editor != nil {
		m.say("Save or cancel the edit first.")
		return
	}
	if m.dpage != nil && m.up(m.dpage.tabbedPage) {
		m.selectTab(m.dpage.tabbedPage, tab)
		return
	}
	m.closeVaultPage()
	p := &desktopPage{tabbedPage: &tabbedPage{kind: pageDesktop, vault: m.vault, title: "Desktop"}}
	p.panes = []*pane{
		newPane("System keyring", func(pn *pane) { m.fillKeyring(p, pn) }),
		newPane("Browsers", func(pn *pane) { m.fillBrowsers(p, pn) }),
		newPane("GnuPG", func(pn *pane) { m.fillGnuPG(p, pn) }),
		newPane("Program helpers", func(pn *pane) { m.fillHelpers(p, pn) }),
		newPane("Host daemon", func(pn *pane) { m.fillHost(p, pn) }),
	}
	m.dpage = p
	m.openPage(p.tabbedPage, tab)
}

// refreshDesktop fills a tab of the desktop page again, if it is up.
func (m *Manager) refreshDesktop(p *desktopPage, tab int) {
	if p != nil && m.up(p.tabbedPage) && p.panes[tab].filled {
		p.panes[tab].refresh()
	}
}

// --- The system keyring ---

func (m *Manager) fillKeyring(p *desktopPage, pn *pane) {
	var holder svops.KeyringHolder
	var st svrpc.Status
	var state *svops.TakeoverState
	here := svops.KeyringHere()
	m.load(pn, func(ctx context.Context, c *secretvault.Client) error {
		holder = svops.KeyringHolderNow(ctx)
		st, _ = c.Status(ctx)
		state, _ = svops.LoadTakeover()
		return nil
	}, func() widget.Component {
		keyring := "none: nothing holds org.freedesktop.secrets"
		switch {
		case holder.BusErr != nil:
			keyring = "no session bus (" + holder.BusErr.Error() + ")"
		case holder.Held:
			keyring = fmt.Sprintf("%s, process %d", svops.DescribeExe(holder.Owner.Exe), holder.Owner.PID)
		}
		rows := [][2]string{{"The keyring now", keyring}, {"secretvault", orNot(st.SecretService)}}
		if state != nil {
			rows = append(rows, [2]string{"Takeover", "done " + state.When.Local().Format("2006-01-02 15:04") + ", from " + svops.DescribeExe(state.Previous)})
		}
		col := widgets.NewColumn(m.paragraph("Programs keep their passwords in the desktop's keyring (the Secret Service). secretvault can "+
			"take its secrets in, and become it, so that they ask before they read; giving it back undoes that exactly."),
			m.facts(rows)).WithGap(gap).WithPad(gap)
		if here != nil {
			col.Add(m.paragraph(sentence(here.Error())))
			return scrolled(col)
		}
		imp := widgets.NewButton("Import its secrets…", func() { m.importKeyring(p) })
		take := widgets.NewButton("Become the keyring…", func() { m.takeOver(p) })
		give := widgets.NewButton("Give it back…", func() { m.restoreKeyring(p) })
		take.SetEnabled(state == nil)
		give.SetEnabled(state != nil)
		pn.focus = imp
		col.Add(buttons(imp, take, give))
		return scrolled(col)
	})
}

func orNot(s string) string {
	if s == "" {
		return "not known"
	}
	return s
}

// readKeyring reads every secret the current keyring holds
// (svops.ReadKeyring), saying whose they are in the status bar, since it
// may ask the person to unlock it. The caller wipes them.
func (m *Manager) readKeyring(ctx context.Context) ([]svsecret.Secret, []string, error) {
	return svops.ReadKeyring(ctx, func(o svsecret.Owner) {
		m.post(func() { m.say("Reading from %s; it may ask you to unlock it.", svops.DescribeExe(o.Exe)) })
	})
}

// importKeyring copies the current keyring's secrets into the vault shown
// (the CLI's keyring import): the names first, as its --dry-run lists
// them, then the import.
func (m *Manager) importKeyring(p *desktopPage) {
	vault := m.vault
	if vault == "" {
		m.fail(errNoVault)
		return
	}
	f := m.newForm("Import the keyring's secrets")
	prefix := f.text("Folder", "imported", "put them under this folder")
	f.note("Its secrets are copied into vault " + vault + "; the keyring keeps them too.")
	f.show("Preview", func() {
		pre := strings.TrimSpace(prefix.Text)
		if pre == "" {
			pre = "imported"
		}
		var secrets []svsecret.Secret
		var warnings, names []string
		f.work(func() error {
			ctx, cancel := context.WithTimeout(m.ctx, 10*time.Minute)
			defer cancel()
			var err error
			if secrets, warnings, err = m.readKeyring(ctx); err != nil {
				return err
			}
			names, _, _ = svops.ImportKeyring(ctx, nil, vault, pre, secrets)
			return nil
		}, func() {
			wipe := func() {
				for i := range secrets {
					secrets[i].Wipe()
				}
			}
			lines := append([]string(nil), names...)
			for _, w := range warnings {
				lines = append(lines, "warning: "+w)
			}
			m.showPlan("Import the keyring's secrets", fmt.Sprintf("%s to import into vault %s:", plural(len(names), "secret"), vault), lines, "Import", func() {
				var n int
				m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
					defer wipe()
					_, n, err = svops.ImportKeyring(ctx, c, vault, pre, secrets)
					return err
				}, func(err error) {
					if err != nil {
						m.fail(err)
						return
					}
					m.say("Imported %s.", plural(n, "secret"))
					if vault == m.vault {
						m.loadItems()
					}
				})
			}, wipe)
		})
	})
}

// takeOver makes secretvault the keyring (the CLI's keyring takeover):
// the plan svops makes (PlanTakeover), shown as the dry run shows it, and
// carried out only when the person says so, in the CLI's order: import,
// ApplyTakeover, the Secret Service on, the units restarted.
func (m *Manager) takeOver(p *desktopPage) {
	if err := svops.KeyringHere(); err != nil {
		m.fail(err)
		return
	}
	if m.takingOver {
		m.say("A takeover is under way already.")
		return
	}
	if s, err := svops.LoadTakeover(); err == nil {
		m.say("The takeover was already done on %s.", s.When.Local().Format("2006-01-02"))
		return
	}
	daemon := m.daemonExe()
	if daemon == "" {
		m.say("There is no secretvaultd beside this program, for the desktop to start as its keyring.")
		return
	}
	vault := m.vault
	var exe string
	var plan *svops.TakeoverPlan
	m.work(func() error {
		ctx, cancel := context.WithTimeout(m.ctx, callTimeout)
		defer cancel()
		if h := svops.KeyringHolderNow(ctx); h.Held {
			exe = h.Owner.Exe
		}
		var err error
		plan, err = svops.PlanTakeover(exe, daemon)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		f := m.newForm("Become the keyring")
		var importFirst *widgets.Checkbox
		var prefix *widgets.TextField
		if exe != "" && vault != "" {
			importFirst = f.check("First import its secrets into vault "+vault, true)
			prefix = f.text("Under", "imported", "the folder for them")
		}
		f.note("The keyring now: " + svops.DescribeExe(exe) + ". The next step shows what would change.")
		f.show("Next", func() {
			doImport := importFirst != nil && importFirst.Checked
			pre := "imported"
			if prefix != nil && strings.TrimSpace(prefix.Text) != "" {
				pre = strings.TrimSpace(prefix.Text)
			}
			f.close()
			var lines []string
			if doImport {
				lines = append(lines, "import its secrets into vault "+vault+", under "+pre)
			}
			for _, file := range plan.Order {
				lines = append(lines, "write "+file)
			}
			for _, r := range plan.Restart {
				lines = append(lines, "restart "+r+" (systemctl --user)")
			}
			lines = append(lines, "turn on secretvaultd's Secret Service")
			for _, n := range plan.Notes {
				lines = append(lines, "by hand: "+n)
			}
			m.showPlan("Become the keyring", "Becoming the keyring would:", lines, "Become the keyring", func() {
				m.applyTakeover(p, plan, exe, vault, pre, doImport)
			}, nil)
		})
	})
}

// applyTakeover carries out a takeover plan the person said yes to. Only
// one runs at a time, and it checks again, as it starts, that no takeover
// was done meanwhile (by the CLI, say): the import before it may wait a
// long time for the old keyring to be unlocked.
func (m *Manager) applyTakeover(p *desktopPage, plan *svops.TakeoverPlan, exe, vault, prefix string, doImport bool) {
	if m.takingOver {
		m.say("A takeover is under way already.")
		return
	}
	m.takingOver = true
	var report []string
	m.call(func(_ context.Context, c *secretvault.Client) error {
		if s, err := svops.LoadTakeover(); err == nil {
			return fmt.Errorf("the takeover was already done on %s", s.When.Local().Format("2006-01-02"))
		}
		if doImport {
			// As the CLI: the import has ten minutes of its own, since the
			// old keyring may ask to be unlocked.
			ctx, cancel := context.WithTimeout(m.ctx, 10*time.Minute)
			secrets, warnings, err := m.readKeyring(ctx)
			if err != nil {
				cancel()
				return fmt.Errorf("importing first: %w", err)
			}
			for _, w := range warnings {
				report = append(report, "warning: "+w)
			}
			_, n, err := svops.ImportKeyring(ctx, c, vault, prefix, secrets)
			for i := range secrets {
				secrets[i].Wipe()
			}
			cancel()
			if err != nil {
				return fmt.Errorf("importing first: %w", err)
			}
			report = append(report, fmt.Sprintf("Imported %s.", plural(n, "secret")))
		}
		written, err := svops.ApplyTakeover(plan, exe)
		for _, f := range written {
			report = append(report, "Wrote "+f)
		}
		if err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(m.ctx, callTimeout)
		defer cancel()
		if err := c.ServeKeyring(ctx, true); err != nil {
			return err
		}
		for _, f := range svops.RestartUnits(plan.Restart) {
			report = append(report, fmt.Sprintf("warning: restarting %s: %v %s", f.Unit, f.Err, strings.TrimSpace(string(f.Output))))
		}
		for _, n := range plan.Notes {
			report = append(report, "Still to do by hand: "+n)
		}
		return nil
	}, func(err error) {
		m.takingOver = false
		intro := "secretvault is now the keyring. Give it back with Desktop › System keyring › Give it back…"
		if err != nil {
			intro = m.describe(err) + " What was done so far is below; Give it back… undoes it."
		}
		m.showText("Become the keyring", intro, strings.Join(report, "\n"))
		m.refreshDesktop(p, tabKeyring)
	})
}

// restoreKeyring undoes the takeover exactly (the CLI's keyring restore):
// what it would remove shown first. It works with the daemon gone too,
// which is when it may be needed most: turning the daemon's Secret
// Service off is then all that is left out, as the CLI leaves it.
func (m *Manager) restoreKeyring(p *desktopPage) {
	s, err := svops.LoadTakeover()
	if errors.Is(err, fs.ErrNotExist) {
		m.say("There is no takeover to undo.")
		return
	}
	if err != nil {
		m.fail(err)
		return
	}
	var lines []string
	for _, f := range s.Created {
		lines = append(lines, "remove "+f)
	}
	for _, r := range s.Restart {
		lines = append(lines, "restart "+r+" (systemctl --user)")
	}
	lines = append(lines, "turn off secretvaultd's Secret Service")
	m.showPlan("Give the keyring back", "Giving the keyring back to "+svops.DescribeExe(s.Previous)+" would:", lines, "Give it back", func() {
		var report []string
		c := m.client
		if m.gone {
			c = nil
		}
		m.work(func() error {
			// What was shown is what is undone: a takeover undone, or done
			// again, meanwhile (by the CLI) is looked at again first.
			now, err := svops.LoadTakeover()
			if err != nil || !now.When.Equal(s.When) || !slices.Equal(now.Created, s.Created) {
				return errors.New("the takeover changed since it was shown: look at it again")
			}
			if c != nil {
				ctx, cancel := context.WithTimeout(m.ctx, callTimeout)
				if err := c.ServeKeyring(ctx, false); err != nil {
					report = append(report, "warning: "+m.describe(err))
				}
				cancel()
			} else {
				report = append(report, "warning: secretvaultd is not running: its Secret Service is off with it")
			}
			removed, _, err := svops.UndoTakeover(now) // as the CLI, units that do not restart go unsaid
			for _, f := range removed {
				report = append(report, "Removed "+f)
			}
			return err
		}, func(err error) {
			intro := "Restored: " + svops.DescribeExe(s.Previous) + " is the keyring again."
			if err != nil {
				intro = m.describe(err)
			}
			m.showText("Keyring given back", intro, strings.Join(report, "\n"))
			m.refreshDesktop(p, tabKeyring)
		})
	}, nil)
}

// --- The browsers ---

func (m *Manager) fillBrowsers(p *desktopPage, pn *pane) {
	cli := m.cliProgram()
	vault := p.vault
	var state *svops.BrowserInstall
	var host string
	var browsers []svrpc.BrowserAssociation
	var states []svops.BrowserState
	var statusErr error
	m.load(pn, func(ctx context.Context, c *secretvault.Client) error {
		state, host, states, statusErr = svops.BrowserStatus(cli)
		if vault != "" {
			var err error
			if browsers, err = c.BrowserAssociations(ctx, vault); errors.Is(err, svrpc.ErrCanceled) {
				return err
			}
		}
		return nil
	}, func() widget.Component {
		p.assoc = browsers
		col := widgets.NewColumn(m.paragraph("Browsers with the KeePassXC-Browser extension fill logins from the vault, once they " +
			"start secretvault in KeePassXC's place. Setting them up writes a manifest per browser that names it; undoing puts back " +
			"exactly what was there.")).WithGap(gap).WithPad(gap)
		if state != nil {
			col.Add(m.paragraph(fmt.Sprintf("Set up %s, starting %s.", state.When.Local().Format("2006-01-02 15:04"), state.Host)))
		}
		if statusErr != nil {
			col.Add(toned(m.describe(statusErr), widgets.ToneWarning))
		}
		if len(states) > 0 {
			t := table("Browsers", []widgets.TableColumn{{Title: "Browser", Width: 130}, {Title: "Starts"}}, len(states), func(r, c int) string {
				b := states[r]
				if c == 0 {
					return b.Spot.Title
				}
				return browserLine(b, host)
			})
			col.Add(widgets.NewHeightBox(min(40+28*float32(len(states)), 220), t))
		}
		setup := widgets.NewButton("Set up…", func() { m.installBrowsers(p, states) })
		undo := widgets.NewButton("Undo…", func() { m.uninstallBrowsers(p) })
		setup.SetEnabled(cli != "")
		undo.SetEnabled(state != nil && len(state.Hosts) > 0)
		pn.focus = setup
		col.Add(buttons(setup, undo))
		col.Add(section(m, "Extensions connected to vault "+vault))
		if len(browsers) == 0 {
			col.Add(m.paragraph("None. Connect one from KeePassXC-Browser's toolbar button, once its browser is set up and restarted."))
		} else {
			p.atable = table("Connected extensions", []widgets.TableColumn{
				{Title: "Name", Width: 140}, {Title: "Browser"}, {Title: "Extension"}, {Title: "Since", Width: 130},
			}, len(browsers), func(r, c int) string {
				a := browsers[r]
				switch c {
				case 0:
					return a.Name
				case 1:
					return a.Program
				case 2:
					return a.Extension
				}
				return a.Created.Local().Format("2006-01-02 15:04")
			})
			col.Add(widgets.NewHeightBox(min(40+28*float32(len(browsers)), 200), p.atable))
			col.Add(buttons(widgets.NewButton("Disconnect…", func() { m.disconnectBrowser(p) })))
		}
		return scrolled(col)
	})
}

// browserLine says which host a browser starts, as the CLI's browser
// status does.
func browserLine(b svops.BrowserState, host string) string {
	s := b.Spot
	var line string
	switch {
	case b.NoKey:
		return "no host (no HKEY_CURRENT_USER\\" + s.RegKey + ")"
	case b.Err != nil:
		return b.Path + ": " + b.Err.Error()
	case !b.Current.Exists:
		used := "not used here"
		if s.Used() {
			used = "used here"
		}
		line = "no host (" + used + ")"
	default:
		line = svops.DescribeHost(b.Current.Host, host)
	}
	switch {
	case b.Changed:
		line += "; changed since secretvault set it up"
	case b.Ours && b.Backup != nil:
		line += "; " + svops.DescribeHost(b.Backup.Host, host) + " kept, to put back"
	}
	return line
}

// installBrowsers sets the browsers chosen up (the CLI's browser install):
// the plan per browser first, then each carried out.
func (m *Manager) installBrowsers(p *desktopPage, states []svops.BrowserState) {
	cli := m.cliProgram()
	if cli == "" {
		m.fail(svops.ErrNoCLI)
		return
	}
	f := m.newForm("Set up browsers")
	f.note("The browsers to start secretvault for KeePassXC-Browser:")
	boxes := map[string]*widgets.Checkbox{}
	for _, b := range states {
		boxes[b.Spot.Name] = f.check(b.Spot.Title, b.Spot.Used())
	}
	f.show("Next", func() {
		var names []string
		for _, b := range states {
			if boxes[b.Spot.Name].Checked && !slices.Contains(names, b.Spot.Name) {
				names = append(names, b.Spot.Name)
			}
		}
		if len(names) == 0 {
			f.fail("Choose a browser.")
			return
		}
		var plan *svops.BrowserInstallPlan
		f.work(func() (err error) {
			plan, err = svops.PlanBrowserInstall(names, cli)
			return err
		}, func() {
			var lines []string
			for _, hp := range plan.Hosts {
				lines = append(lines, hostPlanLines(hp, plan.Host)...)
			}
			if plan.KeePassXC {
				lines = append(lines, "", "KeePassXC writes its manifests back each time it starts with browser integration on:",
					"turn that off in KeePassXC (Settings > Browser Integration), or its option to update the manifests at startup.")
			}
			m.showPlan("Set up browsers", "The browsers would start "+plan.Host+" for KeePassXC-Browser:", lines, "Set them up", func() {
				var report []string
				m.work(func() error {
					for _, hp := range plan.Hosts {
						if hp.Skip != "" {
							continue
						}
						rec, err := plan.Apply(hp)
						if err != nil {
							return fmt.Errorf("%s: %w", hp.Label(), err)
						}
						report = append(report, hp.Label()+": wrote "+hp.Spot.Manifest)
						if rec.Backup != nil {
							report = append(report, "  the manifest it replaced, "+svops.DescribeHost(rec.Backup.Host, plan.Host)+", is kept to put back")
						}
					}
					return nil
				}, func(err error) {
					intro := "Restart the browsers, then connect KeePassXC-Browser from its toolbar button. Desktop › Browsers › Undo… undoes it."
					if err != nil {
						intro = m.describe(err) + " Undo… undoes what was done."
					}
					m.showText("Browsers set up", intro, strings.Join(report, "\n"))
					m.refreshDesktop(p, tabBrowsers)
				})
			}, nil)
		})
	})
}

// hostPlanLines says what an install does to one manifest, as the CLI's
// --dry-run does, in this program's words where the CLI's name its
// commands.
func hostPlanLines(p *svops.HostPlan, host string) []string {
	label := p.Label()
	switch {
	case p.Skip == svops.SkipAlreadyDone:
		return []string{label + ": nothing to do: already done"}
	case p.Skip == svops.SkipChanged:
		return []string{label + ": nothing to do: its manifest changed since secretvault set it up (KeePassXC writes its own back when it starts); undo the setup first"}
	case p.Skip != "":
		return []string{label + ": nothing to do: " + p.Skip}
	case p.Spot.RegKey != "":
		if p.RegPrev != nil {
			return []string{label + ": write " + p.Spot.Manifest, "    point HKEY_CURRENT_USER\\" + p.Spot.RegKey + " at it; it names " +
				svops.DescribeHost(p.Current.Host, host) + " now, to put back on undoing"}
		}
		return []string{label + ": write " + p.Spot.Manifest, "    make HKEY_CURRENT_USER\\" + p.Spot.RegKey + ", naming it"}
	case p.Current.Exists:
		return []string{label + ": replace " + p.Spot.Manifest, "    it names " + svops.DescribeHost(p.Current.Host, host) + " now; a copy is kept, to put back on undoing"}
	}
	lines := []string{label + ": write " + p.Spot.Manifest}
	if made := p.MakesDirs(); len(made) > 0 {
		lines = append(lines, "    making "+strings.Join(made, ", "))
	}
	return lines
}

// uninstallBrowsers undoes the setup exactly (the CLI's browser
// uninstall): what it would do shown first.
func (m *Manager) uninstallBrowsers(p *desktopPage) {
	var would []svops.Uninstalled
	m.work(func() (err error) {
		would, err = svops.UninstallBrowsers(true)
		return err
	}, func(err error) {
		if errors.Is(err, svops.ErrNoBrowserInstall) {
			m.say("secretvault is not set up in any browser.")
			return
		}
		if err != nil {
			m.fail(err)
			return
		}
		var lines []string
		for _, u := range would {
			lines = append(lines, undoLines(u)...)
		}
		m.showPlan("Undo the browsers' setup", "Undoing would:", lines, "Undo", func() {
			var done []svops.Uninstalled
			m.work(func() (err error) {
				done, err = svops.UninstallBrowsers(false)
				return err
			}, func(err error) {
				var report []string
				for _, u := range done {
					report = append(report, doneLines(u)...)
				}
				intro := "Undone: the browsers start what they started before."
				if err != nil {
					intro = m.describe(err)
				}
				m.showText("Browsers' setup undone", intro, strings.Join(report, "\n"))
				m.refreshDesktop(p, tabBrowsers)
			})
		}, nil)
	})
}

// undoLines says what undoing one manifest would do, as the CLI's
// uninstall --dry-run does.
func undoLines(u svops.Uninstalled) []string {
	label := u.Label()
	if u.Changed {
		lines := []string{label + ": " + u.Manifest + " changed since secretvault set it up: left as it is"}
		if u.Backup != nil && u.Backup.Copy != "" {
			lines = append(lines, "  the manifest it replaced is still in "+u.Backup.Copy)
		}
		return lines
	}
	rec := u.InstalledHost
	var lines []string
	switch {
	case rec.RegKey != "" && rec.RegPrev != nil:
		lines = append(lines, fmt.Sprintf("%s: point HKEY_CURRENT_USER\\%s back at %s, and remove %s", label, rec.RegKey, *rec.RegPrev, rec.Manifest))
	case rec.RegKey != "":
		lines = append(lines, fmt.Sprintf("%s: remove HKEY_CURRENT_USER\\%s and %s", label, rec.RegKey, rec.Manifest))
	case rec.Backup != nil && rec.Backup.Link != "":
		lines = append(lines, fmt.Sprintf("%s: make %s a link to %s again", label, rec.Manifest, rec.Backup.Link))
	case rec.Backup != nil:
		lines = append(lines, fmt.Sprintf("%s: put back %s as it was, from %s", label, rec.Manifest, rec.Backup.Copy))
	default:
		lines = append(lines, fmt.Sprintf("%s: remove %s", label, rec.Manifest))
	}
	for i := len(rec.MadeDirs) - 1; i >= 0; i-- {
		lines = append(lines, "  and "+rec.MadeDirs[i]+", if empty")
	}
	return lines
}

// doneLines says what undoing one manifest did.
func doneLines(u svops.Uninstalled) []string {
	label := u.Label()
	switch {
	case u.Changed:
		return undoLines(u)
	case u.RegKey != "" && u.RegPrev != nil:
		return []string{fmt.Sprintf("%s: HKEY_CURRENT_USER\\%s names %s again", label, u.RegKey, *u.RegPrev)}
	case u.RegKey != "":
		return []string{fmt.Sprintf("%s: removed HKEY_CURRENT_USER\\%s", label, u.RegKey)}
	case u.Backup != nil:
		return []string{fmt.Sprintf("%s: put back the manifest naming %s, at %s", label, svops.DescribeHost(u.Backup.Host, u.Host), u.Manifest)}
	}
	return []string{fmt.Sprintf("%s: removed %s", label, u.Manifest)}
}

// disconnectBrowser disconnects the extension selected from the vault
// (the CLI's browser rm).
func (m *Manager) disconnectBrowser(p *desktopPage) {
	i := selected(p.atable)
	if i < 0 || i >= len(p.assoc) {
		return
	}
	a := p.assoc[i]
	m.confirm("Disconnect "+a.Name+"?", fmt.Sprintf("Disconnect %s (%s) from vault %s?\n\nIt has to be connected again, from its toolbar button, to fill logins.", a.Name, a.Program, a.Vault), "Disconnect", func() {
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			return c.RemoveBrowserAssociation(ctx, a.Vault, a.Name)
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Disconnected %s.", a.Name)
			m.refreshDesktop(p, tabBrowsers)
		})
	})
}

// --- GnuPG ---

func (m *Manager) fillGnuPG(p *desktopPage, pn *pane) {
	var st svrpc.Status
	here := svops.GnuPGHere()
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		st, err = c.Status(ctx)
		return err
	}, func() widget.Component {
		agent := "off"
		if st.GPGAgent != "" {
			agent = st.GPGAgent
		}
		homes := "none"
		if len(st.GnuPGHomes) > 0 {
			homes = strings.Join(st.GnuPGHomes, ", ")
		}
		col := widgets.NewColumn(m.paragraph("gpg can sign and decrypt with the OpenPGP keys in vault "+p.vault+", through secretvaultd standing in for "+
			"its agent: the keys never leave the daemon, and each program's first use of a key is asked about."),
			m.facts([][2]string{{"secretvaultd's gpg agent", agent}, {"GnuPG homes using it", homes}})).WithGap(gap).WithPad(gap)
		if here != nil {
			col.Add(m.paragraph(sentence(here.Error())))
			return scrolled(col)
		}
		setup := widgets.NewButton("Let gpg use the vault's keys…", func() { m.gnupgSetup(p) })
		stop := widgets.NewButton("Stop…", func() { m.gnupgRemove(p) })
		pn.focus = setup
		col.Add(buttons(setup, stop))
		return scrolled(col)
	})
}

// gnupgForm asks which GnuPG home, and which gpg.
func (m *Manager) gnupgForm(title string, withGPG bool) (*formDialog, *pathField, *pathField) {
	f := m.newForm(title)
	def, _ := svops.GnuPGHome("")
	home := f.path("GnuPG home", PickFolder, "")
	home.field.SetText(def)
	f.note("Default: secretvault's own GnuPG home, " + def + ". Your own (~/.gnupg) makes gpg use secretvault's keys, and no longer gpg-agent's.")
	var gpg *pathField
	if withGPG {
		gpg = f.path("gpg", PickOpen, "")
		f.note("gpg: optional: the program, when it is not the gpg on PATH.")
	}
	return f, home, gpg
}

// gnupgSetup points a GnuPG home at the daemon (the CLI's pgp gpg-setup):
// the plan first (svops.PlanGnuPGSetup), then carried out.
func (m *Manager) gnupgSetup(p *desktopPage) {
	cli := m.cliProgram()
	if cli == "" {
		m.fail(svops.ErrNoCLI)
		return
	}
	vault := p.vault
	f, homeField, gpgField := m.gnupgForm("Let gpg use the vault's keys", true)
	f.show("Next", func() {
		home, err := svops.GnuPGHome(homeField.Path())
		if err != nil {
			f.fail(sentence(err.Error()))
			return
		}
		gpg := gpgField.Path()
		var plan *svops.GnuPGPlan
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			plan, err = svops.PlanGnuPGSetup(ctx, c, svops.GnuPGOptions{Vault: vault, Home: home, GPG: gpg, CLI: cli})
			return err
		}, func() {
			var lines []string
			if !plan.HomeExists {
				lines = append(lines, "make the directory "+home+" (0700)")
			}
			lines = append(lines, "link "+plan.Socket+" (where gpg looks for its agent) to "+plan.Agent)
			if plan.SSHSocket != "" && plan.SSHAgent != "" {
				lines = append(lines, "link "+plan.SSHSocket+" (its SSH agent) to "+plan.SSHAgent)
			}
			for _, k := range plan.Keys {
				lines = append(lines, fmt.Sprintf("import the public key %s  %s (%s), trusted as your own", svops.GroupFingerprint(k.Fingerprint), svops.FirstUserID(k), k.Item))
			}
			lines = append(lines, "add to "+filepath.Join(home, "gpg.conf")+": "+plan.AgentProgram)
			lines = append(lines, gnupgNotes(plan)...)
			intro := "Pointing the GnuPG home " + home + " at secretvault would:"
			if plan.OwnHome {
				intro = home + " is your own GnuPG home: gpg will use secretvault's keys, and no longer gpg-agent's. Where systemd starts gpg-agent by " +
					"its sockets, stop that first (systemctl --user mask --now gpg-agent.socket gpg-agent-ssh.socket gpg-agent-extra.socket gpg-agent-browser.socket). " + intro
			}
			m.showPlan("Let gpg use the vault's keys", intro, lines, "Do it", func() {
				var res svrpc.GnuPGLinkResult
				var note string
				m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
					res, note, err = svops.ApplyGnuPGSetup(ctx, c, plan)
					return err
				}, func(err error) {
					if err != nil {
						m.fail(err)
						return
					}
					var report []string
					if note != "" {
						report = append(report, "warning: "+note)
					}
					for _, k := range plan.Keys {
						report = append(report, svops.GroupFingerprint(k.Fingerprint)+"  "+svops.FirstUserID(k))
					}
					report = append(report, "Its agent is secretvaultd: "+plan.Socket+" -> "+res.Agent)
					if res.SSHAgent != "" {
						report = append(report, "and so is its SSH agent: "+plan.SSHSocket+" -> "+res.SSHAgent)
					}
					report = append(report, gnupgNotes(plan)...)
					report = append(report, "Use it with: export GNUPGHOME="+home)
					m.showText("gpg uses the vault's keys", "The GnuPG home "+home+" signs and decrypts with secretvault's keys:", strings.Join(report, "\n"))
					m.refreshDesktop(p, tabGnuPG)
				})
			}, plan.Discard)
		})
	})
}

// gnupgNotes says what gpg will not get.
func gnupgNotes(p *svops.GnuPGPlan) []string {
	var out []string
	for _, s := range p.Skipped {
		out = append(out, "Left out: "+s)
	}
	if p.Unreachable > 0 {
		out = append(out, fmt.Sprintf("Note: %d secret keys in %s are GnuPG's own, which gpg cannot use while secretvault is its agent; "+
			"take them into the vault first (export them from gpg, then Keys › OpenPGP keys › Import…).", p.Unreachable, filepath.Join(p.Home, "private-keys-v1.d")))
	}
	return out
}

// gnupgRemove stops pointing a GnuPG home at the daemon (the CLI's
// gpg-setup --remove): what it would do said first.
func (m *Manager) gnupgRemove(p *desktopPage) {
	f, homeField, _ := m.gnupgForm("Stop gpg using the vault's keys", false)
	f.show("Next", func() {
		home, err := svops.GnuPGHome(homeField.Path())
		if err != nil {
			f.fail(sentence(err.Error()))
			return
		}
		var pointed bool
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			pointed, err = svops.GnuPGPointed(ctx, c, home)
			return err
		}, func() {
			if !pointed {
				m.say("%s is not pointed at secretvault.", home)
				return
			}
			m.showPlan("Stop gpg using the vault's keys", "Removing would take away:", []string{
				"the links to secretvaultd in " + home + "'s socket directory",
				"secretvault's agent-program line from " + filepath.Join(home, "gpg.conf"),
				"(the public keys stay)",
			}, "Remove", func() {
				m.call(func(ctx context.Context, c *secretvault.Client) error {
					return svops.RemoveGnuPG(ctx, c, home)
				}, func(err error) {
					if err != nil {
						m.fail(err)
						return
					}
					m.say("The GnuPG home %s is no longer pointed at secretvault; the public keys stay in its keyring.", home)
					m.refreshDesktop(p, tabGnuPG)
				})
			}, nil)
		})
	})
}

// --- Program helpers ---

// helperUse says how each helper is put to use, once its link is there.
var helperUse = map[string]string{
	"git-credential-secretvault":    "git config --global credential.helper secretvault",
	"docker-credential-secretvault": `"credsStore": "secretvault" in ~/.docker/config.json`,
	"age-plugin-secretvault":        "age -d -i IDENTITY-FILE (the identity line of Keys › age identities)",
	"secretvault-browser":           "Desktop › Browsers › Set up…",
}

func (m *Manager) fillHelpers(p *desktopPage, pn *pane) {
	cli := m.cliProgram()
	var links []svops.HelperLink
	pn.gen++
	gen := pn.gen
	m.work(func() error {
		links = svops.HelperLinks(cli)
		return nil
	}, func(error) {
		if !m.up(p.tabbedPage) || gen != pn.gen {
			return
		}
		col := widgets.NewColumn(m.paragraph("git, docker and age start secretvault under these names, as their credential helper and plugin; " +
			"each read is asked about like any program's. The names are links to the secretvault program, beside it: the installer " +
			"(scripts/install.sh) makes them, as it installs the CLI.")).WithGap(gap).WithPad(gap)
		if cli == "" {
			col.Add(toned(m.describe(svops.ErrNoCLI), widgets.ToneWarning))
		}
		for _, h := range links {
			col.Add(section(m, h.Name))
			link := "not made"
			switch {
			case h.Ours:
				link = h.Path
			case h.Exists:
				link = h.Path + ": not a link to secretvault"
			}
			found := "not found on PATH: the program that starts it will not find it"
			if h.OnPath != "" {
				found = h.OnPath
			}
			use := helperUse[h.Name]
			col.Add(m.facts([][2]string{{"Link", link}, {"Found as", found}, {"Use", use}}))
			if strings.HasPrefix(use, "git ") {
				col.Add(buttons(widgets.NewButton("Copy git's setting", func() { m.copyValue([]byte(use), "git's setting", "") }),
					widgets.NewButton("Show git's logins", func() { m.showFolder("git/") })))
			}
			if strings.HasPrefix(h.Name, "docker") {
				col.Add(buttons(widgets.NewButton("Show the registries' logins", func() { m.showFolder("docker/") })))
			}
		}
		refresh := widgets.NewButton("Refresh", pn.refresh)
		pn.focus = refresh
		col.Add(buttons(refresh))
		pn.box.Set(scrolled(col))
	})
}

// showFolder goes back to the items, showing a folder of them.
func (m *Manager) showFolder(folder string) {
	m.closeVaultPage()
	m.folder = folder
	if m.findFolder(folder) == nil {
		m.say("Vault %s has nothing under %s yet: the helper makes those items as it stores logins.", m.vault, folder)
		m.folder = ""
	}
	m.drawFolders()
	m.applyFilter()
}

// --- The host daemon ---

// hostCall talks to the host daemon on its admin socket (root's alone),
// on a connection of its own, as the CLI's host commands do.
func (m *Manager) hostCall(fn func(ctx context.Context, c *secretvault.Client) error, then func(error)) {
	sock := m.hostSocket()
	m.work(func() error {
		c, err := secretvault.Connect(secretvault.Options{Socket: sock, NoStart: true, Name: "secretvault-gui"})
		if err != nil {
			return fmt.Errorf("the host daemon does not answer on %s: %v; is secretvaultd-host.service running? Its admin socket is root's alone", sock, err)
		}
		defer c.Close()
		ctx, cancel := context.WithTimeout(m.ctx, callTimeout)
		defer cancel()
		return fn(ctx, c)
	}, then)
}

func (m *Manager) fillHost(p *desktopPage, pn *pane) {
	var st svrpc.HostStatus
	var pol svrpc.HostPolicy
	var events []svrpc.HostEvent
	pn.gen++
	gen := pn.gen
	m.hostCall(func(ctx context.Context, c *secretvault.Client) (err error) {
		if st, err = c.HostStatus(ctx); err != nil {
			return err
		}
		if pol, err = c.HostPolicy(ctx); err != nil {
			return err
		}
		events, err = c.HostAudit(ctx, 200)
		return err
	}, func(err error) {
		if !m.up(p.tabbedPage) || gen != pn.gen {
			return
		}
		pn.filled = true
		initBtn := widgets.NewButton("Make the host identity…", func() { m.hostInit(p) })
		if err != nil {
			pn.focus = initBtn
			pn.box.Set(m.paneColumn("The host daemon (secretvaultd --host) serves a server's services by policy, and asks nobody. It is set up "+
				"by root, on the server: run this program as root there. "+m.describe(err), nil, initBtn, widgets.NewButton("Try again", pn.refresh)))
			return
		}
		pn.box.Set(m.drawHost(p, pn, st, pol, events, initBtn))
	})
}

func (m *Manager) drawHost(p *desktopPage, pn *pane, st svrpc.HostStatus, pol svrpc.HostPolicy, events []svrpc.HostEvent, initBtn *widgets.Button) widget.Component {
	identity := "none: Make the host identity… makes one"
	switch {
	case st.Identity != "":
		identity = st.Identity
	case st.IdentityError != "":
		identity = "none: " + st.IdentityError
	}
	policy := fmt.Sprintf("%s (%s, %s)", st.Policy, plural(st.Credentials, "credential"), plural(st.Clients, "local service"))
	if st.PolicyError != "" {
		policy = st.Policy + ": " + st.PolicyError + "; everything is refused until it is fixed"
	}
	rows := [][2]string{
		{"secretvaultd --host", fmt.Sprintf("%s, process %d", st.Version, st.PID)},
		{"Data", st.Data}, {"Credentials", st.CredentialSocket}, {"Services", st.ServiceSocket}, {"Admin", st.AdminSocket},
		{"Identity", identity},
	}
	if st.Recipient != "" {
		rows = append(rows, [2]string{"Recipient", st.Recipient})
	}
	rows = append(rows, [2]string{"Policy", policy}, [2]string{"Since it started", fmt.Sprintf("%d delivered, %d refused or failed", st.Delivered, st.Refused)})
	col := widgets.NewColumn(m.facts(rows)).WithGap(gap).WithPad(gap)
	allow := widgets.NewButton("Allow…", func() { m.hostRule(p, true) })
	pn.focus = allow
	col.Add(buttons(allow, widgets.NewButton("Deny…", func() { m.hostRule(p, false) }), initBtn, widgets.NewButton("Refresh", pn.refresh)))

	col.Add(section(m, "Vaults"))
	if len(st.Vaults) == 0 {
		col.Add(m.paragraph("No vaults yet: share one to the recipient above, and bring it here."))
	} else {
		vs := st.Vaults
		col.Add(widgets.NewHeightBox(min(40+28*float32(len(vs)), 180), table("Host vaults", []widgets.TableColumn{
			{Title: "Vault", Width: 140}, {Title: "State", Width: 90}, {Title: "Opens with the host identity"},
		}, len(vs), func(r, c int) string {
			v := vs[r]
			switch c {
			case 0:
				return v.Name
			case 1:
				switch {
				case v.Missing:
					return "missing"
				case v.Locked:
					return "locked"
				}
				return "unlocked"
			}
			if v.HostSlot {
				return "yes"
			}
			return "no: share it to the host's recipient"
		})))
	}
	col.Add(section(m, "Credentials (LoadCredential=CREDENTIAL:"+svrpc.HostCredentialSocket()+")"))
	creds := pol.Credentials
	col.Add(widgets.NewHeightBox(min(40+28*float32(max(1, len(creds))), 180), table("Host credentials", []widgets.TableColumn{
		{Title: "Unit", Width: 170}, {Title: "Credential", Width: 140}, {Title: "Reference"},
	}, len(creds), func(r, c int) string {
		return []string{creds[r].Unit, creds[r].Credential, creds[r].Ref}[c]
	})))
	col.Add(section(m, "Local services (on "+svrpc.HostSocket()+")"))
	clients := pol.Clients
	col.Add(widgets.NewHeightBox(min(40+28*float32(max(1, len(clients))), 180), table("Host local services", []widgets.TableColumn{
		{Title: "User", Width: 120}, {Title: "Program"}, {Title: "References"},
	}, len(clients), func(r, c int) string {
		cl := clients[r]
		switch c {
		case 0:
			return cl.User
		case 1:
			if cl.Program == "" {
				return "any"
			}
			return cl.Program
		}
		return strings.Join(cl.Refs, " ")
	})))
	col.Add(section(m, "Deliveries and refusals, newest first"))
	evs := slices.Clone(events)
	slices.Reverse(evs)
	col.Add(widgets.NewHeightBox(220, table("Host audit", []widgets.TableColumn{
		{Title: "When", Width: 140}, {Title: "Outcome", Width: 80}, {Title: "Who"}, {Title: "What"}, {Title: "Detail"},
	}, len(evs), func(r, c int) string {
		ev := evs[r]
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
		return []string{ev.Time.Local().Format("2006-01-02 15:04:05"), ev.Outcome, who, what, detail}[c]
	})))
	return scrolled(col)
}

// hostRule allows or denies on the host daemon (the CLI's host allow and
// host deny): a unit's credential, or a local service's references.
func (m *Manager) hostRule(p *desktopPage, allow bool) {
	title := "Deny on the host"
	if allow {
		title = "Allow on the host"
	}
	f := m.newForm(title)
	kind := f.choice("For", []string{"a systemd unit's credential", "a local service that is not a unit"}, 0)
	unit := f.text("Unit", "", "app.service, or a glob: app@*.service")
	cred := f.text("Credential", "", "the name in LoadCredential=")
	user := f.text("User", "", "a local service's user: a name or a uid")
	program := f.path("Program", PickOpen, "")
	refs := f.text("References", "", "sv://VAULT/ITEM#FIELD; several separated by spaces")
	if allow {
		f.note("A unit's credential takes one reference; a local service any number.")
	} else {
		f.note("For a local service, no reference denies the whole entry.")
	}
	f.show(strings.SplitN(title, " ", 2)[0], func() {
		var r svrpc.HostRule
		refList := strings.Fields(refs.Text)
		if kind.Selected == 0 {
			r = svrpc.HostRule{Unit: strings.TrimSpace(unit.Text), Credential: strings.TrimSpace(cred.Text)}
			if r.Unit == "" || r.Credential == "" {
				f.fail("Give the unit and the credential's name.")
				return
			}
			if allow {
				if len(refList) != 1 {
					f.fail("Give the one reference the credential is.")
					return
				}
				r.Ref = refList[0]
			}
		} else {
			r = svrpc.HostRule{User: strings.TrimSpace(user.Text), Program: program.Path(), Refs: refList}
			if r.User == "" || allow && len(refList) == 0 {
				f.fail("Give the user, and the references it may read.")
				return
			}
			if r.Program != "" {
				abs, err := filepath.Abs(r.Program)
				if err != nil {
					f.fail(sentence(err.Error()))
					return
				}
				r.Program = abs
			}
		}
		var res svrpc.HostAllowResult
		f.work(func() error {
			done := make(chan error, 1)
			m.hostCallSync(func(ctx context.Context, c *secretvault.Client) (err error) {
				if allow {
					res, err = c.HostAllow(ctx, r)
					return err
				}
				return c.HostDeny(ctx, r)
			}, done)
			return <-done
		}, func() {
			if !allow {
				m.say("Removed from the host policy.")
			} else {
				intro := ""
				if r.Unit != "" {
					intro = fmt.Sprintf("%s now gets its credential %s from %s. In the unit:", r.Unit, r.Credential, r.Ref)
				} else {
					who := "User " + r.User
					if r.Program != "" {
						who = r.Program + ", run by user " + r.User + ","
					}
					intro = fmt.Sprintf("%s may now read %s, on %s.", who, strings.Join(r.Refs, ", "), svrpc.HostSocket())
				}
				text := ""
				if r.Unit != "" {
					text = "LoadCredential=" + r.Credential + ":" + svrpc.HostCredentialSocket()
				}
				for _, w := range res.Warnings {
					text += "\nwarning: " + w
				}
				m.showText("Allowed", intro, strings.TrimSpace(text))
			}
			m.refreshDesktop(p, tabHost)
		})
	})
}

// hostCallSync is hostCall from a worker's goroutine: the answer goes to
// done.
func (m *Manager) hostCallSync(fn func(ctx context.Context, c *secretvault.Client) error, done chan<- error) {
	sock := m.hostSocket()
	c, err := secretvault.Connect(secretvault.Options{Socket: sock, NoStart: true, Name: "secretvault-gui"})
	if err != nil {
		done <- fmt.Errorf("the host daemon does not answer on %s: %v", sock, err)
		return
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(m.ctx, callTimeout)
	defer cancel()
	done <- fn(ctx, c)
}

// hostInit makes the host identity, on files, as root (the CLI's host
// init): sealed with systemd-creds, or in a file root alone reads.
func (m *Manager) hostInit(p *desktopPage) {
	f := m.newForm("Make the host identity")
	suite := f.choice("Cipher suite", []string{"modern: X25519", "nist: P-256 (FIPS 140-3)"}, 0)
	seal := f.check("Seal it with systemd-creds (to the TPM2, and the host key), never writing it in the clear", false)
	pcrs := f.text("TPM2 PCRs", "", "sealed: also bind it to these, such as 7")
	out := f.path("Identity file", PickSave, "")
	out.field.SetText(svrpc.HostIdentityFile())
	credstore := f.path("Sealed, to", PickSave, "")
	credstore.field.SetText(svrpc.HostCredstore)
	f.note("It is made before the service is installed, and never replaces one: vaults shared to the old one would need sharing again.")
	f.show("Make", func() {
		o := svops.HostInitOptions{Suite: []string{"modern", "nist"}[max(0, suite.Selected)], Seal: seal.Checked, Out: out.Path(),
			Credstore: credstore.Path(), PCRs: strings.TrimSpace(pcrs.Text), SystemdCreds: m.systemdCreds}
		var res *svops.HostInitResult
		f.work(func() (err error) {
			res, err = svops.HostInit(o)
			return err
		}, func() {
			intro := "Made the host identity, in " + res.Path + ", readable by root only."
			if res.Sealed {
				intro = "Made the host identity, sealed in " + res.Path + ": systemd passes it to secretvaultd-host.service, and it was never written in the clear."
			}
			next := []string{"Its recipient, which vaults are shared to:", "", "    " + res.Recipient, ""}
			if !res.Sealed {
				next = append(next, "To seal it to this machine instead, and remove the plain copy:",
					"    systemd-creds encrypt --name="+svrpc.HostIdentityCredential+" "+o.Out+" "+svrpc.HostCredstore,
					"    shred -u "+o.Out, "")
			}
			next = append(next, "Then: install the host service (secretvaultd install --host); share a vault to the recipient (Vault › Sharing › Share with…), "+
				"bring it to "+filepath.Join(svrpc.HostDataDir(), "vaults", "NAME")+" and add it; and allow the units their credentials (Allow…).")
			m.showText("Host identity made", intro, strings.Join(next, "\n"))
			m.refreshDesktop(p, tabHost)
		})
	})
}
