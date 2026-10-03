package svmanager

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
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
// browsers starting secretvault for its own extension, gpg using the
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
		keyring := "nothing: no app can keep passwords there now"
		switch {
		case holder.BusErr != nil:
			keyring = "not known: there is no desktop session to ask (" + holder.BusErr.Error() + ")"
		case holder.Held:
			keyring = fmt.Sprintf("%s (%s, process %d)", svops.KeyringName(holder.Owner.Exe), holder.Owner.Exe, holder.Owner.PID)
		}
		rows := [][2]string{{"The system keyring is", keyring}, {"secretvault's keyring service", orNot(st.SecretService)}}
		if state != nil {
			rows = append(rows, [2]string{"secretvault took over", state.When.Local().Format("2006-01-02 15:04") + ", from " + svops.KeyringName(state.Previous)})
		}
		col := widgets.NewColumn(m.paragraph("Apps such as your browser, mail and Wi-Fi settings keep their passwords in the system keyring. "+
			"secretvault can copy them into your vault, or take the keyring's place so that an app must ask you before it reads one. "+
			"Giving the keyring back undoes every change."),
			m.facts(rows)).WithGap(gap).WithPad(gap)
		if here != nil {
			col.Add(m.paragraph(sentence(here.Error())))
			return scrolled(col)
		}
		imp := widgets.NewButton("Copy its passwords into the vault…", func() { m.importKeyring(p) })
		take := widgets.NewButton("Take over the keyring…", func() { m.takeOver(p) })
		give := widgets.NewButton("Give the keyring back…", func() { m.restoreKeyring(p) })
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
	f := m.newForm("Copy the keyring's passwords")
	f.intro("The passwords apps keep in the system keyring are copied into vault " + vault + ". The keyring keeps them too, and nothing changes for your apps.")
	prefix := f.text("Put them in the folder", "imported", "imported")
	f.show("Next", func() {
		pre := strings.TrimSpace(prefix.Text)
		if pre == "" {
			pre = "imported"
		}
		var secrets []svsecret.Secret
		var warnings, names []string
		var holder string
		f.work(func() error {
			ctx, cancel := context.WithTimeout(m.ctx, 10*time.Minute)
			defer cancel()
			if h := svops.KeyringHolderNow(ctx); h.Held {
				holder = h.Owner.Exe
			}
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
			m.showPlan(svops.KeyringImportPlain(holder, vault, pre, names, warnings), func() {
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
					m.say("Copied %s into vault %s.", plural(n, "password"), vault)
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
		show := func(doImport bool, pre string) {
			m.showPlan(svops.TakeoverPlain(plan, exe, doImport, vault), func() {
				m.applyTakeover(p, plan, exe, vault, pre, doImport)
			}, nil)
		}
		if exe == "" || vault == "" {
			show(false, "imported") // nothing to copy first
			return
		}
		f := m.newForm("Make secretvault your system keyring")
		f.intro("Before secretvault takes over, it can copy the passwords " + svops.KeyringName(exe) + " holds into your vault, so that apps still find them.")
		importFirst := f.check("Copy its passwords into vault "+vault+" first", true)
		prefix := f.text("Put them in the folder", "imported", "imported")
		f.show("Next", func() {
			pre := "imported"
			if strings.TrimSpace(prefix.Text) != "" {
				pre = strings.TrimSpace(prefix.Text)
			}
			f.close()
			show(importFirst.Checked, pre)
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
		title, intro := "secretvault is your system keyring", "Apps now ask secretvault for their passwords, and it asks you before they read one. "+
			"Give the keyring back… on this tab undoes it."
		if len(plan.Notes) > 0 {
			intro += " One step is left for you to do: the details say which."
		}
		if err != nil {
			title, intro = "The takeover did not finish", m.describe(err)+" Give the keyring back… on this tab undoes what was done; the details say what that is."
		}
		m.showDone(title, intro, report)
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
	m.showPlan(svops.RestorePlain(s), func() {
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
			title, intro := "Keyring given back", svops.SentenceStart(svops.KeyringName(s.Previous))+" is your system keyring again."
			if err != nil {
				title, intro = "Giving the keyring back did not finish", m.describe(err)
			}
			m.showDone(title, intro, report)
			m.refreshDesktop(p, tabKeyring)
		})
	}, nil)
}

// --- The browsers ---

func (m *Manager) fillBrowsers(p *desktopPage, pn *pane) {
	cli := m.cliProgram()
	var state *svops.BrowserInstall
	var host string
	var states []svops.BrowserState
	var statusErr error
	m.load(pn, func(context.Context, *secretvault.Client) error {
		state, host, states, statusErr = svops.BrowserStatus(cli)
		return nil
	}, func() widget.Component {
		col := widgets.NewColumn(m.paragraph("The secretvault extension fills and saves logins in your browser, asking you first. Two steps: " +
			"Set up… gives a browser permission to start secretvault (one small settings file; Undo… takes it back), " +
			"and Save the extension… writes the extension for you to add to the browser.")).WithGap(gap).WithPad(gap)
		if state != nil {
			col.Add(m.paragraph(fmt.Sprintf("Set up %s, starting %s.", state.When.Local().Format("2006-01-02 15:04"), state.Host)))
		}
		if statusErr != nil {
			col.Add(toned(m.describe(statusErr), widgets.ToneWarning))
		}
		hostTable := func(h svops.NativeHost) {
			ss := svops.StatesOf(states, h)
			if len(ss) == 0 {
				return
			}
			t := table(h.Title, []widgets.TableColumn{{Title: "Browser", Width: 130}, {Title: "Starts"}}, len(ss), func(r, c int) string {
				if c == 0 {
					return ss[r].Spot.Title
				}
				return browserLine(ss[r], host)
			})
			col.Add(widgets.NewHeightBox(min(40+28*float32(len(ss)), 220), t))
		}
		recorded := func(h svops.NativeHost) bool {
			if state == nil {
				return false
			}
			for _, r := range state.Hosts {
				if r.NativeHost().Name == h.Name {
					return true
				}
			}
			return false
		}

		col.Add(section(m, "secretvault's own extension"))
		hostTable(svops.ExtensionHost)
		setup := widgets.NewButton("Set up…", func() { m.installBrowsers(p, states, svops.ExtensionHost) })
		undo := widgets.NewButton("Undo…", func() { m.uninstallBrowsers(p, &svops.ExtensionHost) })
		save := widgets.NewButton("Save the extension…", func() { m.saveExtension() })
		setup.SetEnabled(cli != "")
		undo.SetEnabled(recorded(svops.ExtensionHost))
		pn.focus = setup
		col.Add(buttons(setup, undo, save))
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
	if b.Changed {
		line += "; changed since secretvault set it up"
	}
	return line
}

// installBrowsers lets the browsers chosen start secretvault for a
// native host (the CLI's browser install): which browsers, then the plan
// in plain words (svops.BrowserInstallPlain), its manifests under Show
// details, and only then each carried out.
func (m *Manager) installBrowsers(p *desktopPage, states []svops.BrowserState, native svops.NativeHost) {
	cli := m.cliProgram()
	if cli == "" {
		m.fail(svops.ErrNoCLI)
		return
	}
	f := m.newForm("Let browsers use secretvault")
	f.intro("Which browsers should the secretvault extension work in? Each needs your permission to start secretvault; the next step says what that changes.")
	mine := svops.StatesOf(states, native)
	boxes := map[string]*widgets.Checkbox{}
	for _, b := range mine {
		title := b.Spot.Title
		if !b.Spot.Used() {
			title += " (not found on this computer)"
		}
		boxes[b.Spot.Name] = f.check(title, b.Spot.Used())
	}
	f.show("Next", func() {
		var names []string
		for _, b := range mine {
			if boxes[b.Spot.Name].Checked && !slices.Contains(names, b.Spot.Name) {
				names = append(names, b.Spot.Name)
			}
		}
		if len(names) == 0 {
			f.fail("Choose at least one browser.")
			return
		}
		var plan *svops.BrowserInstallPlan
		f.work(func() (err error) {
			plan, err = svops.PlanBrowserInstall(native, names, cli)
			return err
		}, func() {
			m.showPlan(svops.BrowserInstallPlain(plan), func() {
				var report []string
				var who []string
				m.work(func() error {
					for _, hp := range plan.Todo() {
						if _, err := plan.Apply(hp); err != nil {
							return fmt.Errorf("%s: %w", hp.Label(), err)
						}
						for _, b := range hp.Browsers {
							who = append(who, svops.BrowserTitle(b))
						}
						report = append(report, hp.Label()+": wrote "+hp.Spot.Manifest)
					}
					return nil
				}, func(err error) {
					title := strings.Join(who, ", ") + " can now use secretvault"
					intro := "Restart the browser, then add the secretvault extension to it: Save the extension… on this tab writes it, and says how. Undo… takes the permission back."
					if err != nil {
						title, intro = "Setting up the browsers did not finish", m.describe(err)+" Undo… on this tab takes back what was done."
					}
					m.showDone(title, intro, report)
					m.refreshDesktop(p, tabBrowsers)
				})
			}, nil)
		})
	})
}

// uninstallBrowsers takes back what installBrowsers did, exactly (the
// CLI's browser uninstall): the plan in plain words first.
func (m *Manager) uninstallBrowsers(p *desktopPage, only *svops.NativeHost) {
	var would []svops.Uninstalled
	m.work(func() (err error) {
		would, err = svops.UninstallBrowsers(only, true)
		return err
	}, func(err error) {
		if errors.Is(err, svops.ErrNoBrowserInstall) {
			m.say("No browser is set up to use secretvault: there is nothing to undo.")
			return
		}
		if err != nil {
			m.fail(err)
			return
		}
		m.showPlan(svops.BrowserUninstallPlain(would), func() {
			var done []svops.Uninstalled
			m.work(func() (err error) {
				done, err = svops.UninstallBrowsers(only, false)
				return err
			}, func(err error) {
				var report []string
				for _, u := range done {
					report = append(report, doneLines(u)...)
				}
				title, intro := "Browser access removed", "The browsers no longer start secretvault, and their files are as they were before. Your passwords stay in the vault."
				if err != nil {
					title, intro = "Removing browser access did not finish", m.describe(err)
				}
				m.showDone(title, intro, report)
				m.refreshDesktop(p, tabBrowsers)
			})
		}, nil)
	})
}

// saveExtension writes secretvault's extension out (the CLI's browser
// extension): a .zip for Firefox, or a folder for Chromium's family, then
// says how to load it.
func (m *Manager) saveExtension() {
	f := m.newForm("Save the extension")
	f.intro("This saves the secretvault extension for you to add to your browser: Firefox takes the .zip file; " +
		"Chrome, Chromium, Brave, Edge and Vivaldi take a folder. The next window says how to add it.")
	out := f.path("Save to", PickSave, svops.ExtensionFileName())
	if wd, err := os.Getwd(); err == nil {
		out.field.SetText(filepath.Join(wd, svops.ExtensionFileName()))
	}
	asDir := f.check("Save it as a folder, for Chrome, Chromium, Brave, Edge or Vivaldi", false)
	f.show("Save", func() {
		path, dir := out.Path(), asDir.Checked
		if path == "" {
			f.fail("Choose where to save it.")
			return
		}
		write := func() {
			f.work(func() error {
				if dir {
					return svops.WriteExtensionDir(path)
				}
				return svops.WriteExtension(path, true)
			}, func() {
				m.say("Saved the extension to %s.", path)
				// The CLI's lines, but for the command they end with: here
				// it is a button.
				var lines []string
				for _, l := range svops.ExtensionWrittenLines(path, dir) {
					if !strings.Contains(l, "secretvault browser install") {
						lines = append(lines, l)
					}
				}
				m.showText("Add the extension to your browser",
					"The browser also needs your permission to start secretvault: Set up… on this tab gives it.", strings.Join(lines, "\n"))
			})
		}
		if dir {
			write()
			return
		}
		m.replacing(path, write)
	})
}

// undoLines says what undoing one manifest would do, as the CLI's
// uninstall --dry-run does.
func undoLines(u svops.Uninstalled) []string {
	label := u.Label()
	if u.Changed {
		return []string{label + ": " + u.Manifest + " changed since secretvault set it up: left as it is"}
	}
	rec := u.InstalledHost
	var lines []string
	switch {
	case rec.RegKey != "":
		lines = append(lines, fmt.Sprintf("%s: remove HKEY_CURRENT_USER\\%s and %s", label, rec.RegKey, rec.Manifest))
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
	case u.RegKey != "":
		return []string{fmt.Sprintf("%s: removed HKEY_CURRENT_USER\\%s", label, u.RegKey)}
	}
	return []string{fmt.Sprintf("%s: removed %s", label, u.Manifest)}
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
			agent = "on"
		}
		homes := "none yet"
		if len(st.GnuPGHomes) > 0 {
			homes = strings.Join(st.GnuPGHomes, ", ")
		}
		col := widgets.NewColumn(m.paragraph("gpg can sign and decrypt with the OpenPGP keys in vault "+p.vault+". The private keys stay inside "+
			"secretvault, and you are asked the first time each program uses one."),
			m.facts([][2]string{{"secretvault's stand-in for gpg-agent", agent}, {"GnuPG folders using it", homes}})).WithGap(gap).WithPad(gap)
		if here != nil {
			col.Add(m.paragraph(sentence(here.Error())))
			return scrolled(col)
		}
		setup := widgets.NewButton("Let gpg use the vault's keys…", func() { m.gnupgSetup(p) })
		stop := widgets.NewButton("Stop gpg using them…", func() { m.gnupgRemove(p) })
		pn.focus = setup
		col.Add(buttons(setup, stop))
		return scrolled(col)
	})
}

// gnupgForm asks which GnuPG home, and which gpg.
func (m *Manager) gnupgForm(title string, withGPG bool) (*formDialog, *pathField, *pathField) {
	f := m.newForm(title)
	def, _ := svops.GnuPGHome("")
	f.intro("Which GnuPG folder? The one suggested is secretvault's own, which leaves your usual gpg setup alone. " +
		"Choosing your own (usually ~/.gnupg) makes gpg use the vault's keys instead of its own agent.")
	home := f.path("GnuPG folder", PickFolder, "")
	home.field.SetText(def)
	var gpg *pathField
	if withGPG {
		gpg = f.path("gpg program", PickOpen, "")
		gpg.field.Placeholder = "Leave empty for the gpg on your PATH"
	}
	return f, home, gpg
}

// gnupgSetup points a GnuPG home at the daemon (the CLI's pgp gpg-setup):
// the plan first, in plain words (svops.GnuPGSetupPlain), then carried
// out.
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
			m.showPlan(svops.GnuPGSetupPlain(plan, vault), func() {
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
					report = append(report, svops.GnuPGNotes(plan.Skipped, plan.Unreachable, home)...)
					intro := "gpg now signs and decrypts with the keys in vault " + vault + ". "
					if plan.OwnHome {
						intro += "Use gpg as you always do."
					} else {
						intro += "To use them, set GNUPGHOME to this folder: export GNUPGHOME=" + home
					}
					m.showDone("gpg uses the vault's keys", intro, report)
					m.refreshDesktop(p, tabGnuPG)
				})
			}, plan.Discard)
		})
	})
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
				m.say("gpg does not use the vault's keys in %s: there is nothing to stop.", home)
				return
			}
			m.showPlan(svops.GnuPGRemovePlain(home), func() {
				m.call(func(ctx context.Context, c *secretvault.Client) error {
					return svops.RemoveGnuPG(ctx, c, home)
				}, func(err error) {
					if err != nil {
						m.fail(err)
						return
					}
					m.say("gpg no longer uses the vault's keys in %s; the public keys stay in its keyring.", home)
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
	var plan *svops.HelpersPlan
	var planErr error
	pn.gen++
	gen := pn.gen
	m.work(func() error {
		links = svops.HelperLinks(cli)
		if cli != "" {
			plan, planErr = svops.PlanHelpers(cli)
		}
		return nil
	}, func(error) {
		if !m.up(p.tabbedPage) || gen != pn.gen {
			return
		}
		col := widgets.NewColumn(m.paragraph("git and docker can keep their logins in your vault, and age can decrypt with the vault's keys. " +
			"Set up… lets them, and you are asked before any of them reads a password; Undo… removes only what secretvault added.")).WithGap(gap).WithPad(gap)
		if cli == "" {
			col.Add(toned(m.describe(svops.ErrNoCLI), widgets.ToneWarning))
		}
		if planErr != nil {
			col.Add(toned(m.describe(planErr), widgets.ToneWarning))
		}
		if plan != nil {
			// What the plan sees, in the words the CLI's helpers status
			// uses: git's credential helpers and docker's credsStore.
			rows := plan.StatusRows()
			col.Add(m.facts(rows[len(plan.Links):]))
		}
		setup := widgets.NewButton("Set up…", func() { m.helpersPlan(p, true) })
		undo := widgets.NewButton("Undo…", func() { m.helpersPlan(p, false) })
		setup.SetEnabled(plan != nil)
		undo.SetEnabled(plan != nil && plan.Undoable())
		col.Add(buttons(setup, undo))
		for _, h := range links {
			col.Add(section(m, h.Name))
			link := "not set up"
			switch {
			case h.Ours:
				link = h.Path
			case h.Exists:
				link = h.Path + ": something else, not secretvault's"
			}
			found := "not found: the program that runs it will not find it on your PATH"
			if h.OnPath != "" {
				found = h.OnPath
			}
			use := helperUse[h.Name]
			col.Add(m.facts([][2]string{{"Installed as", link}, {"Programs find it at", found}, {"Used through", use}}))
			if strings.HasPrefix(use, "git ") {
				col.Add(buttons(widgets.NewButton("Copy git's setting", func() { m.copyValue([]byte(use), "git's setting", "") }),
					widgets.NewButton("Show git's logins", func() { m.showFolder("git/") })))
			}
			if strings.HasPrefix(h.Name, "docker") {
				col.Add(buttons(widgets.NewButton("Show the registries' logins", func() { m.showFolder("docker/") })))
			}
		}
		refresh := widgets.NewButton("Refresh", pn.refresh)
		pn.focus = setup
		if plan == nil {
			pn.focus = refresh
		}
		col.Add(buttons(refresh))
		pn.box.Set(scrolled(col))
	})
}

// helpersPlan sets the helpers up, or undoes that (the CLI's helpers
// setup and undo): the plan in plain words (svops.HelpersSetupPlain,
// HelpersUndoPlain), its lines under Show details, and carried out only
// when the person says so; the pane is filled again after.
func (m *Manager) helpersPlan(p *desktopPage, setup bool) {
	cli := m.cliProgram()
	if cli == "" {
		m.fail(svops.ErrNoCLI)
		return
	}
	var plan *svops.HelpersPlan
	m.work(func() (err error) {
		plan, err = svops.PlanHelpers(cli)
		return err
	}, func(err error) {
		if err != nil {
			m.fail(err)
			return
		}
		pl, do := svops.HelpersSetupPlain(plan), plan.Apply
		doneTitle, doneIntro := "git, docker and age can use secretvault", "You are asked before any of them reads a password. Undo… on this tab removes what was added."
		if !setup {
			if !plan.Undoable() {
				m.say("git, docker and age are not set up to use secretvault: there is nothing to undo.")
				m.refreshDesktop(p, tabHelpers)
				return
			}
			pl, do = svops.HelpersUndoPlain(plan), plan.Undo
			doneTitle, doneIntro = "git, docker and age no longer use secretvault", "What secretvault added is removed; everything else is as it was."
		}
		m.showPlan(pl, func() {
			var done []string
			m.work(func() (err error) {
				done, err = do()
				return err
			}, func(err error) {
				if err != nil {
					doneTitle, doneIntro = "It did not finish", m.describe(err)+" The details say what was done so far."
				}
				m.showDone(doneTitle, doneIntro, done)
				m.refreshDesktop(p, tabHelpers)
			})
		}, nil)
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
			pn.box.Set(m.paneColumn("The host daemon hands secrets to the services on a server, by rules you set, without asking anyone. It is set up "+
				"by root, on the server: run this program as root there to manage it. "+m.describe(err), nil, initBtn, widgets.NewButton("Try again", pn.refresh)))
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
	title, action, intro := "Stop a service reading secrets", "Deny",
		"The service will no longer get the secrets named from the host daemon. The secrets themselves do not change."
	if allow {
		title, action, intro = "Let a service read secrets", "Allow",
			"The service gets the secrets you name from the host daemon, without anyone being asked. Deny… takes it back."
	}
	f := m.newForm(title)
	f.intro(intro)
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
	f.show(action, func() {
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
	pl := svops.HostInitPlain()
	f := m.newForm(pl.Title)
	f.intro(pl.Summary)
	suite := f.choice("Cipher suite", []string{"modern: X25519", "nist: P-256 (FIPS 140-3)"}, 0)
	seal := f.check("Seal it to this machine (systemd-creds, with the TPM2), never writing it in the clear", false)
	pcrs := f.text("TPM2 PCRs", "", "Optional, when sealed: also bind it to these, such as 7")
	out := f.path("Identity file", PickSave, "")
	out.field.SetText(svrpc.HostIdentityFile())
	credstore := f.path("Sealed identity file", PickSave, "")
	credstore.field.SetText(svrpc.HostCredstore)
	f.show(pl.Action, func() {
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
