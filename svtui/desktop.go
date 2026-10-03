package svtui

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/rivo/tview"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svsecret"
)

// The desktop: the system keyring (Y: 'secretvault keyring'), the
// browsers (B: 'secretvault browser'), gpg pointed at the daemon
// ('secretvault pgp gpg-setup'), and the helpers git, docker and age run.
// Every change to the desktop is shown as a plan first, in the words the
// CLI's --dry-run uses (svops), and made only when the person says so.
// Paths written into other programs' settings name the secretvault CLI
// (svops.CLIProgram), never this program.

// cliProgram is the secretvault CLI to name to other programs.
func (u *UI) cliProgram() string {
	if u.opts.CLI != "" {
		return u.opts.CLI
	}
	return svops.CLIProgram()
}

// daemonProgram is secretvaultd, for the keyring takeover's service files.
func (u *UI) daemonProgram() string {
	if u.opts.Daemon != "" {
		return u.opts.Daemon
	}
	return svops.SiblingProgram("secretvaultd")
}

// lines turns lines into escaped text.
func lines(ls []string) string { return tview.Escape(strings.Join(ls, "\n")) }

// showKeyring is the keyring panel: 'secretvault keyring status', with
// importing its secrets, taking it over and giving it back.
func (u *UI) showKeyring() {
	p := u.newPanel("System keyring", "", "")
	p.reload = func() {
		var holder svops.KeyringHolder
		var st svrpc.Status
		var stErr error
		u.call(func(ctx context.Context, c *secretvault.Client) error {
			holder = svops.KeyringHolderNow(ctx)
			st, stErr = c.Status(ctx)
			return nil
		}, func(error) {
			p.clear()
			switch {
			case holder.BusErr != nil:
				p.row(nil, "keyring", fmt.Sprintf("no session bus (%v)", holder.BusErr))
			case holder.Held:
				p.row(nil, "keyring", fmt.Sprintf("%s (process %d)", svops.DescribeExe(holder.Owner.Exe), holder.Owner.PID))
			default:
				p.row(nil, "keyring", "none (nothing holds org.freedesktop.secrets)")
			}
			if stErr == nil {
				p.row(nil, "secretvault", st.SecretService)
			}
			if s, err := svops.LoadTakeover(); err == nil {
				p.row(nil, "takeover", "done "+s.When.Local().Format("2006-01-02 15:04")+" (r gives it back)")
			}
			p.done()
		})
	}
	head := "The desktop's keyring (the Secret Service) is where programs keep their passwords. secretvault can import its secrets, and take its place: then programs ask secretvault, and you are asked before they read."
	if err := svops.KeyringHere(); err != nil {
		head = "[yellow]" + tview.Escape(sentence(err.Error())) + "[-]"
	}
	p.setHead(head)
	p.act('i', "Import its secrets…", func() { u.keyringImport(nil) })
	p.act('t', "Take it over…", func() { u.keyringTakeover(p.refresh) })
	p.act('r', "Give it back…", func() { u.keyringRestore(p.refresh) })
	p.show()
}

// readKeyring reads the keyring's secrets off the interface's goroutine
// (it may ask to be unlocked), then hands them to then, which wipes them.
func (u *UI) readKeyring(then func([]svsecret.Secret, []string)) {
	var secrets []svsecret.Secret
	var warnings []string
	u.call(func(context.Context, *secretvault.Client) (err error) {
		ctx, cancel := context.WithTimeout(u.ctx, 10*time.Minute)
		defer cancel()
		secrets, warnings, err = svops.ReadKeyring(ctx, func(o svsecret.Owner) {
			u.post(func() { u.say("Reading from %s; it may ask you to unlock it", svops.DescribeExe(o.Exe)) })
		})
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		then(secrets, warnings)
	})
}

func wipeSecrets(secrets []svsecret.Secret) {
	for i := range secrets {
		secrets[i].Wipe()
	}
}

// keyringImport is 'secretvault keyring import': the names first (the dry
// run), then the secrets stored.
func (u *UI) keyringImport(then func()) {
	if err := svops.KeyringHere(); err != nil {
		u.fail(err)
		return
	}
	if !u.needVault() {
		return
	}
	vault := u.vault
	u.ask("Import the keyring's secrets", "Under the folder:", "imported", func(prefix string) {
		u.readKeyring(func(secrets []svsecret.Secret, warnings []string) {
			names, _, _ := svops.ImportKeyring(u.ctx, nil, vault, prefix, secrets)
			body := fmt.Sprintf("[::b]%d secrets to import into %s:[::-]\n%s", len(names), tview.Escape(vault), lines(names))
			for _, w := range warnings {
				body += "\n[yellow]warning:[-] " + tview.Escape(w)
			}
			u.showPlan("Import the keyring", body, fmt.Sprintf("Import %d", len(names)), func() {
				var n int
				u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
					defer wipeSecrets(secrets)
					_, n, err = svops.ImportKeyring(ctx, c, vault, prefix, secrets)
					return err
				}, func(err error) {
					if err != nil {
						u.fail(err)
						return
					}
					u.say("Imported %d secrets", n)
					if vault == u.vault {
						u.loadItems()
					}
					if then != nil {
						then()
					}
				})
			}, func() { wipeSecrets(secrets) })
		})
	})
}

// keyringTakeover is 'secretvault keyring takeover': the plan
// (svops.PlanTakeover), then, if the person says so, the keyring's
// secrets imported, the files written (svops.ApplyTakeover), the daemon's
// Secret Service turned on, and the units restarted.
func (u *UI) keyringTakeover(then func()) {
	if err := svops.KeyringHere(); err != nil {
		u.fail(err)
		return
	}
	if s, err := svops.LoadTakeover(); err == nil {
		u.say("The takeover was already done on %s", s.When.Local().Format("2006-01-02"))
		return
	}
	daemon := u.daemonProgram()
	if daemon == "" {
		u.say("There is no secretvaultd beside this program, for the desktop to start.")
		return
	}
	vault := u.vault
	var exe string
	var plan *svops.TakeoverPlan
	u.call(func(ctx context.Context, _ *secretvault.Client) (err error) {
		if h := svops.KeyringHolderNow(ctx); h.Held {
			exe = h.Owner.Exe
		}
		plan, err = svops.PlanTakeover(exe, daemon)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		importFirst := exe != "" && vault != ""
		body := lines(svops.TakeoverLines(plan, exe, importFirst))
		if importFirst {
			body += "\n\nIts secrets go into " + tview.Escape(vault) + ", under imported/."
		}
		u.showPlan("Take the keyring over", body, "Take it over", func() {
			var written, notes []string
			var failed []svops.RestartFailure
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				if importFirst {
					rctx, cancel := context.WithTimeout(u.ctx, 10*time.Minute)
					secrets, _, err := svops.ReadKeyring(rctx, nil)
					if err == nil {
						_, _, err = svops.ImportKeyring(rctx, c, vault, "imported", secrets)
					}
					wipeSecrets(secrets)
					cancel()
					if err != nil {
						return fmt.Errorf("importing first: %w", err)
					}
				}
				var err error
				if written, err = svops.ApplyTakeover(plan, exe); err != nil {
					return err
				}
				if err := c.ServeKeyring(ctx, true); err != nil {
					return err
				}
				failed = svops.RestartUnits(plan.Restart)
				notes = plan.Notes
				return nil
			}, func(err error) {
				var b strings.Builder
				for _, f := range written {
					fmt.Fprintf(&b, "Wrote %s\n", tview.Escape(f))
				}
				for _, f := range failed {
					fmt.Fprintf(&b, "[yellow]warning:[-] restarting %s: %v %s\n", tview.Escape(f.Unit), f.Err, tview.Escape(string(f.Output)))
				}
				for _, n := range notes {
					fmt.Fprintf(&b, "Still to do by hand: %s\n", tview.Escape(n))
				}
				if err != nil {
					fmt.Fprintf(&b, "\n[red]%s[-]", tview.Escape(sentence(u.describe(err))))
					u.fail(err)
				} else {
					b.WriteString("\nsecretvault is now the keyring. Give it back from this panel (r).")
					u.say("secretvault is now the keyring")
				}
				if then != nil {
					then()
				}
				u.showText("Keyring takeover", b.String())
			})
		})
	})
}

// keyringRestore is 'secretvault keyring restore'.
func (u *UI) keyringRestore(then func()) {
	if err := svops.KeyringHere(); err != nil {
		u.fail(err)
		return
	}
	s, err := svops.LoadTakeover()
	if errors.Is(err, fs.ErrNotExist) {
		u.say("There is no takeover to undo.")
		return
	}
	if err != nil {
		u.fail(err)
		return
	}
	u.showPlan("Give the keyring back", lines(svops.RestoreLines(s)), "Give it back", func() {
		var removed []string
		var serveErr error
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			serveErr = c.ServeKeyring(ctx, false)
			removed, _, err = svops.UndoTakeover(s)
			return err
		}, func(err error) {
			var b strings.Builder
			for _, f := range removed {
				fmt.Fprintf(&b, "Removed %s\n", tview.Escape(f))
			}
			if serveErr != nil {
				fmt.Fprintf(&b, "[yellow]warning:[-] %s\n", tview.Escape(u.describe(serveErr)))
			}
			if err != nil {
				u.fail(err)
				fmt.Fprintf(&b, "\n[red]%s[-]", tview.Escape(sentence(err.Error())))
			} else {
				fmt.Fprintf(&b, "\nRestored: %s is the keyring again.", tview.Escape(svops.DescribeExe(s.Previous)))
				u.say("Restored: %s is the keyring again", svops.DescribeExe(s.Previous))
			}
			if then != nil {
				then()
			}
			u.showText("Keyring restored", b.String())
		})
	})
}

// browserRow is a browser's row of the browsers panel.
type browserRow struct{ svops.BrowserState }

// showBrowsers is the browsers panel: which program each browser starts
// for secretvault's own extension ('secretvault browser status');
// installing and uninstalling its host, writing the extension out.
func (u *UI) showBrowsers() {
	p := u.newPanel("Browsers", "BROWSER", "STARTS", "")
	p.reload = func() {
		var state *svops.BrowserInstall
		var host string
		var browsers []svops.BrowserState
		var statusErr error
		cli := u.cliProgram()
		u.call(func(context.Context, *secretvault.Client) error {
			state, host, browsers, statusErr = svops.BrowserStatus(cli)
			return nil
		}, func(error) {
			head := "secretvault's own extension fills logins: i sets its host up in the browsers, e writes the extension out to load, u undoes the setup."
			if cli == "" {
				head = "[yellow]" + tview.Escape(sentence(svops.ErrNoCLI.Error())) + "[-] Setting the browsers up needs it; e still writes the extension out."
			} else if state != nil {
				head += fmt.Sprintf("\nSet up %s, starting %s.", state.When.Local().Format("2006-01-02 15:04"), tview.Escape(state.Host))
			}
			if statusErr != nil {
				head += "\n[red]" + tview.Escape(sentence(statusErr.Error())) + "[-]"
			}
			p.setHead(head)
			p.clear()
			for _, h := range svops.NativeHosts {
				p.heading(h.Title)
				for _, b := range svops.StatesOf(browsers, h) {
					line := svops.BrowserStateLine(b, host)
					p.row(browserRow{b}, b.Spot.Name, strings.TrimSpace(strings.TrimPrefix(line, b.Spot.Name)))
				}
			}
			p.done()
		})
	}
	p.act('i', "Set up…", func() { u.browserInstall(svops.ExtensionHost, p.refresh) })
	p.act('u', "Undo…", func() { u.browserUninstall(&svops.ExtensionHost, p.refresh) })
	p.act('e', "Write the extension out…", u.browserExtension)
	p.show()
}

// browserInstall is 'secretvault browser install': which browsers, the
// plan (svops.PlanBrowserInstall, naming the CLI), then each applied.
func (u *UI) browserInstall(native svops.NativeHost, then func()) {
	cli := u.cliProgram()
	if cli == "" {
		u.fail(svops.ErrNoCLI)
		return
	}
	options := append([]string{"every browser used here"}, svops.BrowserNames...)
	u.choose("Set up "+native.Title+" for", options, func(i int) {
		var names []string
		if i > 0 {
			names = []string{svops.BrowserNames[i-1]}
		}
		plan, err := svops.PlanBrowserInstall(native, names, cli)
		if err != nil {
			u.fail(err)
			return
		}
		var b strings.Builder
		fmt.Fprintf(&b, "The browsers would start %s for %s:\n", tview.Escape(plan.Host), tview.Escape(native.Title))
		todo := 0
		for _, hp := range plan.Hosts {
			if hp.Skip != "" {
				fmt.Fprintf(&b, "  %s: nothing to do: %s\n", tview.Escape(hp.Label()), tview.Escape(ownWords(hp.Skip)))
				continue
			}
			todo++
			for _, l := range svops.HostPlanLines(hp, plan.Host) {
				b.WriteString("  " + tview.Escape(l) + "\n")
			}
		}
		if todo == 0 {
			u.showText("Set up the browsers", b.String()+"\nThere is nothing to do.")
			return
		}
		u.showPlan("Set up the browsers", b.String(), "Set up", func() {
			var out []string
			u.call(func(context.Context, *secretvault.Client) error {
				for _, hp := range plan.Hosts {
					if hp.Skip != "" {
						continue
					}
					if _, err := plan.Apply(hp); err != nil {
						return fmt.Errorf("%s: %w (Undo undoes what was done)", hp.Label(), err)
					}
					out = append(out, fmt.Sprintf("%s: wrote %s", hp.Label(), hp.Spot.Manifest))
				}
				return nil
			}, func(err error) {
				text := lines(out)
				switch {
				case err != nil:
					u.fail(err)
					text += "\n\n[red]" + tview.Escape(sentence(err.Error())) + "[-]"
				default:
					text += "\n\nRestart the browsers, then load the extension: e writes it out, and says how."
					u.say("Set the browsers up for the secretvault extension")
				}
				if then != nil {
					then()
				}
				u.showText("Set up", text)
			})
		})
	})
}

// browserUninstall is 'secretvault browser uninstall' for one host: its
// dry run, then the undoing.
func (u *UI) browserUninstall(only *svops.NativeHost, then func()) {
	planned, err := svops.UninstallBrowsers(only, true)
	if errors.Is(err, svops.ErrNoBrowserInstall) {
		u.say("%s is not set up in any browser", sentence(only.Title))
		return
	}
	if err != nil {
		u.fail(err)
		return
	}
	var ls []string
	for _, x := range planned {
		if x.Changed {
			ls = append(ls, svops.UninstalledLines(x)...)
		} else {
			ls = append(ls, svops.UndoLines(x.InstalledHost)...)
		}
	}
	u.showPlan("Undo "+only.Title, lines(ls), "Undo", func() {
		var done []svops.Uninstalled
		u.call(func(context.Context, *secretvault.Client) (err error) {
			done, err = svops.UninstallBrowsers(only, false)
			return err
		}, func(err error) {
			var out []string
			for _, x := range done {
				out = append(out, svops.UninstalledLines(x)...)
			}
			text := lines(out)
			if err != nil {
				u.fail(err)
				text += "\n\n[red]" + tview.Escape(sentence(err.Error())) + "[-]"
			} else {
				u.say("Undone: %s", only.Title)
			}
			if then != nil {
				then()
			}
			u.showText("Undone", text)
		})
	})
}

// browserExtension is 'secretvault browser extension': the extension
// written out, as a zip for Firefox (--out) or a folder for Chromium
// (--dir), then how to load it.
func (u *UI) browserExtension() {
	u.choose("Write the secretvault extension out", []string{"as a .zip, for Firefox", "as a folder, for Chromium's Load unpacked"}, func(i int) {
		dir := i == 1
		value := svops.ExtensionFileName()
		if dir {
			value = strings.TrimSuffix(value, ".zip")
		}
		if wd, err := os.Getwd(); err == nil {
			value = filepath.Join(wd, value)
		}
		u.ask("Write the extension out", "Path: ", value, func(path string) {
			if dir {
				u.extensionWritten(path, true, svops.WriteExtensionDir(path))
				return
			}
			err := svops.WriteExtension(path, false)
			if errors.Is(err, svops.ErrExtensionExists) {
				u.confirm("Replace it?", tview.Escape(path)+" is there already. Replace it?", "Replace", func() {
					u.extensionWritten(path, false, svops.WriteExtension(path, true))
				})
				return
			}
			u.extensionWritten(path, false, err)
		})
	})
}

// extensionWritten says how writing the extension to path went, and how
// to load it.
func (u *UI) extensionWritten(path string, dir bool, err error) {
	if err != nil {
		u.fail(err)
		return
	}
	u.say("Wrote the extension to %s", path)
	u.showText("The secretvault extension", tview.Escape(lines(svops.ExtensionWrittenLines(path, dir))))
}

// gpgSetup is 'secretvault pgp gpg-setup' (and with --remove): a GnuPG
// home, then the plan (svops.PlanGnuPGSetup, naming the CLI as gpg's
// agent-program), then carried out.
func (u *UI) gpgSetup(vault string) {
	if err := svops.GnuPGHere(); err != nil {
		u.fail(err)
		return
	}
	cli := u.cliProgram()
	f := u.newForm("Let gpg use the vault's keys", "gpg signs and decrypts with the OpenPGP keys of "+vault+" through secretvaultd, the keys never leaving it. Or stop that.")
	home := f.path("GnuPG home", "", "default: secretvault's data directory/gnupg")
	gpg := f.path("gpg program", "", "default: gpg on PATH")
	remove := f.check("Stop: point the home back at GnuPG's own agent", false)
	f.show("Plan it", func() string {
		h, err := svops.GnuPGHome(filePath(home))
		if err != nil {
			return err.Error()
		}
		if remove.IsChecked() {
			u.gpgRemove(h)
			return ""
		}
		if cli == "" {
			return svops.ErrNoCLI.Error()
		}
		gpgPath := filePath(gpg)
		var plan *svops.GnuPGPlan
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			plan, err = svops.PlanGnuPGSetup(ctx, c, svops.GnuPGOptions{Vault: vault, Home: h, GPG: gpgPath, CLI: cli})
			return err
		}, func(err error) {
			if err != nil {
				u.fail(err)
				return
			}
			body := lines(svops.GnuPGPlanLines(plan))
			if plan.OwnHome {
				body = "[yellow]" + tview.Escape(svops.GnuPGOwnHomeNote(h)) + "[-]\n\n" + body
			}
			u.showPlan("gpg setup", body, "Set it up", func() {
				var res svrpc.GnuPGLinkResult
				var note string
				u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
					res, note, err = svops.ApplyGnuPGSetup(ctx, c, plan)
					return err
				}, func(err error) {
					if err != nil {
						u.fail(err)
						return
					}
					var b strings.Builder
					if note != "" {
						fmt.Fprintf(&b, "[yellow]warning:[-] %s\n\n", tview.Escape(note))
					}
					fmt.Fprintf(&b, "The GnuPG home %s signs and decrypts with secretvault's keys:\n", tview.Escape(h))
					for _, k := range plan.Keys {
						fmt.Fprintf(&b, "  %s  %s\n", svops.GroupFingerprint(k.Fingerprint), tview.Escape(svops.FirstUserID(k)))
					}
					fmt.Fprintf(&b, "Its agent is secretvaultd: %s -> %s\n", tview.Escape(plan.Socket), tview.Escape(res.Agent))
					if res.SSHAgent != "" {
						fmt.Fprintf(&b, "and so is its SSH agent: %s -> %s\n", tview.Escape(plan.SSHSocket), tview.Escape(res.SSHAgent))
					}
					if ns := svops.GnuPGNotes(plan.Skipped, plan.Unreachable, h); len(ns) > 0 {
						b.WriteString(lines(ns) + "\n")
					}
					fmt.Fprintf(&b, "Use it with: export GNUPGHOME=%s\nEach program's first signature or decryption with a key is asked about.", tview.Escape(h))
					u.say("gpg in %s uses secretvault's keys", h)
					u.showText("gpg setup", b.String())
				})
			}, plan.Discard)
		})
		return ""
	})
}

// gpgRemove is 'secretvault pgp gpg-setup --remove'.
func (u *UI) gpgRemove(home string) {
	var pointed bool
	u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		pointed, err = svops.GnuPGPointed(ctx, c, home)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		if !pointed {
			u.say("%s is not pointed at secretvault", home)
			return
		}
		u.showPlan("Stop gpg using the vault's keys", tview.Escape(svops.GnuPGRemoveText(home)), "Stop", func() {
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				return svops.RemoveGnuPG(ctx, c, home)
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("The GnuPG home %s is no longer pointed at secretvault; the public keys stay", home)
			})
		})
	})
}

// helperRef is a row of the program helpers panel.
type helperRef struct{ svops.HelperLinkState }

// showHelpers is the program helpers panel: the links git, docker and
// age run beside the CLI, git's credential.helper and docker's
// credsStore (svops.PlanHelpers); setting them up and undoing that.
func (u *UI) showHelpers() {
	p := u.newPanel("Program helpers", "HELPER", "STATE")
	p.setHead("git and docker keep their logins as items under git/ and docker/, through these helpers; age and SOPS reach the vault's age identities through its plugin. They are links to the secretvault program.")
	p.reload = func() {
		var plan *svops.HelpersPlan
		cli := u.cliProgram()
		u.call(func(context.Context, *secretvault.Client) (err error) {
			plan, err = svops.PlanHelpers(cli)
			return err
		}, func(err error) {
			p.fillHelpers(plan, err)
		})
	}
	p.act('s', "Set them up…", func() { u.helpersPlan(true, p.refresh) })
	p.act('u', "Undo them…", func() { u.helpersPlan(false, p.refresh) })
	p.show()
}

// fillHelpers fills the program helpers panel.
func (p *panel) fillHelpers(plan *svops.HelpersPlan, err error) {
	p.clear()
	if err != nil {
		p.setHead("[red]" + tview.Escape(sentence(err.Error())) + "[-]")
		p.none("Not here.")
		p.done()
		return
	}
	for i, r := range plan.StatusRows() {
		var ref any
		if i < len(plan.Links) {
			ref = helperRef{plan.Links[i]}
		}
		p.row(ref, r[0], r[1])
	}
	p.done()
}

// helpersPlan shows what setting the helpers up (or undoing that) would
// do, and does it when the person says so.
func (u *UI) helpersPlan(setup bool, then func()) {
	var plan *svops.HelpersPlan
	cli := u.cliProgram()
	u.call(func(context.Context, *secretvault.Client) (err error) {
		plan, err = svops.PlanHelpers(cli)
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		title, intro, body, action, doneTitle, do := "Set the helpers up", svops.HelpersSetupIntro(plan.CLI), plan.SetupLines(), "Set up", "Helpers set up", plan.Apply
		if !setup {
			if !plan.Undoable() {
				u.say("%s", svops.HelpersNothingToUndo)
				return
			}
			title, intro, body, action, doneTitle, do = "Undo the helpers", svops.HelpersUndoIntro, plan.UndoLines(), "Undo", "Helpers undone", plan.Undo
		}
		body = append([]string{intro, ""}, body...)
		u.showPlan(title, lines(body), action, func() {
			var done []string
			u.call(func(context.Context, *secretvault.Client) (err error) {
				done, err = do()
				return err
			}, func(err error) {
				u.helpersDone(doneTitle, done, err)
				if then != nil {
					then()
				}
			})
		})
	})
}

func (u *UI) helpersDone(title string, done []string, err error) {
	text := lines(done)
	if err != nil {
		u.fail(err)
		text += "\n\n[red]" + tview.Escape(sentence(err.Error())) + "[-]"
	} else {
		u.say("%s", title)
	}
	u.showText(title, text)
}
