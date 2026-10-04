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
				p.row(nil, "keyring", "not known: secretvault cannot reach your desktop session")
			case holder.Held:
				p.row(nil, "keyring", fmt.Sprintf("%s (%s, process %d)", svops.KeyringName(holder.Owner.Exe), holder.Owner.Exe, holder.Owner.PID))
			default:
				p.row(nil, "keyring", "nothing: no app can keep passwords there now")
			}
			if stErr == nil {
				p.row(nil, "secretvault", st.SecretService)
			}
			if s, err := svops.LoadTakeover(); err == nil {
				p.row(nil, "takeover", "secretvault took over on "+s.When.Local().Format("2006-01-02 15:04")+", from "+svops.KeyringName(s.Previous)+" (r gives it back)")
			}
			p.done()
		})
	}
	head := "Apps such as your browser, mail and Wi-Fi settings keep their passwords in the system keyring. secretvault can copy them into your vault, " +
		"or take the keyring's place so that an app must ask you before it reads one. Giving the keyring back undoes every change."
	if err := svops.KeyringHere(); err != nil {
		head = "[yellow]" + tview.Escape(sentence(err.Error())) + "[-]"
	}
	p.setHead(head)
	p.act('i', "Copy its passwords into the vault…", func() { u.keyringImport(nil) })
	p.act('t', "Take over the keyring…", func() { u.keyringTakeover(p.refresh) })
	p.act('r', "Give the keyring back…", func() { u.keyringRestore(p.refresh) })
	p.show()
}

// readKeyring reads the keyring's secrets off the interface's goroutine
// (it may ask to be unlocked), then hands them to then, which wipes them.
func (u *UI) readKeyring(then func(string, []svsecret.Secret, []string)) {
	var secrets []svsecret.Secret
	var warnings []string
	var holder string
	u.call(func(context.Context, *secretvault.Client) (err error) {
		ctx, cancel := context.WithTimeout(u.ctx, 10*time.Minute)
		defer cancel()
		secrets, warnings, err = svops.ReadKeyring(ctx, func(o svsecret.Owner) {
			holder = o.Exe
			u.post(func() { u.say("Reading from %s; it may ask you to unlock it", svops.KeyringName(o.Exe)) })
		})
		return err
	}, func(err error) {
		if err != nil {
			u.fail(err)
			return
		}
		then(holder, secrets, warnings)
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
	u.askTo("Copy the keyring's passwords into "+vault, "Put them in the folder: ", "imported", "Next", func(prefix string) {
		u.readKeyring(func(holder string, secrets []svsecret.Secret, warnings []string) {
			names, _, _ := svops.ImportKeyring(u.ctx, nil, vault, prefix, secrets)
			u.showPlan(svops.KeyringImportPlain(holder, vault, prefix, names, warnings), func() {
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
					u.say("Copied %d passwords into vault %s", n, vault)
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
		u.showPlan(svops.TakeoverPlain(plan, exe, importFirst, vault), func() {
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
				var done []string
				for _, f := range written {
					done = append(done, "Wrote "+f)
				}
				for _, f := range failed {
					done = append(done, fmt.Sprintf("warning: restarting %s: %v %s", f.Unit, f.Err, strings.TrimSpace(string(f.Output))))
				}
				for _, n := range notes {
					done = append(done, "Still to do by hand: "+n)
				}
				title, summary := "secretvault is your system keyring", "Apps now ask secretvault for their passwords, and it asks you before they read one. r on this panel gives the keyring back."
				if len(notes) > 0 {
					summary += " One step is left for you to do: the details say which."
				}
				if err != nil {
					u.fail(err)
					title, summary = "The takeover did not finish", sentence(u.describe(err))+" r on this panel undoes what was done; the details say what that is."
				} else {
					u.say("secretvault is now your system keyring")
				}
				if then != nil {
					then()
				}
				u.showDone(title, summary, done)
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
		u.say("secretvault has not taken over the keyring: there is nothing to give back.")
		return
	}
	if err != nil {
		u.fail(err)
		return
	}
	u.showPlan(svops.RestorePlain(s), func() {
		var removed []string
		var serveErr error
		u.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			serveErr = c.ServeKeyring(ctx, false)
			removed, _, err = svops.UndoTakeover(s)
			return err
		}, func(err error) {
			var done []string
			for _, f := range removed {
				done = append(done, "Removed "+f)
			}
			if serveErr != nil {
				done = append(done, "warning: "+u.describe(serveErr))
			}
			title, summary := svops.RestoredText(s.Previous)
			if err != nil {
				u.fail(err)
				title, summary = "Giving the keyring back did not finish", sentence(err.Error())
			} else {
				u.say("%s", strings.TrimSuffix(summary, "."))
			}
			if then != nil {
				then()
			}
			u.showDone(title, summary, done)
		})
	})
}

// browserRow is a browser's row of the browsers panel.
type browserRow struct{ svops.BrowserState }

// showBrowsers is the browsers panel: which program each browser starts
// for secretvault's own extension ('secretvault browser status');
// installing and uninstalling its host, writing the extension out.
func (u *UI) showBrowsers() {
	p := u.newPanel("Browsers", "BROWSER", "CAN USE SECRETVAULT", "")
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
			head := "The secretvault extension fills and saves logins in your browser, asking you first. Two steps: i gives a browser permission to start secretvault " +
				"(one small settings file; u takes it back), and e saves the extension for you to add to the browser."
			if cli == "" {
				head = "[yellow]" + tview.Escape(sentence(svops.ErrNoCLI.Error())) + "[-] Setting the browsers up needs it; e still saves the extension."
			} else if state != nil {
				head += "\n" + svops.BrowserSetUpWhen(state)
			}
			if statusErr != nil {
				head += "\n[red]" + tview.Escape(sentence(statusErr.Error())) + "[-]"
			}
			p.setHead(head)
			p.clear()
			for _, h := range svops.NativeHosts {
				p.heading(h.Title)
				for _, b := range svops.StatesOf(browsers, h) {
					p.row(browserRow{b}, b.Spot.Title, svops.BrowserCanUse(b, host))
				}
			}
			p.done()
		})
	}
	p.act('i', "Let a browser use secretvault…", func() { u.browserInstall(svops.ExtensionHost, p.refresh) })
	p.act('u', "Take the permission back…", func() { u.browserUninstall(&svops.ExtensionHost, p.refresh) })
	p.act('e', "Save the extension…", u.browserExtension)
	p.show()
}

// browserInstall is 'secretvault browser install': which browsers, then
// the plan in plain words (svops.BrowserInstallPlain, naming the CLI),
// its manifests behind Show details, then each applied.
func (u *UI) browserInstall(native svops.NativeHost, then func()) {
	cli := u.cliProgram()
	if cli == "" {
		u.fail(svops.ErrNoCLI)
		return
	}
	options := []string{"Every browser on this computer"}
	for _, n := range svops.BrowserNames {
		options = append(options, svops.BrowserTitle(n))
	}
	u.choose("Which browser should the extension work in?", options, func(i int) {
		var names []string
		if i > 0 {
			names = []string{svops.BrowserNames[i-1]}
		}
		plan, err := svops.PlanBrowserInstall(native, names, cli)
		if err != nil {
			u.fail(err)
			return
		}
		u.showPlan(svops.BrowserInstallPlain(plan), func() {
			var out, who []string
			u.call(func(context.Context, *secretvault.Client) error {
				for _, hp := range plan.Todo() {
					_, err := plan.Apply(hp)
					if err != nil {
						return fmt.Errorf("%s: %w (u on this panel takes back what was done)", hp.Label(), err)
					}
					for _, b := range hp.Browsers {
						who = append(who, svops.BrowserTitle(b))
					}
					out = append(out, fmt.Sprintf("%s: wrote %s", hp.Label(), hp.Spot.Manifest))
				}
				return nil
			}, func(err error) {
				title := svops.AndList(who) + " can now use secretvault"
				summary := "Restart the browser, then add the secretvault extension to it: e on this panel saves it, and says how. u takes the permission back."
				if err != nil {
					u.fail(err)
					title, summary = "Setting up the browsers did not finish", sentence(err.Error())
				} else {
					u.say("%s can now use secretvault", svops.AndList(who))
				}
				if then != nil {
					then()
				}
				u.showDone(title, summary, out)
			})
		})
	})
}

// browserUninstall is 'secretvault browser uninstall': its dry run, in
// plain words, then the undoing.
func (u *UI) browserUninstall(only *svops.NativeHost, then func()) {
	planned, err := svops.UninstallBrowsers(only, true)
	if errors.Is(err, svops.ErrNoBrowserInstall) {
		u.say("No browser is set up to use secretvault: there is nothing to undo.")
		return
	}
	if err != nil {
		u.fail(err)
		return
	}
	u.showPlan(svops.BrowserUninstallPlain(planned), func() {
		var done []svops.Uninstalled
		u.call(func(context.Context, *secretvault.Client) (err error) {
			done, err = svops.UninstallBrowsers(only, false)
			return err
		}, func(err error) {
			var out []string
			for _, x := range done {
				out = append(out, svops.UninstalledLines(x)...)
			}
			title, summary := "Browser access removed", "The browsers no longer start secretvault, and their files are as they were before. Your passwords stay in the vault."
			if err != nil {
				u.fail(err)
				title, summary = "Removing browser access did not finish", sentence(err.Error())
			} else {
				u.say("The browsers no longer start secretvault")
			}
			if then != nil {
				then()
			}
			u.showDone(title, summary, out)
		})
	})
}

// browserExtension is 'secretvault browser extension': the extension
// written out for a family of browsers (--target): a zip for Firefox, a
// folder for Chromium's Load unpacked, or a zip for the Chrome Web Store;
// then how to load it.
func (u *UI) browserExtension() {
	var labels []string
	for _, c := range svops.ExtensionChoices {
		labels = append(labels, c.Label)
	}
	u.choose("Save the extension, to add to your browser", labels, func(i int) {
		c := svops.ExtensionChoices[i]
		value := c.DefaultName()
		if wd, err := os.Getwd(); err == nil {
			value = filepath.Join(wd, value)
		}
		u.askTo("Save the extension", "Path: ", value, "Save the extension", func(path string) {
			if c.Dir {
				u.extensionWritten(path, c, svops.WriteExtensionDir(path, c.Target))
				return
			}
			err := svops.WriteExtension(path, c.Target, false)
			if errors.Is(err, svops.ErrExtensionExists) {
				u.confirm("Replace it?", tview.Escape(path)+" is there already. Replace it?", "Replace", func() {
					u.extensionWritten(path, c, svops.WriteExtension(path, c.Target, true))
				})
				return
			}
			u.extensionWritten(path, c, err)
		})
	})
}

// extensionWritten says how writing the extension to path went, and how
// to load it.
func (u *UI) extensionWritten(path string, c svops.ExtensionChoice, err error) {
	if err != nil {
		u.fail(err)
		return
	}
	u.say("Saved the extension to %s", path)
	u.showText("Add the extension to your browser", "The browser also needs your permission to start secretvault: i on this panel gives it.\n\n"+
		lines(svops.ExtensionAddedLines(path, c.Target, c.Dir)))
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
	f := u.newForm("Let gpg use the vault's keys", "gpg can sign and decrypt with the OpenPGP keys in vault "+vault+"; the private keys stay inside secretvault. "+
		"Which GnuPG folder? Empty means secretvault's own, which leaves your usual gpg setup alone; your own (usually ~/.gnupg) stops gpg using its own agent.")
	home := f.path("GnuPG folder", "", "empty: secretvault's own")
	gpg := f.path("gpg program", "", "empty: the gpg on your PATH")
	remove := f.check("Stop gpg using the vault's keys in this folder instead", false)
	f.show("Next", func() string {
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
			u.showPlan(svops.GnuPGSetupPlain(plan, vault), func() {
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
					var done []string
					if note != "" {
						done = append(done, "warning: "+note)
					}
					for _, k := range plan.Keys {
						done = append(done, svops.GroupFingerprint(k.Fingerprint)+"  "+svops.FirstUserID(k))
					}
					done = append(done, "Its agent is secretvaultd: "+plan.Socket+" -> "+res.Agent)
					if res.SSHAgent != "" {
						done = append(done, "and so is its SSH agent: "+plan.SSHSocket+" -> "+res.SSHAgent)
					}
					done = append(done, svops.GnuPGNotes(plan.Skipped, plan.Unreachable, h)...)
					summary := "gpg now signs and decrypts with the keys in vault " + vault + ", and you are asked the first time each program uses one. "
					if plan.OwnHome {
						summary += "Use gpg as you always do."
					} else {
						summary += "To use them, run gpg with this folder: the first line under Details is the command to type in your terminal first."
						done = append([]string{"export GNUPGHOME=" + h}, done...)
					}
					u.say("gpg uses the keys in vault %s", vault)
					u.showDone("gpg uses the vault's keys", summary, done)
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
			u.say("gpg does not use the vault's keys in %s: there is nothing to stop", home)
			return
		}
		u.showPlan(svops.GnuPGRemovePlain(home), func() {
			u.call(func(ctx context.Context, c *secretvault.Client) error {
				return svops.RemoveGnuPG(ctx, c, home)
			}, func(err error) {
				if err != nil {
					u.fail(err)
					return
				}
				u.say("gpg no longer uses the vault's keys in %s; the public keys stay", home)
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
	p.setHead("git and docker can keep their logins in your vault (under git/ and docker/), and age and SOPS can decrypt with the vault's age keys. " +
		"s lets them, and you are asked before any of them reads a password; u removes only what secretvault added.")
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
	p.act('s', "Let git, docker and age use secretvault…", func() { u.helpersPlan(true, p.refresh) })
	p.act('u', "Remove the setup…", func() { u.helpersPlan(false, p.refresh) })
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
	rows := plan.StatusRows()
	for i, l := range plan.Links {
		p.row(helperRef{l}, rows[i][0], rows[i][1])
	}
	for _, r := range plan.PlainRows() {
		p.row(nil, r[0], r[1])
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
		pl, do := svops.HelpersSetupPlain(plan), plan.Apply
		doneTitle, doneSummary := "git, docker and age can use secretvault", "You are asked before any of them reads a password. u on this panel removes what was added."
		if !setup {
			if !plan.Undoable() {
				u.say("git, docker and age are not set up to use secretvault: there is nothing to undo")
				return
			}
			pl, do = svops.HelpersUndoPlain(plan), plan.Undo
			doneTitle, doneSummary = "git, docker and age no longer use secretvault", "What secretvault added is removed; everything else is as it was."
		}
		u.showPlan(pl, func() {
			var done []string
			u.call(func(context.Context, *secretvault.Client) (err error) {
				done, err = do()
				return err
			}, func(err error) {
				if err != nil {
					u.fail(err)
					doneTitle, doneSummary = "It did not finish", sentence(err.Error())+" The details say what was done so far."
				} else {
					u.say("%s", doneTitle)
				}
				u.showDone(doneTitle, doneSummary, done)
				if then != nil {
					then()
				}
			})
		})
	})
}
