package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
)

// TestScreenshots renders the dialogs to PNG files, headless, for a person
// to look at: SVPROMPT_SHOTS=DIR names the directory, and without it the
// test is skipped. Nothing is shown on a display.
//
//	SVPROMPT_SHOTS=/tmp/shots CGO_ENABLED=1 go test -run Screenshots ./cmd/secretvault-gui-prompt/
func TestScreenshots(t *testing.T) {
	dir := os.Getenv("SVPROMPT_SHOTS")
	if dir == "" {
		t.Skip("SVPROMPT_SHOTS is not set")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	shot := func(h *harness, name string, d *dialog) {
		t.Helper()
		h.app.PumpOnce()
		if err := d.win.WritePNG(filepath.Join(dir, name+".png")); err != nil {
			t.Fatal(err)
		}
		t.Logf("wrote %s", filepath.Join(dir, name+".png"))
	}
	// The desktop's scheme is the process's; put it back for the tests
	// that run after this one.
	t.Cleanup(func() { style.SetDesktopColorScheme(style.SchemeNoPreference) })
	for _, scheme := range []string{"light", "dark"} {
		t.Run(scheme, func(t *testing.T) {
			// The desktop's own look, as the real program takes it, in
			// the desktop's light or dark.
			t.Setenv("UITK_COLOR_SCHEME", scheme)
			h := newHarness(t, nil)

			h.do("SETTITLE Unlock vault Personal",
				"SETDESC mail (/usr/bin/mail) wants to read \"imap/work\" in vault \"Personal\".%0A%0AEnter the passphrase of vault \"Personal\" to unlock it.",
				"SETPROMPT Passphrase:")
			h.send("GETPIN")
			d := h.dialog()
			d.win.Type("correct horse")
			shot(h, "unlock-"+scheme, d)
			d.win.Press(platform.KeyEscape)
			h.expect(errCanceledLine)

			// Refused, and with Caps Lock on: the usual reason.
			h.do("SETERROR That passphrase does not open this vault.")
			h.send("GETPIN")
			d = h.dialog()
			d.win.Inject(platform.Event{Kind: platform.EventKeyDown})
			surface(t, d).SetLockKeys(true, false)
			d.win.Inject(platform.Event{Kind: platform.EventKeyUp, Mods: platform.ModCapsLock})
			shot(h, "unlock-again-"+scheme, d)
			d.win.Press(platform.KeyEscape)
			h.expect(errCanceledLine)

			h.do("RESET", "SETTITLE Allow access to vault Personal?",
				"SETDESC mail (/usr/bin/mail) wants to read \"imap/work\" in vault \"Personal\".%0A%0AProgram: /usr/bin/mail%0AProcess: 4242")
			h.do(consent...)
			h.send("CHOOSE")
			d = h.dialog()
			shot(h, "consent-"+scheme, d)
			d.win.Press(platform.KeyEscape)
			h.expect(errCanceledLine)

			h.do("RESET", "SETTITLE New passphrase for vault Work",
				"SETDESC Choose a passphrase for the new vault \"Work\".",
				"SETPROMPT New passphrase:", "SETREPEAT Repeat:")
			h.send("GETPIN")
			d = h.dialog()
			d.win.Type("tr0ub4dor")
			d.win.Press(platform.KeyReturn)
			d.win.Type("tr0ub4dor&3")
			d.win.Press(platform.KeyReturn)
			shot(h, "new-passphrase-"+scheme, d)
			d.win.Press(platform.KeyEscape)
			h.expect(errCanceledLine)

			// A program asks for a vault of its own (vault.request): the
			// question, then its recovery key, shown once.
			h.do("RESET", "SETTITLE comms-mail wants a new vault called \"mail\"",
				"SETDESC comms-mail asks for a new, empty vault called \"mail\", kept with your other vaults.%0A%0A"+
					"If you create it, you choose its passphrase next, and comms-mail never sees it. "+
					"comms-mail will still have to ask you before it reads or stores anything in the vault.%0A%0A"+
					"Program: /usr/bin/comms-mail%0AProcess: 4242",
				"ADDCHOICE create Create the vault", "ADDCHOICE never Don't ask again for this program", "ADDCHOICE deny Don't create it")
			h.send("CHOOSE")
			d = h.dialog()
			shot(h, "new-vault-"+scheme, d)
			d.win.Press(platform.KeyEscape)
			h.expect(errCanceledLine)
			h.do("RESET", "SETTITLE Recovery key for vault mail",
				"SETDESC Write this recovery key down and keep it somewhere safe. It opens vault mail if the passphrase is lost, "+
					"and it is shown only now: it is stored nowhere, and comms-mail does not see it.",
				"SETSECRET SVRK1-7GQ4-M2XA-PL9C-WB3E-HN6T-K8DV-RF5J-ZQ2M-YC4S-T7NB-UE3K-A9LW",
				"ADDCHOICE no-recovery Don't keep a recovery key", "ADDCHOICE written I have written it down")
			h.send("CHOOSE")
			d = h.dialog()
			shot(h, "recovery-key-"+scheme, d)
			d.win.Press(platform.KeyEscape)
			h.expect(errCanceledLine)

			h.k.asker = func() string { return "ssh (/usr/bin/ssh), process 3187" }
			h.k.askerDone = false
			h.do("RESET", "SETTITLE A program asks for a passphrase",
				"SETDESC Enter passphrase for key '/home/ada/.ssh/id_ed25519':", "SETPROMPT Passphrase:")
			h.send("GETPIN")
			d = h.dialog()
			shot(h, "askpass-"+scheme, d)
			d.win.Press(platform.KeyEscape)
			h.expect(errCanceledLine)

			// Opened with Caps Lock on already: said before the first key.
			h.do("RESET", "SETTITLE Unlock vault Personal", "SETPROMPT Passphrase:")
			h.send("GETPIN")
			d = <-h.k.queue
			d.asker = h.k.who()
			if err := d.open(h.app); err != nil {
				t.Fatal(err)
			}
			surface(t, d).SetLockKeys(true, false) // before its first frame
			shot(h, "caps-at-open-"+scheme, d)
			d.win.Press(platform.KeyEscape)
			h.expect(errCanceledLine)

			// On a 2x display: the same dialog, every length doubled.
			h2 := newHarnessAt(t, nil, 2)
			h2.do("SETTITLE Allow access to vault Personal?",
				"SETDESC mail (/usr/bin/mail) wants to read \"imap/work\" in vault \"Personal\".%0A%0AProgram: /usr/bin/mail%0AProcess: 4242")
			h2.do(consent...)
			h2.send("CHOOSE")
			d = h2.dialog()
			shot(h2, "consent-2x-"+scheme, d)
			d.win.Press(platform.KeyEscape)
			h2.expect(errCanceledLine)
		})
	}
}
