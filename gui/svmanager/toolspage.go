package svmanager

import (
	"context"
	"strings"

	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"

	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// The Tools tab: everything that acts outside the vaults. Files and mail
// signed, checked, encrypted or decrypted (tools.go); references to
// secrets; the password generator; identity files and the security keys
// plugged in (keys.go); and the other programs secretvault works with
// (desktop.go). Its page stays; it is made again for another vault, since
// GnuPG's tab is about the vault shown.

// The Tools tab's tabs.
const (
	tabFiles = iota
	tabReferences
	tabGenerator
	tabIdentities
	tabSecurityKeys
	tabBrowsers
	tabKeyring
	tabGnuPG
	tabHelpers
	tabHost
)

// toolsPage is the Tools tab's page's state.
type toolsPage struct {
	*tabbedPage
	devices []svrpc.FIDO2Device
}

// whereAbout heads the list of where things are kept.
const whereAbout = "Every folder and file secretvault keeps, and every change it made in another program, with what each holds. " +
	"Nothing else of yours is touched."

// showTools brings the Tools tab forward, open at tab (-1 for the one it
// shows already).
func (m *Manager) showTools(tab int) {
	m.showSection(secTools) // which makes it, if need be (sectionShown)
	m.toolsShown()
	if tab >= 0 {
		m.selectTab(m.tpage.tabbedPage, tab)
	}
}

// toolsShown makes the Tools tab's page if there is none yet, or if it
// was made for another vault, open at the tab it showed.
func (m *Manager) toolsShown() {
	if m.tpage != nil && m.tpage.vault == m.vault {
		return
	}
	at := tabFiles
	if m.tpage != nil {
		at = m.tpage.selected()
	}
	m.makeTools(at)
}

// makeTools makes the Tools tab's page, open at tab.
func (m *Manager) makeTools(tab int) {
	p := &toolsPage{tabbedPage: &tabbedPage{kind: pageTools, vault: m.vault, title: "Tools"}}
	d := &desktopPage{tabbedPage: p.tabbedPage}
	p.panes = []*pane{
		newPane("Files and mail", m.fillFileTools),
		newPane("References", m.fillReferenceTools),
		newPane("Password generator", m.fillGeneratorTool),
		newPane("Identity files", m.fillIdentities),
		newPane("Security keys", func(pn *pane) { m.fillSecurityKeys(p, pn) }),
		newPane("Browsers", func(pn *pane) { m.fillBrowsers(d, pn) }),
		newPane("System keyring", func(pn *pane) { m.fillKeyring(d, pn) }),
		newPane("GnuPG", func(pn *pane) { m.fillGnuPG(d, pn) }),
		newPane("Program helpers", func(pn *pane) { m.fillHelpers(d, pn) }),
		newPane("Host daemon", func(pn *pane) { m.fillHost(d, pn) }),
	}
	m.tpage, m.dpage = p, d
	m.standPage(p.tabbedPage, m.ui.toolsHost, tab)
}

// tool is one action of a tools tab: its button, and what it does.
type tool struct {
	label, about string
	do           func()
}

// toolList lays tools out under their headings, in one grid so that the
// buttons line up: each button, and beside it the first sentence of what
// it does, wrapped to the width left.
func (m *Manager) toolList(pn *pane, groups ...any) *widgets.Grid {
	g := widgets.NewGrid()
	g.Cols = []widgets.Track{widgets.Auto(), widgets.Share(1)}
	g.ColGap, g.RowGap = 16, 6
	row := 0
	for _, x := range groups {
		switch x := x.(type) {
		case string:
			g.PlaceSpan(section(m, x), row, 0, 1, 2)
		case tool:
			b := newButton(x.label, x.do)
			if pn.focus == nil {
				pn.focus = b
			}
			g.Place(b, row, 0)
			g.Place(m.paragraph(firstSentence(x.about)), row, 1)
		}
		row++
	}
	return g
}

// firstSentence is s up to its first full stop.
func firstSentence(s string) string {
	if i := strings.Index(s, ". "); i >= 0 {
		return s[:i+1]
	}
	return s
}

func (m *Manager) fillFileTools(pn *pane) {
	pn.focus = nil
	pn.box.Set(scrolled(m.toolList(pn,
		"Files",
		tool{"Sign a file…", svops.SignFileAbout, m.signFile},
		tool{"Check a signature…", svops.CheckSignatureAbout, m.verifyFile},
		tool{"Decrypt a file (OpenPGP)…", svops.DecryptPGPAbout, m.decryptPGPFile},
		tool{"Encrypt a file (age)…", svops.EncryptAgeAbout, m.encryptAgeFile},
		tool{"Decrypt a file (age)…", svops.DecryptAgeAbout, m.decryptAgeFile},
		"Mail",
		tool{"Inspect a message…", svops.InspectMessageAbout, m.inspectMessage},
		tool{"Sign and encrypt a message…", svops.ComposeMessageAbout, m.composeMessage},
	)))
}

func (m *Manager) fillReferenceTools(pn *pane) {
	pn.focus = nil
	pn.box.Set(scrolled(m.toolList(pn,
		tool{"Resolve a reference…", svops.ResolveReferenceAbout, m.resolveReference},
		tool{"Check an env file…", svops.CheckEnvFileAbout, m.checkEnvFile},
		tool{"Check a template…", svops.CheckTemplateAbout, m.checkTemplate},
	)))
}

func (m *Manager) fillGeneratorTool(pn *pane) {
	pn.focus = nil
	pn.box.Set(scrolled(m.toolList(pn,
		tool{"Make a password…", svops.GeneratorAbout, m.openGenerator},
	)))
}

// fillWhere lists where things are kept, as the daemon keeps them: its
// settings, its data, what it holds while it runs, and what it changed in
// other programs. A place not there yet says so.
func (m *Manager) fillWhere(pn *pane) {
	var places []svrpc.Place
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		places, err = c.Where(ctx)
		return err
	}, func() widget.Component {
		col := widgets.NewColumn(m.paragraph(whereAbout)).WithGap(gap)
		var g *widgets.Grid
		row, group := 0, ""
		for _, pl := range places {
			if pl.Group != group {
				group = pl.Group
				col.Add(section(m, group))
				g = widgets.NewGrid()
				g.Cols = []widgets.Track{widgets.Share(1), widgets.Share(1), widgets.Auto()}
				g.ColGap, g.RowGap = 16, 6
				col.Add(g)
				row = 0
			}
			path := widgets.NewLabel(pl.Path)
			path.Mono, path.Wrap = true, true
			what := pl.What
			if !pl.Exists {
				what += " (not there yet)"
			}
			p := pl.Path
			g.Place(path, row, 0)
			g.Place(m.paragraph(what), row, 1)
			g.Place(iconButton("Copy the path "+p, "Copy the path", style.IconCopy, nil, func() {
				m.copyValue([]byte(p), "The path", "")
			}), row, 2)
			row++
		}
		refresh := newButton("Refresh", pn.refresh)
		pn.focus = refresh
		col.Add(buttons(refresh))
		return scrolled(col)
	})
}
