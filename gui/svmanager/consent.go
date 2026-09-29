package svmanager

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svrpc"
)

// A vault's page: what programs may do with it (its grants, which can be
// revoked), what they have done (its audit log), and how its sync is
// doing, if it syncs.

// vaultPage is the vault page's state.
type vaultPage struct {
	vault  string
	tabs   *widgets.TabView
	grants []svrpc.Grant
	gtable *widgets.TableView
	audit  []svrpc.AuditEntry
	sync   *svrpc.SyncStatus
}

// showVaultPage shows the vault's page, open at tab (0 grants, 1 audit
// log, 2 sync).
func (m *Manager) showVaultPage(tab int) {
	if m.editor != nil {
		m.say("Save or cancel the edit first.")
		return
	}
	vault, gen := m.vault, m.listGen
	if vault == "" {
		return
	}
	var grants []svrpc.Grant
	var audit []svrpc.AuditEntry
	var syncs []svrpc.SyncStatus
	m.call(func(ctx context.Context, c *secretvault.Client) (err error) {
		if grants, err = c.Grants(ctx, vault); err != nil {
			return err
		}
		if audit, err = c.Audit(ctx, vault, 500); err != nil {
			return err
		}
		syncs, _ = c.SyncStatus(ctx, vault)
		return nil
	}, func(err error) {
		if err != nil {
			m.fail(err)
			m.reloadVaults()
			return
		}
		if vault != m.vault || gen != m.listGen || m.editor != nil {
			return // the vault shown changed or locked, or an edit began
		}
		m.leaveHistory()
		m.closeItem()
		p := &vaultPage{vault: vault, grants: grants, audit: audit}
		if len(syncs) > 0 {
			p.sync = &syncs[0]
		}
		m.vpage = p
		m.drawVaultPage(tab)
		m.reloadVaults() // asking may have unlocked it
	})
}

func (m *Manager) drawVaultPage(tab int) {
	p := m.vpage
	p.gtable = widgets.NewTableView([]widgets.TableColumn{
		{Title: "Decision", Width: 130},
		{Title: "Program"},
		{Title: "Item", Width: 130},
		{Title: "May", Width: 90},
		{Title: "Since", Width: 140},
	}, len(p.grants), func(row, col int) string {
		if row < 0 || row >= len(p.grants) {
			return ""
		}
		g := p.grants[row]
		switch col {
		case 0:
			return g.Decision
		case 1:
			return g.Program
		case 2:
			if g.Item == "" {
				return "the whole vault"
			}
			return g.Item
		case 3:
			return strings.Join(g.Ops, ", ")
		}
		if g.Created.IsZero() {
			return ""
		}
		return g.Created.Local().Format("2006-01-02 15:04")
	}, nil)
	p.gtable.SetAccessibleName("Grants")
	p.gtable.CellIcon = func(row, col int) (style.ToolIcon, paintengine2d.Color) {
		if col != 0 || row < 0 || row >= len(p.grants) {
			return style.IconNone, paintengine2d.Color{}
		}
		if strings.HasPrefix(p.grants[row].Decision, "deny") {
			return style.IconError, m.win.Look().Palette().Danger
		}
		return style.IconCheck, m.win.Look().Palette().Success
	}
	p.gtable.OnActivate = func(int) { m.revokeGrant() }
	if len(p.grants) > 0 {
		p.gtable.Selected = 0
	}
	revoke := tip(widgets.NewButton("Revoke…", m.revokeGrant), "Delete")
	revoke.SetEnabled(len(p.grants) > 0)
	gnote := "What has been decided about programs using this vault. Revoking a decision means the program is asked again."
	if len(p.grants) == 0 {
		gnote = "No program has a remembered decision about this vault."
	}
	gn := m.muted(gnote)
	gn.Wrap = true
	grants := widgets.NewColumn(gn, p.gtable, widgets.NewRow(revoke)).WithGap(gap).WithPad(gap)
	grants.AddFlex(p.gtable, 1)

	// The audit log, newest first.
	entries := slices.Clone(p.audit)
	slices.Reverse(entries)
	atable := widgets.NewTableView([]widgets.TableColumn{
		{Title: "When", Width: 140},
		{Title: "Outcome", Width: 90},
		{Title: "What", Width: 150},
		{Title: "Program"},
		{Title: "Why"},
	}, len(entries), func(row, col int) string {
		if row < 0 || row >= len(entries) {
			return ""
		}
		e := entries[row]
		if e.Outcome == "log-damaged" {
			if col == 0 {
				return "Damaged"
			}
			if col == 4 {
				return e.Reason
			}
			return ""
		}
		switch col {
		case 0:
			return e.Time.Local().Format("2006-01-02 15:04:05")
		case 1:
			return e.Outcome
		case 2:
			return strings.TrimSpace(e.Op + " " + e.Item)
		case 3:
			return e.Program
		}
		return e.Reason
	}, nil)
	atable.SetAccessibleName("Audit log")
	atable.CellIcon = func(row, col int) (style.ToolIcon, paintengine2d.Color) {
		if col != 1 || row < 0 || row >= len(entries) {
			return style.IconNone, paintengine2d.Color{}
		}
		switch entries[row].Outcome {
		case "allowed":
			return style.IconCheck, m.win.Look().Palette().Success
		case "canceled":
			return style.IconWarning, m.win.Look().Palette().Warning
		}
		return style.IconError, m.win.Look().Palette().Danger
	}
	n := fmt.Sprintf("%d entries", len(entries))
	if len(entries) == 1 {
		n = "1 entry"
	}
	an := m.muted("Every access to this vault on this device, allowed or not: " + n + ", newest first. " +
		"The log is sealed so that only an unlocked vault can read it, and chained so that a removed line shows.")
	an.Wrap = true
	audit := widgets.NewColumn(an, atable).WithGap(gap).WithPad(gap)
	audit.AddFlex(atable, 1)

	p.tabs = widgets.NewTabView(
		widgets.Tab{Title: "Grants", Content: grants},
		widgets.Tab{Title: "Audit log", Content: audit},
		widgets.Tab{Title: "Sync", Content: m.syncTab(p)},
	)
	p.tabs.Select(tab)
	back := tip(widgets.NewButton("Back to the items", m.closeVaultPage), "Escape")
	col := widgets.NewColumn(heading("Vault "+p.vault), p.tabs, widgets.NewRow(back)).WithGap(gap).WithPad(pad)
	col.AddFlex(p.tabs, 1)
	m.ui.main.Set(newPage(pageVault, col, func(e widget.KeyEvent) bool {
		switch {
		case e.Key == platform.KeyEscape:
			m.closeVaultPage()
		case e.Key == platform.KeyDelete && m.win.Focus() == widget.Component(p.gtable):
			m.revokeGrant()
		default:
			return false
		}
		return true
	}))
	if tab == 0 {
		m.win.RequestFocus(p.gtable)
	} else if tab == 1 {
		m.win.RequestFocus(atable)
	}
	m.enableMenus()
}

// syncTab says how the vault's sync is doing. It is for reading: setting
// sync up and joining devices are the CLI's (secretvault sync).
func (m *Manager) syncTab(p *vaultPage) widget.Component {
	s := p.sync
	if s == nil {
		n := m.muted("This vault does not sync. 'secretvault sync setup' keeps it in step with a sync server of your own.")
		n.Wrap = true
		return widgets.NewColumn(n).WithPad(gap)
	}
	when := func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return t.Local().Format("2006-01-02 15:04:05")
	}
	rows := [][2]string{
		{"Server", s.URL},
		{"Vault on the server", s.ServerVault},
		{"This device", s.Device},
		{"Last sync", when(s.Last)},
		{"Last good sync", when(s.LastOK)},
		{"Since the daemon started", fmt.Sprintf("%d pulled, %d pushed, %d removed", s.Pulled, s.Pushed, s.Removed)},
	}
	g := widgets.NewGrid()
	g.Cols = []widgets.Track{widgets.Auto(), widgets.Flex(1)}
	g.ColGap = 16
	for i, r := range rows {
		g.Place(m.muted(r[0]), i, 0)
		g.Place(widgets.NewLabel(r[1]), i, 1)
	}
	col := widgets.NewColumn(g).WithGap(gap).WithPad(gap)
	if s.Error != "" {
		e := toned("The last sync failed: "+s.Error, toneDanger)
		e.Wrap = true
		col.Add(e)
	}
	if s.Kept > 0 {
		k := toned(fmt.Sprintf("%d keyslot removals were refused, because they would have left the vault with no key.", s.Kept), toneWarning)
		k.Wrap = true
		col.Add(k)
	}
	return col
}

// revokeGrant forgets the decision selected, after asking.
func (m *Manager) revokeGrant() {
	p := m.vpage
	if p == nil || p.gtable == nil {
		return
	}
	i := p.gtable.Selected
	if i < 0 || i >= len(p.grants) {
		return
	}
	g := p.grants[i]
	vault := p.vault
	m.confirm("Revoke?", fmt.Sprintf("Forget that %s is %s?\n\nIt will be asked about again.", g.Program, g.Decision), "Revoke", func() {
		var left []svrpc.Grant
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			if err := c.Revoke(ctx, vault, g.ID); err != nil {
				return err
			}
			var err error
			left, err = c.Grants(ctx, vault)
			return err
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Revoked the decision about %s.", g.Program)
			if m.vpage == p && m.showingVaultPage() {
				p.grants = left
				m.drawVaultPage(0)
			}
		})
	})
}

func (m *Manager) closeVaultPage() {
	m.vpage = nil
	if m.showingVaultPage() {
		m.ui.main.Set(m.ui.browse)
		m.showSelected()
		m.win.RequestFocus(m.ui.items)
		m.enableMenus()
	}
}
