package svmanager

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// A vault's page: the ways it opens (its keyslots), the devices that write
// to it, who it is shared with and who may ask for it in an emergency, its
// sync, its encrypted containers, what programs may do with it (its
// grants) and what they have done (its audit log), and its settings.

// The vault page's tabs.
const (
	tabKeyslots = iota
	tabDevices
	tabSharing
	tabSync
	tabContainers
	tabGrants
	tabAudit
	tabSettings
)

// vaultPage is the vault page's state.
type vaultPage struct {
	*tabbedPage

	grants []svrpc.Grant
	gtable *widgets.TableView
	audit  []svrpc.AuditEntry
	sync   *svrpc.SyncStatus

	slots     []svrpc.SlotInfo
	stable    *widgets.TableView
	devices   []svrpc.Device
	policy    svrpc.SignaturePolicy
	dtable    *widgets.TableView
	shared    []svrpc.SlotInfo // the recipient keyslots
	shtable   *widgets.TableView
	emergency svrpc.EmergencyList
	etable    *widgets.TableView
	syncDevs  []svrpc.SyncDevice
	sdtable   *widgets.TableView
	boxes     []svrpc.ContainerInfo
	ctable    *widgets.TableView
	info      *svrpc.VaultInfo
}

// showVaultPage shows the vault's page, open at tab.
func (m *Manager) showVaultPage(tab int) {
	if m.editor != nil {
		m.say("Save or cancel the edit first.")
		return
	}
	vault := m.vault
	if vault == "" || m.gone {
		return
	}
	if m.vpage != nil && m.vpage.vault == vault && m.up(m.vpage.tabbedPage) {
		m.selectTab(m.vpage.tabbedPage, tab)
		return
	}
	m.closeVaultPage()
	p := &vaultPage{tabbedPage: &tabbedPage{kind: pageVault, vault: vault, title: "Vault " + vault}}
	p.panes = []*pane{
		newPane("Keyslots", func(pn *pane) { m.fillSlots(p, pn) }),
		newPane("Devices", func(pn *pane) { m.fillDevices(p, pn) }),
		newPane("Sharing", func(pn *pane) { m.fillSharing(p, pn) }),
		newPane("Sync", func(pn *pane) { m.fillSync(p, pn) }),
		newPane("Containers", func(pn *pane) { m.fillContainers(p, pn) }),
		newPane("Grants", func(pn *pane) { m.fillGrants(p, pn) }),
		newPane("Audit log", func(pn *pane) { m.fillAudit(p, pn) }),
		newPane("Settings", func(pn *pane) { m.fillSettings(p, pn) }),
	}
	p.keys = func(e widget.KeyEvent) bool {
		if e.Key == platform.KeyDelete && p.gtable != nil && m.win.Focus() == widget.Component(p.gtable) {
			m.revokeGrant()
			return true
		}
		return false
	}
	m.vpage = p
	m.openPage(p.tabbedPage, tab)
}

// refreshTab fills a tab of the vault page again, if it is still up.
func (m *Manager) refreshTab(p *vaultPage, tab int) {
	if p != nil && m.up(p.tabbedPage) && p.panes[tab].filled {
		p.panes[tab].refresh()
	}
}

func (m *Manager) fillGrants(p *vaultPage, pn *pane) {
	var grants []svrpc.Grant
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		grants, err = c.Grants(ctx, p.vault)
		return err
	}, func() widget.Component {
		p.grants = grants
		return m.drawGrants(p, pn)
	})
}

func (m *Manager) drawGrants(p *vaultPage, pn *pane) widget.Component {
	p.gtable = widgets.NewTableView([]widgets.TableColumn{
		{Title: "Decision", Width: 190},
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
			return svops.DecisionText(g.Decision)
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
	revoke := tip(widgets.NewButton("Forget the decision…", m.revokeGrant), "Delete")
	revoke.SetEnabled(len(p.grants) > 0)
	allow := widgets.NewButton("Allow a program…", func() { m.decideGrant(p, true) })
	deny := widgets.NewButton("Deny a program…", func() { m.decideGrant(p, false) })
	gnote := "What has been decided about programs using this vault. Once a decision is forgotten, you are asked again."
	if len(p.grants) == 0 {
		gnote = svops.GrantsEmpty
	}
	pn.focus = p.gtable
	return m.paneColumn(gnote, p.gtable, allow, deny, revoke)
}

func (m *Manager) fillAudit(p *vaultPage, pn *pane) {
	var audit []svrpc.AuditEntry
	m.load(pn, func(ctx context.Context, c *secretvault.Client) (err error) {
		audit, err = c.Audit(ctx, p.vault, 500)
		return err
	}, func() widget.Component {
		p.audit = audit
		return m.drawAudit(p, pn)
	})
}

func (m *Manager) drawAudit(p *vaultPage, pn *pane) widget.Component {
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
	pn.focus = atable
	refresh := widgets.NewButton("Refresh", pn.refresh)
	return m.paneColumn("Every access to this vault on this device, allowed or not: "+n+", newest first. "+
		"The log is sealed so that only an unlocked vault can read it, and chained so that a removed line shows.", atable, refresh)
}

// revokeGrant forgets the decision selected, after asking.
func (m *Manager) revokeGrant() {
	p := m.vpage
	if p == nil || p.gtable == nil {
		return
	}
	i := selected(p.gtable)
	if i < 0 || i >= len(p.grants) {
		return
	}
	g := p.grants[i]
	vault := p.vault
	m.confirm(svops.RevokeGrantTitle, svops.RevokeGrantText(g), svops.RevokeGrantAction, func() {
		m.call(func(ctx context.Context, c *secretvault.Client) error {
			return c.Revoke(ctx, vault, g.ID)
		}, func(err error) {
			if err != nil {
				m.fail(err)
				return
			}
			m.say("Forgot the decision about %s.", g.Program)
			m.refreshTab(p, tabGrants)
		})
	})
}

// grantOps are the operations a decision can be about, as grant.add takes
// them.
var grantOps = []string{"read", "list", "write", "delete", "manage", "sign", "decrypt", "mount"}

// decideGrant decides ahead of time about a program (the CLI's grant
// allow and grant deny): the program, the whole vault, an item or its
// contacts, and what it may do.
func (m *Manager) decideGrant(p *vaultPage, allow bool) {
	title := "Deny a program"
	if allow {
		title = "Allow a program"
	}
	f := m.newForm(title)
	if allow {
		f.intro("The program may then use the vault as you choose here, without asking you each time.")
	} else {
		f.intro("The program is then refused, without asking you, whenever it wants what you choose here.")
	}
	prog := f.path("Program", PickOpen, "")
	f.note("The program's path; a Flatpak app as flatpak:APP, a Snap as snap:NAME.")
	scope := f.choice("Applies to", []string{"the whole vault", "one item", "the vault's contacts"}, 0)
	item := f.text("Item", m.targetName(), "web/example.com")
	opsRow := widgets.NewWrap()
	boxes := make([]*widgets.Checkbox, len(grantOps))
	for i, op := range grantOps {
		boxes[i] = widgets.NewCheckbox(op, op == "read", nil)
		opsRow.Add(boxes[i])
	}
	f.row("What it may do", opsRow)
	var untilLock *widgets.Checkbox
	if allow {
		untilLock = f.check("Only until the vault next locks", false)
	}
	action := "Deny the program"
	if allow {
		action = "Allow the program"
	}
	f.show(action, func() {
		program := prog.Path()
		if program == "" {
			f.fail("Choose the program.")
			return
		}
		params := svrpc.GrantAddParams{Vault: p.vault, Program: program, Decision: "deny-always"}
		switch scope.Selected {
		case 1:
			params.Item = strings.TrimSpace(item.Text)
			if err := checkName(params.Item); err != nil {
				f.fail(sentence(err.Error()))
				return
			}
		case 2:
			params.Contacts = true
		}
		for i, b := range boxes {
			if b.Checked {
				params.Ops = append(params.Ops, grantOps[i])
			}
		}
		if len(params.Ops) == 0 {
			f.fail("Choose at least one thing it may do.")
			return
		}
		if allow {
			params.Decision = "allow-always"
			if untilLock.Checked {
				params.Decision = "allow-until-lock"
			}
		}
		var g svrpc.Grant
		f.call(func(ctx context.Context, c *secretvault.Client) (err error) {
			g, err = c.Grant(ctx, params)
			return err
		}, func() {
			m.say("%s", svops.GrantDecided(g))
			m.refreshTab(p, tabGrants)
		})
	})
}

// closeVaultPage takes down whatever page is up over the items, and shows
// them again.
func (m *Manager) closeVaultPage() {
	m.vpage, m.kpage, m.cpage, m.dpage = nil, nil, nil, nil
	if m.page != nil {
		m.page = nil
	}
	if m.showingVaultPage() {
		m.ui.main.Set(m.ui.browse)
		m.showSelected()
		m.win.RequestFocus(m.ui.items)
		m.enableMenus()
		m.syncCapture()
	}
}

// errNoVault is an operation on the vault shown when none is.
var errNoVault = errors.New("choose a vault first")
