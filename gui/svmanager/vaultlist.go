package svmanager

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svrpc"
)

// vaultListView is the list of vaults, in the vault's breadcrumb's
// drop-down (titlebar.go). A row is the vault's name (a star on the
// default) and, as buttons of an icon each, what can be done to its lock:
// lock it; or unlock it, and unlock it with something else than its
// passphrase. A click on a row, or Enter on it, shows that vault; Up and
// Down move. Whatever is done in it closes the drop-down (onDone).
type vaultListView struct {
	widget.Base
	m        *Manager
	Selected int // the vault shown
	cur      int // the row the keyboard is on
	col      *widgets.FlexBox
	rows     []*vaultRow
	onDone   func() // after a vault is picked, or its lock acted on
}

func newVaultList(m *Manager) *vaultListView {
	l := &vaultListView{m: m, Selected: -1}
	l.Init(l)
	l.col = widgets.NewColumn().WithGap(0)
	l.Add(l.col)
	l.SetWantsFocus(true)
	l.SetAccessibleName("Vaults")
	return l
}

func (l *vaultListView) Measure(c layout.Constraints) paintengine2d.Point { return l.col.Measure(c) }

func (l *vaultListView) Arrange(r paintengine2d.Rect) {
	l.SetBounds(r)
	l.col.Arrange(paintengine2d.XYWH(0, 0, r.Dx(), r.Dy()))
}

// MinWidth is the rows' floor (widget.MinWidther).
func (l *vaultListView) MinWidth() float32 { return widget.MinWidthOf(l.col) }

// set fills the list with vaults, the one named shown marked.
func (l *vaultListView) set(vaults []svrpc.VaultInfo, shown string) {
	l.col.ClearChildren()
	l.rows = l.rows[:0]
	l.Selected = -1
	for i, v := range vaults {
		r := newVaultRow(l, i, v)
		l.rows = append(l.rows, r)
		l.col.Add(r)
		if v.Name == shown {
			l.Selected = i
		}
	}
	l.cur = max(l.Selected, 0)
	l.restyle()
	l.RequestLayout()
	l.Invalidate()
}

// restyle marks the vault shown.
func (l *vaultListView) restyle() {
	for i, r := range l.rows {
		r.picked = i == l.Selected
		r.Invalidate()
	}
}

// done closes the drop-down the list is in.
func (l *vaultListView) done() {
	if l.onDone != nil {
		l.onDone()
	}
}

// choose shows vault i, as a click on its row does.
func (l *vaultListView) choose(i int) {
	if i < 0 || i >= len(l.rows) {
		return
	}
	l.Selected, l.cur = i, i
	l.restyle()
	l.m.vaultSelected(i)
}

func (l *vaultListView) KeyPress(e widget.KeyEvent) bool {
	if e.Mods&(platform.ModCtrl|platform.ModAlt) != 0 || len(l.rows) == 0 {
		return false
	}
	switch e.Key {
	case platform.KeyDown:
		l.cur = min(l.cur+1, len(l.rows)-1)
	case platform.KeyUp:
		l.cur = max(l.cur-1, 0)
	case platform.KeyHome:
		l.cur = 0
	case platform.KeyEnd:
		l.cur = len(l.rows) - 1
	case platform.KeyReturn, platform.KeySpace:
		i := l.cur
		l.done()
		l.choose(i)
		l.m.vaultActivated(i)
		return true
	default:
		return false
	}
	for _, r := range l.rows {
		r.Invalidate()
	}
	l.revealCur()
	return true
}

// revealCur scrolls the row the keyboard is on into sight.
func (l *vaultListView) revealCur() {
	if l.cur >= 0 && l.cur < len(l.rows) {
		reveal(l.rows[l.cur])
	}
}

func (l *vaultListView) Describe(n *a11y.Node) {
	n.Role = a11y.RoleList
}

// vaultRow is one vault in the list.
type vaultRow struct {
	widget.Base
	l      *vaultListView
	i      int
	name   *widgets.Label
	picked bool
	hover  bool
}

func newVaultRow(l *vaultListView, i int, v svrpc.VaultInfo) *vaultRow {
	r := &vaultRow{l: l, i: i}
	r.Init(r)
	m := l.m
	r.name = widgets.NewLabel(v.Name)
	if v.Default {
		r.name.Icon = style.IconStar
	}
	row := widgets.NewRow(r.name).WithGap(2).WithAlign(layout.AlignCenter).WithPadding(14, 3, 8, 3)
	row.AddFlex(r.name, 1)
	name := v.Name
	act := func(do func()) func() {
		return func() {
			l.done()
			l.choose(i)
			do()
		}
	}
	switch {
	case v.ID == "":
		row.Add(m.muted("missing"))
	case v.Locked:
		// Its state, as a closed padlock: a click unlocks it.
		row.Add(iconButton("Unlock "+name, "Locked: click to unlock it (asks for its passphrase)", style.IconLock, nil,
			act(func() { m.unlockVault(name) })))
		row.Add(iconButton("Unlock "+name+" with…", "Unlock it with a keyfile, the recovery key, an identity file or a security key", style.IconLock, m.plusBadge(),
			act(m.unlockWith)))
	default:
		// Its state, as an open padlock: a click locks it.
		row.Add(iconButton("Lock "+name, "Unlocked: click to lock it (its items then need the passphrase again)", style.IconLockOpen, nil,
			act(func() { m.lockVault(false) })))
	}
	r.Add(row)
	what := "unlocked"
	switch {
	case v.ID == "":
		what = "missing"
	case v.Locked:
		what = "locked"
	}
	if v.Default {
		what += ", the default"
	}
	r.SetAccessibleName(name + ", " + what)
	return r
}

func (r *vaultRow) Measure(c layout.Constraints) paintengine2d.Point {
	return r.Children()[0].Measure(c)
}

func (r *vaultRow) Arrange(b paintengine2d.Rect) {
	r.SetBounds(b)
	r.Children()[0].Arrange(paintengine2d.XYWH(0, 0, b.Dx(), b.Dy()))
}

func (r *vaultRow) MinWidth() float32 { return widget.MinWidthOf(r.Children()[0]) }

func (r *vaultRow) Paint(ctx *paintengine2d.Context) {
	p := r.Look().Palette()
	switch {
	case r.picked:
		markPicked(ctx, r.LocalBounds(), r.Look())
	case r.hover || r.l.cur == r.i && r.l.Focused():
		ctx.DrawRect(r.LocalBounds(), paintengine2d.Fill(p.Highlight))
	}
}

func (r *vaultRow) MouseEnter() { r.hover = true; r.Invalidate() }
func (r *vaultRow) MouseExit()  { r.hover = false; r.Invalidate() }

func (r *vaultRow) MousePress(e widget.MouseEvent) bool {
	r.l.done()
	r.l.choose(r.i)
	return true
}

func (r *vaultRow) Describe(n *a11y.Node) {
	n.Role = a11y.RoleListItem
	if r.picked {
		n.State |= a11y.StateSelected
	}
}

// iconButton is a button of an icon alone: what it does is its tip, and
// its name for a screen reader. content draws over the icon: the
// manager's logo where it has none, the toolkit's badge (marks.go).
func iconButton(name, tip string, icon style.ToolIcon, content widgets.ButtonContentPainter, do func()) *widgets.ToolButton {
	b := widgets.NewToolButton("", icon, do)
	b.Tip = tip
	b.Content = content
	b.SetAccessibleName(name)
	return b
}
