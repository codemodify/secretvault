package svtui

import (
	"fmt"
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// panel is a table of things (keyslots, devices, contacts...) with the
// actions that apply to them. Each action has a key, listed at the
// panel's foot; Enter on a row offers the row's actions as a menu, so no
// key needs remembering; and ':' opens the menu of every operation.
type panel struct {
	u       *UI
	page    string
	title   string
	vault   string // the vault it shows, "" when it shows none: it closes when that vault locks
	head    *tview.TextView
	t       *tview.Table
	foot    *tview.TextView
	frame   *tview.Flex
	acts    []panelAct
	enter   func(ref any) // Enter on a row; nil: the row's actions, as a menu
	enterIs string        // what Enter does, said at the foot ("" for "open" or "actions")
	onClose func()        // runs when it closes
	tab     bool          // it is a tab of the main screen (Disk, Tools), not a page over it
	reload  func()
	cols    int
	at      int // the row selected before a refill
}

// panelAct is something a panel can do: to the row selected (on says
// which rows), or (on nil) to none in particular.
type panelAct struct {
	key   rune
	label string
	on    func(ref any) bool
	do    func(ref any)
}

// newPanel makes a panel with columns header. reload fills it, and is
// called again after each change.
func (u *UI) newPanel(title string, header ...string) *panel {
	p := &panel{u: u, page: pagePanel, title: title, cols: len(header)}
	p.head = tview.NewTextView().SetDynamicColors(true).SetWrap(true).SetWordWrap(true)
	p.t = tview.NewTable().SetSelectable(true, false).SetFixed(1, 0)
	for i, h := range header {
		p.t.SetCell(0, i, tview.NewTableCell(h).SetTextColor(tview.Styles.SecondaryTextColor).SetSelectable(false))
	}
	p.foot = tview.NewTextView().SetDynamicColors(true).SetWrap(true).SetWordWrap(true)
	p.frame = tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(p.head, 0, 0, false).
		AddItem(p.t, 0, 1, true).
		AddItem(p.foot, 1, 0, false)
	p.frame.SetBorder(true).SetBorderPadding(0, 0, 1, 1)
	p.t.SetSelectedFunc(func(row, _ int) { p.pressEnter() })
	p.t.SetInputCapture(p.keys)
	return p
}

// act adds an action that needs no row.
func (p *panel) act(key rune, label string, do func()) *panel {
	p.acts = append(p.acts, panelAct{key: key, label: label, do: func(any) { do() }})
	return p
}

// rowAct adds an action on the selected row, for the rows on accepts
// (any row when on is nil).
func (p *panel) rowAct(key rune, label string, on func(ref any) bool, do func(ref any)) *panel {
	if on == nil {
		on = func(any) bool { return true }
	}
	p.acts = append(p.acts, panelAct{key: key, label: label, on: on, do: do})
	return p
}

// is makes an on for rows whose reference is a T.
func is[T any](ref any) bool {
	_, ok := ref.(T)
	return ok
}

// setHead puts text above the table ("" for none).
func (p *panel) setHead(text string) {
	p.head.SetText(text)
	h := 0
	if text != "" {
		h = wrappedLines(text, 100) + 1
	}
	p.frame.ResizeItem(p.head, h, 0)
}

// clear empties the table, remembering the selection.
func (p *panel) clear() {
	p.at, _ = p.t.GetSelection()
	for p.t.GetRowCount() > 1 {
		p.t.RemoveRow(p.t.GetRowCount() - 1)
	}
}

// labelWidth bounds headings and "none" rows, which share the first
// column with the rows: say more in the panel's head.
const labelWidth = 30

// heading adds a row that names the rows below it.
func (p *panel) heading(text string) {
	row := p.t.GetRowCount()
	p.t.SetCell(row, 0, tview.NewTableCell("[::b]"+tview.Escape(text)).SetTextColor(tview.Styles.TertiaryTextColor).SetSelectable(false).SetMaxWidth(labelWidth))
	for i := 1; i < p.cols; i++ {
		p.t.SetCell(row, i, tview.NewTableCell("").SetSelectable(false))
	}
}

// none adds a row that says there is nothing.
func (p *panel) none(text string) {
	row := p.t.GetRowCount()
	p.t.SetCell(row, 0, tview.NewTableCell(tview.Escape(text)).SetTextColor(tcell.ColorGray).SetSelectable(false).SetMaxWidth(labelWidth))
	for i := 1; i < p.cols; i++ {
		p.t.SetCell(row, i, tview.NewTableCell("").SetSelectable(false))
	}
}

// row adds a row for ref. Cells are escaped; a cell starting with "\x00"
// is taken as it is, colour tags and all.
func (p *panel) row(ref any, cells ...string) {
	row := p.t.GetRowCount()
	for i := 0; i < p.cols; i++ {
		text := ""
		if i < len(cells) {
			text = cells[i]
		}
		if raw, ok := strings.CutPrefix(text, "\x00"); ok {
			text = raw
		} else {
			text = tview.Escape(text)
		}
		c := tview.NewTableCell(text).SetMaxWidth(80)
		if i == 0 {
			c.SetReference(ref)
		}
		p.t.SetCell(row, i, c)
	}
}

// tagged marks a cell as already escaped, with colour tags.
func tagged(s string) string { return "\x00" + s }

// done puts the selection back where it was, or on the first row.
func (p *panel) done() {
	n := p.t.GetRowCount()
	at := p.at
	if at < 1 {
		at = 1
	}
	if at >= n {
		at = n - 1
	}
	// Move off headings, down then up.
	for i := at; i < n; i++ {
		if !p.t.GetCell(i, 0).NotSelectable {
			p.t.Select(i, 0)
			return
		}
	}
	for i := at; i >= 1; i-- {
		if !p.t.GetCell(i, 0).NotSelectable {
			p.t.Select(i, 0)
			return
		}
	}
}

// hasKey reports whether one of the panel's actions has key.
func (p *panel) hasKey(key rune) bool {
	for _, a := range p.acts {
		if a.key == key {
			return true
		}
	}
	return false
}

// applies reports whether one of the panel's actions has key and does
// something now: it needs no row, or the row selected is one it takes.
func (p *panel) applies(key rune) bool {
	for _, a := range p.acts {
		if a.key != key {
			continue
		}
		if a.on == nil {
			return true
		}
		if ref := p.selected(); ref != nil && a.on(ref) {
			return true
		}
	}
	return false
}

// selectable reports whether any row can be selected.
func (p *panel) selectable() bool {
	for r := 1; r < p.t.GetRowCount(); r++ {
		if !p.t.GetCell(r, 0).NotSelectable {
			return true
		}
	}
	return false
}

// selected is the selected row's reference, or nil.
func (p *panel) selected() any {
	row, _ := p.t.GetSelection()
	if row < 1 || row >= p.t.GetRowCount() {
		return nil
	}
	c := p.t.GetCell(row, 0)
	if c.NotSelectable {
		return nil
	}
	return c.GetReference()
}

// drawFoot lists the keys.
func (p *panel) drawFoot() {
	var parts []string
	for _, a := range p.acts {
		parts = append(parts, fmt.Sprintf("[yellow]%c[-] %s", a.key, tview.Escape(a.label)))
	}
	enter := "actions"
	if p.enter != nil {
		enter = "open"
	}
	if p.enterIs != "" {
		enter = p.enterIs
	}
	parts = append(parts, "[yellow]Enter[-] "+enter, "[yellow]:[-] every action")
	if p.tab {
		parts = append(parts, "[yellow]1 2 3[-] tabs", "[yellow]Esc[-] back to Vault")
	} else {
		parts = append(parts, "[yellow]Esc[-] close")
	}
	text := strings.Join(parts, "  ")
	p.foot.SetText(text)
	p.frame.ResizeItem(p.foot, wrappedLines(stripTags(text), 110), 0)
}

// show puts the panel up (or brings it back to the front), and fills it.
func (p *panel) show() {
	title := " " + tview.Escape(p.title) + " "
	p.frame.SetTitle(title)
	p.drawFoot()
	p.u.openPage(p.page, p.frame, p.t)
	p.u.panels[p.page] = p
	p.refresh()
}

// embed makes the panel a tab of the main screen (u.tabs holds its
// frame): it is never a page of its own, and Esc brings the Vault tab
// back rather than close it.
func (p *panel) embed() {
	p.tab = true
	p.frame.SetTitle(" " + tview.Escape(p.title) + " ")
	p.drawFoot()
}

// refresh fills the panel again.
func (p *panel) refresh() {
	if p.reload != nil {
		p.reload()
	}
}

// close takes the panel down.
func (p *panel) close() {
	if p.u.panels[p.page] == p {
		p.u.closePage(p.page)
		if p.onClose != nil {
			p.onClose()
		}
	}
}

func (p *panel) keys(ev *tcell.EventKey) *tcell.EventKey {
	switch {
	case ev.Key() == tcell.KeyEscape || (ev.Key() == tcell.KeyRune && ev.Rune() == 'q'):
		if p.tab {
			return ev // the main screen's (u.keys)
		}
		p.close()
		return nil
	case ev.Key() == tcell.KeyRune && ev.Rune() == ':':
		p.u.showMenu()
		return nil
	case ev.Key() == tcell.KeyDelete:
		ev = tcell.NewEventKey(tcell.KeyRune, 'x', tcell.ModNone)
	case ev.Key() != tcell.KeyRune:
		if !p.selectable() {
			return nil // tview's table looks for a row to move to forever
		}
		return ev
	}
	for _, a := range p.acts {
		if a.key != ev.Rune() {
			continue
		}
		p.run(a)
		return nil
	}
	return ev
}

// run does a, to the selected row if a needs one.
func (p *panel) run(a panelAct) {
	if a.on == nil {
		a.do(nil)
		return
	}
	ref := p.selected()
	if ref == nil || !a.on(ref) {
		p.u.say("Select a row to %s.", strings.ToLower(strings.TrimSuffix(a.label, "…")))
		return
	}
	a.do(ref)
}

// pressEnter does the row's Enter: its own, or a menu of what can be
// done to it.
func (p *panel) pressEnter() {
	ref := p.selected()
	if ref == nil {
		return
	}
	if p.enter != nil {
		p.enter(ref)
		return
	}
	var acts []panelAct
	var labels []string
	for _, a := range p.acts {
		if a.on != nil && a.on(ref) {
			acts = append(acts, a)
			labels = append(labels, fmt.Sprintf("%s   (%c)", a.label, a.key))
		}
	}
	if len(acts) == 0 {
		return
	}
	p.u.choose("What to do with it?", labels, func(i int) { acts[i].do(ref) })
}
