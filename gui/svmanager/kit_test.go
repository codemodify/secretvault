package svmanager

import (
	"strings"
	"testing"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"
)

// Helpers for driving the dialogs and pages, as a person does: fields
// are found by the names a screen reader reads, typed into with the
// keyboard, and buttons clicked.

// accessible is a widget with a name for assistive technology.
type accessible interface {
	widget.Component
	AccessibleName() string
}

// named is the widget of type T under root that a screen reader calls
// name.
func named[T accessible](h *harness, root widget.Component, name string) T {
	h.t.Helper()
	var zero T
	if root == nil {
		h.t.Fatalf("no dialog up to find %q in; the window says:\n%s", name, h.text())
		return zero
	}
	got := find(root, func(c T) bool { return c.AccessibleName() == name })
	if any(got) == any(zero) {
		h.t.Fatalf("no %T named %q; the window says:\n%s", zero, name, h.text())
	}
	return got
}

// fill types text into the field of the dialog up that is named name,
// replacing what it held: a line of text or a secret.
func (h *harness) fill(name, text string) {
	h.t.Helper()
	root := h.overlay()
	var target widget.Component
	if f := find(root, func(c *widgets.TextField) bool { return c.AccessibleName() == name }); f != nil {
		f.SetText("")
		target = f
	} else if f := find(root, func(c *widgets.SecretField) bool { return c.AccessibleName() == name }); f != nil {
		f.Wipe()
		target = f
	} else if f := find(root, func(c *widgets.SecretArea) bool { return c.AccessibleName() == name }); f != nil {
		f.Wipe()
		target = f
	} else {
		h.t.Fatalf("no field named %q; the window says:\n%s", name, h.text())
	}
	h.win().FocusOn(target)
	h.win().Type(text)
	h.pump()
}

// choose picks entry i of the drop-down list or the radio buttons named
// name in the dialog up.
func (h *harness) choose(name string, i int) {
	h.t.Helper()
	root := h.overlay()
	if c := find(root, func(c *widgets.ComboBox) bool { return c.AccessibleName() == name }); c != nil {
		c.Selected = i
		if c.OnChange != nil {
			c.OnChange(i)
		}
		c.Invalidate()
		return
	}
	if g := find(root, func(c *widgets.RadioGroup) bool { return c.AccessibleName() == name }); g != nil {
		g.Select(i)
		return
	}
	h.t.Fatalf("no choice named %q; the window says:\n%s", name, h.text())
}

// tick sets the checkbox of the dialog up that says text.
func (h *harness) tick(text string, on bool) {
	h.t.Helper()
	c := find(h.overlay(), func(c *widgets.Checkbox) bool { return strings.HasPrefix(c.Text, text) })
	if c == nil {
		h.t.Fatalf("no checkbox %q; the window says:\n%s", text, h.text())
	}
	if c.Checked != on {
		h.win().ClickComponent(c)
		h.pump()
	}
}

// press clicks the button of the dialog up labelled text.
func (h *harness) press(text string) {
	h.t.Helper()
	h.click(h.win(), button(h.overlay(), text))
	h.pump()
}

// pressOn clicks the button labelled text on the page up.
func (h *harness) pressOn(text string) {
	h.t.Helper()
	h.idle() // a tab being filled again replaces its buttons
	h.click(h.main(), button(h.area(), text))
	h.pump()
}

// said waits for the status bar, or the dialog up, to say want.
func (h *harness) said(want string) {
	h.t.Helper()
	h.waitFor("being told "+want, func() bool {
		return strings.Contains(h.m.ui.message, want) || strings.Contains(h.text(), want)
	})
}

// problem is what the dialog up says is wrong.
func (h *harness) problem() string {
	h.t.Helper()
	var p string
	widget.Walk(h.overlay(), func(c widget.Component) {
		if l, ok := c.(*widgets.Label); ok && l.Tone == widgets.ToneDanger && l.Text != "" {
			p = l.Text
		}
	})
	return p
}

// failed waits for the dialog up to say what went wrong, and returns it.
func (h *harness) failed() string {
	h.t.Helper()
	h.waitFor("the dialog to say what went wrong", func() bool { return h.problem() != "" })
	return h.problem()
}

// tab shows tab i of the page up and waits for it to be filled.
func (h *harness) tab(i int) {
	h.t.Helper()
	h.m.selectTab(h.shownPage(), i)
	h.idle()
}

// pressTool clicks the button of an icon alone named name (its name for
// a screen reader) in the window's tab shown.
func (h *harness) pressTool(name string) {
	h.t.Helper()
	h.idle()
	b := h.toolButton(name)
	if b == nil {
		h.t.Fatalf("no %q button; the window says:\n%s", name, h.text())
	}
	for range 3 {
		h.pump()
	}
	if !h.main().ClickComponent(b) {
		h.t.Fatalf("button %q has no box to click", name)
	}
	h.pump()
}

// area is what the window's tab shown holds: the Vaults tab's items or
// page, or the Disks or the Tools tab's page.
func (h *harness) area() widget.Component {
	switch h.m.section() {
	case secDisks:
		return h.m.ui.disksHost
	case secTools:
		return h.m.ui.toolsHost
	case secSettings:
		return h.m.ui.settingsHost
	}
	return h.m.ui.vaultTab
}

// listItems are the names of the items the list shows, in its order.
func (h *harness) listItems() []string {
	var out []string
	for i := range h.m.ui.content.Count {
		out = append(out, h.m.entries[h.m.shown[i]].Item.Name)
	}
	return out
}

// listRows are the list's rows as it shows them.
func (h *harness) listRows() []string {
	var out []string
	for i := range h.m.ui.content.Count {
		out = append(out, h.m.rowText(i))
	}
	return out
}

// pickRow picks the item named in the list, as a click does, with Ctrl
// or Shift held if mods says so; a plain click's item has its kind's tab
// brought forward first.
func (h *harness) pickRow(name string, mods platform.Modifiers) {
	h.t.Helper()
	if e := h.m.entry(name); e != nil && mods == 0 {
		if t := tabOf(e); t >= 0 && t != h.m.itemTab {
			h.m.ui.vaultTabs.Select(t)
			h.pump()
		}
	}
	i := h.m.rowOf(name)
	if i < 0 {
		h.t.Fatalf("no %s in the list: %q", name, h.listItems())
	}
	l := h.m.ui.content
	l.EnsureVisible(i)
	h.pump()
	b := l.Bounds()
	for y := float32(0); y < b.Dy(); y++ {
		if p := paintengine2d.Pt(b.Dx()/3, y); l.RowAt(p) == i {
			l.MousePress(widget.MouseEvent{Pos: p, Button: platform.ButtonLeft, Mods: mods})
			l.MouseRelease(widget.MouseEvent{Pos: p, Button: platform.ButtonLeft, Mods: mods})
			h.pump()
			return
		}
	}
	h.t.Fatalf("row %d of the list is not on screen", i)
}

// shownPage is the page of tabs in the window's tab shown.
func (h *harness) shownPage() *tabbedPage {
	switch {
	case h.m.section() == secDisks && h.m.disks != nil:
		return h.m.disks.tabbedPage
	case h.m.section() == secTools && h.m.tpage != nil:
		return h.m.tpage.tabbedPage
	}
	return h.m.page
}

// secrets are the secrets the dialog up shows, as they are held.
func (h *harness) secrets() []*secretText {
	var out []*secretText
	widget.Walk(h.overlay(), func(c widget.Component) {
		if s, ok := c.(*secretText); ok {
			out = append(out, s)
		}
	})
	return out
}

// escape presses Escape.
func (h *harness) escape() {
	h.win().Press(platform.KeyEscape)
	h.pump()
}

func TestHarnessFindsByName(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.waitText("Vault personal is locked")
	h.m.newVault()
	h.pump()
	h.fill("Name", "x")
	if f := named[*widgets.TextField](h, h.overlay(), "Name"); f.Text != "x" {
		t.Fatalf("typed %q", f.Text)
	}
}

// until waits for cond, answering the daemon's question for a passphrase
// with passphrase whenever it asks one: a vault unlocked by another
// program meanwhile has this one prove itself again.
func (h *harness) until(what, passphrase string, cond func() bool) {
	h.t.Helper()
	h.waitFor(what, func() bool {
		if d := h.m.asking; d != nil && d.win != nil && !d.answered {
			d.win.Type(passphrase)
			d.win.Press(platform.KeyReturn)
		}
		return cond()
	})
}

// toolButton is the icon button named name in the window, its title bar
// or the drop-down up, or nil.
func (h *harness) toolButton(name string) *widgets.ToolButton {
	is := func(b *widgets.ToolButton) bool { return b.AccessibleName() == name }
	for _, root := range []widget.Component{h.main().Content(), h.main().TitleBar(), h.dropUp()} {
		if root == nil {
			continue
		}
		if b := find(root, is); b != nil {
			return b
		}
	}
	return nil
}

// dropUp is what a breadcrumb opened, up: the toolkit's menu, or the
// vaults' drop-down; nil when nothing is.
func (h *harness) dropUp() widget.Component {
	if d := h.m.ui.title.drop; d != nil {
		return d
	}
	if p, ok := h.main().Popup().(*widgets.PopupMenu); ok && !p.Dead() {
		return p
	}
	return nil
}

// closeDrop takes down what a breadcrumb opened.
func (h *harness) closeDrop() {
	h.m.closeDrop()
	if p, ok := h.main().Popup().(*widgets.PopupMenu); ok {
		widget.DismissPopup(p)
	}
	h.pump()
}

// crumbs is the title bar's breadcrumbs.
func (h *harness) crumbs() *widgets.Breadcrumbs {
	return find(h.main().TitleBar(), func(*widgets.Breadcrumbs) bool { return true })
}

// crumbTexts are the title bar's breadcrumbs.
func (h *harness) crumbTexts() []string {
	h.idle()
	var out []string
	for _, c := range h.crumbs().Crumbs {
		out = append(out, c.Text)
	}
	return out
}

// crumb is the breadcrumb that says text, and its place, or nil.
func (h *harness) crumb(text string) (*widgets.Crumb, int) {
	b := h.crumbs()
	for i := range b.Crumbs {
		if b.Crumbs[i].Text == text {
			return &b.Crumbs[i], i
		}
	}
	return nil, -1
}

// openCrumb opens what the breadcrumb that says text opens, as a click on
// it does.
func (h *harness) openCrumb(text string) {
	h.t.Helper()
	h.idle()
	c, i := h.crumb(text)
	if c == nil || c.Menu == nil && c.OnClick == nil {
		h.t.Fatalf("no breadcrumb %q to open: %q", text, h.crumbTexts())
	}
	b := h.crumbs()
	r := b.CrumbRect(i)
	at := paintengine2d.Pt((r.Min.X+r.Max.X)/2, (r.Min.Y+r.Max.Y)/2)
	b.MousePress(widget.MouseEvent{Pos: at, Button: platform.ButtonLeft})
	b.MouseRelease(widget.MouseEvent{Pos: at, Button: platform.ButtonLeft})
	h.pump()
	if h.dropUp() == nil {
		h.t.Fatalf("breadcrumb %q opened nothing", text)
	}
}

// dropRows are the rows of the menu up: each one's text, and its count or
// state after a space.
func (h *harness) dropRows() []string {
	var out []string
	if p, ok := h.dropUp().(*widgets.PopupMenu); ok {
		for _, it := range p.Items {
			if it.Separator {
				continue
			}
			s := it.Text
			if it.Shortcut != "" {
				s += " " + it.Shortcut
			}
			out = append(out, s)
		}
	}
	return out
}

// pickDrop picks the row of the menu up that says text, as a click.
func (h *harness) pickDrop(text string) {
	h.t.Helper()
	p, ok := h.dropUp().(*widgets.PopupMenu)
	if !ok {
		h.t.Fatalf("no menu up")
	}
	for _, it := range p.Items {
		if it.Text == text && !it.Separator {
			widget.DismissPopup(p)
			it.OnClick()
			h.pump()
			return
		}
	}
	h.t.Fatalf("no %q in the menu: %q", text, h.dropRows())
}
