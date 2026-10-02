package svmanager

import (
	"strings"
	"testing"

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
	h.click(h.win(), button(h.m.ui.main, text))
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
	h.m.page.tabs.Select(i)
	h.idle()
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
