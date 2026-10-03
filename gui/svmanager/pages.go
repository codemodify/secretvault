package svmanager

import (
	"fmt"
	"strings"
	"time"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svops"
)

// The right-hand pane: what is selected, the open item, and the states in
// between (nothing chosen, a locked vault, no daemon).

// message is a page that says one thing, with a button or two under it.
func (m *Manager) message(title, text string, buttons ...*widgets.Button) widget.Component {
	body := m.muted(text)
	body.Wrap = true
	col := widgets.NewColumn(heading(title), body).WithGap(gap)
	if len(buttons) > 0 {
		row := widgets.NewRow().WithGap(gap)
		for _, b := range buttons {
			row.Add(b)
		}
		col.Add(row)
	}
	return col
}

func (m *Manager) showEmpty() {
	m.ui.pane.Set(m.message("Nothing selected", "Choose an item from the list, and press Enter to open it."))
}

func (m *Manager) showNoVaults() {
	create := widgets.NewButton("New vault…", m.newVault)
	create.Primary = true
	m.ui.pane.Set(m.message("No vaults yet", "A vault holds your passwords, keys and notes, sealed with a passphrase. Make one to begin.", create))
}

func (m *Manager) showLocked() {
	v := m.vaultInfo(m.vault)
	if v == nil {
		m.showEmpty()
		return
	}
	if v.ID == "" {
		m.ui.pane.Set(m.message("Vault "+v.Name+" cannot be found", "Its folder is not where it was: is a drive or a synced folder missing? "+
			"Once the folder is back, the vault is too. The folder: "+v.Path))
		return
	}
	if m.listing {
		text := "Listing its items…"
		if v.Locked {
			text = "Waiting for its passphrase…"
		}
		m.ui.pane.Set(m.message("Vault "+v.Name, text))
		return
	}
	if !v.Locked {
		// Unlocked by another program since this one last listed it, or
		// listing it failed: listing it may mean proving this program
		// knows the passphrase too, so it waits to be asked.
		show := widgets.NewButton("Show its items", func() { m.showVault(v.Name, true) })
		show.Primary = true
		m.ui.pane.Set(m.message("Vault "+v.Name+" is unlocked",
			"Another program unlocked it. This window shows its items once you have typed its passphrase here too.", show))
		return
	}
	unlock := widgets.NewButton("Unlock…", func() { m.unlockVault(v.Name) })
	unlock.Primary = true
	m.ui.pane.Set(m.message("Vault "+v.Name+" is locked",
		"Unlocking asks for its passphrase, in a window of its own.", unlock))
}

func (m *Manager) showGone() {
	again := widgets.NewButton("Reconnect", m.reconnect)
	again.Primary = true
	why := m.goneWhy
	if why == "" {
		why = svops.DaemonNotRunning
	}
	m.ui.pane.Set(m.message("Not connected",
		why+" Nothing can be shown or changed until it is back: Reconnect tries to start it.", again))
	m.drawItems()
	m.drawStatus()
}

// showSelected shows what the list knows of the selected item, or that
// nothing is selected.
func (m *Manager) showSelected() {
	// Whatever the pane showed goes: an item that was open is wiped, not
	// left held behind a preview.
	m.dropItem()
	switch v := m.vaultInfo(m.vault); {
	case m.gone:
		m.showGone()
		return
	case m.vault == "" && len(m.vaults) == 0:
		m.showNoVaults()
		return
	case v != nil && !m.listed:
		m.showLocked()
		return
	}
	e := m.entry(m.cursor)
	if e == nil {
		m.showEmpty()
		return
	}
	m.ui.view = m.newItemView(e, viewPreview, nil)
	m.ui.pane.Set(m.ui.view.root)
}

// showItem shows the open item.
func (m *Manager) showItem(reveal bool) {
	if m.ui.view != nil {
		m.ui.view.forget()
	}
	m.ui.view = m.newItemView(m.cur, viewOpen, m.otp)
	if reveal {
		m.ui.view.toggleAll()
	}
	m.ui.pane.Set(m.ui.view.root)
	m.drawCodes()
	m.enableMenus()
	m.syncCapture()
}

// Kinds of page that stay up while the list changes under them.
const (
	pageEditor  = "editor"
	pageHistory = "history"
	pageVault   = "vault"
)

// page is a page with keys of its own (Escape goes back, Ctrl+S saves),
// which it sees before the window's.
type page struct {
	widget.Base
	kind  string
	onKey func(widget.KeyEvent) bool
}

func newPage(kind string, child widget.Component, onKey func(widget.KeyEvent) bool) *page {
	p := &page{kind: kind, onKey: onKey}
	p.Init(p)
	p.Add(child)
	return p
}

func (p *page) Measure(c layout.Constraints) paintengine2d.Point {
	return p.Children()[0].Measure(c)
}

func (p *page) Arrange(b paintengine2d.Rect) {
	p.SetBounds(b)
	p.Children()[0].Arrange(paintengine2d.XYWH(0, 0, b.Dx(), b.Dy()))
}

func (p *page) KeyPress(e widget.KeyEvent) bool { return p.onKey != nil && p.onKey(e) }

// MinWidth is the page's floor (widget.MinWidther): what it holds.
func (p *page) MinWidth() float32 { return widget.MinWidthOf(p.Children()[0]) }

// showing reports whether the pane shows a page of that kind.
func (m *Manager) showing(kind string) bool {
	p, ok := m.ui.pane.Page().(*page)
	return ok && p.kind == kind
}

// showingVaultPage reports whether a page is up in place of the items:
// the vault's, or the keys', the contacts' or the desktop's (tabbed.go).
// Whatever acts on an item waits while one is.
func (m *Manager) showingVaultPage() bool {
	_, ok := m.ui.main.Page().(*page)
	return ok
}

func (m *Manager) showingHistory() bool { return m.showing(pageHistory) }

// drawCodes puts the current one-time codes up, and how long they last.
func (m *Manager) drawCodes() {
	v := m.ui.view
	if !v.open() {
		return
	}
	now := m.now()
	for _, cr := range v.codes {
		if cr.key == nil {
			continue
		}
		code, left := cr.key.Code(now)
		// The code comes from svotp as a string; it is shown from a
		// buffer of its own, so it is not kept in the shape cache.
		clear(cr.buf)
		cr.buf = append(cr.buf[:0], groupCode(code)...)
		cr.text.SetValue(cr.buf)
		if cr.key.Type == "totp" {
			secs := int((left + time.Second - 1) / time.Second)
			cr.bar.SetValue(float32(left) / float32(time.Duration(cr.key.Period)*time.Second))
			cr.left.SetText(fmt.Sprintf("%d s", secs))
		} else {
			cr.bar.SetVisible(false)
			cr.left.SetText("counter " + fmt.Sprint(cr.key.Counter))
		}
	}
}

// groupCode splits a numeric code in two for reading: "123 456".
func groupCode(code string) string {
	if len(code) < 6 || strings.Trim(code, "0123456789") != "" {
		return code
	}
	h := len(code) / 2
	return code[:h] + " " + code[h:]
}

// toggleRevealAll is Ctrl+R: the concealed values of what the pane shows
// (the open item, the revision open in its history, the editor), all
// shown or all hidden. An item that is only selected is opened, revealed.
func (m *Manager) toggleRevealAll() {
	switch {
	case m.editor != nil:
		m.editor.toggleReveal()
	case m.showingHistory():
		// In the history, the revision shown is what Ctrl+R is about.
		if m.hist != nil && m.hist.view != nil {
			m.hist.view.toggleAll()
		}
	case m.ui.view.open():
		m.ui.view.toggleAll()
	case m.cursor != "" && m.editor == nil && !m.showingVaultPage():
		m.openItem(m.cursor, true)
	}
}
