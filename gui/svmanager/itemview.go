package svmanager

import (
	"fmt"
	"slices"
	"strings"

	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svrpc"
)

// viewMode is what an item view shows of an item.
type viewMode int

const (
	viewPreview  viewMode = iota // what the list knows: everything but the fields
	viewOpen                     // all of it, fetched: the open item
	viewRevision                 // one revision from its history, read-only
)

// itemView is an item on the page. It shares the item's secret bytes;
// whoever wipes the item wipes those, and forget lets go of them.
type itemView struct {
	m       *Manager
	e       *svrpc.Entry
	mode    viewMode
	keys    map[int]*svotp.Key // one-time password keys, by field
	secrets map[int]*secretRow
	codes   map[int]*codeRow
	root    *widgets.ScrollView
}

// open reports whether the view shows the open item.
func (v *itemView) open() bool { return v != nil && v.mode == viewOpen }

// secretRow is a concealed value and the button that shows it.
type secretRow struct {
	text *secretText
	show *widgets.Button
	key  bool // the key of a one-time password
}

// codeRow is a one-time password: the code, drawn from a buffer of its
// own, and how long it has left.
type codeRow struct {
	key  *svotp.Key
	buf  []byte
	text *secretText
	bar  *widgets.ProgressBar
	left *widgets.Label
}

func (m *Manager) newItemView(e *svrpc.Entry, mode viewMode, keys map[int]*svotp.Key) *itemView {
	v := &itemView{m: m, e: e, mode: mode, keys: keys, secrets: map[int]*secretRow{}, codes: map[int]*codeRow{}}
	col := widgets.NewColumn().WithGap(gap)

	if mode != viewRevision {
		// As the list shows it; its whole name, which references and the
		// CLI use, under it when that is longer.
		shown := m.shownName(e.Item.Name)
		title := newDisplayHeading(shown)
		col.Add(title)
		if shown != e.Item.Name {
			col.Add(m.muted("Full name: " + e.Item.Name))
		}
	}
	sub := svops.KindText(e.Item.Kind)
	if e.Item.Label != "" {
		sub += " · " + e.Item.Label
	}
	col.Add(m.muted(sub))

	if n := len(e.Conflicts); n > 0 && mode != viewRevision {
		text := "1 other version was saved at the same time as this one, on another device. This one won (it is the newest); " +
			"the other is kept, and the history shows it."
		if n > 1 {
			text = fmt.Sprintf("%d other versions were saved at the same time as this one, on other devices. "+
				"This one won (it is the newest); the others are kept, and the history shows them.", n)
		}
		warn := toned(text, widgets.ToneWarning)
		warn.Wrap = true
		col.Add(warn)
	}
	if e.Deleted {
		col.Add(toned("This revision deleted the item.", widgets.ToneDanger))
	}

	if mode != viewRevision {
		actions := widgets.NewWrap()
		if mode == viewOpen {
			if _, ok := secretField(&e.Item); ok {
				cp := newButton("Copy password", m.copySecret)
				cp.Primary = true
				cp.Tip = "Ctrl+C; it clears from the clipboard by itself"
				actions.Add(cp)
			}
		} else {
			o := newButton("Open", m.openSelected)
			o.Primary = true
			o.Tip = "Enter"
			actions.Add(o)
		}
		if !svops.IsPasskey(&e.Item) {
			actions.Add(tip(newButton("Edit", m.editItem), "Ctrl+E"))
		}
		actions.Add(tip(newButton("History", m.showHistory), "Ctrl+H"))
		if !svops.IsPasskey(&e.Item) {
			actions.Add(tip(newButton("Copy reference…", m.copyReference), "Names this secret for scripts and settings files, without holding it"))
		}
		actions.Add(tip(newButton("Rename…", m.renameItem), "F2"))
		actions.Add(tip(newButton("Move to vault…", func() { m.moveItem(false) }), "Shows what would go before anything moves"))
		actions.Add(tip(newButton("Copy to vault…", func() { m.moveItem(true) }), "Shows what would go before anything is copied"))
		actions.Add(tip(newButton("Delete…", m.deleteItem), "Delete"))
		if e.Item.Kind == "container" {
			vault, name := m.vault, e.Item.Name
			actions.Add(tip(newButton("Show the disk", func() { m.showDiskOf(vault, name) }), "The disk this is the key of, in the Disk tab"))
		}
		col.Add(actions)
	}

	if svops.IsPasskey(&e.Item) && mode != viewPreview {
		col.Add(section(m, "Passkey"))
		g := widgets.NewGrid()
		g.Cols = []widgets.Track{widgets.Auto(), widgets.Flex(1)}
		g.ColGap = 16
		for i, r := range svops.PasskeySummary(&e.Item) {
			g.Place(m.muted(r.Label), i, 0)
			g.Place(widgets.NewLabel(r.Value), i, 1)
		}
		col.Add(g)
		n := m.muted(svops.PasskeyKeyNote)
		n.Wrap = true
		col.Add(n)
	}

	if mode == viewPreview {
		n := m.muted("Enter opens it. Its fields are fetched from the vault only then, and every fetch goes in the vault's audit log.")
		n.Wrap = true
		col.Add(n)
	} else if len(e.Item.Fields) > 0 {
		col.Add(section(m, "Fields"))
		col.Add(v.fieldGrid())
	}

	if len(e.Item.Tags) > 0 {
		col.Add(section(m, "Tags"))
		col.Add(widgets.NewLabel(strings.Join(e.Item.Tags, ", ")))
	}
	if len(e.Item.Attrs) > 0 {
		col.Add(section(m, "Attributes"))
		g := widgets.NewGrid()
		g.Cols = []widgets.Track{widgets.Auto(), widgets.Flex(1)}
		g.ColGap = 16
		for i, k := range sortedKeys(e.Item.Attrs) {
			g.Place(m.muted(k), i, 0)
			g.Place(widgets.NewLabel(e.Item.Attrs[k]), i, 1)
		}
		col.Add(g)
	}

	if mode != viewRevision {
		col.Add(section(m, "Files"))
		col.Add(v.fileList())
	}

	if !e.Time.IsZero() {
		foot := "Changed " + e.Time.Local().Format("2006-01-02 15:04") + " · revision " + short(e.Rev)
		if e.Signature.Status != "" || len(e.Device) >= 8 {
			foot += " · " + svops.Author(*e)
		}
		fl := m.muted(foot)
		fl.Wrap = true
		col.Add(fl)
	}
	v.root = widgets.NewScrollView(col)
	return v
}

// tip gives a button its hover help.
func tip(b *widgets.Button, s string) *widgets.Button {
	b.Tip = s
	return b
}

// section is a heading inside a page: a spaced-out label in the accent,
// as the look's small headings are, over a rule.
func section(m *Manager, title string) widget.Component {
	return widgets.NewColumn(toned(strings.ToUpper(title), widgets.ToneAccent), widgets.NewSeparator()).WithGap(4).WithPadding(0, 8, 0, 0)
}

// fieldGrid lays the item's fields out: name, value, and what can be done
// with it.
func (v *itemView) fieldGrid() widget.Component {
	m := v.m
	g := widgets.NewGrid()
	// The values' column is offered its share to wrap to: a long
	// password or key shown wraps there rather than running past it.
	g.Cols = []widgets.Track{widgets.Auto(), widgets.Share(1), widgets.Auto()}
	g.ColGap, g.RowGap = 16, 6
	row := 0
	for i, f := range v.e.Item.Fields {
		if svops.PasskeyHidden(&v.e.Item, f) {
			continue // a passkey's key is never shown
		}
		g.Place(widgets.NewLabel(f.Name), row, 0)
		buttons := widgets.NewRow().WithGap(4)
		switch f.Type {
		case svcore.FieldConcealed, svcore.FieldKey:
			buttons.Add(v.secretCell(g, row, i, f, false))
			buttons.Add(newButton("Copy", func() { v.copyField(i) }))
		case svcore.FieldOTP:
			if k := v.keys[i]; k != nil && v.mode == viewOpen {
				cr := &codeRow{key: k, text: newCodeText(), bar: widgets.NewProgressBar(0), left: m.muted("")}
				cr.text.SetAccessibleName(f.Name)
				v.codes[i] = cr
				g.Place(widgets.NewRow(cr.text, cr.bar, cr.left).WithGap(gap).WithAlign(layout.AlignCenter), row, 1)
				buttons.Add(tip(newButton("Copy", m.copyCode), "Ctrl+T"))
				g.Place(buttons, row, 2)
				// The key itself stays hidden, and can be shown like any
				// other secret, a row down.
				row++
				g.Place(m.muted("key"), row, 0)
				buttons = widgets.NewRow().WithGap(4)
			} else if v.mode == viewOpen {
				g.Place(toned("not a usable one-time password key", widgets.ToneDanger), row, 1)
				g.Place(buttons, row, 2)
				row++
				g.Place(m.muted("key"), row, 0)
				buttons = widgets.NewRow().WithGap(4)
			}
			buttons.Add(v.secretCell(g, row, i, f, true))
		case svcore.FieldBinary:
			g.Place(m.muted(fmt.Sprintf("%d bytes", len(f.Value))), row, 1)
		default:
			val := widgets.NewLabel(string(f.Value))
			val.Wrap = true
			g.Place(val, row, 1)
			if len(f.Value) > 0 {
				buttons.Add(newButton("Copy", func() { v.copyField(i) }))
			}
		}
		g.Place(buttons, row, 2)
		row++
	}
	return g
}

// secretCell puts field i's value, masked, in the grid, and returns the
// button that shows it.
func (v *itemView) secretCell(g *widgets.Grid, row, i int, f svrpc.Field, key bool) *widgets.Button {
	text := newSecretText(f.Value)
	text.wrap = true
	name := f.Name
	if key {
		name += " key"
	}
	text.SetAccessibleName(name)
	sr := &secretRow{text: text, key: key}
	sr.show = newButton(showLabel(false, key), func() { v.toggle(i) })
	sr.show.Tip = "Show or hide it (Ctrl+R: all of them)"
	v.secrets[i] = sr
	g.Place(text, row, 1)
	return sr.show
}

func showLabel(shown, key bool) string {
	switch {
	case shown && key:
		return "Hide key"
	case shown:
		return "Hide"
	case key:
		return "Show key"
	}
	return "Show"
}

// copyField copies the value of field i of the item shown.
func (v *itemView) copyField(i int) {
	if i < len(v.e.Item.Fields) {
		f := v.e.Item.Fields[i]
		v.m.copyValue(f.Value, "The "+f.Name, v.m.vault)
	}
}

// fileList is the item's files, each with a button to save it and one to
// remove it, and a button to add one.
func (v *itemView) fileList() widget.Component {
	m := v.m
	col := widgets.NewColumn().WithGap(6)
	if len(v.e.Item.Files) == 0 {
		col.Add(m.muted("No files: Add file… attaches one."))
	} else {
		g := widgets.NewGrid()
		g.Cols = []widgets.Track{widgets.Flex(1), widgets.Auto(), widgets.Auto()}
		g.ColGap, g.RowGap = 16, 6
		for i, f := range v.e.Item.Files {
			g.Place(widgets.NewLabel(f.Name), i, 0)
			g.Place(m.muted(size(f.Size)), i, 1)
			g.Place(widgets.NewRow(
				newButton("Save…", func() { m.saveFile(v.e.Item.Name, f.Name) }),
				newButton("Remove…", func() { m.removeFile(v.e.Item.Name, f.Name) }),
			).WithGap(4), i, 2)
		}
		col.Add(g)
	}
	add := newButton("Add file…", func() { m.attachFile(v.e.Item.Name) })
	col.Add(widgets.NewRow(add))
	return col
}

// size is a file size for people.
func size(n int64) string {
	switch {
	case n < 1<<10:
		return fmt.Sprintf("%d bytes", n)
	case n < 1<<20:
		return fmt.Sprintf("%.1f KiB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
}

// short is a revision, as far as people need to tell them apart.
func short(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

// toggle shows or hides field i.
func (v *itemView) toggle(i int) {
	sr := v.secrets[i]
	if sr == nil {
		return
	}
	on := !sr.text.Revealed()
	sr.text.SetReveal(on)
	sr.show.Text = showLabel(on, sr.key)
	sr.show.RequestLayout()
	sr.show.Invalidate()
	v.m.syncCapture()
}

// toggleAll shows every concealed value, or hides them all if any shows.
func (v *itemView) toggleAll() {
	anyShown := false
	for _, sr := range v.secrets {
		anyShown = anyShown || sr.text.Revealed()
	}
	for i, sr := range v.secrets {
		if sr.text.Revealed() == anyShown {
			v.toggle(i)
		}
	}
}

// revealedFields are the fields showing.
func (v *itemView) revealedFields() []int {
	if v == nil {
		return nil
	}
	var out []int
	for i, sr := range v.secrets {
		if sr.text.Revealed() {
			out = append(out, i)
		}
	}
	slices.Sort(out)
	return out
}

// reveal shows fields.
func (v *itemView) reveal(fields []int) {
	for _, i := range fields {
		if sr := v.secrets[i]; sr != nil && !sr.text.Revealed() {
			v.toggle(i)
		}
	}
}

// forget takes every value off the screen and lets go of its bytes. The
// bytes themselves are wiped by whoever holds the item.
func (v *itemView) forget() {
	for _, sr := range v.secrets {
		sr.text.Forget()
	}
	for _, cr := range v.codes {
		clear(cr.buf)
		cr.buf = nil
		cr.text.Forget()
	}
}
