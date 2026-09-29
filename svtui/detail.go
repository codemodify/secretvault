package svtui

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svotp"
	"github.com/codemodify/secretvault/svrpc"
)

// detailRow is one line of an item's view.
type detailRow struct {
	label   string // the left column
	heading bool   // a section heading: label only, across the pane
	text    string // the value, when it is not a revealed secret
	secret  []byte // the value, when it is a revealed secret: drawn from its bytes
	style   tcell.Style
	note    string // shown dimmed after the value (a field's type)
	field   int    // the item field this row shows, or -1
}

func (r detailRow) blank() bool { return r.label == "" && r.text == "" && r.secret == nil }

// detailView shows an item as rows of label and value, scrolls, and lets
// a row be selected (to copy that field). It is drawn by hand so that
// revealed secrets go from their bytes straight to the screen.
type detailView struct {
	*tview.Box
	rows     []detailRow
	empty    string // shown when there are no rows
	offset   int
	selected int // -1: none
}

func newDetailView() *detailView {
	return &detailView{Box: tview.NewBox(), selected: -1}
}

// setRows replaces the rows, keeping the selection where it was. The rows
// share the item's secret bytes; whoever wipes the item wipes those.
func (d *detailView) setRows(rows []detailRow) {
	d.rows = rows
	if d.selected >= len(rows) {
		d.selected = -1
	}
}

// reset shows nothing but the text empty.
func (d *detailView) reset(empty string) {
	d.rows, d.empty, d.offset, d.selected = nil, empty, 0, -1
}

// selectedField is the item field of the selected row, or -1.
func (d *detailView) selectedField() int {
	if d.selected < 0 || d.selected >= len(d.rows) {
		return -1
	}
	return d.rows[d.selected].field
}

func (d *detailView) Draw(screen tcell.Screen) {
	d.Box.DrawForSubclass(screen, d)
	x, y, width, height := d.GetInnerRect()
	if width < 3 || height < 1 {
		return
	}
	x, width = x+1, width-2
	if len(d.rows) == 0 {
		for i, line := range strings.Split(d.empty, "\n") {
			if i >= height {
				break
			}
			tview.Print(screen, line, x, y+i, width, tview.AlignLeft, tcell.ColorGray)
		}
		return
	}
	if d.selected >= 0 {
		if d.selected < d.offset {
			d.offset = d.selected
		}
		if d.selected >= d.offset+height {
			d.offset = d.selected - height + 1
		}
	}
	d.offset = max(0, min(d.offset, len(d.rows)-height))
	labelWidth := 0
	for _, r := range d.rows {
		if !r.heading {
			labelWidth = max(labelWidth, tview.TaggedStringWidth(tview.Escape(r.label)))
		}
	}
	labelWidth = min(labelWidth, max(8, width/3))
	for i := 0; i < height && d.offset+i < len(d.rows); i++ {
		r := d.rows[d.offset+i]
		row := y + i
		style := r.style
		if d.offset+i == d.selected && d.HasFocus() {
			style = style.Background(tview.Styles.ContrastBackgroundColor)
			for c := range width {
				screen.SetContent(x+c, row, ' ', nil, style)
			}
		}
		if r.heading {
			tview.Print(screen, "[::b]"+tview.Escape(r.label), x, row, width, tview.AlignLeft, tview.Styles.TertiaryTextColor)
			continue
		}
		tview.Print(screen, tview.Escape(r.label), x, row, labelWidth, tview.AlignLeft, tview.Styles.SecondaryTextColor)
		vx := x + labelWidth + 2
		room := x + width - vx
		if room <= 0 {
			continue
		}
		if r.secret != nil {
			vx += drawSecret(screen, r.secret, vx, row, room, style)
		} else {
			fg, _, _ := style.Decompose()
			_, used := tview.Print(screen, tview.Escape(r.text), vx, row, room, tview.AlignLeft, fg)
			vx += used
		}
		if r.note != "" && x+width-vx > 2 {
			tview.Print(screen, "  "+tview.Escape(r.note), vx, row, x+width-vx, tview.AlignLeft, tcell.ColorGray)
		}
	}
}

// move selects the next row (by delta) that is not blank or a heading.
func (d *detailView) move(delta int) {
	i := d.selected
	for range len(d.rows) {
		i += delta
		if i < 0 || i >= len(d.rows) {
			return
		}
		if !d.rows[i].blank() && !d.rows[i].heading {
			d.selected = i
			return
		}
	}
}

func (d *detailView) InputHandler() func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
	return d.WrapInputHandler(func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
		_, _, _, height := d.GetInnerRect()
		switch event.Key() {
		case tcell.KeyDown:
			d.move(1)
		case tcell.KeyUp:
			d.move(-1)
		case tcell.KeyHome:
			d.selected = -1
			d.move(1)
		case tcell.KeyEnd:
			d.selected = len(d.rows)
			d.move(-1)
		case tcell.KeyPgDn:
			for range max(1, height-1) {
				d.move(1)
			}
		case tcell.KeyPgUp:
			for range max(1, height-1) {
				d.move(-1)
			}
		}
	})
}

func (d *detailView) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
	return d.WrapMouseHandler(func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
		if !d.InRect(event.Position()) {
			return false, nil
		}
		switch action {
		case tview.MouseLeftDown:
			setFocus(d)
			_, y, _, _ := d.GetInnerRect()
			_, my := event.Position()
			if i := d.offset + my - y; i >= 0 && i < len(d.rows) && !d.rows[i].blank() && !d.rows[i].heading {
				d.selected = i
			}
			return true, nil
		case tview.MouseScrollUp:
			d.offset = max(0, d.offset-1)
			return true, nil
		case tview.MouseScrollDown:
			d.offset++
			return true, nil
		}
		return false, nil
	})
}

// secretType reports whether values of field type t are typed and kept
// as secrets: concealed values, keys, and one-time password keys.
func secretType(t string) bool {
	return t == svcore.FieldConcealed || t == svcore.FieldKey || t == svcore.FieldOTP
}

// itemRows lays an item out for the item view. Concealed and key values
// are masked unless reveal is set; otp fields show their current code
// (from keys, by field index) and how long it lasts.
func itemRows(e *svrpc.Entry, reveal bool, keys map[int]*svotp.Key, now time.Time) []detailRow {
	plain := tcell.StyleDefault.Foreground(tview.Styles.PrimaryTextColor)
	var rows []detailRow
	add := func(label, text string) {
		rows = append(rows, detailRow{label: label, text: text, style: plain, field: -1})
	}
	if n := len(e.Conflicts); n > 0 {
		rows = append(rows, detailRow{label: "conflict", field: -1, style: plain.Foreground(tcell.ColorRed),
			text: fmt.Sprintf("%d other version(s) were saved at the same time; this is the newest (h: history)", n)})
	}
	if e.Deleted {
		rows = append(rows, detailRow{label: "deleted", field: -1, style: plain.Foreground(tcell.ColorRed), text: "this revision deleted the item"})
	}
	add("kind", e.Item.Kind)
	add("name", e.Item.Name)
	if e.Item.Label != "" {
		add("label", e.Item.Label)
	}
	if len(e.Item.Tags) > 0 {
		add("tags", strings.Join(e.Item.Tags, ", "))
	}
	if !e.Time.IsZero() {
		add("changed", e.Time.Local().Format("2006-01-02 15:04")+"  revision "+short(e.Rev))
	}
	if len(e.Item.Attrs) > 0 {
		rows = append(rows, detailRow{field: -1}, detailRow{label: "Attributes", heading: true, field: -1})
		keys := make([]string, 0, len(e.Item.Attrs))
		for k := range e.Item.Attrs {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		for _, k := range keys {
			add(k, e.Item.Attrs[k])
		}
	}
	if len(e.Item.Fields) > 0 {
		rows = append(rows, detailRow{field: -1}, detailRow{label: "Fields", heading: true, field: -1})
	}
	for i, f := range e.Item.Fields {
		row := detailRow{label: f.Name, style: plain, field: i}
		switch f.Type {
		case svcore.FieldConcealed, svcore.FieldKey:
			row.note = f.Type
			if !reveal {
				row.text = mask
				rows = append(rows, row)
				continue
			}
			for j, line := range bytes.Split(f.Value, []byte("\n")) {
				if j > 0 {
					row.label, row.note = "", ""
				}
				row.secret = line
				if len(line) == 0 {
					row.secret, row.text = nil, " "
				}
				rows = append(rows, row)
			}
		case svcore.FieldOTP:
			row.note = "one-time code"
			if k := keys[i]; k != nil {
				code, left := k.Code(now)
				row.text = groupCode(code)
				if k.Type == "totp" {
					row.note = fmt.Sprintf("%ds left", int((left+time.Second-1)/time.Second))
				}
			} else {
				row.text, row.note = "(not a usable one-time password key)", ""
			}
			rows = append(rows, row)
			if reveal {
				rows = append(rows, detailRow{secret: f.Value, style: plain, field: i, note: "key"})
			} else {
				rows = append(rows, detailRow{text: mask, style: plain, field: i, note: "key"})
			}
		case svcore.FieldBinary:
			row.text, row.note = fmt.Sprintf("%d bytes", len(f.Value)), f.Type
			rows = append(rows, row)
		default:
			if f.Type != svcore.FieldText {
				row.note = f.Type
			}
			for j, line := range strings.Split(string(f.Value), "\n") {
				if j > 0 {
					row.label, row.note = "", ""
				}
				row.text = line
				if line == "" {
					row.text = " "
				}
				rows = append(rows, row)
			}
		}
	}
	return rows
}

// parseOTP reads an otp field: an otpauth:// URI, or a bare base32 seed
// (a 30-second, six-digit TOTP key, as authenticator apps assume).
func parseOTP(v []byte) (*svotp.Key, error) {
	// svotp reads strings, so the key briefly becomes one here.
	s := strings.TrimSpace(string(v))
	if len(s) > 8 && strings.EqualFold(s[:8], "otpauth:") {
		return svotp.Parse(s)
	}
	secret, err := svotp.DecodeSecret(s)
	if err != nil {
		return nil, err
	}
	return &svotp.Key{Type: "totp", Secret: secret, Algorithm: "SHA1", Digits: 6, Period: 30}, nil
}

// groupCode splits a numeric code in two for reading: "123 456".
func groupCode(code string) string {
	if len(code) < 6 || strings.Trim(code, "0123456789") != "" {
		return code
	}
	h := len(code) / 2
	return code[:h] + " " + code[h:]
}

func short(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}
