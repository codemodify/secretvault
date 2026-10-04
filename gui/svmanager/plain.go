package svmanager

import (
	"strings"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svops"
)

// Asking before a change, in plain words first (docs/wording.md): the
// plan's title, its summary and what else to know, and the technical
// lines under "Show details", closed. svops says all of it, so that the
// TUI and the CLI's --dry-run say the same.

// showPlan asks before making the change p says: its summary, its notes,
// its details folded away, and a button that says what it does. apply
// runs when the person says yes; cancel, when given, when they do not (a
// plan that holds something to give back). A plan with nothing to do
// (no Action) is only shown.
func (m *Manager) showPlan(p svops.Plain, apply, cancel func()) {
	col := plainBody(m, p.Summary, p.Notes, p.Details)
	var d *dialog
	applied := false
	cancelText := "Cancel"
	if p.Action == "" {
		cancelText = "Close"
	}
	no := widgets.NewButton(cancelText, func() { d.Close() })
	no.Primary = true
	buttons := widgets.NewButtonBox()
	if p.Action != "" {
		yes := widgets.NewButton(p.Action, func() {
			applied = true
			d.Close()
			apply()
		})
		buttons.AddButton(yes, widgets.RoleAccept)
	}
	buttons.AddButton(no, widgets.RoleReject)
	d = m.showDialog(p.Title, col, buttons, no, func() {
		if !applied && cancel != nil {
			cancel()
		}
	})
}

// showDone says how a change went: what it means, in a sentence or two,
// and what was done, line by line, under "Show details".
func (m *Manager) showDone(title, summary string, details []string) {
	col := plainBody(m, summary, nil, details)
	var d *dialog
	ok := widgets.NewButton("Close", func() { d.Close() })
	d = m.showDialog(title, col, widgets.NewButtonBox().AddButton(ok, widgets.RoleAccept), ok, nil)
}

// plainBody is a summary over its notes and its details, folded away.
func plainBody(m *Manager, summary string, notes, details []string) *widgets.FlexBox {
	col := widgets.NewColumn().WithGap(12)
	if summary != "" {
		l := widgets.NewLabel(summary)
		l.Wrap = true
		col.Add(l)
	}
	for _, n := range notes {
		l := toned(n, widgets.ToneWarning)
		l.Wrap = true
		col.Add(l)
	}
	if len(details) > 0 {
		col.Add(detailsExpander(details))
	}
	return col
}

// detailsExpander folds technical lines away under "Show details".
func detailsExpander(lines []string) *widgets.Expander {
	e := widgets.NewExpander("Show details", false, newDetailText(lines))
	e.OnToggle = func(open bool) {
		e.Title = "Show details"
		if open {
			e.Title = "Hide details"
		}
		e.Invalidate()
	}
	return e
}

// detailText is technical text to read: paths, commands, file names.
// Each line is wrapped to the width it is given at its spaces and, in a
// word too long for the line (a path), after a path separator, never in
// the middle of a name unless the name alone is wider than the line; its
// continuations are indented. It is as tall as its lines: a dialog that
// holds it scrolls as a whole, so there is no small box to scroll inside.
// (uitoolkit's short text views are fit for that since v0.23.4, and break
// a long word after a separator too, uitoolkit-gaps.md 50; this reads
// better in a dialog all the same.)
type detailText struct {
	widget.Base
	lines []string
	name  string // what assistive technology calls it; "Details" when ""
}

func newDetailText(lines []string) *detailText {
	d := &detailText{lines: lines}
	d.Init(d)
	return d
}

func (d *detailText) font() *style.Font { return d.Look().MonoFont() }

// Text is all of it, a line each.
func (d *detailText) Text() string { return strings.Join(d.lines, "\n") }

func (d *detailText) Measure(c layout.Constraints) paintengine2d.Point {
	f := d.font()
	width := float32(-1)
	if c.HasMaxW() {
		width = c.MaxW
	}
	lines := wrapDetail(f.Advance, d.lines, width)
	var w float32
	for _, l := range lines {
		w = max(w, f.Advance(l))
	}
	return c.Constrain(paintengine2d.Pt(w+2, f.Height()*float32(max(1, len(lines)))))
}

// MinWidth lets it go as narrow as a dozen characters: it wraps.
func (d *detailText) MinWidth() float32 { return d.font().Advance("MMMMMMMMMMMM") }

func (d *detailText) Arrange(r paintengine2d.Rect) { d.SetBounds(r) }

func (d *detailText) Paint(ctx *paintengine2d.Context) {
	lk := d.Look()
	f := d.font()
	b := d.LocalBounds()
	ctx.Save()
	ctx.ClipRect(b)
	y := b.Min.Y
	for _, l := range wrapDetail(f.Advance, d.lines, b.Dx()-2) {
		f.Draw(ctx, l, paintengine2d.Pt(b.Min.X, y), lk.Palette().Text)
		y += f.Height()
	}
	ctx.Restore()
}

// Describe gives assistive technology the text, as its lines are written.
func (d *detailText) Describe(n *a11y.Node) {
	n.Role = a11y.RoleLabel
	n.Name = d.name
	if n.Name == "" {
		n.Name = "Details"
	}
	n.Value = d.Text()
}

// wrapDetail breaks lines to width as measured by advance: at spaces, and
// within a word too long for what is left of the line, after its last
// path separator that fits; a word with none that fits is broken where
// it must be. Continuations are indented two spaces past the line's own
// indent. A negative width breaks nothing.
func wrapDetail(advance func(string) float32, lines []string, width float32) []string {
	if width < 0 {
		return lines
	}
	var out []string
	for _, line := range lines {
		indent := line[:len(line)-len(strings.TrimLeft(line, " "))]
		cont := indent + "  "
		words := strings.Fields(line)
		cur := indent
		fresh := true // cur holds no word yet
		flush := func() {
			out = append(out, strings.TrimRight(cur, " "))
			cur, fresh = cont, true
		}
		for _, w := range words {
			for w != "" {
				try := cur + w
				if !fresh {
					try = cur + " " + w
				}
				if advance(try) <= width {
					cur, fresh = try, false
					w = ""
					continue
				}
				if !fresh && advance(cont+w) <= width {
					flush() // the word fits on a line of its own
					continue
				}
				// The word is too long for any line: as much of it as fits
				// here, up to a separator if it has one.
				lead := cur
				if !fresh {
					lead += " "
				}
				cut := fitPrefix(advance, lead, w, width)
				if cut == 0 {
					if fresh {
						cut = 1 // nothing fits: a character a line
					} else {
						flush()
						continue
					}
				}
				cur, fresh = lead+w[:cut], false
				w = w[cut:]
				flush()
			}
		}
		if !fresh || len(out) == 0 || cur != cont {
			out = append(out, strings.TrimRight(cur, " "))
		}
	}
	return out
}

// fitPrefix is how many bytes of w fit after lead in width: up to just
// after the last path separator that fits; with none, after the last
// other mark a name breaks well at (a dot, a dash); with none of those,
// as many whole characters as fit.
func fitPrefix(advance func(string) float32, lead, w string, width float32) int {
	best, slash, mark := 0, 0, 0
	for i, r := range w {
		end := i + len(string(r))
		if advance(lead+w[:end]) > width {
			break
		}
		best = end
		switch r {
		case '/', '\\':
			slash = end
		case '-', '_', '.', ',', ':', '=', '|':
			if i > 0 && w[i-1] != '/' && w[i-1] != '\\' { // not a name's leading dot
				mark = end
			}
		}
	}
	switch {
	case slash > 0:
		return slash
	case mark > 0:
		return mark
	}
	return best
}
