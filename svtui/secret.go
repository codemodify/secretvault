package svtui

import (
	"unicode"
	"unicode/utf8"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"
)

// Secrets on the screen. tview draws Go strings, and a Go string can be
// neither wiped nor told apart from other garbage, so secret values never
// become one here: they stay in byte slices this package wipes, and are
// drawn straight into the screen's cells a rune at a time (drawSecret).
// Typing a secret goes the same way (secretInput).

// mask is what a hidden secret looks like: always the same length, so the
// screen does not tell how long the secret is.
const mask = "••••••••"

// appendSecret appends p to buf. When buf has to grow, the old array is
// wiped rather than left behind for the garbage collector.
func appendSecret(buf, p []byte) []byte {
	if len(buf)+len(p) > cap(buf) {
		nb := make([]byte, len(buf), max(2*cap(buf), len(buf)+len(p), 64))
		copy(nb, buf)
		clear(buf[:cap(buf)])
		buf = nb
	}
	return append(buf, p...)
}

// drawSecret draws b at (x, y), clipped to maxWidth cells, and returns the
// width it used. Control characters show as "·".
func drawSecret(screen tcell.Screen, b []byte, x, y, maxWidth int, style tcell.Style) int {
	used := 0
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		switch {
		case r == utf8.RuneError && size <= 1:
			r = '�'
		case r < ' ' || r == 0x7f:
			r = '·'
		}
		w := runeWidth(r)
		if w == 0 {
			continue
		}
		if used+w > maxWidth {
			break
		}
		// As tview does: fill the second cell of a wide rune first.
		if w == 2 {
			screen.SetContent(x+used+1, y, ' ', nil, style)
		}
		screen.SetContent(x+used, y, r, nil, style)
		used += w
	}
	return used
}

// secretWidth is the width drawSecret would use for all of b.
func secretWidth(b []byte) int {
	n := 0
	for len(b) > 0 {
		r, size := utf8.DecodeRune(b)
		b = b[size:]
		if r == utf8.RuneError && size <= 1 || r < ' ' || r == 0x7f {
			n++
			continue
		}
		n += runeWidth(r)
	}
	return n
}

// runeWidth is how many cells r takes on a terminal: 0 for combining
// marks, 2 for East Asian wide and fullwidth characters and emoji, else 1
// (after Markus Kuhn's wcwidth).
func runeWidth(r rune) int {
	switch {
	case unicode.In(r, unicode.Mn, unicode.Me), r >= 0x200b && r <= 0x200f:
		return 0
	case r >= 0x1100 && (r <= 0x115f || r == 0x2329 || r == 0x232a ||
		(r >= 0x2e80 && r <= 0xa4cf && r != 0x303f) ||
		(r >= 0xac00 && r <= 0xd7a3) ||
		(r >= 0xf900 && r <= 0xfaff) ||
		(r >= 0xfe30 && r <= 0xfe6f) ||
		(r >= 0xff00 && r <= 0xff60) ||
		(r >= 0xffe0 && r <= 0xffe6) ||
		(r >= 0x1f300 && r <= 0x1f64f) ||
		(r >= 0x1f900 && r <= 0x1f9ff) ||
		(r >= 0x20000 && r <= 0x3fffd)):
		return 2
	}
	return 1
}

// secretInput is a one-line field for typing a secret. What is typed is
// kept in a byte slice, never in a string, and is shown masked (one mask
// character per character typed) unless revealed. It can be used on its
// own or as a tview.Form item.
//
// Editing is append-only, as pinentry's is: runes are added at the end,
// Backspace takes the last one away, Ctrl+U clears the field.
type secretInput struct {
	*tview.Box

	label       string
	labelWidth  int
	labelColor  tcell.Color
	fieldStyle  tcell.Style
	fieldWidth  int
	placeholder string

	buf      []byte
	reveal   bool
	disabled bool

	finished func(tcell.Key)
	changed  func()
}

func newSecretInput(label string) *secretInput {
	return &secretInput{
		Box:        tview.NewBox(),
		label:      label,
		labelColor: tview.Styles.SecondaryTextColor,
		fieldStyle: tcell.StyleDefault.Background(tview.Styles.ContrastBackgroundColor).Foreground(tview.Styles.PrimaryTextColor),
	}
}

// set replaces the value with a copy of b.
func (s *secretInput) set(b []byte) {
	s.wipe()
	s.buf = appendSecret(s.buf, b)
	if s.changed != nil {
		s.changed()
	}
}

// value is a copy of what was typed; the caller wipes it.
func (s *secretInput) value() []byte { return append([]byte(nil), s.buf...) }

// wipe zeroes and empties the field.
func (s *secretInput) wipe() {
	clear(s.buf[:cap(s.buf)])
	s.buf = s.buf[:0]
}

func (s *secretInput) GetLabel() string { return s.label }

func (s *secretInput) SetFormAttributes(labelWidth int, labelColor, bgColor, fieldTextColor, fieldBgColor tcell.Color) tview.FormItem {
	s.labelWidth = labelWidth
	s.labelColor = labelColor
	s.SetBackgroundColor(bgColor)
	s.fieldStyle = tcell.StyleDefault.Foreground(fieldTextColor).Background(fieldBgColor)
	return s
}

func (s *secretInput) GetFieldWidth() int  { return s.fieldWidth }
func (s *secretInput) GetFieldHeight() int { return 1 }

func (s *secretInput) SetFinishedFunc(handler func(key tcell.Key)) tview.FormItem {
	s.finished = handler
	return s
}

func (s *secretInput) SetDisabled(disabled bool) tview.FormItem {
	s.disabled = disabled
	if s.finished != nil && disabled {
		s.finished(-1)
	}
	return s
}

// Focus passes a disabled field over, as tview's own fields do.
func (s *secretInput) Focus(delegate func(p tview.Primitive)) {
	if s.disabled && s.finished != nil {
		s.finished(-1)
		return
	}
	s.Box.Focus(delegate)
}

func (s *secretInput) Draw(screen tcell.Screen) {
	s.Box.DrawForSubclass(screen, s)
	x, y, width, height := s.GetInnerRect()
	if height < 1 || width < 1 {
		return
	}
	labelWidth := s.labelWidth
	if labelWidth == 0 {
		labelWidth = tview.TaggedStringWidth(s.label) + 1
	}
	labelWidth = min(labelWidth, width)
	tview.Print(screen, s.label, x, y, labelWidth, tview.AlignLeft, s.labelColor)
	x += labelWidth
	width -= labelWidth
	fieldWidth := s.fieldWidth
	if fieldWidth <= 0 || fieldWidth > width {
		fieldWidth = width
	}
	if fieldWidth < 1 {
		return
	}
	for i := range fieldWidth {
		screen.SetContent(x+i, y, ' ', nil, s.fieldStyle)
	}
	room := fieldWidth - 1 // the cursor's cell
	var used int
	switch {
	case len(s.buf) == 0 && s.placeholder != "":
		tview.Print(screen, tview.Escape(s.placeholder), x, y, fieldWidth, tview.AlignLeft, tcell.ColorGray)
	case s.reveal:
		// Show the end of the value, where the typing happens.
		b, w := s.buf, secretWidth(s.buf)
		for w > room && len(b) > 0 {
			_, size := utf8.DecodeRune(b)
			w -= secretWidth(b[:size])
			b = b[size:]
		}
		used = drawSecret(screen, b, x, y, room, s.fieldStyle)
	default:
		n := min(utf8.RuneCount(s.buf), room)
		for i := range n {
			screen.SetContent(x+i, y, '•', nil, s.fieldStyle)
		}
		used = n
	}
	if s.HasFocus() {
		screen.ShowCursor(x+used, y)
	}
}

func (s *secretInput) InputHandler() func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
	return s.WrapInputHandler(func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
		if s.disabled {
			return
		}
		switch key := event.Key(); key {
		case tcell.KeyRune:
			var tmp [utf8.UTFMax]byte
			n := utf8.EncodeRune(tmp[:], event.Rune())
			s.buf = appendSecret(s.buf, tmp[:n])
			clear(tmp[:])
		case tcell.KeyBackspace, tcell.KeyBackspace2:
			if len(s.buf) > 0 {
				_, size := utf8.DecodeLastRune(s.buf)
				clear(s.buf[len(s.buf)-size:])
				s.buf = s.buf[:len(s.buf)-size]
			}
		case tcell.KeyCtrlU:
			s.wipe()
		case tcell.KeyEnter, tcell.KeyTab, tcell.KeyBacktab, tcell.KeyEscape:
			if s.finished != nil {
				s.finished(key)
			}
			return
		case tcell.KeyDown:
			if s.finished != nil {
				s.finished(tcell.KeyTab)
			}
			return
		case tcell.KeyUp:
			if s.finished != nil {
				s.finished(tcell.KeyBacktab)
			}
			return
		default:
			return
		}
		if s.changed != nil {
			s.changed()
		}
	})
}

// PasteHandler takes a paste. tview hands it over as a string; it is
// copied into the field at once.
func (s *secretInput) PasteHandler() func(text string, setFocus func(p tview.Primitive)) {
	return s.WrapPasteHandler(func(text string, setFocus func(p tview.Primitive)) {
		if s.disabled {
			return
		}
		for _, r := range text {
			if r == '\n' || r == '\r' {
				continue
			}
			var tmp [utf8.UTFMax]byte
			n := utf8.EncodeRune(tmp[:], r)
			s.buf = appendSecret(s.buf, tmp[:n])
		}
		if s.changed != nil {
			s.changed()
		}
	})
}

func (s *secretInput) MouseHandler() func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
	return s.WrapMouseHandler(func(action tview.MouseAction, event *tcell.EventMouse, setFocus func(p tview.Primitive)) (bool, tview.Primitive) {
		if action == tview.MouseLeftDown && s.InRect(event.Position()) && !s.disabled {
			setFocus(s)
			return true, nil
		}
		return false, nil
	})
}
