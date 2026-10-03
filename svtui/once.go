package svtui

import (
	"strings"

	"github.com/gdamore/tcell/v2"
	"github.com/rivo/tview"

	"github.com/codemodify/secretvault/svqr"
)

// Things shown only once: a recovery key, its shares, an invite. They
// are drawn from their bytes, as revealed secrets are (secret.go), may be
// copied, and are wiped when the view closes; closing asks first, since
// nothing shows them again. An invite also shows as a QR code, drawn
// with half blocks in black on white, as 'secretvault sync invite --qr'
// draws it.

// onceLine is a line of a once view: text to read, or a secret.
type onceLine struct {
	text   string // plain text (escaped when drawn)
	secret []byte // or a secret, drawn from its bytes, selectable and copyable
}

type onceView struct {
	*tview.Box
	lines    []onceLine
	qr       *svqr.Code
	offset   int
	selected int // the selected secret line, -1 for none
}

// onceWidth is the room a once view's text has.
const onceWidth = 84 - 2 - 4

func newOnceView(lines []onceLine, qr *svqr.Code) *onceView {
	v := &onceView{Box: tview.NewBox(), qr: qr, selected: -1}
	for _, l := range lines {
		if l.secret != nil || l.text == "" {
			v.lines = append(v.lines, l)
			continue
		}
		indent := l.text[:len(l.text)-len(strings.TrimLeft(l.text, " "))]
		for i, w := range tview.WordWrap(l.text, onceWidth) {
			if i > 0 {
				w = indent + "  " + strings.TrimLeft(w, " ")
			}
			v.lines = append(v.lines, onceLine{text: w})
		}
	}
	v.move(1)
	return v
}

// height is how many rows it takes: its lines, and the code with its
// quiet zone, two modules to a row.
func (v *onceView) height() int {
	h := len(v.lines)
	if v.qr != nil {
		h += 1 + (v.qr.Size+4+1)/2
	}
	return h
}

func (v *onceView) wipe() {
	for _, l := range v.lines {
		clear(l.secret)
	}
}

func (v *onceView) move(delta int) {
	i := v.selected
	for range len(v.lines) {
		i += delta
		if i < 0 || i >= len(v.lines) {
			return
		}
		if v.lines[i].secret != nil {
			v.selected = i
			return
		}
	}
}

func (v *onceView) Draw(screen tcell.Screen) {
	v.Box.DrawForSubclass(screen, v)
	x, y, width, height := v.GetInnerRect()
	if v.selected >= 0 {
		if v.selected < v.offset {
			v.offset = v.selected
		}
		if v.selected >= v.offset+height {
			v.offset = v.selected - height + 1
		}
	}
	v.offset = max(0, min(v.offset, v.height()-height))
	row := 0
	put := func() (int, bool) {
		r := row - v.offset
		row++
		return y + r, r >= 0 && r < height
	}
	plain := tcell.StyleDefault.Foreground(tview.Styles.PrimaryTextColor)
	for i, l := range v.lines {
		sy, ok := put()
		if !ok {
			continue
		}
		if l.secret != nil {
			style := plain.Foreground(tcell.ColorYellow)
			if i == v.selected {
				style = style.Background(tview.Styles.ContrastBackgroundColor)
			}
			drawSecret(screen, l.secret, x+2, sy, width-2, style)
			continue
		}
		tview.Print(screen, tview.Escape(l.text), x, sy, width, tview.AlignLeft, tview.Styles.PrimaryTextColor)
	}
	if v.qr == nil {
		return
	}
	put()
	ink := tcell.StyleDefault.Foreground(tcell.ColorBlack).Background(tcell.ColorWhite)
	const quiet = 2
	size := v.qr.Size + 2*quiet
	left := x + max(0, (width-size)/2)
	for my := -quiet; my < v.qr.Size+quiet; my += 2 {
		sy, ok := put()
		if !ok {
			continue
		}
		for mx := -quiet; mx < v.qr.Size+quiet; mx++ {
			top, bottom := v.qr.Dark(mx, my), v.qr.Dark(mx, my+1)
			r := ' '
			switch {
			case top && bottom:
				r = '█'
			case top:
				r = '▀'
			case bottom:
				r = '▄'
			}
			if cx := left + mx + quiet; cx < x+width {
				screen.SetContent(cx, sy, r, nil, ink)
			}
		}
	}
}

func (v *onceView) InputHandler() func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
	return v.WrapInputHandler(func(event *tcell.EventKey, setFocus func(p tview.Primitive)) {
		switch event.Key() {
		case tcell.KeyDown:
			before := v.selected
			if v.move(1); v.selected == before {
				v.offset++
			}
		case tcell.KeyUp:
			before := v.selected
			if v.move(-1); v.selected == before {
				v.offset = max(0, v.offset-1)
			}
		case tcell.KeyPgDn:
			v.offset += 10
		case tcell.KeyPgUp:
			v.offset = max(0, v.offset-10)
		}
	})
}

// showOnce shows lines (and the code, if any) until the person closes
// the view, having been told it is the only time. The secrets are wiped
// then.
func (u *UI) showOnce(title string, lines []onceLine, qr *svqr.Code) {
	u.showLines(title, lines, qr, true)
}

// showCode shows lines and a QR code that can be shown again (your own
// contact card): the lines to copy are copyable, and it closes without
// asking.
func (u *UI) showCode(title string, lines []onceLine, qr *svqr.Code) {
	u.showLines(title, lines, qr, false)
}

func (u *UI) showLines(title string, lines []onceLine, qr *svqr.Code, once bool) {
	v := newOnceView(lines, qr)
	hasSecret := v.selected >= 0
	v.SetBorder(true).SetBorderPadding(1, 1, 2, 2)
	hint := "Esc closes"
	if hasSecret {
		hint = "c copies the selected line · Esc closes"
	}
	v.SetTitle(" " + tview.Escape(title) + " — " + hint + " ")
	closed := false
	closeNow := func() {
		if closed {
			return
		}
		closed = true
		u.closeOnce()
	}
	v.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch {
		case ev.Key() == tcell.KeyEscape || ev.Key() == tcell.KeyEnter || ev.Rune() == 'q':
			if !hasSecret || !once {
				closeNow()
				return nil
			}
			u.confirmOnce(closeNow)
			return nil
		case ev.Rune() == 'c' && v.selected >= 0:
			u.copyValue(v.lines[v.selected].secret)
			return nil
		}
		return ev
	})
	open := func() {
		u.once = v
		u.openPage(pageOnce, centred(v, 84, u.fit(v.height()+4)), v)
	}
	if u.once != nil {
		// One shown once is never replaced unseen: this waits for it.
		u.onceQueue = append(u.onceQueue, pendingOnce{v, open})
		return
	}
	open()
}

// pageOnceAsk is the question closing a once view asks, above it: never
// behind a dialog the once view covers.
const pageOnceAsk = "once-ask"

// confirmOnce asks before closing a once view.
func (u *UI) confirmOnce(close func()) {
	m := tview.NewModal().SetText("This is not shown again. Have you written it down, or copied it where it belongs?").
		AddButtons([]string{"Keep it open", "Close it"})
	m.SetTitle(" Close it for good? ")
	answer := func(yes bool) {
		u.closePage(pageOnceAsk)
		if yes {
			close()
		}
	}
	m.SetDoneFunc(func(_ int, label string) { answer(label == "Close it") })
	m.SetInputCapture(func(ev *tcell.EventKey) *tcell.EventKey {
		switch ev.Rune() {
		case 'y', 'Y':
			answer(true)
			return nil
		case 'n', 'N':
			answer(false)
			return nil
		}
		return ev
	})
	u.openPage(pageOnceAsk, m, m)
}

// pendingOnce is a once view waiting for the one up to close.
type pendingOnce struct {
	v    *onceView
	open func()
}

// closeOnce takes down the once view up, wiping it, and shows the next
// one waiting.
func (u *UI) closeOnce() {
	if u.once != nil {
		u.once.wipe()
		u.once = nil
	}
	u.closePage(pageOnce)
	if len(u.onceQueue) > 0 {
		next := u.onceQueue[0]
		u.onceQueue = u.onceQueue[1:]
		next.open()
	}
}

// wipeOnce takes down every once view, shown or waiting, wiping them, and
// any value resolved from a reference (the daemon went away, or the
// program is quitting).
func (u *UI) wipeOnce() {
	u.wipeValue()
	for _, p := range u.onceQueue {
		p.v.wipe()
	}
	u.onceQueue = nil
	if u.once != nil {
		u.once.wipe()
		u.once = nil
	}
	u.closePage(pageOnceAsk)
	u.closePage(pageOnce)
}
