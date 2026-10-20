package svmanager

import (
	"math"
	"time"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/a11y"
	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"

	"github.com/codemodify/secretvault/gui/secretui"
)

// A closed vault is secretvault's logo, a vault's dial, large, over the
// whole of the Vault part, and nothing else: what the vault holds is out
// of sight. Closed is locked, or waiting: its items asked for, and a
// prompt waiting on the person before they come. Under the pointer (or
// with the keyboard on it) the logo lifts, a little larger in a soft
// light, and the pointer is the pointing hand, which say a click does
// something: a click on it (or Enter) asks
// for the vault's passphrase. The title bar's padlocks unlock it too, and
// in the other ways. Once the vault is unlocked the logo turns half
// round, as a vault's dial does, grows a little and fades, the vault's
// items behind it. Locked again, it comes back the same way. Where the
// desktop asks for less motion it only fades; off screen (tests) it is at
// once.

// The face's timeline: the dial turns until faceTurn, and from faceFade
// on it grows and fades. A listing that takes longer than faceWait is
// waiting on a prompt: the vault's face shows meanwhile.
const (
	faceWait     = 400 * time.Millisecond
	faceLift     = 140 * time.Millisecond // the logo lifting under the pointer, or settling
	faceTime     = 1100 * time.Millisecond
	faceQuick    = 260 * time.Millisecond
	faceTurn     = 0.55
	faceFadeFrom = 0.35
)

// syncFace puts the face up over a locked vault, or takes it away from an
// open one: turning it away, or bringing it back, as the shown vault
// changes state here, and at once for another vault.
func (m *Manager) syncFace() {
	if m.ui == nil || m.ui.vaultHost == nil {
		return
	}
	v := m.vaultInfo(m.vault)
	known := v != nil && v.ID != "" && !m.gone
	waiting := m.listing && m.flipNow().Sub(m.listingSince) >= faceWait
	closed := known && (v.Locked || waiting)
	same := m.faceFor == m.vault
	was := m.faceWas
	animate, quick := m.motion()
	f := m.face
	switch {
	case closed && f == nil:
		f = m.raiseFace()
		if same && !was && animate && v.Locked {
			f.play(false, quick) // locked here: it comes back
		}
	case closed:
		if f.vault != m.vault || f.anim != nil && f.anim.opening {
			f.stopAnim()
			f.vault = m.vault
			f.settle()
		}
		f.restate()
	case f != nil:
		switch {
		case f.anim != nil && f.anim.opening:
			// going already
		case known && m.listing && f.vault == m.vault:
			// Its items are on their way (unlocked, or asked for): it goes
			// once they are here.
			f.restate()
		case same && was && animate && f.vault == m.vault && m.listed:
			f.play(true, quick)
		default:
			m.dropFace()
		}
	}
	m.faceFor = m.vault
	m.faceWas = m.face != nil && (m.face.anim == nil || !m.face.anim.opening)
}

// raiseFace puts the face up over the Vault part, the keyboard on it if it
// was in the part.
func (m *Manager) raiseFace() *lockFace {
	f := newLockFace(m, m.vault)
	m.face = f
	m.ui.vaultHost.over(f)
	f.settle()
	if fc := m.win.Focus(); fc == nil || isUnder(fc, m.ui.vaultHost) {
		m.win.FocusOn(f)
	}
	return f
}

// dropFace takes the face away, the Vault part shown.
func (m *Manager) dropFace() {
	f := m.face
	if f == nil {
		return
	}
	f.stopAnim()
	m.face = nil
	hadFocus := isUnder(m.win.Focus(), f)
	m.ui.vaultHost.base().SetVisible(true)
	m.ui.vaultHost.over(nil)
	if hadFocus {
		m.keepFocus()
	}
}

// unlockedHere notes that vault is open now, which the daemon will say
// too: the face goes without waiting for it.
func (m *Manager) unlockedHere(vault string) {
	if v := m.vaultInfo(vault); v != nil {
		v.Locked = false
	}
}

// layered shows its first child, and over it the second, if there is one.
// Its size is its first child's: what is over it fits what is under it.
type layered struct{ widget.Base }

func newLayered(base widget.Component) *layered {
	l := &layered{}
	l.Init(l)
	l.Add(base)
	return l
}

func (l *layered) base() widget.Component { return l.Children()[0] }

func (l *layered) over(c widget.Component) {
	for len(l.Children()) > 1 {
		l.Remove(l.Children()[len(l.Children())-1])
	}
	if c != nil {
		l.Add(c)
		c.Arrange(paintengine2d.XYWH(0, 0, l.Bounds().Dx(), l.Bounds().Dy()))
	}
	l.RequestLayout()
	l.Invalidate()
}

func (l *layered) Measure(c layout.Constraints) paintengine2d.Point { return l.base().Measure(c) }

func (l *layered) MinWidth() float32 { return widget.MinWidthOf(l.base()) }

func (l *layered) Arrange(r paintengine2d.Rect) {
	l.SetBounds(r)
	for _, c := range l.Children() {
		c.Arrange(paintengine2d.XYWH(0, 0, r.Dx(), r.Dy()))
	}
}

// lockFace is a locked vault's face.
type lockFace struct {
	widget.Base
	m     *Manager
	vault string
	anim  *faceAnim
	logo  *paintengine2d.Image // the logo at the side it is drawn

	over             bool      // the pointer is on the logo
	liftFrom, liftTo float32   // the lift: 0 resting, 1 lifted
	liftAt           time.Time // when it set off from liftFrom
	liftStop         func()
}

// faceAnim is the face going (opening) or coming back.
type faceAnim struct {
	opening, quick bool
	begun          time.Time
	dur            time.Duration
	stop           func()
}

func newLockFace(m *Manager, vault string) *lockFace {
	f := &lockFace{m: m, vault: vault}
	f.Init(f)
	f.SetWantsFocus(true)
	f.restate()
	return f
}

// settle shows what is under the face only while it moves.
func (f *lockFace) settle() {
	f.m.ui.vaultHost.base().SetVisible(f.anim != nil)
	f.Invalidate()
}

// restate says what the face is.
func (f *lockFace) restate() {
	f.SetAccessibleName(f.says())
	f.Invalidate()
}

// shut reports whether the vault is locked, rather than open but not to
// this window.
func (f *lockFace) shut() bool {
	v := f.m.vaultInfo(f.vault)
	return v == nil || v.Locked
}

// says is what the face is, for a screen reader: what a click on the logo
// does, or what it waits for. On the screen it says nothing.
func (f *lockFace) says() string {
	if f.m.listing || !f.shut() {
		return "Vault " + f.vault + " is waiting for your answer, in a window of its own"
	}
	return "Vault " + f.vault + " is locked: click to unlock it (it asks for its passphrase)"
}

// knock asks for the vault's passphrase, unless the face is moving.
func (f *lockFace) knock() {
	if f.anim != nil || f.m.listing {
		return
	}
	if f.shut() {
		f.m.unlockVault(f.vault)
	}
}

func (f *lockFace) Measure(c layout.Constraints) paintengine2d.Point {
	return c.Constrain(paintengine2d.Pt(c.MaxW, c.MaxH))
}

func (f *lockFace) Arrange(r paintengine2d.Rect) { f.SetBounds(r) }

// logoSide is the logo's side: one size, whatever the window's.
const logoSide = 220

// dial is where the logo is: its middle and its side, which shrinks only
// where the part is too small to hold it.
func (f *lockFace) dial() (paintengine2d.Point, float32) {
	b := f.LocalBounds()
	side := min(style.Dip(f.Look(), logoSide), b.Dx()*0.8, b.Dy()*0.8)
	return paintengine2d.Pt(b.Dx()/2, b.Dy()/2), max(side, 16)
}

// at is where the face is in its timeline: how far the dial has turned (0
// to 1, half a turn), how big it is (1 on), and how much of it is left (1
// to 0).
func (f *lockFace) at() (turn, grow, left float32) {
	a := f.anim
	if a == nil {
		return 0, 1, 1
	}
	t := float32(f.m.flipNow().Sub(a.begun)) / float32(a.dur)
	t = min(max(t, 0), 1)
	if !a.opening {
		t = 1 - t
	}
	if a.quick {
		return 0, 1, 1 - t
	}
	ease := func(x float32) float32 { return x * x * (3 - 2*x) }
	turn = ease(min(t/faceTurn, 1))
	g := max(t-faceFadeFrom, 0) / (1 - faceFadeFrom)
	return turn, 1 + 0.18*ease(g), 1 - ease(g)
}

// play turns the face away (opening) or brings it back.
func (f *lockFace) play(opening, quick bool) {
	f.stopAnim()
	f.over = false
	f.liftFrom, f.liftTo = 0, 0
	a := &faceAnim{opening: opening, quick: quick, begun: f.m.flipNow(), dur: faceTime}
	if quick {
		a.dur = faceQuick
	}
	f.anim = a
	f.settle()
	f.next()
}

func (f *lockFace) stopAnim() {
	if f.anim != nil && f.anim.stop != nil {
		f.anim.stop()
	}
	f.anim = nil
}

// next draws the next frame, or ends the move once its time is up: gone,
// it is taken away; back, it stays.
func (f *lockFace) next() {
	a := f.anim
	if a == nil || f.m.face != f {
		return
	}
	if f.m.flipNow().Sub(a.begun) >= a.dur {
		f.anim = nil
		if a.opening {
			f.m.dropFace()
		} else {
			f.settle()
		}
		return
	}
	// Only the logo moves: only round it is drawn again (it grows to 1.18
	// of its side).
	c, side := f.dial()
	r := side * 0.62
	f.InvalidateRect(paintengine2d.Rect{Min: paintengine2d.Pt(c.X-r, c.Y-r), Max: paintengine2d.Pt(c.X+r, c.Y+r)}.Intersect(f.LocalBounds()))
	a.stop = widget.After(f, flipFrame, f.next)
}

// onLogo reports whether p is on the logo.
func (f *lockFace) onLogo(p paintengine2d.Point) bool {
	c, side := f.dial()
	dx, dy := p.X-c.X, p.Y-c.Y
	return dx*dx+dy*dy <= side*side/4
}

// MousePress on the logo asks for the passphrase; round it, nothing.
func (f *lockFace) MousePress(e widget.MouseEvent) bool {
	if f.onLogo(e.Pos) {
		f.knock()
	}
	return true
}

// MouseMove lifts the logo as the pointer comes onto it, and settles it
// as the pointer leaves.
func (f *lockFace) MouseMove(e widget.MouseEvent) bool {
	f.over = f.onLogo(e.Pos)
	f.liftTowards()
	return false
}

// CursorAt is the pointing hand on the logo, which a click opens.
func (f *lockFace) CursorAt(p paintengine2d.Point) platform.Cursor {
	if f.onLogo(p) {
		return platform.CursorPointer
	}
	return platform.CursorDefault
}

func (f *lockFace) MouseExit() {
	f.over = false
	f.liftTowards()
}

func (f *lockFace) FocusGained() { f.liftTowards() }
func (f *lockFace) FocusLost()   { f.liftTowards() }

// lifted is whether the logo should be lifted: the pointer on it, or the
// keyboard (come to it by the keyboard), and nothing moving it otherwise.
func (f *lockFace) lifted() bool {
	return f.anim == nil && (f.over || f.Focused() && f.KeyNav())
}

// lift is how far the logo is lifted now, 0 to 1.
func (f *lockFace) lift() float32 {
	if f.liftTo == f.liftFrom {
		return f.liftTo
	}
	t := min(float32(f.m.flipNow().Sub(f.liftAt))/float32(faceLift), 1)
	t = t * (2 - t) // easing out
	return f.liftFrom + (f.liftTo-f.liftFrom)*t
}

// liftTowards sets the logo lifting or settling, as lifted says.
func (f *lockFace) liftTowards() {
	to := float32(0)
	if f.lifted() {
		to = 1
	}
	if to == f.liftTo {
		return
	}
	now := f.lift()
	f.liftFrom, f.liftTo, f.liftAt = now, to, f.m.flipNow()
	if animate, quick := f.m.motion(); !animate || quick {
		f.liftFrom = to
	}
	f.liftFrame()
}

func (f *lockFace) liftFrame() {
	if f.liftStop != nil {
		f.liftStop()
		f.liftStop = nil
	}
	c, side := f.dial()
	r := side * 0.7
	f.InvalidateRect(paintengine2d.Rect{Min: paintengine2d.Pt(c.X-r, c.Y-r), Max: paintengine2d.Pt(c.X+r, c.Y+r)}.Intersect(f.LocalBounds()))
	if f.lift() != f.liftTo && f.m.flipNow().Sub(f.liftAt) < faceLift {
		f.liftStop = widget.After(f, flipFrame, f.liftFrame)
	} else {
		f.liftFrom = f.liftTo
	}
}

func (f *lockFace) KeyPress(e widget.KeyEvent) bool {
	if e.Mods&(platform.ModCtrl|platform.ModAlt) == 0 && (e.Key == platform.KeyReturn || e.Key == platform.KeySpace) {
		f.knock()
		return true
	}
	return false
}

func (f *lockFace) Describe(n *a11y.Node) { n.Role = a11y.RoleButton }

func (f *lockFace) Paint(ctx *paintengine2d.Context) {
	turn, grow, left := f.at()
	if left <= 0 {
		return
	}
	c, side := f.dial()
	px := int(math.Ceil(float64(side)))
	if f.logo == nil || f.logo.Width != px {
		f.logo = secretui.Icon(px)
	}
	if l := f.lift(); l > 0 && f.anim == nil {
		// Lifted: a soft light round it, light on a dark window and a
		// shade on a light one, and the logo a little larger.
		glow := paintengine2d.RGBA(1, 1, 1, 0.17*l)
		if !secretui.IsDark(f.Look()) {
			glow = paintengine2d.RGBA(0, 0, 0, 0.14*l)
		}
		ctx.DrawCircle(c, side*0.66, paintengine2d.Radial(paintengine2d.RadialGradient{Center: c, Radius: side * 0.66,
			Stops: []paintengine2d.GradientStop{{Offset: 0.62, Color: glow}, {Offset: 1, Color: glow.WithAlpha(0)}}}))
		grow *= 1 + 0.07*l
	}
	ctx.Save()
	ctx.Translate(c.X, c.Y)
	ctx.Rotate(float32(turn * math.Pi))
	ctx.Scale(grow, grow)
	paint := paintengine2d.Paint{}
	if left < 1 {
		paint.Opacity = max(left, 0.001)
	}
	ctx.DrawImageRectPaint(f.logo, paintengine2d.XYWH(0, 0, float32(f.logo.Width), float32(f.logo.Height)),
		paintengine2d.XYWH(-side/2, -side/2, side, side), paint)
	ctx.Restore()
}
