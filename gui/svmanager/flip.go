package svmanager

import (
	"github.com/codemodify/uitoolkit/platform"
	"github.com/codemodify/uitoolkit/style"
	"github.com/codemodify/uitoolkit/widget"
)

// The window has two faces. The front is the vaults, the disks and the
// tools, with the rail down its left; the back is Settings, secretvault's
// own (appsettings.go). The gear at the title bar's right end, before the
// window's own buttons, turns the window over, and back again; so do
// Escape on the back, and anything that shows Settings or one of the
// front's parts.
//
// The whole window turns, frame and all, as a card turns about its upright
// middle, the desktop showing through where the card has turned away:
// uitoolkit's own turn (Window.SetFlipFaces and Window.Flip), which since
// v0.23.7 turns a window wearing the toolkit's frame as a picture of
// itself, its buttons and its resizing kept (uitoolkit-gaps.md item 77).
// The toolkit photographs the window with each face up and wipes the
// photographs when the turn is over (item 78).
//
// The window's content is one tree, which shows the front's parts or
// Settings, so the two faces take turns to hold it: as the window turns,
// between its two photographs, the flip panel says the other face is up
// (OnFlip), and the window changes to it there and moves onto it.
//
// It turns even where the person's uitoolkit settings ask for less motion,
// by their wish: the turn's motion is the thing itself (style.MotionAlways
// on the flip panel, item 87), and the rest of the window keeps to the
// setting. UITK_ANIMATIONS=0 still turns it at once, and so does a window
// in the desktop's frame, which cannot turn with it; offscreen (tests) it
// is at once.

// onBack reports whether the window shows its back, Settings.
func (m *Manager) onBack() bool { return m.section() == secSettings }

// turnOver turns the window to its other face: from the back to the part
// the front showed, from the front to Settings.
func (m *Manager) turnOver() {
	if m.onBack() {
		m.showSection(m.frontPart)
		return
	}
	m.showSettings(-1)
}

// buildFaces makes the window's two faces, its content on the front.
func (m *Manager) buildFaces(content widget.Component) {
	m.ui.flip = m.win.SetFlipFaces(content, nil)
	m.ui.flip.OnFlip = m.faceUp
}

// turn shows the window's other face: switchTo changes what it shows.
// Animated, the window turns over to it.
func (m *Manager) turn(switchTo func()) {
	toBack := !m.onBack()
	if toBack {
		m.frontPart = m.section()
	}
	m.switchTo = switchTo
	p := m.ui.flip
	animate, _ := m.motion() // quick or not: it turns, by the person's wish
	if animate && m.win.Decorations() == platform.DecorationsClient && !m.win.Turning() {
		p.SetMotion(style.MotionAlways)
		m.win.Flip()
	} else {
		p.SetMotion(style.MotionNever)
		p.ShowNow(!p.Showing())
	}
	m.faceUp(p.Showing()) // where the panel said nothing: the faces were swapped already
}

// faceUp changes the window to the face now up, and moves its content
// onto it, the keyboard where it was.
func (m *Manager) faceUp(back bool) {
	switchTo := m.switchTo
	if switchTo == nil {
		return
	}
	m.switchTo = nil
	focus := m.win.Focus()
	switchTo()
	p, content := m.ui.flip, m.ui.root
	if back {
		p.SetFront(nil)
		p.SetBack(content)
	} else {
		p.SetBack(nil)
		p.SetFront(content)
	}
	if focus != nil && isUnder(focus, content) && focus.Visible() {
		m.win.FocusOn(focus)
	} else {
		m.keepFocus()
	}
	m.win.RequestLayout()
}
