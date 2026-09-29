package secretui

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/style"
)

// Ink is c, made readable as text on bg: a colour that reaches
// style.MinInkContrast (4.5:1) already is returned as it is, and any other
// is moved towards white on a dark background, or black on a light one, a
// step at a time until it does. It stays recognisably the colour it was:
// a red is still red, lighter.
//
// It is what uitoolkit's Palette.Ink and Label.Tone promise, and what
// v0.22.2's give back is black or white for most status colours: they walk
// the lightness in fractions where the colour code wants percentages
// (uitoolkit-gaps.md, 31). The palette's own status colours are the pack's,
// chosen for fills; as text on a dark pack they are too faint to read
// (uitoolkit-gaps.md, 29).
func Ink(c, bg paintengine2d.Color) paintengine2d.Color {
	if style.ContrastRatio(c, bg) >= style.MinInkContrast {
		return c
	}
	to := paintengine2d.RGB(1, 1, 1)
	if style.RelLuminance(bg) > 0.5 {
		to = paintengine2d.RGB(0, 0, 0)
	}
	const steps = 20
	for i := 1; i < steps; i++ {
		if m := style.Mix(c, to, float32(i)/steps); style.ContrastRatio(m, bg) >= style.MinInkContrast {
			return m
		}
	}
	return to
}
