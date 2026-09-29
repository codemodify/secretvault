package svqr

import (
	"image"
	"image/color"
	"strings"
)

// QuietZone is the light border the standard asks for around a symbol, in
// modules.
const QuietZone = 4

// TerminalOptions choose how Terminal draws a code.
type TerminalOptions struct {
	// Quiet is the light border in modules; zero means QuietZone. Scanners
	// cope with less on a screen: 2 is usually enough.
	Quiet int
	// Colour sets the colours with ANSI escapes (black on white), so the
	// code reads the right way round on any terminal. Without it the
	// terminal's own colours are used: see Invert.
	Colour bool
	// Invert draws light modules as characters, for a terminal with light
	// text on a dark background (the usual case). Without it dark modules
	// are drawn, for dark text on a light background. Ignored with Colour.
	Invert bool
}

// Terminal draws the code with half-block characters, two rows of modules
// to a line, each line ending in a newline.
func (c *Code) Terminal(o TerminalOptions) string {
	q := o.Quiet
	if q <= 0 {
		q = QuietZone
	}
	ink := func(x, y int) bool {
		d := c.Dark(x, y)
		if o.Invert && !o.Colour {
			return !d
		}
		return d
	}
	var b strings.Builder
	for y := -q; y < c.Size+q; y += 2 {
		if o.Colour {
			b.WriteString("\x1b[30;107m") // black on bright white
		}
		for x := -q; x < c.Size+q; x++ {
			top := ink(x, y)
			bottom := y+1 < c.Size+q && ink(x, y+1)
			switch {
			case top && bottom:
				b.WriteString("█")
			case top:
				b.WriteString("▀")
			case bottom:
				b.WriteString("▄")
			default:
				b.WriteByte(' ')
			}
		}
		if o.Colour {
			b.WriteString("\x1b[0m")
		}
		b.WriteByte('\n')
	}
	return b.String()
}

// Image draws the code as a grayscale image, scale pixels to a module,
// with a quiet zone of quiet modules (QuietZone when zero or less).
func (c *Code) Image(scale, quiet int) *image.Gray {
	if scale < 1 {
		scale = 1
	}
	if quiet <= 0 {
		quiet = QuietZone
	}
	side := (c.Size + 2*quiet) * scale
	img := image.NewGray(image.Rect(0, 0, side, side))
	for py := range side {
		for px := range side {
			v := color.Gray{Y: 255}
			if c.Dark(px/scale-quiet, py/scale-quiet) {
				v.Y = 0
			}
			img.SetGray(px, py, v)
		}
	}
	return img
}
