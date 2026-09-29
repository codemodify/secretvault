package svmanager

import (
	"crypto/rand"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/codemodify/uitoolkit/layout"
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svcrypto"
)

// The password generator: characters from the classes chosen, or words.
// What it makes is held in a byte slice, shown from it, and wiped when the
// generator closes; handing it on hands a copy.

// generator is the generator's settings, which it keeps between uses.
type generator struct {
	words   bool
	length  int // characters
	count   int // words
	classes [4]bool
	sep     string
}

func defaultGenerator() generator {
	return generator{length: 24, count: 5, classes: [4]bool{true, true, true, true}, sep: "-"}
}

var classSets = [4]string{svcrypto.Lower, svcrypto.Upper, svcrypto.Digits, svcrypto.Symbols}

// make makes a password. The caller wipes it.
func (g generator) make() ([]byte, error) {
	if g.words {
		return passphrase(g.count, g.sep)
	}
	var classes []string
	for i, on := range g.classes {
		if on {
			classes = append(classes, classSets[i])
		}
	}
	if len(classes) == 0 {
		classes = []string{svcrypto.Lower}
	}
	return svcrypto.Password(g.length, classes...)
}

// bits is how much a password made this way is worth guessing, roughly:
// the entropy of the draw, ignoring the rule that each class appear.
func (g generator) bits() float64 {
	if g.words {
		return float64(g.count) * math.Log2(float64(len(wordList())))
	}
	n := 0
	for i, on := range g.classes {
		if on {
			n += len(classSets[i])
		}
	}
	if n == 0 {
		n = len(svcrypto.Lower)
	}
	return float64(g.length) * math.Log2(float64(n))
}

// passphrase is count words drawn uniformly from the word list, joined by
// sep, in a buffer of its own.
func passphrase(count int, sep string) ([]byte, error) {
	list := wordList()
	max := big.NewInt(int64(len(list)))
	var out []byte
	for i := range count {
		j, err := rand.Int(rand.Reader, max)
		if err != nil {
			clear(out)
			return nil, err
		}
		if i > 0 {
			out = appendSecret(out, []byte(sep))
		}
		out = appendSecret(out, []byte(list[j.Int64()]))
	}
	return out, nil
}

// appendSecret appends p to buf. When buf has to grow, the old array is
// wiped rather than left behind for the collector.
func appendSecret(buf, p []byte) []byte {
	if len(buf)+len(p) > cap(buf) {
		nb := make([]byte, len(buf), max(2*cap(buf), len(buf)+len(p), 64))
		copy(nb, buf)
		clear(buf[:cap(buf)])
		buf = nb
	}
	return append(buf, p...)
}

// showGenerator shows the password generator. With use, its Use button
// hands the password over (to the editor); without, it offers to copy the
// password or to make a new item with it.
func (m *Manager) showGenerator(use func([]byte)) {
	g := &m.gen
	var pw []byte
	preview := newSecretText(nil)
	preview.SetReveal(true)
	preview.SetAccessibleName("Generated password")
	strength := m.muted("")
	problem := m.tint(widgets.NewLabel(""), toneDanger)

	regenerate := func() {
		p, err := g.make()
		if err != nil {
			problem.SetText(sentence(err.Error()))
			return
		}
		problem.SetText("")
		clear(pw)
		pw = p
		preview.SetValue(pw)
		strength.SetText(fmt.Sprintf("About %.0f bits: %s", g.bits(), verdict(g.bits())))
	}

	length := widgets.NewNumberField(8, 128, float64(g.length), 1, nil)
	length.SetAccessibleName("Length")
	count := widgets.NewNumberField(3, 12, float64(g.count), 1, nil)
	count.SetAccessibleName("Words")
	var boxes [4]*widgets.Checkbox
	for i, name := range []string{"Lower case (a-z)", "Upper case (A-Z)", "Digits (0-9)", "Symbols (!#$…)"} {
		boxes[i] = widgets.NewCheckbox(name, g.classes[i], nil)
	}
	chars := widgets.NewColumn(widgets.NewRow(widgets.NewLabel("Length").For(length), length).WithGap(gap).WithAlign(layout.AlignCenter))
	classes := widgets.NewWrap()
	for _, b := range boxes {
		classes.Add(b)
	}
	chars.Add(classes)
	chars.WithGap(gap)
	sep := widgets.NewComboBox([]string{"-", " ", ".", "_"}, max(0, strings.Index("- ._", g.sep)), nil)
	sep.SetAccessibleName("Between words")
	words := widgets.NewRow(widgets.NewLabel("Words").For(count), count, widgets.NewLabel("between them").For(sep), sep).
		WithGap(gap).WithAlign(layout.AlignCenter)
	mode := widgets.NewSegmented([]string{"Characters", "Words"}, 0, nil)
	if g.words {
		mode.Selected = 1
	}
	chars.SetVisible(!g.words)
	words.SetVisible(g.words)

	mode.OnChange = func(i int) {
		g.words = i == 1
		chars.SetVisible(!g.words)
		words.SetVisible(g.words)
		chars.RequestLayout()
		regenerate()
	}
	length.OnChange = func(v float64) {
		if n := int(v); n != g.length && n >= 8 && n <= 128 {
			g.length = n
			regenerate()
		}
	}
	count.OnChange = func(v float64) {
		if n := int(v); n != g.count && n >= 3 && n <= 12 {
			g.count = n
			regenerate()
		}
	}
	for i, b := range boxes {
		b.OnChange = func(on bool) {
			g.classes[i] = on
			regenerate()
		}
	}
	sep.OnChange = func(i int) {
		g.sep = []string{"-", " ", ".", "_"}[i]
		regenerate()
	}

	box := widgets.NewColumn(preview).WithPad(10)
	body := widgets.NewColumn(mode, chars, words, box, strength, problem).WithGap(12)

	var d *dialog
	buttons := widgets.NewButtonBox()
	var first *widgets.Button
	if use != nil {
		first = widgets.NewButton("Use", func() {
			use(pw)
			d.Close()
		})
		buttons.AddButton(first, widgets.RoleAccept)
	} else {
		first = widgets.NewButton("Copy", func() { m.copyValue(pw, "The password") })
		buttons.AddButton(first, widgets.RoleAccept)
		buttons.AddButton(widgets.NewButton("New item with it", func() {
			p := append([]byte(nil), pw...)
			d.Close()
			m.newItem(p)
			clear(p)
		}), widgets.RoleAction)
	}
	buttons.AddButton(widgets.NewButton("Again", regenerate), widgets.RoleAction)
	buttons.AddButton(widgets.NewButton("Close", func() { d.Close() }), widgets.RoleReject)
	regenerate()
	d = m.showDialog("Password generator", body, buttons, first, func() {
		preview.Forget()
		clear(pw)
		pw = nil
	})
}

// verdict says in words what the bits mean.
func verdict(bits float64) string {
	switch {
	case bits < 50:
		return "weak"
	case bits < 80:
		return "fair"
	case bits < 110:
		return "strong"
	}
	return "very strong"
}
