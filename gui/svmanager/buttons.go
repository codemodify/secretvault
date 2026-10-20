package svmanager

import (
	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/gui/secretui"
)

// newButton is a button with the icon its label calls for
// (secretui.ButtonIcon): every button of the manager has one.
func newButton(text string, do func()) *widgets.Button {
	b := widgets.NewButton(text, do)
	b.Icon = secretui.ButtonIcon(text)
	return b
}
