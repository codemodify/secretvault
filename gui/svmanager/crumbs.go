package svmanager

import (
	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit/style"

	"github.com/codemodify/secretvault/gui/secretui"
	"github.com/codemodify/secretvault/svops"
)

// The breadcrumbs in the title bar (titlebar.go) are uitoolkit's
// (widgets.Breadcrumbs), as arrows, each one's point in the next one's
// notch: in each, an icon of what it is, then its words. A click on one
// opens what it can change to.

// inkMark draws a mark in box in one ink.
type inkMark func(ctx *paintengine2d.Context, box paintengine2d.Rect, ink paintengine2d.Color)

// stock is a toolkit icon as a mark, in the window's icon set.
func (m *Manager) stock(icon style.ToolIcon) inkMark {
	return func(ctx *paintengine2d.Context, box paintengine2d.Rect, ink paintengine2d.Color) {
		style.DrawToolIcon(ctx, box, icon, ink, style.IconSetOf(m.win.Look()))
	}
}

// kindIcon is the icon of what a vault holds, by its title (the kinds of
// item, My keys, Contacts, About this vault).
func kindIcon(title string) style.ToolIcon {
	switch title {
	case "Logins":
		return style.IconUser
	case "Passwords":
		return style.IconPassword
	case "Passkeys", "API keys", "Keys", svops.MyKeysRow:
		return style.IconKey
	case "One-time codes":
		return style.IconSync
	case "Cards":
		return style.IconCards
	case "Personal details":
		return style.IconTag
	case "Notes":
		return style.IconPen
	case "SSH keys":
		return style.IconTerminal
	case "Key/value":
		return style.IconTable
	case "Disk keys":
		return style.IconDrive
	case svops.ContactsRow:
		return style.IconMail
	case svops.AboutVaultRow:
		return style.IconInfo
	}
	return style.IconDot
}

// tabMarks are the icons of the pages' tabs that have one of their own;
// the others are their buttons' (secretui.ButtonIcon).
var tabMarks = map[string]style.ToolIcon{
	"Appearance": style.IconEye, "Keyboard shortcuts": style.IconMenu, "About secretvault": style.IconInfo,
	"Where things are kept": style.IconFolder, "Ways to unlock": style.IconLock, "Sharing": style.IconForward,
	"Devices": style.IconLayout, "Sync": style.IconSync, "Grants": style.IconCheck, "Audit log": style.IconRows,
	"Settings": style.IconSettings,
}

// tabIcon is the icon of a page's tab.
func tabIcon(title string) style.ToolIcon {
	if ic, ok := tabMarks[title]; ok {
		return ic
	}
	return secretui.ButtonIcon(title)
}
