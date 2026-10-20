package secretui

import (
	"strings"

	"github.com/codemodify/uitoolkit/style"
)

// Every button of secretvault's windows has an icon beside its label,
// chosen from what the label says it does: its first word, or a phrase
// the first word would get wrong. The manager and the prompt both use it.

// iconPhrases are labels whose icon is not their first word's: tried
// first, as the label begins.
var iconPhrases = []struct {
	prefix string
	icon   style.ToolIcon
}{
	{"show my qr", style.IconEye},
	{"show a file's public key", style.IconEye},
	{"copy the folder's path", style.IconCopy},
	{"cut off", style.IconTrash},
	{"try again", style.IconSync},
	{"i have written it down", style.IconCheck},
	{"don't", style.IconClose},
	{"back up", style.IconSave},
	{"open when", style.IconCheck},
	{"its own passphrase", style.IconLock},
	{"give the vault a new key", style.IconLock},
	{"change the passphrase", style.IconLock},
	{"sign and encrypt", style.IconSend},
	{"let ", style.IconCheck},
	{"take the permission back", style.IconUndo},
	{"take over", style.IconCheck},
	{"give the keyring back", style.IconUndo},
	{"make a password", style.IconPlus},
	{"what it can do", style.IconInfo},
	{"keyboard shortcuts", style.IconInfo},
	{"password generator", style.IconPlus},
	{"lock all", style.IconLock},
	{"add existing", style.IconPlus},
	{"join synced", style.IconSync},
	{"new item here", style.IconPlus},
}

// iconWords are labels' first words, and their icons.
var iconWords = map[string]style.ToolIcon{
	"new": style.IconPlus, "add": style.IconPlus, "make": style.IconPlus, "create": style.IconPlus,
	"generate": style.IconPlus, "invite": style.IconSend, "share": style.IconSend, "send": style.IconSend,
	"copy": style.IconCopy, "paste": style.IconPaste,
	"edit": style.IconPen, "rename": style.IconPen, "sign": style.IconPen, "set": style.IconPen,
	"save": style.IconSave, "keep": style.IconSave, "write": style.IconSave, "record": style.IconSave,
	"delete": style.IconTrash, "remove": style.IconTrash, "forget": style.IconTrash, "revoke": style.IconTrash,
	"deny": style.IconClose2, "refuse": style.IconClose2, "stop": style.IconClose2,
	"cancel": style.IconClose, "close": style.IconClose, "no": style.IconClose,
	"open": style.IconOpen, "mount": style.IconFolder, "unmount": style.IconLock, "browse": style.IconFolder,
	"show": style.IconEye, "hide": style.IconEye, "reveal": style.IconEye, "inspect": style.IconSearch,
	"find": style.IconSearch, "search": style.IconSearch, "look": style.IconSearch, "check": style.IconSearch,
	"resolve": style.IconSearch, "verify": style.IconCheck,
	"lock": style.IconLock, "unlock": style.IconLock, "encrypt": style.IconLock, "decrypt": style.IconLock,
	"import": style.IconDownload, "export": style.IconExternalLink, "attach": style.IconAttach,
	"move": style.IconArrowRight, "back": style.IconArrowLeft, "next": style.IconArrowRight,
	"history": style.IconUndo, "restore": style.IconUndo, "undo": style.IconUndo, "go": style.IconUndo,
	"refresh": style.IconSync, "sync": style.IconSync, "rotate": style.IconSync, "use": style.IconCheck,
	"allow": style.IconCheck, "grant": style.IconCheck, "accept": style.IconCheck, "join": style.IconCheck,
	"ok": style.IconCheck, "yes": style.IconCheck, "done": style.IconCheck, "vouch": style.IconCheck,
	"continue": style.IconArrowRight, "ask": style.IconQuestion, "choose": style.IconFolder,
	"settings": style.IconSettings, "help": style.IconInfo, "about": style.IconInfo,
	"quit": style.IconQuit, "print": style.IconPrint, "mark": style.IconFlag,
}

// ButtonIcon is the icon for a button labelled text; a label it knows no
// icon for gets a plain mark, so that every button has one.
func ButtonIcon(text string) style.ToolIcon {
	l := strings.ToLower(strings.TrimSpace(text))
	for _, p := range iconPhrases {
		if strings.HasPrefix(l, p.prefix) {
			return p.icon
		}
	}
	first, _, _ := strings.Cut(l, " ")
	first = strings.TrimRight(first, "….,:;!?")
	if ic, ok := iconWords[first]; ok {
		return ic
	}
	return style.IconDot
}
