package secretui

import (
	"maps"
	"slices"

	"github.com/codemodify/paintengine2d"
	"github.com/codemodify/uitoolkit"
	"github.com/codemodify/uitoolkit/style"

	"github.com/codemodify/secretvault/svops"
)

// secretvault's look is uitoolkit's Hangar (2026-10-12): a telemetry
// console, a gunmetal ground, one ember accent spent on what is on,
// hairline boxes, three corners cut off every window and panel, and chrome
// labels in capitals. It is a pack of the toolkit's, built in with -tags
// theme_engine_hangar (as scripts/install.sh builds it); secretvault adds
// nothing to it. The look is dark only: a window is in it whatever is
// chosen and whatever the desktop prefers (UseLook); never in the look the
// desktop's uitoolkit settings name. Where the program is built without
// Hangar, its windows are in the dark pack here, secretvault's own colours
// drawn by the toolkit's web engine where that is built in, else flat. The
// light pack is registered still, and used by nothing.

// Hangar is the look's pack, uitoolkit's.
const Hangar = "hangar"

// The packs.
const (
	PackDark  = "secretvault-night"
	PackLight = "secretvault"
)

// darkColors and lightColors are the packs' colours, by the web engine's
// names for them. The window is one ground, #363b3e in the dark look, the
// rail's and the title bar's too (they stand off the pages by a hairline
// and a shadow, svmanager's notes.go); what lies on it is a shade lighter.
var (
	darkColors = map[string]string{
		"window": "#1a2733", "sidebar": "#1a2733", "subPanel": "#141e27", "titleBar": "#1a2733",
		"toolBar": "#1a2733", "card": "#141e27", "tabPane": "#1a2733", "header": "#1a2733",
		"field": "#0f171e", "popup": "#141e27", "popupBorder": "#4b5d6b", "dialog": "#141e27",
		"border0": "#26333d", "border1": "#34444f", "border2": "#26333d", "checkBorder": "#4b5d6b",
		"text": "#c8d3df", "text2": "#7d8d9c", "textDis": "#4c5a66", "link": "#ff7a52", "headerText": "#e8613b",
		"accent": "#e8461f", "onAccent": "#ffffff", "focus": "#e8461f", "fieldFocus": "#e8461f",
		"btn": "#202d39", "btnHover": "#273644", "btnPress": "#141d26", "btnBorder": "#34444f", "btnText": "#c8d3df",
		"wash": "#273644", "sel": "#e8461f", "menuHover": "#e8461f",
		"tip": "#141e27", "tipText": "#c8d3df", "tipBorder": "#4b5d6b",
		"checkOff": "#0f171e", "checkOn": "#e8461f", "checkMark": "#ffffff",
		"switchOff": "#0f171e", "switchOffBorder": "#34444f", "switchOn": "#e8461f", "knobOff": "#7d8d9c", "knobOn": "#ffffff",
		"track": "#0f171e", "progress": "#e8461f", "progressTrack": "#0f171e",
		"scrollThumb": "#4b5d6b", "scrollThumbHot": "#e8461f",
		"tabText2": "#7d8d9c", "segOn": "#273644", "segOnBorder": "#4b5d6b", "segOnText": "#c8d3df",
		"danger": "#ff5a5a", "success": "#5fbf8f", "warning": "#e8a33d",
		"selection": "#e8461f",
	}
	lightColors = map[string]string{
		"window": "#acacaa", "sidebar": "#acacaa", "subPanel": "#a5a5a3", "titleBar": "#acacaa",
		"toolBar": "#acacaa", "card": "#b5b5b3", "tabPane": "#acacaa", "header": "#acacaa",
		"field": "#a6a6a4", "popup": "#b9b9b7", "popupBorder": "#cdcdcb", "dialog": "#b3b3b1",
		"border0": "#bdbdbb", "border1": "#bfbfbd", "border2": "#b6b6b4", "checkBorder": "#7d7d7b",
		"text": "#161616", "text2": "#545452", "textDis": "#858583", "link": "#161616", "headerText": "#545452",
		"accent": "#2c2c2e", "onAccent": "#f3f3f1", "focus": "#2c2c2e", "fieldFocus": "#2c2c2e",
		"btn": "#bdbdbb", "btnHover": "#c6c6c4", "btnPress": "#a2a2a0", "btnBorder": "#c9c9c7", "btnText": "#161616",
		"wash": "#00000010", "sel": "#0000001c", "menuHover": "#0000001c",
		"tip": "#c4c4c2", "tipText": "#161616", "tipBorder": "#cdcdcb",
		"checkOff": "#a6a6a4", "checkOn": "#2c2c2e", "checkMark": "#f3f3f1",
		"switchOff": "#9f9f9d", "switchOffBorder": "#bfbfbd", "switchOn": "#2c2c2e", "knobOff": "#f3f3f1", "knobOn": "#f3f3f1",
		"track": "#9f9f9d", "progress": "#2c2c2e", "progressTrack": "#9f9f9d",
		"scrollThumb": "#0000002a", "scrollThumbHot": "#00000044",
		"tabText2": "#545452", "segOn": "#c6c6c4", "segOnBorder": "#d0d0ce", "segOnText": "#161616",
		"danger": "#a3352a", "success": "#2f7a52", "warning": "#8a6418",
		"selection": "#0000001c",
	}
	// params are the web engine's shapes: Linear's 4px controls, with tabs
	// underlined in the accent, as the picture's.
	params = map[string]float32{"tabStyle": 0, "tabLine": 2, "tabFit": 1, "tabAccent": 1, "tabWeight": 400, "tabSelWeight": 500}
	// fonts are a plain sans, as the picture's; its fields are drawn as an
	// outline on the pane, as the picture's are.
	fonts = style.FontPrefs{UI: []string{"Noto Sans", "Inter", "Roboto", "Cantarell", "DejaVu Sans"}}
)

func init() {
	style.RegisterPack(pack(PackDark, "secretvault Dark", true, darkColors))
	style.RegisterPack(pack(PackLight, "secretvault", false, lightColors))
}

// pack builds one of the packs on Linear's (its shapes and metrics) when
// the web engine is built in, on the base engine's flat bevel otherwise.
func pack(name, label string, dark bool, colors map[string]string) style.ThemePack {
	var tok style.ThemeTokens
	base := "linear"
	if dark {
		base = "linear-night"
	}
	if p, ok := style.LoadTheme(base); ok && slices.Contains(style.EngineIDs(), "web") {
		tok.Engine, tok.Params, tok.Metrics = p.Tokens.Engine, maps.Clone(p.Tokens.Params), p.Tokens.Metrics
		tok.Extra = maps.Clone(p.Tokens.Extra)
	}
	if tok.Params == nil {
		tok.Params = map[string]float32{}
	}
	if tok.Extra == nil {
		tok.Extra = map[string]paintengine2d.Color{}
	}
	maps.Copy(tok.Params, params)
	for k, v := range colors {
		if c, ok := style.ParseHexColor(v); ok {
			tok.Extra[k] = c
		}
	}
	get := func(k string) paintengine2d.Color { return tok.Extra[k] }
	window, text, field, popup, accent := get("window"), get("text"), get("field"), get("popup"), get("accent")
	over := func(base, c paintengine2d.Color) paintengine2d.Color { return style.Mix(base, c.WithAlpha(1), c.A) }
	shadow, overlay := paintengine2d.RGBA(0, 0, 0, 0.18), paintengine2d.RGBA(0, 0, 0, 0.35)
	tok.Family = style.ThemeLight
	if dark {
		tok.Family = style.ThemeDark
		shadow, overlay = paintengine2d.RGBA(0, 0, 0, 0.5), paintengine2d.RGBA(0, 0, 0, 0.55)
	}
	tok.Bevel = style.BevelNone
	tok.Fonts = fonts
	p := style.Palette{
		Background: window, Surface: window, SurfaceAlt: get("sidebar"), Overlay: overlay,
		Border: get("border1"), Divider: get("border2"),
		Text: text, TextMuted: get("text2"), TextOnAccent: get("onAccent"),
		Accent: accent, AccentHover: style.Mix(accent, text, 0.12), AccentPress: style.Mix(accent, window, 0.15),
		Danger: get("danger"), Success: get("success"), Warning: get("warning"),
		Track: get("track"), Thumb: over(window, get("scrollThumb")),
		Field: field, FieldBorder: get("border1"),
		Focus: get("focus"), Selection: over(field, get("selection")),
		Shadow: shadow, Highlight: over(window, get("wash")),
		MenuHover: over(popup, get("menuHover")), MenuHoverBorder: over(popup, get("menuHover")), MenuGutter: popup,
		BevelLight: field, BevelDark: get("border1"),
	}
	tok.Palette = p
	tok.Hot = style.ChromeState{Fill: p.MenuHover, Border: p.MenuHoverBorder}
	tok.Pressed = style.ChromeState{Fill: style.Mix(p.MenuHover, p.Text, 0.06), Border: p.Accent}
	tok.Selected = style.ChromeState{Fill: p.Selection, Border: p.Accent}
	tok.Focus = style.ChromeState{Fill: p.Field, Border: p.Focus}
	fam := style.ThemeLight
	if dark {
		fam = style.ThemeDark
	}
	return style.ThemePack{Name: name, Label: label, Palette: fam, Era: "secretvault", Lineage: "secretvault", Year: 2026,
		Summary: "secretvault's own look: slate panes, hairline borders, flat controls and a soft green accent.", Tokens: tok}
}

// ThemeFor is the pack for the look chosen (svops.LookDesktop, LookDark,
// LookLight) on a desktop that prefers s: Hangar, whatever the choice and
// the desktop (the look is dark only); the dark pack here where the
// program is built without it.
func ThemeFor(look string, s style.ColorScheme) style.ThemeOverride {
	if HangarBuiltIn() {
		return style.ThemeOverride{Pack: Hangar}
	}
	return style.ThemeOverride{Pack: PackDark}
}

// HangarBuiltIn reports whether the program is built with Hangar.
func HangarBuiltIn() bool {
	_, ok := style.LoadTheme(Hangar)
	return ok
}

// looks are the looks chosen, by application: the one each is in.
var looks = map[*uitoolkit.Application]string{}

// UseLook puts every window of a in the look chosen in Tools › Appearance
// (svops.LoadGUIPrefs): dark or light as the desktop is, now and whenever
// it changes its mind, or always one of them.
func UseLook(a *uitoolkit.Application) {
	looks[a] = svops.LoadGUIPrefs().Look
	apply := func() {
		want := ThemeFor(looks[a], a.DesktopColorScheme())
		if a.Theme() != want {
			a.SetTheme(want)
		}
	}
	apply()
	a.OnLookChange(apply)
}

// Look is the look a is in (svops.LookDesktop, LookDark, LookLight).
func Look(a *uitoolkit.Application) string {
	if l, ok := looks[a]; ok {
		return l
	}
	return svops.LookDesktop
}

// SetLook keeps look as the one chosen, and puts every window of a in it
// at once.
func SetLook(a *uitoolkit.Application, look string) error {
	p := svops.LoadGUIPrefs()
	p.Look = look
	if err := svops.SaveGUIPrefs(p); err != nil {
		return err
	}
	looks[a] = look
	a.SetTheme(ThemeFor(look, a.DesktopColorScheme()))
	return nil
}

// IsDark reports whether lk is a dark look: its ground is darker than mid
// grey.
func IsDark(lk style.LookAndFeel) bool {
	bg := lk.Palette().Background
	return 0.2126*bg.R+0.7152*bg.G+0.0722*bg.B < 0.5
}
