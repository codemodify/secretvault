# What secretvault needs from uitoolkit

This list is for [uitoolkit](https://github.com/codemodify/uitoolkit)'s
maintainers.

- `secretvault-gui-prompt` asks for passphrases and consent. Items 1–6
  blocked it; uitoolkit now has all six, and the prompt is built on them.
- `secretvault-gui`, the manager, needed items 1, 2 and 7–11. It is built,
  on items 1–4, 6, 7 and 9, and on the folder-picking file dialog and the
  virtualised tables below. It still works around item 8.
- Items 12–17 were found while building the prompt, and items 18–24 while
  building the manager. uitoolkit v0.22.1 provides 13–17 and most of 12,
  and both programs now use them in place of their own workarounds; 18–24
  are still open. Items 25–29 are new, found while moving to v0.22.1.
  None blocks either program; each open item says what the program does in
  the meantime.

The GUIs build against uitoolkit v0.22.1 from the module proxy
(`gui/go.mod`). `gui/uitoolkit_test.go` checks items 8, 11–26, 28 and 29
against it, headless, a test per item (`TestItem12CapsLock` and so on): a
provided item's test pins what secretvault now relies on, and an open
item's test pins the gap, so it fails on the uitoolkit release that closes
it. (27 is about where a window lands on a real desktop, which a headless
window does not have.)

| # | Item | State in uitoolkit (after v0.22.1) |
| --- | --- | --- |
| 1 | A secret field that does not leak | **Provided**: `widgets.SecretField` (65463cc) |
| 2 | A dialog window | **Provided**: `WindowOptions` `Role`, `Center`, `KeepAbove`; `Window.Activate` (3fa3094) |
| 3 | Holding the keyboard | **Provided**: `Window.SetSecureInput`, `platform.SecureInputAvailable` (b87afe0). Windows has nothing to offer. |
| 4 | Out of screenshots | **Provided**: `Window.SetExcludeFromCapture` (b87afe0). Windows and macOS only. |
| 5 | No input method in secret fields | **Provided**: a `SecretField` is not an input-method target, so text input is off while it has the focus (65463cc) |
| 6 | Headless driving for tests | **Provided**: `Window.Type`, `Press`, `ClickComponent`, `FocusOn` (a0bd1d7) |
| 7 | A clipboard that can hold a secret | **Provided**: `ClipboardSetSecret`, `ClipboardClear`, `ClipboardGetSecret` (7020c65). The X11 owner still serves its copy from a string. |
| 8 | Showing a secret without a string | **Partly provided**: `widgets.SecretLabel` (256978b). Its mask says how long the secret is, and it draws one line; the manager keeps its own. |
| 9 | A tray menu on macOS | **Provided**: `SetMenu` builds an NSMenu (9f360ec) |
| 10 | Search-as-you-type suggestions | **Provided**: `widget.SetPopupKeysPass` (5285f3e) |
| 11 | Symbol and emoji fallback | **Declined** for text: no font fallback, by contract (`docs/contracts.md`, 1fa27f0). Marks are icons (954da57), which the manager uses. |
| 12 | Caps Lock state | **Partly provided**: `platform.ModCapsLock`, `Window.LockKeys`, `Window.OnLockKeys` (923fab0). A focus-in reads as the lock off, and Wayland and macOS cannot tell before the first key. |
| 13 | A dark desktop with no saved look | **Provided**: `DefaultAppearance` follows the desktop, and Plastik has `plastik-night` (c98f83b) |
| 14 | Spacing that follows the display scale | **Provided**: `FlexBox` and `Grid` (so `Form`) lengths are 1x, with `RawSpacing` to opt out (201bbd6). Pad and Spacer are not: 25. |
| 15 | A window as tall as its content | **Provided**: `WindowOptions.FitContent`, `Window.FitToContent` (923fab0). Centring for the fitted height: 27. |
| 16 | A default button that looks it | **Provided**: every pack marks `Primary`, measured per pack (`style.PrimaryFaceOf`, `style.DrawDefaultMark`, 256978b) |
| 17 | A wrapping label measured at its own width | **Provided**: `Font.Wrap` breaks only where `Font.Advance` overflows (256978b) |
| 18 | Giving a secret field a value | Open |
| 19 | A secret text area | Open |
| 20 | Dialogs that stack | Open |
| 21 | A wrapping label's height in a column | Open (a bug; rows were fixed in fa0093a) |
| 22 | Clicking something scrolled out of view, in a test | Open |
| 23 | Knowing that the tray icon is shown | Open |
| 24 | A widget taken out of the tree still has its window | Open (a bug) |
| 25 | Pad, Spacer and ProgressBar lengths that follow the display scale | Open (new) |
| 26 | `UITK_FONT` turns following the desktop off | Open (new; a bug) |
| 27 | A fitted dialog centred for the height it opens at | Open (new) |
| 28 | Caps Lock for more than one listener, and in the field itself | Open (new) |
| 29 | Readable status colours in `plastik-night` | Open (new) |

The first findings come from reading uitoolkit's source at v0.20.x (file
references are to that tree); 12–24 come from building on it after v0.21.0,
and 25–29 from moving to v0.22.1 (references to that tree). Each item says
where the gap is, proposes an API in uitoolkit's own style, and gives a
"done when" check. The names are suggestions; the behaviour is the
requirement.

Ground rule for everything below: **a secret never becomes a Go string
inside the toolkit.** Strings are immutable and cannot be wiped, so every
copy lives until the collector gets to it, and then lingers in freed memory.
Secrets travel as `[]byte`, and whoever holds a buffer wipes it.

---

## For the prompt (provided; the prompt is built on these)

Items 1–6 are kept as they were asked for, as the record of what the prompt
relies on.

### 1. A secret field that does not leak

- **Today.** `NewPasswordField` is a `*TextField` with `Password=true`
  (`widgets/textfield.go`). It paints bullets and masks IME preedit and
  AT-SPI, but:
  - Ctrl+C and Ctrl+X copy the plaintext (around lines 702–716);
  - dragging the selection carries it out (`widgets/drag.go:34`);
  - the value is the public `string` field `Text`, re-created on every
    keystroke.
- **Proposal.** A widget of its own, so no code path shared with `TextField`
  can leak:

  ```go
  f := widgets.NewSecretField()      // *widgets.SecretField
  f.Placeholder = "Passphrase"
  f.OnSubmit = func(f *widgets.SecretField) {
      pass := f.Bytes()              // a copy; the caller wipes it
      f.Wipe()                       // zero the field's own buffer
      ...
  }
  f.Len()                            // runes, for a strength meter; no content
  f.Reveal = false                   // an app-controlled "show" toggle
  ```

  - Contents are held in a `[]byte` edited in place. When it has to grow, the
    old array is zeroed before it is dropped.
  - Nothing converts it to a `string`. That includes undo history (none),
    accessibility (report the role and a bullet count only), and IME (see 5).
- **Refused:** copy, cut, drag out, selection published to PRIMARY, and
  middle-click paste into it.
- **Allowed:** typing, Backspace and Delete, paste from CLIPBOARD (Ctrl+V),
  select-all then type, and Home, End and the arrow keys.
- **Done when:**
  - Tests show Ctrl+C, Ctrl+X and drag put nothing on the clipboard.
  - After `Wipe` the backing array is all zero.
  - `grep` finds no `string(` conversion of the buffer in the widget.

### 2. A dialog window

- **Today** (`platform/event.go`, `WindowOptions`): there is no dialog role,
  no centring, and no keep-above at creation. `Place: PlaceAtScreen` falls
  back to layer-shell, which GNOME lacks. Keep-above does not work on
  Wayland (`app/shade.go`).
- **Proposal.**

  ```go
  win, _ := app.NewWindow(uitoolkit.WindowOptions{
      Title: "Unlock vault", Width: 460, Height: 220,
      Role:      platform.RoleDialog, // new: Normal (zero value), Dialog
      Center:    true,                // new: centred on the monitor with the pointer or focus
      KeepAbove: true,                // new: at creation, not only via SetKeepAbove later
      Sizing:    platform.SizingFixed,
  })
  win.Activate() // new: bring to front and focus
  ```

- **Per platform:**

  | Platform | Dialog role | Centring | Activate |
  | --- | --- | --- | --- |
  | X11 | `_NET_WM_WINDOW_TYPE_DIALOG` | position at map | `_NET_ACTIVE_WINDOW` |
  | Wayland | `xdg_toplevel`, plus `xdg_dialog_v1` where offered | compositors centre dialogs themselves | `xdg_activation_v1`, using `$XDG_ACTIVATION_TOKEN` when the launcher passed one |
  | Windows | owned popup style | `SetWindowPos` | `SetForegroundWindow` |
  | macOS | `NSPanel` at floating level | `center` | `makeKeyAndOrderFront` |

- **Done when:** a dialog opened from a terminal on GNOME, KDE and sway
  appears in front, focused, centred (by us or by the compositor), and above
  other windows where the desktop allows.

### 3. Holding the keyboard while a secret is typed

- **Today.** `XGrabKeyboard` is used only for menu popups
  (`platform/x11_popup_linux.go`). There is no Wayland shortcuts inhibitor
  and no macOS secure input.
- **Proposal.** `win.SetSecureInput(true)` while the prompt is focused, and
  `platform.SecureInputAvailable()` to report whether the platform supports
  it:
  - X11: `XGrabKeyboard` on the window while it is focused, retried briefly
    if another client holds a grab;
  - Wayland: `zwp_keyboard_shortcuts_inhibit_manager_v1`, so compositor
    shortcuts do not steal keys meant for the field;
  - macOS: `EnableSecureEventInput` / `DisableSecureEventInput`, which also
    hides the keystrokes from other processes;
  - Windows: a no-op.
- **Done when:** on X11, `xinput test` from another client sees no keys while
  the prompt has focus. On macOS, the menu-bar lock indicator shows.

### 4. Keeping the prompt out of screenshots and screen shares

- **Proposal.** `win.SetExcludeFromCapture(true)`, and
  `platform.CaptureExclusionAvailable()`:
  - Windows: `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`;
  - macOS: `NSWindow.sharingType = .none`;
  - Linux: not available, reported as such.
- **Done when:** on Windows and macOS, a screenshot of the desktop shows the
  prompt as blank or absent.

### 5. No input method in secret fields

- **Today.** IME stays enabled for password fields (`app/window.go:750`), and
  no password purpose reaches the input method. Input methods can learn and
  suggest what was typed.
- **Proposal.** While a `SecretField` has focus:
  - Wayland text-input-v3: `set_content_type(hint: sensitive_data |
    hidden_text, purpose: password)`, or disable text input entirely;
  - X11: reset and unset the XIM input context;
  - Windows: `ImmAssociateContext(hwnd, NULL)`;
  - macOS: secure input (item 3) already covers it.
- **Done when:** with an IME active (fcitx5 or ibus), typing into the field
  shows no preedit or candidate window, and the IME's history gains nothing.

### 6. Headless driving for tests

- **Needed for:** secretvault's tests type into a prompt and press its
  buttons without a display.
- **Today.** uitoolkit's `Headless` renders to a PNG.
- **Proposal.** A small test API:

  ```go
  h := uitoolkit.NewTestWindow(opts)      // offscreen
  h.Type("correct horse")                  // key events, as a keyboard would
  h.Press(platform.KeyReturn)
  h.Click(widgetOrID)
  ```

  If this already exists in a form we have not found, a pointer to it is
  enough.

---

## For the manager (M2)

### 7. A clipboard that can hold a secret

- **Today** (`platform/clipboard.go`):
  - `ClipboardSet(string)` writes CLIPBOARD and PRIMARY;
  - there is no clear;
  - the toolkit keeps serving the text after its windows close;
  - no hint keeps clipboard managers from saving it;
  - the copy is a string.
- **Proposal.**

  ```go
  c := platform.ClipboardSetSecret(data []byte, clearAfter time.Duration) // takes ownership of data
  c.Clear()                                                             // clear now, if still ours
  platform.ClipboardClear()
  ```

  - **CLIPBOARD only**, never PRIMARY.
  - **Content types:**
    - Linux: `text/plain;charset=utf-8` and `UTF8_STRING`, plus
      `x-kde-passwordManagerHint` with value `secret`, which KDE's Klipper
      and many clipboard managers honour.
    - Windows: `CF_UNICODETEXT`, plus the registered formats
      `ExcludeClipboardContentFromMonitorProcessing`,
      `CanIncludeInClipboardHistory` = 0 and `CanUploadToCloudClipboard`
      = 0.
    - macOS: the string, plus `org.nspasteboard.ConcealedType` and
      `org.nspasteboard.TransientType`.
  - **Clearing.** After `clearAfter`, if the clipboard still holds our data,
    clear it. The toolkit's own copy is wiped then, and on quit.
- **Done when:**
  - A copied secret pastes, and is gone after the timeout.
  - Klipper's history does not record it.
  - Nothing remains after the app quits.

secretvault's CLI and TUI speak the Wayland and X11 clipboard protocols
themselves; the GUI should use this.

**Status: done** (`uitoolkit.ClipboardSetSecret`). The manager copies
through it, clears after 30 seconds, and clears its own copy when the vault
it came from locks (`SecretClip.Clear`, which leaves somebody else's copy
alone). One limit uitoolkit states itself: on X11 the owner serves the
selection from a Go string while it holds it.

### 8. Showing a secret without making it a string

- **Proposal.** `widgets.NewSecretLabel(value func() []byte)`:
  - it paints bullets;
  - with `Reveal = true` it paints the real text, converting only for the
    paint call and wiping the temporary afterwards;
  - `Hide()` drops anything it cached.

  This is for the item view's "show password" and for TOTP codes.

**Status before v0.22.1: open; the manager has its own.** uitoolkit's
byte-slice text path, `style.Font.DrawBytes` (made for `SecretField`'s
"show"), is enough to build it outside the toolkit, and `secretText` in
`gui/svmanager/secret.go` is that widget: a fixed-length mask when hidden
(so the screen does not say how long the secret is), `DrawBytes` from the
caller's slice when revealed, several lines for a key, and an
accessibility node that says "concealed" and nothing else. It holds the
caller's bytes rather than a copy; `Forget` lets go of them, and the caller
wipes them. It could move into uitoolkit as it is. **Done when** a
`SecretLabel` does the above, and a test shows a revealed value never
reaches the shape cache (`style.ShapeCacheKeysForTest`) or the
accessibility tree.

**After v0.22.1: partly provided; the manager keeps its own.**
`widgets.SecretLabel` (256978b, `widgets/secretlabel.go`) takes its value
from a function, draws it revealed through `DrawBytes`, keeps it out of the
shape cache and the accessibility tree, and `Hide` zeroes what it drew
from. Three things keep `secretText` in the manager:

- Its mask is a bullet per rune (`SecretLabel.mask`), and a hidden label
  is measured for the wider of the bullets and the text, so the screen says
  how long the secret is.
- Its `Describe` reports the bullets, so a screen reader says the length
  too.
- It draws one line, so a PEM or OpenSSH private key cannot be shown in it.

A `MaskLen int` (a fixed count of bullets, measured for that alone), a
`Describe` that says "concealed", and lines split at `\n` as `secretText`
does would close it. `TestItem08SecretLabel` pins all three.

### 9. A tray menu on macOS

`SetMenu` stores the rows but shows nothing
(`platform/status_darwin.go:178`). The manager's tray needs Lock all,
Unlock, Search and Quit on every platform.

**Status: done in uitoolkit** (`SetMenu` builds an NSMenu). The manager's
tray menu (open, search, lock all, quit) is in the window's own menus too.

### 10. Search-as-you-type suggestions

The same as comms-mail's gap 1: a popup that does not take the keyboard from
the field it belongs to, so typing continues while suggestions update.

**Status: done in uitoolkit** (`widget.SetPopupKeysPass`); the manager did
not need it: its search filters the item list in place as you type.

### 11. Symbol and emoji fallback

The same as comms-mail's gap 2: ✓, ✗, → and emoji in item names render as
boxes.

**Status before v0.22.1: open.** The manager uses the toolkit's icons for
its marks (the default vault's star, a conflict's warning, a file's
paperclip) rather than symbols in text; item names are the user's, and can
still hold emoji.

**After v0.22.1: declined for text, provided for marks.** uitoolkit's text
contract (`docs/contracts.md`, 1fa27f0 and a0be7dc) says it plainly: one
face draws everything and there is no font fallback, so a rune the face
lacks is a box; a mark is an icon, not a character. Icons go in table
cells, column headers and tree nodes (954da57), which is what the manager
already does. The bundled interface face has the three non-ASCII runes
secretvault types itself (`…`, `·`, `•`); an emoji in an item's name
still draws as a box, and will. `TestItem11SymbolFallback` checks both.
Nothing more is asked here.

---

## Found while building the prompt

Each item is kept as it was asked for, and ends with its state after
v0.22.1.

### 12. Caps Lock state

- **Today.** `platform.Modifiers` has Shift, Ctrl, Alt and Super, and
  nothing reports the lock keys. A passphrase prompt cannot warn that Caps
  Lock is on, which is the usual reason a right passphrase is refused. The
  prompt shows no warning until this exists. Guessing from the case of what
  was typed would mean reading the secret to do it.
- **Proposal.**

  ```go
  platform.ModCapsLock, platform.ModNumLock // set on key events while locked
  caps, num := win.LockKeys()               // the state now, for a window that has just opened
  win.OnLockKeys(func(caps, num bool))      // it changed, whether or not a key reached a widget
  ```

  - X11: the core state's `LockMask`, and `XkbGetIndicatorState` for the
    state at focus-in;
  - Wayland: `wl_keyboard.modifiers`, the xkb "Lock" modifier in
    `mods_locked`;
  - Windows: `GetKeyState(VK_CAPITAL) & 1`;
  - macOS: `NSEventModifierFlagCapsLock`, and `flagsChanged:` for the change.
- **Done when:** a dialog that opens while Caps Lock is on can say so before
  the first key, and the warning follows the key as it is toggled, on all
  four backends.

**After v0.22.1: partly provided, and both programs warn.** 923fab0 adds
`platform.ModCapsLock` and `ModNumLock` on every event that carries
modifiers, `Window.LockKeys()`, `Window.OnLockKeys`, and
`platform.LockKeysSurface` for asking the backend before any event (X11's
`XkbGetIndicatorState`, Windows' `GetKeyState`; `Offscreen.SetLockKeys`
in tests). `secretui.CapsLock` is a line that says "Caps Lock is on" while
it is: beside the buttons of `secretvault-gui-prompt`'s passphrase
dialog and of the manager's passphrase question, where it takes no room,
and in the manager's new-vault dialog. Two things are missing:

- **A focus-in reads as the lock keys off.** `app/window.go`'s `dispatch`
  notes the lock keys from `EventFocusIn`, and no backend puts modifiers on
  that event (`x11_linux.go`, `wayland_linux.go`, `win32_windows.go`,
  `appkit_darwin.go`). So a window that comes back into focus with Caps
  Lock on says it is off, and calls `OnLockKeys(false)`, until the next
  key. `secretui.CapsLock` asks the backend again whenever `OnLockKeys`
  fires, where the backend can answer (X11, Windows), and so stays right
  there.
- **Wayland and macOS cannot tell before the first key.** Neither surface
  is a `LockKeysSurface`, so `LockKeys()` says off until an event carries
  the state, and the first event that does is not reported as a change
  (`noteLockKeys`). A prompt that opens with Caps Lock on says so only
  once the first key is pressed.

Proposal: backends put the modifiers they know on `EventFocusIn` (Wayland
sends `wl_keyboard.modifiers` right after `enter`; AppKit has
`NSEvent.modifierFlags` at any time), or the window does not take the lock
state from an event that did not carry it; and `noteLockKeys` reports the
first event as a change when it differs from what `LockKeys()` answered
before it. `TestItem12CapsLock` pins the focus-in half.

### 13. A dark desktop with no saved look

- **Today.** With no `look.json` and no `UITK_THEME`, every window opens in
  the default pack (Plastik). In the default build it is light and has no
  dark sibling, and `Appearance.FollowDesktop` defaults to off. So on a
  desktop that prefers dark, a uitoolkit program opens white. A prompt that
  flares up white on a dark desktop is hard to read at the moment it
  matters.
- **Meanwhile.** `secretui.MatchDesktop` applies the default pack's dark
  sibling, or the plain `dark` pack, when the desktop prefers dark and
  nobody has chosen a look. A saved choice is left alone. The manager,
  which stays up while the desktop changes, calls `secretui.FollowDesktop`
  instead: it turns `FollowDesktop` on, in the `light` and `dark` pair
  when the default pack has no dark sibling, and so follows the desktop
  both ways while it runs.
- **Proposal.** A fresh appearance follows the desktop (`FollowDesktop` on
  in `DefaultAppearance`), and the default pack has a dark sibling in every
  build (a `plastik-night`), or `SchemeVariant` falls back to `dark` for a
  pack without one.
- **Done when:** with no `look.json` and the portal saying `prefer-dark`, a
  new window of any uitoolkit program is dark, and turns light with the
  desktop.

**After v0.22.1: provided.** c98f83b turns `FollowDesktop` on in
`DefaultAppearance` (`style/appearance.go`) and gives Plastik a dark
sibling, `plastik-night`; a `look.json` or `UITK_THEME` is still a choice
and is kept. `secretui.MatchDesktop` and `secretui.FollowDesktop` are gone:
both programs take uitoolkit's appearance as it comes, the prompt at
start and the manager as the desktop changes. `TestItem13DarkDesktop`
checks the cases the two functions handled. One case differs:
`UITK_FONT` set without a `look.json` now turns following off (26).

### 14. Spacing that follows the display scale

- **Today.** `FlexBox`'s `WithGap` and `WithPad`, and `Grid`'s (and so
  `Form`'s) `ColGap` and `RowGap`, are device pixels. `Wrap.Gap` and
  `ButtonBox.Gap` are 1x lengths that the toolkit scales. So a dialog's
  margins halve on a 2x display unless the program multiplies them itself.
  The prompt does that, by `style.Dip(look, 1)` when it builds, and so do
  the manager's passphrase dialogs. The manager's main window does not yet:
  its gaps are the same pixels at any scale.
- **Proposal.** Treat them as 1x lengths and scale them by the look, as
  `Wrap` does. Where device pixels are wanted, add an opt-out, rather than
  the other way round.
- **Done when:** a column made `WithPad(20)` measures 40 pixels of padding
  at scale 2, and the samples look the same at 1x and 2x.

**After v0.22.1: provided.** 201bbd6 makes `FlexBox`'s gap and padding and
`Grid`'s (so `Form`'s) `ColGap` and `RowGap` 1x lengths scaled by the look,
with `RawSpacing` for device pixels. Multiplying them by the scale as well
would now square it, so the prompt and the manager's passphrase question
give their lengths as they are, and the manager's main window follows the
scale without anything done. Where they used a Pad or a sized Spacer,
which are still device pixels (25), they use a column's padding instead.
`TestADialogIsTheSameAtEveryScale` (the prompt) checks a dialog is the
same size at 1x and 2x.

### 15. A window as tall as its content

- **Today.** `WindowOptions` wants the size before the window exists. A
  dialog whose height depends on its text (a description of one line or
  five) has to measure its content with a look first: `SetLook(app.Look())`,
  `Measure`, then `SetLook(nil)`. When the toolkit draws the frame (Wayland
  without server decorations), the dialog must then add the caption's height
  with `SetSize`. `secretui.Open` does both, and the two scales it measures
  with (the application's, and later the window's) can differ on a
  multi-monitor desktop.
- **Proposal.** `WindowOptions.FitContent` (with `Width` given, the height
  is the content's), or `Window.FitToContent()`, measured at the window's
  own scale and including any frame the toolkit draws.
- **Done when:** a fixed-size dialog opened with the content's height shows
  no clipped last row and no empty band, at 1x, 1.5x and 2x, with the
  desktop's frame and with the toolkit's.

**After v0.22.1: provided.** 923fab0 adds `WindowOptions.FitContent` and
`Window.FitToContent()` (`app/fitcontent.go`), measured at the window's
own scale and with the caption the toolkit draws, if it draws one.
`secretui.Open` no longer measures anything: it opens the window with
`FitContent`, and calls `FitToContent` and `Center` itself before the
window is first shown, because a window is centred when it is made, for
the height it was made with (27). `TestADialogIsAsTallAsItsContent`
checks one line and six, at 1x, 1.5x and 2x.

### 16. A default button that looks it

- **Today.** `Button.Primary` marks the default button, but some packs,
  Plastik among them, paint it like any other. The consent prompt makes
  Deny the default, so that an Enter pressed without reading refuses. In
  Plastik nothing shows which button Enter will press. Packs that paint a
  default face (the Classic ones, Nocturne) show it well.
- **Proposal.** A pack with no default-button face of its own marks
  `Primary` another way: a heavier border, or the accent on the label.
- **Done when:** in every pack, a row of buttons with one `Primary` shows
  which one it is.

**After v0.22.1: provided.** 256978b measures, per pack, whether its
engine paints `Primary` differently (`style.PrimaryFaceOf`), and draws a
heavier border where it does not (`style.DrawDefaultMark`, the two Amiga
packs). Plastik turns out to mark it itself, with KDE 3's ring around the
default button; it is quieter than an accent fill, but it is there, and
`TestItem16DefaultButton` finds several hundred pixels of difference in
Plastik and `plastik-night`. secretvault had no workaround to remove: the
consent prompt's Deny is `Primary`, and now visibly so.

### 17. A wrapping label measured at its own width

- **Today** (a bug). A `Label` with `Wrap` set, measured with `MaxW` at its
  own unbounded width (rounded up), wraps. `/usr/bin/mail` measures
  91.2 pixels wide on one line, and at 92 it comes back as two lines, the
  word broken. `Font.Wrap` seems to measure the text differently from
  `Font.Advance`. `Grid` (and so `Form`) measures its columns at their
  natural widths whenever the form has room, so every wrapping label in a
  form makes its row a line too tall. Arrange then lays it out on one line,
  and the extra height is left as an empty band under the form.
- **Meanwhile.** The prompt lets a value in its form wrap only when it
  cannot fit on one line at the dialog's width.
- **Proposal.** `Font.Wrap` breaks where `Font.Advance` says the text
  overflows, and `Label.Measure` gives back one line when `MaxW` is at least
  its unbounded width.
- **Done when:** for any text, `Measure(Constraints{MaxW: ceil(Measure(Unbounded()).X)})`
  has the height of `Measure(Unbounded())`, and a form of short wrapping
  labels measures one line per row.

**After v0.22.1: provided.** 256978b makes `Font.Wrap` ask `Font.Advance`
before it breaks (`style/font.go`, `wrapLine`). The prompt's `fitFacts`
is gone: a fact's value always wraps, and a short one is still one line,
which the consent test checks (two facts take two lines).
`TestItem17WrapAtOwnWidth` checks the done-when.

---

## Found while building the manager

As above: each item as it was asked for, then its state after v0.22.1.

### 18. Giving a secret field a value

- **Today.** A `SecretField` takes its contents only as typing and pasting.
  The manager's editor has to show an item's existing password in one, so
  it feeds the bytes in one rune at a time through `TextInput`, the path a
  key press takes. That works and makes no string, but it is a key press
  per character, and a value with a control character cannot go in at all.
- **Proposal.** `f.SetBytes(b []byte)`: the field copies b into its own
  buffer (growing it the way typing does, wiping what it drops); the caller
  keeps b and wipes it.
- **Done when:** `SetBytes` then `Bytes` gives the same bytes back, the old
  buffer is zero afterwards, and nothing converts b to a string.

**After v0.22.1: still open.** `widgets/secretfield.go` has no setter; the
editor still feeds the value in a rune at a time.
`TestItem18SecretFieldSetBytes` fails once one exists.

### 19. A secret text area

- **Today.** Some secrets are several lines: PEM and OpenSSH private keys.
  `SecretField` is one line, and a `TextArea` holds a string.
- **Workaround.** The manager's editor keeps such a value as it is, or
  replaces it with a file's contents, read straight into bytes; it cannot
  be edited in place.
- **Proposal.** `widgets.NewSecretArea()`: `SecretField`'s rules (a byte
  buffer edited in place, no copy, cut, drag or PRIMARY, no input method, a
  mask by default) over several lines.
- **Done when:** a PEM key can be pasted into it, shown and hidden, and
  read back with `Bytes`, with the same tests as `SecretField`.

**After v0.22.1: still open.** There is no secret area, and a
`SecretField` drops a newline typed or pasted into it
(`TestItem19SecretArea`). `SecretLabel` (item 8) shows one line too.

### 20. Dialogs that stack

- **Today.** A window has one overlay. Showing a second dismisses the
  first and runs its `OnClose`, so a confirmation raised from inside a
  dialog closes that dialog, and a dialog that wipes its secret fields on
  close wipes them.
- **Workaround.** The manager never stacks: its editor, history and vault
  pages are pages beside the list, not dialogs, so the generator, a
  confirmation or a file dialog can go over them. A dialog that arrives
  on its own (a new vault's recovery key, when the daemon answers) waits
  for the one up to be done with rather than replace it.
- **Proposal.** `ShowOverlay` pushes and `DismissOverlay` pops the top
  overlay only, whose `OnClose` alone runs; focus goes back to the one
  underneath.
- **Done when:** a confirmation shown over a dialog returns to it, with its
  fields as they were.

**After v0.22.1: still open.** `Window.SetOverlay` (`app/window.go`)
still replaces the overlay and calls the old one's `Dismissed`
(`TestItem20DialogsStack`).

### 21. A wrapping label's height in a column

- **Today** (`layout/flex.go`, `heightForWidth`). A column measures a
  wrapping label at the width it is offered, and the second,
  height-for-width pass is for rows only. In an `Overlay` card that comes
  out narrower than it was offered, the label wraps into more lines than
  were measured, and the card is too short: its last lines and its buttons
  are drawn outside it, and clicks on them miss. The manager's
  confirmations did this with a long program path in the text.
- **Workaround.** The manager pins a dialog's body to one width
  (`fixedWidth` in `gui/svmanager/dialogs.go`), so it is measured and laid
  out at the same width.
- **Also.** A `Wrap` of buttons exactly as wide as the space it gets can
  measure as two lines and lay out as one (a float rounding in `flow`),
  leaving a line's height of empty space under it: the same kind of
  disagreement between measuring and laying out as item 17.
- **Proposal.** Height-for-width in columns too: measure a child again at
  its final width when that differs from the width it was measured at.
- **Done when:** a dialog with a long wrapping message fits its text and
  its buttons at any window width.

**After v0.22.1: still open.** fa0093a added the height-for-width pass for
rows, where a wrapping label that flexes is measured again at its final
width; `Flex.heightForWidth` (`layout/flex.go`) still returns at once for a
column, by design ("Horizontal only"). A column measured at 600 pixels and
laid out at 300 puts its last child outside its box
(`TestItem21WrapInAColumn`), so `fixedWidth` stays. The `Wrap` half is
unchanged too: `Wrap.Measure` flows at the width offered, and
`Wrap.Arrange` at its bounds, which are rounded to whole pixels
(`widgets/wrap.go`).

### 22. Clicking something scrolled out of view, in a test

- **Today.** `Window.ClickComponent` clicks where the component's box is,
  which for a button below a `ScrollView`'s fold is outside the view, so
  the click lands on nothing. The manager's tests scroll to it first
  (`ScrollView.Reveal`).
- **Proposal.** `ClickComponent` reveals the component first, as a person
  scrolls to what they are about to click, and `FocusOn` likewise.
- **Done when:** `ClickComponent` on a button below the fold presses it.

**After v0.22.1: still open.** `ClickComponent` (`app/drive.go`) clicks
the component's box as it is; a button below the fold is not pressed
(`TestItem22ClickBelowTheFold`), and the manager's test harness still
reveals it first.

### 23. Knowing that the tray icon is shown

- **Today** (`platform/status_linux.go`, `Alive`). A Linux status item is
  alive whenever it has a session bus, which is as true of a GNOME that
  shows no tray icons (no AppIndicator extension) as of a KDE that does. An
  application that hides its window in the tray when it is closed, as the
  manager does, would lose the window there.
- **Workaround.** The manager asks the session's
  `org.kde.StatusNotifierWatcher` itself whether
  `IsStatusNotifierHostRegistered`, over secretvault's own D-Bus code, and
  quits on close when no host is.
- **Proposal.** `StatusItem.Shown() bool`: true when a host displays the
  item (the watcher's host flag on Linux; the notification area on
  Windows; the menu bar on macOS), and an `OnShownChange` for a host that
  comes or goes.
- **Done when:** on GNOME without the extension `Shown` is false, and
  turning the extension on makes it true without a restart.

**After v0.22.1: still open.** `platform.StatusItem` has `Alive` and no
`Shown` (`TestItem23TrayShown`); the manager still asks the watcher itself.

### 24. A widget taken out of the tree still has its window

- **Today** (`widget/base.go`, `Remove`, `ClearChildren`). Taking a child
  out clears its parent but not its host, which it and its subtree keep:
  `Add` sets the host, and nothing unsets it. So a component cannot tell
  that it has left the screen, and whatever it is referenced from keeps the
  window reachable through it. The manager kept its coloured labels (muted,
  warning, danger) in a list, to colour them again when the look changed,
  and dropped from it the ones whose host was gone: none ever was, and the
  list grew with every item selected.
- **Workaround.** A coloured label takes its colour from the look it is
  measured and painted in (`tonedLabel` in `gui/svmanager/layout.go`), so
  nothing has to keep track of it.
- **Proposal.** `Remove` and `ClearChildren` call `SetHost(nil)` on what
  they take out, as `Add` sets it. And a label coloured by a palette role
  (`Label.Role = style.RoleDanger`, or `Muted`), which follows the look by
  itself, would make the workaround unnecessary.
- **Done when:** after `Remove(c)`, `c.Host()` is nil, and so is every
  descendant's; adding `c` back gives them the host again.

**After v0.22.1: still open.** `Base.Remove` and `ClearChildren`
(`widget/base.go`) clear the parent and not the host
(`TestItem24RemoveKeepsHost`), and there is no palette role on a label.

---

## Found while moving to v0.22.1

### 25. Pad, Spacer and ProgressBar lengths that follow the display scale

- **Today** (`widgets/flex.go`, `widgets/rule.go`, `widgets/progress.go`).
  Item 14 made `FlexBox` and `Grid` spacing 1x lengths. The other lengths a
  layout is written in are still device pixels: `Pad`'s `L`, `T`, `R`,
  `B` (and `Stack.Pad`), a `Spacer`'s size from `NewSpacerSize` or
  `SetPreferred`, and a `ProgressBar`'s natural width (160 pixels, and
  `SetPreferred` is ignored). A column padded 20 has 40 pixels of padding
  at 2x, and a `Pad` of 20 beside it has 20, so a window built from both
  comes apart at 2x.
- **Workaround.** The manager's right-hand pane is padded by a column
  rather than a `Pad`, and the prompt spaces its paragraphs and its buttons
  with a column's padding rather than a `Spacer`.
- **Proposal.** The same as item 14: `Pad`, `Stack.Pad`, `Spacer` sizes and
  `ProgressBar`'s natural width are 1x lengths scaled by the look, with
  `RawSpacing` (or `RawSize`) for device pixels.
- **Done when:** `NewPad(20, c)` and `NewColumn(c).WithPad(20)` place `c`
  at the same point at every scale, and `NewSpacerSize(10, 10)` is 20
  pixels at 2x. `TestItem25DevicePixelLengths` pins today's behaviour.

### 26. `UITK_FONT` turns following the desktop off

- **Today** (a bug; `style/prefs.go`, `LoadAppearance`). With no
  `look.json`, the appearance is `DefaultAppearance()`, which follows the
  desktop (item 13). But when `UITK_FONT` or `UITK_FONT_MONO` is set, even
  to `theme`, the environment counts as a saved file: the appearance is
  resolved from an empty one, whose `followDesktop` is false. So a program
  run with `UITK_FONT` set, on a dark desktop, opens in light Plastik.
  `secretui.MatchDesktop`, before item 13, did not count `UITK_FONT` as a
  choice of look, so this is the one case in which the programs now
  behave differently.
- **Proposal.** A typeface override changes the typeface: `LoadAppearance`
  starts from `DefaultAppearance()` when there is no file, and lays the
  environment over it, as it does for `UITK_THEME` (which alone turns
  following off, deliberately).
- **Done when:** with no `look.json`, `UITK_FONT=theme` and a dark desktop,
  a new window is dark (`TestItem26FontEnvStopsFollowing` fails).

### 27. A fitted dialog centred for the height it opens at

- **Today** (`platform/x11_linux.go`, where a surface is made;
  `platform/x11_dialog_linux.go`, `Center`; `app/fitcontent.go`). A window
  opened with `Center` is centred when it is made, for the height in
  `WindowOptions`. `FitContent` then changes the height at the first
  layout, before the window is mapped, and does not centre it again. On
  X11 the window keeps its top edge, so a dialog opened with a guessed
  height of 600 and fitted to 250 sits 175 logical pixels above the
  middle. Windows and macOS centre at creation too (`win32_windows.go`,
  `appkit_darwin.go`), for the size the window was made with; Wayland
  compositors centre a dialog themselves.
- **Workaround.** `secretui.Open` calls `FitToContent` and then `Center`
  itself right after `SetContent`, before the first frame, so the window
  is centred for the height it opens at; `FitContent` then finds nothing
  to change.
- **Proposal.** `fitOnFirstLayout` centres a window again when it was
  opened with `Center` and has not been shown yet.
- **Done when:** a dialog opened with `Center`, `FitContent` and any
  `Height` opens centred on X11, Windows and macOS.

### 28. Caps Lock for more than one listener, and in the field itself

- **Today** (`app/lockkeys.go`). `Window.OnLockKeys` is one callback a
  window: a second replaces the first (`TestItem28OneLockKeysListener`).
  A widget that wants the lock state, such as `secretui.CapsLock`, has to
  own the window's callback and give it back, and two of them in one
  window cannot both follow it. And every application with a passphrase
  field writes the same warning line.
- **Proposal.** A `widget.LockKeysWatcher` interface
  (`LockKeysChanged(caps, num bool)`), which the window calls on every
  component under its roots that implements it, as it does for
  `widget.FocusWatcher`; and a `SecretField` that shows a Caps Lock mark
  of its own while it has the focus and Caps Lock is on, as macOS's secure
  text field does (`SecretField.CapsHint`, on by default).
- **Done when:** a focused `SecretField` shows a mark while Caps Lock is
  on, with no application code, and two components in one window both
  hear a change.

### 29. Readable status colours in `plastik-night`

- **Today** (`style/enginekit_kde3.go`, `kde3Scheme.palette`). Every KDE 3
  pack gets the same `Danger` (`#c00000`), `Success` (`#008000`) and
  `Warning` (`#c08000`), chosen for KDE 3's light schemes. On
  `plastik-night`'s background, the look a dark desktop now gets by
  default (item 13), `Danger` is 2.2:1 and `Success` 2.8:1. The prompt's
  "That passphrase does not open this vault." is dark red on near-black.
- **Proposal.** `kde3Scheme` carries its own status colours, and
  `plastik-night` takes lighter ones (a red, green and amber of at least
  4.5:1 on `#2b2b2e`), or `kde3Pack` derives them from the family.
- **Done when:** `style.ContrastRatio` of `Danger`, `Warning` and `Success`
  against `Background` is at least 4.5 in `plastik-night`, as `Danger` is
  in `plastik` (5.6:1). `TestItem29DarkStatusColours` pins today's value.

---

## Also worth knowing (not blocking)

- **The file dialog** could not pick folders or suggest a save name
  (comms-mail gaps 9 and 12); it can now (7da97df). The manager needs both
  for import, export and choosing where a vault lives; it saves attachments
  under their own names with it.
- **Large lists.** If `TableView` does not already virtualise its rows, the
  item list needs it (10,000 items is a realistic vault). **It does**; the
  manager's item list is one.
- **Clearing on lock.** When the daemon says a vault locked, the manager
  wipes and hides every revealed secret. That is our code, but it relies on
  item 8's `Hide()` really dropping what it drew from. **Done**, with the
  manager's own `secretText` (item 8): `Forget` drops its hold on the bytes,
  which the manager has already zeroed, and the frame is redrawn at once.
- **A copy that says it has gone.** `SecretClip` clears itself after its
  timeout without telling anyone, so the manager cannot say "the clipboard
  was cleared" when it was. `SecretClip.OnCleared(func())` would do.
  Still missing after v0.22.1.
- **A dialog for one line of text.** v0.22.0 has `Prompt`
  (`MessageBoxOptions.Input`, f96c633), which the manager's `ask` (a new
  name for an item) could use instead of building its own card.
