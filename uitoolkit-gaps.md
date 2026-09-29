# What secretvault needs from uitoolkit

This list is for [uitoolkit](https://github.com/codemodify/uitoolkit)'s
maintainers.

- `secretvault-gui-prompt` asks for passphrases and consent. Items 1–6
  blocked it; uitoolkit now has all six, and the prompt is built on them.
- `secretvault-gui`, the manager, needs items 1, 2 and 7–11.
- Items 12–17 are new, found while building the prompt. None blocks it; each
  says what the prompt does in the meantime.

| # | Item | State in uitoolkit (after v0.21.0) |
| --- | --- | --- |
| 1 | A secret field that does not leak | **Provided**: `widgets.SecretField` (65463cc) |
| 2 | A dialog window | **Provided**: `WindowOptions` `Role`, `Center`, `KeepAbove`; `Window.Activate` (3fa3094) |
| 3 | Holding the keyboard | **Provided**: `Window.SetSecureInput`, `platform.SecureInputAvailable` (b87afe0). Windows has nothing to offer. |
| 4 | Out of screenshots | **Provided**: `Window.SetExcludeFromCapture` (b87afe0). Windows and macOS only. |
| 5 | No input method in secret fields | **Provided**: a `SecretField` is not an input-method target, so text input is off while it has the focus (65463cc) |
| 6 | Headless driving for tests | **Provided**: `Window.Type`, `Press`, `ClickComponent`, `FocusOn` (a0bd1d7) |
| 7 | A clipboard that can hold a secret | **Provided**: `ClipboardSetSecret`, `ClipboardClear`, `ClipboardGetSecret` (7020c65). The X11 owner still serves its copy from a string. |
| 8 | Showing a secret without a string | Open |
| 9 | A tray menu on macOS | **Provided**: `SetMenu` builds an NSMenu |
| 10 | Search-as-you-type suggestions | **Provided**: `widget.SetPopupKeysPass` (5285f3e) |
| 11 | Symbol and emoji fallback | Open |
| 12 | Caps Lock state | Open (new) |
| 13 | A dark desktop with no saved look | Open (new) |
| 14 | Spacing that follows the display scale | Open (new) |
| 15 | A window as tall as its content | Open (new) |
| 16 | A default button that looks it | Open (new) |
| 17 | A wrapping label measured at its own width | Open (new; a bug) |

The first findings come from reading uitoolkit's source at v0.20.x (file
references are to that tree); 12–17 come from building on it after v0.21.0.
Each item says where the gap is, proposes an API in uitoolkit's own style,
and gives a "done when" check. The names are suggestions; the behaviour is
the requirement.

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

### 8. Showing a secret without making it a string

- **Proposal.** `widgets.NewSecretLabel(value func() []byte)`:
  - it paints bullets;
  - with `Reveal = true` it paints the real text, converting only for the
    paint call and wiping the temporary afterwards;
  - `Hide()` drops anything it cached.

  This is for the item view's "show password" and for TOTP codes.

### 9. A tray menu on macOS

`SetMenu` stores the rows but shows nothing
(`platform/status_darwin.go:178`). The manager's tray needs Lock all,
Unlock, Search and Quit on every platform.

### 10. Search-as-you-type suggestions

The same as comms-mail's gap 1: a popup that does not take the keyboard from
the field it belongs to, so typing continues while suggestions update.

### 11. Symbol and emoji fallback

The same as comms-mail's gap 2: ✓, ✗, → and emoji in item names render as
boxes.

---

## Found while building the prompt

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

### 13. A dark desktop with no saved look

- **Today.** With no `look.json` and no `UITK_THEME`, every window opens in
  the default pack (Plastik). In the default build it is light and has no
  dark sibling, and `Appearance.FollowDesktop` defaults to off. So on a
  desktop that prefers dark, a uitoolkit program opens white. A prompt that
  flares up white on a dark desktop is hard to read at the moment it
  matters.
- **Meanwhile.** `secretui.MatchDesktop` applies the default pack's dark
  sibling, or the plain `dark` pack, when the desktop prefers dark and
  nobody has chosen a look. A saved choice is left alone.
- **Proposal.** A fresh appearance follows the desktop (`FollowDesktop` on
  in `DefaultAppearance`), and the default pack has a dark sibling in every
  build (a `plastik-night`), or `SchemeVariant` falls back to `dark` for a
  pack without one.
- **Done when:** with no `look.json` and the portal saying `prefer-dark`, a
  new window of any uitoolkit program is dark, and turns light with the
  desktop.

### 14. Spacing that follows the display scale

- **Today.** `FlexBox`'s `WithGap` and `WithPad`, and `Grid`'s (and so
  `Form`'s) `ColGap` and `RowGap`, are device pixels. `Wrap.Gap` and
  `ButtonBox.Gap` are 1x lengths that the toolkit scales. So a dialog's
  margins halve on a 2x display unless the program multiplies them itself.
  The prompt does that, by `style.Dip(look, 1)` when it builds.
- **Proposal.** Treat them as 1x lengths and scale them by the look, as
  `Wrap` does. Where device pixels are wanted, add an opt-out, rather than
  the other way round.
- **Done when:** a column made `WithPad(20)` measures 40 pixels of padding
  at scale 2, and the samples look the same at 1x and 2x.

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

---

## Also worth knowing (not blocking)

- **The file dialog** could not pick folders or suggest a save name
  (comms-mail gaps 9 and 12); it can now (7da97df). The manager needs both
  for import, export and choosing where a vault lives.
- **Large lists.** If `TableView` does not already virtualise its rows, the
  item list needs it (10,000 items is a realistic vault).
- **Clearing on lock.** When the daemon says a vault locked, the manager
  wipes and hides every revealed secret. That is our code, but it relies on
  item 8's `Hide()` really dropping what it drew from.
