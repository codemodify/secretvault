# What secretvault needs from uitoolkit

This list is for [uitoolkit](https://github.com/codemodify/uitoolkit)'s
maintainers. Both secretvault GUIs are stubs until it is done.

- `secretvault-gui-prompt` asks for passphrases and consent. Items 1–6 block
  it.
- `secretvault-gui`, the manager, needs items 1, 2 and 7–11.

The findings come from reading uitoolkit's source at v0.20.x (file references
are to that tree). Each item says where the gap is, proposes an API in
uitoolkit's own style, and gives a "done when" check. The names are
suggestions; the behaviour is the requirement.

Ground rule for everything below: **a secret never becomes a Go string
inside the toolkit.** Strings are immutable and cannot be wiped, so every
copy lives until the collector gets to it, and then lingers in freed memory.
Secrets travel as `[]byte`, and whoever holds a buffer wipes it.

---

## For the prompt (blocking M1's desktop prompt)

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

## Also worth knowing (not blocking)

- **The file dialog** cannot pick folders or suggest a save name (comms-mail
  gaps 9 and 12). The manager needs both for import, export and choosing
  where a vault lives.
- **Large lists.** If `TableView` does not already virtualise its rows, the
  item list needs it (10,000 items is a realistic vault).
- **Clearing on lock.** When the daemon says a vault locked, the manager
  wipes and hides every revealed secret. That is our code, but it relies on
  item 8's `Hide()` really dropping what it drew from.
