# uitoolkit gaps for secretvault

These are the gaps in [uitoolkit](https://github.com/codemodify/uitoolkit) that
secretvault's GUI needs closed, written for the toolkit's maintainers. They
were found by reading the toolkit's source at v0.20.0 while planning, before
any secretvault GUI code existed. They are not yet confirmed by use. Each
entry says where the gap is and what would close it.

They are ordered by impact. The first seven block `secretvault-gui-prompt` (M1),
because a window that asks for a vault passphrase must not leak it. The rest
matter for the manager (M2).

Not a gap, just a note: on Linux the X11 and Wayland back ends need cgo, so
the GUI binaries are the only secretvault binaries built with cgo. The daemon
links no UI code at all (`cmd/secretvaultd/daemon_test.go`).

## Blocking the prompt (M1)

### 1. A password field copies its plaintext

- **Where.** `NewPasswordField` sets `Password=true` on a `TextField`. The
  field paints bullets and masks IME preedit and AT-SPI, but two paths ignore
  `Password` and carry the real text out:
  - Ctrl+C and Ctrl+X copy it (`widgets/textfield.go`, around lines 702–716);
  - dragging the selection carries it too (`widgets/drag.go:34`).
- **Fix.** When `Password` is set, refuse copy, cut and drag-out, and do not
  publish the selection to PRIMARY.

### 2. The secret lives in a Go string

- **Where.** The field's contents are the public `string` field `t.Text`.
  Every keystroke makes a new immutable copy, and none of them can be wiped.
- **Fix.** A secret-text mode that keeps the contents in a `[]byte` (or
  `[]rune`) buffer the toolkit overwrites on edit, with:
  - `Wipe()`;
  - an `OnSubmit` that hands over the bytes, for the caller to wipe.

### 3. No prompt-style window

- **Where.**
  - `WindowOptions` has no parent/transient-for, modal or "centre on screen"
    option.
  - Keep-above works on X11, Windows and macOS, but not on Wayland
    (`app/shade.go`).
  - Wayland toplevels cannot be positioned. `Place: PlaceAtScreen` uses a
    wlr-layer-shell overlay, which works on KWin, sway and Hyprland but not
    GNOME, and takes the keyboard only on demand.
- **Fix.**
  - Options for a centred dialog window that is transient for a parent where
    there is one.
  - On Wayland, `xdg-dialog-v1` and `xdg-activation-v1`, so the prompt
    appears in front and focused.

### 4. No keyboard grab while typing a secret

- **Where.** `XGrabKeyboard` is used only for menu popups
  (`platform/x11_popup_linux.go`). Wayland has no
  `keyboard-shortcuts-inhibit`, and macOS has no `EnableSecureEventInput`.
- **Fix.** A window option that holds the keyboard while it is focused:
  - X11: grab;
  - Wayland: inhibit compositor shortcuts;
  - macOS: secure event input, which also hides keystrokes from other
    processes.

### 5. Prompt windows can be captured

- **Where.** Nothing keeps a window out of screenshots and screen sharing.
- **Fix.** A window option:
  - Windows: `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)`;
  - macOS: `NSWindowSharingNone`;
  - Wayland: a no-op until a protocol exists.

### 6. The input method stays on in password fields

- **Where.** IME remains enabled for password fields (`app/window.go:750`),
  and no "password" purpose is sent to the input method (text-input-v3
  content purpose, XIM, imm32). Input methods can learn and suggest what was
  typed.
- **Fix.** Disable IME for password fields, or at least send the password
  content purpose.

### 7. The clipboard cannot hold a secret safely

- **Where** (`platform/clipboard.go`):
  - `ClipboardSet(string)` writes both CLIPBOARD and PRIMARY.
  - There is no clear call, so only `ClipboardSet("")` on a timer clears it.
  - The toolkit keeps serving the text after its windows close.
  - No clipboard-manager hints are set:
    - `x-kde-passwordManagerHint: secret` on Linux;
    - `ExcludeClipboardContentFromMonitorProcessing` on Windows;
    - `org.nspasteboard.ConcealedType` on macOS.
  - The copy also stays in a Go string.
- **Fix.** `ClipboardSetSecret(data []byte, ttl)`:
  - CLIPBOARD only;
  - the hints above;
  - clearing after `ttl` if the clipboard still holds our data;
  - wiping the toolkit's own copy.

  Plus a `ClipboardClear`.

## Needed for the manager (M2)

### 8. No input or prompt dialog

The same as comms-mail's gap 10. Small, since secretvault builds its own
prompt, but the manager needs "rename", "new vault" and similar one-field
dialogs.

### 9. The macOS tray shows no menu

`SetMenu` stores the rows but shows nothing
(`platform/status_darwin.go:178`). The tray's Lock, Unlock and Search entries
need it.

### 10. No search-as-you-type suggestions

The same as comms-mail's gap 1. A popup that keeps the field's focus, so the
manager's search can suggest items as you type.

### 11. No symbol and emoji fallback

The same as comms-mail's gap 2. Status marks such as ✓ and ✗ and service
icons in item names render as boxes.
