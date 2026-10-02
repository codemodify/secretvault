# What secretvault needs from uitoolkit

This list is for [uitoolkit](https://github.com/codemodify/uitoolkit)'s
maintainers.

**Does uitoolkit v0.23.2 address all of secretvault's needs? No, not
yet.** It closes most of what v0.23.1 left: of the 49 items, 42 are
satisfactory and one (11) is declined by design. The Wayland owner
serving a secret from a string (41), the copies a pasted passphrase left
(42, on every platform now), X11 reading its own copy (43), a window's
stated minimum (44), a hidden form row's gap (38, 45), a grid cell
offered no width (39) and a dialog taller than its window (40) hold, and
secretvault has taken out its workarounds for them: a keyslot is added in
one step, a long key wraps to the width it is given, a QR code is shown
under its invite again, every dialog scrolls with its buttons in view, and
the manager no longer states its floor again after a resize. What is
left:

- touching the passphrase, on the clipboard, all found in this audit and
  all older than v0.23.2:
  - on Wayland the password-manager hint is answered with the passphrase
    itself, so KDE's Klipper keeps it in its history (47);
  - a copied secret outlives the clipboard: once something else is
    copied, a paste into a `SecretField` still takes the old secret, and
    the clear at the timeout, a lock or the quit empties whatever is on
    the clipboard by then on Windows, macOS and Wayland (48);
  - a pasted secret longer than one read (a private key) leaves the
    buffers it outgrew, on Wayland and in X11's INCR transfer (49);
- touching the passphrase, on Wayland: a prompt opened with Caps Lock on
  still cannot say so before the first key (12). v0.23.2 says the
  protocol does not allow it; it does;
- and one that does not touch a secret: `widgets.DialogContent`, the
  piece v0.23.2 gives for 40, sizes its card to the window rather than to
  what it holds, and squeezes a `ButtonBox` to its natural width (46).

secretvault works around 46 in its own code (its dialogs are built the
same way with a body that sizes to its content), and 47 and 48 on Linux
and the BSDs, where the manager now copies through the CLI beside it
(`secretvault __clip`, svclip), as the CLI and the TUI do; on Windows and
macOS it still copies through uitoolkit, and 48 stands there. 12 and 49 it
cannot.

- `secretvault-gui-prompt` asks for passphrases and consent, and
  `secretvault-gui` is the manager; both are built on uitoolkit.
- Items 1–11 were asked for before either was built, 12–17 while building
  the prompt, 18–24 while building the manager, and 25–37 while moving
  through the releases since (25–29 at v0.22.1, 30–32 at v0.22.2, 33–34 at
  v0.22.5, 35–37 in the audit of v0.23.0), 38–40 while bringing the
  manager level with the CLI, on v0.23.0, 41–45 in the audit of v0.23.1,
  and 46–49 in the audit of v0.23.2.
- **The audit of v0.23.2** re-read every item from scratch against the
  release as the module proxy serves it (the same tree as uitoolkit's
  checkout at the tag). v0.23.2 changed the secret clipboard
  (`clipboard_secret*.go` on all three platforms, the Wayland owner and
  reader, X11's reader and the property it frees), size limits (every
  backend's `SetSizeLimits`, `platform/sizing.go`), `widget.MinWidthOf`,
  `Grid`, `FormRow`, `DialogCard`, `IconButton` and `BrowserTabs`; the
  others are as they were in v0.23.1, and their pins pass. Every changed
  path was read through to the platform backends, Windows and macOS
  included, error paths too, and each fix checked against the need as
  stated, not against its own description. The clipboard was read once
  more end to end, not only where it changed: that found 47 and 48, which
  every audit before this one missed. The pins test the behaviour where a
  headless window can show it (7, 34, 38–40, 44–46, 48), and read
  uitoolkit's functions, parsed rather than grepped, where it cannot (12,
  35, 37, 41–43, 47–49).
- **The manager's clipboard.** On Linux and the BSDs the manager copies
  through the CLI beside it (`gui/svmanager/clip.go`): `secretvault
  __clip SECONDS`, the secret on its stdin, takes the clipboard in a
  process of its own through svclip (Wayland's data control, or X11, as
  XWayland on GNOME), offers the hint as "secret", and clears the
  clipboard at its time only if the clipboard is still its own; a copy
  taken back (its vault locked, the program quitting) ends the helper, and
  its selection goes with it, only if it still has it. Security: Klipper
  honours the hint (47), nobody else's copy is cleared (48), and the
  manager's own heap holds no copy while the secret is on the clipboard.
  UX: the same, the status line saying when the copy has gone; a paste
  into the program's own `SecretField` reads the clipboard itself, not a
  stale copy (48). Complexity: a hundred lines and a headless test (the
  test binary standing in for the CLI); where there is no CLI beside the
  program, or it cannot reach a clipboard, the copy goes to uitoolkit's
  as before. Not on Windows, where an ended helper leaves its copy on the
  clipboard so a lock could not take it back, nor on macOS, where svclip
  has no pasteboard yet. When uitoolkit closes 47 and 48 the manager can
  go back to `ClipboardSetSecret` everywhere.
- **What v0.23.2 gave that the list never asked for.** `BrowserTabs.Align`,
  the selected browser tab's merge, `style.TabLabelInkOf` and
  `TabContentInsetOf`: secretvault has no browser tabs. An `IconButton`'s
  mark at the look's icon size (`style.IconSizeOf`): the manager's marks
  are on buttons, table cells and tree nodes, not `IconButton`s. And
  `widget.MinWidthOf`'s rule that a component holding one thing is never
  narrower than it: the manager's wrappers (`page`, `shortcutRoot`,
  `slot`) keep answering `MinWidther` themselves, which gives exactly
  their child's floor rather than the larger of the probe's guess and
  the child's.

Two voices below. **"After v0.2x.y"** paragraphs are secretvault's own
checks, each pinned by a test in `gui/uitoolkit_test.go`. **"Closed in
0.2x.y"** paragraphs are uitoolkit's maintainers' notes on the same items;
those for 0.23.1 and 0.23.2 are their release notes' words, copied
verbatim (for 0.23.2, the commit's where the release notes say less). The
maintainers count all of 18–32 closed by 0.22.3, 8, 23 and 28 closed by
0.22.5, 12, 33–38 and 40 closed by 0.23.1, and 39 and 41–45 closed by
0.23.2, with 12's other half "still open" as the protocol's. secretvault's
checks agree on 8, 18–29, 31–39, 41–45, and on 40 for the need, and
disagree on:

- 7: on Wayland the hint is answered with the secret (47), and a copied
  secret outlives the clipboard on every platform (48);
- 12: on Wayland the state is there before the first key: the compositor
  sends `wl_keyboard.modifiers` right after `enter`, and the backend
  keeps it;
- 30: `DismissOverlay` from outside closes the *top* dialog only, so the
  manager keeps `SetOverlay(nil)` at quit, which closes them all;
- 40: `DialogContent` keeps the buttons in view, but its card is as tall
  as the window allows whatever it holds, and a `ButtonBox` in its foot
  loses the platform's layout (46);
- 42: the buffers named hold; a paste longer than one read leaves the
  ones it outgrew (49).

The GUIs build against uitoolkit v0.23.2 from the module proxy
(`gui/go.mod`). `gui/uitoolkit_test.go` checks every item from 7 on
against it, headless, a test per item (`TestItem12CapsLock` and so on): a
provided item's test pins what secretvault relies on, and an open item's
test pins the gap, so it fails on the uitoolkit release that closes it.
Item 23's tray half is pinned in `gui/svmanager/tray_test.go` on a private
session bus; 12, 35, 37, 41–43 and 47–49 are about code no headless window
reaches, and their pins read uitoolkit's source as the test is built
against it.

| # | Item | After v0.23.2 | Verdict |
| --- | --- | --- | --- |
| 1 | A secret field that does not leak | `widgets.SecretField` (65463cc): a byte buffer edited in place, zeroed when outgrown or shortened, copy, cut, drag and PRIMARY refused, no string made of it; a paste is bytes on every platform (e54cba4, 18a98d9) | **Satisfactory**; a long paste: 49 |
| 2 | A dialog window | `Role`, `Center`, `KeepAbove`, `Activate` (3fa3094) | **Satisfactory** |
| 3 | Holding the keyboard | `SetSecureInput`, and since 3c3c2c7 `SecureInputHeld`, `OnSecureInput`, the X11 grab taken at the map | **Satisfactory** (37); the prompts say "Keyboard held" |
| 4 | Out of screenshots | `Window.SetExcludeFromCapture` (b87afe0); Windows and macOS only | **Satisfactory** where a platform can; X11 and Wayland cannot, by the platform |
| 5 | No input method in secret fields | input method off while a `SecretTarget` has the focus (`app/window.go`, `syncIMECursor`) | **Satisfactory** |
| 6 | Headless driving for tests | `Type`, `Press`, `ClickComponent`, `FocusOn` (a0bd1d7) | **Satisfactory** |
| 7 | A clipboard that can hold a secret | `ClipboardSetSecret` and the rest (7020c65), `OnCleared` (58140ea); bytes everywhere (e54cba4, d9356f0); wiped before it is said gone (9e7e1c6) | **Satisfactory on X11 only** (47, 48); the manager copies through the CLI on Linux |
| 8 | Showing a secret without a string | `SecretLabel.MaskLen`, `Lines`, `Describe` (649af18); no copy masked (6126bcd) | **Satisfactory**; the manager keeps its own, which holds no copy revealed either |
| 9 | A tray menu on macOS | `SetMenu` builds an NSMenu (9f360ec) | **Satisfactory** (not run on macOS here) |
| 10 | Search-as-you-type suggestions | `widget.SetPopupKeysPass` (5285f3e) | **Satisfactory** (unused) |
| 11 | Symbol and emoji fallback | no font fallback, by contract (`docs/contracts.md`) | **Declined**; marks are icons, which the manager uses |
| 12 | Caps Lock state | `ModCapsLock`, `LockKeys`, `OnLockKeys` (923fab0); a focus-in left alone (285b6b7) | **Partly**: X11 and Windows; on Wayland (and macOS) nothing before the first key |
| 13 | A dark desktop with no saved look | `FollowDesktop` by default, `plastik-night` (c98f83b) | **Satisfactory** |
| 14 | Spacing that follows the display scale | 1x lengths (201bbd6, 36685fe) | **Satisfactory** |
| 15 | A window as tall as its content | `FitContent` (923fab0), re-centred (58140ea) | **Satisfactory** |
| 16 | A default button that looks it | measured per pack (256978b) | **Satisfactory** |
| 17 | A wrapping label measured at its own width | `Font.Wrap` (256978b) | **Satisfactory** |
| 18 | Giving a secret field a value | `SecretField.SetBytes` (58140ea), taking ownership | **Satisfactory** |
| 19 | A secret text area | `widgets.SecretArea` (fc42680) | **Satisfactory**; a long paste: 49 |
| 20 | Dialogs that stack | (fc42680) | **Satisfactory** |
| 21 | A wrapping label's height in a column | for dialogs (91133b2); a column is the caller's | **Satisfactory** |
| 22 | Clicking something scrolled out of view | (5e7a6cc) | **Satisfactory** |
| 23 | Knowing that the tray icon is shown | `Shown`, `SetOnShownChange` (58140ea, 649af18) | **Satisfactory** |
| 24 | A widget taken out of the tree still has its window | (58140ea) | **Satisfactory** |
| 25 | Pad, Spacer and ProgressBar lengths | (36685fe) | **Satisfactory** |
| 26 | `UITK_FONT` turns following the desktop off | (58140ea) | **Satisfactory** |
| 27 | A fitted dialog centred | (58140ea) | **Satisfactory** |
| 28 | Caps Lock in the field itself | `LockKeysWatcher`, `CapsHint`, `LockKeysOf` (5e7a6cc, 649af18); kept through a focus-in (285b6b7) | **Satisfactory** |
| 29 | Readable status colours | `Ink`, `Label.Tone` (36685fe, 6e1d4f9) | **Satisfactory** |
| 30 | Closing a dialog from outside every dialog | the top one (6e1d4f9) | **Satisfactory**; all of them is `SetOverlay(nil)` |
| 31 | Status ink that keeps its colour | (6e1d4f9) | **Satisfactory** |
| 32 | A SecretArea in a narrow form | (6e1d4f9), `PreferredWidth` | **Satisfactory** |
| 33 | A hidden SecretLabel's copy of the secret | (6126bcd) | **Satisfactory** |
| 34 | A window's floor from its content | `Window.SetMinSize`, `Splitter.MinWidth`, `TextField.PreferredWidth` (afa38a3, 3a0fba6); a one-child wrapper (99e0c22) | **Satisfactory**; it lasts (44) |
| 35 | A secret on the Linux clipboard as a string | (e54cba4, d9356f0, 99e0c22) | **Satisfactory**; what is left is 47–49 |
| 36 | A form value read aloud as its caption | (570438f) | **Satisfactory**; the prompt's workaround is gone |
| 37 | Secure input's answer, and its first attempt | (3c3c2c7) | **Satisfactory**; a failed grab is no diagnostic, which secretvault does not need |
| 38 | A form's rows shown or hidden | `Form.Row`, `FormRow` (021593b); no gap (d9356f0) | **Satisfactory**; Add… for a keyslot is one step |
| 39 | A grid cell offered no width | `widgets.Share` (e011659) | **Satisfactory**; the manager's fixed wrap is gone |
| 40 | A dialog taller than its window | `DialogCard` (bba1c63), `DialogContent` (dbb2644) | **Satisfactory** for the need; `DialogContent` itself: 46. The QR code is back under its invite |
| 41 | The Wayland owner serves a secret from a string | (d9356f0) | **Satisfactory** |
| 42 | What a pasted secret leaves behind | (d9356f0, 18a98d9) | **Satisfactory** for a passphrase; a long paste: 49 |
| 43 | X11 reads its own copy as the last paste | (99e0c22) | **Satisfactory** |
| 44 | A window's stated minimum does not last | (99e0c22) | **Satisfactory**; the manager no longer states it again |
| 45 | A hidden form row keeps its gap | (d9356f0) | **Satisfactory** |
| 46 | `DialogContent` fills the window, and squeezes a `ButtonBox` | (new) | **Open**; the manager builds the arrangement itself |
| 47 | Wayland answers the password-manager hint with the secret | (new, older than v0.23.1) | **Open**; the manager copies through the CLI on Linux |
| 48 | A copied secret outlives the clipboard | (new, older than v0.23.1) | **Open**; the manager copies through the CLI on Linux |
| 49 | What a long pasted secret leaves behind | (new) | **Open** |

The first findings come from reading uitoolkit's source at v0.20.x (file
references are to that tree); 12–24 come from building on it after v0.21.0,
25–29 from moving to v0.22.1, 30–32 from moving to v0.22.2, 33–34 from
moving to v0.22.5, 35–37 from the audit of v0.23.0, 41–45 from the
audit of v0.23.1 and 46–49 from the audit of v0.23.2 (references to
those trees). Each item says where the
gap is, proposes an API in uitoolkit's own style, and gives a "done when"
check. The names are suggestions; the behaviour is the requirement.

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

**After v0.23.0 (item 1): satisfactory, but for a paste.** Read again:
`widgets/secretfield.go` makes no string of the buffer (the only strings
are the bullets); `replace` zeroes the old array when it grows and the
tail when it shortens; `Bytes` is a copy; Ctrl+C and Ctrl+X are consumed
and refused, and nothing goes to PRIMARY. A paste reads
`platform.ClipboardGetSecret`, which is byte for byte when the secret is
this program's own copy, and otherwise `[]byte(ClipboardGet())`: the
other program's passphrase is a string in this process first (35). Its
accessible value is a bullet per rune, so a screen reader can say how
much has been typed, which is what an editable field is expected to
say.

**After v0.23.1 (item 1): satisfactory, and a paste is bytes on Linux.**
`widgets/secretfield.go` is as it was. A paste of another program's
secret now goes through `clipboardNativeGetSecret`, which reads the X11
property (`C.GoBytes`) or the Wayland pipe into bytes and hands them over
without a string (e54cba4). What a paste still leaves is 42: when that
read fails it is made again as a string, the readers' own buffers are not
zeroed, and Windows and macOS have no bytes path at all.

**After v0.23.2 (item 1): satisfactory; a long paste leaves what it
outgrew (49).** `widgets/secretfield.go` is as it was. A paste of another
program's secret is bytes on every platform now: X11's property and the
Wayland pipe (e54cba4), Windows' `CF_UNICODETEXT` and the macOS pasteboard
(18a98d9), each through buffers zeroed once read, and a read that fails
is not made again as a string where a bytes path exists (42). What is left
is 49: a paste longer than one read of the Wayland pipe, or than X11
sends at once, leaves the buffers it outgrew. The comment on `paste`
still says another program's secret comes in as a string; it no longer
does.

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

**After v0.23.0: not satisfactory (37).** `platform/x11_secure_linux.go`
tries `XGrabKeyboard` for a quarter of a second and answers whether it
held; the grab is dropped at a focus-out and retaken at a focus-in, once,
without telling anybody whether that worked. A prompt asks as its
passphrase field takes the focus, which is at its first layout, before an
X11 window is mapped: the grab cannot succeed then, so the first frame
waits a quarter of a second and the answer is false, and the grab that
does hold comes later at the focus-in. So `SetSecureInput`'s answer
cannot be used to tell the person the keyboard is not held: on X11 it
would say so every time. None of it is reported through the new
diagnostics (35e0ff9) either. secretvault records nothing from it.

**Closed in 0.23.1** (the release notes, verbatim): **Secure input says what is in effect.** The grab follows the focus and a retake can fail, and none of that was reported, so an application could not say "the keyboard is not held" without being wrong on X11 every time. New: `Window.SecureInputHeld`, `Window.OnSecureInput`, `platform.SecureInputHeldSurface`. A request made before the window is mapped is also recorded rather than retried for a quarter of a second against a window that cannot be grabbed yet.

**After v0.23.1: satisfactory (37), and both programs say so.** A request
made before an X11 window is mapped is recorded and answered at once; the
grab is taken at the map, and again at each focus-in before the window
hears of the focus, so `Window.SecureInputHeld` and `OnSecureInput` say
what is in effect (`x11Surface.secureHeld`). secretui's frame follows
`OnSecureInput`: the header of every secretvault dialog, the prompt's and
the manager's passphrase question, says "Keyboard held" while it is, and
tells a screen reader so, and says nothing while it is not, which on
Windows is always. On Wayland "held" is the inhibitor having been made:
the compositor's `active` and `inactive` events are not followed, which
matters little there, since no other client sees the keys anyway; on
macOS it is secure event input turned on.

### 4. Keeping the prompt out of screenshots and screen shares

- **Proposal.** `win.SetExcludeFromCapture(true)`, and
  `platform.CaptureExclusionAvailable()`:
  - Windows: `SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE)`;
  - macOS: `NSWindow.sharingType = .none`;
  - Linux: not available, reported as such.
- **Done when:** on Windows and macOS, a screenshot of the desktop shows the
  prompt as blank or absent.

**After v0.23.0: satisfactory where a platform can.** Windows
(`SetWindowDisplayAffinity`) and macOS (`sharingType = .none`) answer what
they did; X11 and Wayland cannot keep a window out of a capture, and
`CaptureExclusionAvailable` says so in advance. The prompt asks on every
platform and does not tell the person on X11 and Wayland, where the
answer is always no.

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

**After v0.23.0: satisfactory.** `app/window.go`, `syncIMECursor`, turns
text input off whenever the focus is a `widget.SecretTarget`, which
`SecretField` and so `SecretArea` declare; the backends unset the input
context (X11), stop text input (Wayland) and dissociate it (Windows).

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
selection from a Go string while it holds it. Since v0.22.2 the status bar
says when a copy has gone at its timeout (`SecretClip.OnCleared`,
58140ea).

**After v0.23.0: not satisfactory on Linux (35).** Read again, the limit
the toolkit states is narrower than the code: `clipboard_secret_linux.go`
makes one string of the secret (`s := string(b)`) and hands it to the
Wayland data source *and* the X11 owner, and each serves from it for as
long as it owns the selection; clearing drops the reference
(`wipeClipLocked` sets it to ""), which zeroes nothing. Windows and macOS
hand it to the system and keep no copy. CLIPBOARD only, the password
manager hint and the timeout are as they were.

**Closed in 0.23.1** (the release notes, verbatim): **A secret on the Linux clipboard is never a Go string.** Owning a selection means holding the value, so the question was never whether a copy exists but whether anything can wipe it. Both owners hold bytes and zero them when the selection is given up, cleared or replaced; the X11 serving path also stopped copying through `C.CString`, into a buffer `free()` does not zero. Pasting another program's secret has a bytes path too.

**After v0.23.1: satisfactory on X11, not on Wayland (41).** Read again,
end to end. `clipboardNativeSetSecret` hands the bytes to both owners,
and nothing on the way makes a string; the X11 owner copies them
(`setClipboardSelBytes`), serves them from the slice itself, and zeroes
them when the selection is lost, cleared, replaced or times out
(`wipeClipLocked`, from `handleSelClear` and `clearClipboard`); the
Wayland owner copies them into its cache and zeroes that on the same
occasions (`clipCache.setBytes`, `wipe`). But the Wayland owner answers
every paste another program asks for with `clipCache.get`, which is
`string(c.data)`, and writes `[]byte` of that string to the pipe: two
copies of the passphrase that nothing wipes, made at every paste. That is
41. Windows and macOS hand the value to the system and keep none, as
before; CLIPBOARD only, the password-manager hint and the timeout are as
they were. The same change broke X11's reading of its own selection
(43), which reaches a `SecretField` pasting the program's own ordinary
copy.

**Closed in 0.23.2** (the release notes, verbatim): **A secret was still in the heap after the clipboard said it was gone.** `SecretClip.Clear` dropped the clipboard's reference first — so `ClipboardHoldsSecret` answered false at once — then told the window system, which is a round trip to a compositor, an X server or the Windows clipboard, and only after that zeroed the bytes. For the whole of that trip the passphrase was in the heap while every way of asking said nothing was held. It had been on the flaky-test list for weeks. It was never flaky: a quiet Linux box wins the race, a loaded Windows VM loses it every time, and nobody had looked at why. The copy is zeroed first now, before anything slow happens, and the application's callback runs last — so "it is gone" means the clipboard and not only this copy. **A secret never becomes a Go string on any platform.** 0.23.1 did Linux. Windows decoded `CF_UNICODETEXT` through `syscall.UTF16ToString`, which builds a string on the way to bytes; macOS read `C.GoString` of a `strdup`'d buffer and then `free`d it without clearing, leaving a second copy for whatever got that allocation next. Both have a bytes path now, each zeroing what it worked through. The Wayland *serving* side is bytes too: every paste another client asked for used to go out through a string and back, two copies per paste.

**After v0.23.2: satisfactory on X11; on Wayland, Windows and macOS not
(47, 48); the manager copies through the CLI on Linux.** Read once more
end to end, every backend, and not only where it changed. The fix holds:
`SecretClip.Clear` zeroes the toolkit's copy before it tells the window
system (`wipe`, then `clipboardNativeClear`), and calls back last;
`TestItem07ASecretOnTheClipboard` checks it headless, with the callback
seeing the bytes zeroed and nothing held. The owners' own copies (X11's
`clipData`, the Wayland cache) are zeroed by `clipboardNativeClear` as
before, and Windows and macOS keep none. `ClipboardClear`, which a lock
and the quit run, still calls back before it tells the clipboard; nothing
of secretvault's waits on that. CLIPBOARD only and the timeout are as they
were. Two things fall short of the item as asked, both older than
v0.23.1 and missed by every audit before this one:

- on Wayland the owner offers `x-kde-passwordManagerHint` and answers it,
  like every type it offers, with the clipboard's bytes: Klipper reads the
  passphrase where it looks for "secret", and keeps it in its history,
  which it saves to disk (47). X11 answers the hint with "secret";
- the item's clear is "if the clipboard still holds our data", and
  nothing tells a `SecretClip` that the clipboard has moved on: the clear
  at the timeout, at a lock and at the quit empties whatever is there by
  then on Windows (`EmptyClipboard`), macOS (`clearContents`) and Wayland
  (an empty offer, which takes the primary selection too); X11 checks it
  owns the selection, but its own later ordinary copy it does own; and a
  paste into a `SecretField` takes the old secret rather than what is on
  the clipboard (48).

So the manager, on Linux and the BSDs, copies through the CLI beside it
(`gui/svmanager/clip.go`: `secretvault __clip SECONDS`, which serves the
clipboard with svclip, honours the hint and clears only its own), and
through `ClipboardSetSecret` where there is no CLI or it cannot reach a
clipboard, and on Windows and macOS. `TestCopiesGoThroughTheCLI` pins it
headless, the test binary standing in for the CLI.

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

**After v0.22.2: unchanged.** `widgets/secretlabel.go` is as it was, and
the manager keeps `secretText`.

**After v0.22.3: unchanged** (6e1d4f9 does not touch it).

**After v0.22.5: provided, not satisfactory; the manager keeps
`secretText`.** 649af18 does what was asked of the label's face: with
`MaskLen` a hidden label is measured for its mask alone, so the screen no
longer says the length; `Describe` says "concealed" (or "revealed
secret", or "empty") and never counts bullets; `Lines` shows a key's lines.
Nothing in it turns the value into a string: the mask is the only
string, and revealed text goes through `DrawBytes` and `AdvanceBytes`.
But a hidden label still calls `Value` on every measure and paint and
copies the answer into a buffer of its own, though bullets are all it
draws, and that copy is wiped only by `Hide` or by a shorter value; a
label that leaves the window keeps it, unwiped, until the collector. The
manager's `secretText` holds the caller's bytes and no copy, so adopting
`SecretLabel` would add a copy of every secret on screen. That is 33.
`TestItem08SecretLabel` now checks what 649af18 fixed.

**After v0.23.0: unchanged, and still not satisfactory (33).**
`widgets/secretlabel.go` is as it was in v0.22.5.

**Closed in 0.23.1** (the release notes, verbatim): **A masked `SecretLabel` keeps no copy.** It called `Value` on every measure and paint and copied the answer whether it was revealed or not, so an application showing an item's fields masked held a second copy of every one of them until it remembered to call `Hide`. Masked, it now takes the rune count and lets the bytes go.

**After v0.23.1: satisfactory; the manager keeps `secretText`, by
choice.** Masked, a `SecretLabel` now keeps no bytes; revealed, it draws
from a copy of its own, which it zeroes the first time it is drawn masked
again, when it leaves its window, and on `Hide` (33). That is what this
item asked. `secretText` stays because it does more than the item asked:
it holds no copy even revealed, drawing from the caller's slice, and it
breaks a long key, share or invite into lines, which a `SecretLabel`
(lines split at `\n` only) cannot while a grid offers no width (39).
Swapping would add a copy of every revealed secret, for nothing gained.

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
Nothing more is asked here. v0.22.2's release notes decline font fallback
again, for message content.

**After v0.23.2: unchanged.** "Font fallback remains declined" (the
release notes' "Still open"); `TestItem11SymbolFallback` passes.

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

**After v0.22.2: unchanged, and it now reaches the field too.**
`noteLockKeys` and the focus-in are as they were. v0.22.2 hands the state
to every `widget.LockKeysWatcher` in the window, a `SecretField` among
them (28), through the same path, so the field's own mark has both
problems as well. `secretui.CapsLock` is a watcher now rather than the
window's `OnLockKeys`, asks the window once when it is first laid out,
and still asks the keyboard whenever it is told of a change.

**After v0.22.3: unchanged.** `app/lockkeys.go` and the backends' focus-in
events are as they were; `TestItem12CapsLock` still passes as a pin.

**After v0.22.5: not satisfactory, and worse in one way.** The backends'
focus-in events still carry no modifiers (`x11_linux.go`,
`wayland_linux.go`, `win32_windows.go`, `appkit_darwin.go`), and
`dispatch` still notes the lock keys from them. Before, the first event
was dropped, so on X11 a focus-in as the first event only made the
window's own state wrong. Since 649af18 the first event is reported to
every `LockKeysWatcher`, so the focus-in now tells them all that Caps Lock
is off. Reading the code paths:

- **X11.** The window maps at its first present, after its first layout,
  where the field takes the focus and asks the window (`LockKeysOf`);
  nothing has been noted yet, so the window asks the server
  (`XkbGetIndicatorState`) and the field is right. The focus-in arrives
  after the map, with no modifiers: the window notes "off", tells the
  field, and the mark goes. From then on `LockKeys()` says off, and the
  server is not asked again. The next key with Caps Lock brings it back.
- **Windows.** The same, through `GetKeyState`, if the focus-in comes
  after the first layout; if it comes before, the field asks a window
  that has already noted "off", and the mark waits for the next key.
- **Wayland.** The surface cannot be asked; the window answers "off" until
  a key event carries the xkb state. Before the first key, never.

`secretui.CapsLock` asks the keyboard itself (`LockKeysSurface`) whenever
it is told of a change, and so stays right on X11 and Windows through the
focus-in; it stays beside the field's mark. `TestItem12CapsLock` and
`TestItem28LockKeysWatchers` pin it. The proposal above stands: modifiers
on a focus-in, or no lock state noted from an event that has none.

**After v0.23.0: unchanged, not satisfactory.** `app/lockkeys.go`, the
backends' focus-in events and `widget.LockKeysOf` are as they were in
v0.22.5; `TestItem12CapsLock` and `TestItem28LockKeysWatchers` still pin
it. The Caps Lock line stays.

**Closed in 0.23.1** (the release notes, verbatim): **A focus-in no longer says the lock keys are off.** No backend puts modifiers on a focus-in, and the window noted them from it anyway: a prompt opened with Caps Lock on read the lock correctly, then the focus-in told every watcher it was off. The mark appeared and went before the first keystroke.

**After v0.23.1: satisfactory on X11 and Windows; on Wayland not before
the first key.** `app/window.go`'s `dispatch` no longer notes the lock
keys from `EventFocusIn` (285b6b7), so a window that comes back into
focus keeps what it knew, and no watcher hears the lock go off.
`secretui.CapsLock` takes the window's word again: it no longer asks the
keyboard itself (`asKeyboard` is gone). The other half of the proposal is
not done. A Wayland surface is still no `LockKeysSurface`, though the
backend keeps the xkb state the compositor sends right after `enter`
(`wlMods`): a Wayland prompt opened with Caps Lock on says nothing of it
until the first key or pointer event. A lock changed in another window is
learnt at the next event in this one that carries the modifiers, which is
all a focus-in leaves to go on. `TestItem12CapsLock` pins the
focus-in and the Wayland surface.

**Not done in 0.23.2** (the release notes' "Still open", verbatim): Caps Lock cannot be reported before the first key on Wayland: a surface cannot be asked, and the state arrives with the first key event. That is the protocol.

**After v0.23.2: unchanged, and the reason given does not hold.** The
state does not arrive with the first key: the compositor sends
`wl_keyboard.modifiers` right after `wl_keyboard.enter` (wayland.xml asks
it of the compositor, and Mutter, KWin and wlroots do it), before any key.
uitoolkit's backend already takes it: `uitkWlKeyMods` folds it into its
xkb state and `c.mods`, and stops there, telling no window. A `wlSurface`
that answered `LockKeys` from `c.mods` (a `LockKeysSurface`), or a
modifiers event that reached the window as one, would let a Wayland prompt
say Caps Lock is on before the first key. An AppKit surface is no
`LockKeysSurface` either (`NSEvent.modifierFlags` can be asked at any
time). `TestItem12CapsLock` pins both, and that `uitkWlKeyMods` keeps
the state.

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
checks the cases the two functions handled. One case differed:
`UITK_FONT` set without a `look.json` turned following off (26), which
v0.22.2 fixes.

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
which v0.22.1 left in device pixels (25), they used a column's padding
instead; v0.22.2 scales those too, and the manager's pane is a `Pad`
again.
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
`FitContent`. With v0.22.1 it also called `FitToContent` and `Center`
itself, because a window was centred for the height it was made with
(27); v0.22.2 centres it again after the fit, and that call is gone.
`TestADialogIsAsTallAsItsContent` checks one line and six, at 1x, 1.5x
and 2x, and that the dialog is centred twice.

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

**After v0.22.2: provided.** `SecretField.SetBytes` (58140ea) takes the
buffer over, rather than copying it as proposed, and wipes the one it
replaces. The editor hands it a copy of the item's value (and of a
generated password), which the field then owns and wipes; `setSecret`,
the rune-at-a-time feed, is gone, and so is the limit that a value with a
control character could not go in. `TestItem18SecretFieldSetBytes`.

**Closed in 0.22.2. `SecretField.SetBytes` takes the buffer over rather than copying it — a copy would leave the caller holding the original, and two buffers to wipe instead of one — and wipes what it replaces.**

**After v0.23.0: satisfactory.** `SetBytes` takes the slice over and
wipes what it replaces; the editor hands it a copy it makes for the
purpose, and so never shares a buffer with the field.

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
`SecretField` drops a newline typed or pasted into it. `SecretLabel`
(item 8) shows one line too.

**After v0.22.2: provided.** `widgets.SecretArea` (fc42680) is
`SecretField` over several lines, the same widget with the same rules. The
editor puts a key field, and any concealed value of several lines, in one,
so a PEM or OpenSSH key can be pasted, shown, hidden and edited in place;
"Replace from file…" reads a file straight into it. Only a value no field
can show (binary, or text with other control characters) is still kept as
it is. `TestItem19SecretArea`, and the manager's
`TestAKeyIsEditedInASecretArea`. The area asks to be 280 wide, which a
narrow form cannot give it: 32.

**Closed in 0.22.2. `widgets.NewSecretArea`, which is `SecretField` over several lines rather than a second implementation: the buffer, the wipes, the refusals and the source test all belong to the embedded field. A pasted key keeps its lines and CRLF is normalised in place.**

**After v0.23.0: satisfactory.** A `SecretArea` is the same widget as a
`SecretField`, so item 1's reading covers it; a paste normalises CRLF in
place, and comes in through the same string as item 1's (35).

**After v0.23.2: satisfactory; a long paste: 49.** A paste comes in as
item 1's, bytes on every platform. A key is the paste most likely to be
longer than one read of the Wayland pipe, which is where 49 is.

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
still replaces the overlay and calls the old one's `Dismissed`.

**After v0.22.2: provided.** Overlays are a stack (fc42680):
`ShowOverlay` pushes, `DismissOverlay` pops the one its component is in,
and `Window.SetOverlay` still means "one dialog" and clears the lot. The
manager's queue for dialogs that arrive on their own (`whenNoDialog`,
`nextDialog`, and the tick that polled it) is gone: a recovery key goes
over whatever is up, which is there as it was afterwards, and anything
shown over the new-vault dialog leaves its fields as they were. What
keeps the window out of screen captures looks at every dialog in the
stack, not only the top one. `TestItem20DialogsStack`,
`TestARecoveryKeyGoesOverTheDialogUp`,
`TestADialogOverAnotherLeavesItAsItWas`. The change broke two things in
the manager until it followed it: 30.

**Closed in 0.22.2. `ShowOverlay` pushes and `DismissOverlay` pops the overlay its component is in; the ones underneath stay painted, and only the top takes the keyboard and pointer. `SetOverlay` still means "there is one dialog". One extra rule was needed: an overlay no longer on the stack closes nothing, which is the case reached on the way out of every dismissal.**

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
laid out at 300 puts its last child outside its box, so `fixedWidth`
stays. The `Wrap` half is unchanged too: `Wrap.Measure` flows at the width
offered, and `Wrap.Arrange` at its bounds, which are rounded to whole
pixels (`widgets/wrap.go`).

**After v0.22.2: provided where it mattered.** 91133b2: an `Overlay`
settles its card's width first and asks for the height at that width,
which is the confirmation-with-a-long-path case; `Grid` measures its rows
at the widths it will lay them out at; `Wrap` and `TokenField` flow at
whole pixels. A column itself measured at one width and handed a narrower
box still puts its last child outside it; the release notes say that a
container cannot grow a box it was given, and that it is the caller's.
The manager's `fixedWidth` stays, now for what it also did all along: a
dialog's body is 500 wide, where a wrapping message offered the window
would take most of it. `TestItem21WrapInAColumn` checks the overlay and
pins the column.

**Closed in 0.22.2 for the paths the toolkit owns, and worth re-checking
rather than taking on trust.**

Three fixes, and the cause was deeper than the report. A flexible grid
track was frozen at its children's *unbounded* width, so a wrapping
label's column took the width of its whole text on one line — 1453
pixels of the 400 there were. A track that can fold is now told from one
that cannot by **height**, not width (narrowed, both report a narrow
width). `Overlay` settles its card's width before asking for its height,
which is the path a dialog actually takes. `Wrap` and `TokenField` flow
at whole pixels, so measuring and laying out agree about which child
fits on a line.

**What is *not* fixed, because it cannot be:** a caller that measures a
column at one width and arranges it at another still gets what it asked
for. A column measured at 600 and given a 300-wide box 89 tall still
puts its button at y=127 — the column cannot grow a box it was handed.
Every container *in the toolkit* now measures children at the width it
will give them (`ScrollView`, `Panel`, `Pad`, `Overlay`, `Form`, pinned
by `TestContainersSizeChildrenAtTheWidthTheyGive`), so the practical
paths are covered.

So `fixedWidth` is probably unnecessary now — the dialog body goes into
an `Overlay` card, which is the case that was fixed — but it also pins
the width at 500, which the fix does not do. Try removing it and see
whether the dialogs still look right; this note is not a promise that
they will.

### 22. Clicking something scrolled out of view, in a test

- **Today.** `Window.ClickComponent` clicks where the component's box is,
  which for a button below a `ScrollView`'s fold is outside the view, so
  the click lands on nothing. The manager's tests scroll to it first
  (`ScrollView.Reveal`).
- **Proposal.** `ClickComponent` reveals the component first, as a person
  scrolls to what they are about to click, and `FocusOn` likewise.
- **Done when:** `ClickComponent` on a button below the fold presses it.

**After v0.22.1: still open.** `ClickComponent` (`app/drive.go`) clicks
the component's box as it is; a button below the fold is not pressed, and
the manager's test harness still reveals it first.

**After v0.22.2: provided.** `ClickComponent` and `FocusOn` scroll to the
target first (5e7a6cc). The harness's own scrolling is gone.
`TestItem22ClickBelowTheFold`.

**Closed in 0.22.2. `ClickComponent` and `FocusOn` reveal first, as a person scrolls to what they are about to click.**

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
`Shown`; the manager still asks the watcher itself.

**After v0.22.2: partly provided.** `StatusItem.Shown` and
`SetOnShownChange` (58140ea): Linux reads the watcher's
`IsStatusNotifierHostRegistered` and follows its host signals. But when
there is no watcher on the bus at all, `readHostRegistered`
(`platform/status_linux.go`) answers true, deliberately ("a bus error is
not that statement"), and a GNOME without the AppIndicator extension is
exactly a bus with no watcher: the case the item was about. The manager
now hides its window only where `Shown` is true, brings the window back
if the tray goes while the window is hidden in it (`SetOnShownChange`),
and still asks the watcher itself on Linux, where no watcher is no tray.
`TestItem23TrayShown`, and `TestHidingInTheTrayNeedsAHostThatShowsIt`,
which pins uitoolkit's answer on a private bus with no watcher.

- **Proposal.** No watcher is no tray: `Shown` is false when the watcher's
  name has no owner (a `NameHasOwner` call answers that without guessing),
  and true only when it answers that a host is registered. A bus that
  errors can still be read as shown.
- **Done when:** on a session bus with no `org.kde.StatusNotifierWatcher`,
  `Shown` is false.

**After v0.22.3: unchanged.** `platform/status_linux.go` is as it was, and
the tray test's pin on a private bus with no watcher still holds.

**After v0.22.5: provided, and the manager's own query is gone.** 649af18
asks the bus whether the watcher's name has an owner (`NameHasOwner`)
before its property, and treats a watcher that goes away as no tray. On
the three states, verified on a private bus in
`TestHidingInTheTrayNeedsAHostThatShowsIt`: no watcher, `Shown` is false;
a watcher with no host registered, false; a host registering (the
watcher's `StatusNotifierHostRegistered` signal), true, and
`SetOnShownChange` hears it. A watcher that is there and will not answer
is still read as shown, deliberately; `sniHostRegistered` read it as no
tray, and that is the one case that differs. The manager hides its window
only where `Shown` is true, and its D-Bus query is gone.

**Closed in 0.22.2. `StatusItem.Shown` and `SetOnShownChange`; Linux reads the watcher's `IsStatusNotifierHostRegistered` and follows its host signals. Windows and macOS have an area that is always there, so it follows `Alive`.**

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
(`widget/base.go`) clear the parent and not the host, and there is no
palette role on a label.

**After v0.22.2: provided.** `Remove` and `ClearChildren` detach the
subtree from its window (58140ea), and `Label.Tone` colours a label by
what it means at paint time (fc42680). The manager's `tonedLabel` stays
all the same, because `Label.Tone`'s status colours come out black or
white (31); it now draws them readable itself (29). `TestItem24RemoveKeepsHost`.

---

**Closed in 0.22.2. `Remove` and `ClearChildren` clear the host down the subtree. Re-parenting is unaffected: `Add` sets it again straight after.**

**After v0.22.3: provided, and `tonedLabel` is gone.** With 31 fixed,
`Label.Tone`'s status colours keep their colour, so the manager's labels
say what they mean with `Label.Tone` and nothing of the manager's own
keeps them coloured. `TestTonesFollowTheLook`.

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

**After v0.22.2: provided** (36685fe): `Pad`, `Spacer` and a
`ProgressBar`'s natural width are 1x lengths, with `RawSpacing` on `Pad`
and `Spacer`. The manager's pane is a `Pad` again. A `ProgressBar` still
ignores `SetPreferred`; the manager's one-time-code bar had asked for
64 by 6 and never had it, and the call is gone.

**Closed in 0.22.2. All three are 1x design lengths now, completing the sweep 0.22.0 started; `RawSpacing` on `Pad` and `Spacer` is the way back to device pixels.**

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

**After v0.22.2: provided** (58140ea): a typeface override is applied to
the appearance instead of standing in for a file. `TestItem26FontEnvStopsFollowing`
now checks it.

**Closed in 0.22.2. The override is applied to the appearance rather than to the file read into it, so it says nothing about the rest of it.**

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

**After v0.22.2: provided** (58140ea): a window the toolkit centred is
centred again when a fit changes its size (`recenterIfCentred`). The
workaround in `secretui.Open` is gone. `TestItem27FittedAndCentred`.

**Closed in 0.22.2. Both fit paths re-centre a window the toolkit centred.**

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

**After v0.22.2: partly provided** (5e7a6cc). `widget.LockKeysWatcher`
reaches every component in the window, and a focused `SecretField` (and
so a `SecretArea`) draws a warning mark while Caps Lock is on
(`CapsHint`, on by default). `secretui.CapsLock` is a watcher now, so it
no longer takes the window's one `OnLockKeys` and gives it back; it takes
no room while Caps Lock is off. The line stays beside the field's mark,
because the field learns only of changes: `NotifyLockKeys` runs from
`noteLockKeys`, which does not report the first event, and nothing tells
a field the state it opens in. A prompt opened with Caps Lock on shows no
mark in its field until the lock changes or a focus-in makes it look
changed (12), while the line, which asks the window when it is first laid
out, says so at once. `TestItem28LockKeysWatchers` pins that.

- **Proposal.** A field asks its window for the lock state when it gains
  the focus (`LockKeys`, through its host), as `secretui.CapsLock` does
  when it is laid out.
- **Done when:** a `SecretField` focused in a window opened with Caps Lock
  on shows its mark before the first key, on X11 and Windows.

**Closed in 0.22.2. `widget.LockKeysWatcher` gives every component in the window the lock state, the same shape as `FocusWatcher`, and `SecretField.CapsHint` draws the mark with no application code. `Window.OnLockKeys` remains for the window's own code.**

**After v0.22.3: agreed as far as it goes, and unchanged.** The watcher
and the mark are there, and the mark is amber now rather than white or
black (31). A field still learns only of changes, so the mark misses a
Caps Lock that was on when the dialog opened; `TestItem28LockKeysWatchers`
still pins that, and `secretui.CapsLock` stays beside the field.

**After v0.22.5: provided, not satisfactory.** A `SecretField` asks its
window for the lock state as it takes the focus (`widget.LockKeysOf`,
649af18), and watchers hear the first event. In a headless window that is
enough, and a dialog opened with Caps Lock on marks it in the field at
once (the prompt's `caps-at-open` screenshot). On a desktop the focus-in
that follows turns the mark off again (12), so the field is right for a
moment and wrong from then until the next key; `TestItem28LockKeysWatchers`
shows it with the focus-in every backend sends. The line beside the
buttons stays.

**After v0.23.0: unchanged.** As 12.

**After v0.23.1: satisfactory.** As 12: a `SecretField`'s mark stays
through a focus-in, and `TestItem28LockKeysWatchers` checks no watcher
hears a change from it. The line beside the buttons stays, as words a
screen reader reads; the field's mark is an icon.

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

**After v0.22.2: provided, and broken.** 36685fe keeps the pack's
declared status colours (for fills) and adds `Palette.Ink`, `DangerInk`,
`WarningInk`, `SuccessInk` and `style.ReadableInk` for text, which
`Label.Tone` uses (fc42680). They reach 4.5:1, but not as the colour they
started from: in `plastik-night` all three come back white, and in
`plastik` warning and success come back all but black (31). secretvault
makes its own readable ink, `secretui.Ink`, which lightens a colour
towards white on a dark background (or darkens it towards black on a
light one) until it reads: the prompt's refusal is a lighter red in
`plastik-night`, the Caps Lock line a lighter amber, and the manager's
toned labels likewise. `TestItem29DarkStatusColours`, and secretui's
`TestInkIsReadableAndKeepsItsColour`.

**After v0.22.3: provided.** The inks are readable and still the pack's
colours (31): `plastik-night`'s danger is `#ff5858`, warning `#c78500`
and success `#00af00`. `secretui.Ink` is gone: the prompt's refusal, the
Caps Lock line and the manager's labels use `Label.Tone`, and a
`SecretField`'s own Caps Lock mark is amber. `TestItem29DarkStatusColours`.

---

## Found while moving to v0.22.2

### 30. Closing a dialog from outside every dialog

- **Today** (`widget/popup.go`, `DismissOverlay`, fc42680). Before overlays
  stacked, `DismissOverlay(from)` closed the window's overlay whatever
  `from` was: the manager passed its content's root to close the dialog up
  as it quit (which wipes a recovery key or a typed passphrase), and to
  take its file chooser down. Now it pops the overlay `from` is in, and a
  `from` in no overlay closes nothing, silently. The release notes'
  upgrade list says `SetOverlay` still means one dialog; it does not say
  this. The manager quit with a recovery key up and did not wipe it, and
  a cancelled chooser stayed up, until it followed: it calls
  `Window.SetOverlay(nil)` at quit and `DismissOverlay` on the chooser's
  own overlay.
- **Proposal.** Either `DismissOverlay` from outside every overlay closes
  the top one, as it used to, or it is in the upgrade notes with what to
  call instead.
- **Done when:** `DismissOverlay(root)` with a dialog up closes it, or the
  release notes say it does not. `TestItem30DismissFromOutside` pins
  today's behaviour.

**Closed in 0.22.3. `DismissOverlay` from outside every overlay closes the top one again, as it did before overlays stacked. An overlay that *was* on the stack and is no longer still closes nothing — that is the case reached on the way out of every dismissal — and the two are told apart by `widget.ContentRootHost`. The manager can drop its `SetOverlay(nil)` workaround.**

**After v0.22.3: provided; the manager keeps `SetOverlay(nil)`.**
`DismissOverlay` from outside every dialog closes the top one again
(`widget/popup.go`, `inHostTree`), which is the done-when. But it closes
the top one *only*: with a confirmation over a recovery key, quitting that
way would close the confirmation and leave the key unwiped.
`Window.SetOverlay(nil)` closes every dialog in the stack, each wiping
what it holds, which is what quitting needs; it is the right call, not a
workaround, so it stays. The file chooser is likewise taken down by its
own overlay (`DismissOverlay(shown)`), so that a dialog shown over it is
not the one closed. `TestItem30DismissFromOutside` checks both: the top
one only from outside, all of them with `SetOverlay(nil)`.

### 31. Status ink that keeps its colour

- **Today** (a bug; `style/statusink.go`, `ReadableInk`). The walk hands
  `flatFromHSL` a lightness from 0 to 1 (`float64(i) / steps`), and
  `flatFromHSL` (`style/enginekit_color.go`) takes lightness in percent, as
  `flatHSL` gives it. So every candidate is within 1% of black: on a light
  background the first already reads and the ink is all but black, and on
  a dark one none does and the fallback is white. `plastik-night`'s
  danger, warning and success ink are all `#ffffff`; `plastik`'s warning
  ink is `#050300`. The documentation's promise, "a lifted red is still
  that pack's red", is what the code means to do.
- **Workaround.** `secretui.Ink`, used for the manager's toned labels, the
  prompt's refusal and the Caps Lock line. A `SecretField`'s own Caps Lock
  mark is drawn in `WarningInk`, so it is white or black.
- **Proposal.** Pass the lightness in percent (`100 * float64(i) / steps`).
- **Done when:** `plastik-night`'s `DangerInk` is a red that reads at
  4.5:1 on its background, not white. `TestItem31InkKeepsItsColour` pins
  today's values.

**Closed in 0.22.3, and the diagnosis was exactly right: `ReadableInk` passed lightness as a fraction where `flatFromHSL` takes percent, so every candidate sat within one percent of black. `plastik-night`'s danger is `#ff5858` now and `plastik`'s warning ink `#8f6000`. `secretui.Ink` can go. Two new tests assert the property the old ones missed — a saturated colour comes back saturated, and nothing comes back pure black or white — because the contrast test passed throughout (black on light reads fine) and so did the hue test (hue survives at one percent lightness).**

**After v0.22.3: provided, and `secretui.Ink` is gone.** 6e1d4f9 passes
the lightness in percent (`style/statusink.go`). In `plastik` and
`plastik-night` all three inks keep their strongest channel and stay
saturated; the ones that read already are returned as declared.
`TestItem31InkKeepsItsColour` checks that now, in place of the pin.

### 32. A SecretArea in a narrow form

- **Today** (`widgets/secretarea.go`, `Measure`). A `SecretArea` asks to
  be 280 wide whatever it is offered, and cannot fold, so since 91133b2 a
  grid's flexible column gives it 280 where it has less, and the columns
  after it go off the edge. A `SecretField` asks for 180, a `TextArea`
  for what it is offered. The manager's editor, a form in the right-hand
  pane, lost its Remove buttons off the edge beside a key.
- **Workaround.** The editor wraps a key's area in `fixedWidth`, which asks
  for 180 and lays the area out as wide as the column is.
- **Proposal.** Measure as `TextArea` does (the width offered, when there
  is one), or ask for no more than a `SecretField` does.
- **Done when:** in a 360-wide window, a grid of label, `SecretArea` and
  button keeps the button inside the window.
  `TestItem32SecretAreaInANarrowGrid` pins today's behaviour.

**Closed in 0.22.3. A `SecretArea` takes the width it is offered, as a `TextArea` does, and asks for 180 when it is offered none. The editor's `fixedWidth` wrapper can go.**

**After v0.22.3: provided, and the editor's wrapper is gone.** A
`SecretArea` measures as the `SecretField` beside it does, so in a grid's
flexible column the two are always as wide as each other; the editor lays
a key's area out with no wrapper, and its Remove buttons stay in the pane.
The done-when above asked for more than this item is about: in a
360-wide window the grid of the test still runs 11 pixels over, for a
`SecretField` as much as for a `SecretArea`, because a flexible column
gives nothing that cannot fold less than it asks for (91133b2, by
design). `TestItem32SecretAreaInANarrowGrid` checks the area and the field
at 360, 420 and 600.

**On the 11 pixels (0.22.4).** Confirmed and it is the documented floor,
not a bug: a flexible column never squeezes a child that has no narrower
form, so a label, a field and a button stop at 27 + 180 + 96 and the row
runs over below about 323 px. Qt and GTK stop the same way.

What was missing is a lever and an explanation, and both are now there.
`SecretField.PreferredWidth` and `SecretArea.PreferredWidth` lower what
the field asks for, matching `TokenField.PreferredWidth`; a field asking
120 instead of 180 buys 60 px.
[docs/recipes.md](https://github.com/codemodify/uitoolkit/blob/dev/docs/recipes.md)
has an entry for a form in a narrow pane with the four things that
actually help.

Both of the things that were absent are now there.
`widget.MinWidthOf(c)` is the width below which something starts leaving
the box — containers answer it themselves, since a container asked to fit
in one pixel reports the one pixel it was constrained to — so a program
can size a window from its own content and a test can assert the form
still fits. And `ScrollView.Horizontal` and `TableView.Horizontal` (both
off by default) scroll content that genuinely has no narrower form.

And `WindowOptions.MinWidth` / `MinHeight` is where that answer goes —
it already existed, and the note here that said otherwise was wrong. The
window system is told on every backend, so a window cannot be dragged
below what its own content needs.

**After v0.23.0: agreed that it exists, and it does not close 34.**
`WindowOptions.MinWidth` reaches every backend, and the manager gives it
one (890). But it is given as the window is made, and the content whose
floor it should be is built into that window afterwards; `MinWidthOf` of
that content stops at its outer `Splitter`, which still does not answer
it; and the floor changes with the page shown (the editor's is the
widest), which a value fixed at creation cannot follow. So the manager's
minimum is a constant, and `TestTheEditorFitsTheNarrowestWindow` keeps it
true. `TestItem34AWindowFloorFromItsContent` still pins it.

**After v0.22.5: the lever helps the manager where it reaches, and it
does not reach far enough (34).** The manager's editor sits in the
right-hand pane of two splitters. What it now does:

- its wrappers (`page`, `slot`, the window's root, a dialog's
  `fixedWidth`) answer `widget.MinWidther`, so a splitter asks the pane
  for what the page in it holds, and keeps the editor's pane that wide;
- the lists get floors of their own (`MinA`: 160 for the vaults, 200 for
  the items), because a `TableView` asks for all its columns and a
  splitter would otherwise keep it wider than it needs;
- the window's minimum is 890, where the three floors meet, found and
  kept by `TestTheEditorFitsTheNarrowestWindow`. It was 760, a guess,
  and at 760 the editor's Remove buttons were off the window.

What it could not do: `PreferredWidth` buys nothing in the editor, whose
fields' column is set by the `TextField`s beside the secret ones, at 180,
with no `PreferredWidth` of their own; `MinWidthOf` of the window's
content stops at the outer `Splitter`, which does not answer it, so the
window's floor cannot be worked out from the content; and a window's
minimum can be given only as it is made (`WindowOptions.MinWidth`),
before the content that decides it exists. The maintainers say the last
themselves; it is part of 34 with the other two.

---

## Found while moving to v0.22.5

### 33. A hidden SecretLabel's copy of the secret

- **Today** (`widgets/secretlabel.go`, `refresh`). A `SecretLabel` calls
  `Value` on every `Measure` and `Paint` and copies the answer into a
  buffer of its own, whether it is revealed or not. Hidden with `MaskLen`,
  it draws a fixed row of bullets and needs to know only whether the value
  is empty, but holds the whole secret anyway. The copy is wiped by `Hide`,
  or by a shorter value arriving; a label taken out of the window, or a
  page thrown away without `Hide`, keeps it until the collector, and there
  is no point at which the toolkit wipes it. So an application that shows
  a vault item's fields masked holds a second copy of every one of them for
  as long as the item is open, and must remember to call `Hide` on each
  label, on every way the item can go.
- **Workaround.** The manager keeps `secretText`, which holds the caller's
  bytes and no copy; the caller wipes them and calls `Forget`.
- **Proposal.** A hidden label asks only for the length (or emptiness) and
  keeps nothing: copy only while `Reveal` is set, and wipe the copy when
  `Reveal` goes off. And wipe it when the label leaves its window (its host
  set to nil, which `Remove` now does).
- **Done when:** a hidden `SecretLabel` holds no copy after it is painted,
  and one taken out of the tree has zeroed what it held.
  `TestItem33HiddenSecretLabelHoldsACopy` pins today's behaviour.

**Closed in 0.23.1** (the release notes, verbatim): **A masked `SecretLabel` keeps no copy.** It called `Value` on every measure and paint and copied the answer whether it was revealed or not, so an application showing an item's fields masked held a second copy of every one of them until it remembered to call `Hide`. Masked, it now takes the rune count and lets the bytes go.

**After v0.23.1: closed.** `refresh` takes the rune count and whether
there was a value from what `Value` hands it, and, masked, wipes the
buffer and keeps nothing; `SetHost(nil)` wipes it as the label leaves its
window (`Remove` reaches it), and `Hide` still does.
`TestItem33AMaskedSecretLabelKeepsNoCopy` checks the buffer is empty
masked, zeroed to its capacity when the label is masked again after a
reveal, and zeroed when a revealed label is taken out of the window.

### 34. A window's floor from its content

- **Today.** `widget.MinWidthOf` (0.22.4) is meant to let a program size a
  window from its content. Three things stop it:
  - `Splitter` does not implement `MinWidther`, though it has floors of
    its own (`MinA`, `MinB`, or its panes' `MinWidthOf`), so asking the
    content of a window made of splitters gets the probe's guess;
  - `TextField` asks for 180 and has no `PreferredWidth`, unlike
    `SecretField`, `SecretArea` and `TokenField`, so a form with text
    fields in it keeps a 180 floor whatever its secret fields ask; a
    `TextArea` offered nothing asks for 220 device pixels, and a
    `TableView` for all its columns, though both can be narrower;
  - a window's minimum is `WindowOptions.MinWidth`, given as the window is
    made, before the content that decides it exists, and nothing sets it
    afterwards (the maintainers' own note).
- **Workaround.** The manager's wrappers answer `MinWidther`, its lists get
  explicit splitter floors, and its window's minimum is a constant, 890,
  found by a test that lays the editor out at it.
- **Proposal.** `Splitter.MinWidth` (its floors, its bar, and for a split
  in rows the wider floor); `TextField.PreferredWidth`, and `TextArea` and
  `TableView` answering `MinWidth` with what they can really do with;
  `Window.SetMinSize(w, h)`, in logical pixels, applied at once (the
  backends already hold `SizeLimits`).
- **Done when:** `window.SetMinSize(widget.MinWidthOf(content)/scale, …)`
  on the manager's window keeps its editor inside it, with no constant.
  `TestItem34AWindowFloorFromItsContent` pins today's behaviour.

**Closed in 0.23.1** (the release notes, verbatim): **A window's minimum size can be stated after it is made.** `WindowOptions.MinWidth` is given before the content that decides it exists. New: `Window.SetMinSize` / `MinSize` and `platform.SizeLimitSurface`, implemented on all four backends. `Splitter.MinWidth` and `TextField.PreferredWidth` come with it, so `widget.MinWidthOf(content)` is an answer a program can act on.

**After v0.23.1: satisfactory, and the manager's constant is gone; but the
minimum does not last (44).** `Splitter.MinWidth` answers both panes'
floors and its bar (a split in rows, the wider), `TextField` has
`PreferredWidth` and a floor that follows it, `Stack` answers its pages'
widest floor, and `Window.SetMinSize` restates `SizeLimits` on all four
backends. The manager now states `widget.MinWidthOf(content)/scale`
whenever the page it shows changes: 477 with nothing open, 581 with an
item, 858 with the editor (the constant was 890); a window narrower than
that as the editor opens is widened to it, and
`TestTheEditorFitsTheNarrowestWindow` lays the editor out at the floor it
states. Not done, and not needed: `TextArea` and `TableView` answering
their own floors (the lists keep their splitter floors). What is needed is
44: the minimum a program states is put back to `WindowOptions`' at the
next resize by the program on Windows and headless, and at a change of
resize policy everywhere, so the manager states it again after a resize.

**Closed in 0.23.2** (the release notes, verbatim): `widget.MinWidthOf` is meant to let a program size a window from what is in it. Three things stopped it, and all three are fixed: a **wrapper** that holds one thing and passes everything through answered whatever that thing measured — 320 for a splitter, against the 848 its panes needed, and `SetMinSize`'s own doc recommends that line; a **stated minimum did not last**: every backend recomputes its limits from the options the window was made with, on a resize, a change of resize policy, or a Wayland window being rolled up; **`Splitter` and `TextField`** did not answer for themselves.

**After v0.23.2: satisfactory, and it lasts (44).** `MinWidthOf` of a
component with one child is now at least that child's floor (99e0c22);
`TestItem34AWindowFloorFromItsContent` checks it of a wrapper round a
splitter. The manager's wrappers (`page`, `shortcutRoot`, `slot`) keep
their own `MinWidth`, which answers exactly their child's floor; the new
rule answers the larger of the probe's guess and the child's. The manager
states its floor whenever the page changes, and no longer again after a
resize.

---

## Found in the audit of v0.23.0

### 35. A secret on the Linux clipboard as a string

- **Today.** Two places, both on Linux.
  - **Copying** (`platform/clipboard_secret_linux.go`,
    `clipboardNativeSetSecret`): `s := string(b)`, handed to the Wayland
    data source and to the X11 owner, which serve from it while they own
    the selection. Clearing drops the reference and zeroes nothing.
    Item 7 says only that the X11 owner does this.
  - **Pasting** (`platform/clipboard_secret.go`, `ClipboardGetSecret`):
    when the clipboard holds another program's secret (a passphrase
    copied from a terminal, or from another password manager), it is read
    with `ClipboardGet`, a string, and converted. The doc comment calls
    the string "the session's"; it is in this process's heap all the
    same, unwipeable. A `SecretField` or `SecretArea` paste takes this
    path.
- **Proposal.** Serve and read selections as `[]byte`: the X11 owner
  writes the bytes to the requestor's property from a `[]byte` it zeroes
  when it loses the selection or is cleared; the Wayland source writes
  them to the pipe from the same; the readers read the property or the
  pipe into a `[]byte` (`C.GoBytes` already does it for X11's own
  pastes, `x11_linux.go`) and never convert.
- **Done when:** no `string(` of a secret's bytes on the Linux secret
  clipboard path, and the served copy is zero after a clear, a timeout
  and the loss of the selection. `TestItem35ClipboardSecretsAsStrings`
  pins today's code.

**Closed in 0.23.1** (the release notes, verbatim): **A secret on the Linux clipboard is never a Go string.** Owning a selection means holding the value, so the question was never whether a copy exists but whether anything can wipe it. Both owners hold bytes and zero them when the selection is given up, cleared or replaced; the X11 serving path also stopped copying through `C.CString`, into a buffer `free()` does not zero. Pasting another program's secret has a bytes path too.

**After v0.23.1: partly; the X11 half holds.** Copying: bytes to both
owners, each zeroing its copy (7). The X11 owner serves from the slice,
and `C.CString`, whose buffer `free()` does not zero, is gone from the
serving path. Pasting: `ClipboardGetSecret` asks `clipboardNativeGetSecret`
first, which takes X11's property as bytes (handed over, the connection's
copy dropped) or reads the Wayland pipe into bytes. Three things fall
short of the done-when, each an item of its own: the Wayland owner makes
a string of the secret at every paste (41); a pasted secret still leaves
copies nothing wipes, and falls back to a string when the bytes read
fails (42); and the X11 change broke the program's reading of its own
selection (43). `TestItem35TheLinuxSecretClipboardIsBytes` pins what
holds.

**Closed in 0.23.2** (the release notes, verbatim): **A secret never becomes a Go string on any platform.** 0.23.1 did Linux. Windows decoded `CF_UNICODETEXT` through `syscall.UTF16ToString`, which builds a string on the way to bytes; macOS read `C.GoString` of a `strdup`'d buffer and then `free`d it without clearing, leaving a second copy for whatever got that allocation next. Both have a bytes path now, each zeroing what it worked through. The Wayland *serving* side is bytes too: every paste another client asked for used to go out through a string and back, two copies per paste. And: **X11 read its own copy as the last paste** — a regression 0.23.1 introduced, and the reason to read a release's own report.

**After v0.23.2: satisfactory; what is left is 47–49.** No string of a
secret anywhere on the Linux secret clipboard: the owners hold bytes and
zero them (7), the Wayland owner serves from them (41), the readers read
into bytes and zero their buffers, with no second try as a string (42),
and X11 reads its own copy again (43). `TestItem35TheLinuxSecretClipboardIsBytes`
pins the owners; 41–43 pin the rest. What the item did not ask, and is
not so: what the hint is answered with on Wayland (47), whose clipboard a
clear empties (48), and the buffers a long paste outgrows (49).

### 36. A form value read aloud as its caption

- **Today** (`widgets/grid.go`, `Form.AddRow`; `widgets/a11y.go`,
  `Label.Describe`). `AddRow` names the field beside a caption after the
  caption, Qt's buddy, for anything with `SetAccessibleName` and no name
  yet, and a `Label` has one. `Label.Describe` takes the name over its
  text. So a form row of caption and value, the way the prompt sets out
  the program asking ("Program: /usr/bin/mail"), is read aloud as
  "Program:", "Program": the program, which is what a consent prompt
  exists to say, is not read at all. `a11y.Check` does not notice.
- **Workaround.** The prompt names each value after itself before adding
  the row; its `TestTheDialogsAreAccessible` checks a screen reader hears
  the program and the process.
- **Proposal.** `AddRow` names only what can take input (a
  `widget.Focusable`, or not a `Label`); and `a11y.Check` flags a label
  whose name is not its text.
- **Done when:** a `Form` row of two labels is read as both.
  `TestItem36AFormValueIsReadAsItsCaption` pins today's behaviour.

**Closed in 0.23.1** (the release notes, verbatim): **A form's rows can be shown and hidden** (`Form.Row`, `FormRow`), and **a form's value is read as itself** rather than as its caption — a row of "Program:" and "/usr/bin/mail" was read "Program:", "Program", and the value, which is the whole reason a consent prompt is on the screen, was never read at all.

**After v0.23.1: satisfactory, and the prompt's workaround is gone.**
`Form.AddRow` names the field beside a caption after it only when the
field is not a `*Label`, so a row of "Program:" and a program is read as
both, and a field that takes input is still named after its caption. The
prompt no longer names its facts after themselves, and its
`TestTheDialogsAreAccessible` still hears the program and the process.
Two things short of the proposal, neither needed by secretvault: a type
that embeds a `Label` rather than being one is still named after a
caption (secretvault puts none beside one), and `a11y.Check` does not
flag a label whose name is not its text.

### 37. Secure input's answer, and its first attempt

- **Today** (`platform/x11_secure_linux.go`; `app/secure.go`).
  - **The first attempt comes too early.** A dialog's passphrase field
    takes the focus at the window's first layout, and that is where an
    application asks for secure input; an X11 window is mapped at its
    first present, after that layout. `XGrabKeyboard` on a window that is
    not viewable fails (`GrabNotViewable`, which the helper counts as
    "somebody else has it"), so it is retried for a quarter of a second,
    which holds up the first frame, and the answer is false.
  - **What is in effect is never reported.** The grab is retaken at the
    focus-in, once, and dropped at the focus-out; whether the retake
    worked, and whether a window manager that does not give the focus at
    all left the window without it, is told to nobody, and none of it is
    a diagnostic (35e0ff9). So an application cannot tell a person "the
    keyboard is not held" without being wrong on X11 every time.
- **Proposal.** `SetSecureInput` on a window not yet mapped records the
  wish and grabs at the map, answering "pending" rather than false;
  `Window.SecureInputHeld() bool` and an `OnSecureInput(func(held bool))`
  for what is in effect, called on every change; and a warn-level
  diagnostic when a wanted grab fails.
- **Done when:** on X11 a dialog that asks at its first layout opens with
  no wait, holds the keyboard once it has the focus, and an application
  can say truthfully whether it does. `TestItem37SecureInputAnswer` pins
  today's code.

**Closed in 0.23.1** (the release notes, verbatim): **Secure input says what is in effect.** The grab follows the focus and a retake can fail, and none of that was reported, so an application could not say "the keyboard is not held" without being wrong on X11 every time. New: `Window.SecureInputHeld`, `Window.OnSecureInput`, `platform.SecureInputHeldSurface`. A request made before the window is mapped is also recorded rather than retried for a quarter of a second against a window that cannot be grabbed yet.

**After v0.23.1: satisfactory.** `x11Surface.SetSecureInput` records a
request made before the window is mapped and answers at once; the grab is
taken at the map (`grabIfWantedLocked`, where it can fail under a window
manager that has not mapped the frame yet) and at each focus-in, which is
taken before the event reaches the window (`secureFocusChangedLocked`,
deferred), so `SecureInputHeld` and `OnSecureInput` follow what is in
effect, and a retake that fails is heard as "not held". Offscreen, a
request reads as held, which `TestItem37SecureInputHeld` checks along with
the callback. A failed grab is still not a diagnostic, which was asked;
secretvault does not need it, since what is in effect is now said.

---

## Found while bringing the manager level with the CLI

The manager now does whatever the CLI does: the vault's keyslots,
devices, sharing, sync, containers and settings, the keys, the contacts,
the tools and the desktop's setup, in pages of tabs and some sixty
dialogs. Building them on v0.23.0 found three things, none about a
passphrase.

### 38. A form's rows shown or hidden

- **Today** (`widgets/grid.go`, `Form`). A `Form` has `AddRow` and
  `AddWide`, and nothing to hide a row: hiding the field leaves its
  caption, and there is no handle on the row to hide both. A form whose
  fields depend on a choice (what a keyslot of each kind takes: a
  passphrase, a keyfile, shares, a security key's PIN policy) either
  shows every field, most of them irrelevant, or is torn down and built
  again.
- **Workaround.** The manager asks for the choice first, in a dialog of
  its own (Add… › the kind › Next), and then builds the form for it.
- **Proposal.** `Form.AddRow` returning a `*FormRow` with `SetVisible`,
  hiding the caption with the field and closing the gap; or
  `Form.SetRowVisible(field, bool)`.
- **Done when:** a form with a choice at its head shows only the rows
  that choice takes, with no gaps. `TestItem38AFormRowCannotBeHidden`
  pins today's behaviour.

**Closed in 0.23.1** (the release notes, verbatim): **A form's rows can be shown and hidden** (`Form.Row`, `FormRow`), and **a form's value is read as itself** rather than as its caption — a row of "Program:" and "/usr/bin/mail" was read "Program:", "Program", and the value, which is the whole reason a consent prompt is on the screen, was never read at all.

**After v0.23.1: provided, not satisfactory (45); the two steps stay.**
`Form.Row` returns a `FormRow`, and `SetVisible(false)` hides the caption
with the field, out of the accessibility tree too. But it repaints the
form and does not lay it out again, so nothing moves until something
else asks for a layout; and laid out again, the hidden row keeps its
`RowGap`. A keyslot form showing every kind's rows would have eight rows,
three of them showing for a security key, and five gaps too many between
them: worse than asking for the kind first. That is 45.

**Closed in 0.23.2** (the release notes, verbatim): A **hidden form row** kept its gap: the grid counted the row among its tracks, so a form of eight rows showing three had five gaps too many. `FormRow.SetVisible` also asks for a layout rather than only a repaint.

**After v0.23.2: satisfactory; Add… is one step.** Hiding a row moves
the rows under it at once, to where they are in a form that never had it
(45). The manager's keyslot dialog is one form now: the kind at its head,
the label, and under them only the rows and lines of the kind chosen
(`formDialog.part` and `showPart`); choosing another kind shows its own.
The lines under a form are the manager's (`widget.Base.SetVisible` only
repaints, so `showPart` asks the dialog for a layout itself).
`TestItem38AFormRowShownOrHidden` now hides and shows a row with no layout
asked for, and `TestKeyslotsAreListedAddedAndRemoved` checks the dialog.
Vault › Unlock with… still asks for the kind first: three of its kinds
open a flow of their own (a window for the passphrase, the security key at
once, shares one at a time).

### 39. A grid cell offered no width

- **Today** (`widgets/grid.go`). A `Grid` measures what is in an `Auto`
  or `Flex` column with no maximum width, however narrow the grid, and
  arranges it in its column's share afterwards. A cell that wraps to the
  width it is offered (the manager's secret text, which draws a long key,
  a recovery share or an invite from its bytes, and so cannot be a
  wrapping `Label`) is told it has all the room it likes, measures one
  long line, and is then cut off at the column's edge.
- **Workaround.** The manager breaks a long secret every 48 characters
  (`wrapAt`), whatever it is offered, and puts each secret under its
  label rather than beside it.
- **Proposal.** Measure a `Flex` column's cells, once the `Auto` columns
  are measured, with the width left for it (as `FlexBox` does for its
  flexible children); or a `Track` for "measure at the share".
- **Done when:** a widget in a `Flex` column of a narrow grid is measured
  with a bounded width. `TestItem39AGridCellIsOfferedNoWidth` pins today's
  behaviour.

**Not done in 0.23.1** (the release notes' "Known not done", verbatim): `Grid` still measures a cell in a `Flex` column with no maximum width, so the column's natural width is one long line for a widget that would wrap. Bounding that pass was tried and backed out: widgets end `Measure` with `Constrain`, so a bounded measure cannot tell "I wrapped" from "I was clamped", and a button in a flex column came back a third of its width. It wants a track mode that means "measure at the share" rather than a change to the natural pass. Heights are already measured at the real column width, so wrapping widgets lay out correctly; it is the reported width that is wrong.

**After v0.23.1: open, as the maintainers say.** Heights are measured at
the column's width (`TestItem39AGridCellIsOfferedNoWidth` checks a bounded
measure reaches the cell), so a wrapping cell lays out; the natural width
is still one long line. A secret drawn to the width it is offered would
report that line as its width wherever it is not stretched, as in a row
beside its buttons (the resolved reference) or a grid's column, so the
manager keeps `wrapAt`.

**Closed in 0.23.2** (the release notes, verbatim): `widgets.Share(weight)` is a grid column for cells that wrap to the width they are given: flexible when space is divided, never asked what it would like to be. The obvious fix is not available — `Measure` ends in `Constrain`, so a bounded answer cannot be told from a clamped one, and a button in such a column came back a third of its width.

**After v0.23.2: satisfactory; the fixed wrap is gone.** A cell in a
`Share` column is asked for its width only through `widget.MinWidthOf`
(a `MinWidther` is asked; anything else is measured unbounded and at a
quarter of that, so a cell that cannot fold keeps its natural width as
its floor: `Share` is for cells that wrap, as its name says) and laid out
at the column's share; `Flex` is as it was. The manager's `secretText`
says its floor (the mask's width, so showing a secret does not move the
window's) and wraps to the width it is offered, at a character's
boundary, rather than every 48 bytes (`wrapAt`, gone). Shares and invites
wrap to their dialog; a value shown in an item wraps in the fields grid,
whose values' column is a `Share` column now, where it used to run past
its column; a resolved reference's value wraps in a `Share` column beside
its buttons. `TestItem39AShareColumnOffersItsWidth`, and the manager's
`TestALongSecretWrapsInItsColumn`.

### 40. A dialog taller than its window

- **Today** (`widgets/dialog.go`, `Overlay`). A dialog's card is held to
  the window, but its body is not scrolled: what does not fit is laid out
  past the card's foot, over the buttons there, or pushes them below the
  window's edge, with nothing to scroll them back. A dialog that shows a
  secret and its QR code, or a plan of many lines, can lose its buttons
  in a small window, which also takes them out of reach of the keyboard's
  Tab order as the person sees it.
- **Workaround.** The manager keeps dialogs short: a QR code goes in a
  dialog of its own over the one with the text, long lists and plans in a
  box of their own height (`HeightBox`, a read-only `TextArea`).
- **Proposal.** An `Overlay` card taller than its window scrolls its body
  and keeps its button row in view (the `ButtonBox` at the foot stays put),
  as the platforms' own dialogs do.
- **Done when:** a dialog with a 600-pixel body in a 300-pixel window has
  its buttons in view, and its body scrolls.
  `TestItem40ADialogTallerThanItsWindow` pins today's behaviour.

**Closed in 0.23.1** (the release notes, verbatim): **A tall dialog keeps its buttons in view.** `DialogCard`'s body scrolls and its action row stays at the foot; the buttons used to be laid out past the card, outside the window, where a click or a Tab landed nowhere.

**After v0.23.1: open for any card but `DialogCard`.** `DialogCard` puts
its body, a string, in a `ScrollView` flexed in its column, so the column
held to 0.88 of the window gives the body what is left above the action
row; `TestItem40ADialogTallerThanItsWindow` checks a 60-line `DialogCard`
keeps its button inside a 300-pixel window. An `Overlay` of any other card
is as it was: the manager's dialogs are a `Panel` of a body (a form,
secrets, a QR code) and a `ButtonBox`, and still lay out past their foot.
The remedy `DialogCard` uses is open to an application (the body in a
`ScrollView`, flexed), but this item asked it of the `Overlay`, for every
card, as the platforms' dialogs do it; and a QR code scrolled in its
dialog is no better than one in a dialog of its own. The QR code stays
where it is.

**Closed in 0.23.2** (the release notes, verbatim): **A tall dialog keeps its buttons**, and `widgets.DialogContent` is that arrangement on its own, for a card an application builds itself.

**After v0.23.2: satisfactory for the need, through the manager's own
arrangement (46).** `DialogContent(body, actions...)` is `DialogCard`'s
body in a `ScrollView`, flexed in a column over the action row, so a card
built of it keeps its buttons in view and scrolls its body;
`TestItem40ADialogTallerThanItsWindow` checks it with a body 600 tall in a
window 300 tall. It cannot be used as it is, though (46): its card is as
tall as the window allows whatever it holds (a dialog of one line is most
of the window), and its foot gives a `ButtonBox` only its natural width.
The manager's `showDialog` builds the same arrangement with a
`ScrollView` that shrinks to its content, inside the dialog's fixed
width, over its `ButtonBox`, so every dialog sizes to what it holds and
scrolls when that is more than the window. With that, the workarounds
go: a QR code is shown under its invite again (and under the contact
code's text), many recovery shares are in the dialog rather than in a box
of their own height, and the decrypted message's dialog has no height of
its own. `TestATallDialogKeepsItsButtonsInView` checks the invite in the
shortest window the manager allows.

---

## Found in the audit of v0.23.1

Reading the fixes through to the backends, against the needs as stated,
found five things: two about a passphrase on the clipboard, one the fix
for 35 broke, and two in fixes that hold as far as they go.

### 41. The Wayland owner serves a secret from a string

- **Today** (`platform/wayland_linux.go`, `uitkWlDataSend` and
  `wlSendSelection`; `platform/wlstate.go`, `clipCache.get`). v0.23.1
  keeps the copied secret as bytes in the connection's `clipCache`, and
  zeroes them when the selection goes. But every paste another program
  asks for is answered by `uitkWlDataSend`, which reads the cache with
  `get` (`string(c.data)`) and passes the string to `wlSendSelection`,
  which turns it into bytes again (`[]byte(text)`) to write to the pipe.
  Each paste leaves two copies of the passphrase in the heap, neither of
  which anything can wipe. Item 7's ground rule, on the platform most
  Linux desktops now run.
- **Proposal.** Serve from the bytes: `uitkWlDataSend` and
  `uitkWlPrimSend` read `getBytes`, and `wlSendSelection` takes a
  `[]byte` and writes it straight from the slice (it already writes
  through a pointer to the first byte).
- **Done when:** no `string(` of the cache on the serving path, and a
  test that pastes from a fake requester finds no copy of the secret
  outside the cache. `TestItem41WaylandServesASecretFromAString` pins
  today's code.

**Closed in 0.23.2** (the release notes, verbatim): The Wayland *serving* side is bytes too: every paste another client asked for used to go out through a string and back, two copies per paste.

**After v0.23.2: satisfactory.** `uitkWlDataSend` and `uitkWlPrimSend`
read the cache with `getBytes`, its own slice, and `wlSendSelection`
takes `[]byte` and writes it to the pipe from there: no string, no copy
(d9356f0). The paste is served on the event loop's thread outside
`wlMu`, while the timeout's clear zeroes the cache from the timer's
goroutine: at worst a paste of zeros, not a copy. What is served for the
password-manager hint is 47. `TestItem41WaylandServesASecretFromItsBytes`.

### 42. What a pasted secret leaves behind

- **Today.** A secret pasted from another program into a `SecretField`
  no longer arrives as a string on Linux, but:
  - when the bytes read fails (a slow owner, a timeout, an empty answer),
    `ClipboardGetSecret` reads the clipboard again with `ClipboardGet`, a
    string, and a second try that succeeds leaves the passphrase in the
    heap as one (`platform/clipboard_secret.go`);
  - the Wayland reader reads the pipe through a 4 KiB buffer that is
    never zeroed (`wlReadLoop`), and drops a partial read without
    zeroing it (`wlReadFDBytes`);
  - X11's `handleSelNotify` copies the property with `C.GoBytes` and
    frees Xlib's buffer with `XFree`, which does not zero it: the reason
    v0.23.1 gave for dropping `C.CString` on the serving side;
  - Windows and macOS have no bytes path (`clipboardNativeGetSecret`
    answers `nil, false`), so a paste there is `[]byte(ClipboardGet())`,
    a string first, as item 35 described for Linux.
- **Proposal.** On a platform with a bytes path, no fallback to the
  string read; the read buffers zeroed once copied (and a partial read
  zeroed before it is dropped); the X11 property zeroed before `XFree`;
  and bytes paths for Windows (`GetClipboardData(CF_UNICODETEXT)`, encoded
  to UTF-8 into a `[]byte`, the UTF-16 copy zeroed) and macOS (the
  pasteboard's data into a `[]byte`).
- **Done when:** no string of a pasted secret on any platform, and every
  intermediate buffer zeroed. `TestItem42APastedSecretLeavesCopies` pins
  each of the five.

**Closed in 0.23.2** (the release notes, verbatim): 0.23.1 did Linux. Windows decoded `CF_UNICODETEXT` through `syscall.UTF16ToString`, which builds a string on the way to bytes; macOS read `C.GoString` of a `strdup`'d buffer and then `free`d it without clearing, leaving a second copy for whatever got that allocation next. Both have a bytes path now, each zeroing what it worked through. (And the commit, d9356f0, verbatim: no fallback to the string reader where a bytes path exists, so a read that fails is a failed read rather than one that succeeds the second time and leaves a string behind. Only where there is a display: with no compositor and no X server the clipboard is this process's own buffer, and refusing to read it would be a paste that silently did nothing; the Wayland pipe's 4 KiB staging buffer is zeroed on the way out, and a partial read is zeroed before it is dropped; X11's selection property is zeroed before XFree, which does not clear it — the same reason this file stopped handing C.CString a secret on the serving side. Through a volatile pointer, so the compiler cannot drop a write to memory it can see is being freed.)

**After v0.23.2: satisfactory for a passphrase; a longer paste: 49.**
Each of the five holds, on every path read: `ClipboardGetSecret` returns
nothing when the bytes read fails where a bytes path exists (Linux with a
display, Windows, macOS); `wlReadLoop` zeroes its staging buffer however
it ends, and `wlReadFDBytes` zeroes a partial read; `handleSelNotify`
zeroes the property through a volatile pointer before `XFree`; Windows
decodes into a slice sized never to grow and zeroes its UTF-16 copy and
the runes; macOS copies out of a buffer it zeroes before freeing. What
remains in this process is the platform's own, out of reach: Windows'
clipboard memory, the pasteboard's `NSString` and the UTF-8 buffer AppKit
hands back from it. Headless, with no display, a paste still reads the
in-process buffer as a string, which holds only an ordinary copy this
program made (a secret copy empties it). What does not hold is a paste
longer than one read: 49. `TestItem42APastedSecretLeavesNoString`.

### 43. X11 reads its own copy as the last paste

- **Today** (`platform/x11_linux.go`, `readSelection`,
  `readSelectionString`, `x11ClipGetBytes`). Before v0.23.1,
  `readSelection` answered a selection this program owns with what it
  serves (`clipText`). v0.23.1 made it return only "done", and both
  readers then take `pasteData`, which the owned branch never sets: what
  is there is whatever the last paste from another program left, or
  nothing. So on X11, Ctrl+C then Ctrl+V between two of a program's own
  fields pastes something else (an older paste from elsewhere), and a
  `SecretField` pasting the program's own ordinary copy pastes nothing.
  The program's own *secret* copy is unaffected: `ClipboardGetSecret`
  copies it from the toolkit's buffer first.
- **Proposal.** In the owned branch, copy `clipData` into `pasteData`
  (under the lock, as the foreign branch fills it), or have the two
  readers take `clipData` when the selection is owned.
- **Done when:** on X11 a program that copies text pastes that text back.
  `TestItem43X11ReadsItsOwnCopyAsTheLastPaste` pins today's code.

**Closed in 0.23.2** (the release notes, verbatim): **X11 read its own copy as the last paste** — a regression 0.23.1 introduced, and the reason to read a release's own report.

**After v0.23.2: satisfactory.** `readSelection` answers a selection this
program owns, CLIPBOARD or PRIMARY, by putting a copy of what it serves in
`pasteData` under the lock (99e0c22); `readSelectionString` makes its
string of that, as an ordinary paste always did, and `x11ClipGetBytes`
hands it over. PRIMARY serves the same bytes, and a secret copy gives
PRIMARY up, so PRIMARY never serves a secret.
`TestItem43X11ReadsItsOwnCopy`.

### 44. A window's stated minimum does not last

- **Today.** `Window.SetMinSize` (34) restates the surface's limits, but
  the backends recompute their limits from `WindowOptions` on other
  occasions and overwrite it: `winSurface.Resize` and `Offscreen.Resize`
  on every resize by the program, `SetSizing` on every backend
  (`syncLimits`), and rolling a Wayland window up and down
  (`SetShadedHeight`). A program that states its floor and then resizes
  its window, or changes its resize policy, has lost the floor.
- **Workaround.** The manager states its floor again after any resize
  (`Window.OnResize`).
- **Proposal.** Keep a stated minimum as the window's own, apart from
  `WindowOptions`, and have `limitsFor` take it into account wherever the
  limits are recomputed.
- **Done when:** after `SetMinSize`, `SetSize` and `SetSizing` leave
  `MinSize` as stated. `TestItem44AStatedMinimumDoesNotLast` pins today's
  behaviour.

**Closed in 0.23.2** (the release notes, verbatim): a **stated minimum did not last**: every backend recomputes its limits from the options the window was made with, on a resize, a change of resize policy, or a Wayland window being rolled up;

**After v0.23.2: satisfactory; the manager's workaround is gone.** Every
surface's `SetSizeLimits` (X11, Wayland's `sizeOpts`, Windows, AppKit,
offscreen) writes what it is told back into the options `limitsFor`
recomputes from, at a resize by the program, a change of resize policy
(`syncLimits`) and a Wayland roll-up. `TestItem44AStatedMinimumLasts`
checks a resize and a change of policy headless, and each backend's
`SetSizeLimits`. One edge the manager does not reach: a fixed window that
states a minimum writes its fixed maximum into the options too, which it
keeps if it is made resizable later. The manager no longer states its
floor again after a resize (`Window.OnResize` is gone);
`TestTheEditorFitsTheNarrowestWindow` still resizes it and finds the
floor there.

### 45. A hidden form row keeps its gap

- **Today** (`widgets/grid.go`, `FormRow.SetVisible`, `solve`). Hiding a
  row (38) hides its caption and field, but:
  - `SetVisible` calls `Invalidate`, not `RequestLayout`, so nothing
    moves until something else lays the form out (a resize, another
    change);
  - laid out again, the grid counts the hidden row among its rows: its
    height is nothing, but the `RowGap` before it stays, so each hidden
    row leaves a gap. A form of eight rows showing three has five gaps
    too many between them.
- **Workaround.** The manager still asks for a keyslot's kind in a dialog
  of its own (Add… › the kind › Next) and builds the form for it.
- **Proposal.** `FormRow.SetVisible` lays the form out again; the grid
  leaves out of its tracks a row (and a column) all of whose children are
  hidden, gaps included.
- **Done when:** in a laid-out form, hiding a row moves the rows under it
  up at once, to where they are in a form that never had it.
  `TestItem45AHiddenFormRowKeepsItsGap` pins today's behaviour.

**Closed in 0.23.2** (the release notes, verbatim): A **hidden form row** kept its gap: the grid counted the row among its tracks, so a form of eight rows showing three had five gaps too many. `FormRow.SetVisible` also asks for a layout rather than only a repaint.

**After v0.23.2: satisfactory.** `FormRow.SetVisible` asks for a layout,
and the grid gives a track nothing visible is in neither room nor a gap,
rows and columns alike (d9356f0): in a laid-out form, hiding a row moves
the next at once to where it is in a form that never had it.
`TestItem45AHiddenFormRowLeavesNoGap`. (A visible row of no height loses
its gap too, which no form of secretvault's has.) The keyslot's Add… is
one step (38).

---

## Found in the audit of v0.23.2

Reading the fixes through to the backends, against the needs as stated,
and the secret clipboard once more end to end, found four things: one in
the piece v0.23.2 gives for 40, two in the secret clipboard that are
older than v0.23.1 and that every audit before this one missed, and one
in a fix that holds as far as it goes.

### 46. `DialogContent` fills the window, and squeezes a `ButtonBox`

- **Today** (`widgets/dialog.go`, `DialogContent`; `widgets/scroll.go`).
  `DialogContent` puts the body in a `ScrollView` flexed in a column over
  a row of the actions, and `DialogCard` is made of it. Two things keep an
  application from building its dialogs of it:
  - the `ScrollView` is not told to shrink to its content
    (`ShrinkToContent`), and a scroll view offered a height takes all of
    it: the `Overlay` measures its card in 0.8 of the window, so a card
    built of `DialogContent`, or a `DialogCard`, is that tall whatever it
    holds. A confirmation of one line is 560 pixels tall in a window 700
    tall;
  - the actions go in a row justified to the end, each at its natural
    width. A `ButtonBox`, which is how a dialog's buttons are laid out as
    the look's platform lays them out (the toolkit's own message boxes
    use one), handed to it as the action is squeezed to its natural width
    at the right, and its left-hand group (Help, and a destructive button
    under Mac and GNOME looks) is no longer apart.
- **Workaround.** The manager builds the arrangement itself
  (`showDialog`): a `ScrollView` with `ShrinkToContent`, inside the
  dialog's fixed width (a scroll view takes all the width it is offered
  too), flexed in a column over its `ButtonBox` at the column's full
  width.
- **Proposal.** `DialogContent`'s scroll view shrinks to its content
  (the column already caps it to the card); and an action that is a
  `ButtonBox` is given the row's width, or `DialogContent` takes the foot
  as one component (`DialogContent(body, foot widget.Component)`).
- **Done when:** a `DialogCard` of one line is no taller than its text
  and its button, and a `ButtonBox` in `DialogContent` keeps a destructive
  button apart under a GNOME look. `TestItem46DialogContentFillsTheWindow`
  pins today's behaviour.

### 47. Wayland answers the password-manager hint with the secret

- **Today** (`platform/wayland_linux.go`, `uitk_dsrc_send` and
  `uitkWlDataSend`). A secret copy offers `x-kde-passwordManagerHint`
  beside the text types, as item 7 asked, so that clipboard managers do
  not record it: the convention, as KeePassXC writes it and Klipper reads
  it, is that the hint's *value* is "secret". But the data source's send
  handler drops the type it was asked for (`(void)mime;`), and
  `uitkWlDataSend` writes the clipboard's bytes for every request. Klipper
  asks for the hint, reads the passphrase where it looks for "secret",
  takes the copy for an ordinary one, and keeps it in its history, which
  it saves to disk by default. Every reader that asks for the hint gets
  the passphrase once more too. X11 answers the hint target with "secret"
  (`handleSelReq`), as the toolkit's own comment there says it must. This
  is older than v0.23.1; the audits before this one checked that the hint
  was offered, not what it was answered with.
- **Workaround.** On Linux and the BSDs the manager copies through the
  CLI beside it (`secretvault __clip`), whose svclip offers the hint as
  "secret" on Wayland (data control) and X11; through uitoolkit only where
  there is no CLI or it cannot reach a clipboard.
- **Proposal.** Pass the mime type through to `uitkWlDataSend` (and
  `uitkWlPrimSend`), answer `x-kde-passwordManagerHint` with "secret" while
  the selection is a secret, the text types with the bytes, and nothing
  else with nothing.
- **Done when:** on Wayland a request for the hint is answered "secret",
  and Klipper does not record a secret copy.
  `TestItem47WaylandAnswersTheHintWithTheSecret` pins today's code.

### 48. A copied secret outlives the clipboard

- **Today** (`platform/clipboard_secret*.go`). A `SecretClip` is held
  (`secretHeld`) from `ClipboardSetSecret` until it is cleared, and
  nothing ends it when the clipboard moves on: not another program's copy
  (X11's `SelectionClear`, Wayland's `cancelled`, Windows and macOS, which
  are not even asked), and not the program's own ordinary copy
  (`ClipboardSet`). For the rest of its time, 30 seconds in the manager:
  - a paste into a `SecretField` or `SecretArea` reads the old secret
    (`ClipboardGetSecret` serves `secretHeld` first) rather than what is on
    the clipboard: copy a passphrase from another program into a new
    vault's "Passphrase" and "Repeat", and the vault gets the item copied
    before;
  - `ClipboardHoldsSecret` says a secret is held;
  - the clear at its timeout, at a lock (`SecretClip.Clear`) and at the
    quit (`ClipboardClearSecret`) empties whatever the clipboard holds by
    then, with nothing to check it is still this copy: Windows
    `EmptyClipboard`s, macOS `clearContents`, and Wayland sets an empty
    offer on CLIPBOARD and on the primary selection (where the compositor
    lets it). The item's own words were "if the clipboard still holds our
    data, clear it", and the type's comment says it "does nothing if
    something else has since taken the clipboard". X11 checks it owns the
    selection before it gives it up, but the program's own later ordinary
    copy it does own, and drops.
- **Workaround.** As 47: on Linux and the BSDs the CLI's helper holds the
  copy and clears only its own (svclip: a data-control source that was not
  cancelled, an X11 selection still owned, a Windows clipboard sequence
  number unchanged), and a paste reads the clipboard itself. On Windows and
  macOS the manager still copies through uitoolkit, and this stands.
- **Proposal.** End the held secret when the selection is lost (X11's
  `SelectionClear`, Wayland's `cancelled`) or replaced by any copy of the
  program's; on Windows note `GetClipboardSequenceNumber` after the copy
  and clear only while it is unchanged, on macOS the pasteboard's
  `changeCount` the same; and on Wayland clear by destroying the source
  that is still the selection rather than setting an empty one.
- **Done when:** after another copy, a secret paste reads that copy,
  `ClipboardHoldsSecret` is false, and the clear at the timeout leaves the
  clipboard as it is, on all four backends.
  `TestItem48ACopiedSecretOutlivesTheClipboard` pins today's behaviour
  headless (the program's own copy), and the backends' code.

### 49. What a long pasted secret leaves behind

- **Today.** 42 holds for a secret that fits one read. One that does not
  (a private key pasted into a `SecretArea`, the paste most likely to be
  long) leaves copies nothing wipes:
  - the Wayland reader appends each 4 KiB it reads to what it has
    (`wlReadLoop`: `out = append(out, buf[:n]...)`), so every array the
    paste outgrew is dropped unzeroed;
  - X11's INCR transfer, for a selection larger than its owner sends at
    once, frees each piece Xlib read with `XFree` and no `ui_zero`, and
    grows its buffer by append (`handleProperty`, `AppendINCRPiece`),
    leaving the arrays it outgrew; the whole is zeroed once copied out.
- **Proposal.** Grow by hand, zeroing the array outgrown (or read into a
  buffer sized from what the owner announces, as INCR does); zero each
  INCR piece before `XFree`.
- **Done when:** a paste of 20 KiB leaves no copy outside the bytes
  handed over. `TestItem49ALongPasteLeavesWhatItOutgrew` pins today's code.

---

**Closed in 0.22.2, though not as asked. The declared status colours are era-faithful and mostly used as fills, so they are left alone; `Palette.DangerInk`, `WarningInk`, `SuccessInk` and `Ink` are the readable form for text. It was not one pack: 225 of the 405 status pairs across all 135 packs failed 4.5:1, and the worst were *light* packs at 1.6:1, not plastik-night's 2.2. `Label.Tone` is the widget-level way to it, which replaces `tonedLabel`.**

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
  **Done** in v0.22.2 (58140ea), and the manager says so (item 7).

  **Closed in 0.22.2**: `SecretClip.OnCleared` fires once, on the goroutine
  that cleared the copy, and fires straight away if the copy has already
  gone — so a caller cannot lose the event to a timeout that beat it.
- **A dialog for one line of text.** v0.22.0 has `Prompt`
  (`MessageBoxOptions.Input`, f96c633), and v0.22.2 `PromptFor` with
  `Validate` and `AcceptLabel` (fc42680). The manager's rename is one now:
  its button says Rename, and a name that cannot be used, or is taken, is
  refused under the field with what was typed still there, rather than
  after the dialog has gone. Its own `ask` is gone.
