# What secretvault needs from uitoolkit

This list is for [uitoolkit](https://github.com/codemodify/uitoolkit)'s
maintainers.

**Does uitoolkit v0.23.21 address all of secretvault's needs? Yes, all
it uses.** v0.23.17 to v0.23.21 change nothing at run time (two of its
own tests, and a script that lists skips, subtests included, with each
skip's own reason, a failed run reported as one, two packages' tests of
one name kept apart, and a test run twice reported for each run). v0.23.16 changes nothing secretvault uses (a tag sequence's
flag, and a test of its own that skipped rather than checked; read
against the manager's own run, none of its checks skip but the
screenshot writers, and Hangar's capitals where Hangar is not built
in). v0.23.15 carries a flip panel's clock to the turn a framed
window builds for itself (94, found moving to v0.23.14), so the
manager's test of its turn steps a held clock, under the race detector
too. v0.23.14 let a test hold a flip panel's clock. v0.23.13 fixes a race in the text path that every build had
(a cached shape's groups re-pointed while another goroutine drew from
them); the manager draws on one goroutine, and its tests under the race
detector, run for this release, report no race anywhere. v0.23.12 changes nothing secretvault uses (two emoji
sequences, and a test of its own). v0.23.11 changes nothing the manager needed; its note on what
a tray icon's `Name` does beside its picture (the picture is chosen,
the name is sent as well, and the tray shows which it likes) made the
manager stop sending one, as no icon theme has a "secretvault". v0.23.10
closes the two the manager had been working round
since before v0.23.6: every digit is a key (92), so its parts are
Ctrl+1, 2, 3; and the set has a cloud and an icon can carry a badge
(93), so the only mark it draws itself is its logo. v0.23.9 changed
nothing secretvault uses (a GPU device's closing callback, and complex
text and colour emoji, which it is not built with). v0.23.8 closed the
two found moving to v0.23.7: the flip panel that is a turned window's
content offers a key to the face that is up (90), and a framed window
comes back the way it went (91). v0.23.7 had closed everything found
moving to v0.23.6 but 88: a framed window turns over with its frame
(77), so the manager's window keeps the toolkit's frame, its buttons
and its resizing; a turn's pictures are wiped (78); a breadcrumb says
its own tip and marks what it opens (79, 81), and its words are whole
(82); a mark's strip scales (80); a merged caption keeps Hangar's cut
corners (83), and the cut's hairline is drawn over the content (84); the
two clipboard edges are closed (85, 86); an application may say which
motion is the thing itself (87); and a panel's floor holds its chrome
(89). Of the 94 items, 91 are satisfactory, one (11) is declined by
design, and two are open, neither of them something the manager uses:
61, a tree that picks several nodes (its items are a list), and 88, a
window panel's silhouette that is not its window's shape (its window
wears the toolkit's frame). Moving to v0.23.8 through v0.23.13 and to
v0.23.15 to v0.23.21 found nothing new; v0.23.14 found 94, which
v0.23.15 closed.

The manager copies through uitoolkit's secret clipboard on Linux now,
as on Windows and macOS (2026-10-12); the CLI's helper stays on the BSDs,
where uitoolkit has no clipboard. The workaround for 54 is gone: the manager's
dialogs are `DialogContentFoot` now, rather than its own copy of
`DialogContent`'s arrangement. 50's, `detailText`, stays by choice: a
plan's lines read better as tall as they are, in a dialog that scrolls as
a whole, than in a box of their own. 51 needed none, only the prompts'
tests of it.

- `secretvault-gui-prompt` asks for passphrases and consent, and
  `secretvault-gui` is the manager; both are built on uitoolkit.
- Items 1–11 were asked for before either was built, 12–17 while building
  the prompt, 18–24 while building the manager, and 25–37 while moving
  through the releases since (25–29 at v0.22.1, 30–32 at v0.22.2, 33–34 at
  v0.22.5, 35–37 in the audit of v0.23.0), 38–40 while bringing the
  manager level with the CLI, on v0.23.0, 41–45 in the audit of v0.23.1,
  46–49 in the audit of v0.23.2, 50 since, on v0.23.2, 51–55 in the
  audit of v0.23.3, 56–60 in the audit of v0.23.4, 61–76 since, on
  v0.23.4, 77–89 moving to v0.23.6, 90–91 moving to v0.23.7, 92–93
  looking again for what the manager works round, at v0.23.9, and 94
  moving to v0.23.14.
- **The move to v0.23.6.** Everything the manager did for itself where
  the toolkit had nothing is the toolkit's now: its look is Hangar, a
  pack of uitoolkit's, where it was a skin of its own (`hudskin`, gone);
  its title bar's breadcrumbs are `widgets.Breadcrumbs`, their choices
  the toolkit's menus (but the vaults', a list with buttons under it);
  its notes are toasts; its icons the toolkit's seven new ones; its turn
  to Settings is the toolkit's own (`Window.SetFlipFaces` and
  `Window.Flip`), frame and all since v0.23.7 (77); its pages are plain
  scroll views, and its drop-down passes keys on by itself; the locked
  vault's logo shows the pointing hand, and its buttons' marks are the
  engine's. Since v0.23.10 it works round nothing.
- **The audit of v0.23.4** re-read every item from scratch against the
  release as the module proxy serves it (file for file the same tree as
  uitoolkit's checkout at the tag), and diffed it against v0.23.3 file by
  file. v0.23.4 changed how a secret copy ends (X11's `SelectionClear`,
  Wayland's `cancelled`, the Windows and macOS reads, the Wayland clear),
  X11's paste (a reference held across the read, a fresh timestamp for a
  copy, the INCR pieces, a late transfer), the lock keys
  (`EventLockKeys`, a focus-in), `DialogContent` and `DialogContentFoot`,
  `TextArea`'s view box and the scroll bar's geometry, the wrap of a long
  word, `OnInput`, a grid's spans, lists, owned windows and dialog
  windows, X11's geometry and shapes, racks and skins; the others are as
  they were in v0.23.3, and their pins pass. Every changed path was read
  through to the platform backends, Windows and macOS included, error
  paths too, each fix checked against the need as stated and not against
  its own description, and the notes and commits against the code. The
  claims hold this time, but one: the commit that asks the lock keys
  again at a focus-in says Wayland and AppKit are left out, and they are
  not (51), which does no harm. That found 56 (what an X11 paste that
  gave up waiting keeps), 57 (the copy a loss is pinned on), 58 (the
  primary selection a Wayland secret copy unsets) and, older and missed
  before, 59 (the Wayland clear against the event loop) and 60 (a
  Windows copy that fails). A reviewer then checked each finding against
  the code again, which narrowed 57 (real on X11, rescued with XWayland
  but for goroutine scheduling), found 56's late reply taken for the next
  paste's answer and 60, made 59 an item, and found the one place the
  manager's helper was the weaker of the two (svwayland waited without a
  deadline on a paste nobody read, now fixed). The pins test the behaviour
  where a headless window can show it (7, 34, 38–40, 44–46, 48, 50, 51,
  54), and read uitoolkit's functions, parsed rather than grepped, where
  it cannot (12, 35, 37, 41–43, 47–49, 52, 53, 55–60).
- **The manager's clipboard, decided again at v0.23.6.** With 56–60
  closed, the person chose uitoolkit's secret clipboard on Linux too
  (2026-10-12): one way of copying on every platform but the BSDs.
  What svclip still had over it stays a difference, and was weighed: the
  manager's heap holds the copy while it is on the clipboard, where the
  helper held it in a process of its own. The bullet as it was decided at
  v0.23.4 follows.
- **The manager's clipboard, decided again at v0.23.4.** On Linux the manager kept
  copying through the CLI beside it (`gui/svmanager/clip.go`):
  `secretvault __clip SECONDS`, the secret on its stdin, takes the
  clipboard in a process of its own through svclip (Wayland's data
  control, or X11, as XWayland on GNOME), offers the hint as "secret", and
  clears the clipboard at its time only if the clipboard is still its
  own; a copy taken back (its vault locked, the program quitting) ends the
  helper, and its selection goes with it, only if it still has it. With
  v0.23.4 uitoolkit's clipboard does what 7, 48, 52 and 55 asked on both
  Linux protocols, so going back to it, for one path on every platform,
  was weighed again. It is not done, because svclip is still the safer of
  the two, if now by narrow margins rather than by everyday ones:
  - uitoolkit's copy has two owners in one process, X11's and Wayland's,
    and what they can get wrong between them svclip's one cannot: a loss
    of the last copy handled as the next is made ends the new one, which
    then stays on the clipboard with nothing to clear it (57); a clear on
    its timer's goroutine meets the Wayland event loop unlocked (59);
  - the manager's heap holds no copy of the secret while it is on the
    clipboard; uitoolkit holds three (the `SecretClip`'s, X11's and the
    Wayland cache) for the whole of its time;
  - and svclip never touches the primary selection, which a Wayland secret
    copy of uitoolkit's unsets, whoever holds it (58).

  Where uitoolkit was the better of the two, it no longer is: svwayland
  wrote a paste with a blocking write, so a client that asked for a copy
  larger than a pipe holds and never read it held the helper's loop, and
  with it the clear at its time; it writes with a deadline now
  (`TestAnUnreadPasteDoesNotHoldTheClear`). What uitoolkit still does that
  svclip does not is die with the manager: a helper outlives a crashed
  manager until its time, which is what it is for. On the BSDs uitoolkit
  has no native clipboard at all, so there the CLI is the only way, and
  `clip.go` stays whatever Linux does. Where there is no CLI beside the
  program, or it cannot reach a clipboard, the copy goes to uitoolkit's,
  as before. On Windows (where an ended helper leaves its copy on the
  clipboard, so a lock could not take it back) and macOS (where svclip
  has no pasteboard yet) the manager copies through uitoolkit, where 52
  now holds and 60 stands on Windows. When uitoolkit closes 57 and 59 the
  manager can go back to `ClipboardSetSecret` on Linux.
- **What v0.23.4 gave that the list never asked for.** `ListView`'s
  `OnActivate`, `RowAt` and `ContextKeepsSelection`, and a disabled list
  that takes a press: the manager's lists are `TableView`s, which had
  `OnActivate` already. `Window.OpenDialogWindow` and a file chooser too
  big for its window put in one of its own: the manager's window is at
  least 440 tall, enough for the chooser's overlay, but `pickFile` now
  takes the chooser down by its own `FileDialog.Cancel`, which closes
  such a window too, where the old way took down this window's top
  overlay, the wrong dialog if the chooser was not one (and with the
  desktop's own chooser too). `RoleUtility`, `WindowOptions.Owner` and
  `SkipTaskbar`: the manager's passphrase question could say it belongs
  to the manager's window, but it is asked while that window is in the
  tray too, and a window owned by a hidden one is placed and kept as its
  desktop pleases, so it is left as it is. `DropEvent.Remote`: nothing of
  the manager's takes drops. `style.CanBreakAfter` and `Font.Wrap`
  breaking a path after a separator: the prompt's "Asked by" line gets it
  with no change; `detailText` keeps its own rule, which prefers a slash
  to a dot. `SetSize` laying out again, skins' anchors and racks: nothing
  of the manager's uses them. And `OnChange` and `OnInput` no longer
  counting a handler's own write as input: the "Open when I log in" box
  sets `Checked` itself, so nothing changes for it.

Two voices below. **"After v0.2x.y"** paragraphs are secretvault's own
checks, each pinned by a test in `gui/uitoolkit_test.go`. **"Closed in
0.2x.y"** paragraphs are uitoolkit's maintainers' notes on the same items;
those for 0.23.1 to 0.23.21 are their release notes' words, copied
verbatim (for 0.23.2, for 46 in 0.23.3, and for parts of 51, 54 and 55
in 0.23.4, the commit's where the release notes say less). The
maintainers count all of 18–32 closed by 0.22.3, 8, 23 and 28 closed by
0.22.5, 12, 33–38 and 40 closed by 0.23.1, 39 and 41–45 closed by
0.23.2, 12's other half and 46–49 closed by 0.23.3, and 50–55 closed by
0.23.4; their notes for 0.23.5 and 0.23.6 number none of secretvault's
items, and what they describe closes 56–60 (0.23.5) and 62–76 (0.23.6);
those for 0.23.7 name secretvault's 78 and close 77–87 and 89, and those
for 0.23.8 close 90 and 91; those for 0.23.9 touch none of the items,
those for 0.23.10 close 92 and 93, those for 0.23.11 to 0.23.14 touch
none, those for 0.23.15 close 94, and those for 0.23.16 to 0.23.21 touch none. secretvault's checks agree on 7, 8, 12,
18–29, 31–60, 62–87 and 89–94, and disagree on:

- 30: `DismissOverlay` from outside closes the *top* dialog only, so the
  manager keeps `SetOverlay(nil)` at quit, which closes them all;
- 89: the floor came out too small here, not too large, as the
  maintainers found it; a panel holds its chrome either way now.

The GUIs build against uitoolkit v0.23.21 from the module proxy
(`gui/go.mod`). `gui/uitoolkit_test.go` checks every item from 7 on
against it, headless, a test per item (`TestItem12CapsLock` and so on): a
provided item's test pins what secretvault relies on, and an open item's
test pins the gap, so it fails on the uitoolkit release that closes it.
Item 23's tray half is pinned in `gui/svmanager/tray_test.go` on a private
session bus; 12, 35, 37, 41–43, 47–49, 52, 53 and 55–60 are about code no
headless window reaches, and their pins read uitoolkit's source as the
test is built against it, as do those of 71, 74, 76–79, 81 and 82, to
see that what the manager relies on is there, or that what is missing is
missing still.

| # | Item | After v0.23.21 | Verdict |
| --- | --- | --- | --- |
| 1 | A secret field that does not leak | `widgets.SecretField` (65463cc): a byte buffer edited in place, zeroed when outgrown or shortened, copy, cut, drag and PRIMARY refused, no string made of it; a paste is bytes on every platform (e54cba4, 18a98d9) | **Satisfactory**, a late X11 paste too (56) |
| 2 | A dialog window | `Role`, `Center`, `KeepAbove`, `Activate` (3fa3094) | **Satisfactory** |
| 3 | Holding the keyboard | `SetSecureInput`, and since 3c3c2c7 `SecureInputHeld`, `OnSecureInput`, the X11 grab taken at the map | **Satisfactory** (37); the prompts say "Typing is private" |
| 4 | Out of screenshots | `Window.SetExcludeFromCapture` (b87afe0); Windows and macOS only | **Satisfactory** where a platform can; X11 and Wayland cannot, by the platform |
| 5 | No input method in secret fields | input method off while a `SecretTarget` has the focus (`app/window.go`, `syncIMECursor`) | **Satisfactory** |
| 6 | Headless driving for tests | `Type`, `Press`, `ClickComponent`, `FocusOn` (a0bd1d7) | **Satisfactory** |
| 7 | A clipboard that can hold a secret | `ClipboardSetSecret` and the rest (7020c65), `OnCleared` (58140ea); bytes everywhere (e54cba4, d9356f0); wiped before it is said gone (9e7e1c6); the hint "secret" on Wayland too (dbcb934); cleared only while it is ours (c3ba669); ended by another program's copy everywhere (4a6691c); the Wayland end (6e161a6, 16aca25); held only once it is on the clipboard (34a8a36); a refused copy not taken for one (d635a4b); the clear on the loop (f1cd408); another program's primary selection left alone (88f39fa) | **Satisfactory** (52, 55, 57–60); a Wayland cancel that names nothing: 85; a busy Windows clipboard: 86. The manager copies through uitoolkit on Linux too |
| 8 | Showing a secret without a string | `SecretLabel.MaskLen`, `Lines`, `Describe` (649af18); no copy masked (6126bcd) | **Satisfactory**; the manager keeps its own, which holds no copy revealed either |
| 9 | A tray menu on macOS | `SetMenu` builds an NSMenu (9f360ec) | **Satisfactory** (not run on macOS here) |
| 10 | Search-as-you-type suggestions | `widget.SetPopupKeysPass` (5285f3e) | **Satisfactory** (unused) |
| 11 | Symbol and emoji fallback | no font fallback, by contract (`docs/contracts.md`) | **Declined**; marks are icons, which the manager uses |
| 12 | Caps Lock state | `ModCapsLock`, `LockKeys`, `OnLockKeys` (923fab0); a focus-in left alone (285b6b7); every backend can be asked (dbcb934); `EventLockKeys`, and asked again at a focus-in (70f4d6e, e535eb1) | **Satisfactory** (51) |
| 13 | A dark desktop with no saved look | `FollowDesktop` by default, `plastik-night` (c98f83b) | **Satisfactory** |
| 14 | Spacing that follows the display scale | 1x lengths (201bbd6, 36685fe) | **Satisfactory** |
| 15 | A window as tall as its content | `FitContent` (923fab0), re-centred (58140ea) | **Satisfactory** |
| 16 | A default button that looks it | measured per pack (256978b) | **Satisfactory** |
| 17 | A wrapping label measured at its own width | `Font.Wrap` (256978b) | **Satisfactory** |
| 18 | Giving a secret field a value | `SecretField.SetBytes` (58140ea), taking ownership | **Satisfactory** |
| 19 | A secret text area | `widgets.SecretArea` (fc42680) | **Satisfactory**, a late X11 paste too (56) |
| 20 | Dialogs that stack | (fc42680) | **Satisfactory** |
| 21 | A wrapping label's height in a column | for dialogs (91133b2); a column is the caller's | **Satisfactory** |
| 22 | Clicking something scrolled out of view | (5e7a6cc) | **Satisfactory** |
| 23 | Knowing that the tray icon is shown | `Shown`, `SetOnShownChange` (58140ea, 649af18) | **Satisfactory** |
| 24 | A widget taken out of the tree still has its window | (58140ea) | **Satisfactory** |
| 25 | Pad, Spacer and ProgressBar lengths | (36685fe) | **Satisfactory** |
| 26 | `UITK_FONT` turns following the desktop off | (58140ea) | **Satisfactory** |
| 27 | A fitted dialog centred | (58140ea) | **Satisfactory** |
| 28 | Caps Lock in the field itself | `LockKeysWatcher`, `CapsHint`, `LockKeysOf` (5e7a6cc, 649af18); kept through a focus-in (285b6b7); told what the window system says (70f4d6e) | **Satisfactory** |
| 29 | Readable status colours | `Ink`, `Label.Tone` (36685fe, 6e1d4f9) | **Satisfactory** |
| 30 | Closing a dialog from outside every dialog | the top one (6e1d4f9) | **Satisfactory**; all of them is `SetOverlay(nil)` |
| 31 | Status ink that keeps its colour | (6e1d4f9) | **Satisfactory** |
| 32 | A SecretArea in a narrow form | (6e1d4f9), `PreferredWidth` | **Satisfactory** |
| 33 | A hidden SecretLabel's copy of the secret | (6126bcd) | **Satisfactory** |
| 34 | A window's floor from its content | `Window.SetMinSize`, `Splitter.MinWidth`, `TextField.PreferredWidth` (afa38a3, 3a0fba6); a one-child wrapper (99e0c22) | **Satisfactory**; it lasts (44) |
| 35 | A secret on the Linux clipboard as a string | (e54cba4, d9356f0, 99e0c22) | **Satisfactory**, and what was left (56–59) since v0.23.5 |
| 36 | A form value read aloud as its caption | (570438f) | **Satisfactory**; the prompt's workaround is gone |
| 37 | Secure input's answer, and its first attempt | (3c3c2c7) | **Satisfactory**; a failed grab is no diagnostic, which secretvault does not need |
| 38 | A form's rows shown or hidden | `Form.Row`, `FormRow` (021593b); no gap (d9356f0) | **Satisfactory**; Add… for a keyslot is one step |
| 39 | A grid cell offered no width | `widgets.Share` (e011659) | **Satisfactory**; the manager's fixed wrap is gone |
| 40 | A dialog taller than its window | `DialogCard` (bba1c63), `DialogContent` (dbb2644), `DialogContentFoot` (16aca25) | **Satisfactory**; the manager's dialogs are `DialogContentFoot`. The QR code is back under its invite |
| 41 | The Wayland owner serves a secret from a string | (d9356f0) | **Satisfactory** |
| 42 | What a pasted secret leaves behind | (d9356f0, 18a98d9) | **Satisfactory**, a long paste and a late one too (49, 53, 56) |
| 43 | X11 reads its own copy as the last paste | (99e0c22) | **Satisfactory** |
| 44 | A window's stated minimum does not last | (99e0c22) | **Satisfactory**; the manager no longer states it again |
| 45 | A hidden form row keeps its gap | (d9356f0) | **Satisfactory** |
| 46 | `DialogContent` fills the window, and squeezes a `ButtonBox` | (244f2ac) | **Satisfactory**; a foot that holds a `ButtonBox` too since v0.23.4 (54) |
| 47 | Wayland answers the password-manager hint with the secret | (dbcb934) | **Satisfactory** |
| 48 | A copied secret outlives the clipboard | (c3ba669): the program's own copy, everywhere; another's, everywhere (4a6691c); the clear, on all four, the Wayland one giving up only its own (16aca25) | **Satisfactory** (52, 55, 60) |
| 49 | What a long pasted secret leaves behind | (244f2ac; 6e161a6) | **Satisfactory** (53) |
| 50 | A short text view's scroll bar is squeezed, and its lines run under it | (16aca25) | **Satisfactory**; the manager keeps `detailText`, by choice |
| 51 | Caps Lock is asked of a Wayland window before the compositor has said | (70f4d6e, e535eb1) | **Satisfactory** |
| 52 | Another program's copy leaves a secret held on X11, Windows and macOS | (4a6691c) | **Satisfactory** (60) |
| 53 | X11's INCR transfer still leaves pieces of a long paste | (6e161a6, 16aca25) | **Satisfactory** (56) |
| 54 | `DialogContent` squeezes a foot that holds a `ButtonBox` | (70f4d6e, 16aca25) | **Satisfactory**; the manager's dialogs are `DialogContentFoot` |
| 55 | The Wayland end of a secret copy | (6e161a6, 16aca25) | **Satisfactory** (57, 58) |
| 56 | An X11 paste that gave up waiting keeps what arrives after it | (716d552) | **Satisfactory** |
| 57 | A loss still on its way is pinned on the copy just made | (34a8a36) | **Satisfactory**; a Wayland cancel that names nothing: 85 |
| 58 | A Wayland secret copy unsets the primary selection, whoever holds it | (88f39fa) | **Satisfactory**; the manager copies through uitoolkit on Linux now |
| 59 | A secret's clear runs on its timer's goroutine, against Wayland state the event loop changes unlocked | (f1cd408) | **Satisfactory**; the manager copies through uitoolkit on Linux now |
| 60 | A Windows secret copy that fails is taken for one that was made | (d635a4b), macOS too | **Satisfactory**; a busy Windows clipboard keeps the copy before it: 86 |
| 61 | A tree that picks several nodes | (new, since v0.23.4) | **Open** (unused): the manager's items are a list, which picks several |
| 62 | A popup's keys go to the popup alone | (6f6fc45) | **Satisfactory**; the manager's drop-down takes Escape alone |
| 63 | A key with the keyboard on nothing reaches nothing | (6f6fc45) | **Satisfactory**; the manager still puts the keyboard on the part's button, for Tab |
| 64 | A scroll view takes Ctrl+Page Up and Down | (125681b) | **Satisfactory**; the manager's pages are plain scroll views |
| 65 | `ShowPopup` shows a popup at the size it was measured at | (4d237e5) | **Satisfactory**; the manager places its drop-down with `PlacePopupForAnchor` all the same |
| 66 | Breadcrumbs | `widgets.Breadcrumbs` (c9d508b) | **Satisfactory**; the manager's title bar is one. A tip: 79; a sign of a menu: 81 |
| 67 | Icons a password manager needs | seven icons (52541d9) | **Satisfactory**; the manager draws none of them now |
| 68 | Nothing lies over a framed window's title bar | `Window.SetCover` (c575c39) | **Satisfactory** (unused now: the manager's turn is `Window.Flip`, 77) |
| 69 | A window cannot be laid out at once | `Window.Layout` (7002b3f) | **Satisfactory** |
| 70 | A picture cannot be drawn in perspective | `widgets.FlipPanel` (2041083, ee2acd5) | **Satisfactory** otherwise: the turn is the toolkit's; paintengine2d still has no projective draw. The whole window: 77 |
| 71 | No pointing hand | `platform.CursorPointer` (5dc6a0d) | **Satisfactory**; on the locked vault's logo |
| 72 | No passing note | `widgets.Toast` (e7c055b) | **Satisfactory**; the manager's notes are toasts |
| 73 | A skin's radio is its check box | a `radio` part (2a518d9) | **Satisfactory** (unused: the manager's look is a pack, Hangar) |
| 74 | A button's icon is in the text's colour, not its label's | `style.ButtonDraw` (da6819a, c74233f) | **Satisfactory**; the manager draws no mark again. The strip at 2x: 80 |
| 75 | A framed window's shadow cannot be turned off | `Window.SetFrameShadow` (1fa7918) | **Satisfactory** (unused now: the manager's window has no frame of the toolkit's, 77) |
| 76 | A skin's capitals reach its caption's title alone | `style.ControlLabelOf` (9a643ab) | **Satisfactory**; Hangar's labels are in capitals |
| 77 | A framed window cannot turn over, title bar and all | `Window.Flip` of a framed window (f754b65) | **Satisfactory**; the manager's window turns with its frame, buttons and resizing |
| 78 | A flip panel's pictures are not wiped | `FlipPanel.Wipe`, the window's photographs (c40b170) | **Satisfactory** |
| 79 | A breadcrumb has no tip of its own | `Crumb.Tip` (aadd607) | **Satisfactory**; the vault's step says its state |
| 80 | A marked button's mark strip does not scale with the display | (714f8ab) | **Satisfactory** |
| 81 | A breadcrumb that opens a menu shows no sign of it | `Crumb.Opens` and a chevron (aadd607) | **Satisfactory** |
| 82 | A breadcrumb's words are cut short by a rounding error | `Font.Fit`'s slack (f899ec5) | **Satisfactory** |
| 83 | A merged caption drops the look's silhouette | (05f6aa2) | **Satisfactory**; the manager's window is cut |
| 84 | A cut corner's border is painted under the content | `style.DecorationOverEngine` (44415e8) | **Satisfactory**; Hangar's bracket shows over the rail |
| 85 | A Wayland cancel handled while nothing is held ends the next secret | (39e4fa4) | **Satisfactory** |
| 86 | A busy Windows clipboard keeps the copy before a new one | (39e4fa4) | **Satisfactory** |
| 87 | Nothing animates where the person's settings ask for less motion, whoever asks | `SetMotion`, `style.MotionAlways` (b076d9b) | **Satisfactory**; the manager's turn is `MotionAlways` |
| 88 | A window panel's silhouette is not its window's shape | (new, at v0.23.6) | **Open** (unused now: the manager's window has the toolkit's frame again, 77) |
| 89 | A panel's floor leaves out its chrome | `Panel.MinWidth` (5179abe) | **Satisfactory** (unused now: no window panel) |
| 90 | A flip panel passes a key to neither face | `FlipPanel.KeyPress` (8ca4b6d) | **Satisfactory**; the title bar's keys reach the manager's by themselves |
| 91 | A framed window always turns the same way | (a12ba05) | **Satisfactory** |
| 92 | One digit key | `Key0`..`Key9` (398d343) | **Satisfactory**; the manager's parts are Ctrl+1, 2, 3 |
| 93 | The icon set has no cloud, and an icon carries no badge | `IconCloud`, `DrawIconBadge` (a097e91) | **Satisfactory**; the manager draws its logo alone |
| 94 | A framed window's turn cannot be held still from outside | `FlipPanel.Clock`, carried to the turn (6100823) | **Satisfactory**; the manager's turn test steps a held clock |

The first findings come from reading uitoolkit's source at v0.20.x (file
references are to that tree); 12–24 come from building on it after v0.21.0,
25–29 from moving to v0.22.1, 30–32 from moving to v0.22.2, 33–34 from
moving to v0.22.5, 35–37 from the audit of v0.23.0, 41–45 from the
audit of v0.23.1, 46–49 from the audit of v0.23.2, 50 from the
plain-language pass on v0.23.2, 51–55 from the audit of v0.23.3 and
56–60 from the audit of v0.23.4 (references to those trees). Each item says where the
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

**After v0.23.4 (item 1): satisfactory.** `widgets/secretfield.go` is as
it was. A long paste leaves nothing on either Linux protocol now (49,
53), and a paste after another program's copy reads that copy on every
platform (52). What an X11 paste that gave up waiting keeps is 56.

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
the manager's passphrase question, says "Typing is private" while it is, and
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

**Closed in 0.23.3** (the release notes, verbatim): **Wayland answered the password-manager hint with the passphrase.** A secret copy offers `x-kde-passwordManagerHint` so that clipboard managers do not record it, and the convention — KeePassXC writes it, Klipper reads it — is that the hint's *value* is the word "secret". The Wayland data source dropped the type it was asked for and answered every request with the selection. Klipper asked for the hint, found a passphrase where it looks for "secret", took the copy for an ordinary one, and kept it in the history it writes to disk. X11 had answered it correctly all along. **A copied secret outlived the clipboard.** Nothing ended the held secret when the clipboard moved on, so for the rest of its timeout — 30 seconds in a password manager — a paste into a `SecretField` served the *old* secret rather than what was actually copied, and the clear at the timeout emptied whatever the clipboard held by then. That last one was the toolkit breaking its own documented promise, on three of four backends; only X11 checked. Windows now checks the clipboard sequence number, macOS the pasteboard's `changeCount`.

**After v0.23.3: partly (52, 55); the manager still copies through the
CLI on Linux.** Read once more end to end, every backend. The
hint holds on both Linux protocols (47): the Wayland data source passes
the type it is asked for through, and the hint is answered "secret" while
the selection is a secret; X11 as before. The clear holds on all four
(48): a copy ends without touching the clipboard at the program's own
next copy, everywhere, and at Wayland's `cancelled`; and each backend's
clear checks the copy is still there (X11 that it owns the selection,
Windows the clipboard's sequence number, macOS the pasteboard's
`changeCount`). CLIPBOARD only, the timeout and the wipe before anything
says it has gone are as they were. What falls short: another program's
copy on X11, Windows and macOS leaves the secret held (52); and on
Wayland a cancel ends whatever copy is held when it is handled, which
with XWayland beside the compositor is likely every copy, at once, while
X11 goes on serving it with nobody left to clear it, and the clear takes
the primary selection (55). So "is gone after the timeout" no longer
holds on such a desktop. Smaller edges, not items, none of which the
manager reaches: `ClipboardClear` says it empties the clipboard
"whatever is on it", and on Windows and macOS it no longer does once a
copy has ended without a clear (an ordinary copy after it, or a timeout
that found the clipboard moved on), because the noted sequence number
or `changeCount` is left behind and the clear checks it; Windows notes
the sequence number after a copy whether or not the copy was made (the
clipboard busy for all of `withClipboard`'s tries), so the clear of a
copy that failed empties what was there before it; and the noted number
is a plain variable written on the UI goroutine and read on the timer's,
a data race on those two platforms. Nothing of secretvault's calls
`ClipboardClear`. The manager's decision is the one at the
top: it keeps copying through the CLI on Linux and the BSDs.
`TestItem07ASecretOnTheClipboard`, `TestItem47WaylandAnswersTheHintSecret`
and `TestItem48ACopiedSecretEndsWithTheClipboard`.

**Closed in 0.23.4** (the release notes, verbatim): **Another program's copy left a secret held.** On X11 the bytes the owner served were zeroed and the `SecretClip` was left held with its own copy of the passphrase in it; on Windows and macOS nothing was asked at all. So for the rest of its time a paste into a `SecretField` took the old secret — copy a passphrase from another program into a new vault's "Passphrase" and "Repeat", and the vault was made with the item copied before. The two platform shapes are answered differently because they are different: X11 is *told* it has lost a selection, Windows and macOS say nothing and are asked. **A Wayland clear threw away the user's selection.** It was an ordinary copy of an empty string, which is still a copy: it took CLIPBOARD *and the primary selection* with an empty offer this program then went on serving, so a secret's timeout discarded whatever the person had selected somewhere else since. It gives up the selections this process owns and touches nothing else.

**After v0.23.4: partly, and narrowly (57, 59, 60); the manager still
copies through the CLI on Linux.** Read once more end to end, every
backend, error paths too. What the item asked holds on all four, and
what 52 and 55 asked with it: CLIPBOARD only, the hint answered
"secret" on both Linux protocols, the copy bytes on every path and
wiped before anything says it has gone, a clear only while the copy is
still there, and now an end when another program copies, wherever the
platform says so or can be asked (52), and on a Wayland desktop with
XWayland a copy held while either of its clipboards still serves it
(55). Three things are left, none of which an ordinary day reaches, and
all three where a copy can stay on the clipboard, or go, other than as
its timer says: the new copy is held before it is on the clipboard, and
a loss of the last one is pinned on whatever is held when it is handled,
so one handled as the next copy is made ends that copy, which then stays
with nothing to clear it (57); the clear runs on its timer's goroutine
and meets the Wayland event loop without the lock (59); and on Windows a
copy that fails is taken for one that was made, and its clear empties
what was there (60). A Wayland secret copy also unsets the primary
selection, whoever holds it (58), which costs the person a selection
rather than a secret. The `ClipboardClear` edges of v0.23.3 are as they
were; nothing of secretvault's calls it. The v0.23.4 X11 paste fixes the
release notes call "an empty clipboard about one try in ten" (a
reference held across a read, a fresh timestamp for a copy, a clear
that comes for an ownership already replaced) reach a `SecretField`'s
paste and the manager's own copies on X11 alike, and hold.
`TestItem07ASecretOnTheClipboard`, `TestItem48ACopiedSecretEndsWithTheClipboard`,
`TestItem52AnotherCopyEndsAHeldSecret`, `TestItem55TheWaylandEndOfASecretCopy`
and 57–60's.

**Closed in 0.23.5** (the release notes, verbatim, the head of "The secret clipboard, audited"; its five points are quoted under 56–60): The vault read 0.23.4's clipboard work through to the backends and found five things. Two were 0.23.4's own: … And three older ones that every audit before this one missed: …

**After v0.23.6: satisfactory (57–60); the manager copies through it on
Linux too now.** Read once more end to end, every backend, error
paths too. What the item asked holds on all four, and what 52 and 55
asked with it: CLIPBOARD only, the hint answered "secret" on both Linux
protocols, the copy bytes on every path and wiped before anything says
it has gone, a clear only while the copy is still there, an end when
another program copies, and on a Wayland desktop with XWayland a copy
held while either of its clipboards still serves it. The three things
v0.23.4 left are closed: a copy is held only once the platform has
taken it, so a loss on its way finds nothing to end (57); the clear
runs on the loop rather than against it (59); and a copy the platform
refuses comes back cleared, on Windows and macOS alike, its sequence
number or `changeCount` not noted, a refused Windows block zeroed (60).
A Wayland secret copy leaves another program's primary selection alone
(58), and a paste that gave up waiting keeps nothing that comes after
it (56). Two narrow edges are left, read from the code: a Wayland cancel
handled while nothing is held ends whatever is held when its goroutine
runs (85); and the copy a new one replaces is let go before the new one
is tried, so a Windows clipboard held open by another program for all
of the copy's tries leaves the previous secret on it with nothing to
clear it (86). Of the `ClipboardClear` edges of v0.23.3, the failed
Windows copy is 60's and closed, the noted number has been atomic since
v0.23.4, and the first, that on Windows and macOS it leaves the
clipboard alone once a copy has ended without a clear, is as it was;
nothing of secretvault's calls it.
The manager's clipboard was decided again at the top: it copies through
uitoolkit on Linux too now (2026-10-12), and through the CLI on the BSDs
alone. `TestItem07ASecretOnTheClipboard`,
`TestItem48ACopiedSecretEndsWithTheClipboard`,
`TestItem52AnotherCopyEndsAHeldSecret`,
`TestItem55TheWaylandEndOfASecretCopy` and 56–60's.

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

**Closed in 0.23.3** (the release notes, verbatim): 0.23.2's notes said Caps Lock cannot be reported before the first key on Wayland — "that is the protocol". **That was wrong.** The compositor sends `wl_keyboard.modifiers` directly after `wl_keyboard.enter`, before any key, and this backend has folded it into its xkb state since long before that release; it simply told nobody. A `wlSurface` answers `LockKeys` from it now. macOS could always be asked — `NSEvent.modifierFlags` is a property of the keyboard, not of an event — and did not implement it either. Every backend that can be asked is now asked, so a passphrase prompt opened with Caps Lock on says so before the first keystroke, which is the one case the warning exists for.

**After v0.23.3: satisfactory on X11, Windows and macOS; on Wayland not
yet (51).** Every surface is a `LockKeysSurface` now. An AppKit one reads
`[NSEvent modifierFlags]`, the keyboard's at any moment, so a prompt
opened on macOS with Caps Lock on says so as soon as it is laid out. A
Wayland one answers from `c.mods`, which `uitkWlKeyMods` keeps from the
compositor's modifiers event, under `wlMu`. But a Wayland window is asked
too early: the field and the Caps Lock line ask when they are first laid
out and focused, which is before the window is mapped, so before
`wl_keyboard.enter` and the modifiers that come after it. On
`secretvault-gui-prompt`'s new connection the answer then is off; the
state comes; and nothing tells the window: `uitkWlKeyMods` pushes no
event, and the focus-in notes nothing (285b6b7). So the release notes'
"a passphrase prompt opened with Caps Lock on says so before the first
keystroke" holds on three backends; on Wayland the mark still comes with
the first key, or with the pointer: a window that maps under it gets a
pointer enter, which carries the modifiers, and says so then if the
compositor sent the keyboard's modifiers first. That is 51. (The
manager's own passphrase question, a window of its own on a connection
that already had the keyboard, gets the state the compositor last sent
it, which is right unless the lock was changed in another program
since.) `secretui.CapsLock` needs no change: it asks the window, which
asks the surface. `TestItem12CapsLock` pins every backend's query, and
`TestItem51CapsLockBeforeTheCompositorHasSaid` the Wayland timing.

**Closed in 0.23.4** (the release notes, verbatim): **The lock keys are asked again at a focus-in**, on the backends that can be asked. They belong to the user's keyboard and not to this window, so Caps Lock turned on while another program had the focus is on when the focus comes back — and a prompt went on showing what it knew when it last saw a key.

**After v0.23.4: satisfactory, on all four backends (51).** The half the
release notes do not mention is the one the item turned on: the Wayland
backend now tells the window what the compositor's modifiers say
(`uitkWlKeyMods` pushes `EventLockKeys` to the surface that has the
keyboard), so a prompt laid out before the compositor has said anything
says Caps Lock is on as soon as it has, before the first key. And every
window asks its surface again at a focus-in (`refreshLockKeys`), which
on X11, Windows and macOS is the keyboard at that moment. See 51 for
what the commit says of Wayland and AppKit there, which the code does
not do, to no harm. `TestItem12CapsLock`, and
`TestItem51AWindowLearnsTheLocksItOpenedIn`; the prompt's and the Caps
Lock line's own tests open a dialog with the keyboard off, then say it
is on as the window system says so.

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

**After v0.23.4: satisfactory.** As item 1: a key pasted on X11 in INCR
pieces leaves none now (53); a late one is 56. `SecretArea` is not a
`TextArea`, so 50's changes do not reach it.

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

**After v0.23.4: satisfactory.** A focus-in now asks the keyboard again
(12, 51), so a watcher may hear of it; what it hears is the keyboard's
state, and with Caps Lock on the mark stays. `TestItem28LockKeysWatchers`
checks that a watcher told anything at the focus-in is told the lock is
on.

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

**After v0.23.4: satisfactory; what is left is 56–59.** No string of a
secret on either Linux protocol, the new paths included: the Wayland
clear destroys a source and makes no copy, X11's `endLostSecret` and
the mirror checks read flags, and an INCR piece is zeroed before Xlib
frees it. `TestItem35TheLinuxSecretClipboardIsBytes` passes.

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

**After v0.23.3: satisfactory.** `DialogCard` and `DialogContent` keep
their buttons in view and scroll their body, and now size to what they
hold (46); `TestItem40ADialogTallerThanItsWindow` still passes. The
manager still builds the arrangement itself, for a foot `DialogContent`
squeezes (54).

**After v0.23.4: satisfactory; the manager's dialogs are
`DialogContentFoot`.** The arrangement is the toolkit's now (54), and a
dialog taller than the window scrolls its body with its foot in view as
before; `TestItem40ADialogTallerThanItsWindow` passes, and so does the
manager's own test of a dialog taller than its window. A dialog too big
for its window's overlay, which v0.23.4 puts in a window of its own, is
the file chooser's case only (`OpenDialogWindow`); the manager's window
is tall enough for it.

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

**After v0.23.3: satisfactory.** `uitkWlDataSend` now takes the type
asked for and answers the hint first, with a literal (47); everything
else is served from `getBytes` as before, and `uitkWlPrimSend` is
unchanged. `TestItem41WaylandServesASecretFromItsBytes` passes.

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

**After v0.23.3: satisfactory for a passphrase, and on Wayland for a
longer paste (49); on X11 a longer paste still leaves its pieces (53).**
The five buffers named are handled as they were, and
`TestItem42APastedSecretLeavesNoString` passes.

**After v0.23.4: satisfactory, a longer paste too (53); a late X11 paste
is 56.** The five buffers named are handled as they were. X11's readers
now hold a reference across the read, so the connection is no longer
closed under a paste (a use-after-free the release notes found), and the
pieces of a long one are zeroed before Xlib frees them. What a paste
that gave up waiting keeps until the next is 56.

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

**Closed in 0.23.3** (the commit, 244f2ac, verbatim; the release notes do not mention it): secretvault #46, which is a flaw in what 0.23.2 added: - DialogContent's ScrollView was not told to shrink to its content, and a scroll view offered a height takes all of it. An Overlay measures its card in 0.8 of the window, so a dialog built of it was that tall whatever it held: a one-line confirmation came out 560 pixels tall in a 700-pixel window; - a ButtonBox handed to it as the action was squeezed to its natural width at the right end of a justified row, which loses the point of it — its left-hand group, Help and a destructive button under Mac and GNOME looks, was no longer apart. One action that lays itself out now gets the width.

**After v0.23.3: satisfactory as asked; the manager keeps its own
arrangement (54).** `DialogContent`'s scroll view shrinks to its content,
so a one-line `DialogCard` is 142 pixels tall in a window 700 tall, the
Overlay's floor of 140 and no more; and a `ButtonBox` handed to it alone
is the foot, at the column's full width: under the light look a
destructive button at its left edge, Cancel at its right. "One action
that lays itself out" is, in the code, a `*ButtonBox` and nothing else
(the commit's sentence is about the `ButtonBox`, and its comment says
so). Every passphrase question of the manager's has a foot of "Caps Lock is
on" beside its `ButtonBox`, flexed (a new vault, and every form with a
secret in it, an import's among them with Back at the far left), and that
foot, handed to `DialogContent`, goes in a row justified to the end at
its natural width: Back is no longer at the far left, and the line moves
from the left edge to beside the buttons. So `showDialog` keeps building
the same arrangement itself, one path for every dialog, the
plain-language pass's `detailText` bodies included; that is 54. The
dialog's width is the manager's either way: `DialogContent`'s scroll
view takes all the width it is offered, as every scroll view does.
`TestItem46DialogContentFitsWhatItHolds`.

**After v0.23.4: satisfactory, a foot that holds a `ButtonBox` too
(54).** What 46 asked is as it was, and `TestItem46DialogContentFitsWhatItHolds`
still passes; the rest is 54.

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

**Closed in 0.23.3** (the release notes, verbatim): **Wayland answered the password-manager hint with the passphrase.** A secret copy offers `x-kde-passwordManagerHint` so that clipboard managers do not record it, and the convention — KeePassXC writes it, Klipper reads it — is that the hint's *value* is the word "secret". The Wayland data source dropped the type it was asked for and answered every request with the selection. Klipper asked for the hint, found a passphrase where it looks for "secret", took the copy for an ordinary one, and kept it in the history it writes to disk. X11 had answered it correctly all along.

**After v0.23.3: satisfactory.** `uitk_dsrc_send` passes the type asked
for through, and `uitkWlDataSend` answers the hint before it reads the
selection, with the literal "secret", and only while the selection is a
secret: `clipSecret`, set by the copy (`wlClipSetSel`) and dropped by an
ordinary one and by `cancelled`. The text types get the bytes, served as
41 has it; a type that was never offered gets them too, which only a
reader that could have asked for the text anyway can ask. X11 answers
the hint target "secret" as before. `TestItem47WaylandAnswersTheHintSecret`
reads all of it; Klipper itself is not run here.

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

**Closed in 0.23.3** (the release notes, verbatim): **A copied secret outlived the clipboard.** Nothing ended the held secret when the clipboard moved on, so for the rest of its timeout — 30 seconds in a password manager — a paste into a `SecretField` served the *old* secret rather than what was actually copied, and the clear at the timeout emptied whatever the clipboard held by then. That last one was the toolkit breaking its own documented promise, on three of four backends; only X11 checked. Windows now checks the clipboard sequence number, macOS the pasteboard's `changeCount`.

**After v0.23.3: partly; the rest is 52 and 55.** Read on every backend.
What ends a copy: the program's own ordinary copy, everywhere
(`ClipboardSet` calls `forgetHeldSecret` first, which wipes the held
secret and runs its `OnCleared`, and leaves the clipboard alone); and on
Wayland another program's (`uitkWlDataCancelled` zeroes the cache, drops
`clipSecret` and ends the held secret, on a goroutine of its own). What a
clear checks: X11 gives up only a selection it owns, as before; Windows
notes `GetClipboardSequenceNumber` after the copy and empties the
clipboard only while it is unchanged; macOS the pasteboard's
`changeCount` the same; and a Wayland copy another program replaced has
already ended, so its clear does nothing. So the half the release notes
call the toolkit breaking its promise is mended on all four.
`TestItem48ACopiedSecretEndsWithTheClipboard` checks the program's own
copy headless (the secret wiped and said gone, a paste reading the new
copy, nothing held, the clear leaving the copy alone) and reads each
backend's. What the item asked and v0.23.3 does not do, though the
release notes' first sentence reads as if it did: another program's copy
ends nothing on X11 (`handleSelClear` zeroes what the owner served and
leaves the `SecretClip` held, its bytes in it), Windows or macOS (neither
is asked), so there a paste into a `SecretField` still takes the old
secret, and `ClipboardHoldsSecret` still says one is held: 52. And what
v0.23.3 added on Wayland ends more than it should: a cancel ends whatever
copy is held when it is handled, which on a desktop with XWayland beside
the compositor is likely the copy just made, since the same copy takes
X11's clipboard and the compositor carries that over to Wayland; the
copy is then said gone and never cleared from X11. The Wayland clear
still sets an empty ordinary copy rather than destroying the source,
which takes the primary selection. Both are 55.

**After v0.23.4: satisfactory (52, 55).** Another program's copy ends a
held secret on all four backends now, X11 when it is told
(`SelectionClear`), Wayland when its source is cancelled, Windows and
macOS when a paste or `ClipboardHoldsSecret` reads the sequence number
or `changeCount` back and finds it moved; and the Wayland clear gives up
only this program's own source rather than copying nothing. So after
another copy a secret paste reads it, nothing is said to be held and the
bytes are zeroed, and the clear at the timeout leaves the clipboard as
it is, on all four: the item's "done when". On Windows and macOS the
held bytes go when something asks, or at the timeout, since nothing
tells those two; that is what the proposal asked. One way round the
check is left: a Windows copy that fails is noted as made, so its clear
empties what was there (60). `TestItem48ACopiedSecretEndsWithTheClipboard`
and `TestItem52AnotherCopyEndsAHeldSecret`.

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

**Closed in 0.23.3** (the release notes, verbatim): **A long paste left what it outgrew.** `append` drops the old array unzeroed, so a private key read in pieces left a 4 KiB prefix, then an 8 KiB one, then 16, each holding the start of the secret and none of them reachable to wipe. Both readers grow by hand now, and X11 zeroes each INCR piece before `XFree`.

**After v0.23.3: satisfactory on Wayland; on X11 not (53).**
`appendWiping` grows by hand and zeroes the whole array it outgrows, its
spare capacity too. `wlReadLoop` grows by it, and the staging buffer and
a partial read are zeroed as before (42); X11's `AppendINCRPiece` grows
by it, and the whole is zeroed once copied out.
`TestItem49ALongPasteLeavesNothingItOutgrew` drives the growth through
`AppendINCRPiece` and finds every array it outgrew zeroed. But the
release notes' "X11 zeroes each INCR piece before `XFree`" is not what
the code does: `handleProperty` copies each piece out of Xlib's buffer
(`C.GoBytes`) and frees that buffer at once, unzeroed; what it zeroes,
afterwards, is its own Go copy. And a transfer abandoned part way is
dropped unzeroed. That is 53.

**After v0.23.4: satisfactory (53).** Each INCR piece Xlib read is
zeroed before it is freed now, and the growth is as it was.
`TestItem49ALongPasteLeavesNothingItOutgrew` and
`TestItem53X11INCRLeavesNoPieces`. What a paste that gave up waiting
keeps is 56.

## Found in the plain-language pass

A person setting up Firefox got a plan in a text view two rows tall, its
important line cut off, with "odd stacked arrows" beside it: ▲ at the
top, ▲▼ squeezed at the foot. They are Plastik's three step buttons,
which is right for the look; what is wrong is what a short bar does with
them, and what the text does beside it.

### 50. A short text view's scroll bar is squeezed, and its lines run under it

- **Today** (`widgets/textarea.go`, `vparts`, `wrapWidth`;
  `style/engine.go`, `ScrollGeometry`). In the default look (Plastik, and
  Keramik and KDE 2 too: `ArrowsTripleEnd`):
  - a `TextArea`'s vertical bar is as long as its rows, inside the
    field's padding: 47 pixels for `MinRows = 2` at 1x. `ScrollGeometry`
    wants three buttons of 16 and a track; short of that it shrinks the
    buttons (`a = (along-8)/buttons`) to 13 each, leaving a track of 8,
    shorter than the look's smallest thumb (20). The thumb is clamped to
    the track, so it fills it, and it is in the same place at every
    offset (`lo+(span-th)*(offset/maxOff)` with `span == th`): the bar
    says neither that there is more nor where the view is, and the thumb
    cannot be dragged. What is left are three small arrows, one apart
    from the other two, which is what the person saw;
  - the lines wrap to the field's whole inner width (`wrapWidth` is
    `inner().Dx()`), and the bar is painted over the field's right edge,
    so the end of every full line runs under the bar: "io.gith" and the
    rest of the name hidden;
  - and a word longer than the line (a path) is broken wherever the line
    ends (`lastWrap` breaks at spaces and tabs only), here in the middle
    of a file name. `style.Font.Wrap`, which labels use, does the same.
  A minimal reproduction, headless: a `NewMonoTextView` of three lines of
  text, `MinRows = 2`, in a window of the Plastik look
  (`style.LoadTheme("plastik")`), drawn with `WritePNG`.
- **Workaround.** The manager shows no text in a small box: a plan's
  lines, a report and a key are a `detailText` of its own
  (`gui/svmanager/plain.go`), as tall as its lines in a dialog that
  scrolls as a whole, wrapped at spaces and, in a word too long for the
  line, after a path separator; a plan's lines are folded under "Show
  details" below its summary in plain words. The TUI was never affected.
- **Proposal.** Give a bar too short for its buttons and its smallest
  thumb fewer buttons (one at each end, then none), as Qt's styles do,
  and hide a thumb that cannot move rather than fill the track with it;
  let a `TextArea` that shows its bar wrap to the width the bar leaves;
  and break a word too long for a line after a `/`, `\`, `-` or `.`
  before breaking it anywhere, in `lastWrap` and `Font.Wrap` alike.
- **Done when:** a two-row text view in Plastik shows a bar whose thumb
  moves with the text (or no bar's buttons it cannot fit), no text under
  it, and a path broken after a separator.
  `TestItem50AShortTextViewsScrollBar` pins today's behaviour: the
  squeezed buttons, the thumb in one place at both ends, and a line under
  the bar.

**After v0.23.3: unchanged.** v0.23.3 touches `TextArea` only for
`OnInput` (eb7a52f), and `ScrollGeometry`, `vparts`, `wrapWidth` and
`lastWrap` not at all; `TestItem50AShortTextViewsScrollBar` still pins
it, and `detailText` stays.

**Closed in 0.23.4** (the release notes, verbatim): **A short scroll bar gave up its track instead of its buttons.** Three 12.7-pixel arrows in the 47-pixel bar of a two-row text view left a track of 8, shorter than that look's smallest thumb — so the thumb was clamped to the track, filled it, stood in the same place at every offset and could not be dragged. It drops the buttons now, as Qt's styles do: three, then one at each end, then none. A bar that is only a track still says where the view is and still pages when it is clicked. A track too short for the look's own smallest thumb shows no thumb at all, which is a truer answer than one that cannot move. **Lines wrapped under the bar.** They wrapped to the field's whole inner width while the bar was painted over its right edge, so the end of every full line ran underneath with no way to scroll it clear. `TextArea` has a view box now, as `ScrollView` does, and the wrap, both max-scrolls, the clamp, the bars' own viewport lengths and the page keys all go through it. **A path broke in the middle of a file name.** A word longer than the line is broken after the last `/`, `\`, `-` or `.` it has passed — `style.CanBreakAfter`, shared by `Font.Wrap` and `TextArea` so the rule cannot drift between them. A space still wins, and a word with none of those is still broken anywhere, because something has to give.

**After v0.23.4: satisfactory; `detailText` stays, by choice.** All
three hold, read and run. `ScrollGeometry` gives up the middle button,
then both, before it shrinks one, and draws no thumb in a track shorter
than the look's smallest: the two-row Plastik view of the reproduction
has a bar of no buttons whose thumb moves from top to end. `TextArea`
wraps to `viewW`, the inner width less the bar where there is one,
settled by one measurement at the full width (narrowing only pushes
lines down), and every scroll length goes through the same box; a
`SecretArea` is not a `TextArea` and is untouched. And both wrappers
break a long word after its last separator. `detailText` was the
workaround and is kept for what it does better in a dialog: a plan's
lines as tall as they are, in a dialog that scrolls as a whole, rather
than a box to scroll inside a box. Its own rule for a long word prefers
a slash to a dot, which suits a path; changing it for the toolkit's
would be churn. `TestItem50AShortTextViewKeepsItsBar`.

## Found in the audit of v0.23.3

Reading the fixes through to the backends, against the needs as stated,
and the release notes against the code, found five things: one in each of
the three fixes that hold as far as they go (12, 48, 49), one in the
piece that closes 46, and one in how v0.23.3 ends a Wayland copy, which
with XWayland beside the compositor likely leaves a secret on the
clipboard with nothing left to clear it.

### 51. Caps Lock is asked of a Wayland window before the compositor has said

- **Today** (`app/lockkeys.go`, `Window.LockKeys`;
  `platform/wayland_locks_linux.go`; `platform/wayland_linux.go`,
  `uitkWlKeyEnter`, `uitkWlKeyMods`). v0.23.3 lets a Wayland surface be
  asked (12), and it answers from `c.mods`, the state the compositor's
  last `wl_keyboard.modifiers` left. But:
  - the window is asked when its content is first laid out and focused:
    a `SecretField` as it takes the focus (`FocusGained`), secretvault's
    Caps Lock line when it is first measured. On Wayland that is before
    the window is mapped, so before the compositor sends `enter` and,
    right after it, the modifiers. A program's first window (always, for
    `secretvault-gui-prompt`) is asked on a connection that has had no
    modifiers yet, and is answered off;
  - then the modifiers come: `uitkWlKeyMods` updates `c.mods` and pushes
    nothing, and the `EventFocusIn` that `enter` pushed reaches the
    window, which (rightly, since 285b6b7) notes no lock state from it,
    and asks nothing, nor does the repaint it causes. No watcher is told
    until the first key, or a pointer event over the window: a window
    that maps under the pointer gets a pointer enter carrying `c.mods`,
    which tells the watchers if the keyboard's modifiers came first, and
    fixes the state as off if they did not;
  - the same leaves a window that comes back into focus with what it knew
    before, on every backend, when the lock was changed in another
    program meanwhile (12, after v0.23.1): there is a surface to ask now,
    and nothing asks it at a focus-in.
- **Proposal.** At a focus-in, the window asks its `LockKeysSurface`
  again and notes the answer as it notes an event's, telling the watchers
  if it differs, on every backend. On Wayland that needs the focus-in to
  reach the window after the modifiers that follow `enter`; or the
  backend pushes a modifiers-only event from `uitkWlKeyMods` to the
  surface that has the keyboard, and the window notes the lock keys from
  it.
- **Done when:** on Wayland a prompt opened with Caps Lock on says so
  before the first key, and a window that comes back into focus after the
  lock was changed elsewhere says so at once.
  `TestItem51CapsLockBeforeTheCompositorHasSaid` pins today's behaviour
  headless: the keyboard off when the field takes the focus, on by the
  focus-in, and the field and the watchers told nothing.

**Closed in 0.23.4** (the commit, 70f4d6e, verbatim, where the release notes say less): secretvault #51, the rest of #12. v0.23.3 let a Wayland surface be asked for the lock keys, and nothing asked it at the one moment that matters. A window is asked when its content is first laid out — a SecretField as it takes the focus — and on Wayland that is before the surface is mapped, so before the compositor has sent enter and, right after it, the modifiers. The first window of a program, which for a passphrase prompt is every window, was asked on a connection that had heard nothing and was answered "off"; then the modifiers arrived, updated the connection, and told no one. Nothing more until the first keystroke — and the warning exists for the first passphrase, not the second. platform.EventLockKeys carries it in: the window system saying what the locks are, rather than a keystroke implying it. Wayland sends it from uitkWlKeyMods to the focused surface. (And the release notes, verbatim:) **The lock keys are asked again at a focus-in**, on the backends that can be asked. They belong to the user's keyboard and not to this window, so Caps Lock turned on while another program had the focus is on when the focus comes back — and a prompt went on showing what it knew when it last saw a key.

**After v0.23.4: satisfactory.** Both halves hold. `uitkWlKeyMods` keeps
the compositor's modifiers as before and now pushes `EventLockKeys` to
the surface that has the keyboard; the window notes the lock state from
it as from a key, and tells the field and every watcher. `enter` and the
modifiers that follow it are dispatched in one pump before the window
reads its queue, so the focus-in finds them already kept, and if they
ever came in two reads the `EventLockKeys` that follows would put a
stale answer right; the protocol sends the modifiers after every
`enter`. And at every focus-in the window asks its surface again
(`refreshLockKeys`), so a lock changed in another program is said at
once. The commit that does this (e535eb1) says Wayland and AppKit leave
`LockKeysSurface` out and are not asked, since one "can only repeat its
last answer"; the code does not do that, both surfaces are as v0.23.3
made them, and both are asked. No harm comes of it: AppKit's answer is
the keyboard's own, and Wayland's is the compositor's last word, which
the modifiers after `enter` bring up to date before or just after the
focus-in is read. The prompt (`secretvault-gui-prompt`) and the
manager's passphrase question need no change: `secretui.CapsLock` asks
its window at its first layout and is a watcher after, and their tests
now open a dialog with the keyboard off and see the line come with the
window system's word, before any key. `TestItem51AWindowLearnsTheLocksItOpenedIn`.

### 52. Another program's copy leaves a secret held on X11, Windows and macOS

- **Today** (`platform/clipboard_secret.go`, `ClipboardGetSecret`;
  `platform/x11_linux.go`, `handleSelClear`;
  `clipboard_secret_windows.go`, `clipboard_secret_darwin.go`). v0.23.3
  ends a held secret at the program's own next copy everywhere, and at
  another program's on Wayland (`cancelled`). On the other three nothing
  ends it when another program copies:
  - X11's `SelectionClear` zeroes what the owner served
    (`wipeClipLocked`) and leaves the `SecretClip` held, its own copy of
    the passphrase in it;
  - Windows and macOS are not told and not asked: `ClipboardGetSecret`
    serves the held secret before it reads the clipboard, and
    `ClipboardHoldsSecret` reads only the toolkit's own state.

  So for the rest of its time (30 seconds in the manager) a paste into a
  `SecretField` or `SecretArea` takes the old secret, not what was
  copied: copy a passphrase from another program into a new vault's
  "Passphrase" and "Repeat", and the vault is made with the item copied
  before, a passphrase nobody meant to set. `ClipboardHoldsSecret` says a
  secret is held, and the passphrase stays in the heap until the timeout.
  The clear at the timeout leaves the other program's copy alone (48).
- **Workaround.** On Linux and the BSDs the manager copies through the
  CLI (`secretvault __clip`): it holds no `SecretClip`, so a paste reads
  the clipboard. On Windows and macOS it copies through uitoolkit, and
  this stands.
- **Proposal.** X11's `handleSelClear` ends the held secret, as Wayland's
  `cancelled` does, when the CLIPBOARD selection it served is taken; on
  Windows and macOS, `ClipboardGetSecret` and `ClipboardHoldsSecret` take
  the held secret as the clipboard's only while the sequence number or
  `changeCount` is still the one noted at the copy, and end it otherwise.
- **Done when:** after another program's copy, a secret paste reads that
  copy, `ClipboardHoldsSecret` is false and the held bytes are zeroed, on
  X11, Windows and macOS. `TestItem52AnotherCopyEndsASecretOnlyOnWayland`
  pins today's code.

**Closed in 0.23.4** (the release notes, verbatim): **Another program's copy left a secret held.** On X11 the bytes the owner served were zeroed and the `SecretClip` was left held with its own copy of the passphrase in it; on Windows and macOS nothing was asked at all. So for the rest of its time a paste into a `SecretField` took the old secret — copy a passphrase from another program into a new vault's "Passphrase" and "Repeat", and the vault was made with the item copied before. The two platform shapes are answered differently because they are different: X11 is *told* it has lost a selection, Windows and macOS say nothing and are asked.

**After v0.23.4: satisfactory; a failed Windows copy is 60.** X11's
`handleSelClear` reads whether the `CLIPBOARD` it lost carried a secret
before it wipes what it served, and then ends the held copy
(`endLostSecret`), on a goroutine since it holds `x11Mu` and the
application's `OnCleared` runs in it, unless the Wayland selection still
serves it (55); a clear for an ownership already replaced is told apart
by asking the server who owns the selection. Windows and macOS are asked
at every secret paste and every `ClipboardHoldsSecret`
(`heldSecretIfStillOnTheClipboard`): a sequence number or `changeCount`
that moved since the copy ends the held one, wiped, said gone and not
served, and the paste reads the clipboard; both numbers are atomic now.
Linux answers that question from what it was told, so always yes there,
and so does the in-process buffer. So a new vault's "Passphrase" and
"Repeat", pasted from another program, take what that program copied,
on all four. Where no paste asks, on Windows and macOS the bytes go at
the timeout, as the proposal had it. That the copy a loss ends is the
one held when it is handled, not the one it carried, is 57.
`TestItem52AnotherCopyEndsAHeldSecret` reads all of it; "another
program" is nothing a headless test has.

### 53. X11's INCR transfer still leaves pieces of a long paste

- **Today** (`platform/x11_linux.go`, `handleProperty`,
  `readSelection`). v0.23.3 grows X11's INCR buffer without leaving what
  it outgrew (49), and its notes say "X11 zeroes each INCR piece before
  `XFree`". It does not:
  - `handleProperty` copies each piece out of Xlib's buffer with
    `C.GoBytes` and frees that buffer at once with `C.ui_xfree`,
    unzeroed; the loop added after it zeroes `piece`, the Go copy, once
    it has been appended. Each piece Xlib read, a part of the private
    key, is left in freed memory for whatever gets that allocation next:
    what 42 fixed for the one-shot path, where `handleSelNotify` zeroes
    the property through a volatile pointer before `XFree`;
  - a transfer that does not finish within `readSelection`'s deadline
    stays in `incrRecv`, the part it read in `incrRecv.buf`, until the
    next paste resets it (`c.incrRecv = incrRecvState{}`, and
    `handleSelNotify` the same as the next INCR transfer starts) without
    zeroing it; and if its last pieces come after the deadline, the whole
    lands in `pasteData`, which nothing takes, until the next paste wipes
    it.
- **Proposal.** Append the piece from Xlib's buffer in place and zero
  that buffer before `XFree`, as `handleSelNotify` does; zero
  `incrRecv.buf` wherever the transfer is reset or given up, and drop a
  transfer that completes after its paste stopped waiting.
- **Done when:** no piece of an INCR paste is freed unzeroed, and a
  transfer given up leaves nothing. `TestItem53X11INCRLeavesItsPieces`
  pins today's code.

**Closed in 0.23.4** (the release notes, verbatim): **A long paste left pieces of itself.** Every piece of an INCR transfer was copied out of Xlib's buffer and that buffer freed unzeroed — the thing 0.23.3's notes said it had fixed and had not. A transfer whose last pieces arrive after the paste gave up waiting is now let go rather than kept where nothing would ever read it.

**After v0.23.4: satisfactory; what a paste that gave up waiting keeps
is 56.** This time the notes and the code agree. `handleProperty`
zeroes Xlib's buffer through the volatile helper before `XFree`, and the
Go copy once it is appended; a transfer that completes goes through
`finishINCRLocked`, which makes it the paste only while a reader is
waiting and zeroes and drops the transfer's buffer either way; and every
paste starts by zeroing whatever an earlier transfer left
(`dropINCRLocked`), where it used to reset it unzeroed. The commit's "it
zeroes it wherever the transfer is reset or given up" is wider than the
code: a transfer is not dropped at its paste's deadline, but read to the
end so that its owner is not left hanging, so one whose owner stops part
way keeps what it read until the next paste, and a drop's INCR transfer
resets it unzeroed. That, with a one-shot reply that comes late, is 56.
`TestItem53X11INCRLeavesNoPieces`.

### 54. `DialogContent` squeezes a foot that holds a `ButtonBox`

- **Today** (`widgets/dialog.go`, `DialogContent`). v0.23.3 gives the
  foot's whole width to "one action that lays itself out" (46), and in
  the code that is `actions[0].(*ButtonBox)` and nothing else. Anything
  else goes in a row justified to the end, at its natural width. A dialog whose foot holds a `ButtonBox` beside something
  of its own (each of secretvault's passphrase questions says "Caps Lock
  is on" at the left of its foot, beside a flexed `ButtonBox`) loses what
  46 asked for: under every look Back (`RoleHelp`) is no longer at the far
  left, a destructive button under Mac and GNOME looks no longer apart,
  and the line is pushed up against the buttons.
- **Workaround.** The manager builds `DialogContent`'s arrangement
  itself (`showDialog`), its foot at the column's full width.
- **Proposal.** Give a lone action the foot's whole width whatever it
  is; an application that wants buttons at their natural widths at the
  right passes them as several actions. Or `DialogContent(body, foot)`,
  as 46 proposed.
- **Done when:** a foot of a label and a flexed `ButtonBox`, handed to
  `DialogContent` alone, is as wide as the dialog.
  `TestItem54DialogContentSqueezesAFootThatHoldsAButtonBox` pins today's
  behaviour.

**Closed in 0.23.4** (the release notes, verbatim): `DialogContentFoot(body, foot)` for a foot the application lays out itself. A *lone* action is still natural-width at the right: stretching it would make every one-button dialog look like a phone's, and the test that says so fails on exactly that change. (And the commit, 70f4d6e, verbatim:) secretvault #54, which is 0.23.3's DialogContent being too narrow. It gave the foot's width to a ButtonBox only when the box was handed over alone, and a dialog's foot often holds a word beside its buttons — "Caps Lock is on", a progress note. That is the foot that most needs the box to lay itself out, since its left-hand group (Help, and a destructive button under Mac and GNOME looks) stays apart only if it has the room.

**After v0.23.4: satisfactory, by the proposal's other way; the
manager's dialogs are `DialogContentFoot`.** A lone action that is not a
`ButtonBox` is still put at its natural width, as the maintainers
explain, and the foot handed over as a foot (the proposal's
`DialogContent(body, foot)`) is `DialogContentFoot`: one component, at
the dialog's whole width. And `DialogContent` itself now gives a
`ButtonBox` the width wherever it is among the actions, with whatever
else there is to its left. Both keep Back at the far left and Cancel at
the right, a label beside them. So `showDialog` no longer builds the
arrangement itself: it is `DialogContentFoot` of the body and its foot,
inside the dialog's fixed width (a scroll view still takes all the width
it is offered), for every dialog of the manager's, the passphrase
questions with "Caps Lock is on" beside their buttons, the import's Back
and the plain-language plans alike. The gap and padding are the
toolkit's now (12 and 4, where the manager had 16 and 6), which the
screenshots show and nothing else notices. `TestItem54ADialogsFootKeepsItsRoom`.

### 55. The Wayland end of a secret copy

- **Today** (`platform/clipboard_secret_linux.go`,
  `clipboardNativeSetSecret` and `clipboardNativeClear`;
  `platform/wayland_linux.go`, `wlClipSetSel`, `uitkWlDataCancelled`;
  `platform/clipboard_secret.go`, `forgetHeldSecret`). Three things about the Wayland end of a
  copy, two that v0.23.3 brought and one that 48 asked for and v0.23.3
  left:
  - where there is an X server beside the compositor (XWayland, which
    GNOME and KDE run by default, and `DISPLAY` set for every program),
    a secret copy takes X11's CLIPBOARD as well as the Wayland selection
    (`clipboardNativeSetSecret` does both). A compositor that carries an
    X11 owner's copy over to Wayland (Mutter does, and KWin; whether a
    compositor does it for a client none of whose windows has the focus
    is its own rule) sets the Wayland selection to it, which cancels the
    program's own source just after the copy. Since v0.23.3 a cancel
    ends the held secret: it is wiped in the toolkit, its timer stopped
    and `OnCleared` told it has gone, at once, while the program's X11
    owner goes on serving the passphrase to every paste, through the
    compositor's bridge too. Nothing clears it then: not the timeout,
    which is stopped, nor the quit, where `ClipboardClearSecret` finds
    nothing held; it stays until something else is copied or the program
    ends, and the manager can sit in the tray for days. Before v0.23.3
    the cancel only dropped the Wayland cache, and the timer cleared both.
    This is read from the code; it was not run on a compositor here;
  - without XWayland too: `uitkWlDataCancelled` ends the held secret on a
    goroutine of its own (`go forgetHeldSecret()`), and
    `forgetHeldSecret` ends whatever secret is held when that goroutine
    runs, with no word of which copy the cancelled source carried. A
    secret copied in between (the cancel and a copy of the program's in
    one burst of events, or the goroutine late on a loaded machine) is
    the one ended, as above, while the Wayland cache still serves it. The
    window is narrow; what it lets happen is what 7 exists to prevent;
  - the clear at a secret's time, its vault's lock or the quit, while the
    clipboard is still that copy, is `wlClipSet("")`: an ordinary copy of
    nothing, which takes CLIPBOARD with an empty offer this program goes
    on serving, and the primary selection too, from whoever has it by
    then. Something the person has selected in another program since is
    gone at the timeout. 48 proposed destroying the source that is still
    the selection.
- **Workaround.** As 52: on Linux the manager copies through the CLI,
  whose svclip takes one clipboard, clears by giving its selection up,
  and ends only its own copy.
- **Proposal.** On a Wayland session take the Wayland selection only,
  and leave X11's to the compositor's bridge (or end a copy only when
  neither selection still holds it); end only the copy whose source was
  cancelled (tie the `SecretClip` to its source, or to a generation, and
  end that one); and clear by destroying the data source that is still
  the selection, leaving the primary selection alone.
- **Done when:** on a Wayland desktop with XWayland, a secret copy is
  still held, and cleared, at its time; a copy made right after another
  program's is not ended by that program's cancel; and a Wayland clear
  leaves the primary selection as it is.
  `TestItem55TheWaylandEndOfASecretCopy` pins today's code.

**Closed in 0.23.4** (the release notes, verbatim): **A Wayland clear threw away the user's selection.** It was an ordinary copy of an empty string, which is still a copy: it took CLIPBOARD *and the primary selection* with an empty offer this program then went on serving, so a secret's timeout discarded whatever the person had selected somewhere else since. It gives up the selections this process owns and touches nothing else. (And the commit, 6e161a6, verbatim, where the release notes say nothing:) #55, which v0.23.3 introduced and which is worse than what it replaced. A secret copy takes X11's CLIPBOARD *and* the Wayland selection, because XWayland is running and DISPLAY is set — GNOME and KDE both do that by default. A compositor that bridges an X11 owner's copy to Wayland then sets the Wayland selection to it, cancelling this program's own source moments after the copy. v0.23.3 made a cancel end the held secret: wiped, timer stopped, OnCleared told it has gone — while the X11 owner went on serving the passphrase to every paste, with nothing left to clear it. Not the timeout, which was stopped; not the quit, which found nothing held. It stayed until something else was copied or the program ended, which for a password manager in a tray is days. Before v0.23.3 the timer survived the cancel and cleared both. A cancel now ends the held copy only when this process is not still serving the same secret on X11. And it ends the copy that was *on* that selection rather than whatever is held when the news arrives: the word reaches us on a goroutine, the program may have copied something else by then, and ending that instead is a passphrase the user just put there going quietly missing.

**After v0.23.4: satisfactory as asked; what is left is 57, 58 and
59.** The three parts:

- **XWayland.** The proposal's second way: a copy still takes both
  clipboards, and ends only when neither still serves it. A Wayland
  cancel leaves the held copy while the X11 owner still serves a secret
  (`x11StillServesTheSecret`), and X11's `SelectionClear` leaves it while
  the Wayland source still does (`wlStillServesTheSecret`, 52). Followed
  through the bridge both ways: the compositor taking X11 to serve the
  Wayland copy leaves it held for Wayland, the compositor taking Wayland
  for the X11 copy leaves it held for X11, and another program's copy,
  which the compositor carries to the other side, takes both and ends
  it. So on such a desktop a copy is held, and cleared at its time, from
  both. Read from the code, not run on a compositor here; which way the
  bridge goes is the compositor's.
- **The cancel race.** A cancel names the copy held when it is handled
  (`lost := heldSecret()`) and its goroutine ends only that one
  (`forgetHeldSecretIf`), so a copy made while the goroutine waits is no
  longer the one ended. On Wayland alone that closes it: the copy
  destroys the old source first, and a queued `cancelled` for a destroyed
  source is never dispatched. But the copy is held before it is on the
  clipboard, so a loss handled after that is pinned on it, which X11's
  own round trip inside a copy allows (57).
- **The clear.** `wlClipClear` destroys this program's own source and
  only then unsets the selection, and does the same for a primary source
  of its own; another program's is not touched. But the copy itself still
  unsets the primary selection, whoever holds it (58); and the clear
  runs on its timer's goroutine, against state the event loop changes
  without the lock, so a cancel it has not yet seen lets it unset the
  selection another program has just made (59).

`TestItem55TheWaylandEndOfASecretCopy`, and 57–59's.

## Found in the audit of v0.23.4

Reading the fixes through to the backends, against the needs as stated,
and the notes and commits against the code, found two things in what
v0.23.4 changed (56, 57) and three older ones every audit before this
one missed (58, 59, 60). All five are about the secret clipboard or a
pasted secret, all are narrow, and all are read from the code and not
run.

### 56. An X11 paste that gave up waiting keeps what arrives after it

- **Today** (`platform/x11_linux.go`, `readSelection`, `handleSelNotify`,
  `finishINCRLocked`, `closeLocked`; `platform/x11_dnd_linux.go`). A paste
  asks the owner and waits up to its deadline. What comes after it:
  - a one-shot reply is put in `pasteData` all the same:
    `handleSelNotify` does not ask `pasteWaiting`, which v0.23.4 added
    and only `finishINCRLocked` reads. Nor is a reply checked against what
    was asked for: `pasteWant` is written and never read, so a late reply
    to an earlier paste (of PRIMARY, say, or the ordinary text another
    field asked for) can be taken as the answer to a later secret paste;
  - an INCR transfer whose owner stops part way keeps what it read in
    `incrRecv.buf`: it is read to the end rather than dropped at the
    deadline, so that its owner is not left hanging, and one whose end
    never comes is never dropped; and a drop's INCR transfer starting
    meanwhile resets it without zeroing it (`x11_dnd_linux.go`).

  Both are zeroed by the next paste (`wipePasteLocked`, `dropINCRLocked`),
  which in a manager that sits in the tray can be days, and neither when
  the connection is closed (`closeLocked`). A slow owner is all it takes:
  another password manager, a terminal busy for a second. This is the
  reader every `SecretField` paste goes through, the manager's and the
  prompt's, whatever the manager copies with.
- **Workaround.** None.
- **Proposal.** Take a reply only while a paste is waiting for it, for
  the selection and target it asked (`pasteWant`), zeroing and dropping
  any other; at the deadline zero what an INCR transfer has read and go
  on reading its pieces into nothing; zero both where the connection is
  closed and where a drop's transfer takes the state over.
- **Done when:** a reply or a piece that arrives after its paste gave up
  is zeroed as it arrives, and never answers another paste.
  `TestItem56ALatePasteIsKeptUntilTheNext` pins today's code.

**Closed in 0.23.5** (the release notes, verbatim): A paste that gave up waiting **kept what arrived after it**. `handleSelNotify` never asked `pasteWaiting` — 0.23.4 added that flag for the INCR path and wired it only there — and `pasteWant` was written and never read. So a reply from a slow owner went into `pasteData` and only the *next* paste cleared it, which in a manager that lives in the tray is days; and a late answer about PRIMARY, or about another field's ordinary text, could be served as the answer to a secret paste. (And the commit, 716d552, verbatim, where the release notes say nothing:) The same for an INCR transfer: one still running when its paste gives up has what it read zeroed at once and reads the rest into nothing, rather than sitting on the start of a private key until some later paste replaced it. A drop's transfer taking the state over zeroes what was there first, and closing the connection lets go of both — until now nothing but the next paste ever did.

**After v0.23.6: satisfactory.** The notes and the code agree.
`handleSelNotify` asks first whether a paste is waiting and whether the
reply is about the selection it asked for (`pasteAskedFor`, which reads
`pasteWant` at last); a reply that is neither goes to
`discardSelNotify`, which reads it (an owner waits for its property to
be taken), zeroes Xlib's buffer through the volatile helper before
`XFree`, and puts nothing in `pasteData`; an INCR one becomes a transfer
marked `discard` (where none is running), whose pieces `handleProperty` zeroes as they come, let
go at its end. `readSelection` stops waiting on its way out
(`endPasteWaitLocked`: `pasteWaiting` false, `pasteWant` none), and a
transfer still running then has what it read zeroed at once and the
rest read into nothing (`discardINCRLocked`). A drop's INCR transfer
zeroes what a paste's had read before it takes the state over, and at
its own end (`dropINCRLocked` both times); and closing the connection
wipes `pasteData` and the transfer. The target is checked loosely, on
purpose (UTF8_STRING, STRING or none: a paste asks for both, and an
owner may echo either), the selection strictly: a late reply to an
earlier paste of the same selection can still answer the next one,
which is that selection's own text a moment older; PRIMARY's cannot.
secretvault had no workaround, so nothing comes out; every
`SecretField` paste, the manager's and the prompt's, goes through this
reader. uitoolkit's own
`TestAPasteThatGaveUpDoesNotKeepWhatArrivesAfterIt` runs it against a
slow second client (`clipown`'s `SLOW_MS`); here it is read, not run.
`TestItem56ALatePasteIsDropped`.

### 57. A loss still on its way is pinned on the copy just made

- **Today** (`platform/clipboard_secret.go`, `ClipboardSetSecret`;
  `platform/wayland_linux.go`, `uitkWlDataCancelled`;
  `platform/x11_linux.go`, `endLostSecret`, `setClipboardSelBytes`).
  v0.23.4 ends the copy a loss was about rather than whatever is held
  when its goroutine runs (55). But it names that copy when the loss is
  *handled* (`lost := heldSecret()`), and `ClipboardSetSecret` makes a new
  copy the held one before it puts it on the clipboard. No backend
  records which copy it serves. So a loss of the last copy handled after
  that line is pinned on the new one:
  - on X11 the new copy's own round trip (`freshSelectionTimeLocked`, new
    in v0.23.4) drains the queue, so a `SelectionClear` from another
    program's copy made just before is handled inside the new copy: it
    reads the old copy's `clipSecret`, names the new copy, finds no
    Wayland source to keep it (on X11 alone there is none), and ends it:
    wiped, its timer stopped, `OnCleared` told it has gone, while the
    copy goes on to take the clipboard with it (or with what the wipe has
    left of it, the two unsynchronised) and serves it until something
    else is copied or the program quits. In a window loop such a clear is
    handled before the input that starts a copy, so it takes another
    program copying within milliseconds of this one;
  - with XWayland beside a compositor the Wayland source is set first,
    and the mirror check (`wlStillServesTheSecret`) rescues the new copy,
    but for goroutine scheduling going wrong: the X11 side is handled on
    the selection service's goroutine, beside the UI's.

  On Wayland alone it does not happen: the copy destroys the old source,
  and a queued `cancelled` for it is never dispatched.
- **Workaround.** On Linux the manager copies through the CLI: one copy,
  one process, and nothing to mistake it for.
- **Proposal.** Name the copy when the selection is taken: each owner
  keeps the `SecretClip` (or a generation) it serves, set as it takes the
  selection, and a loss ends that one; or make a copy the held one only
  once it is on the clipboard.
- **Done when:** a `SelectionClear` or a cancel for an earlier copy,
  handled at any point of a new copy, leaves the new one held and
  cleared at its time. `TestItem57ALossOnItsWayIsPinnedOnTheNewCopy`
  pins today's code.

**Closed in 0.23.5** (the release notes, verbatim): **A loss still on its way was pinned on the copy just made.** 0.23.4 made a lost selection end the copy it was about rather than whatever is held — but it named that copy when the news is *handled*, and the fresh selection timestamp 0.23.4 also added is a round trip whose drain dispatches a `SelectionClear` from another program's copy made milliseconds earlier. Inside the new copy's own call. The password manager said "cleared" the instant the user copied, with the passphrase still on the clipboard. Nothing is held for the length of a copy now.

**After v0.23.6: satisfactory, by the proposal's second way; a Wayland
cancel that names nothing is left, narrow.** `ClipboardSetSecret` lets
the copy it replaces go first (nothing held; the old copy wiped, its
timer stopped, said gone), puts the new one on the clipboard, and makes
it the held copy only once the platform has taken it; a refused one is
never held (60). So a `SelectionClear` for the old copy, dispatched by
X11's own round trip inside the new copy, finds nothing held, and
`endLostSecret` returns without ending anything: the copy it was about
has been let go, and the one it was not about is not held yet. That is
the whole of it on X11 alone; with XWayland the X11 side is the same,
and the mirror check as before. The backends still name a copy as its
loss is handled rather than record which they serve; the gap between
the two is now one in which nothing is held. What is left, read from
the code: Wayland's cancel names what is held as it is handled
(`lost := heldSecret()`), and where that is nothing it hands
`forgetHeldSecretIf` a nil, which means "whichever is held" when its
goroutine runs. X11's `endLostSecret` returns on nil; the cancel does
not. So a cancel handled while nothing is held (an ordinary copy's
source cancelled, or, where no window is and the clipboard service
dispatches, one during a secret copy) ends a secret copied before its
goroutine runs, while the Wayland source goes on serving it. Goroutine
scheduling, as 55's second point was; the nil check `endLostSecret`
makes would close it in the cancel too. The manager copies through uitoolkit on Linux now (2026-10-12), so it
can reach it: 85. uitoolkit's own `TestALossOnItsWayIsNotPinnedOnTheCopyJustMade`
runs the X11 case on a display.
`TestItem57ACopyIsHeldOnlyOnceItIsOnTheClipboard`.

### 58. A Wayland secret copy unsets the primary selection, whoever holds it

- **Today** (`platform/wayland_linux.go`, `wlClipSetSel`). A secret copy
  takes CLIPBOARD and not the primary selection, as 7 asked. But it also
  sets the primary selection to nothing whenever there is a primary
  selection device, whoever holds it; and `set_selection` with a null
  source unsets whichever client's selection it is, as the toolkit's own
  comment on `wlClipClear` says. The copy button's click gives a fresh
  serial, so a compositor that checks it accepts it. Whatever the person
  had selected in another program goes as they copy a password, and a
  middle click pastes nothing. The comment's reason, that an application
  must not be left believing it copied a password with an old selection
  of its own behind it, is about a selection this program owns, which
  X11 gives up only when it does own it (`setClipboardSelBytes`); svclip
  never touches it. As in v0.23.3: v0.23.4 changed only what the cache
  says afterwards. It takes no secret anywhere, and costs the person a
  selection.
- **Workaround.** On Linux the manager copies through the CLI.
- **Proposal.** Give up a primary source of this program's own, as the
  clear now does, and leave anyone else's alone.
- **Done when:** a Wayland secret copy leaves another program's primary
  selection as it was.
  `TestItem58AWaylandSecretCopyUnsetsThePrimarySelection` pins today's
  code.

**Closed in 0.23.5** (the release notes, verbatim): **A Wayland secret copy unset whoever held the primary selection.** It called `set_selection(null)` whenever a primary device existed at all, and that unsets whichever client's selection it is — so copying a password threw away whatever the person had selected in another program, and the middle click after it pasted nothing. The clear had been guarded against exactly this since 0.23.3; the copy path never was.

**After v0.23.6: satisfactory.** For a secret, `wlClipSetSel` destroys
a primary source of this program's own and only then unsets the primary
selection, under the same guard as `wlClipClear` (55); anyone else's is
not touched. Its cache of the primary selection goes either way, so a
read of it falls through to whoever holds it. One thing in the notes is
off: the clear's guard is 0.23.4's (6e161a6); 0.23.3's clear was a copy
of nothing. With X11, which gives PRIMARY up only when it owns it, no
secret copy on any backend touches a selection that is not this
program's. uitoolkit's own
`TestAWaylandSecretCopyLeavesAnotherProgramsPrimarySelectionAlone` runs
it on a compositor, with a window for the serial.
`TestItem58AWaylandSecretCopyLeavesThePrimarySelectionAlone`.

### 59. A secret's clear runs on its timer's goroutine, against Wayland state the event loop changes unlocked

- **Today** (`platform/clipboard_secret.go`, `ClipboardSetSecret`;
  `platform/wayland_linux.go`, `wlClipClear`, `uitkWlDataCancelled`,
  `uitkWlDataSend`, `wlSurface.Poll`). A secret's timeout is
  `time.AfterFunc(clearAfter, c.Clear)`, so the clear runs on a goroutine
  of its own, and `wlClipClear` takes `wlMu`. But the Wayland callbacks
  run from the dispatch in `wlSurface.Poll` and `Wait`, and in the
  clipboard service, with no `wlMu` held, and change or read the same
  fields: a source cancelled destroys `c.dataSrc` and wipes `c.clip`, a
  paste served writes `c.clip`'s bytes to the reader. If the two meet,
  both can destroy the same data source (a double proxy destroy, which
  can bring the program down), the cache can be zeroed while it is being
  written, and a clear that has not yet seen a cancel already in hand
  unsets the selection another program has just made. The mirror checks
  of 55 read the same fields across goroutines too. Older than v0.23.4:
  v0.23.3's clear was `wlClipSet("")` from the same timer. Narrow, and a
  crash or a lost selection rather than a leak.
- **Workaround.** On Linux the manager copies through the CLI.
- **Proposal.** Run a secret's clear on the event loop's goroutine (post
  it to the loop, as a toolkit's other cross-goroutine work is), or hold
  `wlMu` across the callbacks that touch the selection.
- **Done when:** nothing the Wayland selection's callbacks touch is
  touched from another goroutine without the lock they hold.
  `TestItem59ASecretsClearRacesTheWaylandEventLoop` pins today's code.

**Closed in 0.23.5** (the release notes, verbatim): **A secret's clear ran on its timer's goroutine**, against Wayland state the event loop mutates without that lock: two destroys of one data source, a cache zeroed while it was being written. It goes to the loop now — `app.Run` lends the platform layer its `Post` for as long as it is running, and only that long, because posted work nothing will ever drain would be a passphrase left on the clipboard.

**After v0.23.6: satisfactory, by the proposal's first way.** A
secret's timer hands its clear to `onLoop` (`platform/looppost.go`),
which posts it to the UI goroutine through the poster `app.Run` lends
the platform (`SetLoopPoster(a.Post)`) from the moment it loops until it
returns, and runs it on the timer's goroutine only where no loop runs (a
headless tool, a test, a program that has not called `Run`). That is the
goroutine that dispatches the Wayland callbacks of a program with a
window, so a clear and a cancel or a paste being served no longer meet:
no double destroy, no cache zeroed as it is written, and a cancel being
dispatched is done before the clear looks or after it, never during
(one still on the wire is the protocol's own window, which no client
closes). Where no window is, the clipboard service dispatches them on a
goroutine of its own, and `wlRetain` stops it before the clear goes on,
as before. A clear posted as the loop stops is left in its queue, but the
quit's `ClipboardClearSecret`, after the loop, clears a copy still held.
Holding `wlMu` across the callbacks, the other way, the commit declines:
one of them writes to a reader's pipe. Left, and harmless: X11's mirror
check (`wlStillServesTheSecret`) reads the Wayland source and its secret
flag under `wlMu` from the X11 side's goroutine, while the cancel writes
them without it; the cancel only ever takes them from serving to not, so
a stale read says "still serving" and keeps the copy, which the cancel's
own check then ends. uitoolkit's own
`TestASecretsTimeoutIsRunOnTheLoopAndNotItsTimer` and
`TestWithNoLoopASecretsTimeoutStillClearsItself` pass here, displayless.
`TestItem59ASecretsClearRunsOnTheLoop`.

### 60. A Windows secret copy that fails is taken for one that was made

- **Today** (`platform/clipboard_secret_windows.go`,
  `clipboardNativeSetSecret`; `platform/clipboard_windows.go`,
  `withClipboard`). The copy notes the clipboard's sequence number in a
  `defer`, whether or not it was made: the clipboard can be held open by
  another program for all of `withClipboard`'s tries (twelve, 20 ms
  apart), and `SetClipboardData` can refuse the block after
  `EmptyClipboard` has already emptied the clipboard. Either way:
  - the program is told nothing and says it copied; a `SecretField`
    paste is served the held secret while the clipboard holds what was
    there (or nothing), and `ClipboardHoldsSecret` says one is held;
  - the clear at its time finds the number unchanged and empties the
    clipboard, which holds what the person had there: the one thing 48's
    check exists to prevent;
  - where `SetClipboardData` refuses the block, the block, which holds
    the passphrase as UTF-16, is freed (`GlobalFree`) without being
    zeroed.

  As in v0.23.3 (one of its smaller edges, under 7); worse since 52, as
  the held copy is now trusted wherever the number has not moved.
- **Workaround.** None: on Windows the manager copies through uitoolkit.
- **Proposal.** Note the sequence number only when the copy was made,
  and end the held copy (wiped, said gone) when it was not, so the
  program can say so; zero a refused block before it is freed.
- **Done when:** a copy that fails ends its `SecretClip` at once, its
  clear leaves the clipboard alone, and no block of the passphrase is
  freed unzeroed. `TestItem60AFailedWindowsCopyIsTakenForOne` pins today's
  code.

**Closed in 0.23.5** (the release notes, verbatim): **A copy the platform refused was taken for one that was made.** `clipboardNativeSetSecret` returned nothing, so Windows noted the clipboard sequence number and macOS the pasteboard changeCount either way — and macOS threw away all three `setString:forType:` results, which is the same defect as the drag types below. The seam reports on every backend now and a refused copy comes back already cleared. "There is no window system here" stays a *success*: the in-memory copy is the copy then, which every displayless test depends on. (And the commit, d635a4b, verbatim, where the release notes say nothing:) A refused block, which holds the passphrase as UTF-16, was also GlobalFree'd without being zeroed.

**After v0.23.6: satisfactory, macOS too; a busy Windows clipboard now
keeps the copy before it, narrow.** `clipboardNativeSetSecret` says
whether the copy was made, on every backend: Windows whether
`withClipboard` got the clipboard and `SetClipboardData` took the block,
macOS whether the string went on the pasteboard (the two hints stay
advisory), X11 whether the server made this process the owner, Wayland
whether a source was made; no window system at all is a copy made.
`ClipboardSetSecret` hands a refused one back already cleared: wiped,
never held, no timer, `Cleared` true and `OnCleared` called at once.
Windows notes the sequence number, and macOS the `changeCount`, only for
a copy that was made, so no clear empties what the person had there on
the strength of a copy that did not happen; and a block
`SetClipboardData` refused is zeroed under `GlobalLock` before
`GlobalFree` (`winGlobalWipeFree`). The manager, on Windows and macOS,
then says the copy is on the clipboard and at once that it is no longer
(`copyValue`) said the copy was on the clipboard and at once that it was
no longer; it asks `Cleared()` after the copy now, and says it could not
copy.
What is left, read from the code and new with 57's fix: the copy being
replaced is let go before the new one is tried, so where another program
holds the Windows clipboard open for all of `withClipboard`'s tries, and
nothing on it changes, the program's previous secret copy stays there
with its timer stopped and nothing held: not cleared at its time, nor at
its vault's lock (the manager clears the refused copy, which is not
held), nor at the quit (`ClipboardClearSecret` finds nothing held). In
v0.23.4 the failed copy's own clear emptied it, by the defect this item
was about. Where `SetClipboardData` refuses after `EmptyClipboard` the
old copy has gone with it, and X11, Wayland and macOS have given theirs
up before they can be refused. On X11 a refused ownership also leaves
the owner's copy of the new secret (`clipData`) unwiped until the next
copy or clear. Both narrow, and 86; ending the copy being replaced only once the new
one is made, or clearing it when the new one is refused, would close the
first. uitoolkit's own `TestARefusedCopyComesBackCleared` passes
here, displayless. `TestItem60ARefusedCopyIsNotTakenForOne`.

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

### 61. A tree that picks several nodes

- **Today** (`widgets/tree.go`). A `TreeView` has one `Selected` node: a
  press picks the node under it, and Ctrl+ and Shift+click pick that one
  node too. Nothing says which modifiers the press had (`OnSelect` gets the
  node alone), and a drag carries the one node pressed.
- **What the manager needed.** Its Vault tab was a tree of the vault's
  contents, items under their folders, and the person picked several items
  to drag onto a folder or delete together, as in any file manager. It
  marked its own picks meanwhile (the modifiers noted at each press, the
  items picked shown bold with a check).
- **Now** there are no folders (`gui/svmanager/content.go`): a tab of
  items is a `ListView` in `SelectExtended` mode, which picks several
  (Ctrl+click, Shift+click and Shift+arrows, Ctrl+A) and reports them
  (`OnSelectionChange`). The manager needs nothing of the tree here.
- **Done when** a `TreeView` has a selection of several nodes
  (Ctrl+click toggling one, Shift+click and Shift+arrows a range from an
  anchor), painted as selected, with an `OnSelectionChange` that reports
  them, and a drag that starts on one of them carries them all.
  `TestItemsArePickedTogetherAndDeleted` pins the manager's side, on the
  list.

## Found redrawing the manager's window (since v0.23.4)

The manager's window draws its own title bar now: secretvault's mark at
its top left locks every vault, and beside it breadcrumbs say where the
window is, each opening what it can change to; Settings is on the
window's back (`gui/svmanager/titlebar.go`, `flip.go`). Building that
found four gaps in how keys and popups behave, and what the toolkit did
not have for the rest. Each is pinned in `gui/uitoolkit_test.go`, and
v0.23.6 closed them all (70 otherwise).

### 62. A popup's keys go to the popup alone

- **Today** (`app/window.go`, the key-down case of the event handler).
  While a popup is up, a key is offered to `widget.CascadeLeaf(popup)`, the
  popup itself for one that is not a menu, and, unless
  `widget.SetPopupKeysPass` says otherwise, to nothing after it: not to
  what has the keyboard inside the popup, though `FocusOn` put it there
  and Tab (which the window handles first) moves it round the popup's
  widgets as it should. A popup of widgets, rather than a menu, therefore
  hears every key itself, and a list or a button in it never does: Up,
  Down and Enter in the manager's vault list reached the drop-down and
  stopped.
- **Workaround.** The manager's drop-down hands each key on to what has
  the keyboard in it, then up its ancestors to the drop-down
  (`dropPanel.KeyPress`, `gui/svmanager/titlebar.go`).
- **Proposal.** Offer a popup's keys as the window's are offered: to what
  has the keyboard, when it is inside the popup, and up from it to the
  popup; a menu, whose leaf is what has the keyboard, is as it is.
- **Done when:** in a popup of a focusable widget with the keyboard on
  it, a key reaches that widget first.
  `TestItem62AKeyInAPopupReachesWhatHasTheKeyboard` pins today's routing (and
  Tab's, which holds).

**Closed in 0.23.6** (the release notes, verbatim): **A key reaches whatever has the keyboard**, in a popup and out of one; a key with no focus reaches the content root instead of being dropped.

**After v0.23.6: satisfactory** (6f6fc45). In a popup a key goes to
what has the keyboard in it, then up to the popup; Tab goes round the
popup's widgets as before. The manager's drop-down takes Escape alone
now (`dropPanel.KeyPress`), and Up, Down and Enter reach the vault list
in it by themselves. `TestItem62AKeyInAPopupReachesWhatHasTheKeyboard`.

### 63. A key with the keyboard on nothing reaches nothing

- **Today** (`app/window.go`, `bubbleKey`). A key is offered to what has
  the keyboard and up its ancestors; with nothing to start from it goes
  to no one, and from a widget that has left the window it goes up to the
  last of what it was under and stops there. The content root, where an
  application keeps its own keys (its `KeyPress`, before the
  accelerators), hears it only when the climb reaches it, or comes from
  the title bar. So when what had the keyboard is taken out of the window
  (a page swapped for another, a tab's content replaced), every key of
  the window's own stops working until something is clicked: in the
  manager, Ctrl+Page Up and Down, Escape clearing the filter, Delete.
- **Workaround.** Whenever a part or a tab is shown, the manager puts the
  keyboard back on the part's button when what had it has gone
  (`keepFocus`, `gui/svmanager/sections.go`).
- **Proposal.** When what has the keyboard leaves the window, give it to
  nothing; and offer a key with the keyboard on nothing to the content
  root, as one from the title bar is offered.
- **Done when:** with the keyboard on a widget that was taken out of the
  window, a key reaches the content root.
  `TestItem63AKeyWithTheKeyboardOnNothingReachesTheRoot` pins it.

**Closed in 0.23.6** (the release notes, verbatim): **A key reaches whatever has the keyboard**, in a popup and out of one; a key with no focus reaches the content root instead of being dropped.

**After v0.23.6: satisfactory** (6f6fc45). A key with the keyboard on a
widget that left the window reaches the content root, so the window's
own keys work whatever was swapped out. The manager still puts the
keyboard on the part's button when what had it goes (`keepFocus`), now
for Tab's sake alone: from there Tab goes into the part.
`TestItem63AKeyWithTheKeyboardOnNothingReachesTheRoot`.

### 64. A scroll view takes Ctrl+Page Up and Down

- **Today** (`widgets/scroll.go`, `ScrollView.KeyPress`). Page Up and Page
  Down scroll by a page whatever the modifiers. Ctrl+Page Up and Down are
  the previous and the next tab, in a `TabView` and in every browser, and
  in the manager the previous and the next part of the window; inside a
  page that scrolls they scroll it instead, and never reach the window.
- **Workaround.** The manager's pages scroll in a view of its own that
  leaves them to the window (`pageScroll`, `gui/svmanager/tabbed.go`).
- **Proposal.** Take Page Up and Down only with no modifier but Shift.
- **Done when:** a `ScrollView` leaves Ctrl+Page Up and Ctrl+Page Down.
  `TestItem64AScrollViewLeavesCtrlPageUpAndDown` pins it.

**Closed in 0.23.6** (the release notes, verbatim): **A scroll view leaves Ctrl+Page Up and Down alone**, so the tabs underneath get them.

**After v0.23.6: satisfactory** (125681b). The manager's pages are the
toolkit's scroll views again; `pageScroll` is gone.
`TestItem64AScrollViewLeavesCtrlPageUpAndDown`.

### 65. `ShowPopup` shows a popup at the size it was measured at

- **Today** (`widget/popup.go`, `ShowPopup`). It puts the window's look on
  the popup (`inheritLook`), and with it the window's display scale, and
  shows it at the bounds it was given. A caller that measured the popup
  before showing it, as one must to arrange it, measured it in the
  toolkit's default look at scale 1: on a screen at twice that, the popup
  is drawn at twice the size inside a box of the first, its words cut
  short and its last rows cut off. This is what the manager's drop-downs
  did on the person's screen. `PlacePopupForAnchor` does it right
  (`PreparePopup` first), but nothing says that `ShowPopup` needs it, and
  a popup arranged by hand, as `ShowPopup` invites, is wrong.
- **Workaround.** The manager places its drop-downs with
  `PlacePopupForAnchor` (`openDrop`, `gui/svmanager/titlebar.go`).
- **Proposal.** Have `ShowPopup` measure the popup again, once its look is
  on, and grow it where it is if it was arranged smaller; or refuse a
  popup that was not prepared, saying to call `PreparePopup` or a
  `Place*` first.
- **Done when:** a popup measured and arranged before `ShowPopup` is shown
  at its size in the window's look.
  `TestItem65ShowPopupShowsAPopupAtItsSizeInTheWindowsLook` pins it.

**Closed in 0.23.6** (the release notes, verbatim): **A popup is shown at the size it was measured at**, in the look it is drawn in rather than the look that opened it.

**After v0.23.6: satisfactory** (4d237e5), by the proposal's first way:
a popup measured in another look is measured again and shown at its
size in the window's, and the toolkit says on its log to call
`PreparePopup` or a `Place*` first. The manager's drop-down was placed
with `PlacePopupForAnchor` and still is, which is the way the toolkit
asks for. `TestItem65ShowPopupShowsAPopupAtItsSizeInTheWindowsLook`.

### 66. Breadcrumbs

- **Today.** Nothing in `widgets` shows a path of steps, each a button
  that opens what it can change to: no breadcrumb bar, no stepper, no row
  whose children overlap (an arrow's point in the next one's notch), and
  no hit test by shape short of overriding `HitTest`.
- **What the manager needed.** The title bar says where the window is,
  Vault › personal › Logins, as arrows in the accent, each with an icon of
  what it is, each opening a drop-down of what it can change to.
- **Workaround.** The manager draws its own (`crumbRow` and
  `crumbButton`, `gui/svmanager/crumbs.go`): the arrow's outline, a row
  that lays each one's start under the one before's point, and a
  `HitTest` that leaves a press in a notch to the arrow before.
- **Proposal.** A `Breadcrumbs` widget: a row of steps, each with its
  text, an icon and what a click on it opens, drawn by the look (arrows,
  or chevrons between words), with the keyboard going from one to the
  next.
- **Done when:** `widgets` has one. `TestItem66Breadcrumbs` pins its
  absence.

**Closed in 0.23.6** (the release notes, verbatim): **`widgets.Breadcrumbs`** is a path of steps whose arrows overlap, hit tested by shape, with the keyboard and the accessibility nodes an application would otherwise write itself.

**After v0.23.6: satisfactory** (c9d508b). The manager's title bar is
`widgets.Breadcrumbs` with `Arrows` (`gui/svmanager/titlebar.go`):
each step with the toolkit's icon of what it is, the kinds of item, a
page's tabs and the disks as the toolkit's menu (`Crumb.Menu`), the
vaults as the manager's own drop-down, a live list with buttons under
it (`Crumb.OnClick`, placed at `CrumbRect`). `crumbRow`, `crumbButton`
and the manager's pick list are gone. The look is the toolkit's now:
the step the window is on in the accent, the others on the window's
surface, where the manager's were all in the accent; and its labels in
the look's capitals. What it lacks: a tip of a step's own (79), and a
sign on a step that opens a menu (81). `TestItem66Breadcrumbs`.

### 67. Icons a password manager needs

- **Today** (`style/icons.go`). The set has a padlock (`IconLock`), but no
  padlock open, no key, no password masked, no shell prompt, no drive, no
  safe and no dice.
- **Workaround.** The manager draws them in one ink, to sit beside the
  set's: `drawLock` (open or shut), `drawVault`, `drawDisk` and
  `drawDice` (`gui/svmanager/marks.go`), `drawKey`, `drawStars` and
  `drawPrompt` (`gui/svmanager/crumbs.go`).
- **Proposal.** `IconLockOpen`, `IconKey`, `IconPassword`, `IconTerminal`,
  `IconDrive`, `IconSafe` and `IconDice`, in every icon set.
- **Done when:** the set has them. `TestItem67IconsAPasswordManagerNeeds`
  pins their absence.

**Closed in 0.23.6** (the release notes, verbatim): **Seven icons a vault is made of**: an open padlock, a key, a masked password, a shell prompt, a disk, a safe and dice.

**After v0.23.6: satisfactory** (52541d9). The rail's Vault, Disk and
generator, the padlocks in the title bar and the vault list, and the
kinds of item are the toolkit's icons; `drawLock`, `drawKey`,
`drawStars`, `drawPrompt`, `drawDisk`, `drawVault` and `drawDice` are
gone. The manager still draws what the set has nothing for: the logo, a
padlock or the logo with a plus, and a cloud a vault comes down from.
`TestItem67IconsAPasswordManagerNeeds`.

### 68. Nothing lies over a framed window's title bar

- **Today** (`app/window.go`, `layout`; `widget/popup.go`). Where the
  toolkit draws the frame, an overlay is laid out over the content alone
  (`ob = g.content`: the title bar stays out of a modal dialog's dimming,
  which is right for a dialog); a popup is placed anywhere but is, on
  Wayland and X11, a surface of its own, with a shadow; and every
  component is clipped to its own box. So nothing can be drawn over the
  whole of the window inside its frame, title bar and content as one.
- **What the manager needed.** The mark at the top left turns the window
  over to Settings, on its back, as a card turns: the title bar turns
  with the rest (`gui/svmanager/flip.go`).
- **Workaround.** The card is drawn in two parts that meet: one in the
  title bar, standing in for its items while they are put out of sight
  (`standIn`, `gui/svmanager/titlebar.go`), and one laid over the
  content. The title bar's ground is guessed from the look's `titleBar`
  colour, as the frame's own painting of it is not exposed; the window's
  buttons, the frame's, stay where they are, painted over the card.
- **Proposal.** A layer of the window's own over everything inside its
  frame, title bar included, under its popups: `Window.SetCover(c)`, for
  a transition, a lock screen or a splash; and the caption's ground
  painted by an exported call, so a picture of the window can be made.
- **Done when:** a component can be laid over the whole window inside its
  frame. `TestItem68ACoverLiesOverTheTitleBar` pins it.

**Closed in 0.23.6** (the release notes, verbatim): **`Window.SetCover`** draws over the whole window, title bar and all. An overlay covers the content alone, because a modal dimming its own title bar would be wrong; a card turning the window over needs the other thing.

**After v0.23.6: satisfactory** (c575c39), and the caption's ground
painted by an exported call too (`style.DrawDecorationOf`). The
manager's turn is one cover over the whole window inside its frame, the
window's buttons included, where it was two canvases that met; the
title bar's stand-in is gone. `TestItem68ACoverLiesOverTheTitleBar`.

### 69. A window cannot be laid out at once

- **Today** (`app/window.go`, `RequestLayout`). A window is laid out at
  its next frame; nothing lays it out now.
- **What the manager needed.** The window's back is painted into a
  picture the moment it is shown, before the turn starts, so it must be
  laid out first.
- **Workaround.** The manager measures and arranges the title bar and
  the content itself, at the size they have (`layoutNow`,
  `gui/svmanager/flip.go`).
- **Proposal.** `Window.Layout()`, laying the window out at once, as its
  next frame would.
- **Done when:** `Window` has it. `TestItem69AWindowIsLaidOutAtOnce`
  pins its absence.

**Closed in 0.23.6** (the release notes, verbatim): **`Window.Layout`** lays the window out at once rather than at its next frame — what a picture of the window, taken the moment it is shown, needs.

**After v0.23.6: satisfactory** (7002b3f); `layoutNow` is gone.
`TestItem69AWindowIsLaidOutAtOnce`.

### 70. A picture cannot be drawn in perspective

- **Today** (paintengine2d, `Context`). Its transforms are affine, and an
  image is drawn into a rectangle: nothing draws one into a quadrilateral.
  This is paintengine2d's, which uitoolkit draws with.
- **What the manager needed.** The card turning over is a face seen in
  perspective, its far edge shorter than its near one.
- **Workaround.** Each face is drawn as narrow upright strips, each as
  tall as its depth makes it, the far ones dimmed (`drawTurned`,
  `gui/svmanager/flip.go`): about 260 strips in a wide window, every
  frame.
- **Proposal.** `Context.DrawImageQuad(img, src, quad [4]Point)`, drawing
  with the projective mapping of src onto quad.
- **Done when:** paintengine2d has it.
  `TestItem70ACardTurnsInPerspective` pins its absence.

**Closed in 0.23.6** (the release notes, verbatim): **`Window.Flip`** turns the whole window over in perspective, front face to back, and `SetFlipShapesWindow` cuts the window to the card's outline while it turns, so the desktop shows through the corner the card has turned away. A card comes back the way it went.

**After v0.23.6: satisfactory otherwise.** paintengine2d still draws
an image into a rectangle alone, but what the manager needed it for is
the toolkit's: `widgets.FlipPanel` turns two faces about the upright
middle in perspective, cut into strips, comes back the way it went, and
says the card's outline at every frame (2041083, ee2acd5). The
manager's turn is one (`gui/svmanager/flip.go`), and `drawTurned` is
gone. The window turning over whole, frame and all, is 77.
`TestItem70ACardTurnsInPerspective`.

### 71. No pointing hand

- **Today** (`platform/cursor.go`). The pointer's shapes are the eight
  resize ones and the column and row ones, move, grab and grabbing, the
  drag ones, and a text beam. None is the pointing hand that says "this
  can be clicked" (a link's, CSS `pointer`, GTK's `pointer`, Qt's
  `PointingHandCursor`, macOS `pointingHandCursor`, Windows `IDC_HAND`).
  The macOS side knows the hand (`akCursorPointingHand`), but no shape
  maps to it.
- **What the manager needed.** A locked vault is its logo alone, on an
  empty page, by the person's wish: no words, no buttons, no ring round
  it. A click on the logo unlocks it, and nothing but the pointer could
  say so without a mark on the page.
- **Workaround.** The logo lifts under the pointer, a little larger in a
  soft light (`lockFace`, `gui/svmanager/lockface.go`); it has no tip, by
  the person's wish. The title bar's padlocks unlock the vault too.
- **Proposal.** `platform.CursorPointer`, mapped on each backend to the
  desktop's own hand (the `pointer` cursor name under X11 and Wayland,
  `IDC_HAND`, `pointingHandCursor`), for a component's `CursorAt` to
  return.
- **Done when:** platform has it. `TestItem71ThePointingHand` pins its
  absence.

**Closed in 0.23.6** (the release notes, verbatim): **`platform.CursorPointer`**, the pointing hand, on all four backends.

**After v0.23.6: satisfactory** (5dc6a0d). The locked vault's logo
shows it under the pointer (`lockFace.CursorAt`), and lifts as before.
`TestItem71ThePointingHand`.

### 72. No passing note

- **Today** (`widgets`). Nothing says something for a few seconds and
  goes, as a toast or a snackbar does (GTK's `AdwToast`, Android's
  `Snackbar`, KDE's `KNotification` in-window, Qt Quick's `ToolTip` with a
  timeout): a `StatusBar` is the only place a window has for what just
  happened, and it stays.
- **What the manager needed.** No status bar, by the person's wish: what
  the window has to say (Copied, Unlocked, Canceled, what went wrong)
  comes as a note at the bottom of the pages, over them and out of the
  pointer's way, that fades after a few seconds; and a note that stays
  while something is so (an emergency request waiting, work taking a
  while).
- **Workaround.** The manager's notes are its own (`noteLayer`,
  `gui/svmanager/notes.go`): a layer over the pages that the pointer goes
  through, the text painted rather than a `Label`'s so that it can fade, a
  frame at a time; its accessible name is what it says, with the role of
  a status bar.
- **Proposal.** `widgets.Toast`: `ShowToast(from, text, kind, for)`, over
  the window's content, out of the pointer's way unless it holds an
  action (Undo), faded in and out by the look (and at once under reduced
  motion), stacked when several come, and announced to a screen reader
  as a polite live region.
- **Done when:** `widgets` has one. `TestItem72APassingNote` pins its
  absence.

**Closed in 0.23.6** (the release notes, verbatim): **`widgets.Toast`** is a line that appears and goes — Copied, Unlocked, Canceled. Nothing in the toolkit said something and went: a status bar was the only place a window had for what just happened, and a status bar never goes. A toast announces itself to the screen reader as a polite live region, and a press goes straight through it.

**After v0.23.6: satisfactory** (e7c055b), stacked, faded by the
toolkit, said to a screen reader, and one that stays until it is taken
down (a negative time). The manager's notes are toasts
(`gui/svmanager/notes.go`): a message for four and a half seconds, an
error for eight, and an emergency request, or work that takes a while,
for as long as it is so; `noteLayer` is gone. A note taken down for the
next fades out, where the manager's went at once.
`TestItem72APassingNote`.

### 73. A skin's radio is its check box

- **Today** (`style/engine_skin.go`, `checkLike`; `docs/skins.md`,
  Parts). The skin format has one part for the check box's well and the
  radio's (`check`), and a mark for each (`check.mark`, `radio.mark`).
  `RadioIndicator` paints the `check` well, so a skin that binds it paints
  its radios in its check boxes' well: square, where a radio is round,
  and no skin can say otherwise.
- **What the manager needed.** Its look, a skin
  (`gui/secretui/hudskin`): check boxes as square wells, radios as round
  ones, both filled orange when on.
- **Workaround.** The skin binds neither, so both are the pack's under
  it, in the look's colours; its sheet has no check or radio art.
- **Proposal.** A `radio` part, the radio's well, falling back to
  `check` where a skin does not bind it, so every skin that exists keeps
  painting as it does.
- **Done when:** `style.SkinPartNames()` has it.
  `TestItem73ASkinHasARadiosWell` pins its absence.

**Closed in 0.23.6** (the release notes, verbatim): **A skin can say what its radios' well looks like.** One part served the check box's well and the radio's, so a skin that bound `check` painted its radios square.

**After v0.23.6: satisfactory, and unused**: the manager's look is
uitoolkit's Hangar now, a pack, and the manager has no skin of its own
(`gui/secretui/hudskin` is gone). `TestItem73ASkinHasARadiosWell`.

### 74. A button's icon is in the text's colour, not its label's

- **Today** (`widgets/button.go`, `Button.face`). A button's leading mark
  (`Icon`) is drawn in `Palette().Text` (or `TextMuted` when disabled),
  whatever face is under it. On the default button, whose face is the
  accent and whose label is in `TextOnAccent` (or a skin's `default`
  ink), the mark is the colour the face is: in a look whose accent is
  near-black, a black mark on a black key.
- **What the manager needed.** Its look's default button is solid
  orange, its label and its icon white on it (an earlier look's was
  near-black, where a mark in the text's colour vanished altogether).
- **Workaround.** Every button the manager makes draws its mark again,
  in `TextOnAccent`, over the toolkit's where it is Primary (`newButton`,
  `gui/svmanager/buttons.go`), at the toolkit's own icon rect.
- **Proposal.** Draw the mark in the label's ink: the engine's label
  colour for the state (`DrawButton` already chooses it), exported so the
  widget can ask for it.
- **Done when:** a default button's mark is in its label's colour.
  `TestItem74AButtonsMarkIsInItsLabelsInk` pins today's code.

**Closed in 0.23.6** (the release notes, verbatim): **Breaking.** `Engine.DrawButton` takes a `ButtonDraw` — the label and the mark — rather than a label string. […] `DrawToolButton` has been handed the icon all along, which is exactly why a tool button can be tight. This is the same idea applied to the seam that was missing it.

**After v0.23.6: satisfactory** (da6819a, c74233f). The engine draws
the mark with the label, in its ink; `newButton` no longer draws it
again. A marked button's strip is narrower at 2x than at 1x, which is
80. `TestItem74AButtonsMarkIsInItsLabelsInk`.

### 75. A framed window's shadow cannot be turned off

- **Today** (`style/engine_web_frame.go`, `webEngine.Decoration`;
  `style/decoration.go`, `DecorationOf`; `app/frame.go`). Where the
  toolkit draws the frame, the look's decoration drops a soft shadow
  round the window into a transparent margin: the web engine always
  does, as every engine that draws a modern frame does, and
  `DecorationOf` takes it away only for a maximised or tiled window or an
  uncomposited screen. Nothing an application or a look states turns it
  off: `Window` has no such option, a pack has no token for it, and a
  skin's `window` block, which restates the border, the radius and the
  shape, has no shadow key.
- **What the manager needed.** Crisp edges, by the person's wish: a
  window that is a plain rectangle, no soft shadow round it and no
  transparent margin, with its own title bar and the toolkit's frame,
  buttons and resizing.
- **Workaround.** None. A window with no frame (`platform.DecorationsNone`)
  and the application drawing its own buttons and resize band was tried
  and taken out: the manager uses the toolkit's frame, buttons and
  resizing, and wears the shadow until the toolkit can drop it.
- **Proposal.** `Window.SetFrameShadow(false)` (or a pack's `shadow`
  token, and a skin's `window.shadow`): the frame as it is, with no
  shadow and no margin, its resize band inside the window as it already
  is when there is no shadow.
- **Done when:** a framed window can drop its shadow.
  `TestItem75AFramedWindowDropsItsShadow` pins its absence.

**Closed in 0.23.6** (the release notes, verbatim): **`Window.SetFrameShadow(false)`** gives up the soft shadow the look drops into the transparent margin, without giving up the toolkit's frame, buttons and resizing with it.

**After v0.23.6: satisfactory** (1fa7918). The manager's window wears
the toolkit's frame, its buttons and its resizing, with no shadow.
`TestItem75AFramedWindowDropsItsShadow`.

### 76. A skin's capitals reach its caption's title alone

- **Today** (`style/skin.go`, `TextRole.Upper`; `style/engine_skin_frame.go`;
  `style/engine_skin.go`). A text role's `"case": "upper"` is documented
  as setting the role's text in capitals, painting only. It is applied
  where the frame paints the window's title, and nowhere else: a button,
  a tab or a tool button bound to the same role draws its label as
  written.
- **What the manager needed.** Its look (`gui/secretui/hudskin`), after
  the picture the person chose: the labels of buttons and tabs in
  capitals, names and values as written.
- **Workaround.** None: the labels are as written. Writing them in
  capitals in the code would change what a screen reader says and what a
  test or a person searching for a label finds; the manager does not.
  Its own headings (sections, breadcrumbs) it paints in capitals itself.
- **Proposal.** Apply the role's case wherever the engine paints a label
  for a part bound to it (`DrawButton`, `DrawTab`, `DrawToolButton`, the
  combo's text), painting only, as the caption's title already is.
- **Done when:** a button bound to an upper-case role draws its label in
  capitals. `TestItem76ALooksCapitalsReachItsLabels` pins today's
  code.

**Closed in 0.23.6** (the release notes, verbatim): **A skin's capitals reach the labels it paints**, and a generated skin can state its typefaces (`skingen.Plan.Fonts`) instead of the application reopening the manifest the generator just wrote.

**After v0.23.6: satisfactory** (9a643ab, `style.ControlLabelOf`),
painting only: a screen reader hears the words as written. The
manager's look is Hangar, whose chrome labels are in capitals; the
breadcrumbs' `ToUpper` is gone with them.
`TestItem76ALooksCapitalsReachItsLabels`.

## Found moving to v0.23.6

Moving the manager onto what v0.23.6 gave (its look Hangar, its title
bar `Breadcrumbs`, its notes toasts, its turn to Settings the toolkit's)
found thirteen more (85 and 86 in the clipboard, read again for 56–60;
87–89 moving to `Window.Flip`). Each is pinned in
`gui/uitoolkit_test.go`.

### 77. A framed window cannot turn over, title bar and all

- **Today** (`app/flip.go`, `Window.SetFlipFaces`). The whole-window turn
  puts its flip panel in the window's content, so its faces are the
  content: under the toolkit's frame the title bar is outside them and
  stands still while the rest turns, and the shape the window takes is
  the content's card alone, the title bar cut away while it turns. The
  file says to use it without the toolkit's frame, and its sample draws a
  frame on each face (`Panel.Window`): a caption, a close button and a
  move, but no minimise, no maximise and no resizing, which a window
  wearing the toolkit's frame has.
- **What the manager needed.** The whole window turning over to Settings
  on its back, by the person's wish (2026-10-12), the desktop showing
  through where the card has turned away; and the toolkit's frame, its
  buttons and its resizing, which the person had asked for before
  (2026-10-10).
- **Workaround.** None now. The manager first laid a flip panel of two
  pictures of the window over it as a cover and shaped the window to the
  card itself, which kept the frame; the person chose uitoolkit's own
  turn instead (2026-10-12). Its window wears no frame
  (`platform.DecorationsNone`): its chrome is a window panel
  (`widgets.Panel` with `Window`), whose caption moves the window and
  closes it, and nothing else: no minimise, no maximise, no resizing
  (`buildFaces` and `turn`, `gui/svmanager/flip.go`).
- **Proposal.** A whole-window turn for a framed window: `SetFlipFaces`
  (or a `Window.FlipTo(switch func())`) that turns the window inside its
  frame, title bar and buttons included, from a picture of it before
  `switch` to one after, as a cover, the window following the card.
- **Done when:** a window wearing the toolkit's frame can turn over with
  its title bar. `TestItem77AFramedWindowCannotTurnOverWhole` pins
  `SetFlipFaces` putting its panel in the content.

**Closed in 0.23.7** (the release notes, verbatim): `Window.Flip` worked only on a window with no frame of the toolkit's, and the frame is what supplies the resize edges, the minimise and the maximise — so an application that wanted the turn gave up all three and drew a caption of its own on each face, with close and move only. The panel could not do otherwise: it is the window's content, every component is clipped to its own box, and the frame is drawn outside that box. A framed window turns as a *picture of itself* instead — photographed with each face up, the two turned over everything it draws, the card's silhouette worn by the window every frame. The live content under the picture is already the face being turned to, so when the picture goes there is nothing to swap.

**After v0.23.7: satisfactory** (f754b65). The manager's window wears
the toolkit's frame again, with its buttons and its resizing, and turns
with `Window.Flip`: the toolkit photographs it with each face up, the
title bar and the frame in both, and turns the pictures over the whole
window, the window shaped to the card. The window's content is one tree,
so the faces take turns to hold it: the flip panel says the other face is
up between the two photographs (`OnFlip`), and the manager changes the
window there and moves the content onto it (`faceUp`,
`gui/svmanager/flip.go`). The window panel and the picture of the
manager's own are gone. One thing the turn needs: the window's content
root is the flip panel, which passes a key to neither face (90).

### 78. A flip panel's pictures are not wiped

- **Today** (`widgets/flip.go`, `FlipPanel.rasterise` and `end`). A turn
  paints both faces into pictures at its first frame, and its end drops
  them (`f.turn = flipTurn{}`) without zeroing them; nothing else does.
- **What the manager needed.** Its window turns over with an item open,
  its password shown, on the front: a picture of it is a copy of the
  password, which the manager wipes wherever it makes one.
- **Workaround.** The manager wipes its own pictures of the window when
  the turn ends (`flipAnim.end`); the panel's copies of them it cannot
  reach, and they stay in memory until they are collected.
- **Proposal.** Zero the pictures at the end of a turn (`clear(img.Pix)`)
  before they are dropped, and when the panel is taken down mid-turn.
- **Done when:** a turn's pictures are zeroed when it ends.
  `TestItem78AFlipPanelsPicturesAreNotWiped` pins today's code.

**Closed in 0.23.7** (the release notes, verbatim): A flip paints both faces into pictures at its first frame and dropped them at its end without zeroing them. A picture of a face is a copy of what that face showed, and a password manager turns its window over with an item open and its password on the front — so these were copies of a passphrase it wipes everywhere it can reach, and could not reach here. The panel zeroes them wherever a turn ends, `FlipPanel.Wipe` is there for an application taking the panel down itself, and a framed window wipes the two photographs of itself as well: 1.5 MB, in that case.

**After v0.23.7: satisfactory** (c40b170): the panel's pictures and the
window's photographs are zeroed when a turn ends. The manager makes no
pictures of its own now. `TestItem78ATurnsPicturesAreWiped`.

### 79. A breadcrumb has no tip of its own

- **Today** (`widgets/breadcrumbs.go`). A `Crumb` has its text, an icon,
  a click and a menu; the row says no tip when the pointer rests on a
  step, and its accessible nodes no description.
- **What the manager needed.** The vault's breadcrumb said, when the
  pointer rested on it, the vault's state, its items and its sync's
  (`personal: unlocked, 4 items; synced 2 minutes ago`).
- **Workaround.** The row is held in a box whose tip, and whose
  description to a screen reader, is the vault's state, whichever step
  the pointer is on (`tipBox`, `gui/svmanager/titlebar.go`); in the Disk
  and Tools parts it says nothing.
- **Proposal.** `Crumb.Tip`, said when the pointer rests on that step,
  and its node's description.
- **Done when:** a step can say a tip of its own.
  `TestItem79ABreadcrumbHasNoTip` pins its absence.

**Closed in 0.23.7** (the release notes, verbatim): **A breadcrumb step says its own tip and marks what it opens.** `Crumb.Tip` is the step's, not the row's — a path whose steps are a vault, an item and a tab has something different to say at each — and a step with a `Menu`, or with `Opens` set, wears a chevron.

**After v0.23.7: satisfactory** (aadd607), and the tip is the step's
description to a screen reader too. The vault's step says the vault's
state and its sync's; `tipBox` is gone. `TestItem79ABreadcrumbHasATip`.

### 80. A marked button's mark strip does not scale with the display

- **Today** (`style/look.go`, `ToolButtonChromeFor`). The icon's side is
  multiplied by the display scale, and the pad and the gap round it (10
  and 8) are not: they are device pixels at any scale. So a button with a
  mark is 32 logical pixels wider than one without at 1x and 28 at 2x,
  and a tool button's and a breadcrumb's chrome are narrower at 2x the
  same way.
- **What the manager needed.** Its passphrase and consent questions are
  the same size at every scale (14): with four marked buttons in a row,
  the consent question is 17 pixels narrower at 2x than at 1x.
- **Workaround.** None: the dialog's test allows for it
  (`TestADialogIsTheSameAtEveryScale`,
  `gui/cmd/secretvault-gui-prompt`).
- **Proposal.** Scale the pad and the gap with the icon (`style.Dip`).
- **Done when:** a mark's strip is the same width in logical pixels at
  1x and 2x. `TestItem80AMarkedButtonsStripDoesNotScale` pins the
  difference.

**Closed in 0.23.7** (the release notes, verbatim): **A mark's strip is the same width in logical pixels at every scale.** The icon was multiplied by the display scale and the pad and the gap round it were not, so a marked button was 32 logical pixels wider than a plain one at 1x and 28 at 2x.

**After v0.23.7: satisfactory** (714f8ab): 32 at 1x and at 2x. The
prompt's test allows nothing for it again.
`TestItem80AMarkedButtonsStripScales`.

### 81. A breadcrumb that opens a menu shows no sign of it

- **Today** (`widgets/breadcrumbs.go`, `paintCrumb`). A step is drawn with
  its icon and its words whether a click on it goes there or opens a menu
  of what it can change to.
- **What the manager needed.** Its own breadcrumbs had a chevron after
  the words of a step that opens something (the vault, the kind of item,
  the tab), and none on one that does not (Vault, Settings, Tools).
- **Workaround.** None: the manager's steps show no sign, as the
  toolkit's look draws them.
- **Proposal.** A chevron (`style.DrawArrowOf`, down) at the end of a
  step with a `Menu`, and one with a flag for an `OnClick` that opens a
  drop-down of the application's own (`Crumb.Opens`).
- **Done when:** a step that opens a menu is marked.
  `TestItem81ABreadcrumbsMenuHasNoSign` pins its absence.

**Closed in 0.23.7** (the release notes, verbatim): **A breadcrumb step says its own tip and marks what it opens.** `Crumb.Tip` is the step's, not the row's — a path whose steps are a vault, an item and a tab has something different to say at each — and a step with a `Menu`, or with `Opens` set, wears a chevron.

**After v0.23.7: satisfactory** (aadd607). The kinds, the tabs and the
disks are menus and wear the chevron by themselves; the vault's step,
which opens the manager's own drop-down, says `Opens`.
`TestItem81ABreadcrumbThatOpensIsMarked`.

### 82. A breadcrumb's words are cut short by a rounding error

- **Today** (`widgets/breadcrumbs.go`, `paintCrumb`). A step is measured
  as its pads, its icon, the gap and its words' advance, and its words
  are drawn with `Font.Fit` in what is left of the step's box once the
  pads, the icon and the gap are taken off again. In float32, at a step
  that starts some hundreds of pixels along, what is left comes out a
  hair narrower than the advance it was made of (57.046844 for
  57.046875), and `Fit`, which allows nothing, puts an ellipsis on the
  words. Which steps it hits depends on where they fall: in the manager,
  Vault › personal › About this vault › Grants shows GRAN….
- **What the manager needed.** Its breadcrumbs' words whole wherever the
  row has the room for them.
- **Workaround.** None: the words are the toolkit's to draw.
- **Proposal.** Fit the words to the advance the step was measured with,
  or allow `Fit` a part of a pixel (`maxW+0.01`), as layout already
  rounds a measured size up to whole pixels.
- **Done when:** a step's words are drawn whole in the box measured for
  them. `TestItem82ABreadcrumbsWordsAreCutShortByARoundingError` pins
  today's arithmetic.

**Closed in 0.23.7** (the release notes, verbatim): **Words fitted to the width they were measured with are not cut short.** A widget measures its words, is given a box that holds them, and fits them into what is left — and float32 does not survive the round trip, so `Font.Fit` put an ellipsis on words that fit. A breadcrumb row drew `Vault › personal › About this vault › Grants` as `GRAN…`. Fit allows a thirty-second of a pixel now, which covers every caller of that shape.

**After v0.23.7: satisfactory** (f899ec5): Grants is whole.
`TestItem82WordsFitTheWidthTheyWereMeasuredWith`.

### 83. A merged caption drops the look's silhouette

- **Today** (`style/silhouette.go`, `WindowShapeOf`). A look's silhouette
  is dropped for a window whose own title bar is its caption
  (`DecorationState.Merged`), as for a maximized or tiled one. The
  reason given is a look whose outline leaves part of the top edge to the
  desktop (BeOS's tab), which an application's bar across the window's
  width would be drawn outside of. It holds for every look, though:
  Hangar cuts the top right, the bottom right and the bottom left, and
  its top edge is whole, yet a window with a merged title bar stays a
  rectangle, while `DrawDecoration` still strokes its border along the
  cuts it did not make. The corners show the window's own ground and
  content beyond the frame's diagonal hairlines.
- **What the manager needed.** Its look's window, cut as the look cuts
  it, with its own title bar (breadcrumbs, the logo, Settings before the
  window's buttons) as the caption.
- **Workaround.** None. The manager's window has no merged caption now
  (77): its chrome is a window panel, which meets 88 instead.
- **Proposal.** Drop a silhouette under a merged caption only where it
  leaves the top edge to the desktop (a `Silhouette` that says so, or a
  look that says its outline holds a full-width bar).
- **Done when:** a merged window in Hangar is cut as an unmerged one is.
  `TestItem83AMergedCaptionDropsTheLooksSilhouette` pins today's code.

**Closed in 0.23.7** (the release notes, verbatim): **A window keeps its look's outline when its own bar is the caption.** The outline was dropped for every look the moment a bar was merged, so a window with tabs in its title bar lost every corner Hangar takes off, and Deck lost its whole silhouette. That rule belongs to BeOS alone, whose tab is only as wide as its title.

**After v0.23.7: satisfactory** (05f6aa2): the manager's window, its
title bar merged, is cut at the top right, the bottom right and the
bottom left. `TestItem83AMergedCaptionKeepsTheLooksSilhouette`.

### 84. A cut corner's border is painted under the content

- **Today** (`app/window.go`, the frame's painting; Hangar's
  `DrawDecoration`). The frame paints its border and caption band first,
  then the title bar and the content over them. A rectangular border
  lies outside the content's box; a border along a cut corner does not:
  the cut crosses the box, so whatever the content paints in that corner
  covers the cut's hairline, and in Hangar the bracket inside its bottom
  left corner.
- **What the manager needed.** Its rail runs down the window's left
  edge on a ground of its own, to the bottom, where Hangar cuts the
  corner and puts its bracket.
- **Workaround.** None.
- **Proposal.** Paint the border of a cut corner, and its marks, over
  the content (as a cover is laid over it), or clip the content to the
  silhouette inset by the border.
- **Done when:** a cut corner's hairline shows over content that fills
  the corner. `TestItem84ACutCornersBorderIsUnderTheContent` pins the
  order.

**Closed in 0.23.7** (the release notes, verbatim): **A cut corner's hairline is drawn over the content.** A rectangular border lies outside the content's box; a chamfer crosses it, so content that filled the corner buried Hangar's hairline and its bracket. `style.DecorationOverEngine` is the seam, because only the engine knows where its chamfer is.

**After v0.23.7: satisfactory** (44415e8): the bracket and the cut's
hairline show over the rail at the bottom left.
`TestItem84ACutCornersBorderIsOverTheContent`.

### 85. A Wayland cancel handled while nothing is held ends the next secret

- **Today** (`platform/wayland_linux.go`, `uitkWlDataCancelled`). See 57's
  "After v0.23.6": the cancel names the copy it ends as whatever is held
  when it is handled, and where that is nothing it hands
  `forgetHeldSecretIf` a nil, which means "whichever is held" when its
  goroutine runs. X11's `endLostSecret` returns on nil; the cancel does
  not. So a cancel handled while nothing is held (an ordinary copy's
  source cancelled, or one during a secret copy where the clipboard
  service dispatches) ends a secret copied before its goroutine runs,
  while the Wayland source goes on serving it: wiped, its timer stopped,
  said gone, and the passphrase on the clipboard with nothing to clear
  it.
- **What the manager needed.** Its copies on Linux go through uitoolkit
  now (2026-10-12).
- **Workaround.** None: goroutine scheduling, narrow.
- **Proposal.** The nil check `endLostSecret` makes, in the cancel too.
- **Done when:** a cancel handled while nothing is held ends nothing.
  `TestItem85AWaylandCancelWithNothingHeldEndsTheNextSecret` pins today's
  code.

**Closed in 0.23.7** (the release notes, verbatim): **A Wayland cancel handled while nothing was held ended the next secret.** The cancel names the copy it ends as whatever is held when it is *handled*, and where that was nothing it passed a nil — `forgetHeldSecretIf` reads nil as "whichever is held when the goroutine runs". So a cancel arriving while no secret was held — an ordinary copy's source cancelled, or one during a secret copy — ended a secret copied in between: wiped, its timer stopped, the application told it had gone, while the Wayland source went on serving it. X11's `endLostSecret` has always returned on nil; the cancel does now.

**After v0.23.7: satisfactory** (39e4fa4).
`TestItem85AWaylandCancelWithNothingHeldEndsNothing`.

### 86. A busy Windows clipboard keeps the copy before a new one

- **Today** (`platform/clipboard_secret.go`, `ClipboardSetSecret`). See
  60's "After v0.23.6": the copy being replaced is let go
  (`prev.forget()`) before the new one is tried, so where another
  program holds the Windows clipboard open for all of the copy's tries,
  and nothing on it changes, the previous secret stays on the clipboard
  with its timer stopped and nothing held: not cleared at its time, nor
  at its vault's lock, nor at the quit. On X11 a refused ownership also
  leaves the owner's copy of the new secret (`clipData`) unwiped until
  the next copy or clear. New with 57's fix.
- **What the manager needed.** On Windows it copies through uitoolkit.
- **Workaround.** None: the manager says the new copy could not be made
  (it asks `Cleared()` after copying), but cannot reach the one before.
- **Proposal.** End the copy being replaced only once the new one is
  made, or clear it when the new one is refused; wipe X11's `clipData`
  when the ownership is refused.
- **Done when:** a refused copy leaves the one before it cleared at its
  time. `TestItem86ABusyClipboardKeepsTheCopyBefore` pins today's order.

**Closed in 0.23.7** (the release notes, verbatim): **A refused copy left the one before it on the clipboard.** The copy being replaced was let go before the new one was tried, so where another program held the clipboard open for every try — and nothing on it changed — the previous secret stayed there with its timer stopped and nobody holding it: not cleared at its time, nor at the vault's lock, nor at the quit. The old copy is let go only once the new one is made now, and *cleared* rather than forgotten when the new one is refused. X11's served buffer is wiped on a refused ownership too, where it sat until the next copy.

**After v0.23.7: satisfactory** (39e4fa4); 60's refused copy is as it
was, never held and never timed, and the manager still says it could not
copy. `TestItem86ARefusedCopyClearsTheOneBefore`.

### 87. Nothing animates where the person's settings ask for less motion, whoever asks

- **Today** (`style/motion.go`, `Animations`; `widgets/flip.go`,
  `animates`). The person's "reduce motion" (`look.json`'s
  `reduceMotion`, `SetReduceMotion`) turns every animation of every
  uitoolkit program off, and nothing lets one component, or one turn, be
  animated over it: `UITK_ANIMATIONS=1` is the whole process's, and a
  flip panel asks `style.Animations()` alone.
- **What the manager needed.** The person keeps "reduce motion" on, and
  asked for the window to turn over to Settings all the same
  (2026-10-12): that one movement, the rest still.
- **Workaround.** The manager lifts the preference for the moment its
  turn starts and puts it back at once (`turn`,
  `gui/svmanager/flip.go`): a flip panel asks whether to animate as a
  turn starts and not again. Nothing else moves meanwhile.
- **Proposal.** A component's own say over its motion where the
  application has the person's word (`FlipPanel.Animate`, or
  `Window.Flip(animate bool)`), the preference staying the default.
- **Done when:** one turn can be animated where the preference says
  otherwise. `TestItem87NoAnimationOverReducedMotion` pins its absence.

**Closed in 0.23.7** (the release notes, verbatim): That preference is right for the motion that decorates — a hover fading in, a scroll bar fading out — and wrong for the motion that *is* the thing. A card that turns over to show it has a back, switched off, simply shows the back: the one cue that said "this is the same object, seen from behind" is gone, and the application had nothing it could say about it. […] `widget.MotionOf` reads the nearest word — the component's own, else an ancestor's, else the window's — so a dialog says it once and everything inside is covered. The preference stays the default, and `UITK_ANIMATIONS=0` still beats everything, because reproducible screenshots need one switch nothing overrides.

**After v0.23.7: satisfactory** (b076d9b). The manager's flip panel is
`style.MotionAlways` as it turns, and nothing else of the window says
anything, so the person's setting holds for the rest; the manager no
longer lifts the setting itself. `TestItem87MotionThatIsTheThingItself`.

### 88. A window panel's silhouette is not its window's shape

- **Today** (`widgets/panel.go`, `PaintClip`; `app/shape.go`,
  `lookShape`; `app/flip.go`, `clearFlipShape`). A `Panel` with `Window`
  clips its chrome to the outline the look gives a window, Hangar's cut
  corners among them; but the window under it takes a look's silhouette
  only where the toolkit draws its frame, and `Window.Flip`, which asks
  for a window with no frame and a window panel on each face, puts the
  window's shape back to none once a turn is over. So such a window
  stays a rectangle at rest: Hangar's three cut corners show the
  window's own ground.
- **What the manager needed.** Its window cut as its look cuts a window,
  at rest as well as while it turns.
- **Workaround.** None: the corners are the toolkit's.
- **Proposal.** Give a frameless window whose content is a window panel
  (or a flip panel of them) the panel's silhouette as its shape, and
  keep it once a turn is over.
- **Done when:** a window turned with `Window.Flip` in Hangar is cut at
  rest. `TestItem88AWindowPanelsSilhouetteIsNotItsWindowsShape` pins
  today's code.

**After v0.23.7: open, and unused**: the manager's window wears the
toolkit's frame again (77), and the frame's silhouette is the window's
shape. A frameless window with a window panel for its chrome still
stays a rectangle.

### 89. A panel's floor leaves out its chrome

- **Today** (`widgets/panel.go`; `widget/minwidth.go`, `MinWidthOf`). A
  `Panel` answers no `MinWidth` of its own, so the floor a window is
  given from it is its one child's, without the frame and the padding the
  panel puts round it.
- **What the manager needed.** Its window as wide as the editor needs at
  the narrowest, the window panel's chrome round it.
- **Workaround.** The manager adds the panel's chrome, its laid-out
  width less its content's, to its content's floor (`contentFloor`,
  `gui/svmanager/manager.go`).
- **Proposal.** `Panel.MinWidth`: its body's floor and its insets.
- **Done when:** a panel's floor holds its chrome.
  `TestItem89APanelsFloorLeavesOutItsChrome` pins its absence.

**Closed in 0.23.7** (the release notes, verbatim): **A panel's floor holds the chrome it draws.** Without one of its own the floor came out *too large*, not too small: `MinWidthOf` fell back to a splitter's fixed unbounded measure, so a window could not be made as narrow as its content allows.

**After v0.23.7: satisfactory, and unused**: the manager's window has
no window panel now (77). The two reports disagree on the sign: the
manager measured the floor 19 pixels too small, the editor's pane 475
wide for the 494 it needs at an 808-pixel window, where the maintainers
found it too large; a panel answers for its chrome either way now.
`TestItem89APanelsFloorHoldsItsChrome`.

## Found moving to v0.23.7

Moving the manager's turn onto `Window.Flip` of a framed window found
two. Each is pinned in `gui/uitoolkit_test.go`.

### 90. A flip panel passes a key to neither face

- **Today** (`app/flip.go`, `SetFlipFaces`; `widgets/flip.go`;
  `app/window.go`, `contentKey` and the title bar's keys).
  `SetFlipFaces` makes the flip panel the window's content root, which is
  where the window offers a key from its title bar, and a key with
  nothing focused; the panel has no `KeyPress` of its own, so neither of
  its faces hears it. An application's own keys, kept on its content
  root as the toolkit has it, are on a face now, and stop working from
  the title bar.
- **What the manager needed.** Its own keys (Ctrl+Page Up and Down for
  the next and the previous part, Escape back from Settings) with the
  keyboard on the title bar's buttons or breadcrumbs, as before the turn
  was the toolkit's.
- **Workaround.** Each of the title bar's groups (the logo, the
  breadcrumbs, the part's buttons, Settings) hands a key nothing in it
  took to the manager's keys (`keyRelay`, `gui/svmanager/titlebar.go`);
  the keyboard is kept on something in the window (`keepFocus`), so a key
  with nothing focused does not come up.
- **Proposal.** Offer a key the flip panel gets, and nothing in it took,
  to the face that is up.
- **Done when:** a key from the title bar of a window turned with
  `Window.Flip` reaches the face that is up.
  `TestItem90AFlipPanelPassesAKeyToNeitherFace` pins its absence.

**Closed in 0.23.8** (the release notes, verbatim): **A framed window always turned the same way**, and **a flip panel passed a key to neither face** (a password manager).

**After v0.23.8: satisfactory** (8ca4b6d): the flip panel offers a key
to the face that is up, so a key from the title bar, or with nothing
focused, reaches the manager's own keys on its content; `keyRelay` is
gone. `TestItem90AFlipPanelOffersAKeyToTheFaceUp`.

### 91. A framed window always turns the same way

- **Today** (`app/flip.go`, `turnWholeWindow`). A framed window's turn is
  a new flip panel each time, the picture of the window before as its
  front and the picture after as its back, turned with `Flip`: front to
  back, always. A flip panel turns back the way it came, one way to its
  back and the other way to its front (`show`, `dir`), so that a card
  retraces its turn; but the window's turn never asks which way its own
  flip panel is going, so every turn goes round the same way, to the
  back and back again alike.
- **What the manager needed.** Its window turning over to Settings and
  back the way it came, as a card is turned over and back.
- **Workaround.** None: the turn is the toolkit's, and nothing says its
  way from outside.
- **Proposal.** Turn the stand-in panel the way the window's flip panel
  goes: with the pictures as back and front, `ShowNow(true)` and then
  `ShowFront()`, where the window is coming back to its front.
- **Done when:** a framed window's turn back to its front goes the other
  way round. `TestItem91AFramedWindowAlwaysTurnsTheSameWay` pins today's
  code.

**Closed in 0.23.8** (the release notes, verbatim): **A framed window always turned the same way**, and **a flip panel passed a key to neither face** (a password manager).

**After v0.23.8: satisfactory** (a12ba05), as proposed: the stand-in
panel of the window's two pictures turns to its back where the window
goes to its back, and to its front where it comes back, so the window
turns to Settings one way and back the other.
`TestItem91AFramedWindowComesBackTheWayItWent`.

## Found looking again for what the manager works round (2026-10-13)

Two the manager had been working round since before v0.23.6, noted in
its code and never written down here. Each is pinned in
`gui/uitoolkit_test.go`.

### 92. One digit key

- **Today** (`platform/event.go`). The keys are the letters, the function
  keys, the arrows and the rest, and of the digits `Key3` alone. No
  widget can take Ctrl+1, 2 or 3, which is how a window steps to its
  first, second and third tab in every browser and most tabbed programs.
- **What the manager needed.** Its parts, Vault, Disk and Tools, and
  Settings' tabs, picked from the keyboard as tabs are: Ctrl+1, 2, 3.
- **Workaround.** Ctrl+Page Up and Down step through them, one at a time
  (`key`, `gui/svmanager/layout.go`).
- **Proposal.** `Key0` to `Key9`, mapped on every backend from the
  digit row (and the keypad's digits, with Num Lock).
- **Done when:** platform has the ten digits. `TestItem92OneDigitKey`
  pins today's one.

**Closed in 0.23.10** (the release notes, verbatim): `platform.Key` had the letters, the function keys, the arrows — and of the digits, `Key3` alone, sitting between `KeySpace` and `KeyHash` because those three characters are what an accelerator needed once. So `Ctrl+3` worked and `Ctrl+1` did nothing: the accelerator parser answered `KeyUnknown`, which matches no key event ever sent. `Key0`..`Key9` are a contiguous run now, so `Key0+n` is the nth, with `DigitKey` and `DigitRune` beside `LetterKey` and `KeyRune`.

**After v0.23.10: satisfactory** (398d343). Ctrl+1, 2 and 3 pick
Vault, Disk and Tools, and on the window's back Settings' tabs, beside
Ctrl+Page Up and Down (`key`, `gui/svmanager/layout.go`); Settings ›
Keyboard shortcuts says so. `TestItem92EveryDigitIsAKey`.

### 93. The icon set has no cloud, and an icon carries no badge

- **Today** (`style/icons.go`; `widgets/toolbar.go`, `ToolButton`). The
  set has a download arrow and a sync, but no cloud; and nothing puts a
  small mark on an icon's corner (a plus, a count), on a tool button or
  anywhere an icon is drawn.
- **What the manager needed.** A vault joined from a sync server, which
  comes down from a cloud; Unlock with…, a padlock with a plus (unlock
  with something else than the passphrase); New vault, the vault's mark
  with a plus.
- **Workaround.** The manager draws those three marks itself, in a tool
  button's content, in the look's text colour (`syncMark`,
  `lockPlusMark`, `newVaultMark`, `gui/svmanager/marks.go`). They reach
  its buttons alone; `style.RegisterIcon` (0.23.5) would make them icons
  of its own, for a menu or a breadcrumb too, which is the manager's to
  do.
- **Proposal.** `IconCloud` and `IconCloudDownload`; and a badge on an
  icon (`ToolButton.Badge`, or `style.DrawToolIconBadge`) for a plus,
  a dot or a count, drawn by the look.
- **Done when:** the set has a cloud and an icon can carry a badge.
  `TestItem93NoCloudAndNoBadge` pins their absence.

**Closed in 0.23.10** (the release notes, verbatim): `IconCloud` is an icon like the others, in all five premiere packs and drawn by both vector sets. […] A badge is a small mark over a corner: a plus for an action that adds, a dot for something waiting, a count for how many. It decorates a **box**, not a widget — a tool bar passes the button it has just had drawn, an application passes the icon it is drawing — which is what keeps thirty-four engines out of it, since where an icon sits inside a tool button is the look's business.

**After v0.23.10: satisfactory** (a097e91), by the proposal's second
way: a badge is drawn over a box (`style.DrawIconBadge`), which a tool
bar's item carries itself (`ToolItem.Badge`) and a lone tool button,
which the manager's are, draws in its content over the icon. Join a
synced vault is the cloud; Unlock with… is the toolkit's padlock with
its plus, and New vault the manager's logo with it (`plusBadge`,
`newVaultMark`, `gui/svmanager/marks.go`). The logo is the only mark the
manager draws now. `TestItem93ACloudAndABadge`.

## Found moving to v0.23.14

### 94. A framed window's turn cannot be held still from outside

- **Today** (`app/flip.go`, `turnWholeWindow`; `widgets/flip.go`,
  `SetClock`). v0.23.14 gave the flip panel a clock a test can hold
  (`SetClock`), so that a turn is stepped a frame at a time instead of
  raced over its 420 ms. A framed window, though, turns in a panel of its
  own, which `Flip` builds as the turn starts: it is handed the window
  flip panel's `Perspective` and `Strips`, not its clock, and nothing
  outside the package can reach it (uitoolkit's own test holds it as
  `win.turn`). So an application's test of a framed window's turn still
  races the wall clock.
- **What the manager needed.** Its test of the window turning over, frame
  and all, to see the window take the card's outline at a frame of the
  turn: under the race detector one frame of the window outlasts the whole
  turn, and the test saw none.
- **Workaround.** The test stands down that one check under the race
  detector (`raceOn`, `gui/svmanager/flip_test.go`), and makes it
  everywhere else.
- **Proposal.** Carry the window flip panel's clock to the panel the turn
  builds, as its perspective and strips are; or `Window.SetClock`, which
  holds a tooltip's time already, holding a turn's too.
- **Done when:** a clock set on the window's flip panel (or the window)
  holds a framed window's turn. `TestItem94AFramedWindowsTurnCannotBeHeldStill`
  pins its absence.

**Closed in 0.23.15** (the release notes, verbatim): 0.23.14 gave `FlipPanel` a clock a test can hold, so that a turn is stepped a frame at a time instead of raced over its 420 ms. It did not reach a framed window, which turns as one picture in a panel `Flip` builds as the turn starts: that panel was handed the perspective and the strips and nothing else, and nothing outside the package can reach it. […] The built panel takes the clock with the rest, and `FlipPanel.Clock` reads it back, which is what lets `app` carry it across the package boundary. The test here now holds the clock from outside, before `Flip`, the way an application would.

**After v0.23.15: satisfactory** (6100823), as proposed. The manager's
test holds the window flip panel's clock before the turn, steps it 30 ms
a frame, and sees the window take the card's outline, under the race
detector as everywhere else; `raceOn` is gone.
`TestItem94AFramedWindowsTurnTakesItsClock`.
