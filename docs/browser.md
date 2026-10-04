# secretvault's browser extension

secretvault has a browser extension of its own
([`browser/extension`](../browser/extension)). It fills and saves logins
in Firefox, and in Chrome, Chromium, Brave, Edge and Vivaldi, and every
login it reads goes through secretvault's consent broker, as any
program's request does.

- [Names](#names)
- [What it does](#what-it-does)
- [How it is built](#how-it-is-built)
- [The protocol](#the-protocol)
- [Threat model](#threat-model)
- [Trying it, and using it](#trying-it-and-using-it)
- [Chromium](#chromium)
- [The Public Suffix List](#the-public-suffix-list)

## Names

The names are in the code in two places: `svext`'s constants
([`svext/session.go`](../svext/session.go)) and the extension's
[`manifest.json`](../browser/extension/manifest.json) and
[`lib/protocol.js`](../browser/extension/lib/protocol.js). A test
(`svext/ids_test.go`) keeps the two in step. Change both before the
extension is published, if they are to change.

| What | Name |
| --- | --- |
| Firefox extension ID (`browser_specific_settings.gecko.id`) | `secretvault@codemodify.github.io` |
| Native-messaging host | `io.github.codemodify.secretvault` |
| Chromium extension ID (fixed by the manifest's `key`) | `bfikbjjlppgnacljfdjhfoiccclkpkde` |
| Protocol, as the host names it to the daemon | `secretvault-extension/1` |

The Chromium ID comes from the public key in `manifest.json`'s `key`
(see [The ID and its key](#the-id-and-its-key)).

## What it does

- **Marks login fields.** On a login form, the user name and password
  fields get a small secretvault mark at their right edge. The mark is
  drawn in a closed shadow root, so the page can neither restyle what is
  in it nor read it.
- **Shows the logins for the page in its own UI.** Clicking a mark opens
  the extension's panel under the field. The panel is an extension page
  in an iframe, which the page cannot read. The toolbar button, or
  Ctrl+Shift+L, opens the same panel as the toolbar popup. The list holds
  titles and user names, never passwords.
- **Fills the login chosen.** The user name and password go into the
  fields of the form whose mark was clicked; from the popup, into the
  focused login form, else the first one. Nothing is filled until the
  person chooses. In Firefox, a login chosen in the panel a mark opens is
  also confirmed in secretvault's own prompt, each time (the browser
  cannot say whether the page covered the panel); one chosen in the
  toolbar popup is not.
- **Fills one-time codes.** A login with a TOTP key shows a Code button.
  Its current code fills a one-time-code field. A login filled into a
  form that also has one gets the code as well.
- **Makes passwords.** On sign-up and change-password forms, "Fill a new
  password" fills every new-password field with a password from the
  managers' generator (`svops.GeneratePassword`: 24 characters,
  letters, digits and symbols).
- **Offers to save.** When a form with a password is sent, the
  extension asks secretvault whether that login is new, a changed
  password, or already known. For a new or changed one, the toolbar button
  shows a badge, and its popup offers Save or Update. Nothing about this
  shows in the page.
- **Shows secretvault's state.** The panel says when secretvault is not
  running or its host is not set up, and when the vault is locked. Its
  Unlock button makes the daemon ask for the passphrase in a window of
  its own; the extension never sees it. When there are several vaults, a
  list chooses one, the default first. Lock locks the vault.

## How it is built

```
 page ─ content.js (marks, fills)          panel.html (popup, or iframe in the page)
           │ runtime messages                    │ runtime messages
           └──────────────► background.js ◄──────┘
                                 │ native messaging (JSON frames)
                                 ▼
                 secretvault browser-host  (the CLI, started by the browser)
                                 │ JSON-RPC: browser.open, browser.message
                                 ▼
                 secretvaultd: svext.Session → vaults, consent broker, audit
```

- **The extension** is plain JavaScript (Manifest V3), with no npm
  packages and no bundler. Each file is one small script:
  - `background.js` holds the connection to the host. It is the only part
    that talks to secretvault, and decides what each sender may ask.
  - `content.js` runs in pages: marks, filling, forms sent.
  - `panel.html` and `panel.js` are the panel.
  - The pure parts are in `lib/` and tested under `node --test`
    ([`browser/test`](../browser/test)):
    - `origin.js` and `psl.js` match logins to origins;
    - `protocol.js` builds and checks messages;
    - `forms.js` tells what a form's fields are for;
    - `style.js` tells whether CSS hides something.
- **The host** is the secretvault CLI. The browser starts it by the
  manifest `io.github.codemodify.secretvault.json`, which
  `secretvault browser install` writes. It checks every request
  ([`svext.ParseRequest`](../svext/protocol.go)) and answers `generate`
  itself. It passes everything else to the daemon and the answers back
  ([`cmd/secretvault/browser_ext.go`](../cmd/secretvault/browser_ext.go)).
  It holds nothing between requests.
- **The daemon** answers from the vaults
  ([`svd/browser_ext.go`](../svd/browser_ext.go)):
  - it identifies the browser itself, as the host's parent process;
  - it decides every read and write with the consent broker, as for any
    program;
  - it writes each decision to the audit log.
- **The package**, `.zip` or folder, is made from the copy every
  secretvault program carries (package [`browser`](../browser) embeds
  it), for Firefox or for Chromium, each with its own manifest
  ([Chromium](#chromium)). The CLI makes it with `secretvault browser
  extension`, the GUI with Desktop › Browsers › Save the extension…,
  and the TUI with `B` then `e`.

## The protocol

Version 1. Each message is one native-messaging frame: a 4-byte length in
the machine's byte order, then that many bytes of UTF-8 JSON
([`svext.ReadFrame`](../svext/frame.go)). Every message is an
object with `"v": 1`.

```
request   {"v":1, "id":"r7", "op":"logins", "vault":"", "origin":"https://github.com"}
answer    {"v":1, "id":"r7", "ok":true, "origin":"https://github.com", "logins":[...]}
refusal   {"v":1, "id":"r7", "ok":false, "error":"locked", "message":"vault \"personal\" is locked"}
event     {"v":1, "event":"vault", "vault":"personal", "locked":true}
```

- **`id`** is the extension's: 1 to 64 letters, digits, `.`, `_` or
  `-`. The answer carries it. A refusal of a request whose `id` could not
  be read has `"id": ""`.
- **`vault`** is a vault's name; `""` or none means the default vault.
- **`origin`** is the page's origin exactly as browsers write it
  (`location.origin`): `http` or `https`, the host in lower case and in
  its ASCII form, the port only when it is not the default. Nothing else:
  no path, no trailing slash.
- **`login`** is an item's ID, 32 lower-case hex digits, as `logins`
  gave it.

| op | members (required in bold) | answer |
| --- | --- | --- |
| `hello` | `extension` (its version) | `protocol` (1), `secretvault` (its version), `browser` (how prompts name the browser) |
| `state` | | `vaults`: `[{name, locked, default}]`, the default first |
| `unlock` | `vault` | `vaults`; the daemon asks for the passphrase on the desktop |
| `lock` | `vault` | `vaults` |
| `logins` | **`origin`**, `vault` | `origin`, `logins`: `[{id, title, username, url, match, totp}]`, best first, at most 200. `match` is `host` or `site`; `url` is the stored URL that fits; `totp` says the login has a code. No passwords. |
| `fill` | **`origin`**, **`login`**, `vault`, `confirm` (ask the person every time, whatever was remembered) | `username`, `password`, and `totp` (the current code) when the login has a key |
| `totp` | **`origin`**, **`login`**, `vault`, `confirm` | `code` |
| `check` | **`origin`**, **`password`**, `username`, `vault` | `status`: `new`, `changed` (with `login`, a login of the page's very host with that user name and another password) or `known` (with `login`) |
| `save` | **`origin`**, **`password`**, `username`, `login` (to change that login), `title`, `vault` | `login`, `created` |
| `generate` | `length` (8 to 128, default 24), `symbols` (default true) | `password` (answered by the host) |

**Events**, sent unasked:

- `{"v":1,"event":"vault","vault":NAME,"locked":BOOL}` when any vault locks
  or unlocks.
- `{"v":1,"event":"down","error":"not-running","message":...}` just
  before the host stops because secretvault cannot be reached.

**Errors** (`error`):

| `error` | Meaning |
| --- | --- |
| `bad-request` | not a request: its shape, a member it does not take, a type, a length |
| `too-large` | over 64 KiB |
| `unknown-op` | no such operation |
| `busy` | eight requests already wait (on a person, say) |
| `not-running` | secretvault cannot be reached |
| `no-vault` | no such vault |
| `locked` | the vault is locked |
| `not-found` | no such login, or one that does not fit the origin |
| `denied` | the person said no, or nobody could be asked |
| `failed` | anything else |

**Limits.** A request is checked whole before anything acts on it:

- **Size.** At most 64 KiB. A frame over 1 MiB, the browser's own
  limit, ends the host, because the stream cannot be read past it.
- **Shape.** Exactly one JSON object, with nothing after it, and only
  the members its operation takes.
- **Strings.** Strings must be strings, and numbers whole numbers.
  Text has no control characters. Lengths:

  | Member | At most |
  | --- | --- |
  | `origin` | 1,024 bytes |
  | `vault` | 256 bytes |
  | `username` | 1,024 bytes |
  | `password` | 4,096 bytes of UTF-8, no lone surrogates |
  | `title` | 256 bytes |

The extension builds its requests to the same rules (`lib/protocol.js`).
The host checks each request, and the daemon checks it again.

**Matching.** A login fits a page by one of its stored URLs: its URL
fields (type `url`, or named `url`, `url2`... or `website`) and its `url`
and `*_url` attributes.

- **The scheme.**
  - A login kept for https is never offered to http.
  - One kept for http is offered to https on the same host and the
    default ports, an upgrade.
  - A stored URL without a scheme is https.
  - Only http and https count.
- **The port.** A stored port must be the page's. A stored URL without
  one fits only the scheme's default port.
- **The host.**
  - `host`: the page's own host.
  - `site`: another host with the same registrable domain by the
    [Public Suffix List](#the-public-suffix-list), both of its sections.
    So `login.example.co.uk` fits `www.example.co.uk`; `alice.github.io`
    does not fit `bob.github.io`; and `co.uk` fits nothing but itself.
  - IP addresses and one-label names (`localhost`) fit only themselves.
  - Names are compared in their ASCII form: `bücher.example` fits
    `xn--bcher-kva.example`.

Go ([`svext/origin.go`](../svext/origin.go)) and JavaScript
(`lib/origin.js`) have the same rules and the same test cases.

## Threat model

secretvault's own threat model is in [security.md](security.md). This
section covers what the extension adds. It is enforced in the files named.

### What is protected

- the logins in the vaults: their passwords and one-time codes most;
- what the vault holds for which sites (titles and user names);
- the person's decisions: what a site gets, and when.

### Who is in play

| Who | Trusted with | Not trusted with |
| --- | --- | --- |
| The person | everything | |
| The browser | the extension's isolation; telling the extension each sender's tab, frame and URL; starting the host only for the extensions its manifest names | the vault: it is a program like any other to the broker |
| The extension | the page's origin (the browser's word, passed on); a login it was given to fill | anything it is not given; it holds no secret beyond a fill |
| The host (secretvault's CLI) | carrying requests | deciding anything |
| secretvaultd | everything in the vaults | |
| A web page | nothing | anything at all |
| Another extension | nothing | starting the host (the manifest lets only ours), messaging ours (it takes no outside messages) |
| Another program running as the person | see [security.md](security.md#programs-running-as-you) | |

### Trust boundaries

1. **The page and the extension.**
   - A page reaches nothing of the extension's except the DOM it shares
     with the content script, and the iframe it cannot read.
   - The content script never holds the list of logins.
   - The content script gets a login only to fill it, after the person
     chose it in the extension's own UI. It does not keep it.
2. **The content script and the background.** The background decides
   which frame may be served from what the browser says of each sender
   (`sender.tab`, `sender.frameId`, `sender.url`), never from what the
   page or the content script says. A frame of another origin than its
   tab's page gets no marks, no panel and no fills.
3. **The extension and the host.** The browser starts the host only for
   the extension the manifest names: `allowed_extensions` is our Firefox
   ID alone, and `allowed_origins` our Chromium origin alone.
   - The host checks the ID the browser passes again. Started by our
     manifest for any other extension, it refuses.
   - Started by Chromium for any other extension, it refuses.
4. **The host and the daemon.**
   - The daemon opens a browser session only for secretvault's own
     binary, and only for our extension's ID with this protocol.
   - It identifies the browser itself (the host's parent process), and
     names it in every prompt and audit entry.
   - It checks every request again.
5. **The origin.** The page's origin is the extension's word, which is
   the browser's: the background takes it from the browser's URL of the
   tab, never from the page. The daemon cannot check it. So a prompt's
   "for https://github.com" is as good as the browser and the extension
   are. A compromised extension, or a browser running as someone else's
   code, could name any origin for any page (see
   [What is not stopped](#what-is-not-stopped)).

### Properties, and where they are enforced

- **Logins match by origin** (above): in the daemon (`fit`, using
  `svext.MatchURL`), which offers only logins that fit and refuses to
  fill, change or give the code of one that does not; and again in the
  background before a list is shown.
- **Never into a cross-origin iframe.** The background serves a frame
  only when its origin is its tab page's origin (`served`). The content
  script checks `location.origin` against the origin the login was chosen
  for before it fills, and the background checks the tab still shows it
  (`stillThere`) both before it asks for the login and after.
- **Never into fields that cannot be seen.** Before filling, every field
  to fill must be:
  - connected, enabled and not read-only;
  - at least 8×8 pixels, with an opacity of at least 0.2 down its
    ancestors;
  - not hidden by CSS, not clipped or masked, under no hiding filter
    (a low opacity, brightness or contrast, blur, or any SVG filter),
    with text that is not transparent;
  - uncovered at its middle and at one of its sides, by hit testing
    (`visible`, `onScreen`), which a cover with `pointer-events: none`
    passes.

  All the fields are filled, or none.
- **No fill on page load.** Nothing is filled but in answer to a choice
  in the panel or the popup. Nothing is read from secretvault when a page
  loads; even listing waits for the person to open the panel.
- **A page cannot trigger a fill, nor read the list.**
  - Only the extension's own pages (`panel.html`) can ask for a list or a
    fill. The background tells them from content scripts by the sender's
    URL, and a page cannot message the extension at all.
  - A mark takes only a click the browser marks as the person's
    (`isTrusted`).
  - The list lives in an extension-origin iframe, or in the browser's
    popup.
  - A panel in a page holds a token made for that tab, frame, field and
    origin when its mark was clicked:
    - it is bound to the first frame that uses it;
    - it lapses after a minute unused, or ten minutes in all;
    - it is dropped when a new page's content script starts in the tab
      (a page changed within the same document keeps its origin, which
      every fill checks).
- **Clickjacking.** A page owns the elements that hold the marks and the
  panel, and could restyle, move or cover them to trick a click. A mark
  only opens the panel, which holds no secret, so what matters is a
  choice made in the panel. It is defended in layers:
  - **A choice in a panel inside the page is vouched for or confirmed.**
    - In Chromium, the browser vouches for it: the panel takes no click
      while IntersectionObserver v2 says anything covers or alters it.
    - Where the browser cannot vouch (Firefox has no
      IntersectionObserver v2), a login or code chosen in an in-page
      panel is confirmed by secretvault's own prompt every time, in a
      window of its own that no page can draw on. Keystrokes do reach
      it, so it says no by default: Deny is first, which a plain
      pinentry makes its OK (Enter), and Escape denies too. A remembered
      "always" does not skip it; a remembered "no" still refuses. Choices
      in the toolbar popup are not confirmed this way.
  - **Our elements go in the top layer** (a manual popover), above the
    page's content. They are shown only while they are open there and
    children of `<html>`. One the page restyles, or takes out of
    `<html>`, is removed. One it takes out of the top layer is removed
    when we hear of it (its `beforetoggle`), and is not trusted anyway,
    as below.
  - **A mark takes a click only when all of these hold:**
    - it has stood still for 400 ms (and, from the keyboard, has held
      the focus that long);
    - nothing of the page's is in the top layer (popovers, modal
      dialogs, a full-screen element, in shadow roots too where the
      browser shows them to extensions) that the mark was not raised
      over, nor shown since as far as the browser signals it (its toggle
      events, which a re-shown popover in a shadow root, or a dialog in
      browsers before Chrome 132 and Firefox 133, does not send); and no
      view transition is running;
    - it is open in the top layer, a child of `<html>`, styled as set, and
      the size it was given times the page's zoom, and at least 12 pixels
      (not shrunk or scaled);
    - neither it nor `<html>` is see-through, filtered, clipped or
      masked, and the mark is not transformed;
    - the page has given none of our elements a `::before` or `::after`
      that paints anything, nor a `::backdrop` that is not see-through;
    - the pointer is on it.
  - **The panel in a page:**
    - it closes when its field moves;
    - it takes no click for 500 ms after it shows;
    - before a choice in it is acted on, the content script confirms the
      panel is still as it was put, by the checks above. That is when it
      is asked, a moment after the click, which is why Firefox also
      confirms;
    - it focuses nothing by itself.
  - **The popup** is the browser's own window, which no page can cover.
- **Nothing in the page depends on what secretvault holds.** Whether a
  login sent is new, changed or known shows only on the toolbar button. A
  page that sends guesses through its own form learns nothing. The check
  is also limited:
  - three a tab every ten seconds;
  - only for what the person did: a trusted event, with user activation,
    and for a form sent, the person pressed or typed in it within the
    last three seconds (a script's `requestSubmit()` alone does not
    count);
  - never in private windows.
- **Consent stays secretvault's.**
  - Listing a page's logins is listing the vault (`OpList`), decided and
    remembered as for any program. So is `check`.
  - Each fill or code is a read of that login (`OpRead`), prompted unless
    a decision is remembered.
  - A login filled on another host of its site than its own, or chosen
    in an in-page panel the browser could not vouch for (`confirm` in the
    protocol), is asked about every time, whatever was remembered, but a
    remembered no.
  - Saving is a write (`OpWrite`). Only a login of the page's very host
    can be changed from it. The browser may then read, change and delete
    the login it saved.
  - Every decision is in the audit log.
- **Secrets cross only on the person's action, to the matched origin,
  and are not kept.**
  - A fill's login goes from the daemon through the host to the
    background, which sends it to the frame it was chosen for, and lets
    it go. The content script drops it once filled.
  - A password a page sent, held for a save offer, stays in the
    background's memory for two minutes at most, and is never stored.
  - The panel never holds a password.
  - JavaScript strings cannot be wiped, so "let go" means unreferenced,
    not zeroed. In Go, passwords stay in byte slices that are wiped
    ([security.md](security.md) says how far that goes).
- **Never logged.** No part logs a request's contents: the extension
  logs nothing, and the host and the daemon log only errors and session
  starts.
- **No remote code.** The extension pages' Content Security Policy is
  `default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
  connect-src 'self'; base-uri 'none'; form-action 'none'; object-src 'none'`.
  It loads nothing from the network, has no `eval`, no inline script, and
  no `innerHTML`; the panel puts text into the page with `textContent`.
  Its permissions are `nativeMessaging` and `storage` (the chosen vault's
  name; and, in `storage.session`, the panels' state, which holds no
  secret), and host access to http and https pages for its content
  script.

### What is not stopped

- **A compromised browser, extension or profile** can name any origin
  and ask for anything the person allows the browser. The broker still
  asks, and logs. "Always" for a login means "always, for this browser,
  on its site".
- **A page on the login's own origin** (or one with XSS there) gets the
  password once it is filled. That is what filling is.
- **Other hosts of a site.** A login is offered on the other hosts of its
  registrable domain, though asked about every time there. Sites that
  host other people's pages on subdomains of their own domain without
  listing it in the Public Suffix List (a university's `~user` pages on
  its own domain) share a site with their login pages. Store such logins
  with their exact host, and refuse what is asked elsewhere.
- **Clickjacking a mark is made hard, not impossible.** A page could
  still draw a convincing lure around a real mark, or find a way over it
  that the checks miss (a closed shadow root the browser hides even from
  extensions, say). What a mark opens is a list, and a choice in it is
  vouched for by the browser (Chromium) or confirmed by secretvault
  (Firefox). The popup (toolbar button, Ctrl+Shift+L) is the safest way
  in.
- **Fields covered with `pointer-events: none`.** Hit testing does not
  see such a cover, so a field under one is filled. The page filled is
  the login's own origin, which gets the password anyway once the person
  logs in; the risk is a login filled where the person did not see it.
- **The panel moving with the page.** It closes when its field moves.
  It does not follow scrolling, so scrolling the page closes it: click
  the mark again.
- **Telling that the extension is installed.** The panel is loaded by a
  URL that changes every session in Chromium (`use_dynamic_url`), and by
  a per-installation UUID in Firefox, so a page cannot probe for it. But
  the marks are elements in the page's DOM, which a page can see once
  they are put next to its login fields.
- **An unpacked extension claiming our ID.** In Chromium the ID is the
  hash of a public key, which anyone can copy into a manifest of their
  own: whoever can load an unpacked extension into the profile (in
  Developer mode) can load one with our ID, which the host's manifest
  then lets start secretvault. That takes the power to change the
  person's browser profile, which a program running as the person has
  anyway; the broker still asks and logs, naming the browser.
- **What other software on the machine can do**, as for every face:
  [security.md](security.md#what-a-prompt-can-and-cannot-stop).

## Trying it, and using it

1. **Set the browsers up**, which writes the host's manifest naming the
   secretvault CLI:

   ```console
   $ secretvault browser install --dry-run   # what would change
   $ secretvault browser install             # for every browser used here; --browser firefox for one
   $ secretvault browser status              # which program each browser starts
   ```

   Desktop › Browsers › Set up… in the desktop manager, and `B` then `i`
   in the terminal manager, do the same. `secretvault browser uninstall`
   undoes it exactly.

2. **Write the extension out**, for one family of browsers (`--target`;
   each gets its own manifest, see [Chromium](#chromium)):

   ```console
   $ secretvault browser extension                       # Firefox: secretvault-extension-0.1.0.zip, here
   $ secretvault browser extension --out /tmp/sv.zip
   $ secretvault browser extension --dir /tmp/sv-ext     # Chromium: a folder for Load unpacked
   $ secretvault browser extension --target chromium     # Chromium: secretvault-extension-0.1.0-chromium.zip, for the Chrome Web Store
   $ secretvault browser extension --target firefox --dir /tmp/sv-ff
   ```

   Without `--target`, a folder is for Chromium and a zip for Firefox.
   The desktop manager (Desktop › Browsers › Save the extension…) and the
   terminal manager (`B` then `e`) offer the same three: a .zip for
   Firefox, a folder for Chromium, a .zip for the Chrome Web Store.

3. **Load it in Firefox, for testing:**
   - open `about:debugging`;
   - choose **This Firefox**, then **Load Temporary Add-on…**;
   - choose the `.zip` (or `manifest.json` in a folder of it).

   It stays until Firefox restarts. To use it on sites, it needs its
   host permission: in `about:addons` › secretvault › Permissions, allow
   "Access your data for all websites" if it is off. The toolbar button
   may be in the extensions menu (the puzzle piece): pin it there.
   Ctrl+Shift+L opens it; `about:addons` › ⚙ › Manage Extension
   Shortcuts changes that.

4. **For every day, on release Firefox**, the extension must be signed by
   Mozilla: release Firefox installs only signed add-ons. Self-distribution
   ("unlisted") gets it signed without listing it on addons.mozilla.org
   (AMO). It needs an AMO account, so it is the person's to do. Nothing
   here signs or uploads anything.
   1. Sign in at <https://addons.mozilla.org/developers/> with a Firefox
      account, and accept the developer agreement.
   2. Choose **Submit a New Add-on**, then **On your own** (unlisted).
   3. Upload the `.zip` from `secretvault browser extension`. AMO checks
      it automatically; the extension has no remote code and needs no
      source upload, since nothing in it is generated or minified.
   4. Once validated, download the signed `.xpi`, and open it in Firefox
      (File › Open File…, or drag it in), which installs it for good.
   5. For a new version, raise `version` in `manifest.json`, write the
      package again, and upload it as a new version of the same add-on.

   Mozilla's command-line tool `web-ext sign` does steps 2 to 4 with AMO
   API keys, if that is preferred.

   **The ID belongs to whoever signs it first.** Extension IDs are
   global on AMO: the first account to sign `secretvault@codemodify.github.io`
   owns it, and nobody else can sign that ID again. So the project's own
   account should claim it, by signing the first release, and publish the
   signed `.xpi` for everyone. Anyone who builds and signs their own must
   use an ID of their own in `manifest.json`, `svext.FirefoxID` (which the
   host's manifest allows, and the host and the daemon check), and
   rebuild secretvault. Keep the ID stable: a new one is a new add-on.

## Chromium

The extension is one source tree, and works in Chrome, Chromium, Brave,
Edge and Vivaldi (version 121 and later) as in Firefox (128 and later).

### Loading it in Chrome, Chromium or Brave

1. Set the browser up, once: `secretvault browser install --browser
   chromium` (or `chrome`, `brave`, `edge`, `vivaldi`; with no
   `--browser`, every browser used here). Restart the browser if it was
   running.
2. Write the extension as a folder:
   `secretvault browser extension --target chromium --dir ~/secretvault-extension`.
3. Open `chrome://extensions` (`brave://extensions` in Brave,
   `edge://extensions` in Edge), turn on **Developer mode**, choose
   **Load unpacked**, and choose that folder.
4. Pin the toolbar button from the extensions menu (the puzzle piece) if
   you want it in sight. Ctrl+Shift+L opens it; `chrome://extensions/shortcuts`
   changes that.

The extension's ID is `bfikbjjlppgnacljfdjhfoiccclkpkde` in every
Chromium browser: the manifest's `key` fixes it, and the host's manifest
lets only that ID start secretvault. A newer secretvault writes a newer
extension: write the folder again and choose the reload button on its
card in `chrome://extensions`.

### What differs from Firefox, and how it is handled

- **The manifest.** `manifest.json` in the source holds what both
  families need. `secretvault browser extension` writes each family's
  own (`svops.ExtensionManifest`), so neither warns about what it does
  not read:
  - for Chromium, without `browser_specific_settings` (Firefox's ID) and
    `background.scripts`;
  - for Firefox, without `key`, `minimum_chrome_version`,
    `background.service_worker` and `use_dynamic_url`.
- **The background is a service worker.** Chromium stops it after 30
  seconds without events (and Firefox suspends its event page the same
  way). Its listeners are registered when it starts, it imports its
  modules itself (`importScripts`), and what a panel or a frame relies on
  (which frames are served, the panels' tokens, what each panel was shown)
  is kept in `storage.session`: in memory only, for this browser session,
  readable only by the extension's own pages and its background, and
  read back before any message is answered. A save offer's password is
  not kept there: if the background stops, the offer is lost and its
  badge cleared, which errs on the side of keeping nothing. While a
  request waits on secretvault (a prompt the person answers), the open
  native-messaging port keeps the worker running; once it stops, the
  host exits, and the next request starts it again.
- **`browser.*` and `chrome.*`.** The scripts use `browser` where there
  is one (Firefox) and `chrome` otherwise; everything they call returns a
  promise in both (Chromium's `chrome.*` do in Manifest V3). A native host
  that is not set up is seen the same way in both: the port disconnects,
  with `chrome.runtime.lastError` in Chromium and the port's `error` in
  Firefox.
- **Content scripts** are declared in the manifest; the extension does
  not use the `scripting` permission.
- **The panel's URL.** `web_accessible_resources` has
  `use_dynamic_url`: in Chromium, a page can load the panel only by a URL
  that changes every browser session, which the extension's content
  script gets from `runtime.getURL` and a page cannot guess. So a page
  cannot load the panel itself, or tell from its static URL that the
  extension is installed. Inside, the panel still has the extension's own
  URL, which is how the background tells it from a content script.
  Firefox gives each installation its own random UUID instead.
- **The toolbar popup and the shortcut** are the manifest's `action` and
  `_execute_action`, the same in both.
- **The marks and the panel** are in closed shadow roots in the top layer
  (popovers), as in Firefox. Closed shadow roots of the page's are seen
  through `chrome.dom.openOrClosedShadowRoot` in Chromium and
  `openOrClosedShadowRoot` in Firefox.
- **IntersectionObserver v2** (whether anything covers the panel) is
  Chromium's alone. In Firefox, a login chosen in an in-page panel is
  confirmed by secretvault's prompt instead.

### The host's manifest

`secretvault browser install` writes `io.github.codemodify.secretvault.json`
for each Chromium browser with `allowed_origins` naming
`chrome-extension://bfikbjjlppgnacljfdjhfoiccclkpkde/` alone (and Firefox's
with `allowed_extensions` naming the Firefox ID alone). On Linux:

| Browser | Folder |
| --- | --- |
| Chrome | `~/.config/google-chrome/NativeMessagingHosts` |
| Chromium | `~/.config/chromium/NativeMessagingHosts` |
| Brave | `~/.config/BraveSoftware/Brave-Browser/NativeMessagingHosts` |
| Edge | `~/.config/microsoft-edge/NativeMessagingHosts` |
| Vivaldi | `~/.config/vivaldi/NativeMessagingHosts` |

(`$XDG_CONFIG_HOME` in place of `~/.config` where it is set.) On macOS
they are under `~/Library/Application Support`, and on Windows a
registry key under HKEY_CURRENT_USER names the manifest; Brave and
Vivaldi read Chrome's key there. Those two are tested in temporary homes
only.

Limits:

- **A profile elsewhere.** Chromium started with `--user-data-dir` reads
  `NativeMessagingHosts` in that folder, not in `~/.config/chromium`;
  Brave reads its usual folder whatever the profile.
- **Flatpak and Snap browsers are not supported.** A Flatpak Chrome or
  Chromium (`com.google.Chrome`, `org.chromium.Chromium`) reads host
  manifests from `~/.var/app/ID/config/...` and starts the host inside its
  sandbox, where neither the secretvault program nor the daemon's socket
  can be reached; the Snap Chromium (`~/snap/chromium/...`) is confined the
  same way. Making them work would mean opening the sandbox
  (`flatpak-spawn --host`), which is the person's call, not secretvault's.
  `secretvault browser install` writes nothing for them.

### Publishing in the Chrome Web Store

Publishing needs a Chrome Web Store developer account (a one-time
registration fee), so it is the person's to do. Nothing here uploads
anything.

1. Register at <https://chrome.google.com/webstore/devconsole>.
2. Write the package: `secretvault browser extension --target chromium`
   (`secretvault-extension-0.1.0-chromium.zip`). Its manifest is
   Chromium's without the `key`, which the store does not take in a
   manifest (`svops.ExtensionStoreManifest`); a folder for Load unpacked
   keeps it.
3. To publish under the ID the host's manifest allows, the store has to
   be given the ID's private key with the first upload (see below): add
   it at the root of a copy of the zip as `key.pem` (`zip -j copy.zip
   key.pem`), and upload that copy as a new item (**Add new item**). The
   store keeps the ID and drops the key. Delete that copy once it is
   uploaded, and never leave `key.pem` in the extension's folder or in any
   other package. If the dashboard will not take
   it, the store gives the item an ID of its own: then put the public key
   the dashboard shows (Package › View public key) in `key`, the new ID in
   `svext.ChromeID` (`svext/ids_test.go` checks the two agree), and build
   secretvault again, so the host's manifest allows the store's ID.
4. Fill in the listing and the privacy form. It asks why each permission
   is needed: `nativeMessaging`, to reach secretvault on the same
   computer; `storage`, for the chosen vault's name and the panels'
   short-lived state; host access to http and https pages, to mark and
   fill login fields there. The extension collects no data and loads no
   remote code.
5. Submit it for review. For a new version, raise `version` in
   `manifest.json`, write the package again, and upload it to the same
   item (the key is not needed again).

### The ID and its key

The Chromium ID `bfikbjjlppgnacljfdjhfoiccclkpkde` is derived from the
public key in `manifest.json`'s `key`. Its private key is **not** in this
repository, and must never be committed. Whoever holds it can:

- publish an extension under this ID in the Chrome Web Store, if nobody
  has yet (the first upload claims the ID for that account);
- sign `.crx` packages that Chromium installs under this ID.

So keep it offline, with the project's release keys, until the first
store upload; after that the store holds the ID, and the key is needed
only to sign packages outside the store. Losing it means a store item
gets an ID of its own (step 3 above says what to change). Note that the
ID is not a secret and proves nothing to a browser in developer mode:
anyone who can load an unpacked extension into the profile can give it
this public key, and so this ID (see [What is not stopped](#what-is-not-stopped)).

### Testing it in a real browser

`TestTheExtensionFillsInChromium` (`cmd/secretvault/browser_e2e_test.go`)
runs the extension in a headless Chromium (`--headless=new`), in a home
and profile of its own under the test's temporary directory, kept off
the session bus and the system keyring. It writes the extension as
`--target chromium --dir` does, and the host's manifest as `browser
install` does, in that home; the host the browser starts is the test
binary, speaking to a daemon in the test, whose prompts the test
answers. It drives the browser over the DevTools protocol on a pipe
(`--remote-debugging-pipe`, `internal/cdptest`), clicking as a mouse
would, and checks that the marks come, that a login chosen in the panel
is filled after secretvault is asked, that this still works after the
service worker was stopped (with the panel's token still bound to its own
frame), and that a frame of another origin gets
neither marks nor a fill. It runs when `chromium` is installed (or
`SECRETVAULT_TEST_CHROMIUM` names a browser: Brave passes too), and not
with `-short`.

## The Public Suffix List

The list is bundled as `browser/extension/data/public_suffix_list.dat`,
fetched from <https://publicsuffix.org/list/public_suffix_list.dat>
(Mozilla Public License 2.0). The extension reads it, and so does
secretvaultd, which embeds it (package `browser`). There is one copy.

To refresh it:

```console
$ scripts/update-psl.sh
$ go test ./svext ./browser     # the list's own test vectors, in Go and under node
```

Then commit the file. The script refuses a download that is not the
whole list. A newer list changes which hosts count as one site, so
refresh it now and then, and before a release.
