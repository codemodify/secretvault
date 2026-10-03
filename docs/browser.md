# secretvault's browser extension

secretvault has a browser extension of its own
([`browser/extension`](../browser/extension)). It fills and saves logins
in Firefox, and in Chrome, Chromium, Brave, Edge and Vivaldi, and every
login it reads goes through secretvault's consent broker, as any
program's request does.

Before it, browsers reached secretvault through KeePassXC's extension,
KeePassXC-Browser, with secretvault standing in for KeePassXC. That
legacy link still works. It is removed once the extension has replaced
it; [the plan](#removing-the-keepassxc-browser-link) is at the end.

- [Names](#names)
- [What it does](#what-it-does)
- [How it is built](#how-it-is-built)
- [The protocol](#the-protocol)
- [Threat model](#threat-model)
- [Trying it, and using it](#trying-it-and-using-it)
- [Chromium](#chromium)
- [The Public Suffix List](#the-public-suffix-list)
- [Removing the KeePassXC-Browser link](#removing-the-keepassxc-browser-link)

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

The Chromium ID comes from the public key in `manifest.json`'s `key`. Its
private key was not kept: it is needed only to publish in the Chrome Web
Store under that ID. To publish there, make a key pair of your own, put
its public half in `key`, and change `svext.ChromeID` to the ID it gives
(the test says which).

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
  it). The CLI makes it with `secretvault browser extension`, the GUI
  with Desktop › Browsers › Save the extension…, and the TUI with `B`
  then `e`.

## The protocol

Version 1. Each message is one native-messaging frame: a 4-byte length in
the machine's byte order, then that many bytes of UTF-8 JSON
([`svbrowser.ReadFrame`](../svbrowser/frame.go)). Every message is an
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
   - Started by Chromium for an extension that is neither ours nor
     KeePassXC-Browser, it refuses.
   - The KeePassXC-Browser relay never serves our extension.
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
      window of its own that no page can reach. A remembered "always"
      does not skip it; a remembered "no" still refuses. Choices in the
      toolbar popup are not confirmed this way.
  - **Our elements go in the top layer** (a manual popover), above the
    page's content. They are shown only while they are open there and
    children of `<html>`. One the page restyles, or takes out of
    `<html>`, is removed. One it takes out of the top layer is removed
    when we hear of it (its `beforetoggle`), and is not trusted anyway,
    as below.
  - **A mark takes a click only when all of these hold:**
    - it has stood still for 400 ms (and, from the keyboard, has held
      the focus that long);
    - the page has put nothing in the top layer since the mark was
      raised over what was there: popovers, modal dialogs or a
      full-screen element, in shadow roots too where the browser shows
      them to extensions; and no view transition is running;
    - it is open in the top layer, a child of `<html>`, styled as set and
      the size it was given (not zoomed or scaled);
    - neither it nor `<html>` is see-through, filtered, clipped or
      masked, and the mark is not transformed;
    - the page has given none of our elements `::before`, `::after`, or
      a `::backdrop` that is not see-through;
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
    the login it saved, as with KeePassXC-Browser.
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
  name), and host access to http and https pages for its content script.

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
- **Fingerprinting on Chromium.** The panel is web-accessible, and the
  Chromium ID is fixed, so a page can tell the extension is installed
  (`use_dynamic_url` is not used: see [Chromium](#chromium)). Firefox
  gives each installation its own internal UUID.
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
   in the terminal manager, do the same. `secretvault browser uninstall
   --extension` undoes it exactly.

2. **Write the extension out:**

   ```console
   $ secretvault browser extension                       # secretvault-extension-0.1.0.zip, here
   $ secretvault browser extension --out /tmp/sv.zip
   $ secretvault browser extension --dir /tmp/sv-ext     # a folder, for Chromium
   ```

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

The extension is the same, and works in Chrome, Chromium, Brave, Edge and
Vivaldi, with these gaps:

- **Loading.** Use **Load unpacked** on a folder:
  - `secretvault browser extension --dir DIR`;
  - open `chrome://extensions` and turn on Developer mode;
  - choose **Load unpacked**, then the folder.

  The `key` in the manifest gives it the ID the host's manifest allows.
  Publishing in the Chrome Web Store needs its own key ([Names](#names)).
- **The manifest.**
  - It has `background.scripts` for Firefox and `background.service_worker`
    for Chromium. Chromium 121 and later take both; older ones refuse it.
  - Chromium warns about `browser_specific_settings`, and Firefox about
    `key` and `minimum_chrome_version`; both ignore them.
- **The service worker** may be stopped while idle. A save offer waiting
  in it is then lost, which errs on the side of keeping nothing. The open
  native-messaging port keeps it running while the host is.
- **`use_dynamic_url`** is left out of `web_accessible_resources`. With
  it, the panel's URL changes per session, and pages cannot detect the
  extension. But the extension would have to load the panel by that
  dynamic URL, and the background tells its pages from content scripts
  by `runtime.getURL`.
- **IntersectionObserver v2** (whether anything covers the panel) is
  Chromium's alone. In Firefox, a login chosen in an in-page panel is
  confirmed by secretvault's prompt instead.
- **Windows and macOS.** The host's manifest is written in the browsers'
  per-user places on macOS, and named by registry keys under
  HKEY_CURRENT_USER on Windows. Both are tested in temporary homes only,
  as for the legacy link.

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

## Removing the KeePassXC-Browser link

The legacy link (secretvault in KeePassXC's place behind
KeePassXC-Browser) stays until the extension has replaced it in daily
use. Then it goes, in this order.

**For people using it:**

1. Install secretvault's extension, as above, and set its host up:
   `secretvault browser install`. Both work side by side. The legacy
   link's manifest is `org.keepassxc.keepassxc_browser.json`, the
   extension's `io.github.codemodify.secretvault.json`.
2. Undo the legacy link: `secretvault browser uninstall --keepassxc`
   (Desktop › Browsers › Undo the legacy link…, or `B` then `l`). That
   puts KeePassXC's own manifest back, exactly as it was, or removes
   secretvault's if there was none.
3. Remove KeePassXC-Browser from the browser, unless KeePassXC itself is
   still used with it.
4. Remove the old associations: `secretvault browser ls`, then
   `secretvault browser rm NAME` for each. They are only records; they
   give nothing to the new extension.

Logins and grants carry over. The grants for the browser are for the
browser's program, whichever extension asked. The release that removes
the link prints, on `browser status` and `browser install`, that a legacy
manifest is still installed and how to undo it, so nobody is left with a
manifest pointing at a host that no longer answers.

**In the code:**

- **Remove:**
  - `svbrowser/` (the KeePassXC-Browser protocol, its NaCl `box`
    channel, the groups);
  - `svd/browser.go`, but for the session plumbing the extension uses:
    `browserOpen`'s launcher check, the protocol switch and
    `browserMessage`'s dispatch move to `svd/browser_ext.go`;
  - the association records and `browser.list` and `browser.remove`;
  - the relay half of `cmd/secretvault/browser.go`.
- **Move:** `svbrowser/frame.go` (the framing) moves to `svext`, with
  the JSON secret helpers (`AppendJSONSecret`, `DecodeJSONSecret`).
- **Commands:**
  - remove `secretvault browser ls` and `rm`, and `install --keepassxc`;
  - keep `uninstall --keepassxc`, so that what is installed can still be
    undone;
  - `KeePassXCHost` stays in svops for that, uninstall only.
- **The managers:** remove the legacy half of Desktop › Browsers, and of
  `B`. Keep "Undo the legacy link…" while a record of one exists.
- **Tests:** remove `cmd/secretvault/browser_test.go` (the
  KeePassXC-Browser end-to-end tests), `svd/browser_test.go` and
  `svbrowser`'s tests. Keep the install tests that undo an older record.
- **Docs:**
  - remove the KeePassXC-Browser parts of [architecture.md](architecture.md),
    [security.md](security.md), [landscape.md](landscape.md), the README
    and [interfaces.md](interfaces.md) (the `browser ls` and `rm` rows);
  - change the `browser-host` row to the extension alone;
  - drop the NaCl `box` reason from the dependency list in
    architecture.md, if nothing else uses it.
