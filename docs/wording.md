# How secretvault talks to people

The GUI and the TUI are for people who have not read these docs. Every
dialog, confirmation, form, empty list and error message should let them
see at a glance **what this is**, **what they need to do**, **what
happens when they press the button**, and **whether it is safe**. The
CLI's `--dry-run` keeps its exact lines for scripts; the faces show those
only when asked.

## Asking before a change

- A change to the desktop, the browsers, gpg, git and docker, a vault's
  login, the keyring or the host is a **plan** made in `svops`, and says
  itself as an `svops.Plain` (`svops/plain.go`): a **title**, a plain
  **summary**, any **notes**, the confirm **action**, and the technical
  **details**. Every face uses it: the GUI's and the TUI's `showPlan`,
  and the CLI's `--dry-run` (the title and summary over its own lines,
  which stay as they were).
- The **title** is a few words naming the outcome: "Let Firefox use
  secretvault", "Make secretvault your system keyring".
- The **summary** is one to three sentences: what happens, why, what does
  not change, and how to undo it. "Firefox needs your permission to start
  secretvault when the secretvault extension asks for a login. This
  writes one small settings file in its folder. No passwords move,
  nothing else in the browser changes, and undoing it removes the file
  again."
- **Notes** are what the person must know or do besides, in the same
  plain words (a step left to do by hand, a file left alone). Shown as a
  warning, under the summary.
- The **details** are the technical lines: paths, commands, the CLI's
  dry-run text. The GUI folds them under "Show details", wrapped at spaces
  and path separators, never in the middle of a name, as tall as they
  are (no small box to scroll inside). The TUI shows them behind a "Show
  details" button.
- After the change, say what it means in a sentence (`showDone`), and put
  what was done line by line under the details.

## Words

- **Plain words first.** No file paths, commands, RPC or method names,
  `sv://` references, D-Bus names, "manifest", "credsStore", "epoch" or
  "recipient" in a title, a summary, or the first sentence of a note or
  form. They belong in the details, or in a field's placeholder where the
  person has to type one.
- **Name things as people know them:** "Firefox", not `firefox`;
  "GNOME Keyring", not `gnome-keyring-daemon (/usr/bin/…)`; "passwords"
  for what apps keep in the system keyring; "GnuPG folder", not "GnuPG
  home".
- **Unavoidable jargon gets a one-line explanation** where it first
  appears: "a keyslot (another way to open the vault)", "recipient (the
  public key others share vaults with)", "fingerprint (a short code to
  compare)".
- **Say what is safe.** When nothing secret moves, say so ("No passwords
  move"); when something weakens protection, say who could then do what
  ("Anyone who can use your logged-in account can then open this vault").
- **Keep it short.** No walls of text: a summary, then the details for
  whoever wants them. Do not repeat what the title says.

## Buttons and fields

- **One clear primary action**, and its button says what it does: "Allow
  Firefox", "Take over the keyring", "Copy 12 passwords", "Delete the
  file". Never "OK", "Yes", "Do it", "Set them up" or a bare "Undo".
  Cancel is always there, and is the default where the action cannot be
  taken back.
- A step that only leads to the next says **Next**; the last says what it
  does.
- **A field's label says what goes in it** ("Put them in the folder",
  "GnuPG folder", "gpg program"), and its placeholder gives an example or
  says what empty means ("Leave empty for the gpg on your PATH").
- **An empty list says why it is empty and what to do:** "No devices yet:
  Invite a device… adds one", not "None".
- **An error says what went wrong and what to do next**, in a sentence,
  not a Go error chain; the status line says the short form.

## Where the words live

- Words a plan says, or that more than one face says, live in `svops`
  (`plain.go`, `describe.go`, `sources.go`), and each face takes them from
  there. A face adds only what is its own: which button or key to press
  ("Save the extension… on this tab", "e on this panel").
- `svops/plain_test.go` holds every plan to these rules where a test can:
  a title and a summary, at most three sentences, no paths or internal
  names in them, a button that says what it does.
