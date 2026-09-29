// Package secretui is what secretvault's desktop programs share for
// asking about secrets: the header that marks a window as secretvault's,
// the dialog frame and window that every such question is asked in (a
// dialog, centred, as tall as its content, above the others, out of
// screen captures, holding the keyboard while a passphrase is typed), the
// line that says Caps Lock is on, status colours made readable as text
// (Ink), and secretvault's icon.
//
// The look is uitoolkit's own: with no look chosen in its Settings it
// follows the desktop's light or dark mode, at the desktop's scale.
//
// Passphrases are uitoolkit SecretFields, whose contents are a []byte and
// never a Go string; nothing here reads them.
package secretui
