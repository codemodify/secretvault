// Package secretui is what secretvault's desktop programs share for
// asking about secrets: the header that marks a window as secretvault's,
// and the dialog frame and window that every such question is asked in
// (a dialog, centred, above the others, out of screen captures, holding
// the keyboard while a passphrase is typed).
//
// Passphrases are uitoolkit SecretFields, whose contents are a []byte and
// never a Go string; nothing here reads them.
package secretui
