// Package svops holds what secretvault's interfaces do in their own
// process: the command line (cmd/secretvault), the terminal manager
// (svtui) and the desktop manager (gui/svmanager). They are only faces of
// the same functionality, and must be interchangeable: whatever one can
// do, the others can, by calling the same code.
//
// What touches vaults or the daemon's state is a daemon method, reached
// through the client library (package secretvault). What is here is local
// work around it: reading and writing files, parsing what people type,
// making keys before they are stored, planning changes to the desktop
// (the keyring takeover, browsers' manifests, a GnuPG home) and carrying
// them out.
//
// Nothing here asks, prints or confirms. A function takes its inputs
// (passphrases already asked for, paths already chosen) and returns
// results, or a plan that says what would change, which an interface
// shows for a dry run and then applies. Where a function needs the person
// in the middle of its work (a passphrase only an encrypted file turns
// out to need), it takes a callback. Where it runs system commands, it
// goes through CommandRunner, which tests replace.
//
// docs/interfaces.md maps every command to the operation here or in the
// daemon, and to where it lives in each interface.
package svops
