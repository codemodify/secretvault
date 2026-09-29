// Package gui holds what secretvault's two desktop programs share. They
// are in a module of their own, so that the rest of secretvault never
// depends on uitoolkit or needs cgo:
//
//	gui/cmd/secretvault-gui          the password manager
//	gui/cmd/secretvault-gui-prompt   the desktop prompt (pinentry protocol)
//	gui/svmanager                    the password manager, as a library
//	gui/secretui                     what both ask about secrets with
//
// Build with CGO_ENABLED=1 on Linux and macOS (uitoolkit's windowing needs
// it), from this directory: go build ./cmd/... The module requires a
// uitoolkit release, which go fetches from the module proxy, and takes
// secretvault itself from the checkout it is in (the replace in go.mod).
// No build tags are needed: the programs use uitoolkit's default theme
// engine.
//
// The tests here check what secretvault asked uitoolkit for
// (uitoolkit-gaps.md at the repository's root) against the release this
// module is built with.
package gui
