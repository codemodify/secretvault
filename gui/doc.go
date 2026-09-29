// Package gui holds what secretvault's two desktop programs share. They
// are in a module of their own, so that the rest of secretvault never
// depends on uitoolkit or needs cgo:
//
//	gui/cmd/secretvault-gui          the password manager
//	gui/cmd/secretvault-gui-prompt   the desktop prompt (pinentry protocol)
//
// Build with CGO_ENABLED=1 on Linux and macOS (uitoolkit's windowing needs
// it), from this directory: go build ./cmd/...
package gui
