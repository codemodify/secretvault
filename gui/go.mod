module github.com/codemodify/secretvault/gui

go 1.26.0

require (
	github.com/codemodify/paintengine2d v0.11.0
	github.com/codemodify/secretvault v0.0.0-00010101000000-000000000000
	github.com/codemodify/uitoolkit v0.22.1
)

require (
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/image v0.18.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

// The GUIs build against secretvault as it is checked out around them, and
// against uitoolkit's release from the module proxy.
replace github.com/codemodify/secretvault => ../
