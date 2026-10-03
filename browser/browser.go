// Package browser holds secretvault's own browser extension, a plain
// JavaScript WebExtension (Manifest V3) in extension/, embedded so that
// the programs can package it (svops.WriteExtension) and the daemon can
// match logins with the same Public Suffix List the extension bundles.
//
// The extension talks to secretvault through its native-messaging host,
// io.github.codemodify.secretvault (svext, docs/browser.md). Nothing here
// runs JavaScript: the tests in test/ run under node --test, which
// node_test.go starts when node is installed.
package browser

import (
	"embed"
	"io/fs"
)

//go:embed extension
var files embed.FS

// Extension is the extension's source: manifest.json at its root.
func Extension() fs.FS {
	sub, err := fs.Sub(files, "extension")
	if err != nil {
		panic(err) // the directory is embedded above
	}
	return sub
}

// PSLPath is where the Public Suffix List is in the extension.
const PSLPath = "data/public_suffix_list.dat"

// PSL is the Public Suffix List (https://publicsuffix.org/list/), as
// scripts/update-psl.sh last fetched it.
func PSL() []byte {
	b, err := fs.ReadFile(files, "extension/"+PSLPath)
	if err != nil {
		panic(err) // embedded above
	}
	return b
}
