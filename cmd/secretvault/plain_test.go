package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A dry run says what the change means first, in the managers' words
// (svops.Plain), and then its own lines, as they always were: a script
// reading them finds them unchanged under the summary.
func TestADryRunSaysWhatItMeansOverItsLines(t *testing.T) {
	h := newHarness(t)
	home := browserHome(t)
	if err := os.MkdirAll(filepath.Join(home, ".mozilla", "firefox"), 0o700); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, home)
	out := h.ok("", "browser", "install", "--dry-run")
	title, rest, _ := strings.Cut(out, "\n")
	if title != "Let Firefox use secretvault" || !strings.Contains(rest, "Firefox needs your permission to start secretvault") {
		t.Fatalf("the dry run does not start with what it means:\n%s", out)
	}
	plain, lines, ok := strings.Cut(out, "\nThe browsers would start ")
	if !ok || strings.Contains(plain, firefoxExtManifest(home)) || !strings.Contains(lines, "\n  firefox: write "+firefoxExtManifest(home)+"\n") {
		t.Fatalf("the plain words name the file, or the lines changed:\n%s", out)
	}
	if after := snapshot(t, home); after != before {
		t.Fatalf("the dry run changed files:\n%s\n---\n%s", before, after)
	}
}
