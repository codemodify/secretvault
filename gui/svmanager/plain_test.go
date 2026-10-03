package svmanager

import (
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/codemodify/uitoolkit/widgets"

	"github.com/codemodify/secretvault/svops"
)

// A plan's details wrap at spaces, and a path too long for the line after
// one of its separators, never in the middle of a name that has one; no
// line is wider than the width, and nothing is lost.
func TestDetailsWrapAtSpacesAndPathSeparators(t *testing.T) {
	advance := func(s string) float32 { return float32(utf8.RuneCountInString(s)) } // a mono face of 1
	in := []string{
		"firefox: write /home/user/.mozilla/native-messaging-hosts/io.github.codemodify.secretvault.json",
		"    making /home/user/.mozilla/native-messaging-hosts",
		"short",
	}
	out := wrapDetail(advance, in, 30)
	for _, l := range out {
		if advance(l) > 30 {
			t.Errorf("a line wider than 30: %q", l)
		}
	}
	joined := strings.Join(out, "\n")
	for _, broken := range []string{"/hom\n", "messag\n", "/.\n", "io.gith\n"} {
		if strings.Contains(joined, broken) {
			t.Errorf("broken in a name (%q):\n%s", broken, joined)
		}
	}
	if !strings.Contains(joined, "/home/user/\n") && !strings.Contains(joined, "/home/user/.mozilla/\n") {
		t.Errorf("the path is not broken after a separator:\n%s", joined)
	}
	if !strings.HasPrefix(out[1], "  ") || out[len(out)-1] != "short" {
		t.Errorf("continuations are not indented, or a short line changed:\n%s", joined)
	}
	squeeze := func(s string) string { return strings.Join(strings.Fields(strings.ReplaceAll(s, "\n", "")), "") }
	if squeeze(joined) != squeeze(strings.Join(in, "")) {
		t.Errorf("text was lost:\n%s", joined)
	}
	// A word with nowhere to break is broken where it must be.
	if long := wrapDetail(advance, []string{strings.Repeat("x", 70)}, 30); len(long) != 3 {
		t.Errorf("a 70-character word in 30: %q", long)
	}
}

// The plan's details are folded under "Show details", the summary is what
// is read first, and a plan with nothing to do has no button but Close.
func TestAPlanSaysItsSummaryAndFoldsItsDetails(t *testing.T) {
	h := newHarness(t)
	h.start(Options{})
	h.unlock()
	h.m.showPlan(svops.Plain{Title: "Let Firefox use secretvault", Summary: "Firefox needs your permission.",
		Action: "Allow Firefox", Details: []string{"firefox: write /home/ada/x.json"}}, func() {}, nil)
	h.pump()
	if !strings.Contains(h.text(), "Firefox needs your permission.") || strings.Contains(h.text(), "x.json") {
		t.Fatalf("the plan, folded:\n%s", h.text())
	}
	if find(h.overlay(), func(*widgets.TextArea) bool { return true }) != nil {
		t.Fatal("the plan shows its text in a text box")
	}
	h.expand("Show details")
	h.waitText("firefox: write /home/ada/x.json")
	h.press("Cancel")

	h.m.showPlan(svops.Plain{Title: "Nothing to set up", Summary: "Firefox can already start secretvault."}, func() { t.Error("carried out") }, nil)
	h.pump()
	if button(h.overlay(), "Close") == nil {
		t.Fatalf("a plan with nothing to do has no Close:\n%s", h.text())
	}
	h.press("Close")
}
