package svd

import (
	"os"
	"testing"
)

// TestMain keeps every test away from the person's desktop: no display in
// the environment, and no session to learn one from, so no test can open a
// real prompt window, whatever it does with the daemon's prompters.
func TestMain(m *testing.M) {
	os.Unsetenv("WAYLAND_DISPLAY")
	os.Unsetenv("DISPLAY")
	sessionEnv = func() []string { return nil }
	os.Exit(m.Run())
}
