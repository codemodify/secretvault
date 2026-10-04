package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

// TestMain lets the test binary stand in for the clipboard helper, so
// copySecret can be driven without touching the real clipboard.
func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == clipCommand {
		// A helper that fails at once, as it does with no clipboard.
		fmt.Println("error: no clipboard in this test")
		os.Exit(1)
	}
	if sock := os.Getenv(e2eHostEnv); sock != "" {
		// Started by a headless Chromium as its native-messaging host
		// (browser_e2e_test.go).
		os.Exit(e2eHost(sock))
	}
	os.Exit(m.Run())
}

func TestCopySecretReportsTheHelpersError(t *testing.T) {
	c := &cli{}
	for range 20 {
		_, err := c.copySecret([]byte("hunter2"), 30*time.Second)
		if err == nil || !strings.Contains(err.Error(), "no clipboard in this test") {
			t.Fatalf("copySecret = %v, want the helper's own error", err)
		}
	}
}
