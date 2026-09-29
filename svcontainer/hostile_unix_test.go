//go:build unix

package svcontainer

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svluks"
)

// Images named by other programs are not trusted: a FIFO must not hang
// whoever opens it, and a container key is tried only on keyslots cheap
// enough to hold one.

func TestAFIFOIsNotAContainer(t *testing.T) {
	fifo := filepath.Join(t.TempDir(), "fifo.img")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skip("no mkfifo here:", err)
	}
	done := make(chan error, 3)
	go func() {
		_, err := Inspect(fifo)
		done <- err
		_, err = Check(fifo, NewKey())
		done <- err
		done <- BackupHeader(fifo, fifo+".header")
	}()
	for range 3 {
		select {
		case err := <-done:
			if err == nil || !strings.Contains(err.Error(), "not a regular file") {
				t.Fatalf("a FIFO: %v", err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("opening a FIFO hung")
		}
	}
}

func TestTheKeyIsTriedOnlyWhereAKeyCanBe(t *testing.T) {
	// An image whose only keyslot opens with the key, but through Argon2:
	// no container of ours looks like that, and the key is not tried there.
	path := filepath.Join(t.TempDir(), "odd.img")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	f.Truncate(MinSize)
	key := NewKey()
	_, vk, err := svluks.Format(f, key, svluks.Options{KDF: svluks.KDF{Type: svluks.KDFArgon2id, Iterations: 4, MemoryKiB: 32, Threads: 1}})
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	vk.Destroy()
	if _, err := Check(path, key); err == nil || !strings.Contains(err.Error(), "does not open") {
		t.Fatalf("the key was tried on an Argon2 keyslot: %v", err)
	}
	if n, err := CheckPassphrase(path, key); err != nil || n != 0 {
		t.Fatalf("as a passphrase: %d %v", n, err)
	}
}
