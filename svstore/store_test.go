package svstore

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sync"
	"testing"
)

func backends(t *testing.T) map[string]Backend {
	d, err := OpenDir(filepath.Join(t.TempDir(), "vault"))
	if err != nil {
		t.Fatal(err)
	}
	return map[string]Backend{"dir": d, "mem": NewMem()}
}

func TestCreateIsExclusiveAndWriteReplaces(t *testing.T) {
	for name, b := range backends(t) {
		t.Run(name, func(t *testing.T) {
			if err := b.Create("slots/a.json", []byte("one")); err != nil {
				t.Fatal(err)
			}
			if err := b.Create("slots/a.json", []byte("two")); !errors.Is(err, ErrExist) {
				t.Fatalf("second Create = %v, want ErrExist", err)
			}
			if got, _ := b.Read("slots/a.json"); string(got) != "one" {
				t.Fatalf("Create overwrote: %q", got)
			}
			if err := b.Write("vault.json", []byte("v1")); err != nil {
				t.Fatal(err)
			}
			if err := b.Write("vault.json", []byte("v2")); err != nil {
				t.Fatal(err)
			}
			if got, _ := b.Read("vault.json"); string(got) != "v2" {
				t.Fatalf("Write did not replace: %q", got)
			}
			if _, err := b.Read("nope"); !errors.Is(err, ErrNotExist) {
				t.Fatalf("Read of a missing file = %v", err)
			}
		})
	}
}

func TestListFindsFilesUnderADirectory(t *testing.T) {
	for name, b := range backends(t) {
		t.Run(name, func(t *testing.T) {
			for _, n := range []string{"objects/ab/x/1.svr", "objects/ab/x/2.svr", "objects/cd/y/3.svr", "slots/s.json", "vault.json"} {
				if err := b.Create(n, []byte(n)); err != nil {
					t.Fatal(err)
				}
			}
			got, err := b.List("objects")
			if err != nil {
				t.Fatal(err)
			}
			want := []string{"objects/ab/x/1.svr", "objects/ab/x/2.svr", "objects/cd/y/3.svr"}
			if !slices.Equal(got, want) {
				t.Fatalf("List = %q, want %q", got, want)
			}
			if all, _ := b.List(""); len(all) != 5 {
				t.Fatalf("List(\"\") = %q", all)
			}
			if none, err := b.List("missing"); err != nil || len(none) != 0 {
				t.Fatalf("List of a missing dir = %q, %v", none, err)
			}
			b.Remove("slots/s.json")
			b.Remove("slots/s.json")
			if got, _ := b.List("slots"); len(got) != 0 {
				t.Fatalf("Remove left %q", got)
			}
		})
	}
}

func TestNamesCannotEscapeTheVault(t *testing.T) {
	for name, b := range backends(t) {
		for _, bad := range []string{"", "/etc/passwd", "../x", "a/../../x", "a//b", "./a", ".hidden", "a/.tmp-1", "a b", `a\b`, "a/"} {
			if err := b.Create(bad, nil); !errors.Is(err, ErrName) {
				t.Errorf("%s: Create(%q) = %v", name, bad, err)
			}
		}
	}
}

func TestConcurrentCreatesOfOneNameHaveOneWinner(t *testing.T) {
	for name, b := range backends(t) {
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := range 16 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if b.Create("objects/aa/x/r.svr", []byte{byte(i)}) == nil {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if wins != 1 {
			t.Errorf("%s: %d creates succeeded", name, wins)
		}
	}
}

func TestDirFilesAreOwnerOnlyAndLeaveNoTemporaries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX modes")
	}
	root := filepath.Join(t.TempDir(), "v")
	d, _ := OpenDir(root)
	d.Create("slots/a.json", []byte("x"))
	d.Write("vault.json", []byte("x"))
	for _, p := range []string{"slots/a.json", "vault.json"} {
		fi, err := os.Stat(filepath.Join(root, p))
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Errorf("%s: mode %v, %v", p, fi.Mode(), err)
		}
	}
	if fi, _ := os.Stat(root); fi.Mode().Perm() != 0o700 {
		t.Errorf("root mode %v", fi.Mode())
	}
	entries, _ := os.ReadDir(filepath.Join(root, "slots"))
	if len(entries) != 1 {
		t.Errorf("slots holds %d entries, want 1 (a temporary was left behind)", len(entries))
	}
}
