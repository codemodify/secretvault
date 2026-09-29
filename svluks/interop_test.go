package svluks

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Interoperability with cryptsetup itself, which works on image files
// without root: images this package writes must satisfy cryptsetup's own
// validation and open there with the same volume key, and images
// cryptsetup writes must open here. The data sectors are checked against
// Python's cryptography package (check_xts.py), since mapping them through
// dm-crypt would need root.

func needCryptsetup(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("cryptsetup")
	if err != nil {
		t.Skip("cryptsetup is not installed")
	}
	return p
}

// cryptsetup runs it, failing the test unless it succeeds.
func cryptsetup(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("cryptsetup", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("cryptsetup %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// dumpKey is the volume key cryptsetup finds with the passphrase in
// keyfile.
func dumpKey(t *testing.T, image, keyfile string) []byte {
	t.Helper()
	out := cryptsetup(t, "luksDump", "--dump-volume-key", "--batch-mode", "--key-file", keyfile, image)
	var hexKey strings.Builder
	in := false
	s := bufio.NewScanner(strings.NewReader(out))
	for s.Scan() {
		line := s.Text()
		if _, rest, ok := strings.Cut(line, "MK dump:"); ok {
			in, line = true, rest
		} else if _, rest, ok := strings.Cut(line, "Volume key:"); ok {
			in, line = true, rest
		} else if in && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(line, " ") {
			break
		}
		if in {
			hexKey.WriteString(strings.ReplaceAll(strings.TrimSpace(line), " ", ""))
		}
	}
	key, err := hex.DecodeString(hexKey.String())
	if err != nil || len(key) == 0 {
		t.Fatalf("no volume key in cryptsetup's dump:\n%s", out)
	}
	return key
}

func writeFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// newFileImage makes a sparse image file with room for the header and
// data bytes after it.
func newFileImage(t *testing.T, dir string, data int64) (string, *os.File) {
	t.Helper()
	p := filepath.Join(dir, "c.img")
	f, err := os.OpenFile(p, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	if err := f.Truncate(DataOffset + data); err != nil {
		t.Fatal(err)
	}
	return p, f
}

func TestCryptsetupReadsOurs(t *testing.T) {
	needCryptsetup(t)
	for _, c := range []struct {
		ss        int
		first, kd KDF
	}{
		{512, cheapPBKDF, cheapArgon},
		{4096, cheapArgon, cheapPBKDF},
		{4096, KDF{Type: KDFArgon2i, Iterations: 4, MemoryKiB: 64, Threads: 2}, KDF{Type: KDFPBKDF2, Hash: "sha512", Iterations: 1000}},
	} {
		t.Run(fmt.Sprintf("%d-%s", c.ss, c.first.Type), func(t *testing.T) {
			dir := t.TempDir()
			img, f := newFileImage(t, dir, 1<<20)
			h, key, err := Format(f, pass, Options{SectorSize: c.ss, KDF: c.first, Label: "sv-test"})
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			// A second keyslot, changed once, so that adding and changing
			// are checked too.
			second, third := []byte("a second passphrase"), []byte("a third passphrase")
			id, err := h.AddKeyslot(f, key, second, c.kd)
			if err != nil {
				t.Fatal(err)
			}
			if err := h.ChangeKeyslot(f, id, key, third, c.kd); err != nil {
				t.Fatal(err)
			}

			dump := cryptsetup(t, "luksDump", img)
			for _, want := range []string{"Version:       \t2", "sector: " + fmt.Sprint(c.ss), "Label:         \tsv-test", "UUID:          \t" + h.UUID()} {
				if !strings.Contains(dump, want) {
					t.Errorf("luksDump lacks %q:\n%s", want, dump)
				}
			}
			cryptsetup(t, "isLuks", "--type", "luks2", img)
			for _, p := range [][]byte{pass, third} {
				kf := writeFile(t, dir, "key", p)
				cryptsetup(t, "open", "--test-passphrase", "--key-file", kf, img)
				if got := dumpKey(t, img, kf); !bytes.Equal(got, key.Bytes()) {
					t.Fatalf("cryptsetup found volume key %x, we made %x", got, key.Bytes())
				}
			}
			kf := writeFile(t, dir, "key", second)
			if out, err := exec.Command("cryptsetup", "open", "--test-passphrase", "--key-file", kf, img).CombinedOutput(); err == nil {
				t.Fatalf("the changed-away passphrase still opens:\n%s", out)
			}

			// Removing a keyslot leaves a header cryptsetup still takes.
			if err := h.RemoveKeyslot(f, 0); err != nil {
				t.Fatal(err)
			}
			kf = writeFile(t, dir, "key", pass)
			if out, err := exec.Command("cryptsetup", "open", "--test-passphrase", "--key-file", kf, img).CombinedOutput(); err == nil {
				t.Fatalf("a removed keyslot still opens:\n%s", out)
			}
			cryptsetup(t, "open", "--test-passphrase", "--key-file", writeFile(t, dir, "key", third), img)

			// Our header backup is a header cryptsetup reads.
			bf, err := os.Create(filepath.Join(dir, "backup"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := BackupHeader(f, bf); err != nil {
				t.Fatal(err)
			}
			bf.Close()
			cryptsetup(t, "luksDump", filepath.Join(dir, "backup"))
			cryptsetup(t, "open", "--test-passphrase", "--key-file", writeFile(t, dir, "key", third), "--header", filepath.Join(dir, "backup"), img)
		})
	}
}

func TestWeReadCryptsetups(t *testing.T) {
	needCryptsetup(t)
	for _, c := range []struct {
		name string
		args []string
		ss   int
	}{
		{"pbkdf2-512", []string{"--pbkdf", "pbkdf2", "--pbkdf-force-iterations", "1000", "--sector-size", "512"}, 512},
		{"argon2id-4096", []string{"--pbkdf", "argon2id", "--pbkdf-memory", "32", "--pbkdf-force-iterations", "4", "--pbkdf-parallel", "1", "--sector-size", "4096"}, 4096},
		{"argon2i-4096", []string{"--pbkdf", "argon2i", "--pbkdf-memory", "64", "--pbkdf-force-iterations", "4", "--pbkdf-parallel", "2", "--sector-size", "4096"}, 4096},
		{"pbkdf2-sha512-aes128", []string{"--pbkdf", "pbkdf2", "--hash", "sha512", "--pbkdf-force-iterations", "1000", "--key-size", "256"}, 4096},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			img, f := newFileImage(t, dir, 1<<20)
			kf := writeFile(t, dir, "key", pass)
			cryptsetup(t, append(append([]string{"luksFormat", "--type", "luks2", "--batch-mode", "--key-file", kf}, c.args...), img)...)
			// A token of cryptsetup's, which we must keep.
			tok := writeFile(t, dir, "token.json", []byte(`{"type":"secretvault-test","keyslots":["0"],"note":"kept <&> as is"}`))
			cryptsetup(t, "token", "import", "--token-id", "0", "--json-file", tok, img)
			want := dumpKey(t, img, kf)

			h, err := Read(f)
			if err != nil {
				t.Fatal(err)
			}
			if h.SectorSize() != c.ss || h.DataOffset() != DataOffset {
				t.Fatalf("sector size %d, data at %d", h.SectorSize(), h.DataOffset())
			}
			key, slot, err := h.Unlock(f, pass)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Destroy()
			if slot != 0 || !bytes.Equal(key.Bytes(), want) {
				t.Fatalf("slot %d gave key %x; cryptsetup says %x", slot, key.Bytes(), want)
			}
			if _, _, err := h.Unlock(f, []byte("wrong")); err == nil {
				t.Fatal("a wrong passphrase opened it")
			}
			if _, err := h.Volume(f, key); err != nil {
				t.Fatal(err)
			}

			// A keyslot we add opens in cryptsetup; the token survives; and
			// removing cryptsetup's own keyslot works there too.
			newPass := []byte("added by svluks")
			if _, err := h.AddKeyslot(f, key, newPass, cheapArgon); err != nil {
				t.Fatal(err)
			}
			if err := h.RemoveKeyslot(f, 0); err != nil {
				t.Fatal(err)
			}
			nkf := writeFile(t, dir, "newkey", newPass)
			cryptsetup(t, "open", "--test-passphrase", "--key-file", nkf, img)
			if out, err := exec.Command("cryptsetup", "open", "--test-passphrase", "--key-file", kf, img).CombinedOutput(); err == nil {
				t.Fatalf("the removed keyslot still opens:\n%s", out)
			}
			if got := dumpKey(t, img, nkf); !bytes.Equal(got, want) {
				t.Fatalf("after our changes cryptsetup finds key %x, want %x", got, want)
			}
			exported := cryptsetup(t, "token", "export", "--token-id", "0", img)
			if !strings.Contains(exported, `"note":"kept <&> as is"`) || !strings.Contains(exported, `"keyslots":[]`) {
				t.Fatalf("the token after our changes: %s", exported)
			}

			// cryptsetup's header backup restores through us.
			backup := filepath.Join(dir, "backup")
			cryptsetup(t, "luksHeaderBackup", "--header-backup-file", backup, img)
			if _, err := h.AddKeyslot(f, key, []byte("after the backup"), cheapPBKDF); err != nil {
				t.Fatal(err)
			}
			bf, err := os.Open(backup)
			if err != nil {
				t.Fatal(err)
			}
			defer bf.Close()
			if st, _ := bf.Stat(); st.Size() != h.MetadataSize() {
				t.Errorf("cryptsetup's backup is %d bytes; we back up %d", st.Size(), h.MetadataSize())
			}
			if err := RestoreHeader(f, bf); err != nil {
				t.Fatal(err)
			}
			if h, err = Read(f); err != nil || len(h.Keyslots()) != 1 {
				t.Fatalf("after restoring: %v", err)
			}
		})
	}
}

func TestSectorsAgainstPython(t *testing.T) {
	py, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is not installed")
	}
	if out, err := exec.Command(py, "-c", "from cryptography.hazmat.primitives.ciphers import modes; modes.XTS").CombinedOutput(); err != nil {
		t.Skipf("python3 has no cryptography package with XTS: %s", out)
	}
	script, _ := filepath.Abs("testdata/check_xts.py")
	for _, c := range []struct {
		ss    int
		tweak uint64
	}{{512, 0}, {4096, 0}, {512, 123}, {4096, 123}} {
		t.Run(fmt.Sprintf("%d-tweak%d", c.ss, c.tweak), func(t *testing.T) {
			const data = 256 << 10
			dev, _, key := newImage(t, data, Options{SectorSize: c.ss})
			if c.tweak != 0 {
				editJSON(t, dev, func(m map[string]any) { obj(m, "segments", "0")["iv_tweak"] = fmt.Sprint(c.tweak) })
			}
			h := mustRead(t, dev)
			v, err := h.Volume(dev, key)
			if err != nil {
				t.Fatal(err)
			}
			dir := t.TempDir()
			ours := make([]byte, 64<<10)
			rand.Read(ours)
			if _, err := v.WriteAt(ours, 8192); err != nil {
				t.Fatal(err)
			}
			img := writeFile(t, dir, "img", dev.b)
			k := hex.EncodeToString(key.Bytes())
			args := func(mode string, at int, rest ...string) []string {
				return append([]string{script, mode, img, k, fmt.Sprint(DataOffset), fmt.Sprint(c.ss), fmt.Sprint(c.tweak), fmt.Sprint(at)}, rest...)
			}
			// Python decrypts what we encrypted...
			out := filepath.Join(dir, "plain")
			if o, err := exec.Command(py, args("decrypt", 8192, fmt.Sprint(len(ours)), out)...).CombinedOutput(); err != nil {
				t.Fatalf("check_xts.py: %v\n%s", err, o)
			}
			if got, _ := os.ReadFile(out); !bytes.Equal(got, ours) {
				t.Fatal("Python decrypts our sectors to something else")
			}
			// ...and we decrypt what Python encrypted.
			theirs := make([]byte, 32<<10)
			rand.Read(theirs)
			in := writeFile(t, dir, "in", theirs)
			if o, err := exec.Command(py, args("encrypt", 128<<10, in)...).CombinedOutput(); err != nil {
				t.Fatalf("check_xts.py: %v\n%s", err, o)
			}
			written, _ := os.ReadFile(img)
			copy(dev.b, written)
			got := make([]byte, len(theirs))
			if _, err := v.ReadAt(got, 128<<10); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, theirs) {
				t.Fatal("we decrypt Python's sectors to something else")
			}
		})
	}
}
