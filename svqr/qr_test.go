package svqr

import (
	"bytes"
	"errors"
	"image/png"
	"math/rand/v2"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The error correction codewords of ISO/IEC 18004's worked example
// (annex I: "01234567" as version 1-M) and of the widely reproduced
// "HELLO WORLD" 1-M example.
func TestReedSolomonWorkedExamples(t *testing.T) {
	for _, tc := range []struct {
		data, ecc []byte
	}{
		{
			data: []byte{16, 32, 12, 86, 97, 128, 236, 17, 236, 17, 236, 17, 236, 17, 236, 17},
			ecc:  []byte{165, 36, 212, 193, 237, 54, 199, 135, 44, 85},
		},
		{
			data: []byte{32, 91, 11, 120, 209, 114, 220, 77, 67, 64, 236, 17, 236, 17, 236, 17},
			ecc:  []byte{196, 35, 39, 119, 235, 215, 231, 226, 93, 23},
		},
	} {
		if got := rsRemainder(tc.data, rsGenerator(len(tc.ecc))); !bytes.Equal(got, tc.ecc) {
			t.Errorf("error correction of %v = %v, want %v", tc.data, got, tc.ecc)
		}
	}
}

// capacity is the most bytes a version holds at a level.
func capacity(version int, level Level) int {
	n := 0
	for bitsNeeded(n+1, version) <= 8*dataCodewords(version, level) {
		n++
	}
	return n
}

func TestCapacities(t *testing.T) {
	// ISO/IEC 18004, table 7 (byte mode).
	for _, tc := range []struct {
		version int
		level   Level
		bytes   int
	}{
		{1, L, 17}, {1, M, 14}, {1, Q, 11}, {1, H, 7},
		{10, M, 213}, {10, H, 119},
		{27, L, 1465}, {27, Q, 805},
		{40, L, 2953}, {40, M, 2331}, {40, Q, 1663}, {40, H, 1273},
	} {
		if got := capacity(tc.version, tc.level); got != tc.bytes {
			t.Errorf("version %d-%v holds %d bytes, want %d", tc.version, tc.level, got, tc.bytes)
		}
	}
	if rawModules(1)/8 != 26 || rawModules(40)/8 != 3706 {
		t.Errorf("codewords: version 1 %d, version 40 %d", rawModules(1)/8, rawModules(40)/8)
	}
	for v := 1; v <= 40; v++ {
		for l := L; l <= H; l++ {
			raw := rawModules(v) / 8
			blocks := ecBlocks[l][v]
			if short := raw/blocks - ecCodewordsPerBlock[l][v]; short < 1 || dataCodewords(v, l) < 1 {
				t.Errorf("version %d-%v has blocks of %d data codewords", v, l, short)
			}
		}
	}
}

func TestSmallestVersionAndTooLong(t *testing.T) {
	c, err := Encode([]byte("hello"), M)
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != 1 || c.Size != 21 || c.Level != M {
		t.Fatalf("hello: version %d size %d level %v", c.Version, c.Size, c.Level)
	}
	if c, err = Encode(make([]byte, 2331), M); err != nil || c.Version != 40 {
		t.Fatalf("2331 bytes at M: %v, %v", c, err)
	}
	if _, err := Encode(make([]byte, 2332), M); !errors.Is(err, ErrTooLong) {
		t.Fatalf("2332 bytes at M: %v", err)
	}
}

// readQrencode runs the reference encoder (libqrencode's CLI) on data and
// reads its symbol back.
func readQrencode(t *testing.T, bin, dir string, data []byte, level Level) [][]bool {
	t.Helper()
	in := filepath.Join(dir, "data")
	if err := os.WriteFile(in, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(bin, "-8", "-l", level.String(), "-m", "0", "-t", "ASCII", "-r", in, "-o", "-").Output()
	if err != nil {
		t.Fatalf("qrencode: %v", err)
	}
	lines := strings.Split(strings.TrimRight(string(out), "\n"), "\n")
	var rows [][]bool
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		row := make([]bool, len(lines))
		for x := range row {
			if 2*x < len(line) && line[2*x] == '#' {
				row[x] = true
			}
		}
		rows = append(rows, row)
	}
	return rows
}

// formatMask reads the mask from the first copy of a symbol's format
// information.
func formatMask(rows [][]bool) int {
	bits := 0
	for i := range 6 {
		if rows[i][8] {
			bits |= 1 << i
		}
	}
	if rows[7][8] {
		bits |= 1 << 6
	}
	if rows[8][8] {
		bits |= 1 << 7
	}
	if rows[8][7] {
		bits |= 1 << 8
	}
	for i := 9; i < 15; i++ {
		if rows[8][14-i] {
			bits |= 1 << i
		}
	}
	return (bits ^ 0x5412) >> 10 & 7
}

func equalSymbol(c *Code, rows [][]bool) bool {
	if len(rows) != c.Size {
		return false
	}
	for y, row := range rows {
		for x, d := range row {
			if c.Dark(x, y) != d {
				return false
			}
		}
	}
	return true
}

// Every version at every level, module for module against libqrencode:
// data encoding, error correction, interleaving, placement, format and
// version information, and the choice of mask.
func TestMatchesQrencode(t *testing.T) {
	bin, err := exec.LookPath("qrencode")
	if err != nil {
		t.Skip("qrencode is not installed")
	}
	dir := t.TempDir()
	rng := rand.New(rand.NewPCG(1, 2))
	for level := L; level <= H; level++ {
		for v := 1; v <= 40; v++ {
			// The most a version holds, and something in between.
			for _, n := range []int{capacity(v, level), capacity(v, level) - rng.IntN(8)} {
				data := make([]byte, n)
				for i := range data {
					data[i] = byte(rng.Uint32())
				}
				ref := readQrencode(t, bin, dir, data, level)
				c, err := Encode(data, level)
				if err != nil {
					t.Fatal(err)
				}
				if c.Version != v && n == capacity(v, level) {
					t.Fatalf("%d bytes at %v: version %d, want %d", n, level, c.Version, v)
				}
				if equalSymbol(c, ref) {
					continue
				}
				// Tell a different mask choice from a different symbol.
				forced, err := encode(data, level, c.Version, formatMask(ref))
				if err != nil {
					t.Fatal(err)
				}
				if equalSymbol(forced, ref) {
					t.Errorf("%d bytes at %v (version %d): mask %d, qrencode chose %d", n, level, c.Version, c.Mask, forced.Mask)
				} else {
					t.Fatalf("%d bytes at %v (version %d): the symbol differs from qrencode's", n, level, c.Version)
				}
			}
		}
	}
}

// A scanner reads what we draw: zbar's, where it is installed.
func TestZbarReadsOurCodes(t *testing.T) {
	bin, err := exec.LookPath("zbarimg")
	if err != nil {
		t.Skip("zbarimg is not installed")
	}
	dir := t.TempDir()
	for i, msg := range []string{
		"hello",
		"secretvault-contact:v1?n=Alice%20Example&e=alice%40example.org&pgp=0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF",
		strings.Repeat("The quick brown fox jumps over the lazy dog. ", 25),
	} {
		for _, level := range []Level{L, H} {
			c, err := Encode([]byte(msg), level)
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(dir, "code.png")
			f, err := os.Create(p)
			if err != nil {
				t.Fatal(err)
			}
			if err := png.Encode(f, c.Image(4, 0)); err != nil {
				t.Fatal(err)
			}
			f.Close()
			out, err := exec.Command(bin, "--raw", "-q", "-Sbinary", p).Output()
			if err != nil {
				t.Fatalf("zbarimg on message %d at %v (version %d): %v", i, level, c.Version, err)
			}
			if got := strings.TrimSuffix(string(out), "\n"); got != msg {
				t.Fatalf("zbarimg read %q, want %q", got, msg)
			}
		}
	}
}

// The half-block drawing reads back as the symbol, quiet zone included.
func TestTerminalDrawsEveryModule(t *testing.T) {
	c, err := Encode([]byte("secretvault"), Q)
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range []TerminalOptions{{}, {Quiet: 2, Invert: true}, {Colour: true}} {
		s := c.Terminal(o)
		if o.Colour {
			s = strings.NewReplacer("\x1b[30;107m", "", "\x1b[0m", "").Replace(s)
		}
		q := o.Quiet
		if q == 0 {
			q = QuietZone
		}
		side := c.Size + 2*q
		lines := strings.Split(strings.TrimSuffix(s, "\n"), "\n")
		if len(lines) != (side+1)/2 {
			t.Fatalf("%+v: %d lines for %d rows", o, len(lines), side)
		}
		for ly, line := range lines {
			cells := []rune(line)
			if len(cells) != side {
				t.Fatalf("%+v: line %d is %d wide, want %d", o, ly, len(cells), side)
			}
			for x, r := range cells {
				top := slices.Contains([]rune{'█', '▀'}, r)
				bottom := slices.Contains([]rune{'█', '▄'}, r)
				for dy, ink := range []bool{top, bottom} {
					y := 2*ly + dy - q
					if y >= c.Size+q {
						continue
					}
					want := c.Dark(x-q, y)
					if o.Invert {
						want = !want
					}
					if ink != want {
						t.Fatalf("%+v: module (%d, %d) drawn wrong", o, x-q, y)
					}
				}
			}
		}
	}
}
