// Package svqr makes QR codes (ISO/IEC 18004) in our own code: byte mode,
// the four error correction levels, the smallest version that holds the
// data, and the mask with the lowest penalty. It draws them on a terminal
// with half-block characters (two rows of modules to a line), or as an
// image. It does not read them: scanning is the phone's job.
//
//	code, err := svqr.Encode([]byte("secretvault-contact:v1?..."), svqr.M)
//	fmt.Print(code.Terminal(svqr.TerminalOptions{}))
//
// Where the standard's penalty rules are loose (how finder-like patterns at
// the edge count, how the dark-module ratio rounds), they are read as
// libqrencode reads them, so the mask chosen matches that widely used
// encoder and its output can be compared with ours module for module.
package svqr

import (
	"errors"
	"fmt"
)

// Level is an error correction level: how much of the symbol can be lost
// or misread and still be recovered.
type Level int

// Error correction levels.
const (
	L Level = iota // about 7% of the codewords
	M              // about 15%
	Q              // about 25%
	H              // about 30%
)

func (l Level) String() string {
	switch l {
	case L:
		return "L"
	case M:
		return "M"
	case Q:
		return "Q"
	case H:
		return "H"
	}
	return fmt.Sprintf("Level(%d)", int(l))
}

// formatBits are the level's two bits in the format information.
func (l Level) formatBits() int { return [...]int{1, 0, 3, 2}[l] }

// ErrTooLong is data that does not fit in the largest QR code at the
// level asked for.
var ErrTooLong = errors.New("svqr: too much data for a QR code")

// Code is a QR code symbol.
type Code struct {
	Version int   // 1 to 40
	Level   Level // the error correction level
	Mask    int   // the mask pattern, 0 to 7
	Size    int   // modules on each side: 17 + 4*Version

	dark []bool // row by row
}

// Dark reports whether the module at column x, row y is dark. Modules
// outside the symbol (the quiet zone) are light.
func (c *Code) Dark(x, y int) bool {
	if x < 0 || y < 0 || x >= c.Size || y >= c.Size {
		return false
	}
	return c.dark[y*c.Size+x]
}

// Encode makes the smallest QR code that holds data in byte mode at the
// level given, with the best mask.
func Encode(data []byte, level Level) (*Code, error) {
	return encode(data, level, 1, -1)
}

// encode makes a code of at least version minVersion; mask -1 picks the
// best mask, else that mask is used.
func encode(data []byte, level Level, minVersion, mask int) (*Code, error) {
	if level < L || level > H {
		return nil, fmt.Errorf("svqr: no error correction level %d", int(level))
	}
	version := 0
	for v := max(minVersion, 1); v <= 40; v++ {
		if bitsNeeded(len(data), v) <= 8*dataCodewords(v, level) {
			version = v
			break
		}
	}
	if version == 0 {
		return nil, fmt.Errorf("%w: %d bytes at level %v", ErrTooLong, len(data), level)
	}
	codewords := addErrorCorrection(dataBits(data, version, level), version, level)

	s := newSymbol(version)
	s.drawFunctionPatterns()
	s.drawCodewords(codewords)
	if mask < 0 {
		best := -1
		for m := range 8 {
			s.applyMask(m)
			s.drawFormat(level, m)
			if p := s.penalty(); best < 0 || p < best {
				best, mask = p, m
			}
			s.applyMask(m) // a mask undoes itself
		}
	}
	s.applyMask(mask)
	s.drawFormat(level, mask)
	return &Code{Version: version, Level: level, Mask: mask, Size: s.size, dark: s.dark}, nil
}

// countBits is how many bits the byte mode character count takes.
func countBits(version int) int {
	if version <= 9 {
		return 8
	}
	return 16
}

// bitsNeeded is the length of a byte mode segment of n bytes.
func bitsNeeded(n, version int) int {
	if n >= 1<<countBits(version) {
		return 1 << 30
	}
	return 4 + countBits(version) + 8*n
}

// ecCodewordsPerBlock and ecBlocks are the error correction structure of
// each version at each level (ISO/IEC 18004, table 9); index 0 is unused.
var ecCodewordsPerBlock = [4][41]int{
	{0, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{0, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28},
	{0, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
	{0, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30},
}

var ecBlocks = [4][41]int{
	{0, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25},
	{0, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49},
	{0, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68},
	{0, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81},
}

// rawModules is how many modules of a version carry codewords (and
// remainder bits): everything but the function patterns and the format
// and version information.
func rawModules(version int) int {
	n := (16*version+128)*version + 64
	if version >= 2 {
		align := version/7 + 2
		n -= (25*align-10)*align - 55
		if version >= 7 {
			n -= 36
		}
	}
	return n
}

// dataCodewords is how many data codewords a version holds at a level.
func dataCodewords(version int, level Level) int {
	return rawModules(version)/8 - ecCodewordsPerBlock[level][version]*ecBlocks[level][version]
}

// dataBits is the data codewords: one byte mode segment, the terminator,
// and padding.
func dataBits(data []byte, version int, level Level) []byte {
	var b bitBuffer
	b.put(0b0100, 4)
	b.put(len(data), countBits(version))
	for _, c := range data {
		b.put(int(c), 8)
	}
	capacity := 8 * dataCodewords(version, level)
	b.put(0, min(4, capacity-b.n))
	b.put(0, (8-b.n%8)%8)
	for pad := 0xEC; b.n < capacity; pad ^= 0xEC ^ 0x11 {
		b.put(pad, 8)
	}
	return b.bytes
}

type bitBuffer struct {
	bytes []byte
	n     int // bits written
}

func (b *bitBuffer) put(v, bits int) {
	for i := bits - 1; i >= 0; i-- {
		if b.n%8 == 0 {
			b.bytes = append(b.bytes, 0)
		}
		if v>>i&1 != 0 {
			b.bytes[b.n/8] |= 0x80 >> (b.n % 8)
		}
		b.n++
	}
}

// addErrorCorrection splits the data into blocks, adds each block's
// Reed-Solomon codewords, and interleaves them into the final sequence.
func addErrorCorrection(data []byte, version int, level Level) []byte {
	blocks := ecBlocks[level][version]
	ecLen := ecCodewordsPerBlock[level][version]
	raw := rawModules(version) / 8
	short := blocks - raw%blocks // blocks one data codeword shorter
	shortLen := raw/blocks - ecLen
	gen := rsGenerator(ecLen)
	var dataBlocks, ecc [][]byte
	for i, off := 0, 0; i < blocks; i++ {
		n := shortLen
		if i >= short {
			n++
		}
		block := data[off : off+n]
		off += n
		dataBlocks = append(dataBlocks, block)
		ecc = append(ecc, rsRemainder(block, gen))
	}
	out := make([]byte, 0, raw)
	for i := 0; i <= shortLen; i++ {
		for _, b := range dataBlocks {
			if i < len(b) {
				out = append(out, b[i])
			}
		}
	}
	for i := range ecLen {
		for _, e := range ecc {
			out = append(out, e[i])
		}
	}
	return out
}

// Reed-Solomon over GF(2^8) with the polynomial x^8+x^4+x^3+x^2+1.

func gfMul(a, b byte) byte {
	var p byte
	for b != 0 {
		if b&1 != 0 {
			p ^= a
		}
		carry := a & 0x80
		a <<= 1
		if carry != 0 {
			a ^= 0x1D
		}
		b >>= 1
	}
	return p
}

// rsGenerator is the generator polynomial (x-α^0)(x-α^1)...(x-α^(n-1)),
// highest power first, without its leading 1.
func rsGenerator(n int) []byte {
	g := make([]byte, n)
	g[n-1] = 1
	root := byte(1)
	for range n {
		for j := range n {
			g[j] = gfMul(g[j], root)
			if j+1 < n {
				g[j] ^= g[j+1]
			}
		}
		root = gfMul(root, 2)
	}
	return g
}

// rsRemainder is data times x^n modulo the generator: the error
// correction codewords.
func rsRemainder(data, gen []byte) []byte {
	rem := make([]byte, len(gen))
	for _, b := range data {
		factor := b ^ rem[0]
		copy(rem, rem[1:])
		rem[len(rem)-1] = 0
		for i, g := range gen {
			rem[i] ^= gfMul(g, factor)
		}
	}
	return rem
}

// symbol is a code being drawn.
type symbol struct {
	version int
	size    int
	dark    []bool
	fixed   []bool // function modules, which masks leave alone
}

func newSymbol(version int) *symbol {
	size := 17 + 4*version
	return &symbol{version: version, size: size, dark: make([]bool, size*size), fixed: make([]bool, size*size)}
}

func (s *symbol) set(x, y int, dark bool) {
	s.dark[y*s.size+x] = dark
	s.fixed[y*s.size+x] = true
}

func (s *symbol) drawFunctionPatterns() {
	for i := range s.size {
		s.set(6, i, i%2 == 0)
		s.set(i, 6, i%2 == 0)
	}
	s.drawFinder(3, 3)
	s.drawFinder(s.size-4, 3)
	s.drawFinder(3, s.size-4)
	pos := alignmentPositions(s.version)
	for i, x := range pos {
		for j, y := range pos {
			// Not over the finder patterns.
			if i == 0 && j == 0 || i == 0 && j == len(pos)-1 || i == len(pos)-1 && j == 0 {
				continue
			}
			s.drawAlignment(x, y)
		}
	}
	// Reserve the format information, which depends on the mask.
	s.drawFormat(L, 0)
	s.drawVersion()
}

// drawFinder draws a finder pattern centred on (x, y), with its separator.
func (s *symbol) drawFinder(x, y int) {
	for dy := -4; dy <= 4; dy++ {
		for dx := -4; dx <= 4; dx++ {
			xx, yy := x+dx, y+dy
			if xx < 0 || yy < 0 || xx >= s.size || yy >= s.size {
				continue
			}
			d := max(abs(dx), abs(dy))
			s.set(xx, yy, d != 2 && d != 4)
		}
	}
}

func (s *symbol) drawAlignment(x, y int) {
	for dy := -2; dy <= 2; dy++ {
		for dx := -2; dx <= 2; dx++ {
			s.set(x+dx, y+dy, max(abs(dx), abs(dy)) != 1)
		}
	}
}

func abs(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// alignmentPositions are the centre coordinates of a version's alignment
// patterns, on both axes.
func alignmentPositions(version int) []int {
	if version == 1 {
		return nil
	}
	n := version/7 + 2
	step := (version*8 + n*3 + 5) / (n*4 - 4) * 2
	pos := make([]int, n)
	pos[0] = 6
	for i, p := n-1, 17+4*version-7; i >= 1; i, p = i-1, p-step {
		pos[i] = p
	}
	return pos
}

// drawFormat draws both copies of the format information: the level and
// the mask, with their BCH code, and the dark module.
func (s *symbol) drawFormat(level Level, mask int) {
	data := level.formatBits()<<3 | mask
	rem := data
	for range 10 {
		rem = rem<<1 ^ (rem>>9)*0x537
	}
	bits := (data<<10 | rem) ^ 0x5412
	bit := func(i int) bool { return bits>>i&1 != 0 }
	for i := range 6 {
		s.set(8, i, bit(i))
	}
	s.set(8, 7, bit(6))
	s.set(8, 8, bit(7))
	s.set(7, 8, bit(8))
	for i := 9; i < 15; i++ {
		s.set(14-i, 8, bit(i))
	}
	for i := range 8 {
		s.set(s.size-1-i, 8, bit(i))
	}
	for i := 8; i < 15; i++ {
		s.set(8, s.size-15+i, bit(i))
	}
	s.set(8, s.size-8, true)
}

// drawVersion draws both copies of the version information (versions 7
// and up).
func (s *symbol) drawVersion() {
	if s.version < 7 {
		return
	}
	rem := s.version
	for range 12 {
		rem = rem<<1 ^ (rem>>11)*0x1F25
	}
	bits := s.version<<12 | rem
	for i := range 18 {
		d := bits>>i&1 != 0
		a, b := s.size-11+i%3, i/3
		s.set(a, b, d)
		s.set(b, a, d)
	}
}

// drawCodewords places the codewords in the zigzag order of the standard,
// two columns at a time from the bottom right, skipping function modules.
func (s *symbol) drawCodewords(data []byte) {
	i := 0
	for right := s.size - 1; right >= 1; right -= 2 {
		if right == 6 {
			right = 5 // the vertical timing pattern
		}
		for vert := range s.size {
			for j := range 2 {
				x := right - j
				y := vert
				if (right+1)&2 == 0 {
					y = s.size - 1 - vert // upwards
				}
				if s.fixed[y*s.size+x] {
					continue
				}
				if i < 8*len(data) {
					s.dark[y*s.size+x] = data[i/8]>>(7-i%8)&1 != 0
					i++
				}
				// Remainder bits stay light.
			}
		}
	}
}

// masked reports whether mask pattern m flips the module at (x, y).
func masked(m, x, y int) bool {
	switch m {
	case 0:
		return (x+y)%2 == 0
	case 1:
		return y%2 == 0
	case 2:
		return x%3 == 0
	case 3:
		return (x+y)%3 == 0
	case 4:
		return (x/3+y/2)%2 == 0
	case 5:
		return x*y%2+x*y%3 == 0
	case 6:
		return (x*y%2+x*y%3)%2 == 0
	case 7:
		return ((x+y)%2+x*y%3)%2 == 0
	}
	panic("svqr: no mask pattern " + fmt.Sprint(m))
}

func (s *symbol) applyMask(m int) {
	for y := range s.size {
		for x := range s.size {
			if !s.fixed[y*s.size+x] && masked(m, x, y) {
				s.dark[y*s.size+x] = !s.dark[y*s.size+x]
			}
		}
	}
}

// Penalty weights (ISO/IEC 18004, section 7.8.3).
const (
	penaltyRun     = 3  // N1: a run of five or more modules of one colour
	penaltyBlock   = 3  // N2: a 2x2 block of one colour
	penaltyFinder  = 40 // N3: a 1:1:3:1:1 pattern beside four light modules
	penaltyBalance = 10 // N4: each 5% the dark share strays from half
)

// penalty scores the symbol as drawn; the lowest score's mask is used.
func (s *symbol) penalty() int {
	n := s.size
	p := 0
	dark := 0
	for y := range n {
		for x := range n {
			if s.dark[y*n+x] {
				dark++
			}
			if x > 0 && y > 0 {
				c := s.dark[y*n+x]
				if s.dark[y*n+x-1] == c && s.dark[(y-1)*n+x] == c && s.dark[(y-1)*n+x-1] == c {
					p += penaltyBlock
				}
			}
		}
	}
	total := n * n
	ratio := (200*dark + total) / total / 2 // percent, rounded
	p += abs(ratio-50) / 5 * penaltyBalance
	runs := make([]int, 0, n+1)
	for i := range n {
		p += runPenalty(s.runs(runs[:0], i, true))
		p += runPenalty(s.runs(runs[:0], i, false))
	}
	return p
}

// runs lists the lengths of the runs of one colour along row (or column)
// i. Even indexes are light runs and odd ones dark: a line that starts
// dark gets a light run of length -1 first, which stands for the edge.
func (s *symbol) runs(out []int, i int, row bool) []int {
	at := func(j int) bool {
		if row {
			return s.dark[i*s.size+j]
		}
		return s.dark[j*s.size+i]
	}
	prev := at(0)
	if prev {
		out = append(out, -1)
	}
	out = append(out, 1)
	for j := 1; j < s.size; j++ {
		if c := at(j); c != prev {
			out = append(out, 1)
			prev = c
		} else {
			out[len(out)-1]++
		}
	}
	return out
}

// runPenalty scores one line's runs: long runs (N1), and finder-like
// dark:light:dark:light:dark runs in the ratio 1:1:3:1:1 at any scale,
// with four times the unit of light (or the edge) before or after (N3).
func runPenalty(runs []int) int {
	p := 0
	for i, r := range runs {
		if r >= 5 {
			p += penaltyRun + r - 5
		}
		if i%2 == 0 || i < 3 || i >= len(runs)-2 || r%3 != 0 {
			continue
		}
		f := r / 3
		if runs[i-2] != f || runs[i-1] != f || runs[i+1] != f || runs[i+2] != f {
			continue
		}
		if i == 3 || runs[i-3] >= 4*f || i+4 >= len(runs) || runs[i+3] >= 4*f {
			p += penaltyFinder
		}
	}
	return p
}
