package svimport

import (
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/chacha20"
	"golang.org/x/crypto/salsa20/salsa"
	"golang.org/x/crypto/twofish"
)

// KeePass's KDBX files, versions 3.1 and 4.x
// (https://keepass.info/help/kb/kdbx.html, kdbx_4.1.html). The outer
// layers, from the file inwards:
//
//   - a header of typed fields: the cipher (AES-256-CBC, ChaCha20 or
//     Twofish-CBC), gzip or not, a master seed, an IV, and the key
//     derivation: AES-KDF (version 3.1: the transform seed and rounds;
//     version 4: in a "variant dictionary", which may instead name Argon2d
//     or Argon2id);
//   - the composite key: SHA-256 over SHA-256(password) and the key
//     file's key (kdbxkey.go), transformed by the KDF, then hashed with the
//     master seed into the cipher key;
//   - version 3.1: the whole payload encrypted, starting with 32 known
//     "stream start bytes" (a wrong key shows there), then blocks each
//     carrying its SHA-256;
//   - version 4: the header's SHA-256 and HMAC-SHA-256 (a wrong key shows
//     there), then HMAC-SHA-256-authenticated blocks of ciphertext, whose
//     plaintext starts with an inner header: the inner stream cipher, its
//     key, and attachments;
//   - gzip, then XML (kdbxxml.go), in which protected values are XORed
//     with the inner stream: Salsa20 (3.1) or ChaCha20 (4).

var (
	kdbxAES      = mustUUID("31c1f2e6bf714350be5805216afc5aff")
	kdbxChaCha20 = mustUUID("d6038a2b8b6f4cb5a524339a31dbb59a")
	kdbxTwofish  = mustUUID("ad68f29f576f4bb9a36ad47af965346c")

	kdfAES3     = mustUUID("c9d9f39a628a4460bf740d08c18a4fea") // KeePass's AES-KDF
	kdfAES4     = mustUUID("7c02bb8279a74ac0927d114a00648238") // KeePassXC's name for it in KDBX 4
	kdfArgon2d  = mustUUID("ef636ddf8c29444b91f7a9a403e30a0c")
	kdfArgon2id = mustUUID("9e298b1956db4773b23dfc3ec6f0a1e6")

	// salsaNonce is the fixed nonce of KDBX 3.1's inner Salsa20 stream.
	salsaNonce = []byte{0xe8, 0x30, 0x09, 0x4b, 0x97, 0x20, 0x5d, 0x2a}
)

func mustUUID(s string) string {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		panic("svimport: bad UUID " + s)
	}
	return string(b)
}

// Header field ids.
const (
	hEnd             = 0
	hCipher          = 2
	hCompression     = 3
	hMasterSeed      = 4
	hTransformSeed   = 5 // 3.1
	hTransformRounds = 6 // 3.1
	hIV              = 7
	hStreamKey       = 8  // 3.1
	hStreamStart     = 9  // 3.1
	hStreamID        = 10 // 3.1
	hKDF             = 11 // 4
)

// Inner stream ciphers.
const (
	streamNone     = 0
	streamSalsa20  = 2
	streamChaCha20 = 3
)

type kdbxHeader struct {
	major, minor  uint16
	cipher        string
	gzip          bool
	masterSeed    []byte
	iv            []byte
	transformSeed []byte // 3.1
	rounds        uint64 // 3.1
	streamKey     []byte // 3.1
	streamStart   []byte // 3.1
	streamID      uint32 // 3.1
	kdf           vdict  // 4
	raw           []byte // the header's bytes, for its hash and HMAC

	binaries [][]byte // 4: the attachments, from the inner header
}

func parseKDBXHeader(data []byte) (*kdbxHeader, error) {
	if len(data) < 12 || !bytes.HasPrefix(data, kdbxSignature[:4]) {
		return nil, fmt.Errorf("%w: not a KeePass file", ErrFormat)
	}
	switch sig2 := binary.LittleEndian.Uint32(data[4:]); sig2 {
	case 0xb54bfb67:
	case 0xb54bfb66:
		return nil, fmt.Errorf("%w: a KeePass 1.x (.kdb) database; open it in KeePass 2 or KeePassXC and save it as .kdbx", ErrUnsupported)
	default:
		return nil, fmt.Errorf("%w: not a KDBX file", ErrFormat)
	}
	v := binary.LittleEndian.Uint32(data[8:])
	h := &kdbxHeader{major: uint16(v >> 16), minor: uint16(v)}
	if h.major != 3 && h.major != 4 {
		return nil, fmt.Errorf("%w: KDBX version %d.%d (this reads 3.1 and 4.x)", ErrUnsupported, h.major, h.minor)
	}
	p := 12
	for {
		sizeLen := 2
		if h.major >= 4 {
			sizeLen = 4
		}
		if len(data) < p+1+sizeLen {
			return nil, fmt.Errorf("%w: the KDBX header is cut short", ErrFormat)
		}
		id := data[p]
		var n int
		if sizeLen == 2 {
			n = int(binary.LittleEndian.Uint16(data[p+1:]))
		} else {
			n = int(binary.LittleEndian.Uint32(data[p+1:]))
		}
		p += 1 + sizeLen
		if n < 0 || n > len(data)-p {
			return nil, fmt.Errorf("%w: the KDBX header is cut short", ErrFormat)
		}
		val := data[p : p+n]
		p += n
		var err error
		switch id {
		case hEnd:
			h.raw = data[:p]
			return h, h.check()
		case hCipher:
			h.cipher = string(val)
		case hCompression:
			h.gzip = len(val) == 4 && binary.LittleEndian.Uint32(val) == 1
		case hMasterSeed:
			h.masterSeed = val
		case hTransformSeed:
			h.transformSeed = val
		case hTransformRounds:
			if len(val) == 8 {
				h.rounds = binary.LittleEndian.Uint64(val)
			}
		case hIV:
			h.iv = val
		case hStreamKey:
			h.streamKey = val
		case hStreamStart:
			h.streamStart = val
		case hStreamID:
			if len(val) == 4 {
				h.streamID = binary.LittleEndian.Uint32(val)
			}
		case hKDF:
			h.kdf, err = parseVariantDict(val)
		}
		if err != nil {
			return nil, err
		}
	}
}

func (h *kdbxHeader) check() error {
	switch {
	case h.cipher != kdbxAES && h.cipher != kdbxChaCha20 && h.cipher != kdbxTwofish:
		return fmt.Errorf("%w: KDBX cipher %x", ErrUnsupported, h.cipher)
	case len(h.masterSeed) != 32:
		return fmt.Errorf("%w: KDBX master seed", ErrFormat)
	case h.cipher == kdbxChaCha20 && len(h.iv) != 12, h.cipher != kdbxChaCha20 && len(h.iv) != 16:
		return fmt.Errorf("%w: KDBX IV", ErrFormat)
	case h.major == 3 && (len(h.transformSeed) != 32 || len(h.streamStart) != 32):
		return fmt.Errorf("%w: KDBX 3 key parameters", ErrFormat)
	case h.major == 4 && h.kdf == nil:
		return fmt.Errorf("%w: KDBX 4 without key derivation parameters", ErrFormat)
	}
	return nil
}

// readKDBX opens a KDBX file and reads its entries.
func readKDBX(b *builder, data []byte, opts Options) error {
	h, err := parseKDBXHeader(data)
	if err != nil {
		return err
	}
	if len(opts.Passphrase) == 0 && len(opts.Keyfile) == 0 {
		return ErrPassphrase
	}
	b.crypted = true
	composite, err := kdbxCompositeKey(opts.Passphrase, opts.Keyfile)
	if err != nil {
		return err
	}
	defer clear(composite)
	transformed, err := h.transformKey(composite)
	if err != nil {
		return err
	}
	defer clear(transformed)
	var xmlData []byte
	var stream innerStream
	if h.major == 3 {
		xmlData, stream, err = h.openV3(data[len(h.raw):], transformed)
	} else {
		xmlData, stream, err = h.openV4(data[len(h.raw):], transformed)
	}
	if err != nil {
		return err
	}
	defer clear(xmlData)
	return kdbxRead(b, h, xmlData, stream)
}

// cipherKey is SHA-256(master seed || transformed key).
func (h *kdbxHeader) cipherKey(transformed []byte) []byte {
	s := sha256.New()
	s.Write(h.masterSeed)
	s.Write(transformed)
	return s.Sum(nil)
}

// decrypt removes the outer cipher. It returns errBadPadding when CBC
// padding is wrong, which is how a wrong key can show in a KDBX 3.1 file.
func (h *kdbxHeader) decrypt(key, ct []byte) ([]byte, error) {
	out := make([]byte, len(ct))
	if h.cipher == kdbxChaCha20 {
		c, err := chacha20.NewUnauthenticatedCipher(key, h.iv)
		if err != nil {
			return nil, err
		}
		c.XORKeyStream(out, ct)
		return out, nil
	}
	var blk cipher.Block
	var err error
	if h.cipher == kdbxTwofish {
		blk, err = twofish.NewCipher(key)
	} else {
		blk, err = aes.NewCipher(key)
	}
	if err != nil {
		return nil, err
	}
	if len(ct) == 0 || len(ct)%blk.BlockSize() != 0 {
		return nil, fmt.Errorf("%w: the KDBX payload is cut short", ErrFormat)
	}
	cipher.NewCBCDecrypter(blk, h.iv).CryptBlocks(out, ct)
	plain, err := unpad(out, blk.BlockSize())
	if err != nil {
		clear(out)
		return nil, errBadPadding
	}
	return plain, nil
}

var errBadPadding = errors.New("bad padding")

func (h *kdbxHeader) openV3(payload, transformed []byte) ([]byte, innerStream, error) {
	key := h.cipherKey(transformed)
	defer clear(key)
	plain, err := h.decrypt(key, payload)
	if errors.Is(err, errBadPadding) {
		return nil, nil, ErrWrongKey
	}
	if err != nil {
		return nil, nil, err
	}
	defer clear(plain)
	if len(plain) < 32 || subtle.ConstantTimeCompare(plain[:32], h.streamStart) != 1 {
		return nil, nil, ErrWrongKey
	}
	body, err := readHashedBlocks(plain[32:])
	if err != nil {
		return nil, nil, err
	}
	if h.gzip {
		z, err := gunzip(body)
		clear(body)
		if err != nil {
			return nil, nil, err
		}
		body = z
	}
	stream, err := newInnerStream(h.streamID, h.streamKey)
	if err != nil {
		clear(body)
		return nil, nil, err
	}
	return body, stream, nil
}

func (h *kdbxHeader) openV4(rest, transformed []byte) ([]byte, innerStream, error) {
	if len(rest) < 64 {
		return nil, nil, fmt.Errorf("%w: the KDBX file is cut short", ErrFormat)
	}
	sum := sha256.Sum256(h.raw)
	if subtle.ConstantTimeCompare(sum[:], rest[:32]) != 1 {
		return nil, nil, fmt.Errorf("%w: the KDBX header is damaged", ErrFormat)
	}
	hmacKey := kdbxHMACKey(h.masterSeed, transformed)
	defer clear(hmacKey)
	if !hmac.Equal(kdbxBlockMAC(hmacKey, ^uint64(0), h.raw, false), rest[32:64]) {
		return nil, nil, ErrWrongKey
	}
	ct, err := readHMACBlocks(rest[64:], hmacKey)
	if err != nil {
		return nil, nil, err
	}
	key := h.cipherKey(transformed)
	defer clear(key)
	plain, err := h.decrypt(key, ct)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the KDBX payload does not decrypt", ErrFormat)
	}
	if h.gzip {
		z, err := gunzip(plain)
		clear(plain)
		if err != nil {
			return nil, nil, err
		}
		plain = z
	}
	id, sk, binaries, n, err := readInnerHeader(plain)
	if err != nil {
		clear(plain)
		return nil, nil, err
	}
	h.binaries = binaries
	stream, err := newInnerStream(id, sk)
	if err != nil {
		clear(plain)
		return nil, nil, err
	}
	xmlData := append([]byte(nil), plain[n:]...)
	clear(plain)
	return xmlData, stream, nil
}

// kdbxHMACKey is SHA-512(master seed || transformed key || 0x01).
func kdbxHMACKey(seed, transformed []byte) []byte {
	s := sha512.New()
	s.Write(seed)
	s.Write(transformed)
	s.Write([]byte{1})
	return s.Sum(nil)
}

// kdbxBlockMAC authenticates block i (the header is block 2^64-1): the key
// is SHA-512(i || HMAC key), over i || size || data for blocks, over the
// data alone for the header.
func kdbxBlockMAC(hmacKey []byte, i uint64, data []byte, block bool) []byte {
	s := sha512.New()
	s.Write(binary.LittleEndian.AppendUint64(nil, i))
	s.Write(hmacKey)
	k := s.Sum(nil)
	defer clear(k)
	m := hmac.New(sha256.New, k)
	if block {
		m.Write(binary.LittleEndian.AppendUint64(nil, i))
		m.Write(binary.LittleEndian.AppendUint32(nil, uint32(len(data))))
	}
	m.Write(data)
	return m.Sum(nil)
}

// readHMACBlocks reads KDBX 4's authenticated blocks: MAC (32), size (4),
// data; an empty block ends them.
func readHMACBlocks(b, hmacKey []byte) ([]byte, error) {
	var out []byte
	for i := uint64(0); ; i++ {
		if len(b) < 36 {
			return nil, fmt.Errorf("%w: the KDBX blocks are cut short", ErrFormat)
		}
		mac, size := b[:32], binary.LittleEndian.Uint32(b[32:36])
		b = b[36:]
		if uint64(size) > uint64(len(b)) {
			return nil, fmt.Errorf("%w: the KDBX blocks are cut short", ErrFormat)
		}
		blk := b[:size]
		if !hmac.Equal(kdbxBlockMAC(hmacKey, i, blk, true), mac) {
			return nil, fmt.Errorf("%w: KDBX block %d does not authenticate: the file is damaged", ErrFormat, i)
		}
		if size == 0 {
			return out, nil
		}
		out = append(out, blk...)
		b = b[size:]
	}
}

// readHashedBlocks reads KDBX 3.1's blocks: index (4), SHA-256 (32),
// size (4), data; an empty block with a zero hash ends them.
func readHashedBlocks(b []byte) ([]byte, error) {
	var out []byte
	for i := uint32(0); ; i++ {
		if len(b) < 40 {
			return nil, fmt.Errorf("%w: the KDBX blocks are cut short", ErrFormat)
		}
		idx, hash, size := binary.LittleEndian.Uint32(b), b[4:36], binary.LittleEndian.Uint32(b[36:40])
		b = b[40:]
		if idx != i || uint64(size) > uint64(len(b)) {
			return nil, fmt.Errorf("%w: the KDBX blocks are out of order or cut short", ErrFormat)
		}
		if size == 0 {
			if !bytes.Equal(hash, make([]byte, 32)) {
				return nil, fmt.Errorf("%w: the last KDBX block is malformed", ErrFormat)
			}
			return out, nil
		}
		sum := sha256.Sum256(b[:size])
		if !bytes.Equal(sum[:], hash) {
			return nil, fmt.Errorf("%w: KDBX block %d does not match its hash: the file is damaged", ErrFormat, i)
		}
		out = append(out, b[:size]...)
		b = b[size:]
	}
}

// readInnerHeader reads KDBX 4's inner header: the inner stream's cipher
// and key, and the attachments (type 3: a flags byte, then the contents),
// which entries refer to by their position. n is the header's length.
func readInnerHeader(b []byte) (id uint32, key []byte, binaries [][]byte, n int, err error) {
	for {
		if len(b)-n < 5 {
			return 0, nil, nil, 0, fmt.Errorf("%w: the KDBX inner header is cut short", ErrFormat)
		}
		typ, size := b[n], binary.LittleEndian.Uint32(b[n+1:])
		n += 5
		if uint64(size) > uint64(len(b)-n) {
			return 0, nil, nil, 0, fmt.Errorf("%w: the KDBX inner header is cut short", ErrFormat)
		}
		val := b[n : n+int(size)]
		n += int(size)
		switch typ {
		case 0:
			return id, key, binaries, n, nil
		case 1:
			if len(val) == 4 {
				id = binary.LittleEndian.Uint32(val)
			}
		case 2:
			key = append([]byte(nil), val...)
		case 3:
			if len(val) == 0 {
				return 0, nil, nil, 0, fmt.Errorf("%w: an empty KDBX attachment", ErrFormat)
			}
			binaries = append(binaries, append([]byte(nil), val[1:]...))
		}
	}
}

func gunzip(b []byte) ([]byte, error) {
	z, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%w: KDBX gzip: %v", ErrFormat, err)
	}
	out, err := io.ReadAll(io.LimitReader(z, maxInput+1))
	if err != nil {
		return nil, fmt.Errorf("%w: KDBX gzip: %v", ErrFormat, err)
	}
	if len(out) > maxInput {
		return nil, fmt.Errorf("%w: the KDBX contents are larger than %d MiB", ErrUnsupported, maxInput>>20)
	}
	return out, nil
}

// innerStream is the keystream protected values are XORed with, consumed
// in document order.
type innerStream interface {
	XORKeyStream(dst, src []byte)
}

func newInnerStream(id uint32, key []byte) (innerStream, error) {
	switch id {
	case streamNone:
		return nullStream{}, nil
	case streamSalsa20:
		s := &salsaStream{pos: 64}
		s.key = sha256.Sum256(key)
		copy(s.counter[:8], salsaNonce)
		return s, nil
	case streamChaCha20:
		h := sha512.Sum512(key)
		defer clear(h[:])
		return chacha20.NewUnauthenticatedCipher(h[:32], h[32:44])
	}
	return nil, fmt.Errorf("%w: KDBX inner stream %d (ArcFour, from KeePass 2.0x)", ErrUnsupported, id)
}

type nullStream struct{}

func (nullStream) XORKeyStream(dst, src []byte) { copy(dst, src) }

// salsaStream is Salsa20 as a continuing keystream: x/crypto's salsa20
// starts afresh at every call, and KDBX 3.1 needs one stream across all
// protected values.
type salsaStream struct {
	key     [32]byte
	counter [16]byte // nonce, then the little-endian block counter
	buf     [64]byte
	pos     int
}

func (s *salsaStream) XORKeyStream(dst, src []byte) {
	var zero [64]byte
	for i := range src {
		if s.pos == 64 {
			salsa.XORKeyStream(s.buf[:], zero[:], &s.counter, &s.key)
			binary.LittleEndian.PutUint64(s.counter[8:], binary.LittleEndian.Uint64(s.counter[8:])+1)
			s.pos = 0
		}
		dst[i] = src[i] ^ s.buf[s.pos]
		s.pos++
	}
}

// vdict is KDBX 4's variant dictionary: typed values by name.
type vdict map[string]vdValue

type vdValue struct {
	typ byte
	b   []byte
}

// Variant dictionary value types.
const (
	vdUint32 = 0x04
	vdUint64 = 0x05
	vdBool   = 0x08
	vdInt32  = 0x0c
	vdInt64  = 0x0d
	vdString = 0x18
	vdBytes  = 0x42
)

func parseVariantDict(b []byte) (vdict, error) {
	bad := fmt.Errorf("%w: malformed KDBX variant dictionary", ErrFormat)
	if len(b) < 2 || b[1] > 1 {
		return nil, bad
	}
	d := vdict{}
	p := 2
	for {
		if p >= len(b) {
			return nil, bad
		}
		typ := b[p]
		p++
		if typ == 0 {
			return d, nil
		}
		if len(b)-p < 4 {
			return nil, bad
		}
		kl := int(binary.LittleEndian.Uint32(b[p:]))
		p += 4
		if kl < 0 || kl > len(b)-p-4 {
			return nil, bad
		}
		k := string(b[p : p+kl])
		p += kl
		vl := int(binary.LittleEndian.Uint32(b[p:]))
		p += 4
		if vl < 0 || vl > len(b)-p {
			return nil, bad
		}
		d[k] = vdValue{typ, b[p : p+vl]}
		p += vl
	}
}

func (d vdict) bytes(k string) []byte { return d[k].b }

func (d vdict) uint(k string) (uint64, bool) {
	v, ok := d[k]
	switch {
	case !ok:
		return 0, false
	case (v.typ == vdUint32 || v.typ == vdInt32) && len(v.b) == 4:
		return uint64(binary.LittleEndian.Uint32(v.b)), true
	case (v.typ == vdUint64 || v.typ == vdInt64) && len(v.b) == 8:
		return binary.LittleEndian.Uint64(v.b), true
	}
	return 0, false
}
