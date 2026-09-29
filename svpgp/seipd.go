package svpgp

import (
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"hash"
	"io"
)

// Encrypted data packets: SEIPD version 1 (CFB with a SHA-1 modification
// detection code) and version 2 (AEAD in chunks), RFC 9580 section 5.13,
// and the old SED packet (section 5.7), which has no integrity protection
// and is only read when asked to.

type encryptedData struct {
	tag        packetType // ptSEIPD or ptSED
	version    int        // SEIPD version: 1 or 2; 0 for SED
	cipher     CipherAlgorithm
	aead       AEADAlgorithm
	chunkByte  byte
	salt       []byte
	ciphertext []byte
}

// maxChunkByte is the largest v2 SEIPD chunk size octet accepted: 16, for
// 4 MiB chunks, the most a writer may use (RFC 9580, section 5.13.2).
const maxChunkByte = 16

// defaultChunkByte is the chunk size octet used when encrypting: 64 KiB.
const defaultChunkByte = 10

// readEncryptedData reads an encrypted data packet whole, up to max bytes
// of ciphertext.
func readEncryptedData(tag packetType, body *bodyReader, max int64) (*encryptedData, error) {
	ed := &encryptedData{tag: tag}
	if tag == ptSEIPD {
		var v [1]byte
		if _, err := io.ReadFull(body, v[:]); err != nil {
			return nil, truncated(err)
		}
		ed.version = int(v[0])
		switch ed.version {
		case 1:
		case 2:
			var hdr [35]byte
			if _, err := io.ReadFull(body, hdr[:]); err != nil {
				return nil, truncated(err)
			}
			ed.cipher, ed.aead, ed.chunkByte = CipherAlgorithm(hdr[0]), AEADAlgorithm(hdr[1]), hdr[2]
			ed.salt = append([]byte{}, hdr[3:]...)
			if ed.chunkByte > maxChunkByte {
				return nil, unsupported("v2 SEIPD chunk size octet %d", ed.chunkByte)
			}
			if !ed.cipher.isAES() {
				return nil, unsupported("v2 SEIPD with %v", ed.cipher)
			}
			if ed.aead.nonceSize() == 0 {
				return nil, unsupported("v2 SEIPD with %v", ed.aead)
			}
		default:
			return nil, unsupported("version %d SEIPD packets", ed.version)
		}
	}
	ct, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(ct)) > max {
		return nil, limit("encrypted data over %d bytes", max)
	}
	ed.ciphertext = ct
	return ed, nil
}

var errQuickCheck = errors.New("svpgp: quick check failed")

// quickCheck tests a v1 SEIPD or SED session key on the repeated prefix
// bytes. It is only used to choose between several candidate keys, never
// reported on its own (RFC 9580, section 13.4).
func (ed *encryptedData) quickCheck(alg CipherAlgorithm, key []byte) bool {
	block, err := alg.newBlock(key)
	if err != nil {
		return false
	}
	bs := block.BlockSize()
	if len(ed.ciphertext) < bs+2 {
		return false
	}
	prefix := make([]byte, bs+2)
	newCFB(block, make([]byte, bs), true).XORKeyStream(prefix, ed.ciphertext[:bs+2])
	return prefix[bs-2] == prefix[bs] && prefix[bs-1] == prefix[bs+1]
}

// decrypt decrypts with a session key and checks integrity. All failures
// are ErrDecryption.
func (ed *encryptedData) decrypt(alg CipherAlgorithm, key []byte) ([]byte, error) {
	switch {
	case ed.tag == ptSED:
		return ed.decryptSED(alg, key)
	case ed.version == 1:
		return ed.decryptV1(alg, key)
	case ed.version == 2:
		return ed.decryptV2(key)
	}
	return nil, ErrDecryption
}

func (ed *encryptedData) decryptV1(alg CipherAlgorithm, key []byte) ([]byte, error) {
	block, err := alg.newBlock(key)
	if err != nil {
		return nil, ErrDecryption
	}
	bs := block.BlockSize()
	ct := ed.ciphertext
	if len(ct) < bs+2+2+sha1.Size {
		return nil, ErrDecryption
	}
	plain := make([]byte, len(ct))
	newCFB(block, make([]byte, bs), true).XORKeyStream(plain, ct)
	mdc := len(plain) - sha1.Size - 2
	sum := sha1.Sum(plain[:mdc+2])
	ok := subtle.ConstantTimeByteEq(plain[mdc], 0xD3) & subtle.ConstantTimeByteEq(plain[mdc+1], 0x14) &
		subtle.ConstantTimeCompare(sum[:], plain[mdc+2:])
	if ok != 1 {
		clear(plain)
		return nil, ErrDecryption
	}
	return plain[bs+2 : mdc], nil
}

// decryptSED decrypts the old packet: the prefix with a zero IV, then the
// data with the CFB state resynchronised (RFC 9580, section 5.7). There is
// nothing to check.
func (ed *encryptedData) decryptSED(alg CipherAlgorithm, key []byte) ([]byte, error) {
	block, err := alg.newBlock(key)
	if err != nil {
		return nil, ErrDecryption
	}
	bs := block.BlockSize()
	ct := ed.ciphertext
	if len(ct) < bs+2 {
		return nil, ErrDecryption
	}
	plain := make([]byte, len(ct)-bs-2)
	newCFB(block, ct[2:bs+2], true).XORKeyStream(plain, ct[bs+2:])
	return plain, nil
}

// v2Keys derives the message key and IV of a v2 SEIPD packet.
func v2Keys(alg CipherAlgorithm, mode AEADAlgorithm, chunkByte byte, salt, sessionKey []byte) (cipher.AEAD, []byte, []byte, error) {
	info := []byte{0xC0 | byte(ptSEIPD), 2, byte(alg), byte(mode), chunkByte}
	keyLen, nonceLen := alg.KeySize(), mode.nonceSize()
	okm, err := hkdf.Key(sha256.New, sessionKey, salt, string(info), keyLen+nonceLen-8)
	if err != nil {
		return nil, nil, nil, err
	}
	defer clear(okm[:keyLen])
	aead, err := mode.newAEAD(alg, okm[:keyLen])
	if err != nil {
		return nil, nil, nil, err
	}
	return aead, append([]byte{}, okm[keyLen:]...), info, nil
}

func (ed *encryptedData) decryptV2(key []byte) ([]byte, error) {
	if len(key) != ed.cipher.KeySize() {
		return nil, ErrDecryption
	}
	aead, iv, ad, err := v2Keys(ed.cipher, ed.aead, ed.chunkByte, ed.salt, key)
	if err != nil {
		return nil, ErrDecryption
	}
	chunk := 1 << (int(ed.chunkByte) + 6)
	data := ed.ciphertext
	if len(data) < aeadTagSize {
		return nil, ErrDecryption
	}
	final := data[len(data)-aeadTagSize:]
	data = data[:len(data)-aeadTagSize]
	nonce := make([]byte, len(iv)+8)
	copy(nonce, iv)
	out := make([]byte, 0, len(data))
	var index uint64
	for len(data) > 0 {
		n := min(len(data), chunk+aeadTagSize)
		if n <= aeadTagSize {
			// Only an empty message has an empty chunk, and it has none.
			return nil, ErrDecryption
		}
		binary.BigEndian.PutUint64(nonce[len(iv):], index)
		if out, err = aead.Open(out, nonce, data[:n], ad); err != nil {
			clear(out)
			return nil, ErrDecryption
		}
		data = data[n:]
		index++
	}
	binary.BigEndian.PutUint64(nonce[len(iv):], index)
	finalAD := binary.BigEndian.AppendUint64(append([]byte{}, ad...), uint64(len(out)))
	if _, err := aead.Open(nil, nonce, final, finalAD); err != nil {
		clear(out)
		return nil, ErrDecryption
	}
	return out, nil
}

// seipdV1Writer encrypts a stream into a v1 SEIPD packet.
type seipdV1Writer struct {
	pw  *partialWriter
	cfb *cfb
	mdc hash.Hash
	buf []byte
}

func newSEIPDv1Writer(w io.Writer, alg CipherAlgorithm, key []byte) (io.WriteCloser, error) {
	block, err := alg.newBlock(key)
	if err != nil {
		return nil, err
	}
	pw, err := newPartialWriter(w, ptSEIPD)
	if err != nil {
		return nil, err
	}
	if _, err := pw.Write([]byte{1}); err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	sw := &seipdV1Writer{pw: pw, cfb: newCFB(block, make([]byte, bs), false), mdc: sha1.New()}
	prefix := make([]byte, bs+2)
	rand.Read(prefix[:bs])
	prefix[bs], prefix[bs+1] = prefix[bs-2], prefix[bs-1]
	if _, err := sw.Write(prefix); err != nil {
		return nil, err
	}
	return sw, nil
}

func (sw *seipdV1Writer) Write(p []byte) (int, error) {
	sw.mdc.Write(p)
	if cap(sw.buf) < len(p) {
		sw.buf = make([]byte, len(p))
	}
	out := sw.buf[:len(p)]
	sw.cfb.XORKeyStream(out, p)
	if _, err := sw.pw.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (sw *seipdV1Writer) Close() error {
	trailer := []byte{0xD3, 0x14}
	sw.mdc.Write(trailer)
	trailer = sw.mdc.Sum(trailer)
	out := make([]byte, len(trailer))
	sw.cfb.XORKeyStream(out, trailer)
	if _, err := sw.pw.Write(out); err != nil {
		return err
	}
	clear(sw.buf)
	return sw.pw.Close()
}

// seipdV2Writer encrypts a stream into a v2 SEIPD packet.
type seipdV2Writer struct {
	pw    *partialWriter
	aead  cipher.AEAD
	nonce []byte // the IV, then the chunk index
	ivLen int
	ad    []byte
	chunk int
	buf   []byte
	index uint64
	total uint64
}

func newSEIPDv2Writer(w io.Writer, alg CipherAlgorithm, mode AEADAlgorithm, key []byte) (io.WriteCloser, error) {
	salt := make([]byte, 32)
	rand.Read(salt)
	aead, iv, ad, err := v2Keys(alg, mode, defaultChunkByte, salt, key)
	if err != nil {
		return nil, err
	}
	pw, err := newPartialWriter(w, ptSEIPD)
	if err != nil {
		return nil, err
	}
	hdr := append([]byte{2, byte(alg), byte(mode), defaultChunkByte}, salt...)
	if _, err := pw.Write(hdr); err != nil {
		return nil, err
	}
	chunk := 1 << (defaultChunkByte + 6)
	nonce := make([]byte, len(iv)+8)
	copy(nonce, iv)
	return &seipdV2Writer{pw: pw, aead: aead, nonce: nonce, ivLen: len(iv), ad: ad, chunk: chunk, buf: make([]byte, 0, chunk+aeadTagSize)}, nil
}

func (sw *seipdV2Writer) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		k := min(len(p), sw.chunk-len(sw.buf))
		sw.buf = append(sw.buf, p[:k]...)
		p = p[k:]
		if len(sw.buf) == sw.chunk {
			if err := sw.flush(); err != nil {
				return n - len(p), err
			}
		}
	}
	return n, nil
}

func (sw *seipdV2Writer) flush() error {
	binary.BigEndian.PutUint64(sw.nonce[sw.ivLen:], sw.index)
	sw.total += uint64(len(sw.buf))
	sealed := sw.aead.Seal(sw.buf[:0], sw.nonce, sw.buf, sw.ad)
	sw.index++
	_, err := sw.pw.Write(sealed)
	sw.buf = sw.buf[:0]
	return err
}

func (sw *seipdV2Writer) Close() error {
	if len(sw.buf) > 0 {
		if err := sw.flush(); err != nil {
			return err
		}
	}
	binary.BigEndian.PutUint64(sw.nonce[sw.ivLen:], sw.index)
	finalAD := binary.BigEndian.AppendUint64(append([]byte{}, sw.ad...), sw.total)
	if _, err := sw.pw.Write(sw.aead.Seal(nil, sw.nonce, nil, finalAD)); err != nil {
		return err
	}
	return sw.pw.Close()
}
