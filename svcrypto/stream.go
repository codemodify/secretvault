package svcrypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

// Streams encrypt data too large to hold in memory at once: attachments,
// file encryption, volume contents. The construction is the STREAM online
// AEAD (Hoang, Reyhanitabar, Rogaway, Vizár), as age uses it:
//
//	stream   = salt(16) || chunk*
//	key      = Derive(key, salt || aad, "stream", 32)
//	chunk_i  = AEAD(key, nonce = counter_i(11 bytes BE) || last(1), plaintext_i)
//
// Every chunk but the last holds exactly StreamChunkSize plaintext bytes.
// The last chunk carries the last flag, so a stream cut at a chunk boundary
// fails to open instead of reading as shorter. The last chunk may be empty
// only when it is also the first (an empty stream).

// StreamChunkSize is the plaintext size of every chunk but the last.
const StreamChunkSize = 64 * 1024

const (
	streamSaltSize = 16
	streamTagSize  = 16
	streamEncChunk = StreamChunkSize + streamTagSize
)

// ErrStream is a stream that is truncated, reordered or altered.
var ErrStream = errors.New("svcrypto: stream authentication failed")

func (s Suite) streamAEAD(key, salt, aad []byte) (cipher.AEAD, error) {
	sk := Derive(key, append(append([]byte{}, salt...), aad...), "stream", KeySize)
	defer clear(sk)
	switch s {
	case Modern:
		return chacha20poly1305.New(sk)
	case NIST:
		block, err := aes.NewCipher(sk)
		if err != nil {
			return nil, err
		}
		return cipher.NewGCM(block)
	}
	return nil, ErrSuite
}

func streamNonce(counter uint64, last bool) []byte {
	nonce := make([]byte, 12)
	binary.BigEndian.PutUint64(nonce[3:11], counter)
	if last {
		nonce[11] = 1
	}
	return nonce
}

// StreamWriter encrypts everything written to it. Close must be called to
// write the final chunk; without it the stream will not open.
type StreamWriter struct {
	aead    cipher.AEAD
	w       io.Writer
	buf     []byte
	counter uint64
	err     error
}

// NewStreamWriter starts a stream sealed under key and bound to aad, and
// writes its salt to w.
func (s Suite) NewStreamWriter(key, aad []byte, w io.Writer) (*StreamWriter, error) {
	if len(key) != KeySize {
		return nil, errors.New("svcrypto: stream key must be 32 bytes")
	}
	salt := RandomBytes(streamSaltSize)
	aead, err := s.streamAEAD(key, salt, aad)
	if err != nil {
		return nil, err
	}
	if _, err := w.Write(salt); err != nil {
		return nil, err
	}
	return &StreamWriter{aead: aead, w: w, buf: make([]byte, 0, StreamChunkSize+1)}, nil
}

// Write buffers p and seals every chunk that is known not to be the last.
func (sw *StreamWriter) Write(p []byte) (int, error) {
	if sw.err != nil {
		return 0, sw.err
	}
	n := 0
	for len(p) > 0 {
		take := min(len(p), StreamChunkSize+1-len(sw.buf))
		sw.buf = append(sw.buf, p[:take]...)
		p, n = p[take:], n+take
		// A full chunk with at least one more byte behind it is not the last.
		if len(sw.buf) == StreamChunkSize+1 {
			if err := sw.flush(sw.buf[:StreamChunkSize], false); err != nil {
				return n, err
			}
			extra := sw.buf[StreamChunkSize]
			clear(sw.buf)
			sw.buf = append(sw.buf[:0], extra)
		}
	}
	return n, nil
}

// Close seals the final chunk. The underlying writer is not closed.
func (sw *StreamWriter) Close() error {
	if sw.err != nil {
		return sw.err
	}
	err := sw.flush(sw.buf, true)
	clear(sw.buf)
	sw.err = errors.New("svcrypto: stream writer is closed")
	return err
}

func (sw *StreamWriter) flush(chunk []byte, last bool) error {
	out := sw.aead.Seal(nil, streamNonce(sw.counter, last), chunk, nil)
	sw.counter++
	if _, err := sw.w.Write(out); err != nil {
		sw.err = err
		return err
	}
	return nil
}

// StreamReader decrypts a stream, returning plaintext only after its chunk
// has been authenticated. An error from Read means the stream must not be
// trusted, including everything already read from it when the error is
// ErrStream at the end.
type StreamReader struct {
	aead    cipher.AEAD
	r       io.Reader
	in      []byte // ciphertext read ahead: up to one chunk plus one byte
	out     []byte // authenticated plaintext not yet returned
	counter uint64
	done    bool
	err     error
}

// NewStreamReader reads the stream's salt from r and prepares to decrypt.
func (s Suite) NewStreamReader(key, aad []byte, r io.Reader) (*StreamReader, error) {
	if len(key) != KeySize {
		return nil, errors.New("svcrypto: stream key must be 32 bytes")
	}
	salt := make([]byte, streamSaltSize)
	if _, err := io.ReadFull(r, salt); err != nil {
		return nil, ErrStream
	}
	aead, err := s.streamAEAD(key, salt, aad)
	if err != nil {
		return nil, err
	}
	return &StreamReader{aead: aead, r: r, in: make([]byte, 0, streamEncChunk+1)}, nil
}

// Read returns authenticated plaintext.
func (sr *StreamReader) Read(p []byte) (int, error) {
	for len(sr.out) == 0 {
		if sr.err != nil {
			return 0, sr.err
		}
		if sr.done {
			return 0, io.EOF
		}
		sr.err = sr.next()
	}
	n := copy(p, sr.out)
	sr.out = sr.out[n:]
	return n, nil
}

func (sr *StreamReader) next() error {
	have := len(sr.in)
	n, err := io.ReadFull(sr.r, sr.in[have:streamEncChunk+1])
	sr.in = sr.in[:have+n]
	switch {
	case err == nil:
		// More follows, so this chunk is not the last.
		pt, err := sr.aead.Open(nil, streamNonce(sr.counter, false), sr.in[:streamEncChunk], nil)
		if err != nil {
			return ErrStream
		}
		sr.counter++
		sr.in = append(sr.in[:0], sr.in[streamEncChunk])
		sr.out = pt
		return nil
	case errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF):
		pt, err := sr.aead.Open(nil, streamNonce(sr.counter, true), sr.in, nil)
		if err != nil || (len(pt) == 0 && sr.counter > 0) {
			return ErrStream
		}
		sr.done = true
		sr.in = sr.in[:0]
		sr.out = pt
		return nil
	default:
		return err
	}
}
