package svpgp

import (
	"compress/bzip2"
	"compress/flate"
	"compress/zlib"
	"io"
)

// Compressed data packets (RFC 9580, section 5.6). ZIP (raw DEFLATE) and
// ZLIB are read and written; BZip2 is only read. Decompression is bounded
// in size and in ratio, so a small packet cannot become a huge one.

// decompressor wraps a compressed data packet body.
func decompressor(body io.Reader, lim Limits, budget int64) (io.Reader, CompressionAlgorithm, error) {
	var alg [1]byte
	if _, err := io.ReadFull(body, alg[:]); err != nil {
		return nil, 0, truncated(err)
	}
	in := &countingReader{r: body}
	var r io.Reader
	switch CompressionAlgorithm(alg[0]) {
	case ZIP:
		r = flate.NewReader(in)
	case ZLIB:
		zr, err := zlib.NewReader(in)
		if err != nil {
			return nil, 0, malformed("ZLIB data: %v", err)
		}
		r = zr
	case BZip2:
		r = bzip2.NewReader(in)
	case Uncompressed:
		return nil, 0, malformed("a compressed data packet that says it is uncompressed")
	default:
		return nil, 0, unsupported("%v", CompressionAlgorithm(alg[0]))
	}
	return &boundedReader{r: r, in: in, max: budget, ratio: lim.MaxDecompressionRatio}, CompressionAlgorithm(alg[0]), nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// boundedReader stops decompression that grows beyond max bytes, or beyond
// ratio times the compressed size once past the first MiB.
type boundedReader struct {
	r     io.Reader
	in    *countingReader
	out   int64
	max   int64
	ratio int64
}

const ratioGrace = 1 << 20

func (b *boundedReader) Read(p []byte) (int, error) {
	n, err := b.r.Read(p)
	b.out += int64(n)
	if b.out > b.max {
		return 0, limit("decompressed data over %d bytes", b.max)
	}
	if b.out > ratioGrace && b.out > b.ratio*max(b.in.n, 1) {
		return 0, limit("decompression ratio over %d:1", b.ratio)
	}
	if err != nil && err != io.EOF {
		return n, malformed("compressed data: %v", err)
	}
	return n, err
}

// compressor wraps w so what is written is compressed into a compressed
// data packet. Close finishes the packet but not w.
func compressor(w io.Writer, alg CompressionAlgorithm) (io.WriteCloser, error) {
	pw, err := newPartialWriter(w, ptCompressed)
	if err != nil {
		return nil, err
	}
	if _, err := pw.Write([]byte{byte(alg)}); err != nil {
		return nil, err
	}
	var c io.WriteCloser
	switch alg {
	case ZIP:
		c, err = flate.NewWriter(pw, flate.DefaultCompression)
	case ZLIB:
		c, err = zlib.NewWriterLevel(pw, zlib.DefaultCompression)
	default:
		return nil, unsupported("compressing with %v", alg)
	}
	if err != nil {
		return nil, err
	}
	return &compressWriter{c: c, pw: pw}, nil
}

type compressWriter struct {
	c  io.WriteCloser
	pw *partialWriter
}

func (c *compressWriter) Write(p []byte) (int, error) { return c.c.Write(p) }

func (c *compressWriter) Close() error {
	if err := c.c.Close(); err != nil {
		return err
	}
	return c.pw.Close()
}
