package svformat

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/codemodify/secretvault/svcrypto"
)

// A blob is the contents of one attached file, in a file of its own:
//
//	blobs/<id[0:2]>/<blob id>.svb
//
//	blob   = prefix || stream
//	prefix = "SVB1" || suite(1) || 0x00 || header_len(2, BE) || header
//	header = TLV {
//	    0x01 vault ID (16)
//	    0x02 blob ID (16)
//	}
//	stream = STREAM(content key, contents || zeros to Padmé length, aad = prefix)
//
// The content key is random, one per blob, and kept only in the item the
// file is attached to (inside its encrypted payload), with the file's
// name, type, size and SHA-256. So a blob opens only for whoever can read
// that item; the item stays small however large its files are; and a
// rotation, which writes every item again under the new key, leaves blobs
// alone: a file attached after it has a key that exists only under the
// new epoch. Blobs are written once and never changed, like revisions;
// one no revision refers to any more is garbage, never a risk.

// BlobsDir holds the blobs.
const BlobsDir = "blobs"

// BlobExt ends a blob's name.
const BlobExt = ".svb"

// MaxBlob is the largest file that can be attached, and MaxBlobFile the
// largest its blob can be (with padding and the stream's tags).
const (
	MaxBlob     = 64 << 20
	MaxBlobFile = MaxBlob + 4<<20
)

// IsBlob reports whether a file starts as a blob does, for a store that
// never opens it.
func IsBlob(file []byte) bool { return bytes.HasPrefix(file, []byte(blobMagic)) }

const blobMagic = "SVB1"

// ErrBlob is a blob that is malformed, of another vault or blob, or that
// does not authenticate.
var ErrBlob = errors.New("svformat: malformed or damaged attachment")

// BlobName is where a blob lives.
func BlobName(id ID) string {
	s := id.String()
	return BlobsDir + "/" + s[:2] + "/" + s + BlobExt
}

// ParseBlobName reads the blob ID back out of its name.
func ParseBlobName(name string) (ID, bool) {
	parts := strings.Split(name, "/")
	if len(parts) != 3 || parts[0] != BlobsDir || !strings.HasSuffix(parts[2], BlobExt) {
		return ID{}, false
	}
	id, err := ParseID(strings.TrimSuffix(parts[2], BlobExt))
	if err != nil || parts[1] != id.String()[:2] || BlobName(id) != name {
		return ID{}, false
	}
	return id, true
}

func blobPrefix(suite svcrypto.Suite, vault, blob ID) ([]byte, error) {
	var t tlvBuilder
	t.add(0x01, vault[:])
	t.add(0x02, blob[:])
	h, err := t.encode()
	if err != nil {
		return nil, err
	}
	p := append([]byte(blobMagic), byte(suite), 0)
	p = binary.BigEndian.AppendUint16(p, uint16(len(h)))
	return append(p, h...), nil
}

// SealBlob seals contents as blob id of vault under key.
func SealBlob(suite svcrypto.Suite, vault, id ID, key, contents []byte) ([]byte, error) {
	if len(contents) > MaxBlob {
		return nil, fmt.Errorf("svformat: a file of %d bytes is larger than the %d MiB an attachment may be", len(contents), MaxBlob>>20)
	}
	prefix, err := blobPrefix(suite, vault, id)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	out.Write(prefix)
	w, err := suite.NewStreamWriter(key, prefix, &out)
	if err != nil {
		return nil, err
	}
	w.Write(contents)
	w.Write(make([]byte, padme(len(contents))-len(contents)))
	if err := w.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// OpenBlob opens blob id of vault, whose contents are size bytes long.
func OpenBlob(file []byte, suite svcrypto.Suite, vault, id ID, key []byte, size int64) ([]byte, error) {
	prefix, err := blobPrefix(suite, vault, id)
	if err != nil {
		return nil, err
	}
	if size < 0 || size > MaxBlob || !bytes.HasPrefix(file, prefix) {
		return nil, ErrBlob
	}
	r, err := suite.NewStreamReader(key, prefix, bytes.NewReader(file[len(prefix):]))
	if err != nil {
		return nil, ErrBlob
	}
	padded := make([]byte, 0, padme(int(size)))
	buf := make([]byte, 64<<10)
	for {
		n, err := r.Read(buf)
		padded = append(padded, buf[:n]...)
		if len(padded) > padme(int(size)) {
			clear(padded)
			return nil, ErrBlob
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			clear(padded)
			return nil, ErrBlob
		}
	}
	clear(buf)
	if len(padded) != padme(int(size)) {
		clear(padded)
		return nil, ErrBlob
	}
	for _, b := range padded[size:] {
		if b != 0 {
			clear(padded)
			return nil, ErrBlob
		}
	}
	return padded[:size], nil
}
