package svpgp

import (
	"errors"
	"io"
	"slices"
)

// Recipients are whom an encrypted message says it is encrypted to, as
// its session key packets name them. Nothing proves it: the packets are
// read, not decrypted.
type Recipients struct {
	// KeyIDs are the (sub)key IDs of version 3 session key packets, and
	// Fingerprints the (sub)key fingerprints of version 6 ones.
	KeyIDs       []uint64
	Fingerprints [][]byte
	// Anonymous is set when a packet hides its recipient.
	Anonymous bool
	// Passphrase is set when the message can also be decrypted with a
	// passphrase.
	Passphrase bool
}

// EncryptedTo reads the session key packets at the start of an encrypted
// message, binary or armored, so a caller can tell which of its keys the
// message is for before using any. Session key packets of a version or
// algorithm this package cannot use are skipped. A message that is not
// encrypted is refused with ErrNotEncrypted.
func EncryptedTo(r io.Reader) (*Recipients, error) {
	br, typ, err := openInput(r)
	if err != nil {
		return nil, err
	}
	var src io.Reader = br
	switch typ {
	case "":
	case BlockMessage:
		block, err := armorBody(br, typ)
		if err != nil {
			return nil, err
		}
		src = block.Body
	default:
		return nil, ErrNotEncrypted
	}
	pr := newPacketReader(src)
	out := &Recipients{}
	for n := 0; ; n++ {
		tag, body, err := pr.next()
		if err == io.EOF {
			return nil, ErrNotEncrypted
		}
		if err != nil {
			return nil, err
		}
		switch tag {
		case ptMarker, ptPadding:
		case ptPKESK:
			if n >= maxESKPackets {
				return nil, limit("more than %d session key packets", maxESKPackets)
			}
			data, err := body.readAll(maxPacketSize)
			if err != nil {
				return nil, err
			}
			k, err := parsePKESK(data)
			if errors.Is(err, ErrUnsupported) {
				continue
			}
			if err != nil {
				return nil, err
			}
			switch {
			case k.anonymous():
				out.Anonymous = true
			case k.version == 3:
				out.KeyIDs = append(out.KeyIDs, k.keyID)
			default:
				out.Fingerprints = append(out.Fingerprints, slices.Clone(k.fp))
			}
		case ptSKESK:
			if n >= maxESKPackets {
				return nil, limit("more than %d session key packets", maxESKPackets)
			}
			if _, err := body.readAll(maxPacketSize); err != nil {
				return nil, err
			}
			out.Passphrase = true
		case ptSEIPD, ptSED:
			return out, nil
		default:
			return nil, ErrNotEncrypted
		}
	}
}
