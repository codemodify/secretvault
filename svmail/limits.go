package svmail

import (
	"github.com/codemodify/secretvault/svcms"
	"github.com/codemodify/secretvault/svpgp"
)

// Limits bound the resources that reading an untrusted message may take.
// The zero value of each field means its default.
type Limits struct {
	// MaxSize bounds the message, and each decrypted or unwrapped message
	// inside it. Messages are read whole, into memory. Default 128 MiB.
	MaxSize int

	// MaxDepth bounds how deeply MIME parts, and the cryptographic layers
	// between them, may nest. Default 32.
	MaxDepth int

	// MaxParts bounds the MIME parts in the whole message, counting those
	// inside encrypted parts. Default 2000.
	MaxParts int

	// MaxLayers bounds the cryptographic layers (signatures and
	// encryption) that are verified or decrypted. Default 16.
	MaxLayers int

	// MaxHeaderFields bounds the fields in one header, and MaxHeaderSize
	// its bytes. Defaults 1000 and 1 MiB.
	MaxHeaderFields int
	MaxHeaderSize   int
}

// DefaultLimits are the limits used when none are given.
var DefaultLimits = Limits{
	MaxSize:         128 << 20,
	MaxDepth:        32,
	MaxParts:        2000,
	MaxLayers:       16,
	MaxHeaderFields: 1000,
	MaxHeaderSize:   1 << 20,
}

func (l *Limits) withDefaults() Limits {
	out := DefaultLimits
	if l == nil {
		return out
	}
	if l.MaxSize > 0 {
		out.MaxSize = l.MaxSize
	}
	if l.MaxDepth > 0 {
		out.MaxDepth = l.MaxDepth
	}
	if l.MaxParts > 0 {
		out.MaxParts = l.MaxParts
	}
	if l.MaxLayers > 0 {
		out.MaxLayers = l.MaxLayers
	}
	if l.MaxHeaderFields > 0 {
		out.MaxHeaderFields = l.MaxHeaderFields
	}
	if l.MaxHeaderSize > 0 {
		out.MaxHeaderSize = l.MaxHeaderSize
	}
	return out
}

// The limits handed to the packages underneath.
func (l Limits) cms() *svcms.Limits { return &svcms.Limits{MaxSize: l.MaxSize} }
func (l Limits) pgp() *svpgp.Limits { return &svpgp.Limits{MaxMessageSize: int64(l.MaxSize)} }

// Fixed limits, not worth a knob.
const (
	maxInlineBlocks = 8       // inline PGP blocks read from one text part
	maxAutocrypt    = 64      // Autocrypt and gossip headers read from one header
	maxPGPScan      = 1 << 20 // bytes of an OpenPGP message read to list its recipients
)
