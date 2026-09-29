package svpgp

// Limits bound the resources that reading untrusted input may take. The
// zero value of each field means its default.
type Limits struct {
	// MaxMessageSize bounds the plaintext of a message, after decryption
	// and after decompression. Messages are read whole, so this is also
	// roughly the memory a read may use. Default 512 MiB.
	MaxMessageSize int64

	// MaxDecompressionRatio bounds how much larger decompressed data may
	// be than the compressed data it came from, once past the first MiB.
	// DEFLATE cannot exceed about 1032:1, so the default of 1100 only
	// stops bombs, mostly BZip2 ones.
	MaxDecompressionRatio int64

	// MaxNesting bounds how deeply containers (compressed data inside
	// encrypted data inside ...) may nest. Default 8.
	MaxNesting int

	// MaxArgon2Memory bounds the memory an Argon2 S2K may ask for, in KiB.
	// Default 2 GiB (2^21 KiB, RFC 9106's first recommended option).
	MaxArgon2Memory uint32

	// MaxArgon2Passes bounds an Argon2 S2K's passes. Default 16.
	MaxArgon2Passes uint8
}

// DefaultLimits are the limits used when none are given.
var DefaultLimits = Limits{
	MaxMessageSize:        512 << 20,
	MaxDecompressionRatio: 1100,
	MaxNesting:            8,
	MaxArgon2Memory:       1 << 21,
	MaxArgon2Passes:       16,
}

func (l *Limits) withDefaults() Limits {
	out := DefaultLimits
	if l == nil {
		return out
	}
	if l.MaxMessageSize > 0 {
		out.MaxMessageSize = l.MaxMessageSize
	}
	if l.MaxDecompressionRatio > 0 {
		out.MaxDecompressionRatio = l.MaxDecompressionRatio
	}
	if l.MaxNesting > 0 {
		out.MaxNesting = l.MaxNesting
	}
	if l.MaxArgon2Memory > 0 {
		out.MaxArgon2Memory = l.MaxArgon2Memory
	}
	if l.MaxArgon2Passes > 0 {
		out.MaxArgon2Passes = l.MaxArgon2Passes
	}
	return out
}

// Fixed limits, not worth a knob.
const (
	maxESKPackets     = 256  // session key packets in front of one encrypted message
	maxOnePass        = 64   // one-pass signatures (and prefix signatures) on one message
	maxDetachedSigs   = 256  // signatures in one detached signature
	maxSubpackets     = 1024 // subpackets in one signature area
	maxPacketsPerKey  = 1 << 17
	maxSelfSigChecks  = 1024 // self-signature candidates verified per key
	maxRecipientTries = 64   // secret keys tried against an anonymous recipient
)
