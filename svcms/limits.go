package svcms

// Limits bound the resources that reading untrusted input may take. The
// zero value of each field means its default.
type Limits struct {
	// MaxSize bounds the input (a whole CMS structure or PKCS#12 file)
	// and so, roughly, the content inside it. Structures are read whole,
	// into memory. Default 128 MiB.
	MaxSize int

	// MaxDepth bounds how deeply ASN.1 elements may nest. Default 64.
	MaxDepth int

	// MaxCertificates bounds the certificates in one structure. Default
	// 256.
	MaxCertificates int

	// MaxSigners bounds the signer infos in one SignedData. Default 64.
	MaxSigners int

	// MaxRecipients bounds the recipient infos (and, in key agreement,
	// the recipients each holds) in one enveloped message. Default 1024.
	MaxRecipients int

	// MaxAttributes bounds the attributes in one attribute set, and the
	// bags in one PKCS#12 file. Default 256.
	MaxAttributes int

	// MaxIterations bounds the iteration count of a password-based key
	// derivation (PBKDF2, and PKCS#12's own) in a PKCS#12 file, which
	// otherwise lets a file choose how long reading it takes. Default
	// 10,000,000.
	MaxIterations int
}

// DefaultLimits are the limits used when none are given.
var DefaultLimits = Limits{
	MaxSize:         128 << 20,
	MaxDepth:        64,
	MaxCertificates: 256,
	MaxSigners:      64,
	MaxRecipients:   1024,
	MaxAttributes:   256,
	MaxIterations:   10_000_000,
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
	if l.MaxCertificates > 0 {
		out.MaxCertificates = l.MaxCertificates
	}
	if l.MaxSigners > 0 {
		out.MaxSigners = l.MaxSigners
	}
	if l.MaxRecipients > 0 {
		out.MaxRecipients = l.MaxRecipients
	}
	if l.MaxAttributes > 0 {
		out.MaxAttributes = l.MaxAttributes
	}
	if l.MaxIterations > 0 {
		out.MaxIterations = l.MaxIterations
	}
	return out
}

// Fixed limits, not worth a knob.
const (
	maxElements    = 1 << 20 // ASN.1 elements in one structure
	maxBagNesting  = 4       // safeContentsBag inside safeContentsBag
	maxDerivations = 16      // password-based key derivations per PKCS #12 file
)
