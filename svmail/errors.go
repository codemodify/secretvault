package svmail

import (
	"errors"
	"fmt"
)

// Errors returned by the package. Most are wrapped with detail; test for
// them with errors.Is. Inspect returns an error only for input it cannot
// read as a message at all; everything that goes wrong inside a message
// that can be read (a signature that does not verify, a part that does not
// decrypt) is reported in the Report instead.
var (
	// ErrMalformed is input that does not parse as a message: no header,
	// or a MIME structure too broken to follow.
	ErrMalformed = errors.New("svmail: malformed message")

	// ErrLimit is input that exceeds a limit set to keep resource use
	// bounded: its size, the number of parts or header fields, nesting.
	ErrLimit = errors.New("svmail: limit exceeded")

	// ErrNoKeys is what a Keys without the keys for something returns,
	// such as NoKeys for every decryption.
	ErrNoKeys = errors.New("svmail: no key for this")
)

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

func limit(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrLimit, fmt.Sprintf(format, args...))
}
