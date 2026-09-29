package svpgp

import (
	"errors"
	"fmt"
)

// Errors returned by the package. Most are wrapped with detail; test for
// them with errors.Is.
var (
	// ErrMalformed is input that does not parse as OpenPGP: a truncated
	// packet, a length that points outside its packet, a field of the
	// wrong size, a packet where the grammar allows none.
	ErrMalformed = errors.New("svpgp: malformed OpenPGP data")

	// ErrUnsupported is well-formed input that uses something this
	// package does not implement or refuses on policy: an algorithm, a
	// packet or key version, a hash that is too weak.
	ErrUnsupported = errors.New("svpgp: unsupported")

	// ErrLimit is input that exceeds a limit set to keep resource use
	// bounded: packet size, nesting depth, decompressed size or ratio,
	// the number of packets or signatures, S2K work.
	ErrLimit = errors.New("svpgp: limit exceeded")

	// ErrDecryption is any failure to decrypt a message once its session
	// key is being used: a wrong session key, a failed MDC or AEAD tag, a
	// truncated ciphertext. It deliberately says nothing about which, so
	// that it cannot be used as an oracle (RFC 9580, section 13.5).
	ErrDecryption = errors.New("svpgp: decryption failed: the message is corrupt, has been tampered with, or was not encrypted to this key")

	// ErrUnprotected is an encrypted message without integrity
	// protection (a Symmetrically Encrypted Data packet). It is refused
	// unless DecryptOptions.AllowUnprotected is set.
	ErrUnprotected = errors.New("svpgp: the message is encrypted without integrity protection (SED packet) and was refused")

	// ErrNoKey is an encrypted message for which none of the given keys
	// (or passphrases) holds a session key.
	ErrNoKey = errors.New("svpgp: no key or passphrase can decrypt this message")

	// ErrKeyLocked is an operation that needs secret key material from a
	// key that is locked (protected by a passphrase and not unlocked), or
	// that has no secret material at all.
	ErrKeyLocked = errors.New("svpgp: the secret key is locked or not present")

	// ErrPassphrase is a wrong passphrase: the key or session key it
	// protects failed its integrity check.
	ErrPassphrase = errors.New("svpgp: wrong passphrase")

	// ErrNotEncrypted is returned by Decrypt for a message that is not
	// encrypted. Use ReadMessage or VerifyInline for signed messages.
	ErrNotEncrypted = errors.New("svpgp: the message is not encrypted")

	// ErrNoSignature is a signature to verify that holds no signatures.
	ErrNoSignature = errors.New("svpgp: no signature found")

	// ErrNoUsableKey is a key with no valid (sub)key for what was asked:
	// signing, or encryption, at the given time.
	ErrNoUsableKey = errors.New("svpgp: the key has no valid subkey for this use")
)

// Reasons a signature is not valid. A SignatureResult carries one of these,
// wrapped with detail, in its Err field.
var (
	// ErrUnknownSigner is a signature by a key that is not in the keyring.
	ErrUnknownSigner = errors.New("svpgp: signature by an unknown key")

	// ErrBadSignature is a signature that does not verify: the data or the
	// signature was changed, or it was made by another key.
	ErrBadSignature = errors.New("svpgp: bad signature")

	// ErrWeakAlgorithm is a signature made with an algorithm or key size
	// the policy no longer accepts, such as SHA-1 after 2023-01-01.
	ErrWeakAlgorithm = errors.New("svpgp: signature uses an algorithm that is too weak")

	// ErrKeyExpired is a signature made when the signing key had expired.
	ErrKeyExpired = errors.New("svpgp: signing key was expired")

	// ErrKeyRevoked is a signature made by a revoked key.
	ErrKeyRevoked = errors.New("svpgp: signing key is revoked")

	// ErrKeyInvalid is a signature by a key, or subkey, that has no valid
	// self-signature binding it at the time of signing, or that was not
	// allowed to sign data.
	ErrKeyInvalid = errors.New("svpgp: signing key is not valid for signing at that time")

	// ErrSignatureExpired is a signature that has passed its own
	// expiration time.
	ErrSignatureExpired = errors.New("svpgp: signature has expired")

	// ErrSignatureFuture is a signature whose creation time is later than
	// the time it is verified at.
	ErrSignatureFuture = errors.New("svpgp: signature was made in the future")

	// ErrSignatureMalformed is a signature this package cannot evaluate: an
	// unknown version or type, an unknown critical subpacket, a one-pass
	// header that does not match, a missing creation time.
	ErrSignatureMalformed = errors.New("svpgp: signature is malformed or of an unknown kind")

	// ErrNotIntendedRecipient is a signature that names its intended
	// recipients, verified outside an encrypted message or in one that
	// was not decrypted with a key of one of those recipients.
	ErrNotIntendedRecipient = errors.New("svpgp: signature was meant for other recipients")
)

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

func unsupported(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrUnsupported, fmt.Sprintf(format, args...))
}

func limit(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrLimit, fmt.Sprintf(format, args...))
}
