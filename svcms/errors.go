package svcms

import (
	"errors"
	"fmt"
)

// Errors returned by the package. Most are wrapped with detail; test for
// them with errors.Is.
var (
	// ErrMalformed is input that does not parse as CMS, PKCS#12 or the
	// ASN.1 inside them: a truncated element, a length that points
	// outside its parent, a field of the wrong type, trailing data.
	ErrMalformed = errors.New("svcms: malformed data")

	// ErrUnsupported is well-formed input that uses something this
	// package does not implement or refuses on policy: an algorithm, a
	// structure version, a recipient kind, a weak hash or key.
	ErrUnsupported = errors.New("svcms: unsupported")

	// ErrLimit is input that exceeds a limit set to keep resource use
	// bounded: its size, nesting depth, the number of certificates,
	// signers, recipients or attributes, a key derivation's cost.
	ErrLimit = errors.New("svcms: limit exceeded")

	// ErrDecryption is any failure to decrypt content once a content key
	// is being used: a wrong key, bad padding, a failed GCM tag, a
	// truncated ciphertext. It deliberately says nothing about which, so
	// it cannot serve as a padding or Bleichenbacher oracle.
	ErrDecryption = errors.New("svcms: decryption failed: the message is corrupt, has been tampered with, or was not encrypted to this key")

	// ErrNotRecipient is returned when no Decrypter holds a private key
	// for any of an enveloped message's recipients. A Decrypter returns
	// it (wrapped) for a recipient it has no key for.
	ErrNotRecipient = errors.New("svcms: the message is not encrypted to any key held here")

	// ErrPassword is a PKCS#12 file whose integrity check (its MAC) or
	// decryption fails with the password given: the password is wrong,
	// or the file was changed.
	ErrPassword = errors.New("svcms: wrong password, or the file has been changed")

	// ErrNoSignature is a SignedData with no signers (a certificates-only
	// message, say) given to Verify, or detached signed data verified
	// without its content.
	ErrNoSignature = errors.New("svcms: no signature to verify")

	// ErrWrongType is a ContentInfo of another type than the one asked
	// for: enveloped data given to ParseSignedData, say.
	ErrWrongType = errors.New("svcms: wrong content type")
)

// Reasons a signature, or its signer's certificate, is not valid. A
// SignerResult carries them, wrapped with detail, in its Err fields; a
// certificate can fail for several reasons at once, joined with
// errors.Join, so test with errors.Is.
var (
	// ErrBadSignature is a signature that does not verify: the content,
	// the signed attributes or the signature was changed, the
	// message-digest attribute does not match the content, or the
	// signing-certificate attribute names another certificate.
	ErrBadSignature = errors.New("svcms: bad signature")

	// ErrUnknownSigner is a signature whose signer's certificate is in
	// neither the message nor the certificates given.
	ErrUnknownSigner = errors.New("svcms: the signer's certificate was not found")

	// ErrWeakAlgorithm is a signature made with an algorithm or key the
	// policy no longer accepts: MD5 at all, SHA-1 in signatures made on or
	// after 2023-01-01 (or with no signing time), RSA under 2048 bits.
	ErrWeakAlgorithm = errors.New("svcms: signature uses an algorithm that is too weak")

	// ErrSignatureMalformed is a signature this package cannot evaluate:
	// signed attributes that are missing, duplicated or of the wrong
	// form, algorithms that contradict each other.
	ErrSignatureMalformed = errors.New("svcms: signature is malformed")

	// ErrUntrustedRoot is a certificate that does not chain to any of the
	// roots given.
	ErrUntrustedRoot = errors.New("svcms: the certificate does not chain to a trusted root")

	// ErrCertExpired is a certificate, or one of its issuers, that has
	// expired or is not yet valid at the time it is checked.
	ErrCertExpired = errors.New("svcms: the certificate has expired or is not yet valid")

	// ErrWrongUsage is a certificate that may not be used for this: its
	// extended key usage lacks emailProtection, or its key usage lacks
	// what signing, key transport or key agreement needs.
	ErrWrongUsage = errors.New("svcms: the certificate may not be used for this")

	// ErrAddressMismatch is a certificate that does not name the email
	// address it was expected to, neither as an rfc822Name in its subject
	// alternative names nor as an emailAddress in its subject.
	ErrAddressMismatch = errors.New("svcms: the certificate is not for this email address")

	// ErrCertInvalid is any other reason a certificate chain does not
	// validate: name constraints, a CA that may not issue, too many
	// intermediates.
	ErrCertInvalid = errors.New("svcms: the certificate chain is not valid")
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
