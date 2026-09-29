// Package svcms is secretvault's own CMS (RFC 5652) for S/MIME 4.0 (RFC
// 8551), and PKCS #12 (RFC 7292) for moving S/MIME keys in and out,
// written on encoding/asn1, golang.org/x/crypto/cryptobyte and the
// standard library's crypto/x509, with no CMS library underneath. The
// trust store uses it to check people's signatures and read their mail,
// so, like svpgp, it refuses rather than guesses.
//
// # Signed data
//
// ParseSignedData reads a SignedData, attached or detached, BER or DER;
// SignedData.Verify checks each signer and returns a SignerResult with two
// verdicts: the signature's (does it verify over the content, does it pass
// the policy) and the certificate's (VerifyCertificate: does it chain to
// the roots given, is it valid now, may it sign mail, does it name the
// address). Sign makes a SignedData, detached by default, with a signer
// that may keep its key elsewhere (any crypto.Signer).
//
//	sd, err := svcms.ParseSignedData(der, nil)
//	res, err := sd.Verify(svcms.VerifyOptions{Content: body, Roots: roots, Email: from})
//	res[0].Valid; res[0].SignatureErr; res[0].CertificateErr; res[0].Certificate
//	der, err := svcms.Sign(body, key, chain, svcms.SignOptions{})
//
// A signature with signed attributes counts only if content-type and
// message-digest are present once each and match the content, CMS
// algorithm protection (RFC 6211) agrees with the algorithms used, and the
// ESS signing-certificate attributes (RFC 2634, RFC 5035), when present,
// name the certificate the signature verified with. Without signed
// attributes the content must be id-data.
//
// # Certificates
//
// VerifyCertificate builds a chain with crypto/x509 to the roots given,
// from the intermediates given and those the message carried, requiring
// the emailProtection extended key usage through the chain, a key usage
// that allows the use (digitalSignature or nonRepudiation to sign,
// keyEncipherment or keyAgreement to receive), and, when asked, the
// address as an rfc822Name or legacy emailAddress. It reports every
// problem it finds, joined, each wrapping one of ErrUntrustedRoot,
// ErrCertExpired, ErrWrongUsage, ErrAddressMismatch or ErrCertInvalid, and
// builds chains at a time the certificate was valid, so an expired
// certificate is reported as expired and, separately, as trusted or not.
// The operating system's roots are never used implicitly. Revocation is
// not checked: no CRL or OCSP is fetched or read.
//
// # Enveloped data
//
// ParseEnvelopedData reads EnvelopedData and AuthEnvelopedData (RFC 5083);
// EnvelopedData.Decrypt decrypts with a Decrypter, which is handed one
// Recipient at a time and returns the content key, so the private key can
// stay in another process behind a consent prompt. KeyDecrypter makes a
// Decrypter from a certificate and a key that does only the raw
// operation: a crypto.Decrypter for RSA, an ECDHKey for EC. Encrypt makes
// AuthEnvelopedData with AES-256-GCM, or with EncryptOptions.Legacy
// EnvelopedData with AES-256-CBC for older clients, to RSA-OAEP (SHA-256)
// and ECDH recipients.
//
// Failures once a content key is in use are all ErrDecryption, and an RSA
// PKCS #1 v1.5 key transport that does not decrypt yields a random key
// rather than an error (RFC 3218), so neither the padding nor the key
// transport can be used as an oracle. EnvelopedData with CBC has no
// integrity protection whatsoever; Plaintext.Authenticated says which kind
// was read.
//
// # PKCS #12
//
// DecodePKCS12 reads a .p12 or .pfx file: the MAC is checked first (a
// wrong password is ErrPassword), then the key and certificates are
// decrypted. EncodePKCS12 writes PBES2 (PBKDF2 with HMAC-SHA-256, AES-256
// CBC) under a SHA-256 MAC, 600,000 iterations by default, which OpenSSL 3
// and Windows read.
//
// # What is supported
//
//   - Signatures: RSA PKCS #1 v1.5 and RSA-PSS (MGF1 with the signature's
//     hash), ECDSA on P-256, P-384 and P-521, and Ed25519 (RFC 8419, with
//     SHA-512). Digests: SHA-224, SHA-256, SHA-384 and SHA-512.
//   - Key transport: RSA-OAEP with any SHA-1 or SHA-2 hash and label, and
//     RSA PKCS #1 v1.5 for decrypting only.
//   - Key agreement: ephemeral-static ECDH on P-256, P-384 and P-521
//     (stdDH and cofactorDH, the same on these curves), with the X9.63 KDF
//     over SHA-1 (for decrypting; OpenSSL's old default) or SHA-2, and AES
//     key wrap (RFC 3394, implemented here and checked against its
//     vectors).
//   - Content encryption: AES-128, -192 and -256 in CBC and GCM (12-byte
//     nonces, 12- to 16-byte tags); Triple DES CBC for decrypting only,
//     with a warning.
//   - PKCS #12: PBES2 with PBKDF2 (HMAC with SHA-1 or SHA-2) and AES-CBC or
//     Triple DES; for reading, PKCS #12's own pbeWithSHAAnd3-KeyTripleDES,
//     2-KeyTripleDES, 128BitRC2 and 40BitRC2; the MAC with SHA-1 or SHA-2,
//     and PBMAC1 (RFC 9579); unencrypted key bags and nested safe
//     contents; empty passwords in both encodings writers use.
//   - BER throughout: indefinite lengths and constructed strings are
//     rewritten to DER before parsing, keeping DER input byte for byte.
//
// # What is refused
//
//   - MD5 anywhere; SHA-1 in signatures made on or after 2023-01-01, or with
//     no signing time (the same cutoff as svpgp); RSA keys under 2048 bits.
//   - RC2, DES and RC4 content encryption; PKCS #12 with RC4, or in
//     public-key integrity or privacy mode.
//   - Key agreement with a static originator key, explicit curve
//     parameters, and curves other than the three NIST ones;
//     KEKRecipientInfo, PasswordRecipientInfo and OtherRecipientInfo
//     (listed, never decrypted); encrypted content outside the message.
//   - RSA-PSS whose MGF1 hash differs from its signature hash; GCM outside
//     AuthEnvelopedData, and anything but an AEAD inside it.
//
// # Limits
//
// Everything read is bounded (see Limits): the input's size (128 MiB by
// default; structures are read whole into memory), ASN.1 nesting (64),
// elements per structure, certificates (256), signers (64), recipients
// (1024), attributes and bags (256), and the iteration count a PKCS #12
// file may ask for (10,000,000). Malformed input is refused with
// ErrMalformed and never makes the package panic; fuzz targets check that.
//
// # Keys in memory
//
// Content keys, key-encryption keys, shared secrets and decrypted PKCS #8
// bytes are zeroed after use. Private keys the standard library parses
// cannot be, and PBKDF2 takes the password as a string; as elsewhere in
// secretvault this is hygiene, not a guarantee.
//
// # Interoperability
//
// The tests check this package against OpenSSL 3 in both directions:
// signed (detached, opaque, streamed BER, without attributes, RSA-PSS,
// ECDSA, Ed25519), enveloped and auth-enveloped messages to RSA (PKCS #1
// v1.5 and OAEP) and EC recipients, and PKCS #12 files in its default,
// legacy and PBMAC1 forms; and against the RFC 3394 key wrap, RFC 2268 RC2
// and OpenSSL's PKCS #12 KDF vectors.
package svcms
