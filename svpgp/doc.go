// Package svpgp is secretvault's own OpenPGP implementation, written against
// RFC 9580 (version 6 keys, AEAD encryption) and reading RFC 4880 and RFC
// 6637 data (version 4 keys, which almost every existing key is), with no
// OpenPGP library underneath: only the Go standard library and
// golang.org/x/crypto. The trust store uses it to verify people's
// signatures and read their mail, so it is strict: when input is unclear,
// weak or malformed it refuses rather than guesses.
//
// # Keys
//
// A Key is a certificate (a transferable public key) and, when read from
// a secret key, its secret key material. ReadKeys and ReadKey read keys,
// binary or armored; GenerateKey makes new ones: version 6 by default
// (Ed25519 with an X25519 subkey), or version 4 (EdDSALegacy with an ECDH
// Curve25519 subkey), which GnuPG 2.4 reads.
//
//	keys, err := svpgp.ReadKeys(r)
//	k.Fingerprint(); k.KeyID(); k.UserIDs(); k.Revoked(); k.ExpiresAt()
//	k.Valid(t)       // nil if the key is usable at t, else why not
//	k.Subkeys()      // each subkey, and what it may do now
//	k.Public(); k.Serialize(w, secret); k.Armor(secret)
//	k.Unlock(passphrase); k.Lock(passphrase, opts); k.Close()
//	k.Revoke(reason, text, at)
//
// Reading a key verifies every self-signature once. Whether a part of the
// key is valid at a given time is worked out when asked: the most recent
// self-signature made by then counts, expiry is taken from it (and from
// the direct key signature), revocations by the key itself apply (a
// compromise, or a revocation without a reason, for all time; a superseded
// or retired key from the revocation on), a version 6 key needs a direct
// key signature, and a signing subkey needs the primary key binding
// signature that proves it agreed to be bound. User IDs count only with a
// valid self-certification: anyone can append a user ID to a certificate.
// Third-party certifications are kept, for export, but not evaluated; the
// trust store decides whom to believe. Designated revokers (a deprecated
// mechanism) are not honoured.
//
// # Signing and verifying
//
// Sign makes detached, inline or cleartext signatures (SignOptions.Mode),
// binary or text. Verify checks a detached signature; VerifyInline reads
// an inline or cleartext signed message. Both return a SignatureResult per
// signature: whether it is valid, the issuer it names, the key and subkey
// it verified with, when it was made, its hash, and why it is not valid
// otherwise. A signature is valid only if it verifies, was made by a key in
// the keyring that was valid and allowed to sign when the signature was
// made, is not expired or from the future (as of the verification time),
// passes the hash policy, and, if it names its intended recipients, was
// read from a message encrypted to one of them.
//
// # Encrypting and decrypting
//
// Encrypt returns a writer that encrypts to the recipients' valid
// encryption subkeys and, optionally, a passphrase, and optionally signs
// too. It uses v2 SEIPD (AEAD: OCB, GCM or EAX) when every recipient says
// it can read it, and v1 SEIPD (CFB with the SHA-1 modification detection
// code) otherwise, following the recipients' algorithm preferences.
// Decrypt reads an encrypted message with the unlocked secret keys in a
// keyring, or with a passphrase, and verifies the signatures inside it.
// ReadMessage reads any message, encrypted or not. Messages are read whole:
// the integrity of encrypted data (MDC or AEAD tags) is checked before
// anything in it is parsed, and nothing is returned from a message that
// fails. All failures of that kind are one error, ErrDecryption, so they
// cannot be told apart. Encrypted data without integrity protection (SED
// packets) is refused unless ReadOptions.AllowUnprotected is set.
//
// # What is supported
//
//   - Packets: public and secret keys and subkeys (versions 4 and 6), user
//     IDs, signatures (3 for data only, 4, 6), one-pass signatures (3, 6),
//     PKESK (3, 6), SKESK (4, 6), SEIPD (1, 2), literal data, compressed
//     data (ZIP and ZLIB both ways, BZip2 read only), marker, padding,
//     trust (ignored) and user attributes (kept, not interpreted), in old
//     and new packet formats, with partial and indeterminate lengths.
//   - Public-key algorithms: Ed25519 and X25519 (the version 6 native IDs 27
//     and 25, also in version 4 keys); EdDSALegacy and ECDH over Curve25519
//     in version 4 keys; ECDSA and ECDH over NIST P-256, P-384 and P-521;
//     RSA for signing, verifying, encrypting and decrypting (2048 to 8192
//     bits); DSA for verifying old signatures only; ElGamal for decrypting
//     old messages only, with a warning.
//   - Ciphers: AES-128, AES-192 and AES-256 (the only ones used to
//     encrypt, and the only ones accepted in AEAD modes); TripleDES, CAST5,
//     Blowfish and Twofish for decrypting old data, with a warning for the
//     first three. AEAD: OCB (RFC 7253) and EAX, both implemented here on
//     crypto/aes, and GCM from the standard library.
//   - Hashes: SHA2-224, -256, -384, -512, SHA3-256 and SHA3-512. SHA-1 only
//     where the format requires it: version 4 fingerprints, the MDC, old
//     S2K specifiers, and signatures made before 2023 (see below).
//   - S2K: simple, salted and iterated-and-salted for reading, Argon2
//     (RFC 9580, section 3.7.1.4); secret keys protected with AEAD (S2K
//     usage 253) or CFB with a SHA-1 check (254), and read with the old
//     16-bit checksum (255). GnuPG's stubs for secret keys kept elsewhere
//     or on a smartcard are read and kept, as locked keys that cannot be
//     unlocked.
//   - Armor, with the CRC24 checksum checked when present, and the
//     cleartext signature framework.
//
// # What is refused
//
//   - Ed448, X448, the brainpool curves and secp256k1: keys using them are
//     read (so they can be listed) but every use fails with ErrUnsupported.
//     Keys of versions 2, 3 (PGP 2) and 5 (LibrePGP) are skipped.
//   - IDEA and Camellia; MD5 and RIPEMD-160; secret keys protected with an
//     MD5-derived key; LibrePGP's AEAD packet (type 20); multi-part armor.
//   - RSA keys under 2048 bits, DSA outside 1024 to 3072 bits, ElGamal
//     outside 1024 to 4096 bits, and signatures whose hash is shorter than
//     the key's security level (RFC 9580, section 5.2.3).
//   - Unknown critical packets and critical subpackets, including any
//     critical notation; a one-pass signature without its signature; more
//     than one literal data packet; encrypted data anywhere but as the
//     outermost layer of a message (so no nested encryption). Session key
//     packets whose version does not match the encrypted data after them
//     are ignored, as RFC 9580 requires.
//
// # Policy
//
// SHA-1 is not accepted in any signature (data, certification or binding)
// made on or after 2023-01-01, nor in any version 6 signature. Revocations
// are the exception: they count whatever hash they use, because ignoring a
// real revocation is worse than honouring a forged one. A forger who
// can find a SHA-1 collision can also backdate a signature, so this is a
// migration aid for old keys and archives, not a guarantee; the cutoff
// matches the one other implementations use. MD5 is never accepted. A
// signature is judged by the key's state when it was made, which needs the
// self-signature in force then: a key whose old self-signatures were
// stripped (and only a newer one kept) will not validate signatures older
// than it.
//
// RFC 9580 says an implementation must not reject armor whose CRC24 does
// not match; this package does, as GnuPG does, since a changed armored
// block is corrupt and nothing is lost by saying so. The CRC24 line is
// written for version 4 keys and signatures and v1 SEIPD messages, where
// older readers expect it, and never for version 6 data.
//
// Text literal data is written with CR LF line endings, as RFC 9580
// requires, and read back as stored: Message.Body is exactly the literal
// data. A cleartext signed message's Body is exactly its signed text, with
// LF line endings.
//
// # Limits
//
// Everything read is bounded (see Limits): single packets (8 MiB),
// messages (512 MiB of plaintext by default, read whole into memory),
// decompression (by size, and by ratio once past 1 MiB, which stops
// compression bombs), nesting of compressed data (8 levels), Argon2 S2K
// cost (2 GiB and 16 passes by default), the number of session key
// packets, signatures, subpackets and packets per key, and the
// self-signatures verified per key. Malformed input is refused with
// ErrMalformed and never makes the package panic; fuzz targets check that.
//
// # Secret key material in memory
//
// Decrypted secret key material is kept in an svcrypto.Secret: memory of
// its own, locked against swapping and (on Linux) excluded from core
// dumps, zeroed by Lock and Close. For each operation the standard
// library's key types are built from it and afterwards wiped as far as Go
// allows: byte slices and the words of big integers are zeroed, but the
// standard library keeps copies of its own that cannot be reached (the
// FIPS module's RSA and ECDSA keys, crypto/ecdh private keys), and the Go
// runtime may have copied anything before it was wiped. Passphrases,
// derived keys and session keys are zeroed after use. As in the rest of
// secretvault this is hygiene, not a guarantee.
//
// # Interoperability
//
// The tests check this package against the RFC 9580 appendix vectors, the
// RFC 7253 OCB, RFC 3394 key wrap and EAX paper vectors, and GnuPG 2.4 in
// both directions (GnuPG speaks version 4 and v1 SEIPD only).
package svpgp
