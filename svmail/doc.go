// Package svmail takes whole mail messages apart and checks them: it finds
// every OpenPGP and S/MIME layer in a raw message, however they nest,
// verifies the signatures and decrypts what it has keys for, and reports
// it all in one structure a mail client can show. It also builds outgoing
// PGP/MIME and S/MIME messages. It reads MIME itself, keeping the exact
// bytes of every part, and uses svpgp for OpenPGP and svcms for CMS; it
// depends on neither the daemon nor the trust store.
//
// # Inspecting
//
//	report, err := svmail.Inspect(raw, keys)
//
// Inspect recognises:
//
//   - PGP/MIME (RFC 3156): multipart/signed with application/pgp-signature,
//     and multipart/encrypted with application/pgp-encrypted, signed inside
//     (section 6.2) or around a multipart/signed (section 6.1);
//   - inline OpenPGP: BEGIN PGP MESSAGE (encrypted or signed) and BEGIN PGP
//     SIGNED MESSAGE blocks in text/plain parts;
//   - S/MIME (RFC 8551): multipart/signed with application/pkcs7-signature
//     or application/x-pkcs7-signature, and application/pkcs7-mime (or
//     x-pkcs7-mime, or an octet-stream named .p7m) holding signed-data,
//     enveloped-data, authEnveloped-data or certs-only, the kind read from
//     the CMS content type when smime-type is missing;
//   - any nesting of these, signed then encrypted or encrypted then signed,
//     to a bounded depth;
//   - protected header fields (RFC 9788's hp="cipher" and hp="clear", with
//     HP-Outer, and the older Memory Hole protected-headers="v1");
//   - Autocrypt headers, and Autocrypt-Gossip headers inside encrypted
//     messages.
//
// The error is only for input that cannot be read as a message. Everything
// else goes into the Report: a Layer per signature or encryption layer
// (its format, where it is, whether it covers the whole message or one
// part, the verdict on each signature, the recipients and cipher of each
// encryption and whether it was decrypted), the content with the layers
// covering the whole message removed, every leaf part with its text
// decoded, the keys the message carries, and warnings: a signature over
// only part of a message, unsigned parts beside signed ones, text around
// an inline block, encryption without integrity protection, an obsolete
// cipher, a signer who is not the sender, an outer header field that
// differs from its protected copy.
//
// # Keys and trust
//
// Keys supplies what Inspect needs: OpenPGP public keys by fingerprint,
// key ID and address, S/MIME roots and intermediates, and decryption for
// both, which may happen elsewhere. The daemon implements it over the
// trust store and the vault, so private keys never enter this package and
// each use can be asked about: an OpenPGP decryption is handed the message
// and the recipients its session key packets name, an S/MIME one each
// svcms.Recipient in turn. LocalKeys implements it over keys in memory;
// NoKeys has none.
//
// svmail decides nothing about trust in people. A signature is "valid"
// when it is cryptographically sound and its key or certificate was valid
// for signing (and, for S/MIME, chains to a root Keys gave); the report
// names the key (fingerprint and user IDs) or certificate (subject,
// issuer, serial, addresses, chain), and whether it is for the From
// address. Mapping those to people, and deciding how far to believe them,
// is the trust store's job. OpenPGP keys found in the message itself
// (Autocrypt) are reported as discovered and never used to verify it;
// certificates an S/MIME signature carries are reported too, and count
// only through a chain to the roots Keys gives.
//
// # Outgoing
//
// SignPGPMIME, EncryptPGPMIME (optionally signing inside), SignSMIME and
// EncryptSMIME (optionally signing first) take a message as a client
// composes it and return one ready to send, with CR LF line endings. The
// part that is signed is first made 7-bit safe (8-bit text becomes
// quoted-printable, other 8-bit data base64; signed and encrypted parts
// inside are never touched), since a signature must survive transport
// byte for byte, and every new signature is verified before it is
// returned. Bcc fields are removed, and an encrypted message names the
// keys of all its recipients, so Bcc recipients need a copy of their own.
// ComposeOptions.ProtectHeaders adds RFC 9788 header
// protection: the header fields go inside, an encrypted message's
// Subject becomes "[...]" outside, and HP-Outer records what is outside.
//
// # What is not done
//
//   - Charsets other than UTF-8, US-ASCII, ISO-8859-1 and Windows-1252
//     are not decoded (ISO-8859-1 is read as Windows-1252, as browsers
//     do): such text is reported, not shown.
//   - Attached messages (message/rfc822) are parts, not inspected as
//     messages of their own; an 8-bit one cannot be protected on the way
//     out.
//   - RFC 9788's legacy display elements are recognised and flagged, not
//     written.
//   - S/MIME compressed data, and signatures on a multipart/signed of
//     another protocol, are reported as unsupported.
//
// # Limits
//
// Everything read is bounded (see Limits): the message's size, and each
// decrypted message's (128 MiB by default; messages are read whole),
// nesting (32 levels of parts and layers), parts (2000), layers (16),
// header fields (1000 and 1 MiB per header), inline blocks per part, and
// the OpenPGP bytes read to list recipients. svpgp and svcms bound what
// they parse. Malformed input never makes the package panic; fuzz targets
// check that.
//
// # Interoperability
//
// The tests check the package against GnuPG 2.4 (PGP/MIME signed,
// encrypted, both; inline cleartext and encrypted; and the reverse, gpg
// verifying and decrypting the parts of messages built here) and OpenSSL 3
// (detached, streamed, RSA-PSS and opaque signatures; enveloped and
// auth-enveloped messages to RSA and EC recipients; sign-then-encrypt and
// encrypt-then-sign; a missing smime-type; and `openssl cms` verifying and
// decrypting messages built here).
package svmail
