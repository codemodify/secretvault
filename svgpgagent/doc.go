// Package svgpgagent speaks GnuPG's agent protocol, so that gpg can use
// OpenPGP keys it does not hold: secretvaultd serves it (svd's gpg-agent
// face) with the keys in your vaults, which never leave the daemon.
//
// gpg keeps only public keys. Whatever needs a secret key it asks its
// agent over Assuan (https://www.gnupg.org/documentation/manuals/assuan/),
// naming the (sub)key by its keygrip: whether the key is there (HAVEKEY,
// KEYINFO), to sign a digest (SIGKEY, SETHASH, PKSIGN), or to undo the
// public-key encryption of a session key (SETKEY, PKDECRYPT, with the
// ciphertext asked for by INQUIRE CIPHERTEXT). Keys, ciphertexts and
// signatures travel as libgcrypt's canonical S-expressions. This package
// is the server's side of that, as GnuPG 2.4's agent/command.c has it,
// for what gpg sends when it signs and decrypts; a Backend holds the keys
// and decides who may use them.
//
//   - Keygrips are libgcrypt's, for RSA, ECDSA and ECDH on the NIST
//     curves, EdDSA on Ed25519 and ECDH on Curve25519 (Keygrip), and are
//     checked against GnuPG's own.
//   - Signatures come back as (sig-val(rsa(s S))), (sig-val(ecdsa(r R)(s
//     S))) or (sig-val(eddsa(r R)(s S))).
//   - Decryption comes back as (value V): for ECDH the shared point, which
//     gpg turns into the key-wrapping key itself (0x04 || x || y on the
//     NIST curves, 0x40 || u on Curve25519, as libgcrypt writes them); for
//     RSA the session key with its padding already removed, which a
//     "PADDING 0" status says. gpg-agent sends RSA's raw result instead,
//     padding and all; this server's backend only gives back a message
//     that was properly padded, so that decrypting cannot be used to sign.
//   - Every OPTION is accepted (they tell a pinentry where to show).
//     GETINFO answers version, pid, socket_name, ssh_socket_name,
//     s2k_count and cmd_has_option. RESET, NOP, BYE, HELP,
//     UPDATESTARTUPTTY and CLEAR_PASSPHRASE are answered, ISTRUSTED is
//     answered "not trusted", and KILLAGENT and RELOADAGENT are answered
//     and do nothing.
//   - GET_PASSPHRASE works only with pinentry-mode=loopback, where gpg
//     supplies the passphrase itself: nothing asks a person for a
//     passphrase that would go to the program asking.
//   - Refused, with the reason: GENKEY, IMPORT_KEY, KEYWRAP_KEY,
//     EXPORT_KEY, DELETE_KEY and PASSWD (secret keys come in and go out
//     through secretvault, never gpg), SCD, LEARN, KEYTOCARD and KEYTOTPM
//     (no smartcards or TPM), PKSIGN of anything but a digest (SETHASH
//     --inquire, --pss), and anything else it does not know.
//
// Every line is at most 1000 bytes; a longer one ends the connection.
// Ciphertexts are at most 4096 bytes and passphrases 255, as gpg-agent
// has them, and S-expressions are read in canonical form only, nested at
// most 8 deep.
package svgpgagent
