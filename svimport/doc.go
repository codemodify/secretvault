// Package svimport moves secrets between secretvault and other password
// managers: it reads their export files into items, and writes items out
// as KeePass (KDBX 4) and FIDO Credential Exchange Format files.
//
// Import reads, and Detect recognises:
//
//   - kdbx: KeePass 2.x databases, KDBX 3.1 and 4.x, opened with a
//     passphrase, a key file (XML 1.0 or 2.0, 32 raw bytes, 64 hex
//     digits, or any file's SHA-256) or both; AES-256-CBC, ChaCha20 or
//     Twofish-CBC; AES-KDF, Argon2d or Argon2id. KeePass 1.x (.kdb) is not
//     read.
//   - bitwarden: Bitwarden's JSON export, plain or password-protected
//     (PBKDF2-SHA256 or Argon2id). An export encrypted with the account's
//     own key can only be read by Bitwarden, and is refused with a note
//     saying so.
//   - 1pux: 1Password's unencrypted export (the zip, or its export.data).
//   - protonpass: Proton Pass's export (the zip, or its data.json). Its
//     passphrase-encrypted export is OpenPGP, refused until milestone M5.
//   - csv: exports from Chrome and Edge, Firefox, Safari, Bitwarden,
//     KeePassXC, and any CSV whose columns have recognisable names.
//   - aegis: Aegis Authenticator vaults, plain or password-encrypted.
//   - google-authenticator: the otpauth-migration:// URIs of Google
//     Authenticator's transfer QR codes, one per line.
//   - cxf: the FIDO Alliance's Credential Exchange Format, version 1.
//
// pass and gopass stores, and any other OpenPGP-encrypted file, need
// OpenPGP, which secretvault implements in milestone M5; Import returns
// ErrOpenPGP for them.
//
// # How items are made
//
// Every format maps onto items the same way:
//
//   - Name: the source's folder path (KeePass groups below the root,
//     Bitwarden folders or collections, 1Password and Proton Pass vaults,
//     Aegis groups, CXF collections), then the title, under
//     Options.Prefix. A '/' in a title or folder name becomes '-', except
//     in the formats that nest folders by it (Bitwarden folders and
//     collections, CSV folder columns); control characters become spaces,
//     "." and ".." become "_" and "__", an empty title becomes "untitled",
//     and over-long names are shortened. A name already taken gets " (2)",
//     " (3)"... Label is the source's title.
//   - Kind: "login" for usernames, passwords, URLs and OTP keys; "note"
//     for secure notes; "card"; "identity" (also for 1Password's driver's
//     licences, passports and social security numbers, and CXF's identity
//     documents); "ssh-key"; "otp" for authenticator entries (Aegis, Google
//     Authenticator, a CXF item holding only a TOTP key); "password" and
//     "api-key" where the source has exactly those (1Password's Password
//     and API Credential, CXF's generated-password and api-key); "generic"
//     for everything else.
//   - Tags are carried over where the source has them.
//
// Fields, by kind:
//
//   - login: username (text), password (concealed), url, url2, url3...
//     (url), otp (otp: an otpauth:// URI, normalised through svotp,
//     whether the source held a URI, a bare base32 secret, Bitwarden's
//     steam://, KeeOTP's key=..., KeePassXC's "TOTP Seed"/"TOTP
//     Settings" or KeePass's TimeOtp-*), email (email) where the source
//     keeps one apart from the username.
//   - card: cardholder, number (concealed), expiry (MM/YYYY), cvv
//     (concealed), pin (concealed), brand.
//   - identity: title, first_name, middle_name, last_name, full_name,
//     email (email), phone, company, address (lines joined by newlines),
//     city, state, postal_code, country, username, birth_date, and
//     ssn, passport_number, license_number (concealed).
//   - ssh-key: private_key (key), public_key, fingerprint, passphrase
//     (concealed).
//   - every kind: notes (text), and the source's custom fields under their
//     own names, concealed where the source marks them hidden or
//     protected, text otherwise.
//
// Items in the trash or recycle bin are skipped. What cannot be brought
// across is left behind with a warning in Result.Warnings that names the
// item but never holds a secret: attachments and documents, passkeys,
// history (older versions), OTP keys of kinds with no otpauth form (MOTP,
// Yandex, MD5), and credential types a format added after this reader.
//
// # Exports
//
// ExportKDBX writes a KDBX 4 file KeePass and KeePassXC open with the
// passphrase; ExportCXF writes a CXF document, which is JSON in the clear.
// Both keep what their format has no place for (kind, attributes, field
// types) in the format's own extension points, so a round trip through
// either and back through Import gives the same items.
//
// Import never logs, and never returns errors holding, file contents.
// Key derivation costs in a file are bounded, so a planted file cannot
// exhaust the machine.
package svimport
