// Package secretvault is one secret store for the desktop, the server and
// the terminal: a keyring (Secret Service, and bridges to Keychain and
// Credential Manager), a password manager, a developer secrets tool (age,
// SOPS, `run`), a host credential store (systemd), an encrypted-volume tool
// and a Vault-compatible secrets server, all over one encrypted vault
// format.
//
// The packages:
//
//	svcrypto   every cryptographic primitive, nothing else
//	svformat   the v1 on-disk format (docs/format.md)
//	svstore    where vault files live (a directory, memory; later remote)
//	svcore     the vault engine: keyslots, items, revisions, conflicts
//	svprompt   asking people for secrets
//
// and the binaries under cmd/. See README.md and docs/architecture.md.
package secretvault
