// Package svdeliver is secretvault-server's second role: delivering
// secrets to services, Kubernetes and CI pipelines, from vaults it holds
// open. It is apart from the sync hub (svserver), which only relays
// ciphertext and never opens a vault; the two share a process and,
// usually, a listener, and nothing else.
//
// A delivery vault is an ordinary vault that its owner shared with the
// server's identity (secretvault share RECIPIENT). The server reads it
// with that keyslot and never writes to it: the owner's devices write,
// and whatever syncs the folder (this server's own hub, or Syncthing, git
// and the like) brings the changes.
//
// # Sealed at start
//
// Everything the server holds that is secret is sealed under a root key,
// itself sealed under an unseal key that exists only as Shamir shares,
// any k of n of which rebuild it (seal.go). The server starts sealed, and
// serves nothing but its status until operators give k shares, one per
// request; the shares given so far are held in memory for ten minutes
// (unseal_timeout) and never logged. It can also unseal itself at start
// from a systemd credential ($CREDENTIALS_DIRECTORY), a key of its own
// that systemd-creds seals to the machine's TPM. Sealing again forgets
// every key and session. Rekeying makes new shares (and a new
// credential, if asked), and needs k of the current shares.
//
// # Storage
//
// The delivery directory holds:
//
//	seal.json       the root key sealed under the unseal key (and the credential
//	                key), the server's identities sealed under the root key, and
//	                the audit log's public key
//	policy.sealed   vaults, issuers, the client CA, roles, tokens (as hashes) and
//	                the admin token's hash, sealed under the root key
//	audit.log       one entry per request, each sealed to the audit key, chained
//	config.json     settings: session lifetime, unseal timeout, the credential's
//	                name, the rate limit. Nothing in it grants access.
//
// Whoever can read the directory learns nothing from it but sizes and
// times; whoever can write to it cannot grant themselves anything, since
// the policy is authenticated under the root key.
//
// # API
//
// Everything is JSON under /v1/deliver/; errors are {"error": "..."}.
//
//	GET  /v1/deliver/status                  the seal's state (Status). No credential.
//	POST /v1/deliver/unseal                  one share: {"share": "SVUS1-..."}, or {"reset": true}.
//	                                         No credential: the share is one.
//	POST /v1/deliver/rekey                   one current share towards a rekey the admin
//	                                         started: {"nonce", "share"}. The last one answers
//	                                         the new shares.
//	POST /v1/deliver/login/oidc              {"role", "jwt"}: an ID token for a session
//	                                         (Session), 15 minutes unless the role says.
//	GET  /v1/deliver/secret/{vault}/{item}   the item's fields (Secret); ?field=NAME for one,
//	                                         and &raw=true for its bare value.
//	GET  /v1/deliver/list/{vault}/{prefix}   the item names under prefix the caller may list.
//
// The admin API needs the admin token, and so an unsealed server:
//
//	POST   /v1/deliver/admin/seal
//	POST   /v1/deliver/admin/rekey           start a rekey (RekeyRequest); DELETE cancels it
//	GET    /v1/deliver/admin/identity        the server's recipients
//	GET    /v1/deliver/admin/tokens          POST makes one (TokenRequest), shown once;
//	DELETE /v1/deliver/admin/tokens/{name}   revokes it
//	GET    /v1/deliver/admin/roles           PUT /roles/{name} sets one (Role); DELETE removes it
//	GET    /v1/deliver/admin/vaults          POST adds one (VaultRequest); DELETE /vaults/{name}
//	GET    /v1/deliver/admin/issuers         PUT /issuers/{name} sets one (Issuer); DELETE
//	GET    /v1/deliver/admin/client-ca       PUT sets it ({"pem"}); DELETE clears it
//	POST   /v1/deliver/admin/admin-token     a new admin token; the old one stops working
//	GET    /v1/deliver/admin/audit           ?after=SEQ&limit=N: entries, and whether the
//	                                         chain is intact
//
// # Machine authentication
//
// There are no human logins. A request carries one of (auth.go):
//
//   - A token an admin made (svdt_...): 256 random bits, kept as a hash,
//     with an optional expiry and optional CIDRs it may be used from.
//   - A session from an OIDC login (svds_...), in memory only.
//   - An ID token itself, with the role in the X-Secretvault-Role header:
//     a login and a request in one.
//   - A TLS client certificate, when there is no Authorization header:
//     recognised by a pinned SHA-256 fingerprint, or by its subject or
//     SAN once it chains to the client CA.
//
// ID tokens (GitHub Actions, GitLab CI, Kubernetes service accounts, any
// OpenID Connect issuer) are verified here, without a JOSE library
// (jwt.go, jwks.go): RS256, ES256 and EdDSA only; keys from the issuer's
// JWKS through discovery, or configured; iss, aud, exp, nbf and iat
// checked, with a minute's leeway.
//
// # Policy
//
// A role (policy.go) names one identity (a token, a certificate match, or
// an issuer and globs its tokens' claims must match) and rules: a vault,
// an item glob and capabilities (read, list). Nothing is allowed that no
// rule allows. The policy is decided on names alone, before any vault is
// opened, and a caller refused an item gets the same answer as for an
// item that does not exist: "no such secret, or not allowed".
//
// # Audit
//
// Every request but the status goes in the audit log (audit.go) before it
// is answered: who, which role, what, from where, and the outcome. A
// request whose entry cannot be written gets an error, never a secret.
package svdeliver
