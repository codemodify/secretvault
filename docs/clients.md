# Using secretvault from a program

secretvault is a service your program asks for secrets. It never hands your
program the vault's passphrase, and you never ask the person for it: when a
secret is requested, the daemon identifies your program and, the first time,
asks the person whether to allow it. The person's answer (once, until the
vault locks, always, or deny) is remembered by the daemon, not by you.

## From Go

```go
import "github.com/codemodify/secretvault"

c, err := secretvault.Connect(secretvault.Options{Name: "comms-mail"})
if err != nil {
	// secretvaultd is not installed, or could not be started.
}
defer c.Close()

ctx := context.Background()

// Read an item from the default vault ("" names it).
e, err := c.Get(ctx, "", "comms-mail/vault-key")
switch {
case errors.Is(err, svrpc.ErrDenied):   // the person said no
case errors.Is(err, svrpc.ErrNotFound): // no such item yet
case errors.Is(err, svrpc.ErrLocked):   // locked, and nobody could be asked
case err != nil:                        // anything else
}
for _, f := range e.Item.Fields {
	if f.Name == "password" {
		use(f.Value)
		clear(f.Value)
	}
}

// Store one (the first write also asks the person).
_, err = c.Put(ctx, "", svrpc.Item{
	Kind: "api-key", Name: "comms-mail/vault-key",
	Fields: []svrpc.Field{{Name: "secret", Type: "concealed", Value: key}},
})
```

- `Connect` starts `secretvaultd` if it is not running (it must be installed
  beside your program, or on `PATH`). Pass `NoStart: true` to fail instead.
- `OnEvent` in `Options` delivers `vault.locked`, `vault.unlocked` and
  `item.changed`, so a program can drop cached secrets when a vault locks.
- Item names are paths; use your program's name as the first segment.

### comms-mail's hook

comms-mail's vault has `keyringKey func() ([]byte, bool)`, waiting for
exactly this. A sketch of the wiring, for the comms-mail side:

```go
keyringKey = func() ([]byte, bool) {
	c, err := secretvault.Connect(secretvault.Options{Name: "comms-mail"})
	if err != nil {
		return nil, false
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	e, err := c.Get(ctx, "", "comms-mail/vault-key")
	if errors.Is(err, svrpc.ErrNotFound) {
		key := make([]byte, 32)
		rand.Read(key)
		// First run: a new key, which comms-mail then re-seals its vault
		// with (a change on comms-mail's side).
		if _, err := c.Put(ctx, "", svrpc.Item{Kind: "key", Name: "comms-mail/vault-key",
			Fields: []svrpc.Field{{Name: "secret", Type: "key", Value: key}}}); err != nil {
			return nil, false
		}
		return key, true
	}
	if err != nil {
		return nil, false
	}
	for _, f := range e.Item.Fields {
		if f.Name == "secret" {
			return f.Value, true
		}
	}
	return nil, false
}
```

### Mail clients: who signed this?

A mail client tells secretvault about the keys that come with messages,
and asks about each signature's signer. Reading the contacts is asked
about once (and remembered), and recording keys is a write:

```go
// A key that came with a message: an Autocrypt header's keydata
// (base64-decoded), or an S/MIME signer's certificate.
c.KeySeen(ctx, svrpc.TrustSeenParams{Key: keydata, Address: "alice@example.org", Time: received, Name: "Alice"})

// A signature your OpenPGP or CMS code verified, by this key.
v, err := c.CheckSigner(ctx, svrpc.TrustCheckParams{Fingerprint: signerFP, From: fromHeader})
// v.Status: "verified", "unverified", "suspicious" (the address belongs to
// someone else's key) or "unknown"; v.Reasons in plain words to show.

// Or let secretvault verify OpenPGP too, with the person's contacts.
r, err := c.VerifyPGP(ctx, svrpc.PGPVerifyParams{Data: body, Signature: sig, From: fromHeader})

// Decrypt with the person's own key, which never leaves the daemon.
d, err := c.DecryptPGP(ctx, svrpc.PGPDecryptParams{Data: armored, Verify: true, From: fromHeader})
```

Or hand over the whole message, as received, and let secretvault take it
apart: every signature is checked and judged against the contacts, and,
with `Decrypt`, what is encrypted to the person's keys is decrypted (asked
about as decrypting, never as reading the key):

```go
res, err := c.InspectMail(ctx, svrpc.MailInspectParams{Message: raw, Decrypt: true})
// res.Report is svmail.Report as JSON: signed/encrypted ("none", "partial",
// "full"), every layer and what it covers, protected headers, the parts'
// text, the decrypted content, keys the message carries, and warnings.
// res.Verdicts: for each signature (layer, index), the verdict on its signer.
```

The methods and their shapes are in [`svrpc/trust.go`](../svrpc/trust.go) and
[`svrpc/mail.go`](../svrpc/mail.go).

## From any language

Connect to the socket (`$SECRETVAULT_SOCK`, else
`$XDG_RUNTIME_DIR/secretvault/secretvaultd.sock` on Linux) and speak
JSON-RPC 2.0, one object per line. Say hello first, then call:

```
→ {"jsonrpc":"2.0","id":1,"method":"client.hello","params":{"client":"my-tool","version":"1"}}
← {"jsonrpc":"2.0","id":1,"result":{"daemon":"secretvaultd","version":"0.1.0","caller":"my-tool (/usr/bin/my-tool)"}}
→ {"jsonrpc":"2.0","id":2,"method":"item.get","params":{"name":"my-tool/token"}}
← {"jsonrpc":"2.0","id":2,"result":{"id":"…","rev":"…","item":{"kind":"api-key","name":"my-tool/token","fields":[{"name":"secret","type":"concealed","value":"aHVudGVyMg=="}]}}}
```

Field values are base64. Errors carry codes: -32001 locked, -32002 denied,
-32003 not found, -32005 canceled, -32007 nobody could be asked. The full
list of methods and shapes is in [`svrpc/methods.go`](../svrpc/methods.go).

## Programs that run where nobody can be asked

A backup job at 3 a.m. cannot wait for a prompt. Decide for it ahead of time,
from a terminal:

```console
$ secretvault grant allow /usr/local/bin/backup --item backup/key
allow-always: backup (/usr/local/bin/backup) may read "backup/key"
```

A program in your home directory is identified by its content too: after it
changes, it is asked about again. `--contacts` decides about the contacts
instead of an item:

```console
$ secretvault grant allow /usr/bin/comms-mail --contacts --ops read,write
```

## Services on a server

On a machine that runs `secretvaultd --host`, a service that is not a
systemd unit (a unit uses `LoadCredential=`) asks the host daemon, which
answers what root's policy lists for the service's user and program
(`secretvault host allow --user USER [--program PATH] sv://...`), and
never asks anyone:

```go
c, err := secretvault.Connect(secretvault.Options{Socket: svrpc.HostSocket(), NoStart: true})
...
v, err := c.HostResolve(ctx, "sv://prod/backup/s3#secret")
defer clear(v)
```

Only `host.resolve` is served on that socket, and it sends the one value
the reference names. From a script, `secretvault --host read sv://...` or
`secretvault --host run -- CMD` does the same.
