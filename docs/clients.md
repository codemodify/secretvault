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
case errors.Is(err, svrpc.ErrNoVault):  // no such vault (or no default one)
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

### A vault of its own

A program that wants its secrets apart from the person's asks for a
vault by name. It never chooses or sees the passphrase: secretvault asks
the person, in its own prompt, whether to create it, and they choose its
passphrase there. The answer is the new vault's name, or why not:

```go
// Wait as long as a person may take to answer.
ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
defer cancel()
name, err := c.RequestVault(ctx, "mail")
switch {
case err == nil:                           // made: use name in every call
case errors.Is(err, svrpc.ErrExists):      // there is one called "mail" already (nobody was asked)
case errors.Is(err, svrpc.ErrDenied):      // the person said no, now or for good
case errors.Is(err, svrpc.ErrCanceled):    // they closed the question, or chose no passphrase
case errors.Is(err, svrpc.ErrNoPrompter):  // there was no way to ask them
case err != nil:                           // anything else
}
```

What the person sees:

1. "comms-mail wants a new vault called "mail"": that it is a new, empty
   vault kept with their others, that comms-mail never sees its
   passphrase, and that comms-mail still has to ask before it reads or
   stores anything in it. **Create the vault**, **Don't ask again for
   this program**, or **Don't create it** (the default).
2. The new passphrase, typed twice (at least 8 characters).
3. The vault's recovery key, shown once to write down, as the managers'
   New vault shows one: **I have written it down** (the default) or
   **Don't keep a recovery key**. Neither the key nor the passphrase
   reaches the program.

What the program gets, and does not:

- Only the name goes in: `vault.request` refuses a path, a suite, a
  passphrase or anything else (-32602), so no program believes it chose
  them. The vault goes in secretvault's own data folder with the default
  cipher suite, and is never made the default: name it in every call.
- The vault is unlocked once made, and locks itself as any vault does.
  Nothing is granted: the first `item.put` into it is asked about like
  any other (the person may say "always").
- One request at a time: a second one while the first waits fails at once
  (-32000). After "Don't ask again", requests are denied without asking,
  until the person forgets that decision in the vault's Grants.
- A name that is taken is refused before anyone is asked (-32006):
  `vault.list` names every vault anyway.
- The request and how it ended go to the default vault's audit log (and
  the new vault's own).

Over the wire: `{"method":"vault.request","params":{"name":"mail"}}`,
answered `{"vault":"mail"}`.

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

To send, hand over the plain message and let secretvault sign it with the
person's key for its From address, and encrypt it to every recipient's key
(OpenPGP, or S/MIME where a recipient has only a certificate):

```go
out, err := c.ComposeMail(ctx, svrpc.MailComposeParams{Message: plain, Sign: true, Encrypt: true})
// out.Message is ready to send; out.Format, out.SignedWith, out.EncryptedTo say how.
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

Field values are base64. Errors carry codes ([`svrpc/errors.go`](../svrpc/errors.go)):

| Code | Go | Meaning |
| --- | --- | --- |
| -32000 | | failed, for any other reason (the message says) |
| -32001 | `svrpc.ErrLocked` | the vault is locked, and could not be unlocked |
| -32002 | `svrpc.ErrDenied` | the person (or a remembered decision) said no |
| -32003 | `svrpc.ErrNotFound` | no such item (or slot, grant, key, ...) in a vault that is there |
| -32004 | `svrpc.ErrWrongKey` | that key does not open the vault |
| -32005 | `svrpc.ErrCanceled` | the person dismissed the question |
| -32006 | `svrpc.ErrExists` | it is there already |
| -32007 | `svrpc.ErrNoPrompter` | the person had to be asked, and there was no way to ask |
| -32008 | `svrpc.ErrNoVault` | no such vault: the vault named, or the default when none is named and there is none, or one whose folder is gone |
| -32602 | | bad parameters |

The full list of methods and shapes is in
[`svrpc/methods.go`](../svrpc/methods.go).

### Changes for app authors

- **A missing vault is -32008, not -32003.** Until now, an item call that
  named a vault that is not there answered -32003, as a missing item does,
  and a program that took -32003 to mean "nothing saved yet" would store
  a fresh secret, or tell the person they had none, when the vault was
  the thing missing. Every method that names a vault (item.*, vault.*,
  slot.*, grant.*, audit.list, file.*, ...) now answers -32008
  (`svrpc.ErrNoVault`) for one that is not there; -32003 means only an
  item, slot, grant or key missing from a vault that is. A program that
  matched -32003 for both must handle -32008 too: see the vault is
  there with `vault.list`, or ask for one with `vault.request`.
- **`vault.request` is new**: a program asks for a vault of its own by
  name (above).

Faces that speak other protocols keep their own terms: the Secret
Service answers `NoSuchObject` for a collection that is not there, as for
any object (the message says it is the collection); gpg hears "no secret
key"; an SSH client hears the agent's one failure; docker's credential
helper says "credentials not found" (and names the missing vault on
stderr), so that docker goes on without a login; the browser extension
has its own `no-vault`.

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
