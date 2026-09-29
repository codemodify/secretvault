// Package svtrust is secretvault's trust store: the people whose keys you
// hold, how you verified each key, and the verdict on a message's signer
// ("is this signed by Alice?").
//
// # Contacts and keys
//
// A Contact is a person (or an organisation) with names, addresses, notes
// and keys of four types: OpenPGP, X.509 (S/MIME), SSH and secretvault
// recipients. Each Key holds its material, its fingerprint, the addresses
// bound to it, the verification Events it has had, and how often it was
// seen in mail from each address (Sighting). Contacts live in a vault as
// records of kind "contact", so they are encrypted, keep their history
// and sync like items; a record changed on two devices at once is merged
// when read. The JSON keeps members it does not know, so a newer
// version's additions survive an older one's rewrite.
//
//	store := svtrust.NewStore(vault)
//	keys, _ := svtrust.ParseKeys(fileBytes)        // any of the four types
//	c, warnings, _ := store.Add(&svtrust.Contact{Name: "Alice", Keys: keys})
//	store.Verify("Alice", fp, svtrust.Event{Method: svtrust.MethodFingerprint, By: "you"})
//	store.Seen(key, "alice@example.org", received, "", "comms-mail", "Alice")
//	v, _ := store.Check(svtrust.Query{Fingerprint: fp, From: "alice@example.org"})
//	v.Reasons  // "Signed by Alice's key, which you verified in person on 2026-09-01."
//	svtrust.DefaultPolicy.Judge(v)
//
// # Verification
//
// Levels, strongest first: InPerson (fingerprints compared, or a QR code
// scanned), Organisation (its CA or its directory), Logged (a transparency
// log; the level is reserved, nothing records it yet), Published (WKD, or
// a keyserver that checked the address by email), and TOFU (seen in mail
// before). An event covers the key as a whole, or only the addresses it
// lists: a key found by WKD is published for that one address.
//
// Trust on first use binds an address to the first key seen for it. A
// different key for an address that already has one is never put in its
// place: it is kept apart, in a contact of its own, the conflict is
// recorded, and verdicts about it warn of an impostor until you verify it.
//
// # Verdicts and policy
//
// Check reports facts: the contact, the best verification of the key for
// the claimed address and of the key alone, whether the address is bound
// to the key, how often it was seen, other contacts' keys bound to the
// address, and plain-words Reasons. A Policy judges those facts;
// DefaultPolicy counts Published and better as verified.
//
// # Discovery
//
// ParseKeys reads files; ParseCard reads secretvault-contact and
// openpgp4fpr URIs, and Scan records one as scanned in person. WKD looks
// in an address's Web Key Directory (the advanced method, then the
// direct one); Keyserver asks a VKS keyserver (keys.openpgp.org) and falls
// back to HKP; Directory is the interface an organisation's directory
// (LDAP, later) will implement. Nothing here goes on the network unless
// asked to.
package svtrust
