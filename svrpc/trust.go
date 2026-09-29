package svrpc

import "time"

// The trust store (contacts and their keys) and OpenPGP keys held in
// vaults. For contact and trust methods "Vault" is the vault contacts are
// kept in: "" means the configured contacts vault, else the default
// vault. For pgp methods it is the vault holding the key.
//
// Consent: reading contacts (list, get, lookup, check, verify a
// signature) is asked about as reading "contacts" in that vault, and
// changing them (add, import, remove, verify a key, a key seen in mail)
// as changing them; a decision about contacts covers no item, and one
// about an item covers no contacts. Signing with a vault key is OpSign on
// its item, and decrypting OpDecrypt: neither lets the program read the
// key, which never leaves the daemon.
const (
	MContactList   = "contact.list"   // ContactListParams -> []Contact (keys summarised)
	MContactGet    = "contact.get"    // ContactRef -> Contact
	MContactAdd    = "contact.add"    // ContactAddParams -> ContactChange
	MContactImport = "contact.import" // ContactImportParams -> ContactImportResult
	MContactRemove = "contact.remove" // ContactRemoveParams -> Contact (what was removed, or what is left)
	MContactVerify = "contact.verify" // ContactVerifyParams -> Contact
	MContactLookup = "contact.lookup" // ContactLookupParams -> ContactLookupResult
	MContactVault  = "contact.vault"  // VaultRef -> VaultRef (sets the contacts vault when Vault is given; the CLI only)

	MTrustCheck = "trust.check" // TrustCheckParams -> Verdict
	MTrustSeen  = "trust.seen"  // TrustSeenParams -> SeenResult

	MPGPGenerate = "pgp.generate" // PGPGenerateParams -> PGPKey
	MPGPPublic   = "pgp.public"   // PGPKeyRef -> PGPKey
	MPGPSign     = "pgp.sign"     // PGPSignParams -> PGPSignResult
	MPGPDecrypt  = "pgp.decrypt"  // PGPDecryptParams -> PGPDecryptResult
	MPGPVerify   = "pgp.verify"   // PGPVerifyParams -> PGPVerifyResult
)

// Contact is a person (or organisation) in the trust store; see
// svtrust.Contact. Level is the best verification of any of its keys.
type Contact struct {
	ID           string       `json:"id"`
	Name         string       `json:"name"`
	Emails       []string     `json:"emails,omitempty"`
	Notes        string       `json:"notes,omitempty"`
	Organisation bool         `json:"organisation,omitempty"`
	Origin       string       `json:"origin,omitempty"` // added, mail, lookup, qr
	Created      time.Time    `json:"created"`
	Updated      time.Time    `json:"updated"`
	Level        string       `json:"level"`
	Keys         []ContactKey `json:"keys,omitempty"`
	// Warnings are things to tell the person: an address seen with a key
	// that belongs to someone else's, a revoked or expired key.
	Warnings []string `json:"warnings,omitempty"`
}

// ContactKey is one key of a contact. Material, Chain, Verifications and
// Seen come with contact.get only.
type ContactKey struct {
	Type        string    `json:"type"` // openpgp, x509, ssh, secretvault
	Fingerprint string    `json:"fingerprint"`
	Label       string    `json:"label,omitempty"`
	Addresses   []string  `json:"addresses,omitempty"` // bound to the key
	Level       string    `json:"level"`               // its best verification ("" for none)
	State       string    `json:"state,omitempty"`     // "revoked", "expired on ...": why it cannot be used now
	Added       time.Time `json:"added"`
	Source      string    `json:"source,omitempty"`

	Material      []byte         `json:"material,omitempty"` // OpenPGP binary, certificate DER, authorized_keys line, recipient text
	Chain         [][]byte       `json:"chain,omitempty"`
	Subkeys       []string       `json:"subkeys,omitempty"`
	Verifications []Verification `json:"verifications,omitempty"`
	Seen          []Sighting     `json:"seen,omitempty"`
}

// Verification is one verification of a key: recorded, or (Derived)
// worked out now, as an organisation's CA vouching for a certificate.
type Verification struct {
	Level       string    `json:"level"`
	Method      string    `json:"method"`
	By          string    `json:"by,omitempty"`
	At          time.Time `json:"at"`
	Source      string    `json:"source,omitempty"`
	Addresses   []string  `json:"addresses,omitempty"`
	Derived     bool      `json:"derived,omitempty"`
	Description string    `json:"description"` // in plain words
}

// Sighting is how often a key was seen in mail from an address.
type Sighting struct {
	Address   string    `json:"address"`
	First     time.Time `json:"first"`
	Last      time.Time `json:"last"`
	Count     int       `json:"count"`
	Source    string    `json:"source,omitempty"`
	Conflicts []string  `json:"conflicts,omitempty"` // keys bound to the address when this one was first seen for it
}

// ContactListParams list contacts; Query, when set, keeps those whose
// name or an address contains it.
type ContactListParams struct {
	Vault string `json:"vault,omitempty"`
	Query string `json:"query,omitempty"`
}

// ContactRef names a contact: by ID, name, address, or a key's
// fingerprint.
type ContactRef struct {
	Vault string `json:"vault,omitempty"`
	Ref   string `json:"ref"`
}

// ContactAddParams make a new contact. Keys are key files' contents, in
// any form the trust store reads (OpenPGP, PEM or DER certificates, SSH
// public keys, secretvault recipients); Source says where they came from.
type ContactAddParams struct {
	Vault        string   `json:"vault,omitempty"`
	Name         string   `json:"name,omitempty"` // "" takes it from the first key
	Emails       []string `json:"emails,omitempty"`
	Notes        string   `json:"notes,omitempty"`
	Organisation bool     `json:"organisation,omitempty"`
	Keys         [][]byte `json:"keys,omitempty"`
	Source       string   `json:"source,omitempty"`
}

// ContactChange is a contact as a change left it, and what to tell the
// person about it.
type ContactChange struct {
	Contact  Contact  `json:"contact"`
	Warnings []string `json:"warnings,omitempty"`
}

// ContactImportParams add keys to the contacts: from Data (a key file,
// which may hold many keys), or from URI, a secretvault-contact or
// openpgp4fpr URI scanned from someone's QR code, which verifies the keys
// it names in person. Fetch fetches the OpenPGP keys a URI names that
// are missing, from Keyserver ("" for keys.openpgp.org).
type ContactImportParams struct {
	Vault     string `json:"vault,omitempty"`
	Data      []byte `json:"data,omitempty"`
	URI       string `json:"uri,omitempty"`
	Contact   string `json:"contact,omitempty"` // put new keys in this contact
	Name      string `json:"name,omitempty"`    // name new contacts
	Source    string `json:"source,omitempty"`
	Fetch     bool   `json:"fetch,omitempty"`
	Keyserver string `json:"keyserver,omitempty"`
}

// ContactImportResult says what happened to each key.
type ContactImportResult struct {
	Keys     []ImportedKey `json:"keys"`
	Missing  []string      `json:"missing,omitempty"` // a URI's keys that were not found, as "type:fingerprint"
	Warnings []string      `json:"warnings,omitempty"`
}

// ImportedKey is one key imported, or verified by a scanned URI.
type ImportedKey struct {
	ContactID   string   `json:"contact_id"`
	Contact     string   `json:"contact"` // its name
	Type        string   `json:"type"`
	Fingerprint string   `json:"fingerprint"`
	Label       string   `json:"label,omitempty"`
	New         bool     `json:"new,omitempty"`
	Verified    bool     `json:"verified,omitempty"` // verified in person, by the scanned URI
	Warnings    []string `json:"warnings,omitempty"`
}

// ContactRemoveParams remove a contact, or only one of its keys.
type ContactRemoveParams struct {
	Vault       string `json:"vault,omitempty"`
	Ref         string `json:"ref"`
	Fingerprint string `json:"fingerprint,omitempty"`
}

// Verification methods for ContactVerifyParams.Method.
const (
	VerifyFingerprint  = "fingerprint"   // fingerprints compared in person
	VerifyQR           = "qr"            // their QR code scanned
	VerifyOrgDirectory = "org-directory" // an organisation's directory vouches (Source names it)
	VerifyOrgCA        = "org-ca"        // an organisation's CA vouches (Source names it)
	VerifyTOFU         = "tofu"          // accepted as it is, without verifying
	VerifyWKD          = "wkd"
	VerifyKeyserver    = "keyserver-email"
)

// ContactVerifyParams record a verification of a key. Ref, when it names
// a contact other than the one holding the key, moves the key to it.
// Addresses limit what the verification covers ("" for the key's own).
type ContactVerifyParams struct {
	Vault       string   `json:"vault,omitempty"`
	Ref         string   `json:"ref,omitempty"`
	Fingerprint string   `json:"fingerprint"`
	Method      string   `json:"method"`
	Source      string   `json:"source,omitempty"`
	Addresses   []string `json:"addresses,omitempty"`
}

// ContactLookupParams look keys up: Query is an address (WKD, then
// keys.openpgp.org) or an OpenPGP fingerprint or key ID (the keyserver).
// WKD asks WKD only; Keyserver asks that keyserver only (https://,
// hkps:// or hkp://). Add stores what is found as contacts.
type ContactLookupParams struct {
	Vault     string `json:"vault,omitempty"`
	Query     string `json:"query"`
	WKD       bool   `json:"wkd,omitempty"`
	Keyserver string `json:"keyserver,omitempty"`
	Add       bool   `json:"add,omitempty"`
	Name      string `json:"name,omitempty"`
}

// ContactLookupResult is what each place asked had.
type ContactLookupResult struct {
	Found  []LookupFound `json:"found,omitempty"`
	Added  []ImportedKey `json:"added,omitempty"`
	Errors []string      `json:"errors,omitempty"` // places that had nothing, or failed
}

// LookupFound is what one place had. Known says, per key, which contact
// already has it ("" for none).
type LookupFound struct {
	URL    string       `json:"url"`
	Policy []string     `json:"policy,omitempty"` // the domain's WKD policy flags
	Keys   []ContactKey `json:"keys"`
	Known  []string     `json:"known,omitempty"`
}

// TrustCheckParams ask who signed: the signer's Fingerprint (any key
// type, a subkey, or an OpenPGP key ID) or Key (certificate or public
// key), and From, the address the message claims to be from. MinLevel is
// the policy's weakest verification that counts ("" for "published").
type TrustCheckParams struct {
	Vault       string `json:"vault,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	Key         []byte `json:"key,omitempty"`
	From        string `json:"from,omitempty"`
	MinLevel    string `json:"min_level,omitempty"`
}

// Verdict is what the trust store knows about a signer (see
// svtrust.Verdict), with the policy's reading of it: Trusted, and Status
// "verified", "unverified", "suspicious" or "unknown".
type Verdict struct {
	Fingerprint  string        `json:"fingerprint"`
	From         string        `json:"from,omitempty"`
	Known        bool          `json:"known"`
	ContactID    string        `json:"contact_id,omitempty"`
	Contact      string        `json:"contact,omitempty"` // its name
	Key          *ContactKey   `json:"key,omitempty"`
	Level        string        `json:"level"`     // for the key and From
	KeyLevel     string        `json:"key_level"` // for the key alone
	Verification *Verification `json:"verification,omitempty"`
	Bound        bool          `json:"bound"`   // From is one of the key's addresses
	Claimed      bool          `json:"claimed"` // the key names From itself
	Seen         *Sighting     `json:"seen,omitempty"`
	State        string        `json:"state,omitempty"`
	Others       []OtherKey    `json:"others,omitempty"` // other contacts' keys bound to From
	Reasons      []string      `json:"reasons"`
	Trusted      bool          `json:"trusted"`
	Status       string        `json:"status"`
}

// OtherKey is another contact's key.
type OtherKey struct {
	ContactID   string `json:"contact_id"`
	Contact     string `json:"contact"`
	Fingerprint string `json:"fingerprint"`
	Level       string `json:"level"`
}

// TrustSeenParams record that a key (an Autocrypt header's key data,
// decoded, or an S/MIME signer's certificate) came with a message from
// Address, received at Time (zero means now). Source describes the
// message ("" for "mail from ADDRESS on DATE"); Name is the sender's
// display name, for naming a new contact.
type TrustSeenParams struct {
	Vault   string    `json:"vault,omitempty"`
	Key     []byte    `json:"key"`
	Address string    `json:"address"`
	Time    time.Time `json:"time,omitempty"`
	Source  string    `json:"source,omitempty"`
	Name    string    `json:"name,omitempty"`
}

// SeenResult is what recording a key seen in mail did. Conflicts are
// other contacts' keys bound to the address: the key was kept apart from
// them, never put in their place.
type SeenResult struct {
	Contact     Contact    `json:"contact"`
	Fingerprint string     `json:"fingerprint"`
	New         bool       `json:"new,omitempty"`
	Bound       bool       `json:"bound"`
	Conflicts   []OtherKey `json:"conflicts,omitempty"`
	Warnings    []string   `json:"warnings,omitempty"`
}

// The item an OpenPGP key of your own is kept in: kind "key", with the
// secret key (armored) and the public key (armored) as fields, the
// passphrase protecting the secret key if it has one, and the fingerprint
// and primary user ID as attributes.
const (
	PGPItemKind    = "key"
	PGPItemPrefix  = "pgp/" // new keys are named pgp/ADDRESS
	PGPSecretField = "pgp_secret_key"
	PGPPublicField = "pgp_public_key"
	PGPPassField   = "passphrase"
	PGPFingerprint = "pgp_fingerprint" // attribute
	PGPUserID      = "pgp_uid"         // attribute
)

// PGPGenerateParams make a new OpenPGP key in a vault, as item Item (""
// for pgp/EMAIL). Version is 6 (the default) or 4; LifetimeDays 0 means
// it does not expire.
type PGPGenerateParams struct {
	Vault        string   `json:"vault,omitempty"`
	Item         string   `json:"item,omitempty"`
	Name         string   `json:"name,omitempty"`
	Emails       []string `json:"emails,omitempty"`
	Version      int      `json:"version,omitempty"`
	LifetimeDays int      `json:"lifetime_days,omitempty"`
}

// PGPKeyRef names one of your OpenPGP keys: by item name, fingerprint,
// key ID or address; "" when the vault has only one.
type PGPKeyRef struct {
	Vault string `json:"vault,omitempty"`
	Key   string `json:"key,omitempty"`
}

// PGPKey is one of your OpenPGP keys, without its secret.
type PGPKey struct {
	Vault       string    `json:"vault"`
	Item        string    `json:"item"`
	Fingerprint string    `json:"fingerprint"`
	Version     int       `json:"version"`
	UserIDs     []string  `json:"user_ids,omitempty"`
	Created     time.Time `json:"created"`
	Expires     time.Time `json:"expires,omitempty"`
	PublicKey   string    `json:"public_key"` // armored
}

// Signing modes.
const (
	SignDetached  = "detached"
	SignInline    = "inline"
	SignCleartext = "cleartext"
)

// PGPSignParams sign Data with one of your keys (see PGPKeyRef). Mode is
// detached (the default), inline or cleartext; Text makes a text
// signature.
type PGPSignParams struct {
	Vault string `json:"vault,omitempty"`
	Key   string `json:"key,omitempty"`
	Data  []byte `json:"data"`
	Mode  string `json:"mode,omitempty"`
	Armor bool   `json:"armor,omitempty"`
	Text  bool   `json:"text,omitempty"`
}

// PGPSignResult is the signature, or the signed message.
type PGPSignResult struct {
	Signature   []byte `json:"signature"`
	Item        string `json:"item"`
	Fingerprint string `json:"fingerprint"`
}

// PGPDecryptParams decrypt Data with whichever of your keys it is
// encrypted to (or Key). Verify also checks the signatures inside
// against your contacts (which is reading them), with From the claimed
// sender.
type PGPDecryptParams struct {
	Vault  string `json:"vault,omitempty"`
	Key    string `json:"key,omitempty"`
	Data   []byte `json:"data"`
	Verify bool   `json:"verify,omitempty"`
	From   string `json:"from,omitempty"`
}

// PGPDecryptResult is the decrypted message.
type PGPDecryptResult struct {
	Body        []byte         `json:"body"`
	FileName    string         `json:"file_name,omitempty"`
	Item        string         `json:"item"`
	Fingerprint string         `json:"fingerprint"` // the (sub)key that decrypted it
	Signatures  []PGPSignature `json:"signatures,omitempty"`
	Warnings    []string       `json:"warnings,omitempty"`
}

// PGPVerifyParams verify a signed message against your contacts (Vault
// is the contacts vault here): Data is the message and Signature a
// detached signature, or Signature is empty and Data an inline or
// cleartext signed message. From is the claimed sender.
type PGPVerifyParams struct {
	Vault     string `json:"vault,omitempty"`
	Data      []byte `json:"data"`
	Signature []byte `json:"signature,omitempty"`
	From      string `json:"from,omitempty"`
}

// PGPVerifyResult has a verdict per signature, and the message of an
// inline or cleartext signed one.
type PGPVerifyResult struct {
	Body       []byte         `json:"body,omitempty"`
	Signatures []PGPSignature `json:"signatures"`
}

// PGPSignature is one signature: whether it is valid (see
// svpgp.SignatureResult), by which key, and the trust store's verdict on
// its signer.
type PGPSignature struct {
	Valid      bool      `json:"valid"`
	Error      string    `json:"error,omitempty"`
	Issuer     string    `json:"issuer,omitempty"`      // what the signature says: a fingerprint or key ID
	Signer     string    `json:"signer,omitempty"`      // the primary key it verified with
	SigningKey string    `json:"signing_key,omitempty"` // the (sub)key it verified with
	Created    time.Time `json:"created"`
	Verdict    *Verdict  `json:"verdict,omitempty"`
}
