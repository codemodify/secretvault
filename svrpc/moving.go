package svrpc

// Items going from one vault to another (item.move, item.copy). The
// daemon reads them, writes them to the other vault (their files sealed
// again under its keys) and, for a move, takes them out of the first
// vault after every one is written: into its deleted items, from which
// they can be brought back. Nothing secret is in the parameters or the
// reply.

// MaxMoveItems is the most items one item.move or item.copy takes. A
// request for more (more names, or a prefix more items start with) is
// refused (CodeInvalidParams) before anything is asked or written: name a
// narrower prefix, or fewer items, and move the rest in another request.
const MaxMoveItems = 500

// MoveParams say which items go where: those Names, or every item whose
// name starts with Prefix ("" is every item of the vault). Exactly one of
// the two is given. Vault "" is the default vault; To must be named, and
// be another vault. The items keep their names.
//
// Plan only says what would happen (MoveResult.Items and .Readers), and
// changes nothing: it is for secretvault's own programs, which confirm a
// move in their own words before they make it. Any other program is
// refused it (CodeDenied), as it would list items no one let it see.
type MoveParams struct {
	Vault  string   `json:"vault,omitempty"`
	To     string   `json:"to"`
	Names  []string `json:"names,omitempty"`
	Prefix *string  `json:"prefix,omitempty"`
	Plan   bool     `json:"plan,omitempty"`
}

// VaultReaders are who can read what is in a vault besides the person
// and this device: what a move or copy into it discloses to them.
type VaultReaders struct {
	// People are the keys of other people or devices that open it (its
	// keyslots of their keys), by their labels ("" for one without).
	People []string `json:"people,omitempty"`

	// Trustees are those who can get it through emergency access.
	Trustees []string `json:"trustees,omitempty"`

	// Devices are the other devices registered in it (they have used
	// it), by their labels.
	Devices []string `json:"devices,omitempty"`

	// Sync is the server it syncs through (its host), with every device
	// that joins it; "" when it does not.
	Sync string `json:"sync,omitempty"`
}

// Anyone reports whether anyone besides the person reads the vault.
func (r *VaultReaders) Anyone() bool {
	return r != nil && (len(r.People) > 0 || len(r.Trustees) > 0 || len(r.Devices) > 0 || r.Sync != "")
}

// PrefixOf is a MoveParams.Prefix: PrefixOf("") is every item.
func PrefixOf(p string) *string { return &p }

// MoveResult is what became of the items, by name: the reply of a request
// that went through, and the Data of the error of one that did not.
//
// For a move, Done are the items in To that left Vault (into its deleted
// items); for a copy, the items written to To. Both are the items a move
// wrote to To but did not take out of Vault (it stopped, or the item
// changed meanwhile): they are in both vaults, and nothing is lost.
// NotDone are the items not written to To: they are in Vault only, as
// they were.
//
// An error that refuses the whole request before anything is written
// names the items it is about: Clashes (CodeExists) are names To has
// already; Missing (CodeNotFound) are names Vault does not have;
// Conflicts (CodeFailed) are items changed on two devices at once, to be
// settled first ('secretvault resolve').
//
// A plan (MoveParams.Plan) has Items, every item that would go, and
// Readers, who else reads To (nil when nobody does), and nothing done.
type MoveResult struct {
	Vault     string        `json:"vault"`
	To        string        `json:"to"`
	Items     []string      `json:"items,omitempty"`
	Readers   *VaultReaders `json:"readers,omitempty"`
	Done      []string      `json:"done"`
	Both      []string      `json:"both,omitempty"`
	NotDone   []string      `json:"not_done,omitempty"`
	Clashes   []string      `json:"clashes,omitempty"`
	Missing   []string      `json:"missing,omitempty"`
	Conflicts []string      `json:"conflicts,omitempty"`
}
