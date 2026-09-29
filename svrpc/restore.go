package svrpc

import "time"

// Going back to an earlier version of an item, and deleted items.
const (
	MItemRestore = "item.restore" // RestoreParams -> Entry (fields omitted)
	MItemDeleted = "item.deleted" // ListParams -> []DeletedItem
)

// RestoreParams make an earlier revision of an item current again. Rev is
// its ID, or a unique prefix of at least 6 hex digits; "" for a deleted
// item's last contents. Restoring one of an item's conflicting versions
// settles the conflict in its favour.
type RestoreParams struct {
	Vault string `json:"vault,omitempty"`
	Name  string `json:"name"`
	Rev   string `json:"rev,omitempty"`
}

// DeletedItem is an item that was deleted, as it was before.
type DeletedItem struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Kind    string    `json:"kind"`
	Rev     string    `json:"rev"`
	Deleted time.Time `json:"deleted"`
}
