package svrpc

// MWhere lists every place secretvault keeps or changes anything, as the
// daemon sees them (its own environment, its config): its folders and
// their files, the vaults wherever they are, its sockets, and what it
// changed in other programs.
const MWhere = "where" // nil -> []Place

// Place is one folder or file secretvault keeps or changed.
type Place struct {
	Group  string `json:"group"`  // one of the Place* groups, in their order
	Path   string `json:"path"`   // a path, or a registry key on Windows (HKEY_CURRENT_USER\...)
	What   string `json:"what"`   // what it is and why it is there, in a plain sentence
	Exists bool   `json:"exists"` // it is there now
	Dir    bool   `json:"dir"`    // it is a folder
}

// The groups of places, in the order they are listed.
const (
	PlaceSettings = "Settings"       // the settings folder and its files
	PlaceData     = "Data"           // the data folder, the vaults wherever they are, keys, logs, state
	PlaceRunning  = "While running"  // the daemon's runtime folder and its sockets
	PlaceOther    = "Other programs" // what secretvault changed elsewhere, from its records
	PlaceHost     = "Host daemon"    // the machine's own daemon, when it is set up
)

// PlaceGroups are the groups, in order.
var PlaceGroups = []string{PlaceSettings, PlaceData, PlaceRunning, PlaceOther, PlaceHost}
