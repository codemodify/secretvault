package svrpc

// Attachments.
const (
	MFileAttach = "file.attach" // FileAttachParams -> Entry (fields omitted)
	MFileGet    = "file.get"    // FileRef -> FileData
	MFileRemove = "file.remove" // FileRef -> Entry (fields omitted)
)

// MaxFileData is the largest file that fits in one message (base64 in
// JSON, under MaxMessage).
const MaxFileData = MaxMessage/4*3 - 64<<10

// FileInfo describes an attached file.
type FileInfo struct {
	Name   string `json:"name"`
	Type   string `json:"type,omitempty"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"` // hex
}

// FileAttachParams attaches a file to an item, replacing one of the same
// name.
type FileAttachParams struct {
	Vault string `json:"vault,omitempty"`
	Item  string `json:"item"`
	Name  string `json:"name"`
	Type  string `json:"type,omitempty"`
	Data  []byte `json:"data"`
}

// FileRef names an attached file.
type FileRef struct {
	Vault string `json:"vault,omitempty"`
	Item  string `json:"item"`
	Name  string `json:"name"`
}

// FileData is an attached file and its contents.
type FileData struct {
	FileInfo
	Data []byte `json:"data"`
}
