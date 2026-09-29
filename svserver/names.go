package svserver

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svstore"
)

// FileKind is what a vault file is, judged by its name alone. The server
// stores only the kinds the vault format names, so a client cannot use it
// as a general file store, and nothing it holds can be mistaken for a
// file of another kind.
type FileKind int

const (
	// Descriptor is vault.json, written once when the vault is made.
	Descriptor FileKind = iota + 1
	// Slot is a keyslot, slots/<id>.json: the one kind that can be removed.
	Slot
	// Epoch is a key rotation's record, epochs/<n>.json with n ≥ 2.
	Epoch
	// Revision is one revision of an object, named by its SHA-256.
	Revision
	// Checkpoint is under checkpoints/, reserved for signed checkpoints.
	Checkpoint
)

func (k FileKind) String() string {
	switch k {
	case Descriptor:
		return "descriptor"
	case Slot:
		return "keyslot"
	case Epoch:
		return "epoch record"
	case Revision:
		return "revision"
	case Checkpoint:
		return "checkpoint"
	}
	return "unknown"
}

// CheckpointsDir is reserved for the signed checkpoints that will detect
// rollback (docs/format.md, "Reserved and future").
const CheckpointsDir = "checkpoints"

// Size limits. Keyslots, epoch records and the descriptor are small JSON
// files; revisions are as large as the items in them.
const (
	MaxJSONFile        = 64 << 10
	MaxCheckpoint      = 1 << 20
	DefaultMaxRevision = 16 << 20
)

// ErrFileName is a name that is not one of a vault's files.
var ErrFileName = errors.New("svserver: not a vault file name")

// ClassifyName says which kind of vault file name is, accepting only the
// canonical names the vault format writes (lowercase hex IDs, eight-digit
// epochs from 2 up). Anything else is refused.
func ClassifyName(name string) (FileKind, error) {
	if err := svstore.CheckName(name); err != nil {
		return 0, fmt.Errorf("%w: %q", ErrFileName, name)
	}
	switch {
	case name == svformat.DescriptorName:
		return Descriptor, nil
	case strings.HasPrefix(name, svformat.SlotsDir+"/"):
		if id, ok := svformat.ParseSlotName(name); ok && svformat.SlotName(id) == name {
			return Slot, nil
		}
	case strings.HasPrefix(name, svformat.EpochsDir+"/"):
		if n, ok := parseEpochName(name); ok && n >= 2 {
			return Epoch, nil
		}
	case strings.HasPrefix(name, svformat.ObjectsDir+"/"):
		if obj, rev, ok := svformat.ParseRevisionName(name); ok && svformat.RevisionName(obj, rev) == name {
			return Revision, nil
		}
	case strings.HasPrefix(name, CheckpointsDir+"/"):
		if strings.Count(name, "/") <= 3 {
			return Checkpoint, nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrFileName, name)
}

// revisionHash is the SHA-256 a revision's name says its contents have.
func revisionHash(name string) string {
	_, rev, _ := svformat.ParseRevisionName(name)
	return rev.String()
}

func parseEpochName(name string) (uint32, bool) {
	digits := strings.TrimSuffix(strings.TrimPrefix(name, svformat.EpochsDir+"/"), ".json")
	if len(digits) != 8 {
		return 0, false
	}
	n, err := strconv.ParseUint(digits, 10, 32)
	if err != nil || svformat.EpochName(uint32(n)) != name {
		return 0, false
	}
	return uint32(n), true
}

// maxSize is the largest file of a kind the server accepts.
func maxSize(k FileKind, maxRevision int64) int64 {
	switch k {
	case Revision:
		return maxRevision
	case Checkpoint:
		return MaxCheckpoint
	}
	return MaxJSONFile
}

var vaultNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)

// CheckVaultName accepts the names vaults have on a server: lowercase
// letters, digits, '-' and '_', at most 64, starting with a letter or
// digit. Lowercase only, so two names never share a directory on a
// filesystem that ignores case. A vault's own ID (32 hex digits) is one.
func CheckVaultName(name string) error {
	if !vaultNamePattern.MatchString(name) {
		return fmt.Errorf("svserver: %q is not a vault name (lowercase letters, digits, '-' and '_', at most 64)", name)
	}
	return nil
}
