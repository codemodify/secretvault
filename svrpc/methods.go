package svrpc

import "time"

// Methods a client calls on secretvaultd. Params and results are the
// types below; "Vault" fields name a registered vault ("" means the
// default vault).
const (
	MHello  = "client.hello"  // HelloParams -> HelloResult
	MStatus = "daemon.status" // nil -> Status

	MVaultList    = "vault.list"    // nil -> []VaultInfo
	MVaultCreate  = "vault.create"  // VaultCreateParams -> VaultCreateResult
	MVaultAdd     = "vault.add"     // VaultAddParams -> VaultInfo
	MVaultForget  = "vault.forget"  // VaultRef -> nil
	MVaultDefault = "vault.default" // VaultRef -> nil
	MVaultUnlock  = "vault.unlock"  // UnlockParams -> VaultInfo
	MVaultLock    = "vault.lock"    // LockParams -> nil
	MVaultVerify  = "vault.verify"  // VaultRef -> VerifyResult
	MVaultPasswd  = "vault.passwd"  // PasswdParams -> SlotInfo
	MVaultRotate  = "vault.rotate"  // RotateParams -> RotateResult

	MSlotList   = "slot.list"   // VaultRef -> []SlotInfo
	MSlotAdd    = "slot.add"    // SlotAddParams -> SlotInfo
	MSlotRemove = "slot.remove" // SlotRemoveParams -> nil

	MItemGet     = "item.get"     // ItemRef -> Entry
	MItemList    = "item.list"    // ListParams -> []Entry (fields omitted)
	MItemPut     = "item.put"     // PutParams -> Entry (fields omitted)
	MItemDelete  = "item.delete"  // ItemRef -> nil
	MItemRename  = "item.rename"  // RenameParams -> Entry (fields omitted)
	MItemHistory = "item.history" // ItemRef -> []Entry

	MGrantList   = "grant.list"   // VaultRef -> []Grant
	MGrantRevoke = "grant.revoke" // GrantRef -> nil
	MGrantAdd    = "grant.add"    // GrantAddParams -> Grant

	MAuditList = "audit.list" // AuditParams -> []AuditEntry

	MPromptRegister = "prompt.register" // PromptRegisterParams -> nil

	MKeyringServe = "keyring.serve" // KeyringServeParams -> nil

	// The browser relay (secretvault-browser): it opens a session for the
	// browser that started it, then hands over the extension's messages.
	MBrowserOpen    = "browser.open"    // BrowserOpenParams -> BrowserOpenResult
	MBrowserMessage = "browser.message" // BrowserFrame -> BrowserFrame (empty: no answer)
	MBrowserList    = "browser.list"    // VaultRef -> []BrowserAssociation
	MBrowserRemove  = "browser.remove"  // BrowserRemoveParams -> nil
)

// BrowserOpenParams open a browser session on a vault ("" for the
// default). Origin is the extension as the browser named it on the
// relay's command line; it is shown, not trusted.
type BrowserOpenParams struct {
	Vault  string `json:"vault,omitempty"`
	Origin string `json:"origin,omitempty"`
}

// BrowserOpenResult says who the daemon takes the browser to be.
type BrowserOpenResult struct {
	Browser string `json:"browser"`
	Vault   string `json:"vault"`
}

// BrowserFrame is one native-messaging message, as the extension sent it
// or is to receive it.
type BrowserFrame struct {
	Frame []byte `json:"frame,omitempty"`
}

// BrowserAssociation is a browser extension connected to a vault on this
// device.
type BrowserAssociation struct {
	Name      string    `json:"name"`
	Vault     string    `json:"vault"`
	Program   string    `json:"program"`   // the browser, as shown to people
	Extension string    `json:"extension"` // as the browser named it
	Created   time.Time `json:"created"`
}

// BrowserRemoveParams disconnect an extension by its association's name.
type BrowserRemoveParams struct {
	Vault string `json:"vault,omitempty"`
	Name  string `json:"name"`
}

// KeyringServeParams turn the Secret Service face on or off.
type KeyringServeParams struct {
	Enable bool `json:"enable"`
}

// Methods the daemon calls on a client that offered to prompt.
const (
	MPromptAsk = "prompt.ask" // PromptAsk -> PromptAnswer
)

// Notifications the daemon sends to every client.
const (
	EVaultLocked   = "vault.locked"   // VaultEvent
	EVaultUnlocked = "vault.unlocked" // VaultEvent
	EItemChanged   = "item.changed"   // VaultEvent

	// To a browser relay only, in place of the above: a message for the
	// extension that it did not ask for (the vault locked or unlocked).
	EBrowserFrame = "browser.frame" // BrowserFrame
)

// HelloParams introduce a client. CanPrompt says the client will answer
// prompt.ask on the terminal it runs in.
type HelloParams struct {
	Client    string `json:"client"`
	Version   string `json:"version"`
	CanPrompt bool   `json:"can_prompt,omitempty"`
}

// HelloResult is what the daemon says back.
type HelloResult struct {
	Daemon  string `json:"daemon"`
	Version string `json:"version"`
	// Caller is how the daemon sees this client, as shown in prompts.
	Caller string `json:"caller"`
}

// Status describes the running daemon.
type Status struct {
	Version string      `json:"version"`
	PID     int         `json:"pid"`
	Home    string      `json:"home"`
	Socket  string      `json:"socket"`
	Vaults  []VaultInfo `json:"vaults"`
	Prompts string      `json:"prompts"` // how desktop prompts are shown
	// SecretService says whether the daemon is the desktop's keyring.
	SecretService string `json:"secret_service"`
	// SSHAgent is the SSH agent socket, "" when off.
	SSHAgent string `json:"ssh_agent,omitempty"`
}

// VaultRef names a vault.
type VaultRef struct {
	Vault string `json:"vault,omitempty"`
}

// VaultInfo describes a registered vault.
type VaultInfo struct {
	Name     string    `json:"name"`
	ID       string    `json:"id"`
	Path     string    `json:"path"`
	Suite    string    `json:"suite"`
	Default  bool      `json:"default,omitempty"`
	Locked   bool      `json:"locked"`
	Created  time.Time `json:"created"`
	AutoLock AutoLock  `json:"auto_lock"`

	// LoginUnlock is a vault the daemon opens when the person logs in,
	// with a key the OS keeps for them (vault.login).
	LoginUnlock bool `json:"login_unlock,omitempty"`
}

// AutoLock is when a vault locks itself.
type AutoLock struct {
	IdleMinutes  int  `json:"idle_minutes"` // 0: never on idle
	OnScreenLock bool `json:"on_screen_lock"`
	OnSleep      bool `json:"on_sleep"`
}

// VaultCreateParams create a vault in the daemon's data directory (or at
// Path) and register it.
type VaultCreateParams struct {
	Name       string `json:"name"`
	Path       string `json:"path,omitempty"`
	Suite      string `json:"suite,omitempty"`
	Passphrase []byte `json:"passphrase"`
	Recovery   bool   `json:"recovery,omitempty"`
}

// VaultCreateResult is the new vault, and its recovery key if one was
// asked for (shown once, stored nowhere).
type VaultCreateResult struct {
	Vault       VaultInfo `json:"vault"`
	RecoveryKey string    `json:"recovery_key,omitempty"`
}

// VaultAddParams register an existing vault folder under a name.
type VaultAddParams struct {
	Name string `json:"name"`
	Path string `json:"path"`
}

// Key is a key presented to unlock a vault. Secret holds the passphrase,
// the recovery key text, the keyfile's contents, or the identity file's
// text, by Type.
type Key struct {
	Type   string `json:"type"` // "passphrase", "recovery", "keyfile", "identity"
	Secret []byte `json:"secret"`
}

// UnlockParams unlock a vault. With no Key the daemon asks the person.
type UnlockParams struct {
	Vault string `json:"vault,omitempty"`
	Key   *Key   `json:"key,omitempty"`
}

// LockParams lock one vault, or every vault.
type LockParams struct {
	Vault string `json:"vault,omitempty"`
	All   bool   `json:"all,omitempty"`
}

// VerifyResult is what a full re-authentication of a vault found.
type VerifyResult struct {
	Objects    int                 `json:"objects"`
	Revisions  int                 `json:"revisions"`
	Live       int                 `json:"live"`
	Problems   []string            `json:"problems,omitempty"`
	Conflicts  []string            `json:"conflicts,omitempty"`
	Duplicates map[string][]string `json:"duplicates,omitempty"`
}

// PasswdParams replace the passphrase slot used to unlock with a new one.
type PasswdParams struct {
	Vault      string `json:"vault,omitempty"`
	Passphrase []byte `json:"passphrase"`
}

// RotateParams rotate a vault's master key. The new key opens with the
// passphrase given (the current one, or a new one), a new recovery key if
// asked, and every current recipient slot except those in Drop.
type RotateParams struct {
	Vault      string   `json:"vault,omitempty"`
	Passphrase []byte   `json:"passphrase"`
	Recovery   bool     `json:"recovery,omitempty"`
	Drop       []string `json:"drop,omitempty"` // recipient slot IDs to cut off
}

// RotateResult is the new epoch's keyslots.
type RotateResult struct {
	Epoch       uint32     `json:"epoch"`
	Slots       []SlotInfo `json:"slots"`
	RecoveryKey string     `json:"recovery_key,omitempty"`
}

// SlotInfo describes a keyslot. RecoveryKey is set only in the answer to
// adding a recovery slot.
type SlotInfo struct {
	ID          string    `json:"id"`
	Type        string    `json:"type"`
	Label       string    `json:"label,omitempty"`
	Created     time.Time `json:"created"`
	Detail      string    `json:"detail,omitempty"`
	Recipient   string    `json:"recipient,omitempty"`
	RecoveryKey string    `json:"recovery_key,omitempty"`
}

// SlotAddParams add a keyslot. Secret is the passphrase (passphrase), the
// keyfile's contents (keyfile) or the recipient text (recipient); recovery
// slots take nothing.
type SlotAddParams struct {
	Vault  string `json:"vault,omitempty"`
	Type   string `json:"type"`
	Label  string `json:"label,omitempty"`
	Secret []byte `json:"secret,omitempty"`
}

// SlotRemoveParams remove a keyslot.
type SlotRemoveParams struct {
	Vault string `json:"vault,omitempty"`
	ID    string `json:"id"`
}

// Item is an item's contents; see svcore.Item.
type Item struct {
	Kind   string            `json:"kind"`
	Name   string            `json:"name"`
	Label  string            `json:"label,omitempty"`
	Attrs  map[string]string `json:"attrs,omitempty"`
	Tags   []string          `json:"tags,omitempty"`
	Fields []Field           `json:"fields,omitempty"`

	// Files describe the item's attachments; their contents come from
	// file.get. They are read-only here: item.put keeps an item's files as
	// they are, and file.attach and file.remove change them.
	Files []FileInfo `json:"files,omitempty"`
}

// Field is one named value of an item.
type Field struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value []byte `json:"value,omitempty"`
}

// Entry is an item as stored.
type Entry struct {
	ID        string    `json:"id"`
	Rev       string    `json:"rev"`
	Time      time.Time `json:"time"`
	Device    string    `json:"device,omitempty"`
	Deleted   bool      `json:"deleted,omitempty"`
	Conflicts []string  `json:"conflicts,omitempty"`
	Item      Item      `json:"item"`
}

// ItemRef names an item.
type ItemRef struct {
	Vault string `json:"vault,omitempty"`
	Name  string `json:"name"`
}

// ListParams list items whose names start with Prefix.
type ListParams struct {
	Vault  string `json:"vault,omitempty"`
	Prefix string `json:"prefix,omitempty"`
}

// PutParams store an item under its name.
type PutParams struct {
	Vault string `json:"vault,omitempty"`
	Item  Item   `json:"item"`
}

// RenameParams rename an item.
type RenameParams struct {
	Vault string `json:"vault,omitempty"`
	From  string `json:"from"`
	To    string `json:"to"`
}

// Grant is a remembered decision about a program.
type Grant struct {
	ID       string    `json:"id"`
	Vault    string    `json:"vault"`
	Program  string    `json:"program"` // as shown to people
	Identity string    `json:"identity"`
	Item     string    `json:"item,omitempty"` // "" for the whole vault
	Ops      []string  `json:"ops"`
	Decision string    `json:"decision"` // allow-until-lock, allow-always, deny-always, ...
	Created  time.Time `json:"created"`
	Scope    string    `json:"scope"` // "session" (until lock) or "stored"
}

// GrantAddParams decide about a program ahead of time: Program is its path
// (or flatpak:<app>, snap:<name>), Item an item name ("" for the whole
// vault) or Contacts the vault's contacts, Decision allow-always,
// allow-until-lock or deny-always.
type GrantAddParams struct {
	Vault    string   `json:"vault,omitempty"`
	Program  string   `json:"program"`
	Item     string   `json:"item,omitempty"`
	Contacts bool     `json:"contacts,omitempty"` // the decision is about the vault's contacts, not an item
	Ops      []string `json:"ops,omitempty"`      // default: read
	Decision string   `json:"decision"`
}

// GrantRef names a grant to revoke.
type GrantRef struct {
	Vault string `json:"vault,omitempty"`
	ID    string `json:"id"`
}

// AuditParams ask for the newest Limit entries of a vault's audit log.
type AuditParams struct {
	Vault string `json:"vault,omitempty"`
	Limit int    `json:"limit,omitempty"`
}

// AuditEntry is one access decision.
type AuditEntry struct {
	Time    time.Time `json:"time"`
	Program string    `json:"program"`
	PID     int       `json:"pid,omitempty"`
	Op      string    `json:"op"`
	Item    string    `json:"item,omitempty"`
	Outcome string    `json:"outcome"` // allowed, denied, canceled, failed
	Reason  string    `json:"reason,omitempty"`
}

// PromptRegisterParams register this connection as the session's prompter
// (secretvault-tui-prompt --agent), used when the requesting program cannot
// prompt itself.
type PromptRegisterParams struct {
	Terminal string `json:"terminal,omitempty"` // for display: which terminal answers
}

// Prompt kinds.
const (
	PromptPassphrase    = "passphrase"     // ask for an existing passphrase
	PromptNewPassphrase = "new-passphrase" // ask twice for a new one
	PromptChoose        = "choose"         // pick one of Choices
)

// Consent choices offered for a program's request.
const (
	ChoiceOnce   = "once"
	ChoiceLock   = "until-lock"
	ChoiceAlways = "always"
	ChoiceDeny   = "deny"
)

// PromptAsk is a question the daemon wants put to the person.
type PromptAsk struct {
	Kind        string   `json:"kind"`
	Title       string   `json:"title"`
	Description string   `json:"description"`
	Prompt      string   `json:"prompt,omitempty"`
	Choices     []Choice `json:"choices,omitempty"`
	Error       string   `json:"error,omitempty"` // why a previous attempt failed
}

// Choice is one answer to a PromptChoose.
type Choice struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// PromptAnswer is the person's answer.
type PromptAnswer struct {
	Secret   []byte `json:"secret,omitempty"`
	Choice   string `json:"choice,omitempty"`
	Canceled bool   `json:"canceled,omitempty"`
}

// VaultEvent is the payload of the vault notifications.
type VaultEvent struct {
	Vault string `json:"vault"`
	Item  string `json:"item,omitempty"`
}

// MVaultLogin sets a vault to open at login, or not.
const MVaultLogin = "vault.login" // VaultLoginParams -> VaultInfo

// VaultLoginParams turn opening a vault at login on or off.
type VaultLoginParams struct {
	Vault string `json:"vault,omitempty"`
	On    bool   `json:"on"`
}
