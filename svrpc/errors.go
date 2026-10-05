package svrpc

import (
	"encoding/json"
	"errors"
	"fmt"
)

// Error is a JSON-RPC error object. It is also a Go error, so a client can
// test for one with errors.As, or for a code with Is (below).
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

func (e *Error) Error() string { return e.Message }

// Is lets errors.Is(err, svrpc.ErrLocked) and friends match by code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// Standard JSON-RPC codes, and secretvault's own (-32000 and below).
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603

	CodeFailed     = -32000 // anything without a more specific code
	CodeLocked     = -32001 // the vault is locked and could not be unlocked
	CodeDenied     = -32002 // the person (or a remembered decision) said no
	CodeNotFound   = -32003 // no such item, slot, grant, key, ... (a vault has its own code)
	CodeWrongKey   = -32004 // no keyslot accepts the key
	CodeCanceled   = -32005 // the person dismissed a prompt
	CodeExists     = -32006 // it already exists
	CodeNoPrompter = -32007 // a person had to be asked, and there was no way to ask
	CodeNoVault    = -32008 // the vault named (or the default) does not exist, or its folder is missing
)

// Sentinels for errors.Is. Only the code is compared.
var (
	ErrLocked     = &Error{Code: CodeLocked, Message: "the vault is locked"}
	ErrDenied     = &Error{Code: CodeDenied, Message: "access denied"}
	ErrNotFound   = &Error{Code: CodeNotFound, Message: "not found"}
	ErrWrongKey   = &Error{Code: CodeWrongKey, Message: "that key does not open this vault"}
	ErrCanceled   = &Error{Code: CodeCanceled, Message: "canceled"}
	ErrExists     = &Error{Code: CodeExists, Message: "already exists"}
	ErrNoPrompter = &Error{Code: CodeNoPrompter, Message: "there is no way to ask you"}
	ErrNoVault    = &Error{Code: CodeNoVault, Message: "there is no such vault"}
)

// Errorf makes an *Error with a code and a formatted message.
func Errorf(code int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// AsError turns any error into the *Error sent to the peer: itself if it
// already is one (or wraps one), else a CodeFailed error with its text.
func AsError(err error) *Error {
	var e *Error
	if errors.As(err, &e) {
		return e
	}
	return &Error{Code: CodeFailed, Message: err.Error()}
}
