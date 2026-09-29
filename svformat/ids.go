// Package svformat is the secretvault on-disk format, version 1: the vault
// descriptor, keyslot records, and the revision envelope every stored
// object is written in. It knows the byte layout and which bytes are bound
// into which authentication tag; it holds no keys and keeps no state.
//
// docs/format.md is the prose specification; this package is its
// reference implementation, and the two change together.
package svformat

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
)

// ID names a vault, keyslot, object or device: 16 random bytes, written as
// 32 lowercase hex digits.
type ID [16]byte

// NewID returns a fresh random ID.
func NewID() ID {
	var id ID
	rand.Read(id[:])
	return id
}

// ParseID reads an ID as String writes it.
func ParseID(s string) (ID, error) {
	var id ID
	if len(s) != 2*len(id) {
		return id, fmt.Errorf("svformat: ID %q is not 32 hex digits", s)
	}
	if _, err := hex.Decode(id[:], []byte(s)); err != nil {
		return id, fmt.Errorf("svformat: ID %q: %w", s, err)
	}
	return id, nil
}

func (id ID) String() string { return hex.EncodeToString(id[:]) }

// IsZero reports whether id is unset.
func (id ID) IsZero() bool { return id == ID{} }

func (id ID) MarshalText() ([]byte, error) { return []byte(id.String()), nil }

func (id *ID) UnmarshalText(b []byte) error {
	v, err := ParseID(string(b))
	*id = v
	return err
}

// RevID names one revision of an object: the SHA-256 of the revision's
// complete file. A revision's name is therefore also its checksum, and a
// revision's parents are named by content, so history cannot be rewritten
// without every later name changing.
type RevID [32]byte

// RevIDOf returns the revision ID of a revision file's bytes.
func RevIDOf(file []byte) RevID { return sha256.Sum256(file) }

// ParseRevID reads a RevID as String writes it.
func ParseRevID(s string) (RevID, error) {
	var r RevID
	if len(s) != 2*len(r) {
		return r, errors.New("svformat: revision ID is not 64 hex digits")
	}
	_, err := hex.Decode(r[:], []byte(s))
	return r, err
}

func (r RevID) String() string { return hex.EncodeToString(r[:]) }

// Short is the first 12 hex digits, for people.
func (r RevID) Short() string { return r.String()[:12] }

func (r RevID) MarshalText() ([]byte, error) { return []byte(r.String()), nil }

func (r *RevID) UnmarshalText(b []byte) error {
	v, err := ParseRevID(string(b))
	*r = v
	return err
}
