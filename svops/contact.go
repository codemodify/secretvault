package svops

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svtrust"
)

// Contacts and the trust store are the daemon's; here is what is shown
// for someone to scan, and what a scanned code is.

// IsContactURI reports whether text is a URI a contact's QR code shows
// (secretvault-contact:, openpgp4fpr:), rather than a file name.
func IsContactURI(s string) bool {
	l := strings.ToLower(s)
	return strings.HasPrefix(l, svtrust.ContactScheme+":") || strings.HasPrefix(l, "openpgp4fpr:")
}

// OwnCard gathers the fingerprints of your own keys, for a QR code
// (svtrust.Card.URI, drawn with svqr): the key items named (OpenPGP or
// SSH keys), else every OpenPGP key in the vault, and the recipients
// given (as text, files, or identity files: RecipientArg). Its name and
// address are the first OpenPGP key's.
func OwnCard(ctx context.Context, cl *secretvault.Client, vault string, items, recipients []string) (*svtrust.Card, error) {
	entries, err := cl.List(ctx, vault, "")
	if err != nil {
		return nil, err
	}
	card := &svtrust.Card{}
	firstUID := ""
	addPGP := func(it svrpc.Item) {
		card.Keys = append(card.Keys, svtrust.CardKey{Type: svtrust.OpenPGP, Fingerprint: it.Attrs[svrpc.PGPFingerprint]})
		if firstUID == "" {
			firstUID = it.Attrs[svrpc.PGPUserID]
		}
	}
	for _, want := range items {
		var found *svrpc.Item
		for i := range entries {
			if entries[i].Item.Name == want {
				found = &entries[i].Item
			}
		}
		switch {
		case found == nil:
			return nil, fmt.Errorf("%s: %w", want, svrpc.ErrNotFound)
		case found.Attrs[svrpc.PGPFingerprint] != "":
			addPGP(*found)
		case found.Kind == "ssh-key":
			fp := found.Attrs["fingerprint"]
			if fp == "" {
				e, err := cl.Get(ctx, vault, want)
				if err != nil {
					return nil, err
				}
				if f, ok := Field(&e.Item, "public_key"); ok {
					if k, err := svtrust.ParseKey(f.Value); err == nil {
						fp = k.Fingerprint
					}
				}
				Wipe(&e.Item)
			}
			if fp == "" {
				return nil, fmt.Errorf("%s has no public key to show", want)
			}
			card.Keys = append(card.Keys, svtrust.CardKey{Type: svtrust.SSH, Fingerprint: fp})
		default:
			return nil, fmt.Errorf("%s is neither an OpenPGP key nor an SSH key", want)
		}
	}
	if len(items) == 0 {
		for _, e := range entries {
			if e.Item.Kind == svrpc.PGPItemKind && e.Item.Attrs[svrpc.PGPFingerprint] != "" {
				addPGP(e.Item)
			}
		}
	}
	for _, r := range recipients {
		text, err := RecipientArg(r)
		if err != nil {
			return nil, err
		}
		k, err := svtrust.ParseKey([]byte(text))
		if err != nil {
			return nil, err
		}
		card.Keys = append(card.Keys, svtrust.CardKey{Type: svtrust.Secretvault, Fingerprint: k.Fingerprint})
	}
	if len(card.Keys) == 0 {
		return nil, errors.New("no keys to show: make one with 'secretvault pgp new', or name them with --key or --recipient")
	}
	name, addr := svtrust.SplitUserID(firstUID)
	card.Name = name
	if addr != "" {
		card.Emails = []string{addr}
	}
	return card, nil
}

// LevelText says a verification level in words.
func LevelText(l string) string {
	if l == "" {
		return "not verified"
	}
	return svtrust.Level(l).String()
}
