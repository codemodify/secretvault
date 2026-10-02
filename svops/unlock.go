package svops

import (
	"fmt"
	"os"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// KeyFromFile reads a key to present to vault.unlock from a file, by its
// type: svformat.SlotKeyfile (the file's bytes are the key), "identity"
// (an identity file's text), or svformat.SlotPassphrase (a passphrase,
// without its final newline). The caller clears Secret.
func KeyFromFile(typ, path string) (*svrpc.Key, error) {
	switch typ {
	case svformat.SlotKeyfile, "identity":
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		return &svrpc.Key{Type: typ, Secret: b}, nil
	case svformat.SlotPassphrase:
		b, err := ReadSecretFile(path)
		if err != nil {
			return nil, err
		}
		return &svrpc.Key{Type: typ, Secret: b}, nil
	}
	return nil, fmt.Errorf("a %q is not a key read from a file", typ)
}
