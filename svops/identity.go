package svops

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
)

// Identities (a person's, a device's, a server's), the recipients that
// keyslots and shares are made for, and keyfiles.

// NewIdentity makes an identity of a cipher suite ("modern" or "nist")
// and returns its recipient and the identity file's text, headed
// "# secretvault <what>, created ...". The caller clears the text.
func NewIdentity(suiteName, what string) (recipient string, file []byte, err error) {
	suite, err := svcrypto.ParseSuite(suiteName)
	if err != nil {
		return "", nil, err
	}
	id, err := suite.NewIdentity()
	if err != nil {
		return "", nil, err
	}
	priv, err := id.Bytes()
	if err != nil {
		return "", nil, err
	}
	defer clear(priv)
	rcpt := svformat.EncodeRecipient(suite, id.Recipient())
	file = []byte(fmt.Sprintf("# secretvault %s, created %s\n# recipient: %s\n%s\n",
		what, time.Now().UTC().Format(time.RFC3339), rcpt, svformat.EncodeIdentity(suite, priv)))
	return rcpt, file, nil
}

// ReadIdentity reads the first identity in an identity file.
func ReadIdentity(path string) (*svcrypto.Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		suite, priv, err := svformat.ParseIdentity(line)
		if err != nil {
			return nil, err
		}
		defer clear(priv)
		return suite.ParseIdentity(priv)
	}
	return nil, fmt.Errorf("%s holds no identity", path)
}

// IdentityRecipient is the recipient of the identity in a file.
func IdentityRecipient(path string) (string, error) {
	id, err := ReadIdentity(path)
	if err != nil {
		return "", err
	}
	return svformat.EncodeRecipient(id.Suite(), id.Recipient()), nil
}

// RecipientArg reads a recipient given as text, as a file holding one, or
// as an identity file (whose public half is the recipient), and returns
// its text form.
func RecipientArg(arg string) (string, error) {
	if suite, pub, err := svformat.ParseRecipient(arg); err == nil {
		return svformat.EncodeRecipient(suite, pub), nil
	}
	b, err := os.ReadFile(arg)
	if err != nil {
		return "", fmt.Errorf("%q is neither a recipient nor a readable file", arg)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if suite, pub, err := svformat.ParseRecipient(line); err == nil {
			return svformat.EncodeRecipient(suite, pub), nil
		}
	}
	clear(b)
	id, err := ReadIdentity(arg)
	if err != nil {
		return "", fmt.Errorf("%s holds no recipient or identity", arg)
	}
	return svformat.EncodeRecipient(id.Suite(), id.Recipient()), nil
}

// CreateKeyfile writes a new keyfile: 64 random bytes, mode 0600, never
// over an existing file.
func CreateKeyfile(path string) error {
	return WriteNew(path, svcrypto.RandomBytes(64))
}
