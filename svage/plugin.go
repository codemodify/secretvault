package svage

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
)

// The age plugin protocol (c2sp.org/age-plugin). A plugin NAME is a
// program age-plugin-NAME that age runs with --age-plugin=identity-v1 to
// unwrap file keys, or --age-plugin=recipient-v1 to wrap them. Its
// identities are AGE-PLUGIN-NAME-1... and its recipients age1NAME1...,
// Bech32 around data only the plugin interprets. Client and plugin talk
// over the plugin's stdin and stdout in stanzas, framed exactly like the
// header's:
//
//	-> add-identity AGE-PLUGIN-SECRETVAULT-1...
//
//	-> recipient-stanza 0 X25519 ajtqAvDEkVNr2B7zUOtq2mAQXDSBlNrVAuM/dKb5sT4
//	U+hKlJ4isweJ9PKG7pgscmG3cPASLgTw7SOBpbZ8x2U
//	-> done
//
// in phases, each ended by "done": first the client says what it has,
// then the plugin answers, asking the client for help (a message to show,
// a PIN to ask for) as it goes. Commands a side does not know are ignored
// in the client's phase and answered "unsupported" in the plugin's, so
// either side may add "grease" (random commands) to keep the other honest.

// Protocol state machines.
const (
	PluginIdentityV1  = "identity-v1"
	PluginRecipientV1 = "recipient-v1"
)

// maxPluginStanza bounds one stanza of the plugin protocol.
const maxPluginStanza = 2 << 20

// validPluginName reports whether name may name a plugin: letters,
// digits, and - _ . +.
func validPluginName(name string) bool {
	if name == "" {
		return false
	}
	for _, c := range name {
		if !(c < 128 && (unicode.IsLetter(c) || unicode.IsDigit(c)) || strings.ContainsRune("-_.+", c)) {
			return false
		}
	}
	return true
}

// EncodePluginIdentity writes the AGE-PLUGIN-NAME-1... identity holding
// data for the plugin name.
func EncodePluginIdentity(name string, data []byte) (string, error) {
	if !validPluginName(name) {
		return "", fmt.Errorf("svage: invalid plugin name %q", name)
	}
	return bech32Encode("AGE-PLUGIN-"+strings.ToUpper(name)+"-", data)
}

// ParsePluginIdentity reads an AGE-PLUGIN-NAME-1... identity, returning
// the plugin's name (lowercase) and the identity's data.
func ParsePluginIdentity(s string) (name string, data []byte, err error) {
	hrp, data, err := bech32Decode(s)
	if err != nil {
		return "", nil, fmt.Errorf("svage: malformed plugin identity: %v", err)
	}
	name, ok := strings.CutPrefix(hrp, "AGE-PLUGIN-")
	if name, ok2 := strings.CutSuffix(name, "-"); ok && ok2 && validPluginName(name) {
		return strings.ToLower(name), data, nil
	}
	return "", nil, errors.New("svage: not a plugin identity")
}

// EncodePluginRecipient writes the age1NAME1... recipient holding data
// for the plugin name.
func EncodePluginRecipient(name string, data []byte) (string, error) {
	if !validPluginName(name) {
		return "", fmt.Errorf("svage: invalid plugin name %q", name)
	}
	return bech32Encode("age1"+strings.ToLower(name), data)
}

// ParsePluginRecipient reads an age1NAME1... recipient, returning the
// plugin's name and the recipient's data.
func ParsePluginRecipient(s string) (name string, data []byte, err error) {
	hrp, data, err := bech32Decode(s)
	if err != nil {
		return "", nil, fmt.Errorf("svage: malformed plugin recipient: %v", err)
	}
	name, ok := strings.CutPrefix(hrp, "age1")
	if !ok || !validPluginName(name) {
		return "", nil, errors.New("svage: not a plugin recipient")
	}
	return name, data, nil
}

// pluginConn frames the protocol's stanzas over a pair of streams.
type pluginConn struct {
	lr *lineReader
	w  io.Writer
}

func newPluginConn(r io.Reader, w io.Writer) *pluginConn {
	return &pluginConn{lr: &lineReader{r: bufio.NewReader(r)}, w: w}
}

func (c *pluginConn) read() (*Stanza, error) {
	c.lr.budget = maxPluginStanza
	// A recipient-stanza carries a header stanza behind two arguments.
	s, err := readStanza(c.lr, MaxStanzaArgs+2)
	if errors.Is(err, errBudget) {
		err = errors.New("a protocol message is too large")
	}
	return s, err
}

func (c *pluginConn) write(typ string, body []byte, args ...string) error {
	var b bytes.Buffer
	if err := (&Stanza{Type: typ, Args: args, Body: body}).marshal(&b); err != nil {
		return err
	}
	_, err := c.w.Write(b.Bytes())
	clear(b.Bytes())
	return err
}

// expect reads the other side's answer, which must be a bare typ: no
// arguments, no body.
func (c *pluginConn) expect(typ string) error {
	s, err := c.read()
	if err != nil {
		return err
	}
	if s.Type != typ || len(s.Args) != 0 || len(s.Body) != 0 {
		return fmt.Errorf("expected %q, got %q", typ, s.Type)
	}
	return nil
}

// shape checks a command's shape: n arguments, and a body only if
// allowed.
func shape(s *Stanza, n int, body bool) error {
	if len(s.Args) != n {
		return fmt.Errorf("%s: %d arguments, want %d", s.Type, len(s.Args), n)
	}
	if !body && len(s.Body) != 0 {
		return fmt.Errorf("%s: unexpected body", s.Type)
	}
	return nil
}

// parseIndex reads a file index: a decimal number, no sign, no leading
// zeros.
func parseIndex(s string) (int, error) {
	if s == "" || (len(s) > 1 && s[0] == '0') || len(s) > 9 {
		return 0, fmt.Errorf("invalid index %q", s)
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, fmt.Errorf("invalid index %q", s)
		}
	}
	return strconv.Atoi(s)
}

// printable makes text from the other side safe to show on a terminal.
func printable(b []byte) string {
	s := strings.ToValidUTF8(string(b), "?")
	s = strings.Map(func(r rune) rune {
		if r == '\n' || r == '\t' || unicode.IsPrint(r) {
			return r
		}
		return '?'
	}, s)
	if len(s) > 1024 {
		s = s[:1024] + "..."
	}
	return s
}
