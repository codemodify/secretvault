package svage

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
)

// Plugin is the plugin's side of the protocol: what a program named
// age-plugin-NAME runs when age starts it. It turns the data inside the
// plugin's identities and recipients into ordinary Identity and Recipient
// values, and does the rest.
type Plugin struct {
	// Name is the plugin's name, the NAME in age-plugin-NAME.
	Name string

	// Identity makes an identity of the data in an AGE-PLUGIN-NAME-1...
	// string, for identity-v1. An error here says the identity itself is
	// unusable; errors from its Unwrap are reported per file.
	Identity func(data []byte) (Identity, error)

	// Recipient makes a recipient of the data in an age1NAME1... string,
	// for recipient-v1. Nil refuses such recipients.
	Recipient func(data []byte) (Recipient, error)

	// IdentityAsRecipient makes the recipient that is an identity's
	// public half, for recipient-v1 (age -e -i IDENTITY). Nil refuses.
	IdentityAsRecipient func(data []byte) (Recipient, error)
}

// Serve runs the state machine sm (PluginIdentityV1 or PluginRecipientV1)
// with the client on in and out. A returned error is a protocol failure,
// for the plugin to report on stderr and exit non-zero; problems with a
// particular identity, recipient or file are told to the client inside
// the protocol and are not errors here.
func (p *Plugin) Serve(sm string, in io.Reader, out io.Writer) error {
	c := newPluginConn(in, out)
	switch sm {
	case PluginIdentityV1:
		if p.Identity == nil {
			return errors.New("identity-v1 is not supported")
		}
		return p.identityV1(c)
	case PluginRecipientV1:
		if p.Recipient == nil && p.IdentityAsRecipient == nil {
			return errors.New("recipient-v1 is not supported")
		}
		return p.recipientV1(c)
	}
	return fmt.Errorf("unknown state machine %q", sm)
}

// sendError reports a problem to the client, which acknowledges it.
func (p *Plugin) sendError(c *pluginConn, err error, args ...string) error {
	if werr := c.write("error", []byte(err.Error()), args...); werr != nil {
		return werr
	}
	return c.expect("ok")
}

func (p *Plugin) identityV1(c *pluginConn) error {
	var idStrings []string
	var files [][]*Stanza
	for done := false; !done; {
		s, err := c.read()
		if err != nil {
			return fmt.Errorf("reading the client's commands: %v", err)
		}
		switch s.Type {
		case "add-identity":
			if err := shape(s, 1, false); err != nil {
				return err
			}
			idStrings = append(idStrings, s.Args[0])
		case "recipient-stanza":
			if len(s.Args) < 2 {
				return errors.New("recipient-stanza: too few arguments")
			}
			i, err := parseIndex(s.Args[0])
			if err != nil {
				return fmt.Errorf("recipient-stanza: %v", err)
			}
			st := &Stanza{Type: s.Args[1], Args: s.Args[2:], Body: s.Body}
			switch i {
			case len(files):
				files = append(files, []*Stanza{st})
			case len(files) - 1:
				files[i] = append(files[i], st)
			default:
				return fmt.Errorf("recipient-stanza: file %d out of order", i)
			}
		case "done":
			if err := shape(s, 0, false); err != nil {
				return err
			}
			done = true
		}
		// Anything else is grease, or a command from a later version.
	}
	if len(idStrings) == 0 {
		return errors.New("no identities given")
	}

	// Every identity must be usable before any is used.
	var ids []Identity
	bad := false
	for i, s := range idStrings {
		id, err := p.parseIdentity(s)
		if err != nil {
			bad = true
			if err := p.sendError(c, err, "identity", strconv.Itoa(i)); err != nil {
				return err
			}
			continue
		}
		ids = append(ids, id)
	}
	if bad {
		return c.write("done", nil)
	}

	for i, stanzas := range files {
		for k, id := range ids {
			fileKey, err := id.Unwrap(stanzas)
			if errors.Is(err, ErrIncorrectIdentity) {
				continue
			}
			var se *StanzaError
			switch {
			case errors.As(err, &se):
				err = p.sendError(c, se, "stanza", strconv.Itoa(i), strconv.Itoa(se.Index))
			case err != nil:
				err = p.sendError(c, err, "identity", strconv.Itoa(k))
			default:
				err = c.write("file-key", fileKey, strconv.Itoa(i))
				clear(fileKey)
				if err == nil {
					err = c.expect("ok")
				}
			}
			if err != nil {
				return err
			}
			break
		}
	}
	return c.write("done", nil)
}

func (p *Plugin) parseIdentity(s string) (Identity, error) {
	name, data, err := ParsePluginIdentity(s)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if name != strings.ToLower(p.Name) {
		return nil, fmt.Errorf("an identity for plugin %q, not %q", name, p.Name)
	}
	return p.Identity(data)
}

func (p *Plugin) recipientV1(c *pluginConn) error {
	var rcptStrings, idStrings []string
	var fileKeys [][]byte
	defer func() {
		for _, k := range fileKeys {
			clear(k)
		}
	}()
	labelsOK := false
	for done := false; !done; {
		s, err := c.read()
		if err != nil {
			return fmt.Errorf("reading the client's commands: %v", err)
		}
		switch s.Type {
		case "add-recipient", "add-identity":
			if err := shape(s, 1, false); err != nil {
				return err
			}
			if s.Type == "add-recipient" {
				rcptStrings = append(rcptStrings, s.Args[0])
			} else {
				idStrings = append(idStrings, s.Args[0])
			}
		case "wrap-file-key":
			if err := shape(s, 0, true); err != nil {
				return err
			}
			if len(s.Body) != FileKeySize {
				return fmt.Errorf("wrap-file-key: a file key of %d bytes", len(s.Body))
			}
			fileKeys = append(fileKeys, s.Body)
		case "extension-labels":
			if err := shape(s, 0, false); err != nil {
				return err
			}
			labelsOK = true
		case "done":
			if err := shape(s, 0, false); err != nil {
				return err
			}
			done = true
		}
	}
	if len(rcptStrings)+len(idStrings) == 0 {
		return errors.New("no recipients or identities given")
	}
	if len(fileKeys) == 0 {
		return errors.New("no file keys given")
	}

	// Resolve everything, then wrap everything; only if all of it works
	// does the client see a single stanza.
	type target struct {
		kind  string // "recipient" or "identity"
		index int
		r     Recipient
	}
	var targets []target
	for i, s := range rcptStrings {
		r, err := p.parseRecipient(s)
		if err != nil {
			return p.fail(c, err, "recipient", i)
		}
		targets = append(targets, target{"recipient", i, r})
	}
	for i, s := range idStrings {
		r, err := p.parseIdentityAsRecipient(s)
		if err != nil {
			return p.fail(c, err, "identity", i)
		}
		targets = append(targets, target{"identity", i, r})
	}
	stanzas := make([][]*Stanza, len(fileKeys))
	var labels []string
	for i, fk := range fileKeys {
		for j, t := range targets {
			ss, ll, err := wrap(t.r, fk)
			if err == nil && len(ss) == 0 {
				err = errors.New("no stanza made")
			}
			if err != nil {
				return p.fail(c, err, t.kind, t.index)
			}
			ll = slices.Clone(ll)
			slices.Sort(ll)
			if i == 0 && j == 0 {
				labels = ll
			} else if !slices.Equal(labels, ll) {
				return p.fail(c, incompatible(labels, ll), t.kind, t.index)
			}
			stanzas[i] = append(stanzas[i], ss...)
		}
	}

	if labelsOK {
		if err := c.write("labels", nil, labels...); err != nil {
			return err
		}
		if err := c.expect("ok"); err != nil {
			return err
		}
	}
	for i, ss := range stanzas {
		for _, s := range ss {
			if err := c.write("recipient-stanza", s.Body, append([]string{strconv.Itoa(i), s.Type}, s.Args...)...); err != nil {
				return err
			}
			if err := c.expect("ok"); err != nil {
				return err
			}
		}
	}
	return c.write("done", nil)
}

// fail reports an error about one recipient or identity and ends the
// phase.
func (p *Plugin) fail(c *pluginConn, err error, kind string, index int) error {
	if err := p.sendError(c, err, kind, strconv.Itoa(index)); err != nil {
		return err
	}
	return c.write("done", nil)
}

func (p *Plugin) parseRecipient(s string) (Recipient, error) {
	name, data, err := ParsePluginRecipient(s)
	if err != nil {
		return nil, err
	}
	if name != strings.ToLower(p.Name) {
		return nil, fmt.Errorf("a recipient for plugin %q, not %q", name, p.Name)
	}
	if p.Recipient == nil {
		return nil, fmt.Errorf("plugin %q takes no recipients of its own", p.Name)
	}
	return p.Recipient(data)
}

func (p *Plugin) parseIdentityAsRecipient(s string) (Recipient, error) {
	name, data, err := ParsePluginIdentity(s)
	if err != nil {
		return nil, err
	}
	defer clear(data)
	if name != strings.ToLower(p.Name) {
		return nil, fmt.Errorf("an identity for plugin %q, not %q", name, p.Name)
	}
	if p.IdentityAsRecipient == nil {
		return nil, fmt.Errorf("plugin %q cannot encrypt to its identities", p.Name)
	}
	return p.IdentityAsRecipient(data)
}
