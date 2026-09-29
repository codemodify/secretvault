package svage

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

// Text forms: recipients and identities one per line, as age reads them
// from files, with blank lines and lines starting with "#" skipped.

// maxKeyFile bounds a recipients or identities file.
const maxKeyFile = 16 << 20

// ParseRecipient reads one recipient: age1... (X25519), age1pq1...
// (post-quantum), age1tag1... and age1tagpq1... (hardware tags), an SSH
// public key line, or age1NAME1... for the plugin age-plugin-NAME.
func ParseRecipient(s string) (Recipient, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "ssh-") {
		return ParseSSHRecipient(s)
	}
	hrp, _, err := bech32Decode(s)
	if err != nil {
		return nil, fmt.Errorf("svage: %q is not a recipient: %v", shorten([]byte(s)), err)
	}
	var r Recipient
	switch {
	case hrp == "age":
		r, err = ParseX25519Recipient(s)
	case hrp == "age1pq":
		r, err = ParseHybridRecipient(s)
	case hrp == "age1tag", hrp == "age1tagpq":
		r, err = ParseTagRecipient(s)
	case strings.HasPrefix(hrp, "age1") && len(hrp) > 4:
		r, err = NewPluginRecipient(s, nil)
	default:
		err = fmt.Errorf("svage: %q is not a recipient", shorten([]byte(s)))
	}
	if err != nil {
		return nil, err
	}
	return r, nil
}

// ParseIdentity reads one identity: AGE-SECRET-KEY-1... (X25519),
// AGE-SECRET-KEY-PQ-1... (post-quantum), or AGE-PLUGIN-NAME-1... for the
// plugin age-plugin-NAME (which then runs without a user interface; use
// NewPluginIdentity to give it one).
func ParseIdentity(s string) (Identity, error) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "AGE-PLUGIN-") {
		id, err := NewPluginIdentity(s, nil)
		if err != nil {
			return nil, err
		}
		return id, nil
	}
	b := []byte(s)
	defer clear(b)
	return ParseIdentityBytes(b)
}

// ParseIdentityBytes is ParseIdentity for a native identity (X25519 or
// post-quantum) held in memory the caller will wipe: it makes no copy of
// it that it does not wipe itself.
func ParseIdentityBytes(b []byte) (Identity, error) {
	b = bytes.TrimSpace(b)
	var id Identity
	var err error
	switch {
	case bytes.HasPrefix(b, []byte("AGE-SECRET-KEY-PQ-1")):
		id, err = parseHybridIdentity(b)
	case bytes.HasPrefix(b, []byte("AGE-SECRET-KEY-1")):
		id, err = parseX25519Identity(b)
	default:
		err = errors.New("svage: not an X25519 or post-quantum identity")
	}
	if err != nil {
		return nil, err
	}
	return id, nil
}

// ParseRecipients reads recipients, one per line.
func ParseRecipients(r io.Reader) ([]Recipient, error) {
	var out []Recipient
	err := eachLine(r, func(n int, line string) error {
		rc, err := ParseRecipient(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, rc)
		return nil
	})
	if err == nil && len(out) == 0 {
		err = errors.New("svage: no recipients found")
	}
	return out, err
}

// ParseIdentities reads identities, one per line.
func ParseIdentities(r io.Reader) ([]Identity, error) {
	var out []Identity
	err := eachLine(r, func(n int, line string) error {
		id, err := ParseIdentity(line)
		if err != nil {
			return fmt.Errorf("line %d: %w", n, err)
		}
		out = append(out, id)
		return nil
	})
	if err == nil && len(out) == 0 {
		err = errors.New("svage: no identities found")
	}
	return out, err
}

func eachLine(r io.Reader, f func(n int, line string) error) error {
	lr := &io.LimitedReader{R: r, N: maxKeyFile + 1}
	sc := bufio.NewScanner(lr)
	sc.Buffer(make([]byte, 0, 64<<10), maxKeyFile)
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !utf8.ValidString(line) {
			return fmt.Errorf("svage: line %d is not UTF-8", n)
		}
		if err := f(n, line); err != nil {
			return err
		}
	}
	if err := sc.Err(); err != nil {
		return fmt.Errorf("svage: reading keys: %v", err)
	}
	if lr.N == 0 {
		return fmt.Errorf("svage: a key file larger than %d bytes", maxKeyFile)
	}
	return nil
}
