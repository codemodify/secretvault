package svage

import (
	"bufio"
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
	switch {
	case hrp == "age":
		return ParseX25519Recipient(s)
	case hrp == "age1pq":
		return ParseHybridRecipient(s)
	case hrp == "age1tag", hrp == "age1tagpq":
		return ParseTagRecipient(s)
	case strings.HasPrefix(hrp, "age1") && len(hrp) > 4:
		return NewPluginRecipient(s, nil)
	}
	return nil, fmt.Errorf("svage: %q is not a recipient", shorten([]byte(s)))
}

// ParseIdentity reads one identity: AGE-SECRET-KEY-1... (X25519),
// AGE-SECRET-KEY-PQ-1... (post-quantum), or AGE-PLUGIN-NAME-1... for the
// plugin age-plugin-NAME (which then runs without a user interface; use
// NewPluginIdentity to give it one).
func ParseIdentity(s string) (Identity, error) {
	s = strings.TrimSpace(s)
	hrp, _, err := bech32Decode(s)
	if err != nil {
		// Nothing of the line in the error: it may be a mistyped key.
		return nil, fmt.Errorf("svage: not an identity: %v", err)
	}
	switch {
	case hrp == "AGE-SECRET-KEY-":
		return ParseX25519Identity(s)
	case hrp == "AGE-SECRET-KEY-PQ-":
		return ParseHybridIdentity(s)
	case strings.HasPrefix(hrp, "AGE-PLUGIN-"):
		return NewPluginIdentity(s, nil)
	}
	return nil, errors.New("svage: not an identity")
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
