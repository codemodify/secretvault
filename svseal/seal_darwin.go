//go:build darwin

package svseal

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// keychain keeps the secret in the login keychain, as a generic password
// of service "secretvault-login" and account name, as hex text; what is
// "sealed" is only a marker naming it. The secret goes to security(1) on
// its standard input, never in its arguments.
type keychain struct{}

func platform() Sealer { return keychain{} }

func (keychain) Name() string { return "the macOS login keychain" }

func (keychain) Available() error {
	if _, err := exec.LookPath("security"); err != nil {
		return fmt.Errorf("%w: security(1) is missing", ErrUnavailable)
	}
	return nil
}

const service = "secretvault-login"

func (keychain) Seal(name string, secret []byte) ([]byte, error) {
	if strings.ContainsAny(name, " \"'\n") {
		return nil, fmt.Errorf("svseal: bad name %q", name)
	}
	cmd := exec.Command("security", "-i")
	line := "add-generic-password -U -s " + service + " -a " + name + " -w " + hex.EncodeToString(secret) + "\n"
	cmd.Stdin = strings.NewReader(line)
	if out, err := cmd.CombinedOutput(); err != nil {
		return nil, fmt.Errorf("svseal: security: %v: %s", err, bytes.TrimSpace(out))
	}
	return []byte("keychain:" + service + "/" + name), nil
}

func (keychain) Unseal(name string, sealed []byte) ([]byte, error) {
	if string(sealed) != "keychain:"+service+"/"+name {
		return nil, errors.New("svseal: not a keychain reference for " + name)
	}
	out, err := exec.Command("security", "find-generic-password", "-s", service, "-a", name, "-w").Output()
	if err != nil {
		return nil, fmt.Errorf("svseal: security: %v", err)
	}
	s := strings.TrimSpace(string(out))
	clear(out)
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, errors.New("svseal: the keychain item is not ours")
	}
	return b, nil
}
