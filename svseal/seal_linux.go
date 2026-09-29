//go:build linux

package svseal

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

// systemdCreds seals with systemd-creds' user scope (systemd 256 and
// later): systemd's credential service encrypts for the calling user's
// UID, with the host key and the TPM2 if the machine has one.
type systemdCreds struct{}

func platform() Sealer { return systemdCreds{} }

func (systemdCreds) Name() string { return "systemd-creds (user scope)" }

// run stands in for systemd-creds in tests.
var run = func(stdin []byte, args ...string) ([]byte, error) {
	cmd := exec.Command("systemd-creds", args...)
	cmd.Stdin = bytes.NewReader(stdin)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(errb.String())
		if msg == "" {
			msg = err.Error()
		}
		return nil, errors.New(msg)
	}
	return out.Bytes(), nil
}

func (systemdCreds) Available() error {
	if _, err := exec.LookPath("systemd-creds"); err != nil {
		return fmt.Errorf("%w: systemd-creds is not installed", ErrUnavailable)
	}
	out, err := run(nil, "--help")
	if err != nil || !bytes.Contains(out, []byte("--user")) {
		return fmt.Errorf("%w: this systemd-creds has no --user (systemd 256 or later)", ErrUnavailable)
	}
	return nil
}

func (systemdCreds) Seal(name string, secret []byte) ([]byte, error) {
	out, err := run(secret, "--user", "encrypt", "--name="+name, "-", "-")
	if err != nil {
		return nil, fmt.Errorf("svseal: systemd-creds encrypt: %v", err)
	}
	return out, nil
}

func (systemdCreds) Unseal(name string, sealed []byte) ([]byte, error) {
	out, err := run(sealed, "--user", "decrypt", "--name="+name, "-", "-")
	if err != nil {
		return nil, fmt.Errorf("svseal: systemd-creds decrypt: %v", err)
	}
	return out, nil
}
