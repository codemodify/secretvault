package svops

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/codemodify/secretvault/svrpc"
)

// The host daemon (secretvaultd --host) is set up by root. Its identity is
// made here, on files, before the service is installed, and systemd-creds
// writes where the hardened service cannot. The rest (allow, deny, ls,
// status, audit) is the host daemon's, on its admin socket.

// HostInitOptions say how to make the host identity.
type HostInitOptions struct {
	Suite     string // "modern" or "nist"
	Seal      bool   // seal it with systemd-creds instead of writing it in the clear
	Out       string // the plain identity's file (svrpc.HostIdentityFile() when "")
	Credstore string // with Seal: the sealed identity's file (svrpc.HostCredstore, usually)
	PCRs      string // with Seal: also bind it to these TPM2 PCRs
	// SystemdCreds runs systemd-creds with stdin (exec when nil; tests
	// stand in, so nothing touches the system).
	SystemdCreds func(stdin []byte, args ...string) ([]byte, error)
}

// HostInitResult says what was made.
type HostInitResult struct {
	Recipient string // which vaults are shared to
	Path      string // where the identity is: the sealed credential, or the plain file
	Sealed    bool
}

// HostInit makes the host identity, sealed or in a root-only file; it
// never replaces one.
func HostInit(o HostInitOptions) (*HostInitResult, error) {
	if o.Out == "" {
		o.Out = svrpc.HostIdentityFile()
	}
	rcpt, text, err := NewIdentity(o.Suite, "host identity")
	if err != nil {
		return nil, err
	}
	defer clear(text)
	if o.Seal {
		if _, err := os.Stat(o.Credstore); err == nil {
			return nil, fmt.Errorf("there is a sealed host identity at %s already: remove it first to make a new one (vaults shared to the old one then need sharing again)", o.Credstore)
		}
		if err := os.MkdirAll(filepath.Dir(o.Credstore), 0o700); err != nil {
			return nil, err
		}
		cargs := []string{"encrypt", "--name=" + svrpc.HostIdentityCredential}
		if o.PCRs != "" {
			cargs = append(cargs, "--tpm2-pcrs="+o.PCRs)
		}
		cargs = append(cargs, "-", o.Credstore)
		run := o.SystemdCreds
		if run == nil {
			run = func(stdin []byte, args ...string) ([]byte, error) {
				cmd := exec.Command("systemd-creds", args...)
				cmd.Stdin = bytes.NewReader(stdin)
				return cmd.CombinedOutput()
			}
		}
		if msg, err := run(text, cargs...); err != nil {
			return nil, fmt.Errorf("systemd-creds: %v: %s", err, strings.TrimSpace(string(msg)))
		}
		return &HostInitResult{Recipient: rcpt, Path: o.Credstore, Sealed: true}, nil
	}
	if err := os.MkdirAll(filepath.Dir(o.Out), 0o700); err != nil {
		return nil, err
	}
	if err := WriteNew(o.Out, text); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, fmt.Errorf("there is a host identity at %s already: remove it first to make a new one (vaults shared to the old one then need sharing again)", o.Out)
		}
		return nil, err
	}
	return &HostInitResult{Recipient: rcpt, Path: o.Out}, nil
}
