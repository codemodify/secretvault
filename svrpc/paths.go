package svrpc

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// EnvSocket overrides where secretvaultd listens and clients connect.
const EnvSocket = "SECRETVAULT_SOCK"

// DefaultSocket is secretvaultd's socket for this user:
//
//	$SECRETVAULT_SOCK, if set
//	Linux, BSD  $XDG_RUNTIME_DIR/secretvault/secretvaultd.sock
//	            (else $TMPDIR/secretvault-<uid>/secretvaultd.sock)
//	macOS       $TMPDIR/secretvault-<uid>/secretvaultd.sock ($TMPDIR is per user)
//	Windows     %LOCALAPPDATA%\secretvault\run\secretvaultd.sock (AF_UNIX)
//
// The socket lives in a directory of its own, created 0700, so nobody
// else can put anything at its path.
func DefaultSocket() string {
	if p := os.Getenv(EnvSocket); p != "" {
		return p
	}
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("LOCALAPPDATA"), "secretvault", "run", "secretvaultd.sock")
	}
	if runtime.GOOS != "darwin" {
		if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
			return filepath.Join(dir, "secretvault", "secretvaultd.sock")
		}
	}
	return filepath.Join(os.TempDir(), "secretvault-"+strconv.Itoa(os.Getuid()), "secretvaultd.sock")
}

// SSHAgentSocket is where secretvaultd answers the SSH agent protocol:
// beside its own socket, as ssh-agent.sock. Point SSH_AUTH_SOCK at it.
func SSHAgentSocket() string {
	return filepath.Join(filepath.Dir(DefaultSocket()), "ssh-agent.sock")
}
