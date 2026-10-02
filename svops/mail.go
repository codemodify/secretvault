package svops

import (
	"io"
	"os"

	"github.com/codemodify/secretvault/svrpc"
)

// Whole mail messages are the daemon's to take apart, check, decrypt and
// build (mail.inspect, mail.compose); here are the files they come from
// and go to.

// ReadMessage reads a message as received (.eml): from path, or from
// stdin when path is "-", up to what one request carries.
func ReadMessage(path string, stdin io.Reader) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(io.LimitReader(stdin, svrpc.MaxMessage/2))
	}
	return os.ReadFile(path)
}

// WriteMessage writes a composed message to path, mode 0600 (it may be
// the plain text of what was encrypted).
func WriteMessage(path string, msg []byte) error { return os.WriteFile(path, msg, 0o600) }
