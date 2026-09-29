package svdbus

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// authenticate runs the client side of the SASL handshake on a fresh
// connection: the credentials NUL byte, AUTH EXTERNAL with our user ID
// (the decimal uid, hex-encoded as the mechanism requires), then
// NEGOTIATE_UNIX_FD if wanted, then BEGIN. It returns the server's GUID and
// whether descriptors may be passed.
func authenticate(tr transport, r *msgReader, identity string, wantFDs bool) (guid string, fds bool, err error) {
	send := func(s string) error { return tr.write([]byte(s), nil) }
	if err := send("\x00AUTH EXTERNAL " + hex.EncodeToString([]byte(identity)) + "\r\n"); err != nil {
		return "", false, err
	}
	answeredData := false
	for guid == "" {
		line, err := r.readLine()
		if err != nil {
			return "", false, err
		}
		cmd, arg, _ := strings.Cut(line, " ")
		switch cmd {
		case "OK":
			if len(arg) != 32 {
				return "", false, fmt.Errorf("%w: the bus sent a malformed GUID", ErrAuth)
			}
			if _, err := hex.DecodeString(arg); err != nil {
				return "", false, fmt.Errorf("%w: the bus sent a malformed GUID", ErrAuth)
			}
			guid = arg
		case "DATA":
			// EXTERNAL has nothing more to say than its initial response;
			// a server that still asks gets one empty answer.
			if answeredData {
				return "", false, fmt.Errorf("%w: the bus keeps asking for EXTERNAL data", ErrAuth)
			}
			answeredData = true
			if err := send("DATA\r\n"); err != nil {
				return "", false, err
			}
		case "REJECTED":
			return "", false, fmt.Errorf("%w: the bus refused EXTERNAL (it offers %.80q)", ErrAuth, arg)
		default:
			return "", false, fmt.Errorf("%w: the bus answered %.80q", ErrAuth, line)
		}
	}
	if wantFDs && tr.canPassFDs() {
		if err := send("NEGOTIATE_UNIX_FD\r\n"); err != nil {
			return "", false, err
		}
		line, err := r.readLine()
		if err != nil {
			return "", false, err
		}
		switch {
		case line == "AGREE_UNIX_FD":
			fds = true
		case line == "ERROR" || strings.HasPrefix(line, "ERROR "):
		default:
			return "", false, fmt.Errorf("%w: the bus answered %.80q to NEGOTIATE_UNIX_FD", ErrAuth, line)
		}
	}
	if err := send("BEGIN\r\n"); err != nil {
		return "", false, err
	}
	return guid, fds, nil
}
