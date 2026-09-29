package svdbus

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"sync"
)

// peerIface is org.freedesktop.DBus.Peer, answered on every path.
var peerIface = &Interface{
	Name: peerInterface,
	Methods: []*Method{
		{
			Name:    "Ping",
			Handler: func(ctx context.Context, call *Call) ([]any, error) { return nil, nil },
		},
		{
			Name: "GetMachineId",
			Out:  []Arg{{Name: "machine_uuid", Type: "s"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				id, err := MachineID()
				if err != nil {
					return nil, NewError(ErrorFailed, err.Error())
				}
				return []any{id}, nil
			},
		},
	},
}

var machineID = sync.OnceValues(func() (string, error) {
	for _, p := range []string{"/etc/machine-id", "/var/lib/dbus/machine-id"} {
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		id := strings.TrimSpace(string(b))
		if _, err := hex.DecodeString(id); err == nil && len(id) == 32 {
			return id, nil
		}
	}
	return "", errors.New("svdbus: this machine has no machine ID")
})

// MachineID returns this machine's D-Bus machine ID (/etc/machine-id), as
// org.freedesktop.DBus.Peer.GetMachineId reports it.
func MachineID() (string, error) { return machineID() }
