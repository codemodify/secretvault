package svdbus

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
)

// DefaultSystemBusAddress is the system bus when DBUS_SYSTEM_BUS_ADDRESS is
// not set.
const DefaultSystemBusAddress = "unix:path=/run/dbus/system_bus_socket"

// Address is one server address: a transport and its parameters, as in
// unix:path=/run/user/1000/bus,guid=... Values are held unescaped.
type Address struct {
	Transport string
	Params    map[string]string
}

// ParseAddresses parses a D-Bus address string: one or more addresses
// separated by ';', each a transport name, ':', and comma-separated
// key=value pairs whose values are %-escaped. Empty entries are skipped.
func ParseAddresses(s string) ([]Address, error) {
	var out []Address
	for _, part := range strings.Split(s, ";") {
		if part == "" {
			continue
		}
		a, err := parseAddress(part)
		if err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		return nil, invalidf("empty D-Bus address")
	}
	return out, nil
}

func parseAddress(s string) (Address, error) {
	transport, rest, ok := strings.Cut(s, ":")
	if !ok || transport == "" {
		return Address{}, invalidf("address %.80q has no transport", s)
	}
	a := Address{Transport: transport, Params: map[string]string{}}
	if rest == "" {
		return a, nil
	}
	for _, kv := range strings.Split(rest, ",") {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return Address{}, invalidf("address %.80q has a malformed key=value pair", s)
		}
		if _, dup := a.Params[k]; dup {
			return Address{}, invalidf("address %.80q repeats the key %q", s, k)
		}
		uv, err := unescapeAddressValue(v)
		if err != nil {
			return Address{}, err
		}
		a.Params[k] = uv
	}
	return a, nil
}

// optionallyEscaped reports whether a byte may appear in an address value
// unescaped: [-0-9A-Za-z_/.\*].
func optionallyEscaped(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' ||
		c == '-' || c == '_' || c == '/' || c == '.' || c == '\\' || c == '*'
}

func unescapeAddressValue(v string) (string, error) {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '%':
			if i+2 >= len(v) {
				return "", invalidf("address value %.80q ends inside an escape", v)
			}
			hi, ok1 := unhex(v[i+1])
			lo, ok2 := unhex(v[i+2])
			if !ok1 || !ok2 {
				return "", invalidf("address value %.80q has a malformed escape", v)
			}
			b.WriteByte(hi<<4 | lo)
			i += 2
		case optionallyEscaped(c):
			b.WriteByte(c)
		default:
			return "", invalidf("address value %.80q has %q unescaped", v, c)
		}
	}
	return b.String(), nil
}

func unhex(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

func escapeAddressValue(v string) string {
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		if optionallyEscaped(c) {
			b.WriteByte(c)
		} else {
			fmt.Fprintf(&b, "%%%02x", c)
		}
	}
	return b.String()
}

// String formats the address with its keys sorted and its values escaped.
func (a Address) String() string {
	keys := make([]string, 0, len(a.Params))
	for k := range a.Params {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var b strings.Builder
	b.WriteString(a.Transport)
	b.WriteByte(':')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(k)
		b.WriteByte('=')
		b.WriteString(escapeAddressValue(a.Params[k]))
	}
	return b.String()
}

// unixSocket returns the socket a connectable unix (or launchd) address
// names, in the form net.Dial takes: a path, or "@name" for Linux's
// abstract namespace.
func (a Address) unixSocket() (string, error) {
	switch a.Transport {
	case "unix":
	case "launchd":
		env := a.Params["env"]
		if env == "" {
			return "", invalidf("launchd address without env=")
		}
		p := os.Getenv(env)
		if p == "" {
			return "", fmt.Errorf("%w: launchd address names $%s, which is not set", ErrInvalid, env)
		}
		return p, nil
	default:
		return "", fmt.Errorf("%w: transport %q", ErrUnsupported, a.Transport)
	}
	var set []string
	for _, k := range []string{"path", "abstract", "runtime", "tmpdir", "dir"} {
		if _, ok := a.Params[k]; ok {
			set = append(set, k)
		}
	}
	if len(set) != 1 {
		return "", invalidf("unix address needs exactly one of path, abstract or runtime, not %q", set)
	}
	switch set[0] {
	case "path":
		p := a.Params["path"]
		if p == "" {
			return "", invalidf("unix address with an empty path")
		}
		if strings.HasPrefix(p, "@") {
			p = "./" + p // a file, not the abstract namespace
		}
		return p, nil
	case "abstract":
		if runtime.GOOS != "linux" && runtime.GOOS != "android" {
			return "", fmt.Errorf("%w: abstract sockets on %s", ErrUnsupported, runtime.GOOS)
		}
		return "@" + a.Params["abstract"], nil
	case "runtime":
		if a.Params["runtime"] != "yes" {
			return "", invalidf("unix address with runtime=%q", a.Params["runtime"])
		}
		dir := os.Getenv("XDG_RUNTIME_DIR")
		if dir == "" {
			return "", invalidf("unix:runtime=yes without XDG_RUNTIME_DIR")
		}
		return filepath.Join(dir, "bus"), nil
	}
	return "", invalidf("unix:%s= is for listening, not connecting", set[0])
}

// SessionBusAddress returns the session bus address: DBUS_SESSION_BUS_ADDRESS,
// or else unix:path=$XDG_RUNTIME_DIR/bus when that socket exists.
func SessionBusAddress() (string, error) {
	if a := os.Getenv("DBUS_SESSION_BUS_ADDRESS"); a != "" {
		return a, nil
	}
	if dir := os.Getenv("XDG_RUNTIME_DIR"); dir != "" {
		p := filepath.Join(dir, "bus")
		if fi, err := os.Stat(p); err == nil && fi.Mode()&os.ModeSocket != 0 {
			return Address{Transport: "unix", Params: map[string]string{"path": p}}.String(), nil
		}
	}
	return "", errors.New("svdbus: no session bus: DBUS_SESSION_BUS_ADDRESS is not set and $XDG_RUNTIME_DIR/bus does not exist")
}

// SystemBusAddress returns the system bus address: DBUS_SYSTEM_BUS_ADDRESS,
// or else DefaultSystemBusAddress.
func SystemBusAddress() string {
	if a := os.Getenv("DBUS_SYSTEM_BUS_ADDRESS"); a != "" {
		return a
	}
	return DefaultSystemBusAddress
}
