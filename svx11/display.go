package svx11

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// Display is a parsed $DISPLAY: [host]:number[.screen].
type Display struct {
	Host   string // "" or "unix" for the local socket
	Number string
}

// ErrNoDisplay is a session without X11.
var ErrNoDisplay = errors.New("svx11: no X display (DISPLAY is not set)")

// ParseDisplay reads a display name ($DISPLAY when s is "").
func ParseDisplay(s string) (Display, error) {
	if s == "" {
		s = os.Getenv("DISPLAY")
	}
	if s == "" {
		return Display{}, ErrNoDisplay
	}
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return Display{}, fmt.Errorf("svx11: DISPLAY=%q has no ':'", s)
	}
	num, _, _ := strings.Cut(s[i+1:], ".")
	if _, err := strconv.Atoi(num); err != nil {
		return Display{}, fmt.Errorf("svx11: DISPLAY=%q has no display number", s)
	}
	return Display{Host: s[:i], Number: num}, nil
}

func (d Display) dial() (net.Conn, error) {
	if d.Host == "" || d.Host == "unix" {
		path := "/tmp/.X11-unix/X" + d.Number
		if runtime.GOOS == "linux" {
			// The abstract socket first, as Xlib does.
			if c, err := net.Dial("unix", "@"+path); err == nil {
				return c, nil
			}
		}
		return net.Dial("unix", path)
	}
	n, _ := strconv.Atoi(d.Number)
	return net.Dial("tcp", net.JoinHostPort(d.Host, strconv.Itoa(6000+n)))
}

// Xauthority families.
const (
	familyInternet = 0
	familyLocal    = 256
	familyWild     = 65535
)

// findCookie reads the MIT-MAGIC-COOKIE-1 for d from $XAUTHORITY (or
// ~/.Xauthority). No entry means connecting without authorisation, which
// a server with host-based access control may still accept.
func findCookie(d Display) (string, []byte) {
	path := os.Getenv("XAUTHORITY")
	if path == "" {
		h, err := os.UserHomeDir()
		if err != nil {
			return "", nil
		}
		path = filepath.Join(h, ".Xauthority")
	}
	f, err := os.Open(path)
	if err != nil {
		return "", nil
	}
	defer f.Close()
	host, _ := os.Hostname()
	local := d.Host == "" || d.Host == "unix"
	readField := func() ([]byte, error) {
		var n [2]byte
		if _, err := io.ReadFull(f, n[:]); err != nil {
			return nil, err
		}
		b := make([]byte, binary.BigEndian.Uint16(n[:]))
		_, err := io.ReadFull(f, b)
		return b, err
	}
	for {
		var fam [2]byte
		if _, err := io.ReadFull(f, fam[:]); err != nil {
			return "", nil
		}
		family := binary.BigEndian.Uint16(fam[:])
		addr, err1 := readField()
		num, err2 := readField()
		name, err3 := readField()
		data, err4 := readField()
		if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
			return "", nil
		}
		if string(name) != "MIT-MAGIC-COOKIE-1" || (len(num) > 0 && string(num) != d.Number) {
			continue
		}
		switch {
		case family == familyWild,
			family == familyLocal && local && string(addr) == host,
			family == familyLocal && !local && string(addr) == d.Host:
			return string(name), data
		}
	}
}
