//go:build linux || freebsd || netbsd || openbsd

package svclip

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/codemodify/secretvault/svwayland"
	"github.com/codemodify/secretvault/svx11"
)

// The text types offered, and the hint clipboard managers honour.
var textTypes = []string{"text/plain;charset=utf-8", "text/plain", "UTF8_STRING", "TEXT", "STRING"}

const hintType = "x-kde-passwordManagerHint"

// copyText uses Wayland data control where the compositor offers it,
// else X11 (native, or XWayland, whose clipboard the desktop bridges).
func copyText(secret []byte, ttl time.Duration, ready func(string)) (bool, error) {
	if os.Getenv("WAYLAND_DISPLAY") != "" || os.Getenv("WAYLAND_SOCKET") != "" {
		cb, err := svwayland.OpenClipboard()
		if err == nil {
			defer cb.Close()
			offers := []svwayland.Offer{{MIME: hintType, Data: []byte("secret")}}
			for _, t := range textTypes {
				offers = append(offers, svwayland.Offer{MIME: t, Data: secret})
			}
			return cb.Serve(offers, ttl, func() { ready("wayland") })
		}
		if !errors.Is(err, svwayland.ErrNoDataControl) || os.Getenv("DISPLAY") == "" {
			return false, fmt.Errorf("%w: %v", ErrUnavailable, err)
		}
	}
	c, err := svx11.Connect()
	if err != nil {
		return false, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer c.Close()
	offers := []svx11.Offer{{Target: hintType, Data: []byte("secret")}}
	for _, t := range textTypes {
		offers = append(offers, svx11.Offer{Target: t, Data: secret})
	}
	return svx11.Serve(c, offers, ttl, func() { ready("x11") })
}

func pasteText() ([]byte, error) {
	if os.Getenv("WAYLAND_DISPLAY") != "" {
		if cb, err := svwayland.OpenClipboard(); err == nil {
			defer cb.Close()
			return cb.Read("text/plain;charset=utf-8")
		}
	}
	c, err := svx11.Connect()
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrUnavailable, err)
	}
	defer c.Close()
	return svx11.Read(c, "UTF8_STRING")
}
