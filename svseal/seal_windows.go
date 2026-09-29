//go:build windows

package svseal

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dpapi seals with the Data Protection API, under the user's logon
// credentials; the name is the optional entropy, so it must match.
type dpapi struct{}

func platform() Sealer { return dpapi{} }

func (dpapi) Name() string     { return "Windows DPAPI" }
func (dpapi) Available() error { return nil }

func blob(b []byte) *windows.DataBlob {
	if len(b) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(b)), Data: &b[0]}
}

func take(out *windows.DataBlob) []byte {
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	b := unsafe.Slice(out.Data, out.Size)
	c := append([]byte(nil), b...)
	clear(b)
	return c
}

func (dpapi) Seal(name string, secret []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptProtectData(blob(secret), nil, blob([]byte(name)), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("svseal: CryptProtectData: %w", err)
	}
	return take(&out), nil
}

func (dpapi) Unseal(name string, sealed []byte) ([]byte, error) {
	var out windows.DataBlob
	if err := windows.CryptUnprotectData(blob(sealed), nil, blob([]byte(name)), 0, nil, windows.CRYPTPROTECT_UI_FORBIDDEN, &out); err != nil {
		return nil, fmt.Errorf("svseal: CryptUnprotectData: %w", err)
	}
	return take(&out), nil
}
