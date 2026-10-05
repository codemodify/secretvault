//go:build !linux

package ptytest

import (
	"errors"
	"os"
)

func open() (*os.File, string, error) {
	return nil, "", errors.New("pseudo-terminals are made on Linux only here")
}
