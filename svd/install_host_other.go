//go:build !linux

package svd

import "errors"

var errHostLinux = errors.New("svd: host mode needs Linux and systemd")

func installHost(string, HostInstall) (string, error) { return "", errHostLinux }

func uninstallHost(HostInstall) (string, error) { return "", errHostLinux }
