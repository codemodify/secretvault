//go:build windows

package svd

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

const runKey = `Software\Microsoft\Windows\CurrentVersion\Run`

func install(exe string) (string, error) {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return "", err
	}
	defer k.Close()
	if err := k.SetStringValue("secretvaultd", `"`+exe+`"`); err != nil {
		return "", err
	}
	return `Added secretvaultd to HKCU\` + runKey + `; it starts at every login.`, nil
}

func uninstall() (string, error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, runKey, registry.SET_VALUE)
	if err != nil {
		return "secretvaultd was not set to start at login.", nil
	}
	defer k.Close()
	if err := k.DeleteValue("secretvaultd"); err != nil {
		if errors.Is(err, registry.ErrNotExist) {
			return "secretvaultd was not set to start at login.", nil
		}
		return "", err
	}
	return "secretvaultd no longer starts at login.", nil
}
