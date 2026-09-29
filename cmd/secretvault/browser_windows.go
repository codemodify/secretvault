//go:build windows

package main

import (
	"errors"

	"golang.org/x/sys/windows/registry"
)

// On Windows a browser finds its native-messaging host by a key under
// HKEY_CURRENT_USER whose default value is the manifest's path.

// registryValue reads a key's default value; ok is false when there is
// no such key.
func registryValue(key string) (value string, ok bool, err error) {
	k, err := registry.OpenKey(registry.CURRENT_USER, key, registry.QUERY_VALUE)
	if errors.Is(err, registry.ErrNotExist) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	defer k.Close()
	v, _, err := k.GetStringValue("")
	if errors.Is(err, registry.ErrNotExist) {
		return "", true, nil
	}
	return v, err == nil, err
}

// setRegistryValue sets a key's default value, making the key if need be.
func setRegistryValue(key, value string) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, key, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()
	return k.SetStringValue("", value)
}

// deleteRegistryKey removes a key install made.
func deleteRegistryKey(key string) error {
	err := registry.DeleteKey(registry.CURRENT_USER, key)
	if errors.Is(err, registry.ErrNotExist) {
		return nil
	}
	return err
}
