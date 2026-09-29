//go:build !windows

package main

import "errors"

// Only Windows keeps native-messaging hosts in the registry; elsewhere a
// browserSpot has no key and these are never called.

var errNoRegistry = errors.New("there is no registry here")

func registryValue(string) (string, bool, error) { return "", false, errNoRegistry }

func setRegistryValue(string, string) error { return errNoRegistry }

func deleteRegistryKey(string) error { return errNoRegistry }
