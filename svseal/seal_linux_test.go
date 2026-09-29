package svseal

import (
	"bytes"
	"errors"
	"slices"
	"testing"
)

func TestSystemdCredsIsAskedForTheUsersScopeAndTheName(t *testing.T) {
	saved := run
	t.Cleanup(func() { run = saved })
	var calls [][]string
	run = func(stdin []byte, args ...string) ([]byte, error) {
		calls = append(calls, args)
		switch {
		case slices.Contains(args, "encrypt"):
			return append([]byte("sealed:"), stdin...), nil
		case slices.Contains(args, "decrypt"):
			if rest, ok := bytes.CutPrefix(stdin, []byte("sealed:")); ok {
				return rest, nil
			}
			return nil, errors.New("Failed to decrypt")
		}
		return nil, errors.New("unexpected")
	}
	s := Default()
	sealed, err := s.Seal("secretvault-login-x", []byte("key"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := s.Unseal("secretvault-login-x", sealed); err != nil || string(got) != "key" {
		t.Fatalf("Unseal = %q, %v", got, err)
	}
	for _, c := range calls {
		if c[0] != "--user" || !slices.Contains(c, "--name=secretvault-login-x") {
			t.Errorf("systemd-creds %v: not the user's scope, or no name", c)
		}
	}
	if _, err := s.Unseal("secretvault-login-x", []byte("garbage")); err == nil {
		t.Fatal("garbage unsealed")
	}
}
