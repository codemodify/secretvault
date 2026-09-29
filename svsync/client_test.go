package svsync

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svserver"
)

func TestAPinnedCertificateIsTrustedAndNoOtherIs(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	good := s.remote("v")
	c, err := NewClient(good, NewIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.CreateVault(ctx, adminToken, ""); err != nil {
		t.Fatalf("with the right pin: %v", err)
	}

	wrong := good
	wrong.Fingerprint = strings.Repeat("ab:", 31) + "ab"
	c, _ = NewClient(wrong, NewIdentity())
	if err := c.CreateVault(ctx, adminToken, ""); !errors.Is(err, ErrPin) {
		t.Fatalf("with another pin: %v", err)
	}

	unpinned := good
	unpinned.Fingerprint = ""
	c, _ = NewClient(unpinned, NewIdentity())
	if err := c.CreateVault(ctx, adminToken, ""); err == nil {
		t.Fatal("a self-signed certificate was trusted without a pin")
	}
}

func TestRemotesAreChecked(t *testing.T) {
	for _, r := range []Remote{
		{URL: "http://example.com", Vault: "v"},
		{URL: "ftp://example.com", Vault: "v"},
		{URL: "example.com", Vault: "v"},
		{URL: "https://example.com?x=1", Vault: "v"},
		{URL: "https://example.com", Vault: "Not/A/Name"},
		{URL: "https://example.com", Vault: "v", Fingerprint: "abcd"},
	} {
		if _, err := NewClient(r, NewIdentity()); err == nil {
			t.Errorf("%+v was accepted", r)
		}
	}
	for _, r := range []Remote{
		{URL: "http://127.0.0.1:8080", Vault: "v"},
		{URL: "http://localhost:8080/", Vault: "v"},
		{URL: "https://sync.example.com/prefix/", Vault: "0123456789abcdef0123456789abcdef", Fingerprint: strings.Repeat("AB", 32)},
	} {
		if _, err := NewClient(r, NewIdentity()); err != nil {
			t.Errorf("%+v: %v", r, err)
		}
	}
}

func TestAServerMountedUnderAPathWorks(t *testing.T) {
	srv, err := svserver.New(svserver.Config{Root: t.TempDir(), OpenRegistration: true, Rate: -1})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.Handle("/sync/", http.StripPrefix("/sync", srv))
	h := httptest.NewServer(mux)
	defer h.Close()
	defer srv.Close()
	c, err := NewClient(Remote{URL: h.URL + "/sync/", Vault: "v"}, NewIdentity())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := c.CreateVault(ctx, "", "laptop"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Put(ctx, "vault.json", []byte(`{}`)); err != nil {
		t.Fatal(err)
	}
	if cs, err := c.Changes(ctx, 0, 0, 0); err != nil || len(cs.Changes) != 1 {
		t.Fatalf("changes: %+v, %v", cs, err)
	}
}

func TestDevicesAreEnrolledByInviteListedAndRemoved(t *testing.T) {
	s := newServer(t)
	ctx := context.Background()
	a := s.founder("v", nil)
	inv, err := a.client.Enrol(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// The invite travels as text (or a QR code).
	got, err := ParseInvite(inv.String())
	if err != nil {
		t.Fatal(err)
	}
	if got.Remote != inv.Remote || got.Code != inv.Code {
		t.Fatalf("the invite read back as %+v, want %+v", got, inv)
	}
	b, err := NewClient(got.Remote, NewIdentity())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.Devices(ctx); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("before joining: %v", err)
	}
	if err := b.Join(ctx, got.Code, "phone"); err != nil {
		t.Fatal(err)
	}
	if err := b.Join(ctx, got.Code, "phone"); err != nil {
		t.Fatalf("joining again: %v", err)
	}
	c := NewIdentity()
	cc, _ := NewClient(got.Remote, c)
	if err := cc.Join(ctx, got.Code, "thief"); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("a second device with the same code: %v", err)
	}
	devs, err := b.Devices(ctx)
	if err != nil || len(devs) != 2 || devs[0].Key != a.client.Identity().Key() || devs[1].Key != b.Identity().Key() || devs[1].Label != "phone" {
		t.Fatalf("devices: %+v, %v", devs, err)
	}
	if err := a.client.RemoveDevice(ctx, b.Identity().Key()); err != nil {
		t.Fatal(err)
	}
	if _, err := b.Devices(ctx); !errors.Is(err, ErrNotEnrolled) {
		t.Fatalf("after removal: %v", err)
	}
	if err := a.client.RemoveDevice(ctx, a.client.Identity().Key()); !errors.Is(err, ErrConflict) {
		t.Fatalf("removing the last device: %v", err)
	}
}

func TestInvitesAreChecked(t *testing.T) {
	for _, s := range []string{
		"",
		"https://example.com",
		"secretvault-sync:?url=https%3A%2F%2Fexample.com&vault=v",
		"secretvault-sync:?url=http%3A%2F%2Fexample.com&vault=v&code=X",
		"secretvault-sync:?url=https%3A%2F%2Fexample.com&vault=V&code=X",
	} {
		if _, err := ParseInvite(s); err == nil {
			t.Errorf("%q was accepted", s)
		}
	}
}

func TestTheDeviceKeyIsMadeOnceAndKeptPrivate(t *testing.T) {
	dir := t.TempDir()
	a, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadIdentity(dir)
	if err != nil {
		t.Fatal(err)
	}
	if a.Key() != b.Key() || !a.key.Equal(b.key) {
		t.Fatal("a second load made another key")
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(dir + "/" + IdentityFile)
		if err != nil || fi.Mode().Perm() != 0o600 {
			t.Fatalf("key file: %v, %v", fi.Mode(), err)
		}
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("the data directory holds %d files; a temporary was left behind", len(entries))
	}
	os.WriteFile(dir+"/"+IdentityFile, []byte("garbage"), 0o600)
	if _, err := LoadIdentity(dir); err == nil {
		t.Fatal("a damaged key file was accepted")
	}
}
