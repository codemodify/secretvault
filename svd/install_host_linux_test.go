//go:build linux

package svd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeSystemctl stands in for systemctl, recording what it was asked.
func fakeSystemctl(t *testing.T) *[]string {
	var calls []string
	systemctl = func(args ...string) ([]byte, error) {
		calls = append(calls, strings.Join(args, " "))
		return nil, nil
	}
	t.Cleanup(func() {
		systemctl = func(args ...string) ([]byte, error) { panic("systemctl after test") }
	})
	return &calls
}

func TestInstallHostWritesHardenedUnitsAndStartsThem(t *testing.T) {
	calls := fakeSystemctl(t)
	dir := t.TempDir()
	o := HostInstall{UnitDir: filepath.Join(dir, "units"), Credstore: filepath.Join(dir, "credstore.encrypted", "secretvault-host.identity")}

	// Without a sealed identity the unit could not start: say what to do.
	if _, err := InstallHost("/usr/bin/secretvaultd", o); err == nil || !strings.Contains(err.Error(), "host init --seal") {
		t.Fatalf("no sealed identity: %v", err)
	}
	if len(*calls) != 0 {
		t.Fatalf("systemctl ran: %v", *calls)
	}
	os.MkdirAll(filepath.Dir(o.Credstore), 0o700)
	os.WriteFile(o.Credstore, []byte("sealed"), 0o600)

	msg, err := InstallHost("/usr/bin/secretvaultd", o)
	if err != nil {
		t.Fatal(err)
	}
	service, err := os.ReadFile(filepath.Join(o.UnitDir, HostServiceName))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{
		"ExecStart=/usr/bin/secretvaultd --host",
		"LoadCredentialEncrypted=secretvault-host.identity:" + o.Credstore,
		"ProtectSystem=strict", "PrivateTmp=yes", "NoNewPrivileges=yes",
		"ReadWritePaths=/var/lib/secretvault", "StateDirectory=secretvault",
		"RuntimeDirectory=secretvault", "RuntimeDirectoryMode=0755", "RuntimeDirectoryPreserve=yes",
		"Requires=secretvaultd-host.socket", "LimitCORE=0", "WantedBy=multi-user.target",
	} {
		if !strings.Contains(string(service), "\n"+line+"\n") {
			t.Errorf("the service lacks %q", line)
		}
	}
	socket, err := os.ReadFile(filepath.Join(o.UnitDir, HostSocketName))
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range []string{"ListenStream=/run/secretvault/credentials.sock", "SocketMode=0600", "WantedBy=sockets.target"} {
		if !strings.Contains(string(socket), "\n"+line+"\n") {
			t.Errorf("the socket lacks %q", line)
		}
	}
	if got := strings.Join(*calls, "; "); got != "daemon-reload; enable --now secretvaultd-host.socket secretvaultd-host.service" {
		t.Fatalf("systemctl: %s", got)
	}
	if !strings.Contains(msg, "running now") {
		t.Fatalf("message %q", msg)
	}

	*calls = nil
	if _, err := UninstallHost(o); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{HostServiceName, HostSocketName} {
		if _, err := os.Stat(filepath.Join(o.UnitDir, name)); !os.IsNotExist(err) {
			t.Errorf("%s is still there", name)
		}
	}
	if got := strings.Join(*calls, "; "); got != "disable --now secretvaultd-host.service secretvaultd-host.socket; daemon-reload" {
		t.Fatalf("systemctl: %s", got)
	}
	if _, err := os.Stat(o.Credstore); err != nil {
		t.Fatal("uninstalling removed the sealed identity")
	}
}

func TestInstallHostWithAPlainIdentity(t *testing.T) {
	calls := fakeSystemctl(t)
	o := HostInstall{UnitDir: t.TempDir(), Credstore: filepath.Join(t.TempDir(), "none"), PlainIdentity: true, NoStart: true}
	if _, err := InstallHost("/opt/secret vault/secretvaultd", o); err != nil {
		t.Fatal(err)
	}
	service, _ := os.ReadFile(filepath.Join(o.UnitDir, HostServiceName))
	if strings.Contains(string(service), "LoadCredentialEncrypted=") || !strings.Contains(string(service), `ExecStart="/opt/secret vault/secretvaultd" --host`) {
		t.Fatalf("the service:\n%s", service)
	}
	if got := strings.Join(*calls, "; "); got != "daemon-reload; enable secretvaultd-host.socket secretvaultd-host.service" {
		t.Fatalf("systemctl: %s", got)
	}
	if _, err := InstallHost("relative/secretvaultd", o); err == nil {
		t.Fatal("a relative path was installed")
	}
}
