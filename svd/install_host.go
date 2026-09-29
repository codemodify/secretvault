package svd

import (
	"fmt"
	"path/filepath"

	"github.com/codemodify/secretvault/svrpc"
)

// Installing host mode. `secretvaultd install --host` writes two system
// units and starts them:
//
//	secretvaultd-host.socket   holds credentials.sock from early boot
//	                           (socket activation), so a unit that starts
//	                           before the daemon waits for its credential
//	                           instead of failing; no unit needs to order
//	                           itself after the daemon.
//	secretvaultd-host.service  the daemon, as root, with the host identity
//	                           as an encrypted credential, and hardened.
//
// `secretvaultd uninstall --host` removes them, and leaves the vaults and
// the identity alone.

const (
	// HostServiceName is the host daemon's system unit.
	HostServiceName = "secretvaultd-host.service"
	// HostSocketName is its socket unit.
	HostSocketName = "secretvaultd-host.socket"
)

// The layout the units use: systemd's StateDirectory= and
// RuntimeDirectory= put them here.
const (
	hostDataDir    = "/var/lib/secretvault"
	hostRuntimeDir = "/run/secretvault"
)

// HostInstall configures InstallHost.
type HostInstall struct {
	// UnitDir is where the units go (/etc/systemd/system when "").
	UnitDir string

	// Credstore is the sealed host identity (svrpc.HostCredstore when "").
	// The service loads it with LoadCredentialEncrypted=, and it must
	// exist: systemd does not start a unit whose credential file is
	// missing.
	Credstore string

	// PlainIdentity leaves LoadCredentialEncrypted= out: the daemon reads
	// its identity from the plain file (<data>/host.identity) instead.
	PlainIdentity bool

	// NoStart enables the units without starting them.
	NoStart bool
}

func (o HostInstall) withDefaults() HostInstall {
	if o.UnitDir == "" {
		o.UnitDir = "/etc/systemd/system"
	}
	if o.Credstore == "" {
		o.Credstore = svrpc.HostCredstore
	}
	return o
}

// InstallHost installs the host daemon at exe as a system service, and
// says what it did.
func InstallHost(exe string, o HostInstall) (string, error) {
	if !filepath.IsAbs(exe) {
		return "", fmt.Errorf("svd: %q is not an absolute path", exe)
	}
	return installHost(exe, o.withDefaults())
}

// UninstallHost undoes InstallHost.
func UninstallHost(o HostInstall) (string, error) { return uninstallHost(o.withDefaults()) }

// hostServiceUnit is the host daemon's system unit. It runs as root,
// which it needs to serve other users' services and to identify them,
// and gives up everything else it can.
func hostServiceUnit(exe string, o HostInstall) string {
	cred := "# The host identity, sealed to this machine by systemd-creds ('secretvault host init --seal').\n" +
		"LoadCredentialEncrypted=" + svrpc.HostIdentityCredential + ":" + o.Credstore + "\n"
	if o.PlainIdentity {
		cred = "# The host identity is read from " + hostDataDir + "/host.identity (installed with --plain-identity).\n"
	}
	return `[Unit]
Description=secretvault host daemon: serves secrets to this machine's services
Documentation=https://github.com/codemodify/secretvault
Requires=` + HostSocketName + `
After=` + HostSocketName + `

[Service]
ExecStart=` + systemdQuote(exe) + ` --host
Restart=on-failure
RestartSec=2
# A second daemon on the same sockets exits 3; restarting would only clash.
RestartPreventExitStatus=3
` + cred + `StateDirectory=secretvault
StateDirectoryMode=0700
RuntimeDirectory=secretvault
RuntimeDirectoryMode=0755
# ` + HostSocketName + `'s credentials.sock lives there too.
RuntimeDirectoryPreserve=yes
UMask=0077
ProtectSystem=strict
ReadWritePaths=` + hostDataDir + `
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
# Unix sockets, and the network for a vault kept in step with a sync server.
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
SystemCallArchitectures=native
LimitCORE=0

[Install]
WantedBy=multi-user.target
Also=` + HostSocketName + `
`
}

// hostSocketUnit is the socket units load their credentials from.
func hostSocketUnit() string {
	return `[Unit]
Description=secretvault host daemon: the socket services load credentials from
Documentation=https://github.com/codemodify/secretvault

[Socket]
ListenStream=` + hostRuntimeDir + `/` + svrpc.HostCredentialSocketName + `
SocketMode=0600
DirectoryMode=0755

[Install]
WantedBy=sockets.target
`
}
