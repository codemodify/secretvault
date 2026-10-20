package svd

import (
	"context"
	"os"

	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Where things are kept (svrpc.MWhere): every folder and file the daemon
// keeps, and what secretvault changed in other programs, as the daemon
// itself uses them: its folders, its config's vaults and GnuPG folders,
// its sockets. svops builds the list, which the CLI also builds when no
// daemon runs. Only secretvault's own programs are told.

func init() {
	registerMethod(svrpc.MWhere, (*Daemon).where)
}

func (d *Daemon) where(_ context.Context, cl *client, _ func(any) error) (any, error) {
	if !cl.cli {
		return nil, svrpc.Errorf(svrpc.CodeDenied, "only secretvault's own programs are told where it keeps things")
	}
	return d.Where(), nil
}

// Where lists the places the daemon keeps or changed.
func (d *Daemon) Where() []svrpc.Place {
	gpgSock, sshSock := d.gnupgSockets()
	d.mu.Lock()
	o := svops.WhereOptions{Config: d.config, Data: d.home, Socket: d.opts.Socket, SSHAgent: sshSock, GPGAgent: gpgSock}
	for _, vc := range d.cfg.Vaults {
		o.Vaults = append(o.Vaults, svops.WhereVault{Name: vc.Name, Path: vc.Path})
	}
	for _, h := range d.cfg.GnuPG {
		o.GnuPG = append(o.GnuPG, svops.WhereGnuPG{Home: h.Home, Socket: h.Socket, SSHSocket: h.SSHSocket})
	}
	d.mu.Unlock()
	if d.host != nil {
		o.Host, o.HostData, o.HostRuntime = true, d.home, d.host.opts.Runtime
		return svops.Where(o)
	}
	if o.Socket == "" {
		o.Socket = svrpc.DefaultSocket()
	}
	if o.SSHAgent == "" && d.SSHAgentEnabled() {
		o.SSHAgent = svrpc.SSHAgentSocket()
	}
	if o.GPGAgent == "" && d.GPGAgentEnabled() {
		o.GPGAgent = svrpc.GPGAgentSocket()
	}
	o.CLI = svops.CLIProgram()
	if data, err := svcore.DataDir(); err == nil && os.Getenv(svcore.EnvHome) == "" && sameDir(data, d.home) {
		o.Old, _ = svcore.LegacyDir() // listed while it is there
	}
	return svops.Where(o)
}
