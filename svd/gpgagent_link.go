package svd

import (
	"cmp"
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/codemodify/secretvault/svrpc"
)

// Pointing GnuPG homes at the daemon. gpg looks for its agent at
// S.gpg-agent in its socket directory: /run/user/UID/gnupg (or a d.HASH
// directory below it, for a home other than ~/.gnupg) where /run/user
// exists, else the home itself. A home is pointed at the daemon by making
// that a symbolic link to the gpg-agent face's socket, and S.gpg-agent.ssh
// one to the SSH agent's, so that `gpgconf --list-dirs agent-socket` and
// agent-ssh-socket lead here. /run/user is emptied at every boot, so the
// daemon links the homes it was given again whenever it starts serving.
//
// Only secretvault's own programs may give it a home (the CLI's `pgp
// gpg-setup`, and the CLI again when gpg finds no agent and starts it,
// gpg.conf's agent-program). A link replaces only a socket or a link:
// never a file or a directory.

func init() {
	registerMethod(svrpc.MGnuPGLink, (*Daemon).gnupgLink)
}

// gnupgSockets are the sockets the faces serve, "" for one that does not
// run.
func (d *Daemon) gnupgSockets() (agent, ssh string) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.gpgSock, d.sshSock
}

// relinkGnuPG links every recorded home's sockets to the faces serving
// now: the gpg-agent socket, or with ssh the SSH agent's.
func (d *Daemon) relinkGnuPG(ssh bool) {
	d.mu.Lock()
	homes := slices.Clone(d.cfg.GnuPG)
	d.mu.Unlock()
	agent, sshSock := d.gnupgSockets()
	for _, h := range homes {
		if _, err := os.Stat(h.Home); err != nil {
			d.opts.Log(fmt.Sprintf("GnuPG home %s is gone; not linking it (secretvault pgp gpg-setup --remove forgets it)", h.Home))
			continue
		}
		path, target := h.Socket, agent
		if ssh {
			path, target = h.SSHSocket, sshSock
		}
		if path == "" || target == "" {
			continue
		}
		if err := linkSocket(path, target); err != nil {
			d.opts.Log(fmt.Sprintf("GnuPG home %s: %v", h.Home, err))
		}
	}
}

// checkSocketPath accepts the absolute path of one of GnuPG's sockets.
func checkSocketPath(path, name string) error {
	if path == "" {
		return nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || filepath.Base(path) != name {
		return svrpc.Errorf(svrpc.CodeInvalidParams, "%q is not a GnuPG socket path (a clean absolute path ending in %s)", path, name)
	}
	return nil
}

// sameDir reports whether two paths are the same directory.
func sameDir(a, b string) bool {
	if a == b {
		return true
	}
	fa, err1 := os.Stat(a)
	fb, err2 := os.Stat(b)
	return err1 == nil && err2 == nil && os.SameFile(fa, fb)
}

func (d *Daemon) gnupgLink(_ context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.GnuPGLinkParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	if !cl.cli {
		return nil, svrpc.Errorf(svrpc.CodeDenied, "only secretvault's own programs may point GnuPG at the daemon")
	}
	if runtime.GOOS == "windows" {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "the gpg-agent face does not run on Windows, where gpg reaches its agent through a TCP socket emulation")
	}
	if !filepath.IsAbs(p.Home) {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "the GnuPG home %q is not an absolute path", p.Home)
	}
	home := filepath.Clean(p.Home)
	if err := checkSocketPath(p.Socket, svrpc.GnuPGAgentSocketName); err != nil {
		return nil, err
	}
	if err := checkSocketPath(p.SSHSocket, svrpc.GnuPGSSHSocketName); err != nil {
		return nil, err
	}
	agent, ssh := d.gnupgSockets()
	d.mu.Lock()
	homes := slices.Clone(d.cfg.GnuPG)
	d.mu.Unlock()
	idx := slices.IndexFunc(homes, func(h GnuPGHome) bool { return sameDir(h.Home, home) })
	var known GnuPGHome
	if idx >= 0 {
		known = homes[idx]
	}

	if p.Remove {
		if idx < 0 {
			return nil, svrpc.Errorf(svrpc.CodeNotFound, "%s is not pointed at secretvault", home)
		}
		unlinkSocket(known.Socket, cmp.Or(agent, svrpc.GPGAgentSocket()))
		unlinkSocket(known.SSHSocket, cmp.Or(ssh, svrpc.SSHAgentSocket()))
		d.mu.Lock()
		d.cfg.GnuPG = slices.DeleteFunc(d.cfg.GnuPG, func(h GnuPGHome) bool { return h.Home == known.Home })
		err := d.cfg.save(d.home)
		d.mu.Unlock()
		return svrpc.GnuPGLinkResult{}, err
	}

	if agent == "" {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "the gpg-agent face is off (no_gpg_agent in the daemon's config.json)")
	}
	want := GnuPGHome{Home: home, Socket: p.Socket, SSHSocket: p.SSHSocket}
	if p.Relink {
		if idx < 0 {
			// gpg started secretvault as its agent-program, which has no
			// stderr to say this on: the log says it.
			d.opts.Log(fmt.Sprintf("gpg looked for its agent in %s, which is not pointed at secretvault", home))
			return nil, svrpc.Errorf(svrpc.CodeNotFound, "%s is not pointed at secretvault: run 'secretvault pgp gpg-setup --gnupghome %s'", home, home)
		}
		if want.Socket == "" {
			want.Socket, want.SSHSocket = known.Socket, known.SSHSocket
		}
	}
	if want.Socket == "" {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "where gpg looks for its agent in %s is missing (gpgconf --list-dirs agent-socket)", home)
	}
	if err := linkSocket(want.Socket, agent); err != nil {
		d.opts.Log(fmt.Sprintf("GnuPG home %s: %v", home, err))
		return nil, svrpc.Errorf(svrpc.CodeFailed, "%v", err)
	}
	if !p.Relink {
		d.mu.Lock()
		d.cfg.GnuPG = slices.DeleteFunc(d.cfg.GnuPG, func(h GnuPGHome) bool { return idx >= 0 && h.Home == known.Home })
		d.cfg.GnuPG = append(d.cfg.GnuPG, want)
		err := d.cfg.save(d.home)
		d.mu.Unlock()
		if err != nil {
			return nil, err
		}
	}
	res := svrpc.GnuPGLinkResult{Agent: agent}
	if want.SSHSocket != "" && ssh != "" {
		// Its SSH agent is an extra: a link that cannot be made is said in
		// the log, and gpg works without it.
		if err := linkSocket(want.SSHSocket, ssh); err != nil {
			d.opts.Log(fmt.Sprintf("GnuPG home %s: %v", home, err))
		} else {
			res.SSHAgent = ssh
		}
	}
	return res, nil
}

// linkSocket makes path a symbolic link to target, replacing a socket or
// a link that is there (a gpg-agent's, an old link), never anything else.
// The directories on the way are made, 0700, as gpg makes them.
func linkSocket(path, target string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	if fi, err := os.Lstat(path); err == nil {
		switch {
		case fi.Mode()&os.ModeSymlink != 0:
			if t, err := os.Readlink(path); err == nil && t == target {
				return nil
			}
		case fi.Mode()&os.ModeSocket == 0:
			return fmt.Errorf("%s is not a socket or a link; it was left alone", path)
		}
	}
	// A new link, renamed over the old one: gpg never finds nothing there.
	var r [8]byte
	rand.Read(r[:])
	tmp := filepath.Join(filepath.Dir(path), ".secretvault-"+hex.EncodeToString(r[:]))
	if err := os.Symlink(target, tmp); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}

// unlinkSocket removes path if it is a link to target.
func unlinkSocket(path, target string) {
	if path == "" {
		return
	}
	if t, err := os.Readlink(path); err == nil && t == target {
		os.Remove(path)
	}
}
