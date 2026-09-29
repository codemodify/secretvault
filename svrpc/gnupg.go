package svrpc

import "path/filepath"

// GnuPG's gpg, signing and decrypting with the OpenPGP keys in your
// vaults: secretvaultd answers gpg-agent's protocol on a socket of its
// own, and a GnuPG home is pointed at it by linking the agent socket gpg
// looks for there (`gpgconf --list-dirs agent-socket`) to that one.
// `secretvault pgp gpg-setup` does it. Only secretvault's own programs
// may: the daemon makes the links where it is told.
const (
	MGnuPGLink = "gnupg.link" // GnuPGLinkParams -> GnuPGLinkResult
)

// GnuPGLinkParams point a GnuPG home at the daemon. Socket is where gpg
// looks for its agent there, and SSHSocket its SSH agent (as gpgconf
// --list-dirs agent-socket and agent-ssh-socket print them): the daemon
// links them to its gpg-agent and SSH agent sockets now, and again each
// time it starts, since they usually live in /run/user, which every boot
// empties. Relink links a home it already has again, without recording
// anything (gpg, finding no agent, starts secretvault to bring it back).
// Remove forgets the home and takes away its links.
type GnuPGLinkParams struct {
	Home      string `json:"home"`
	Socket    string `json:"socket,omitempty"`
	SSHSocket string `json:"ssh_socket,omitempty"`
	Relink    bool   `json:"relink,omitempty"`
	Remove    bool   `json:"remove,omitempty"`
}

// GnuPGLinkResult names the sockets the links lead to ("" for none).
type GnuPGLinkResult struct {
	Agent    string `json:"agent,omitempty"`
	SSHAgent string `json:"ssh_agent,omitempty"`
}

// GPGAgentSocket is where secretvaultd answers gpg-agent's protocol:
// beside its own socket, as gpg-agent.sock.
func GPGAgentSocket() string {
	return filepath.Join(filepath.Dir(DefaultSocket()), "gpg-agent.sock")
}

// GnuPG's names for the sockets in its socket directory.
const (
	GnuPGAgentSocketName = "S.gpg-agent"
	GnuPGSSHSocketName   = "S.gpg-agent.ssh"
)
