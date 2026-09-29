package svd

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// Host mode: secretvaultd --host, the machine's system service. It serves
// secrets to the machine's services, with nobody there to ask:
//
//   - systemd's LoadCredential=. A unit that says
//     LoadCredential=db-password:/run/secretvault/credentials.sock gets,
//     each time it starts, what the policy maps its (unit, credential) to.
//     systemd connects from an abstract socket named "\0RANDOM/unit/UNIT/ID"
//     (systemd.exec(5)), which says who asks for what, and reads until the
//     connection ends. The peer must be systemd: PID 1, or the root
//     process it forks to start the unit, which is what connects.
//   - Local services that are not units (cron jobs, scripts run as a
//     service user) use the client API on secretvaultd.sock, and may read
//     the sv:// references the policy lists for their uid and program.
//   - root runs it over admin.sock ('secretvault host ...', and every other
//     command with --host), and may do anything.
//
// The policy (<data>/host.json) lists everything served; anything else is
// refused. Every delivery and refusal goes to the host's log
// (<data>/host.log, and the journal), and every read of a vault to that
// vault's audit log too.
//
// Vaults are opened with the host identity, through a recipient keyslot
// ('secretvault share' on the machine that holds the vault). systemd hands
// the identity over as a credential (LoadCredentialEncrypted=, sealed by
// systemd-creds to the TPM2 or the host key); without systemd it is read
// from a file only root can read. Nothing prompts, the Secret Service,
// the SSH agent and the prompt protocol are not served, and vaults do not
// lock on idle unless their config says so.

// HostOptions configure host mode.
type HostOptions struct {
	// Runtime is where the sockets go (svrpc.HostRuntimeDir() when "").
	Runtime string

	// Policy is the policy file (<Home>/host.json when "").
	Policy string

	// Identity is the plain identity file, read when systemd passed no
	// credential (<Home>/host.identity when "").
	Identity string

	// Credentials is the directory systemd put the unit's credentials in
	// ($CREDENTIALS_DIRECTORY when "").
	Credentials string

	// FromServiceManager checks that a connection to the credential
	// socket comes from systemd. Nil means: SO_PEERCRED says PID 1 or uid
	// 0. Tests, which are neither, stand in.
	FromServiceManager func(net.Conn) error
}

// hostState is what host mode keeps.
type hostState struct {
	opts HostOptions
	log  string // <Home>/host.log

	id       *svcrypto.Identity // nil when there is none
	idSource string             // where it came from
	idErr    error              // why one that was found is not used

	mu     sync.Mutex // the policy and its cache
	pol    *hostPolicy
	polSum [sha256.Size]byte // of the file pol was read from

	delivered, refused atomic.Int64

	logMu sync.Mutex
}

// HostListeners are the host daemon's sockets (ListenHost): Serve takes
// Admin, ServeServices Services, ServeCredentials Credentials.
type HostListeners struct {
	Admin, Services, Credentials net.Listener
	closers                      []func()
}

// Close closes them all, and removes the sockets the daemon made itself.
func (l *HostListeners) Close() {
	for i := len(l.closers) - 1; i >= 0; i-- {
		l.closers[i]()
	}
	l.closers = nil
}

// credentialTimeout bounds one answer on the credential socket.
const credentialTimeout = 30 * time.Second

// maxHostLog is the size at which host.log moves aside to host.log.1.
const maxHostLog = 8 << 20

// startHost sets up host mode in New: the identity, the vaults it opens,
// and the policy.
func (d *Daemon) startHost() error {
	o := d.opts.Host
	if o.Runtime == "" {
		o.Runtime = svrpc.HostRuntimeDir()
	}
	if o.Policy == "" {
		o.Policy = filepath.Join(d.home, "host.json")
	}
	if o.Identity == "" {
		o.Identity = filepath.Join(d.home, "host.identity")
	}
	if o.Credentials == "" {
		o.Credentials = os.Getenv("CREDENTIALS_DIRECTORY")
	}
	if o.FromServiceManager == nil {
		o.FromServiceManager = fromServiceManager
	}
	if err := os.MkdirAll(d.home, 0o700); err != nil {
		return err
	}
	h := &hostState{opts: o, log: filepath.Join(d.home, "host.log")}
	d.host = h
	h.id, h.idSource, h.idErr = loadHostIdentity(o)
	switch {
	case h.id != nil:
		d.opts.Log("the host identity is from " + h.idSource)
	case h.idErr != nil:
		d.opts.Log("the host identity is not used: " + h.idErr.Error())
	default:
		d.opts.Log("there is no host identity (no systemd credential " + svrpc.HostIdentityCredential + ", no " + o.Identity + "), so vaults stay locked until root unlocks them")
	}
	// Open what the identity opens now, so the first unit to start does
	// not wait for it.
	for _, info := range d.vaultInfos() {
		mv, err := d.vault(info.Name)
		if err != nil || h.id == nil {
			continue
		}
		if err := d.hostUnlock(mv); err != nil {
			d.opts.Log(err.Error())
		}
	}
	if _, err := h.policy(d.opts.Log); err != nil {
		d.opts.Log("the host policy: " + err.Error() + "; everything is refused until it is fixed")
	}
	return nil
}

// fromServiceManager is the default FromServiceManager.
func fromServiceManager(c net.Conn) error {
	pid, uid, err := svpeer.PeerCred(c)
	if err != nil {
		return err
	}
	if pid == 1 || uid == 0 {
		return nil
	}
	return fmt.Errorf("process %d runs as uid %d, and only systemd (root) asks here", pid, uid)
}

// loadHostIdentity reads the host identity: from systemd's credential if
// the unit was given one, else from the plain file. Either must be
// readable by the daemon's own user alone.
func loadHostIdentity(o HostOptions) (*svcrypto.Identity, string, error) {
	type place struct{ path, source string }
	var places []place
	if o.Credentials != "" {
		places = append(places, place{filepath.Join(o.Credentials, svrpc.HostIdentityCredential), "systemd's credential " + svrpc.HostIdentityCredential})
	}
	places = append(places, place{o.Identity, o.Identity})
	for _, p := range places {
		b, err := readOwned(p.path, true)
		if errors.Is(err, fs.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		id, err := parseIdentity(b)
		clear(b)
		if err != nil {
			return nil, "", fmt.Errorf("%s: %w", p.path, err)
		}
		return id, p.source, nil
	}
	return nil, "", nil
}

// readOwned reads a file that belongs to the daemon's own user (root, in
// production) and that nobody else may change; with private, nobody else
// may read it either.
func readOwned(p string, private bool) ([]byte, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", p)
	}
	if uid, ok := fileOwner(st); ok && uid != os.Getuid() {
		return nil, fmt.Errorf("%s belongs to uid %d, not to this daemon's user (uid %d)", p, uid, os.Getuid())
	}
	mask := os.FileMode(0o022)
	if private {
		mask = 0o077
	}
	if st.Mode().Perm()&mask != 0 {
		want := "0600"
		if !private {
			want = "0644 at most"
		}
		return nil, fmt.Errorf("%s has mode %04o: make it %s", p, st.Mode().Perm(), want)
	}
	var b bytes.Buffer
	if _, err := b.ReadFrom(f); err != nil {
		clear(b.Bytes())
		return nil, err
	}
	return b.Bytes(), nil
}

// hostUnlock opens a locked vault with the host identity. It never asks
// anyone: without an identity that opens it, the vault stays locked
// (root can still unlock it with a key, 'secretvault --host unlock').
func (d *Daemon) hostUnlock(mv *managedVault) error {
	id := d.host.id
	if id == nil {
		return svrpc.Errorf(svrpc.CodeLocked, "vault %q is locked, and this host has no identity to open it with ('secretvault host init' makes one; until then root can unlock it with a key: 'secretvault --host unlock %s --passphrase-file FILE')", mv.cfg.Name, mv.cfg.Name)
	}
	mv.prompt.Lock()
	defer mv.prompt.Unlock()
	if !mv.v.Locked() {
		return nil
	}
	switch err := d.unlockWith(mv, svcore.IdentityKey(id)); {
	case err == nil:
		d.opts.Log(fmt.Sprintf("unlocked %s with the host identity", mv.cfg.Name))
		return nil
	case errors.Is(err, svcore.ErrWrongKey):
		return svrpc.Errorf(svrpc.CodeLocked, "vault %q is locked, and the host identity does not open it: share the vault to the host's recipient ('secretvault host status' shows it)", mv.cfg.Name)
	case errors.Is(err, svcore.ErrKeyRemoved):
		return svrpc.Errorf(svrpc.CodeLocked, "vault %q is locked: its key was rotated, and the host's keyslot was left out", mv.cfg.Name)
	default:
		return err
	}
}

// hostRead reads the value r names, opening its vault with the host
// identity if need be; nobody is asked. mv is the vault, when it is here.
// The caller clears the value.
func (d *Daemon) hostRead(r svrpc.Ref) (mv *managedVault, value []byte, err error) {
	mv, err = d.vault(r.Vault)
	if err != nil {
		return nil, nil, err
	}
	d.fresh(mv)
	if mv.v.Locked() {
		if err := d.hostUnlock(mv); err != nil {
			return mv, nil, err
		}
	}
	e, err := mv.v.Get(r.Item)
	if err != nil {
		return mv, nil, mapErr(err)
	}
	defer e.Item.Wipe()
	f, ok := e.Item.Secret()
	if r.Field != "" {
		f, ok = e.Item.Field(r.Field)
	}
	if !ok {
		if r.Field == "" {
			return mv, nil, svrpc.Errorf(svrpc.CodeNotFound, "%s has no secret field: name one with #FIELD", r)
		}
		return mv, nil, svrpc.Errorf(svrpc.CodeNotFound, "%s: the item has no field %q", r, r.Field)
	}
	d.touch(mv)
	return mv, append([]byte(nil), f.Value...), nil
}

// ServeCredentials answers systemd's LoadCredential= on ln until ctx
// ends (host mode).
func (d *Daemon) ServeCredentials(ctx context.Context, ln net.Listener) error {
	if d.host == nil {
		return errors.New("svd: credentials are served in host mode only")
	}
	return accept(ctx, ln, d.serveCredential)
}

// ServeServices accepts local services on ln until ctx ends (host mode):
// the client API, for the references the policy lists for each.
func (d *Daemon) ServeServices(ctx context.Context, ln net.Listener) error {
	if d.host == nil {
		return errors.New("svd: local services are served in host mode only")
	}
	return accept(ctx, ln, func(c net.Conn) { d.serveConn(c, roleService) })
}

// serveCredential answers one request from systemd: the credential, then
// the end of the connection; refused, the end alone. systemd reads until
// the end, so a refused unit gets an empty credential and starts; it
// cannot tell a refusal from an empty secret.
func (d *Daemon) serveCredential(c net.Conn) {
	defer c.Close()
	c.SetDeadline(time.Now().Add(credentialTimeout))
	ev := svrpc.HostEvent{UID: -1}
	if pid, uid, err := svpeer.PeerCred(c); err == nil {
		ev.PID, ev.UID = pid, uid
	}
	refuse := func(why string) {
		ev.Outcome, ev.Reason = "refused", why
		d.hostEvent(ev)
	}
	// What the peer claims to be asking for is read first, for the log.
	addr, addrErr := peerAddress(c)
	unit, cred, nameErr := parseCredentialPeer(addr)
	if nameErr == nil {
		ev.Unit, ev.Credential = unit, cred
	}
	if err := d.host.opts.FromServiceManager(c); err != nil {
		refuse("not systemd: " + err.Error())
		return
	}
	switch {
	case addrErr != nil:
		refuse(addrErr.Error())
		return
	case nameErr != nil:
		refuse(nameErr.Error())
		return
	}
	pol, err := d.host.policy(d.opts.Log)
	if err != nil {
		refuse("the host policy cannot be read: " + err.Error())
		return
	}
	rule, ok := pol.credential(unit, cred)
	if !ok {
		refuse("not in the host policy")
		return
	}
	r, _ := svrpc.ParseRef(rule.Ref) // checked when the policy was read
	ev.Ref = r.String()
	entry := svbroker.Entry{Program: "systemd, for " + unit, Identity: "unit:" + unit, PID: ev.PID,
		Op: svbroker.OpRead, Item: r.Item, Reason: "LoadCredential " + cred}
	mv, value, err := d.hostRead(r)
	if err == nil {
		_, err = c.Write(value)
		clear(value)
	}
	if err != nil {
		if mv != nil {
			entry.Outcome = "failed"
			d.audit.Record(mv.v, entry)
		}
		ev.Outcome, ev.Reason = "failed", strings.TrimPrefix(err.Error(), "svcore: ")
		d.hostEvent(ev)
		return
	}
	entry.Outcome = "allowed"
	d.audit.Record(mv.v, entry)
	ev.Outcome = "delivered"
	d.hostEvent(ev)
}

var (
	// unitPattern is a systemd unit name (letters, digits, ":-_.\", and
	// "@" for templates); unitGlob allows path.Match's globs as well.
	unitPattern = regexp.MustCompile(`^[A-Za-z0-9:_.\\@-]{1,256}$`)
	unitGlob    = regexp.MustCompile(`^[A-Za-z0-9:_.\\@*?\[\]^-]{1,256}$`)
	// randomPattern is the random part systemd starts its name with.
	randomPattern = regexp.MustCompile(`^[0-9A-Za-z]{1,64}$`)
)

// parseCredentialPeer reads which unit asks for which credential from the
// address systemd bound its end to: "\0" RANDOM "/unit/" UNIT "/" ID,
// shown with "@" for the NUL.
func parseCredentialPeer(addr string) (unit, cred string, err error) {
	rest, ok := strings.CutPrefix(addr, "@")
	random, tail, ok2 := strings.Cut(rest, "/unit/")
	unit, cred, ok3 := strings.Cut(tail, "/")
	if !ok || !ok2 || !ok3 || !randomPattern.MatchString(random) {
		return "", "", fmt.Errorf("the peer's address %q is not systemd's LoadCredential= (\\0RANDOM/unit/UNIT/ID)", addr)
	}
	if !unitPattern.MatchString(unit) {
		return "", "", fmt.Errorf("%q is not a unit name", unit)
	}
	if err := checkCredentialName(cred); err != nil {
		return "", "", err
	}
	return unit, cred, nil
}

// checkCredentialName accepts a systemd credential ID: a file name, of
// printable ASCII without ':' (LoadCredential= splits on it).
func checkCredentialName(s string) error {
	if s == "" || len(s) > 255 || s == "." || s == ".." {
		return fmt.Errorf("%q is not a credential name", s)
	}
	for i := 0; i < len(s); i++ {
		if b := s[i]; b <= ' ' || b >= 0x7f || b == '/' || b == ':' {
			return fmt.Errorf("%q is not a credential name (printable ASCII, no spaces, '/' or ':')", s)
		}
	}
	return nil
}

func isGlob(s string) bool { return strings.ContainsAny(s, "*?[") }

// hostPolicy is the policy file, checked and ready to match.
type hostPolicy struct {
	svrpc.HostPolicy
	clients []hostClient // Clients, compiled
}

type hostClient struct {
	user    string // as the policy names it
	uid     int    // when it names a uid; -1 for a name, looked up at each use
	program string
	refs    []svrpc.Ref
}

// runsAs reports whether the entry is for uid. A user name is looked up
// each time, so a user made after the policy was read counts.
func (c hostClient) runsAs(uid int) bool {
	if c.uid >= 0 {
		return c.uid == uid
	}
	n, err := lookupUser(c.user)
	return err == nil && n == uid
}

// policy returns the host policy. The file is read (and its owner and
// mode checked) on every use, which is rare, so an edit by hand counts at
// once; it is parsed again only when its contents change. A policy that
// cannot be read, or that anyone but root could have written, refuses
// everything.
func (h *hostState) policy(logf func(string)) (*hostPolicy, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.policyLocked(logf)
}

func (h *hostState) policyLocked(logf func(string)) (*hostPolicy, error) {
	b, err := readOwned(h.opts.Policy, false)
	if errors.Is(err, fs.ErrNotExist) {
		b, err = nil, nil // nothing is served
	}
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(b)
	if h.pol != nil && sum == h.polSum {
		return h.pol, nil
	}
	pol, warnings, err := parseHostPolicy(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", h.opts.Policy, err)
	}
	for _, w := range warnings {
		logf("the host policy: " + w)
	}
	h.pol, h.polSum = pol, sum
	return pol, nil
}

func parseHostPolicy(b []byte) (*hostPolicy, []string, error) {
	if len(b) == 0 {
		return &hostPolicy{}, nil, nil
	}
	var file svrpc.HostPolicy
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields() // a misspelt "program" must not widen anything
	if err := dec.Decode(&file); err != nil {
		return nil, nil, err
	}
	return compilePolicy(file)
}

// compilePolicy checks every entry. A user this host does not have is a
// warning (the entry matches nobody, until there is one), not an error:
// the policy may be shared between hosts.
func compilePolicy(file svrpc.HostPolicy) (*hostPolicy, []string, error) {
	p := &hostPolicy{HostPolicy: file}
	var warnings []string
	for i, c := range file.Credentials {
		if err := checkCredentialRule(c); err != nil {
			return nil, nil, fmt.Errorf("credential %d: %w", i+1, err)
		}
	}
	for i, c := range file.Clients {
		hc := hostClient{user: c.User, uid: -1, program: c.Program}
		uid, err := lookupUser(c.User)
		switch {
		case errors.Is(err, errNoUser):
			warnings = append(warnings, fmt.Sprintf("client %d: %v", i+1, err))
		case err != nil:
			return nil, nil, fmt.Errorf("client %d: %w", i+1, err)
		case c.User == strconv.Itoa(uid):
			hc.uid = uid
		}
		if c.Program != "" && !filepath.IsAbs(c.Program) {
			return nil, nil, fmt.Errorf("client %d: the program %q is not an absolute path", i+1, c.Program)
		}
		if len(c.Refs) == 0 {
			return nil, nil, fmt.Errorf("client %d lists no references", i+1)
		}
		for _, s := range c.Refs {
			r, err := parsePattern(s)
			if err != nil {
				return nil, nil, fmt.Errorf("client %d: %w", i+1, err)
			}
			hc.refs = append(hc.refs, r)
		}
		p.clients = append(p.clients, hc)
	}
	return p, warnings, nil
}

// checkCredentialRule checks one unit's credential.
func checkCredentialRule(c svrpc.HostCredential) error {
	if !unitGlob.MatchString(c.Unit) {
		return fmt.Errorf("%q is not a unit name, or a glob of one", c.Unit)
	}
	if _, err := path.Match(c.Unit, ""); err != nil {
		return fmt.Errorf("the glob %q: %v", c.Unit, err)
	}
	if err := checkCredentialName(c.Credential); err != nil {
		return err
	}
	if _, err := svrpc.ParseRef(c.Ref); err != nil {
		return err
	}
	return nil
}

// parsePattern reads a reference a local service may read, whose item
// and field may be globs.
func parsePattern(s string) (svrpc.Ref, error) {
	r, err := svrpc.ParseRef(s)
	if err != nil {
		return r, err
	}
	if _, err := path.Match(r.Item, ""); err != nil {
		return r, fmt.Errorf("%s: %v", s, err)
	}
	if _, err := path.Match(r.Field, ""); err != nil {
		return r, fmt.Errorf("%s: %v", s, err)
	}
	return r, nil
}

var errNoUser = errors.New("no such user")

// lookupUser reads a user name or a numeric uid.
func lookupUser(s string) (int, error) {
	if s == "" {
		return 0, errors.New("no user named (a user name or a numeric uid)")
	}
	if n, err := strconv.Atoi(s); err == nil {
		if n < 0 {
			return 0, fmt.Errorf("%d is not a uid", n)
		}
		return n, nil
	}
	u, err := user.Lookup(s)
	if err != nil {
		return 0, fmt.Errorf("%w %q on this host (a uid works for users not in /etc/passwd)", errNoUser, s)
	}
	return strconv.Atoi(u.Uid)
}

// credential finds the rule for a unit's credential: the unit's own name
// first, else the first glob that matches it.
func (p *hostPolicy) credential(unit, cred string) (svrpc.HostCredential, bool) {
	var glob *svrpc.HostCredential
	for i := range p.Credentials {
		c := &p.Credentials[i]
		if c.Credential != cred {
			continue
		}
		if c.Unit == unit {
			return *c, true
		}
		if glob == nil && isGlob(c.Unit) {
			if ok, _ := path.Match(c.Unit, unit); ok {
				glob = c
			}
		}
	}
	if glob != nil {
		return *glob, true
	}
	return svrpc.HostCredential{}, false
}

// clientMay reports whether a local service may read r. The uid is the
// kernel's word; the program narrows it, but anything running as that
// uid can pose as its programs (docs/security.md).
func (p *hostPolicy) clientMay(proc *svpeer.Process, r svrpc.Ref, defaultVault string) bool {
	vault := orDefault(r.Vault, defaultVault)
	for _, c := range p.clients {
		if c.program != "" && c.program != proc.Exe && c.program != proc.Script || !c.runsAs(proc.UID) {
			continue
		}
		for _, pat := range c.refs {
			if orDefault(pat.Vault, defaultVault) != vault {
				continue
			}
			if ok, _ := path.Match(pat.Item, r.Item); !ok {
				continue
			}
			if ok, _ := path.Match(pat.Field, r.Field); ok {
				return true
			}
		}
	}
	return false
}

func orDefault(vault, def string) string {
	if vault == "" {
		return def
	}
	return vault
}

func (d *Daemon) defaultVault() string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg.Default
}

// savePolicyLocked writes the policy file and makes it the current one.
func (h *hostState) savePolicyLocked(file svrpc.HostPolicy, pol *hostPolicy) error {
	if file.Credentials == nil {
		file.Credentials = []svrpc.HostCredential{}
	}
	if file.Clients == nil {
		file.Clients = []svrpc.HostClient{}
	}
	b, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if err := writeAtomic(h.opts.Policy, b); err != nil {
		return err
	}
	h.pol, h.polSum = pol, sha256.Sum256(b)
	return nil
}

// hostEvent records what the host daemon did: in its log (<Home>/host.log,
// one JSON object per line, which names units, items and programs but
// never a secret) and in the daemon's own (the journal).
func (d *Daemon) hostEvent(ev svrpc.HostEvent) {
	h := d.host
	ev.Time = d.opts.Now().UTC()
	switch ev.Outcome {
	case "delivered":
		h.delivered.Add(1)
	case "refused", "failed":
		h.refused.Add(1)
	}
	d.opts.Log(describeHostEvent(ev))
	b, err := json.Marshal(ev)
	if err != nil {
		return
	}
	h.logMu.Lock()
	defer h.logMu.Unlock()
	if st, err := os.Stat(h.log); err == nil && st.Size() > maxHostLog {
		os.Rename(h.log, h.log+".1")
	}
	f, err := os.OpenFile(h.log, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		d.opts.Log("the host log: " + err.Error())
		return
	}
	defer f.Close()
	if _, err := f.Write(append(b, '\n')); err != nil {
		d.opts.Log("the host log: " + err.Error())
	}
}

// describeHostEvent is a host event as a line of the journal.
func describeHostEvent(ev svrpc.HostEvent) string {
	if ev.Outcome == "changed" {
		return fmt.Sprintf("%s changed the host policy: %s", ev.Program, ev.Reason)
	}
	var what string
	switch {
	case ev.Unit != "":
		what = fmt.Sprintf("credential %s for %s", ev.Credential, ev.Unit)
		if ev.Ref != "" {
			what += " (" + ev.Ref + ")"
		}
	case ev.Ref != "":
		what = fmt.Sprintf("%s for %s, uid %d", ev.Ref, ev.Program, ev.UID)
	default:
		what = fmt.Sprintf("a request from process %d (uid %d)", ev.PID, ev.UID)
	}
	if ev.Outcome == "delivered" {
		return "delivered " + what
	}
	return ev.Outcome + " " + what + ": " + ev.Reason
}

// readHostLog returns the newest limit events (all when limit <= 0),
// oldest first.
func (h *hostState) readHostLog(limit int) ([]svrpc.HostEvent, error) {
	h.logMu.Lock()
	defer h.logMu.Unlock()
	f, err := os.Open(h.log)
	if errors.Is(err, fs.ErrNotExist) {
		return []svrpc.HostEvent{}, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	out := []svrpc.HostEvent{}
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 64<<10), 1<<20)
	for s.Scan() {
		var ev svrpc.HostEvent
		if json.Unmarshal(s.Bytes(), &ev) == nil {
			out = append(out, ev)
		}
		if limit > 0 && len(out) > limit {
			out = out[1:]
		}
	}
	return out, s.Err()
}

// hostSlot reports whether mv has a keyslot for the host identity.
func (d *Daemon) hostSlot(mv *managedVault) bool {
	if d.host.id == nil || mv.v == nil {
		return false
	}
	slots, err := mv.v.Slots()
	if err != nil {
		return false
	}
	for _, s := range slots {
		if s.Type == svformat.SlotRecipient && bytes.Equal(s.Recipient, d.host.id.Recipient()) {
			return true
		}
	}
	return false
}

func (d *Daemon) hostStatus() svrpc.HostStatus {
	h := d.host
	st := svrpc.HostStatus{
		Version: secretvault.Version, PID: os.Getpid(), Data: d.home,
		CredentialSocket: filepath.Join(h.opts.Runtime, svrpc.HostCredentialSocketName),
		ServiceSocket:    filepath.Join(h.opts.Runtime, svrpc.HostServiceSocketName),
		AdminSocket:      filepath.Join(h.opts.Runtime, svrpc.HostAdminSocketName),
		Policy:           h.opts.Policy,
		Delivered:        int(h.delivered.Load()),
		Refused:          int(h.refused.Load()),
		Vaults:           []svrpc.HostVault{},
	}
	if h.id != nil {
		st.Identity = h.idSource
		st.Recipient = svformat.EncodeRecipient(h.id.Suite(), h.id.Recipient())
	} else if h.idErr != nil {
		st.IdentityError = h.idErr.Error()
	}
	if pol, err := h.policy(d.opts.Log); err != nil {
		st.PolicyError = err.Error()
	} else {
		st.Credentials, st.Clients = len(pol.Credentials), len(pol.Clients)
	}
	for _, info := range d.vaultInfos() {
		hv := svrpc.HostVault{Name: info.Name, Locked: info.Locked, Missing: info.ID == ""}
		if mv, err := d.vault(info.Name); err == nil {
			hv.HostSlot = d.hostSlot(mv)
		}
		st.Vaults = append(st.Vaults, hv)
	}
	return st
}

// errNotHost answers a host method on a person's own daemon.
var errNotHost = svrpc.Errorf(svrpc.CodeMethodNotFound, "this is not the host daemon (secretvaultd --host): use 'secretvault --host' to reach that")

// hostAdmin wraps a host method only root, on the admin socket, may call.
func hostAdmin(h handler) handler {
	return func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		if d.host == nil {
			return nil, errNotHost
		}
		if cl.role != roleAdmin {
			return nil, svrpc.Errorf(svrpc.CodeDenied, "only root, on the host daemon's admin socket, may do that")
		}
		return h(d, ctx, cl, decode)
	}
}

func init() {
	registerMethod(svrpc.MHostResolve, (*Daemon).hostResolve)
	registerMethod(svrpc.MHostStatus, hostAdmin(func(d *Daemon, _ context.Context, _ *client, _ func(any) error) (any, error) {
		return d.hostStatus(), nil
	}))
	registerMethod(svrpc.MHostList, hostAdmin(func(d *Daemon, _ context.Context, _ *client, _ func(any) error) (any, error) {
		pol, err := d.host.policy(d.opts.Log)
		if err != nil {
			return nil, err
		}
		out := pol.HostPolicy
		if out.Credentials == nil {
			out.Credentials = []svrpc.HostCredential{}
		}
		if out.Clients == nil {
			out.Clients = []svrpc.HostClient{}
		}
		return out, nil
	}))
	registerMethod(svrpc.MHostAllow, hostAdmin((*Daemon).hostAllow))
	registerMethod(svrpc.MHostDeny, hostAdmin((*Daemon).hostDeny))
	registerMethod(svrpc.MHostAudit, hostAdmin(func(d *Daemon, _ context.Context, _ *client, decode func(any) error) (any, error) {
		var p svrpc.AuditParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		return d.host.readHostLog(p.Limit)
	}))
}

// hostResolve serves host.resolve: root may read anything, a local
// service what the policy lists for it.
func (d *Daemon) hostResolve(_ context.Context, cl *client, decode func(any) error) (any, error) {
	if d.host == nil {
		return nil, errNotHost
	}
	var p svrpc.HostResolveParams
	if err := decode(&p); err != nil {
		return nil, err
	}
	ev := svrpc.HostEvent{Program: cl.display(), UID: cl.proc.UID, PID: cl.proc.PID, Ref: p.Ref}
	r, err := svrpc.ParseRef(p.Ref)
	if err != nil {
		ev.Outcome, ev.Reason = "refused", err.Error()
		d.hostEvent(ev)
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	ev.Ref = r.String()
	if cl.role != roleAdmin {
		pol, err := d.host.policy(d.opts.Log)
		reason := "not in the host policy"
		if err != nil {
			reason = "the host policy cannot be read: " + err.Error()
		}
		if err != nil || !pol.clientMay(cl.proc, r, d.defaultVault()) {
			ev.Outcome, ev.Reason = "refused", reason
			d.hostEvent(ev)
			return nil, svrpc.Errorf(svrpc.CodeDenied, "the host policy does not let %s, run by uid %d, read %s", cl.display(), cl.proc.UID, r)
		}
	}
	entry := svbroker.Entry{Program: fmt.Sprintf("%s, uid %d", cl.display(), cl.proc.UID),
		Identity: fmt.Sprintf("uid:%d %s", cl.proc.UID, cl.identity()), PID: cl.proc.PID,
		Op: svbroker.OpRead, Item: r.Item, Reason: "host policy"}
	if cl.role == roleAdmin {
		entry.Reason = "the host's administrator"
	}
	mv, value, err := d.hostRead(r)
	if err != nil {
		if mv != nil {
			entry.Outcome = "failed"
			d.audit.Record(mv.v, entry)
		}
		ev.Outcome, ev.Reason = "failed", strings.TrimPrefix(err.Error(), "svcore: ")
		d.hostEvent(ev)
		return nil, err
	}
	entry.Outcome = "allowed"
	d.audit.Record(mv.v, entry)
	ev.Outcome = "delivered"
	d.hostEvent(ev)
	return svrpc.HostResolveResult{Value: value}, nil
}

// hostAllow adds a rule to the policy.
func (d *Daemon) hostAllow(_ context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.HostRule
	if err := decode(&p); err != nil {
		return nil, err
	}
	var what string
	var refs []string
	warnings, err := d.changePolicy(func(file *svrpc.HostPolicy) error {
		switch {
		case p.Unit != "" || p.Credential != "":
			r, err := svrpc.ParseRef(p.Ref)
			if err != nil {
				return err
			}
			rule := svrpc.HostCredential{Unit: p.Unit, Credential: p.Credential, Ref: r.String()}
			replaced := false
			for i, c := range file.Credentials {
				if c.Unit == rule.Unit && c.Credential == rule.Credential {
					file.Credentials[i], replaced = rule, true
				}
			}
			if !replaced {
				file.Credentials = append(file.Credentials, rule)
			}
			what = fmt.Sprintf("%s gets its credential %s from %s", rule.Unit, rule.Credential, rule.Ref)
			refs = []string{rule.Ref}
		case p.User != "":
			if len(p.Refs) == 0 {
				return errors.New("name at least one sv:// reference the service may read")
			}
			i, err := findClient(*file, p.User, p.Program)
			if err != nil {
				return err
			}
			if i < 0 {
				file.Clients = append(file.Clients, svrpc.HostClient{User: p.User, Program: p.Program})
				i = len(file.Clients) - 1
			}
			for _, s := range p.Refs {
				r, err := parsePattern(s)
				if err != nil {
					return err
				}
				if !contains(file.Clients[i].Refs, r.String()) {
					file.Clients[i].Refs = append(file.Clients[i].Refs, r.String())
					refs = append(refs, r.String())
				}
			}
			what = fmt.Sprintf("%s may read %s", clientName(p.User, p.Program), strings.Join(p.Refs, ", "))
		default:
			return errors.New("name a unit and a credential, or a user")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	d.hostEvent(svrpc.HostEvent{Outcome: "changed", Program: cl.display(), UID: cl.proc.UID, PID: cl.proc.PID,
		Unit: p.Unit, Credential: p.Credential, Reason: "allowed: " + what})
	if p.Program != "" {
		if _, err := os.Stat(p.Program); err != nil {
			warnings = append(warnings, fmt.Sprintf("%s is not there (yet)", p.Program))
		}
	}
	return svrpc.HostAllowResult{Warnings: append(warnings, d.refWarnings(refs)...)}, nil
}

// hostDeny removes a rule from the policy.
func (d *Daemon) hostDeny(_ context.Context, cl *client, decode func(any) error) (any, error) {
	var p svrpc.HostRule
	if err := decode(&p); err != nil {
		return nil, err
	}
	var what string
	_, err := d.changePolicy(func(file *svrpc.HostPolicy) error {
		switch {
		case p.Unit != "" || p.Credential != "":
			kept := file.Credentials[:0]
			for _, c := range file.Credentials {
				if c.Unit != p.Unit || c.Credential != p.Credential {
					kept = append(kept, c)
				}
			}
			if len(kept) == len(file.Credentials) {
				return svrpc.Errorf(svrpc.CodeNotFound, "the host policy gives %s no credential %s", p.Unit, p.Credential)
			}
			file.Credentials = kept
			what = fmt.Sprintf("%s no longer gets its credential %s", p.Unit, p.Credential)
		case p.User != "":
			i, err := findClient(*file, p.User, p.Program)
			if err != nil {
				return err
			}
			if i < 0 {
				return svrpc.Errorf(svrpc.CodeNotFound, "the host policy has no entry for %s", clientName(p.User, p.Program))
			}
			c := &file.Clients[i]
			what = fmt.Sprintf("%s may read nothing", clientName(p.User, p.Program))
			if len(p.Refs) > 0 {
				var gone []string
				for _, s := range p.Refs {
					r, err := svrpc.ParseRef(s)
					if err != nil {
						return err
					}
					if !contains(c.Refs, r.String()) {
						return svrpc.Errorf(svrpc.CodeNotFound, "%s may not read %s already", clientName(p.User, p.Program), r)
					}
					gone = append(gone, r.String())
				}
				var kept []string
				for _, s := range c.Refs {
					if !contains(gone, s) {
						kept = append(kept, s)
					}
				}
				c.Refs = kept
				what = fmt.Sprintf("%s may no longer read %s", clientName(p.User, p.Program), strings.Join(gone, ", "))
			}
			if len(p.Refs) == 0 || len(c.Refs) == 0 {
				file.Clients = append(file.Clients[:i], file.Clients[i+1:]...)
			}
		default:
			return errors.New("name a unit and a credential, or a user")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	d.hostEvent(svrpc.HostEvent{Outcome: "changed", Program: cl.display(), UID: cl.proc.UID, PID: cl.proc.PID,
		Unit: p.Unit, Credential: p.Credential, Reason: "denied: " + what})
	return nil, nil
}

// changePolicy reads the policy, lets change edit it, checks the result
// and writes it, all under the policy's lock. An error from change that
// is not already a protocol error is a bad request.
func (d *Daemon) changePolicy(change func(*svrpc.HostPolicy) error) (warnings []string, err error) {
	h := d.host
	h.mu.Lock()
	defer h.mu.Unlock()
	pol, err := h.policyLocked(d.opts.Log)
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeFailed, "the host policy cannot be read, so it is left alone: %v", err)
	}
	file := clonePolicy(pol.HostPolicy)
	if err := change(&file); err != nil {
		var e *svrpc.Error
		if errors.As(err, &e) {
			return nil, err
		}
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	newPol, warnings, err := compilePolicy(file)
	if err != nil {
		return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "%v", err)
	}
	return warnings, h.savePolicyLocked(file, newPol)
}

// findClient finds the entry for a user (by uid, however it is written)
// and program; -1 when there is none.
func findClient(file svrpc.HostPolicy, userName, program string) (int, error) {
	uid, err := lookupUser(userName)
	if err != nil {
		return -1, err
	}
	for i, c := range file.Clients {
		if cuid, err := lookupUser(c.User); err == nil && cuid == uid && c.Program == program {
			return i, nil
		}
	}
	return -1, nil
}

func clientName(userName, program string) string {
	if program == "" {
		return "user " + userName
	}
	return program + " run by user " + userName
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

func clonePolicy(p svrpc.HostPolicy) svrpc.HostPolicy {
	out := svrpc.HostPolicy{Credentials: append([]svrpc.HostCredential(nil), p.Credentials...)}
	for _, c := range p.Clients {
		c.Refs = append([]string(nil), c.Refs...)
		out.Clients = append(out.Clients, c)
	}
	return out
}

// refWarnings says what keeps references from resolving now, for root,
// who just allowed them: a vault that is not here, or that the host
// cannot open, an item or field that is not there.
func (d *Daemon) refWarnings(refs []string) []string {
	var out []string
	for _, s := range refs {
		r, err := svrpc.ParseRef(s)
		if err != nil {
			continue
		}
		if _, err := d.vault(r.Vault); err != nil {
			out = append(out, fmt.Sprintf("%s: %v", r, err))
			continue
		}
		if isGlob(r.Item) || isGlob(r.Field) {
			continue
		}
		_, v, err := d.hostRead(r)
		clear(v)
		if err != nil {
			out = append(out, fmt.Sprintf("%s: %v", r, err))
		}
	}
	return out
}
