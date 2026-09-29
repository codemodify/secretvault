package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// Talking to the daemon, and answering its questions on this terminal.

// timeout bounds one command, prompts included.
const timeout = 5 * time.Minute

func (c *cli) ctx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// daemon returns the connection to secretvaultd, connecting on first use.
func (c *cli) daemon() (*secretvault.Client, error) {
	if c.client != nil {
		return c.client, nil
	}
	opts := secretvault.Options{Name: "secretvault"}
	if c.clientName != "" {
		opts.Name = c.clientName
	}
	if c.canAsk {
		opts.Prompter = c.answer
	}
	if c.host || c.hostAdmin {
		// The host daemon runs as a system service: nothing starts it
		// from here, and it asks nobody.
		opts.Socket, opts.NoStart, opts.Prompter = svrpc.HostSocket(), true, nil
		if c.hostAdmin || c.isRoot() {
			opts.Socket = svrpc.HostAdminSocket()
		}
	}
	cl, err := c.connect(opts)
	if err != nil {
		if opts.NoStart && errors.Is(err, secretvault.ErrNoDaemon) {
			why := "is secretvaultd-host.service running?"
			if opts.Socket == svrpc.HostAdminSocket() {
				why += " Its admin socket is root's alone."
			}
			return nil, fmt.Errorf("the host daemon does not answer on %s: %v; %s", opts.Socket, err, why)
		}
		return nil, err
	}
	c.client = cl
	return cl, nil
}

// isRoot reports whether this runs as root.
func (c *cli) isRoot() bool {
	if c.root != nil {
		return c.root()
	}
	return os.Geteuid() == 0
}

// answer puts the daemon's question to the person at this terminal.
func (c *cli) answer(_ context.Context, q svrpc.PromptAsk) (svrpc.PromptAnswer, error) {
	fmt.Fprintln(c.stderr)
	if q.Description != "" {
		fmt.Fprintln(c.stderr, q.Description)
	}
	if q.Error != "" {
		fmt.Fprintln(c.stderr, "!", q.Error)
	}
	prompt := strings.TrimSpace(q.Prompt)
	if prompt == "" {
		prompt = "Passphrase:"
	}
	var secret []byte
	var err error
	switch q.Kind {
	case svrpc.PromptPassphrase, svrpc.PromptPIN:
		secret, err = c.ask(prompt + " ")
	case svrpc.PromptNewPassphrase:
		secret, err = c.askNew(prompt+" ", minPassphrase)
	case svrpc.PromptNotice:
		return svrpc.PromptAnswer{}, nil // said above; nothing to answer
	default:
		return svrpc.PromptAnswer{Canceled: true}, nil
	}
	if err != nil || len(secret) == 0 {
		return svrpc.PromptAnswer{Canceled: true}, nil
	}
	return svrpc.PromptAnswer{Secret: secret}, nil
}

// unlockFlags choose a key to present up front, instead of being asked.
type unlockFlags struct {
	passFile string
	keyfile  string
	identity string
	recovery bool
	shares   bool
	fido2    bool
}

func (u *unlockFlags) register(fs *flag.FlagSet) {
	fs.StringVar(&u.passFile, "passphrase-file", "", "unlock with the passphrase in `FILE`")
	fs.StringVar(&u.keyfile, "keyfile", "", "unlock with the keyfile at `PATH`")
	fs.StringVar(&u.identity, "identity", "", "unlock with the identity in `FILE`")
	fs.BoolVar(&u.recovery, "recovery", false, "unlock with a recovery key (asked for on the terminal)")
	fs.BoolVar(&u.shares, "shares", false, "unlock with shares of a recovery key (asked for on the terminal)")
	fs.BoolVar(&u.fido2, "fido2", false, "unlock with the security key plugged in (its PIN, if it needs one, is asked for here)")
}

func (u *unlockFlags) given() bool {
	return u.passFile != "" || u.keyfile != "" || u.identity != "" || u.recovery || u.shares || u.fido2
}

// key reads the key the flags name. The caller zeroes Secret.
func (c *cli) key(u *unlockFlags) (*svrpc.Key, error) {
	switch {
	case u.fido2:
		return &svrpc.Key{Type: svformat.SlotFIDO2}, nil
	case u.keyfile != "":
		b, err := os.ReadFile(u.keyfile)
		return &svrpc.Key{Type: svformat.SlotKeyfile, Secret: b}, err
	case u.identity != "":
		b, err := os.ReadFile(u.identity)
		return &svrpc.Key{Type: "identity", Secret: b}, err
	case u.recovery:
		if !c.canAsk {
			return nil, errors.New("no terminal to type the recovery key on")
		}
		b, err := c.ask("Recovery key: ")
		return &svrpc.Key{Type: svformat.SlotRecovery, Secret: b}, err
	case u.shares:
		if !c.canAsk {
			return nil, errors.New("no terminal to type the recovery shares on")
		}
		rk, err := c.askShares()
		return &svrpc.Key{Type: svformat.SlotRecovery, Secret: rk}, err
	case u.passFile != "":
		b, err := readSecretFile(u.passFile)
		return &svrpc.Key{Type: svformat.SlotPassphrase, Secret: b}, err
	}
	return nil, nil
}

// askShares asks for recovery shares until there are as many as the
// first one says it takes, and returns the recovery key they rebuild, as
// text. A share typed twice, or from another split, is caught there, or
// by the key's own checksum.
func (c *cli) askShares() ([]byte, error) {
	var shares [][]byte
	defer func() {
		for _, s := range shares {
			clear(s)
		}
	}()
	need := 0
	for need == 0 || len(shares) < need {
		prompt := fmt.Sprintf("Recovery share %d: ", len(shares)+1)
		if need > 0 {
			prompt = fmt.Sprintf("Recovery share %d of %d: ", len(shares)+1, need)
		}
		b, err := c.ask(prompt)
		if err != nil {
			return nil, err
		}
		share, k, err := svformat.ParseRecoveryShare(string(b))
		clear(b)
		if err != nil {
			fmt.Fprintln(c.stderr, strings.TrimPrefix(err.Error(), "svformat: "))
			continue
		}
		if need != 0 && k != need {
			clear(share)
			fmt.Fprintf(c.stderr, "That share is from a split that needs %d, not %d: it belongs to another recovery key.\n", k, need)
			continue
		}
		need = k
		shares = append(shares, share)
	}
	rk, err := svcrypto.CombineShares(shares)
	if err != nil {
		return nil, fmt.Errorf("those shares do not fit together: %w", err)
	}
	defer clear(rk)
	return []byte(svformat.EncodeRecoveryKey(rk)), nil
}

// open connects and, when the flags name a key, presents it: that unlocks
// the vault if needed and proves this command may use it.
func (c *cli) open(u *unlockFlags) (*secretvault.Client, error) {
	cl, err := c.daemon()
	if err != nil {
		return nil, err
	}
	if u == nil || !u.given() {
		return cl, nil
	}
	k, err := c.key(u)
	if err != nil {
		return nil, err
	}
	defer clear(k.Secret)
	ctx, cancel := c.ctx()
	defer cancel()
	if _, err := cl.Unlock(ctx, c.vault, k); err != nil {
		return nil, err
	}
	return cl, nil
}

// readSecretFile reads a secret from a file, without its final newline.
func readSecretFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return trimNewline(b), nil
}

func trimNewline(b []byte) []byte {
	b = bytes.TrimSuffix(b, []byte("\n"))
	return bytes.TrimSuffix(b, []byte("\r"))
}

// newPassphrase gets a new passphrase from a file or the terminal.
func (c *cli) newPassphrase(file string) ([]byte, error) {
	if file != "" {
		p, err := readSecretFile(file)
		if err == nil && len(p) < minPassphrase {
			return nil, fmt.Errorf("the passphrase is too short: use at least %d characters", minPassphrase)
		}
		return p, err
	}
	if !c.canAsk {
		return nil, errors.New("no terminal to ask for the new passphrase on; use --passphrase-file")
	}
	return c.askNew("New passphrase: ", minPassphrase)
}

func readIdentity(path string) (*svcrypto.Identity, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		suite, priv, err := svformat.ParseIdentity(line)
		if err != nil {
			return nil, err
		}
		defer clear(priv)
		return suite.ParseIdentity(priv)
	}
	return nil, fmt.Errorf("%s holds no identity", path)
}

// recipientArg reads a recipient given as text, as a file holding one, or
// as an identity file (whose public half is the recipient), and returns
// its text form.
func recipientArg(arg string) (string, error) {
	if suite, pub, err := svformat.ParseRecipient(arg); err == nil {
		return svformat.EncodeRecipient(suite, pub), nil
	}
	b, err := os.ReadFile(arg)
	if err != nil {
		return "", fmt.Errorf("%q is neither a recipient nor a readable file", arg)
	}
	for _, line := range strings.Split(string(b), "\n") {
		if suite, pub, err := svformat.ParseRecipient(line); err == nil {
			return svformat.EncodeRecipient(suite, pub), nil
		}
	}
	clear(b)
	id, err := readIdentity(arg)
	if err != nil {
		return "", fmt.Errorf("%s holds no recipient or identity", arg)
	}
	return svformat.EncodeRecipient(id.Suite(), id.Recipient()), nil
}

// writeNew creates a file that must not exist yet, mode 0600.
func writeNew(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	return err
}
