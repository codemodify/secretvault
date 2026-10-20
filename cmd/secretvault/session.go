package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svops"
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
		return svops.KeyFromFile(svformat.SlotKeyfile, u.keyfile)
	case u.identity != "":
		return svops.KeyFromFile("identity", u.identity)
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
		return svops.KeyFromFile(svformat.SlotPassphrase, u.passFile)
	}
	return nil, nil
}

// askShares asks for recovery shares until there are as many as the
// first one says it takes, and returns the recovery key they rebuild, as
// text. A share typed twice, or from another split, is caught there, or
// by the key's own checksum.
func (c *cli) askShares() ([]byte, error) {
	var shares svops.ShareCollector
	defer shares.Wipe()
	for !shares.Done() {
		prompt := fmt.Sprintf("Recovery share %d: ", shares.Have()+1)
		if shares.Need() > 0 {
			prompt = fmt.Sprintf("Recovery share %d of %d: ", shares.Have()+1, shares.Need())
		}
		b, err := c.ask(prompt)
		if err != nil {
			return nil, err
		}
		err = shares.Add(b)
		clear(b)
		if err != nil {
			fmt.Fprintln(c.stderr, err)
		}
	}
	return shares.Key()
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

// newPassphrase gets a new passphrase from a file or the terminal.
func (c *cli) newPassphrase(file string) ([]byte, error) {
	if file != "" {
		p, err := svops.ReadSecretFile(file)
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

// confirm asks a yes-or-no question on the terminal. Only yes is yes:
// Enter, like anything else, is no.
func (c *cli) confirm(prompt string) (bool, error) {
	var answer string
	if c.askLine != nil {
		a, err := c.askLine(prompt)
		if err != nil {
			return false, err
		}
		answer = a
	} else {
		a, err := c.ask(prompt)
		if err != nil {
			return false, err
		}
		answer = string(a)
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	}
	return false, nil
}
