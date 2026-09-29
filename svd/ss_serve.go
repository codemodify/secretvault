package svd

import (
	"context"
	"errors"

	"github.com/codemodify/secretvault/svdbus"
)

// Running the Secret Service face as the config says.

// SSHAgentEnabled reports whether the config wants the SSH agent socket.
func (d *Daemon) SSHAgentEnabled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return !d.cfg.NoSSHAgent
}

// SecretServiceEnabled reports whether the config asks for the Secret
// Service.
func (d *Daemon) SecretServiceEnabled() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cfg.SecretService
}

// StartSecretService connects to the session bus and serves the Secret
// Service there, queueing behind another keyring if one holds the name.
func (d *Daemon) StartSecretService(ctx context.Context) error {
	d.mu.Lock()
	running := d.ssStop != nil
	d.mu.Unlock()
	if running {
		return nil
	}
	bus, err := svdbus.ConnectSession(svdbus.WithMaxMessageSize(1 << 20))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	if err := d.ServeSecretService(ctx, bus, true); err != nil {
		cancel()
		bus.Close()
		return err
	}
	d.mu.Lock()
	d.ssStop = func() { cancel(); bus.Close() }
	d.mu.Unlock()
	go func() { <-ctx.Done(); bus.Close() }()
	return nil
}

// StopSecretService stops serving (the name goes back to whoever queued).
func (d *Daemon) StopSecretService() {
	d.mu.Lock()
	stop := d.ssStop
	d.ssStop, d.ss = nil, nil
	d.mu.Unlock()
	if stop != nil {
		stop()
	}
}

// setSecretService records the choice and acts on it.
func (d *Daemon) setSecretService(ctx context.Context, on bool) error {
	d.mu.Lock()
	d.cfg.SecretService = on
	err := d.cfg.save(d.home)
	d.mu.Unlock()
	if err != nil {
		return err
	}
	if !on {
		d.StopSecretService()
		return nil
	}
	return d.StartSecretService(context.WithoutCancel(ctx))
}

// secretServiceState says what the face is doing, for status output.
func (d *Daemon) secretServiceState(ctx context.Context) string {
	d.mu.Lock()
	ss, on := d.ss, d.cfg.SecretService
	d.mu.Unlock()
	switch {
	case !on:
		return "off"
	case ss == nil:
		return "on, but not running"
	}
	owner, err := ss.bus.GetNameOwner(ctx, ssBusName)
	if err == nil && owner == ss.bus.UniqueName() {
		return "serving org.freedesktop.secrets"
	}
	return "waiting for another keyring to let go of org.freedesktop.secrets"
}

var errNotCLI = errors.New("only secretvault's own commands may change this")
