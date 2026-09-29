package svsync

import (
	"context"
	"time"

	"github.com/codemodify/secretvault/svserver"
	"github.com/codemodify/secretvault/svstore"
)

// WatchOptions configure Watch.
type WatchOptions struct {
	// Every is the longest Watch goes without syncing, which is what sends
	// this device's own writes when nothing triggers it. Default 1 minute.
	Every time.Duration

	// Wait is how long each long poll lasts. Default 50 seconds; at most
	// svserver.MaxWait.
	Wait time.Duration

	// Trigger makes Watch sync at once when it receives: the daemon sends
	// on it (without blocking, into a buffer of one) after writing to the
	// vault.
	Trigger <-chan struct{}

	// Changed is called after a sync that changed the local folder: the
	// open vault should be refreshed (svcore.Vault.Refresh).
	Changed func(Report)

	// Failed is called after a sync that failed. Watch tries again after
	// a pause that doubles with every failure, up to MaxBackoff.
	Failed func(error)
}

// MaxBackoff is the longest Watch waits after a failed sync.
const MaxBackoff = 5 * time.Minute

// Watch keeps a local vault folder in sync with the server until ctx
// ends: it syncs, then holds a long poll open on the server's change log,
// and syncs again as soon as the server reports a change, Trigger fires,
// or Every has passed. It returns ctx's error.
func Watch(ctx context.Context, local svstore.Backend, c *Client, st *State, o WatchOptions) error {
	if o.Every <= 0 {
		o.Every = time.Minute
	}
	if o.Wait <= 0 {
		o.Wait = 50 * time.Second
	}
	o.Wait = min(o.Wait, svserver.MaxWait)
	var backoff time.Duration
	for {
		rep, err := Sync(ctx, local, c, st)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if rep.Changed() && o.Changed != nil {
			o.Changed(rep)
		}
		if err != nil {
			if o.Failed != nil {
				o.Failed(err)
			}
			backoff = min(max(2*backoff, time.Second), MaxBackoff)
			pause(ctx, backoff, o.Trigger)
			continue
		}
		backoff = 0
		waitForWork(ctx, c, st, o)
		if ctx.Err() != nil {
			return ctx.Err()
		}
	}
}

// pause waits for d, a trigger, or ctx.
func pause(ctx context.Context, d time.Duration, trigger <-chan struct{}) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-trigger:
	case <-ctx.Done():
	}
}

// waitForWork returns when there is something to sync: the server has a
// change after the cursor, a trigger fired, or Every has passed.
func waitForWork(ctx context.Context, c *Client, st *State, o WatchOptions) {
	deadline := time.Now().Add(o.Every)
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	go func() {
		select {
		case <-o.Trigger:
			cancel()
		case <-ctx.Done():
		}
	}()
	for ctx.Err() == nil {
		wait := min(o.Wait, time.Until(deadline))
		if wait < time.Second {
			break
		}
		st.mu.Lock()
		log, cursor := st.Log, st.Cursor
		st.mu.Unlock()
		cs, err := c.Changes(ctx, cursor, wait, 1)
		if err != nil {
			// Unreachable, or refusing: the next sync reports it.
			<-ctx.Done()
			return
		}
		if len(cs.Changes) > 0 || cs.Log != log || cs.Latest != cursor {
			return
		}
	}
	<-ctx.Done()
}
