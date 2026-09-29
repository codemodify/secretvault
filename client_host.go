package secretvault

import (
	"context"

	"github.com/codemodify/secretvault/svrpc"
)

// The host daemon (secretvaultd --host). A machine's services connect to
// svrpc.HostSocket(), without starting anything:
//
//	c, err := secretvault.Connect(secretvault.Options{Socket: svrpc.HostSocket(), NoStart: true})
//	...
//	v, err := c.HostResolve(ctx, "sv://prod/db/postgres#password")
//
// and get what the host's policy lists for their uid and program; the
// other methods are for root, on svrpc.HostAdminSocket().

// HostResolve reads the value an sv:// reference names. The caller should
// zero it when done.
func (c *Client) HostResolve(ctx context.Context, ref string) ([]byte, error) {
	var out svrpc.HostResolveResult
	err := c.conn.Call(ctx, svrpc.MHostResolve, svrpc.HostResolveParams{Ref: ref}, &out)
	return out.Value, err
}

// HostStatus describes the host daemon.
func (c *Client) HostStatus(ctx context.Context) (out svrpc.HostStatus, err error) {
	err = c.conn.Call(ctx, svrpc.MHostStatus, nil, &out)
	return
}

// HostPolicy returns what the host daemon serves, and to whom.
func (c *Client) HostPolicy(ctx context.Context) (out svrpc.HostPolicy, err error) {
	err = c.conn.Call(ctx, svrpc.MHostList, nil, &out)
	return
}

// HostAllow adds a rule to the host's policy (see svrpc.HostRule).
func (c *Client) HostAllow(ctx context.Context, r svrpc.HostRule) (out svrpc.HostAllowResult, err error) {
	err = c.conn.Call(ctx, svrpc.MHostAllow, r, &out)
	return
}

// HostDeny removes a rule from the host's policy.
func (c *Client) HostDeny(ctx context.Context, r svrpc.HostRule) error {
	return c.conn.Call(ctx, svrpc.MHostDeny, r, nil)
}

// HostAudit returns the newest limit lines of the host's log (all when
// limit <= 0), oldest first.
func (c *Client) HostAudit(ctx context.Context, limit int) (out []svrpc.HostEvent, err error) {
	err = c.conn.Call(ctx, svrpc.MHostAudit, svrpc.AuditParams{Limit: limit}, &out)
	return
}
