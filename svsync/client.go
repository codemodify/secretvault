package svsync

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/codemodify/secretvault/svserver"
)

// Device is a device enrolled in a vault on a server.
type Device = svserver.Device

// Errors a server answers with. A *ServerError matches the one for its
// status with errors.Is.
var (
	ErrUnauthenticated = errors.New("svsync: the server did not accept this device's signature")
	ErrNotEnrolled     = errors.New("svsync: this device is not enrolled in the vault on the server (or it has no such vault)")
	ErrNotFound        = errors.New("svsync: not on the server")
	ErrConflict        = errors.New("svsync: the server holds something different")
	ErrGone            = errors.New("svsync: removed from the server for good")
	ErrRateLimited     = errors.New("svsync: the server asks this device to slow down")
)

// ServerError is a request the server refused.
type ServerError struct {
	Method, Path string
	Status       int
	Message      string
}

func (e *ServerError) Error() string {
	return fmt.Sprintf("svsync: %s %s: %d %s", e.Method, e.Path, e.Status, e.Message)
}

func (e *ServerError) Is(target error) bool {
	switch e.Status {
	case http.StatusUnauthorized:
		return target == ErrUnauthenticated
	case http.StatusForbidden:
		return target == ErrNotEnrolled
	case http.StatusNotFound:
		return target == ErrNotFound
	case http.StatusConflict:
		return target == ErrConflict
	case http.StatusGone:
		return target == ErrGone
	case http.StatusTooManyRequests:
		return target == ErrRateLimited
	}
	return false
}

// Client talks to one vault on one server, signing every request with
// this device's identity. It is safe for concurrent use.
type Client struct {
	remote Remote
	base   *url.URL
	id     *Identity

	// HTTP carries the requests. NewClient sets it up to pin the server's
	// certificate; tests wrap its Transport.
	HTTP *http.Client

	// Now is the clock requests are signed with. Defaults to time.Now.
	Now func() time.Time
}

// NewClient returns a client for r, signing as id.
func NewClient(r Remote, id *Identity) (*Client, error) {
	base, err := r.base()
	if err != nil {
		return nil, err
	}
	pin, _ := parseFingerprint(r.Fingerprint)
	return &Client{remote: r, base: base, id: id, HTTP: newHTTPClient(pin), Now: time.Now}, nil
}

// Remote is where the client syncs to.
func (c *Client) Remote() Remote { return c.remote }

// Identity is the key the client signs with.
func (c *Client) Identity() *Identity { return c.id }

// requestTimeout bounds a request that is not a long poll.
const requestTimeout = 2 * time.Minute

// maxResponse is the largest answer read: well above any file a server
// accepts by default.
const maxResponse = 256 << 20

// do sends a signed request for the vault: suffix is the part of the path
// after /v1/vaults/{vault}. A 2xx answer is decoded into out (unless out is
// nil or the body is empty); anything else is a *ServerError. A request
// the server asks to slow down is sent again, a few times, after the
// pause it asks for.
func (c *Client) do(ctx context.Context, method, suffix, query string, body []byte, out any) (int, []byte, error) {
	path := "/v1/vaults/" + c.remote.Vault + suffix
	target := path
	if query != "" {
		target += "?" + query
	}
	for attempt := 0; ; attempt++ {
		status, data, retry, err := c.once(ctx, method, path, query, body)
		if err != nil {
			return 0, nil, err
		}
		if status == http.StatusTooManyRequests && attempt < 3 && retry > 0 && retry <= 10*time.Second {
			select {
			case <-time.After(retry):
				continue
			case <-ctx.Done():
				return 0, nil, ctx.Err()
			}
		}
		if status < 200 || status > 299 {
			var e svserver.ErrorBody
			if json.Unmarshal(data, &e) != nil || e.Error == "" {
				e.Error = http.StatusText(status)
			}
			return status, nil, &ServerError{Method: method, Path: target, Status: status, Message: e.Error}
		}
		if out != nil && len(data) > 0 {
			if err := json.Unmarshal(data, out); err != nil {
				return status, nil, fmt.Errorf("svsync: %s %s: the answer is not understood: %w", method, target, err)
			}
		}
		return status, data, nil
	}
}

// once sends one signed request. The signature covers the path from /v1/
// on, whatever prefix the server's URL has.
func (c *Client) once(ctx context.Context, method, path, query string, body []byte) (status int, data []byte, retry time.Duration, err error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, requestTimeout)
		defer cancel()
	}
	u := *c.base
	u.Path += path
	u.RawQuery = query
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(body))
	if err != nil {
		return 0, nil, 0, err
	}
	target := path
	if query != "" {
		target += "?" + query
	}
	req.Header.Set("Authorization", svserver.Authorization(c.id.key, method, target, body, c.Now()))
	if body != nil {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return 0, nil, 0, err
	}
	defer resp.Body.Close()
	data, err = io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return 0, nil, 0, err
	}
	if len(data) > maxResponse {
		return 0, nil, 0, fmt.Errorf("svsync: %s %s: the answer is larger than %d bytes", method, target, maxResponse)
	}
	if s, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil {
		retry = time.Duration(s) * time.Second
	}
	return resp.StatusCode, data, retry, nil
}

// CreateVault makes the vault on the server, with this device as its first
// device. adminToken is the server's, unless it is open for registration;
// label names this device to the others ("" for none). Making a vault
// this device made already is not an error.
func (c *Client) CreateVault(ctx context.Context, adminToken, label string) error {
	body, _ := json.Marshal(svserver.CreateVaultRequest{AdminToken: adminToken, Label: label})
	_, _, err := c.do(ctx, "POST", "", "", body, nil)
	return err
}

// Enrol asks for a one-time code with which one more device can join the
// vault, and returns it as an invite to hand to that device.
func (c *Client) Enrol(ctx context.Context) (Invite, error) {
	var e svserver.Enrolment
	if _, _, err := c.do(ctx, "POST", "/enrol", "", nil, &e); err != nil {
		return Invite{}, err
	}
	return Invite{Remote: c.remote, Code: e.Code, Expires: e.Expires}, nil
}

// Join enrols this device in the vault with a code from Enrol. Joining
// again once enrolled is not an error.
func (c *Client) Join(ctx context.Context, code, label string) error {
	body, _ := json.Marshal(svserver.JoinRequest{Code: code, Label: label})
	_, _, err := c.do(ctx, "POST", "/devices", "", body, nil)
	return err
}

// Devices lists the devices enrolled in the vault.
func (c *Client) Devices(ctx context.Context) ([]Device, error) {
	var out []Device
	_, _, err := c.do(ctx, "GET", "/devices", "", nil, &out)
	return out, err
}

// RemoveDevice removes a device (by its Key) from the vault on the server.
// It stops syncing; it keeps whatever it already has, and whatever key it
// opens the vault with (removing that needs a keyslot removal and a
// rotation).
func (c *Client) RemoveDevice(ctx context.Context, key string) error {
	if _, err := svserver.DecodeKey(key); err != nil {
		return err
	}
	_, _, err := c.do(ctx, "DELETE", "/devices/"+key, "", nil, nil)
	return err
}

// Put stores a file, returning the sequence number of the change that
// stored it. ErrConflict means the server holds other bytes under the
// name; ErrGone, that it is a keyslot removed for good.
func (c *Client) Put(ctx context.Context, name string, data []byte) (uint64, error) {
	var r svserver.PutResult
	if data == nil {
		data = []byte{}
	}
	_, _, err := c.do(ctx, "PUT", "/files/"+name, "", data, &r)
	return r.Seq, err
}

// Get fetches a file. ErrNotFound means the server has none of that name.
func (c *Client) Get(ctx context.Context, name string) ([]byte, error) {
	_, data, err := c.do(ctx, "GET", "/files/"+name, "", nil, nil)
	if data == nil && err == nil {
		data = []byte{}
	}
	return data, err
}

// Delete removes a keyslot, returning the sequence number of its removal.
func (c *Client) Delete(ctx context.Context, name string) (uint64, error) {
	var r svserver.PutResult
	_, _, err := c.do(ctx, "DELETE", "/files/"+name, "", nil, &r)
	return r.Seq, err
}

// Changes returns up to limit changes after seq (0 for the server's
// default). With wait, the server holds the request until there is one,
// or wait (at most a minute) has passed.
func (c *Client) Changes(ctx context.Context, after uint64, wait time.Duration, limit int) (svserver.Changes, error) {
	q := url.Values{}
	q.Set("after", strconv.FormatUint(after, 10))
	if wait > 0 {
		q.Set("wait", strconv.Itoa(int(min(wait, svserver.MaxWait)/time.Second)))
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, wait+requestTimeout)
		defer cancel()
	}
	if limit > 0 {
		q.Set("limit", strconv.Itoa(limit))
	}
	var cs svserver.Changes
	_, _, err := c.do(ctx, "GET", "/changes", q.Encode(), nil, &cs)
	return cs, err
}
