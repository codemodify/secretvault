package svd

import (
	"context"
	"errors"
	"os"
	"regexp"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svdbus"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
)

// The Secret portal's backend (org.freedesktop.impl.portal.Secret).
//
// A Flatpak app keeps its secrets in an encrypted file inside its sandbox,
// under a key it asks the Secret portal for. xdg-desktop-portal passes the
// question to a backend with the app's ID, which the sandbox guarantees,
// and a pipe to write the key into. secretvault answers it from the same
// connection as the Secret Service, at the path gnome-keyring uses, so
// gnome-keyring.portal (DBusName=org.freedesktop.secrets) reaches it; on
// KDE, portals.conf chooses that backend over kwallet.
//
// Each app's key is an item of its own (flatpak/<app id>), made on first
// use, and handed out under the same per-app consent as everything else:
// the app is asked about by its Flatpak ID.
//
// Only xdg-desktop-portal itself may ask. Any program on the bus can call
// the method with any app ID, so without that check it would hand every
// app's key to whoever asks.

const (
	portalPath  = svdbus.ObjectPath("/org/freedesktop/portal/desktop")
	ifPortal    = "org.freedesktop.impl.portal.Secret"
	portalOK    = uint32(0)
	portalNo    = uint32(1) // the person said no
	portalError = uint32(2)
)

// flatpakID is a Flatpak app ID: reverse DNS, at least three parts.
var flatpakID = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_-]*(\.[A-Za-z_][A-Za-z0-9_-]*){2,}$`)

func (ss *secretService) portalInterface() *svdbus.Interface {
	return &svdbus.Interface{
		Name: ifPortal,
		Methods: []*svdbus.Method{
			{Name: "RetrieveSecret", In: args("handle", "o", "app_id", "s", "fd", "h", "options", "a{sv}"),
				Out: args("response", "u", "results", "a{sv}"), Handler: ss.retrieveSecret},
		},
		Properties: []*svdbus.Property{
			{Name: "version", Type: "u", Get: func(context.Context, *svdbus.Call) (any, error) { return uint32(1), nil }},
		},
	}
}

func (ss *secretService) retrieveSecret(ctx context.Context, call *svdbus.Call) ([]any, error) {
	var handle svdbus.ObjectPath
	var appID string
	var fd svdbus.UnixFD
	var options map[string]svdbus.Variant
	if err := call.Decode(&handle, &appID, &fd, &options); err != nil {
		return nil, err
	}
	out := os.NewFile(uintptr(fd), "portal secret")
	defer out.Close()
	no := map[string]svdbus.Variant{}
	portal, err := ss.caller(ctx, call.Sender())
	if err != nil {
		return nil, err
	}
	if !ss.d.opts.IsPortal(portal.proc) {
		return nil, svdbus.NewError(svdbus.ErrorAccessDenied, "only xdg-desktop-portal may ask for an app's secret")
	}
	if !flatpakID.MatchString(appID) {
		// Programs outside a sandbox have no app ID: they use the Secret
		// Service directly.
		return []any{portalError, no}, nil
	}
	key, err := ss.d.appSecret(ctx, appID, portal.proc.PID)
	switch {
	case err == nil:
	case errors.Is(err, svrpc.ErrDenied), errors.Is(err, svrpc.ErrCanceled), errors.Is(err, svrpc.ErrNoPrompter):
		return []any{portalNo, no}, nil
	default:
		ss.d.opts.Log("the Secret portal, for " + appID + ": " + err.Error())
		return []any{portalError, no}, nil
	}
	_, err = out.Write(key)
	clear(key)
	if err != nil {
		return []any{portalError, no}, nil
	}
	return []any{portalOK, no}, nil
}

// appSecret is a Flatpak app's key for its own secret storage, from the
// default vault, made on first use.
func (d *Daemon) appSecret(ctx context.Context, appID string, portalPID int) ([]byte, error) {
	cl := &client{proc: &svpeer.Process{PID: portalPID, Flatpak: appID}}
	mv, err := d.vault("")
	if err != nil {
		return nil, err
	}
	name := "flatpak/" + appID
	why := cl.display() + " asks for the key to its own secret storage."
	record := d.recorder(cl, mv, name, svbroker.OpRead)
	prompted, own, err := d.ensureUnlocked(ctx, cl, mv, why)
	if err != nil {
		record(outcomeOf(err), err.Error())
		return nil, err
	}
	e, err := mv.v.Get(name)
	if errors.Is(err, svcore.ErrNotFound) {
		key := svcrypto.RandomBytes(64)
		it := svcore.Item{Kind: "key", Name: name, Label: "Secret storage key of " + appID + " (Flatpak)",
			Attrs:  map[string]string{"flatpak-app": appID},
			Fields: []svcore.Field{{Name: "key", Type: svcore.FieldConcealed, Value: key}}}
		e, err = mv.v.Put(it)
		clear(key)
	}
	if err != nil {
		return nil, err
	}
	defer e.Item.Wipe()
	if err := d.decide(ctx, cl, mv, e.ID.String(), name, svbroker.OpRead, why, prompted, own, record); err != nil {
		return nil, err
	}
	for _, f := range e.Item.Fields {
		if f.Name == "key" && len(f.Value) > 0 {
			return append([]byte(nil), f.Value...), nil
		}
	}
	return nil, errors.New(name + " has no key field")
}
