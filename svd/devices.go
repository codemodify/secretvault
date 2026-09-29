package svd

import (
	"context"
	"errors"
	"fmt"

	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// Devices and signatures. The daemon signs every revision it writes with
// this device's key (svcore.DeviceKeyFile in the data directory), and
// registers the device in each vault it opens that does not know it yet,
// under the machine's name (registerDevice). Every entry it serves says
// who signed it (toEntry).

// registerDevice registers this device in a vault it has just opened,
// unless its key is registered there already, or was and has been
// removed: a device removed elsewhere does not come back by itself.
func (d *Daemon) registerDevice(mv *managedVault) {
	if mv.cfg.Emergency != "" {
		return // someone else's vault, read-only here: this device writes nothing to it
	}
	info, fresh, err := mv.v.RegisterDevice(deviceLabel(""))
	switch {
	case err != nil:
		d.opts.Log(fmt.Sprintf("registering this device in %s: %v", mv.cfg.Name, err))
	case fresh:
		d.opts.Log(fmt.Sprintf("registered this device in %s as %q (key %s)", mv.cfg.Name, info.Label, info.Key))
	case info.Removed:
		d.opts.Log(fmt.Sprintf("this device was removed from %s: what it writes there is signed, and shown as a removed device's", mv.cfg.Name))
	}
}

func toDevice(i svcore.DeviceInfo) svrpc.Device {
	out := svrpc.Device{Key: i.Key.String(), Device: i.Device.String(), Label: i.Label, Registered: i.Registered,
		Removed: i.Removed, This: i.This, Vouched: i.Vouched}
	for _, k := range i.Vouches {
		out.Vouches = append(out.Vouches, k.String())
	}
	return out
}

func toSignature(s svcore.Signature) svrpc.Signature {
	out := svrpc.Signature{Status: string(s.Status), Label: s.Label, Removed: s.Removed, Vouched: s.Vouched, Mine: s.Mine}
	if !s.Key.IsZero() {
		out.Key = s.Key.String()
	}
	if !s.Device.IsZero() {
		out.Device = s.Device.String()
	}
	return out
}

// device resolves a device of an unlocked vault; "" is this one.
func (d *Daemon) device(mv *managedVault, ref string) (svcore.DeviceInfo, error) {
	if ref == "" {
		ref = d.svOpts.Signer.ID().String()
	}
	info, err := mv.v.Device(ref)
	if errors.Is(err, svcore.ErrNoDevice) {
		return info, svrpc.Errorf(svrpc.CodeNotFound, "vault %q has no device %q ('secretvault device ls' lists them)", mv.cfg.Name, ref)
	}
	return info, err
}

func init() {
	registerMethod(svrpc.MDeviceList, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.VaultRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		devs, err := mv.v.Devices()
		if err != nil {
			return nil, err
		}
		out := []svrpc.Device{}
		for _, i := range devs {
			out = append(out, toDevice(i))
		}
		return out, nil
	})
	registerMethod(svrpc.MDeviceLabel, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.DeviceLabelParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		dev, err := d.device(mv, p.Device)
		if err != nil {
			return nil, err
		}
		info, err := mv.v.LabelDevice(dev.Key, p.Label)
		if err != nil {
			return nil, err
		}
		d.recorder(cl, mv, "", svbroker.OpManage)("allowed", fmt.Sprintf("labelled device %s %q", info.Key, info.Label))
		return toDevice(info), nil
	})
	registerMethod(svrpc.MDeviceRemove, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.DeviceRef
		if err := decode(&p); err != nil {
			return nil, err
		}
		if p.Device == "" {
			return nil, svrpc.Errorf(svrpc.CodeInvalidParams, "which device? ('secretvault device ls' lists them)")
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		dev, err := d.device(mv, p.Device)
		if err != nil {
			return nil, err
		}
		if err := mv.v.RemoveDevice(dev.Key); err != nil {
			return nil, err
		}
		d.recorder(cl, mv, "", svbroker.OpManage)("allowed", fmt.Sprintf("removed device %s %q", dev.Key, dev.Label))
		info, err := mv.v.Device(dev.Key.String())
		if err != nil {
			return nil, err
		}
		return toDevice(info), nil
	})
	registerMethod(svrpc.MDeviceVouch, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.DeviceVouchParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		dev, err := d.device(mv, p.Device)
		if err != nil {
			return nil, err
		}
		info, err := mv.v.VouchDevice(dev.Key, !p.Withdraw)
		if err != nil {
			return nil, err
		}
		what := "vouched for"
		if p.Withdraw {
			what = "withdrew its word for"
		}
		d.recorder(cl, mv, "", svbroker.OpManage)("allowed", fmt.Sprintf("%s device %s %q", what, info.Key, info.Label))
		return toDevice(info), nil
	})
	registerMethod(svrpc.MVaultSignatures, func(d *Daemon, ctx context.Context, cl *client, decode func(any) error) (any, error) {
		var p svrpc.SignaturesParams
		if err := decode(&p); err != nil {
			return nil, err
		}
		mv, err := d.managed(ctx, cl, p.Vault, "", "", svbroker.OpManage)
		if err != nil {
			return nil, err
		}
		if p.Require != nil {
			if *p.Require {
				// Requiring signatures writes the current state again:
				// do it on the newest copy, as a rotation does.
				if err := d.syncBefore(ctx, mv, "requiring signatures"); err != nil {
					return nil, err
				}
			}
			if err := mv.v.SetPolicy(svcore.Policy{RequireSignatures: *p.Require}); err != nil {
				return nil, err
			}
			what := "signatures are optional"
			if *p.Require {
				what = "signatures are required"
			}
			d.recorder(cl, mv, "", svbroker.OpManage)("allowed", "changed the vault's policy: "+what)
			d.notify(svrpc.EItemChanged, svrpc.VaultEvent{Vault: mv.cfg.Name})
		}
		pol, err := mv.v.Policy()
		if err != nil {
			return nil, err
		}
		return svrpc.SignaturePolicy{Vault: mv.cfg.Name, Require: pol.RequireSignatures}, nil
	})
}
