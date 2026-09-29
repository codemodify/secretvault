package svdbus

import (
	"context"
	"fmt"
)

// properties is the org.freedesktop.DBus.Properties interface of the object
// at path, whose own interfaces are user.
func (c *Conn) properties(path ObjectPath, user []*Interface) *Interface {
	return &Interface{
		Name: propertiesInterface,
		Methods: []*Method{
			{
				Name:    "Get",
				In:      []Arg{{Name: "interface_name", Type: "s"}, {Name: "property_name", Type: "s"}},
				Out:     []Arg{{Name: "value", Type: "v"}},
				Handler: func(ctx context.Context, call *Call) ([]any, error) { return propGet(ctx, call, user) },
			},
			{
				Name: "Set",
				In: []Arg{{Name: "interface_name", Type: "s"}, {Name: "property_name", Type: "s"},
					{Name: "value", Type: "v"}},
				Handler: func(ctx context.Context, call *Call) ([]any, error) { return c.propSet(ctx, call, path, user) },
			},
			{
				Name:    "GetAll",
				In:      []Arg{{Name: "interface_name", Type: "s"}},
				Out:     []Arg{{Name: "properties", Type: "a{sv}"}},
				Handler: func(ctx context.Context, call *Call) ([]any, error) { return propGetAll(ctx, call, user) },
			},
		},
		Signals: []*Signal{{
			Name: "PropertiesChanged",
			Args: []Arg{{Name: "interface_name", Type: "s"}, {Name: "changed_properties", Type: "a{sv}"},
				{Name: "invalidated_properties", Type: "as"}},
		}},
	}
}

// findProperty finds a property by interface and name; with no interface
// named, the first property of that name in any interface.
func findProperty(user []*Interface, ifaceName, name string) (*Interface, *Property, error) {
	found := false
	for _, i := range user {
		if ifaceName != "" && i.Name != ifaceName {
			continue
		}
		found = true
		for _, p := range i.Properties {
			if p.Name == name {
				return i, p, nil
			}
		}
	}
	if !found {
		return nil, nil, NewError(ErrorUnknownInterface, fmt.Sprintf("No such interface '%s'", ifaceName))
	}
	return nil, nil, NewError(ErrorUnknownProperty, fmt.Sprintf("No such property '%s'", name))
}

func propGet(ctx context.Context, call *Call, user []*Interface) ([]any, error) {
	var ifaceName, name string
	if err := call.Decode(&ifaceName, &name); err != nil {
		return nil, NewError(ErrorInvalidArgs, err.Error())
	}
	_, p, err := findProperty(user, ifaceName, name)
	if err != nil {
		return nil, err
	}
	if p.Get == nil {
		return nil, NewError(ErrorAccessDenied, fmt.Sprintf("Property '%s' is write-only", name))
	}
	v, err := p.Get(ctx, call)
	if err != nil {
		return nil, err
	}
	return []any{Variant{Signature: p.Type, Value: v}}, nil
}

func propGetAll(ctx context.Context, call *Call, user []*Interface) ([]any, error) {
	var ifaceName string
	if err := call.Decode(&ifaceName); err != nil {
		return nil, NewError(ErrorInvalidArgs, err.Error())
	}
	out := map[string]Variant{}
	found := false
	for _, i := range user {
		if ifaceName != "" && i.Name != ifaceName {
			continue
		}
		found = true
		for _, p := range i.Properties {
			if p.Get == nil {
				continue
			}
			v, err := p.Get(ctx, call)
			if err != nil {
				return nil, err
			}
			out[p.Name] = Variant{Signature: p.Type, Value: v}
		}
	}
	if !found {
		return nil, NewError(ErrorUnknownInterface, fmt.Sprintf("No such interface '%s'", ifaceName))
	}
	return []any{out}, nil
}

func (c *Conn) propSet(ctx context.Context, call *Call, path ObjectPath, user []*Interface) ([]any, error) {
	var ifaceName, name string
	var value Variant
	if err := call.Decode(&ifaceName, &name, &value); err != nil {
		return nil, NewError(ErrorInvalidArgs, err.Error())
	}
	iface, p, err := findProperty(user, ifaceName, name)
	if err != nil {
		return nil, err
	}
	if p.Set == nil {
		return nil, NewError(ErrorPropertyReadOnly, fmt.Sprintf("Property '%s' is read-only", name))
	}
	if value.Signature != p.Type {
		return nil, NewError(ErrorInvalidArgs,
			fmt.Sprintf("Property '%s' has type '%s', not '%s'", name, p.Type, value.Signature))
	}
	if err := p.Set(ctx, call, value); err != nil {
		return nil, err
	}
	switch {
	case p.EmitsChanged == EmitsChangedTrue && p.Get != nil:
		if v, err := p.Get(ctx, call); err == nil {
			err = c.EmitPropertiesChanged(path, iface.Name, map[string]any{name: Variant{Signature: p.Type, Value: v}})
			if err != nil {
				c.opts.logger.Error("svdbus: cannot emit PropertiesChanged", "path", path, "property", name, "err", err)
			}
		}
	case p.EmitsChanged == EmitsChangedTrue || p.EmitsChanged == EmitsChangedInvalidates:
		_ = c.EmitPropertiesChanged(path, iface.Name, nil, name)
	}
	return nil, nil
}

// EmitPropertiesChanged emits org.freedesktop.DBus.Properties.PropertiesChanged
// for the interface iface of the object at path: changed maps property names
// to their new values, and invalidated names properties whose values are not
// sent. A value that is not a Variant is encoded as the property's declared
// type when the interface is exported at path, and by inference otherwise.
func (c *Conn) EmitPropertiesChanged(path ObjectPath, iface string, changed map[string]any, invalidated ...string) error {
	types := map[string]Signature{}
	for _, i := range c.lookup(path) {
		if i.Name == iface {
			for _, p := range i.Properties {
				types[p.Name] = p.Type
			}
		}
	}
	values := make(map[string]Variant, len(changed))
	for k, v := range changed {
		switch vv := v.(type) {
		case Variant:
			values[k] = vv
		default:
			if t, ok := types[k]; ok {
				values[k] = Variant{Signature: t, Value: v}
			} else {
				values[k] = MakeVariant(v)
			}
		}
	}
	if invalidated == nil {
		invalidated = []string{}
	}
	m := NewSignal(path, propertiesInterface, "PropertiesChanged", iface, values, invalidated)
	m.Signature = "sa{sv}as"
	return c.send(m, nil)
}

// GetProperty reads a property of a remote object.
func (c *Conn) GetProperty(ctx context.Context, dest string, path ObjectPath, iface, name string) (Variant, error) {
	r, err := c.Call(ctx, dest, path, propertiesInterface, "Get", iface, name)
	if err != nil {
		return Variant{}, err
	}
	var v Variant
	return v, r.Decode(&v)
}

// GetAllProperties reads every property of one interface of a remote
// object.
func (c *Conn) GetAllProperties(ctx context.Context, dest string, path ObjectPath, iface string) (map[string]Variant, error) {
	r, err := c.Call(ctx, dest, path, propertiesInterface, "GetAll", iface)
	if err != nil {
		return nil, err
	}
	var v map[string]Variant
	return v, r.Decode(&v)
}

// SetProperty writes a property of a remote object. A value that is not a
// Variant is wrapped with its inferred type.
func (c *Conn) SetProperty(ctx context.Context, dest string, path ObjectPath, iface, name string, value any) error {
	v, ok := value.(Variant)
	if !ok {
		v = MakeVariant(value)
	}
	m := NewMethodCall(dest, path, propertiesInterface, "Set", iface, name, v)
	m.Signature = "ssv"
	_, err := c.Send(ctx, m)
	return err
}
