package svdbus

import (
	"context"
	"encoding/xml"
)

// IntrospectDocType starts every introspection document.
const IntrospectDocType = `<!DOCTYPE node PUBLIC "-//freedesktop//DTD D-BUS Object Introspection 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd">
`

// NodeInfo is introspection data: an object's interfaces and its child
// nodes, as org.freedesktop.DBus.Introspectable.Introspect returns it.
type NodeInfo struct {
	XMLName    xml.Name        `xml:"node"`
	Name       string          `xml:"name,attr,omitempty"`
	Interfaces []InterfaceInfo `xml:"interface"`
	Children   []NodeInfo      `xml:"node"`
}

// InterfaceInfo describes one interface in introspection data.
type InterfaceInfo struct {
	Name        string           `xml:"name,attr"`
	Methods     []MethodInfo     `xml:"method"`
	Signals     []SignalInfo     `xml:"signal"`
	Properties  []PropertyInfo   `xml:"property"`
	Annotations []AnnotationInfo `xml:"annotation"`
}

// MethodInfo describes a method; its Args have Direction "in" or "out".
type MethodInfo struct {
	Name        string           `xml:"name,attr"`
	Args        []ArgInfo        `xml:"arg"`
	Annotations []AnnotationInfo `xml:"annotation"`
}

// SignalInfo describes a signal.
type SignalInfo struct {
	Name        string           `xml:"name,attr"`
	Args        []ArgInfo        `xml:"arg"`
	Annotations []AnnotationInfo `xml:"annotation"`
}

// ArgInfo describes an argument.
type ArgInfo struct {
	Name      string `xml:"name,attr,omitempty"`
	Type      string `xml:"type,attr"`
	Direction string `xml:"direction,attr,omitempty"`
}

// PropertyInfo describes a property; Access is read, write or readwrite.
type PropertyInfo struct {
	Name        string           `xml:"name,attr"`
	Type        string           `xml:"type,attr"`
	Access      string           `xml:"access,attr"`
	Annotations []AnnotationInfo `xml:"annotation"`
}

// AnnotationInfo is an annotation.
type AnnotationInfo struct {
	Name  string `xml:"name,attr"`
	Value string `xml:"value,attr"`
}

// ParseIntrospection parses an introspection document.
func ParseIntrospection(data []byte) (*NodeInfo, error) {
	var n NodeInfo
	if err := xml.Unmarshal(data, &n); err != nil {
		return nil, invalidf("introspection data: %v", err)
	}
	return &n, nil
}

// XML formats the node as an introspection document.
func (n *NodeInfo) XML() (string, error) {
	b, err := xml.MarshalIndent(n, "", "  ")
	if err != nil {
		return "", err
	}
	return IntrospectDocType + string(b) + "\n", nil
}

// Introspect asks the object at path on dest to describe itself.
func (c *Conn) Introspect(ctx context.Context, dest string, path ObjectPath) (*NodeInfo, error) {
	r, err := c.Call(ctx, dest, path, introspectableInterface, "Introspect")
	if err != nil {
		return nil, err
	}
	var doc string
	if err := r.Decode(&doc); err != nil {
		return nil, err
	}
	return ParseIntrospection([]byte(doc))
}

func annotationInfo(as []Annotation) []AnnotationInfo {
	var out []AnnotationInfo
	for _, a := range as {
		out = append(out, AnnotationInfo(a))
	}
	return out
}

func argInfo(args []Arg, dir string) []ArgInfo {
	var out []ArgInfo
	for _, a := range args {
		out = append(out, ArgInfo{Name: a.Name, Type: string(a.Type), Direction: dir})
	}
	return out
}

// Info returns the interface's introspection data.
func (i *Interface) Info() InterfaceInfo {
	info := InterfaceInfo{Name: i.Name, Annotations: annotationInfo(i.Annotations)}
	for _, m := range i.Methods {
		info.Methods = append(info.Methods, MethodInfo{
			Name:        m.Name,
			Args:        append(argInfo(m.In, "in"), argInfo(m.Out, "out")...),
			Annotations: annotationInfo(m.Annotations),
		})
	}
	for _, s := range i.Signals {
		info.Signals = append(info.Signals, SignalInfo{
			Name: s.Name, Args: argInfo(s.Args, ""), Annotations: annotationInfo(s.Annotations),
		})
	}
	for _, p := range i.Properties {
		access := "readwrite"
		switch {
		case p.Set == nil:
			access = "read"
		case p.Get == nil:
			access = "write"
		}
		pi := PropertyInfo{Name: p.Name, Type: string(p.Type), Access: access, Annotations: annotationInfo(p.Annotations)}
		if p.EmitsChanged != EmitsChangedTrue {
			pi.Annotations = append(pi.Annotations, AnnotationInfo{
				Name: "org.freedesktop.DBus.Property.EmitsChangedSignal", Value: p.EmitsChanged.String(),
			})
		}
		info.Properties = append(info.Properties, pi)
	}
	return info
}

// introspectable is the Introspectable interface of the object at path;
// ifaces points at every interface the object ends up with.
func (c *Conn) introspectable(path ObjectPath, ifaces *[]*Interface) *Interface {
	return &Interface{
		Name: introspectableInterface,
		Methods: []*Method{{
			Name: "Introspect",
			Out:  []Arg{{Name: "xml_data", Type: "s"}},
			Handler: func(ctx context.Context, call *Call) ([]any, error) {
				node := NodeInfo{Name: string(path)}
				for _, i := range *ifaces {
					node.Interfaces = append(node.Interfaces, i.Info())
				}
				for _, name := range c.children(path) {
					node.Children = append(node.Children, NodeInfo{Name: name})
				}
				doc, err := node.XML()
				if err != nil {
					return nil, err
				}
				return []any{doc}, nil
			},
		}},
	}
}
