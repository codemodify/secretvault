package svops

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svrpc"
)

// References, sv://VAULT/ITEM[#FIELD]: what 'read', 'run' and 'inject'
// resolve for other programs, and what an interface shows a person who
// wants to know what one points at.

// Resolve reads the value a reference names from the daemon: the field it
// names, or the item's secret. The caller clears it.
func Resolve(ctx context.Context, cl *secretvault.Client, r svrpc.Ref) ([]byte, error) {
	e, err := cl.Get(ctx, r.Vault, r.Item)
	if err != nil {
		return nil, fmt.Errorf("sv://%s/%s: %w", r.Vault, r.Item, err)
	}
	defer Wipe(&e.Item)
	var f svrpc.Field
	var ok bool
	if r.Field != "" {
		f, ok = Field(&e.Item, r.Field)
	} else {
		f, ok = SecretField(&e.Item)
	}
	if !ok {
		return nil, fmt.Errorf("sv://%s/%s has no field %q", r.Vault, r.Item, r.Field)
	}
	return append([]byte(nil), f.Value...), nil
}

// ReadEnvFile reads KEY=VALUE lines (# comments, optional export, quotes).
func ReadEnvFile(path string) ([][2]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out [][2]string
	s := bufio.NewScanner(f)
	for n := 1; s.Scan(); n++ {
		line := strings.TrimSpace(s.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		k, v, ok := strings.Cut(line, "=")
		if !ok || strings.TrimSpace(k) == "" {
			return nil, fmt.Errorf("%s:%d: not KEY=VALUE", path, n)
		}
		v = strings.TrimSpace(v)
		if len(v) >= 2 && (v[0] == '"' && v[len(v)-1] == '"' || v[0] == '\'' && v[len(v)-1] == '\'') {
			v = v[1 : len(v)-1]
		}
		out = append(out, [2]string{strings.TrimSpace(k), v})
	}
	return out, s.Err()
}

// Environ is an environment being put together for a command: variables
// in the order they were first set, later settings winning.
type Environ struct {
	order []string
	vals  map[string]string
}

// NewEnviron starts from base, KEY=VALUE strings such as os.Environ().
func NewEnviron(base []string) *Environ {
	e := &Environ{vals: map[string]string{}}
	for _, kv := range base {
		if k, v, ok := strings.Cut(kv, "="); ok {
			e.Set(k, v)
		}
	}
	return e
}

// Set sets a variable.
func (e *Environ) Set(k, v string) {
	if _, ok := e.vals[k]; !ok {
		e.order = append(e.order, k)
	}
	e.vals[k] = v
}

// Get is a variable's value.
func (e *Environ) Get(k string) string { return e.vals[k] }

// LoadFiles sets the variables of env files (ReadEnvFile), in order.
func (e *Environ) LoadFiles(paths []string) error {
	for _, f := range paths {
		pairs, err := ReadEnvFile(f)
		if err != nil {
			return err
		}
		for _, p := range pairs {
			e.Set(p[0], p[1])
		}
	}
	return nil
}

// SetPairs sets KEY=VALUE arguments (--env).
func (e *Environ) SetPairs(kvs []string) error {
	for _, kv := range kvs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("--env %q is not KEY=VALUE", kv)
		}
		e.Set(k, v)
	}
	return nil
}

// Refs are the variables whose values are references, in order.
func (e *Environ) Refs() []string {
	var out []string
	for _, k := range e.order {
		if strings.HasPrefix(e.vals[k], "sv://") {
			out = append(out, k)
		}
	}
	return out
}

// Resolve replaces each reference with what it names: parse reads it
// (svrpc.ParseRef, or a stricter reader), fetch gets the value. connect,
// when set, is called once, before the first value is fetched (to reach
// the daemon, or a server), and its failure returned as it is; any other
// failure stops it, named by its variable.
func (e *Environ) Resolve(parse func(string) (svrpc.Ref, error), connect func() error, fetch func(svrpc.Ref) ([]byte, error)) error {
	for _, k := range e.Refs() {
		r, err := parse(e.vals[k])
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		if connect != nil {
			if err := connect(); err != nil {
				return err
			}
			connect = nil
		}
		v, err := fetch(r)
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		e.vals[k] = string(v)
		clear(v)
	}
	return nil
}

// List is the environment as KEY=VALUE strings, for exec.Cmd.Env.
func (e *Environ) List() []string {
	var list []string
	for _, k := range e.order {
		list = append(list, k+"="+e.vals[k])
	}
	return list
}

// templateRef is a reference in a template: {{ sv://... }}.
var templateRef = regexp.MustCompile(`\{\{\s*(sv://[^\s}]+)\s*\}\}`)

// TemplateRefs are the references a template holds, in order, as written.
func TemplateRefs(tmpl []byte) []string {
	var out []string
	for _, m := range templateRef.FindAllSubmatch(tmpl, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

// Inject fills a template's {{ sv://... }} references with what fetch
// gets for each. The caller clears the result.
func Inject(tmpl []byte, fetch func(svrpc.Ref) ([]byte, error)) ([]byte, error) {
	var failure error
	result := templateRef.ReplaceAllFunc(tmpl, func(m []byte) []byte {
		if failure != nil {
			return m
		}
		r, err := svrpc.ParseRef(string(templateRef.FindSubmatch(m)[1]))
		if err != nil {
			failure = err
			return m
		}
		v, err := fetch(r)
		if err != nil {
			failure = err
			return m
		}
		return v
	})
	if failure != nil {
		clear(result)
		return nil, failure
	}
	return result, nil
}
