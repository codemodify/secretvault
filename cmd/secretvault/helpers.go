package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svrpc"
)

// Helpers for other programs, each reading and writing vault items:
//
//	git-credential-secretvault get|store|erase    git's credential helper protocol
//	docker-credential-secretvault get|store|erase|list
//	age-plugin-secretvault --age-plugin=...       age's plugin protocol (age_plugin.go)
//	secretvault read sv://VAULT/ITEM[#FIELD]     print one value
//	secretvault run [--env-file F] -- CMD ...    run CMD with sv:// references in its
//	                                             environment resolved
//	secretvault inject [-i IN] [-o OUT]           fill {{ sv://... }} in a template
//
// The helpers are this program under another name (a symlink, so the
// daemon still knows it as secretvault's own CLI). A reference names a
// vault ("-" for the default one), an item, and optionally a field (the
// item's secret when left out): sv://-/web/github.com#username.

// ref is a parsed sv:// reference.
type ref struct {
	vault, item, field string
}

var refPattern = regexp.MustCompile(`^sv://([^/]*)/(.+?)(?:#([^#]+))?$`)

func parseRef(s string) (ref, error) {
	m := refPattern.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return ref{}, fmt.Errorf("%q is not a reference (sv://VAULT/ITEM[#FIELD], VAULT - for the default)", s)
	}
	r := ref{vault: m[1], item: m[2], field: m[3]}
	if r.vault == "-" {
		r.vault = ""
	}
	return r, nil
}

// resolve reads what a reference points at.
func (c *cli) resolve(ctx context.Context, cl *secretvault.Client, r ref) ([]byte, error) {
	e, err := cl.Get(ctx, r.vault, r.item)
	if err != nil {
		return nil, fmt.Errorf("sv://%s/%s: %w", r.vault, r.item, err)
	}
	defer wipe(&e.Item)
	var f svrpc.Field
	var ok bool
	if r.field != "" {
		f, ok = field(&e.Item, r.field)
	} else {
		f, ok = secretField(&e.Item)
	}
	if !ok {
		return nil, fmt.Errorf("sv://%s/%s has no field %q", r.vault, r.item, r.field)
	}
	return append([]byte(nil), f.Value...), nil
}

func (c *cli) cmdRead(args []string) error {
	fs := c.flags("read")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "sv://VAULT/ITEM[#FIELD]")
	if err != nil {
		return err
	}
	r, err := parseRef(pos[0])
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	v, err := c.resolve(ctx, cl, r)
	if err != nil {
		return err
	}
	defer clear(v)
	c.stdout.Write(v)
	fmt.Fprintln(c.stdout)
	return nil
}

// readEnvFile reads KEY=VALUE lines (# comments, optional export, quotes).
func readEnvFile(path string) ([][2]string, error) {
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

// cmdRun runs a command with its environment's references resolved.
func (c *cli) cmdRun(args []string) error {
	fs := c.flags("run")
	var envFiles, envs multi
	fs.Var(&envFiles, "env-file", "also load KEY=VALUE lines from `FILE` (repeatable)")
	fs.Var(&envs, "env", "set `KEY=VALUE` (repeatable)")
	var u unlockFlags
	u.register(fs)
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	cmdline := fs.Args()
	if len(cmdline) == 0 {
		fmt.Fprintln(c.stderr, "usage: secretvault run [--env-file F] [--env K=V] -- COMMAND [ARGS...]")
		return errUsage
	}
	env := map[string]string{}
	var order []string
	set := func(k, v string) {
		if _, ok := env[k]; !ok {
			order = append(order, k)
		}
		env[k] = v
	}
	for _, kv := range os.Environ() {
		if k, v, ok := strings.Cut(kv, "="); ok {
			set(k, v)
		}
	}
	for _, f := range envFiles {
		pairs, err := readEnvFile(f)
		if err != nil {
			return err
		}
		for _, p := range pairs {
			set(p[0], p[1])
		}
	}
	for _, kv := range envs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok {
			return fmt.Errorf("--env %q is not KEY=VALUE", kv)
		}
		set(k, v)
	}
	var cl *secretvault.Client
	ctx, cancel := c.ctx()
	defer cancel()
	for _, k := range order {
		if !strings.HasPrefix(env[k], "sv://") {
			continue
		}
		r, err := parseRef(env[k])
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		if cl == nil {
			if cl, err = c.open(&u); err != nil {
				return err
			}
		}
		v, err := c.resolve(ctx, cl, r)
		if err != nil {
			return fmt.Errorf("%s: %w", k, err)
		}
		env[k] = string(v)
		clear(v)
	}
	var list []string
	for _, k := range order {
		list = append(list, k+"="+env[k])
	}
	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
	path, err := exec.LookPath(cmdline[0])
	if err != nil {
		return err
	}
	cmd := exec.Command(path, cmdline[1:]...)
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = list, c.stdin, c.stdout, c.stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitCode(ee.ExitCode())
		}
		return err
	}
	return nil
}

// exitCode passes a child's exit status through as ours.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

var templateRef = regexp.MustCompile(`\{\{\s*(sv://[^\s}]+)\s*\}\}`)

// cmdInject fills {{ sv://... }} references in a template.
func (c *cli) cmdInject(args []string) error {
	fs := c.flags("inject")
	in := fs.String("i", "", "read the template from `FILE` (default: stdin)")
	out := fs.String("o", "", "write the result to `FILE`, created 0600 (default: stdout)")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, "[-i TEMPLATE] [-o OUT]"); err != nil {
		return err
	}
	var tmpl []byte
	var err error
	if *in != "" {
		tmpl, err = os.ReadFile(*in)
	} else {
		tmpl, err = io.ReadAll(c.stdin)
	}
	if err != nil {
		return err
	}
	var cl *secretvault.Client
	ctx, cancel := c.ctx()
	defer cancel()
	var failure error
	result := templateRef.ReplaceAllFunc(tmpl, func(m []byte) []byte {
		if failure != nil {
			return m
		}
		r, err := parseRef(string(templateRef.FindSubmatch(m)[1]))
		if err != nil {
			failure = err
			return m
		}
		if cl == nil {
			if cl, err = c.open(&u); err != nil {
				failure = err
				return m
			}
		}
		v, err := c.resolve(ctx, cl, r)
		if err != nil {
			failure = err
			return m
		}
		return v
	})
	defer clear(result)
	if failure != nil {
		return failure
	}
	if *out == "" {
		_, err = c.stdout.Write(result)
		return err
	}
	return writeNew(*out, result)
}

// Git's credential helper protocol
// (https://git-scm.com/docs/git-credential): key=value lines on stdin,
// the same back on stdout for get.

func readKV(r io.Reader) map[string]string {
	out := map[string]string{}
	s := bufio.NewScanner(r)
	for s.Scan() {
		line := s.Text()
		if line == "" {
			break
		}
		if k, v, ok := strings.Cut(line, "="); ok {
			out[k] = v
		}
	}
	return out
}

func gitItemName(kv map[string]string) string {
	name := "git/" + pathSafe(kv["host"])
	if kv["path"] != "" {
		name += "/" + pathSafe(kv["path"])
	}
	if kv["username"] != "" {
		name += "/" + pathSafe(kv["username"])
	}
	return name
}

func gitMatches(it *svrpc.Item, kv map[string]string) bool {
	for _, k := range []string{"protocol", "host", "path", "username"} {
		if kv[k] != "" && it.Attrs["git_"+k] != kv[k] {
			return false
		}
	}
	return it.Attrs["git_host"] != ""
}

func (c *cli) cmdGitCredential(args []string) error {
	fs := c.flags("git-credential")
	var u unlockFlags
	u.register(fs)
	args, err := parse(fs, args, 1, 1, "get|store|erase")
	if err != nil {
		return err
	}
	kv := readKV(c.stdin)
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	switch args[0] {
	case "get":
		entries, err := cl.List(ctx, c.vault, "git/")
		if err != nil {
			return err
		}
		for _, e := range entries {
			if !gitMatches(&e.Item, kv) {
				continue
			}
			full, err := cl.Get(ctx, c.vault, e.Item.Name)
			if err != nil {
				return err
			}
			defer wipe(&full.Item)
			if u, ok := field(&full.Item, "username"); ok {
				fmt.Fprintf(c.stdout, "username=%s\n", u.Value)
			}
			if p, ok := secretField(&full.Item); ok {
				fmt.Fprintf(c.stdout, "password=%s\n", p.Value)
			}
			return nil
		}
		return nil // nothing stored: git asks the person
	case "store":
		if kv["host"] == "" || kv["password"] == "" {
			return nil
		}
		attrs := map[string]string{}
		for _, k := range []string{"protocol", "host", "path", "username"} {
			if kv[k] != "" {
				attrs["git_"+k] = kv[k]
			}
		}
		it := svrpc.Item{Kind: "login", Name: gitItemName(kv), Label: kv["host"], Attrs: attrs, Fields: []svrpc.Field{
			{Name: "username", Type: svcore.FieldText, Value: []byte(kv["username"])},
			{Name: "password", Type: svcore.FieldConcealed, Value: []byte(kv["password"])},
			{Name: "url", Type: svcore.FieldURL, Value: []byte(kv["protocol"] + "://" + kv["host"])},
		}}
		_, err := cl.Put(ctx, c.vault, it)
		return err
	case "erase":
		entries, err := cl.List(ctx, c.vault, "git/")
		if err != nil {
			return err
		}
		for _, e := range entries {
			if gitMatches(&e.Item, kv) {
				if err := cl.Delete(ctx, c.vault, e.Item.Name); err != nil {
					return err
				}
			}
		}
		return nil
	}
	return nil // unknown actions are ignored, as the protocol asks
}

// Docker's credential helper protocol
// (https://github.com/docker/docker-credential-helpers).

func dockerItemName(server string) string {
	u := server
	if p, err := url.Parse(server); err == nil && p.Host != "" {
		u = p.Host + p.Path
	}
	return "docker/" + pathSafe(u)
}

func (c *cli) cmdDockerCredential(args []string) error {
	fs := c.flags("docker-credential")
	var u unlockFlags
	u.register(fs)
	args, err := parse(fs, args, 1, 1, "get|store|erase|list|version")
	if err != nil {
		return err
	}
	if args[0] == "version" {
		fmt.Fprintln(c.stdout, "docker-credential-secretvault")
		return nil
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	type creds struct {
		ServerURL string `json:"ServerURL"`
		Username  string `json:"Username"`
		Secret    string `json:"Secret"`
	}
	switch args[0] {
	case "get":
		server, _ := io.ReadAll(c.stdin)
		name := dockerItemName(strings.TrimSpace(string(server)))
		e, err := cl.Get(ctx, c.vault, name)
		if err != nil {
			if errors.Is(err, svrpc.ErrNotFound) {
				fmt.Fprintln(c.stdout, "credentials not found in native keychain")
				return exitCode(1)
			}
			return err
		}
		defer wipe(&e.Item)
		u, _ := field(&e.Item, "username")
		p, _ := secretField(&e.Item)
		return json.NewEncoder(c.stdout).Encode(creds{ServerURL: strings.TrimSpace(string(server)), Username: string(u.Value), Secret: string(p.Value)})
	case "store":
		var in creds
		if err := json.NewDecoder(c.stdin).Decode(&in); err != nil {
			return err
		}
		it := svrpc.Item{Kind: "login", Name: dockerItemName(in.ServerURL), Label: in.ServerURL,
			Attrs: map[string]string{"docker_server": in.ServerURL}, Fields: []svrpc.Field{
				{Name: "username", Type: svcore.FieldText, Value: []byte(in.Username)},
				{Name: "password", Type: svcore.FieldConcealed, Value: []byte(in.Secret)},
				{Name: "url", Type: svcore.FieldURL, Value: []byte(in.ServerURL)},
			}}
		_, err := cl.Put(ctx, c.vault, it)
		return err
	case "erase":
		server, _ := io.ReadAll(c.stdin)
		return cl.Delete(ctx, c.vault, dockerItemName(strings.TrimSpace(string(server))))
	case "list":
		entries, err := cl.List(ctx, c.vault, "docker/")
		if err != nil {
			return err
		}
		out := map[string]string{}
		for _, e := range entries {
			if s := e.Item.Attrs["docker_server"]; s != "" {
				full, err := cl.Get(ctx, c.vault, e.Item.Name)
				if err != nil {
					continue
				}
				u, _ := field(&full.Item, "username")
				out[s] = string(u.Value)
				wipe(&full.Item)
			}
		}
		return json.NewEncoder(c.stdout).Encode(out)
	}
	fmt.Fprintf(c.stderr, "unknown action %q\n", args[0])
	return errUsage
}

// helperName is the command a program name stands for.
func helperName(argv0 string) string {
	base := strings.TrimSuffix(filepath.Base(argv0), ".exe")
	switch base {
	case "git-credential-secretvault":
		return "git-credential"
	case "docker-credential-secretvault":
		return "docker-credential"
	case "age-plugin-secretvault":
		return "age-plugin"
	}
	return ""
}
