package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svops"
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
// item's secret when left out): sv://-/web/github.com#username. What a
// reference resolves to, the items the helpers keep, and env files and
// templates are svops' (refs.go, helpers.go).

// resolve reads what a reference points at. The host daemon resolves it
// itself (host.resolve), so a local service is sent the one value its
// policy lists and never the rest of the item.
func (c *cli) resolve(ctx context.Context, cl *secretvault.Client, r svrpc.Ref) ([]byte, error) {
	if c.host || c.hostAdmin {
		return cl.HostResolve(ctx, r.String())
	}
	return svops.Resolve(ctx, cl, r)
}

func (c *cli) cmdRead(args []string) error {
	fs := c.flags("read")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "sv://VAULT/ITEM[#FIELD]")
	if err != nil {
		return err
	}
	r, err := svrpc.ParseRef(pos[0])
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

// lazyResolve resolves references, connecting (and presenting the keys
// the flags name) at the first one.
func (c *cli) lazyResolve(ctx context.Context, u *unlockFlags) func(svrpc.Ref) ([]byte, error) {
	var cl *secretvault.Client
	return func(r svrpc.Ref) ([]byte, error) {
		if cl == nil {
			var err error
			if cl, err = c.open(u); err != nil {
				return nil, err
			}
		}
		return c.resolve(ctx, cl, r)
	}
}

// runCommand runs a command with an environment, passing its exit status
// through as ours.
func (c *cli) runCommand(cmdline, env []string) error {
	path, err := exec.LookPath(cmdline[0])
	if err != nil {
		return err
	}
	cmd := exec.Command(path, cmdline[1:]...)
	cmd.Env, cmd.Stdin, cmd.Stdout, cmd.Stderr = env, c.stdin, c.stdout, c.stderr
	if err := cmd.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return exitCode(ee.ExitCode())
		}
		return err
	}
	return nil
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
	env := svops.NewEnviron(os.Environ())
	if err := env.LoadFiles(envFiles); err != nil {
		return err
	}
	if err := env.SetPairs(envs); err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	var cl *secretvault.Client
	connect := func() (err error) {
		cl, err = c.open(&u)
		return err
	}
	fetch := func(r svrpc.Ref) ([]byte, error) { return c.resolve(ctx, cl, r) }
	if err := env.Resolve(svrpc.ParseRef, connect, fetch); err != nil {
		return err
	}
	if c.client != nil {
		c.client.Close()
		c.client = nil
	}
	return c.runCommand(cmdline, env.List())
}

// exitCode passes a child's exit status through as ours.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

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
	ctx, cancel := c.ctx()
	defer cancel()
	result, err := svops.Inject(tmpl, c.lazyResolve(ctx, &u))
	if err != nil {
		return err
	}
	defer clear(result)
	if *out == "" {
		_, err = c.stdout.Write(result)
		return err
	}
	return svops.WriteNew(*out, result)
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
			if !svops.GitMatches(&e.Item, kv) {
				continue
			}
			full, err := cl.Get(ctx, c.vault, e.Item.Name)
			if err != nil {
				return err
			}
			defer svops.Wipe(&full.Item)
			if u, ok := svops.Field(&full.Item, "username"); ok {
				fmt.Fprintf(c.stdout, "username=%s\n", u.Value)
			}
			if p, ok := svops.SecretField(&full.Item); ok {
				fmt.Fprintf(c.stdout, "password=%s\n", p.Value)
			}
			return nil
		}
		return nil // nothing stored: git asks the person
	case "store":
		if kv["host"] == "" || kv["password"] == "" {
			return nil
		}
		_, err := cl.Put(ctx, c.vault, svops.GitItem(kv))
		return err
	case "erase":
		entries, err := cl.List(ctx, c.vault, "git/")
		if err != nil {
			return err
		}
		for _, e := range entries {
			if svops.GitMatches(&e.Item, kv) {
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
		name := svops.DockerItemName(strings.TrimSpace(string(server)))
		e, err := cl.Get(ctx, c.vault, name)
		if err != nil {
			// Docker's protocol has one answer for "nothing stored",
			// which lets it go on without a login; a missing vault gets
			// it too, as it did before secretvault told the two apart,
			// with what is missing said on stderr.
			if errors.Is(err, svrpc.ErrNoVault) {
				fmt.Fprintln(c.stderr, "secretvault:", describe(err))
			}
			if errors.Is(err, svrpc.ErrNotFound) || errors.Is(err, svrpc.ErrNoVault) {
				fmt.Fprintln(c.stdout, "credentials not found in native keychain")
				return exitCode(1)
			}
			return err
		}
		defer svops.Wipe(&e.Item)
		u, _ := svops.Field(&e.Item, "username")
		p, _ := svops.SecretField(&e.Item)
		return json.NewEncoder(c.stdout).Encode(creds{ServerURL: strings.TrimSpace(string(server)), Username: string(u.Value), Secret: string(p.Value)})
	case "store":
		var in creds
		if err := json.NewDecoder(c.stdin).Decode(&in); err != nil {
			return err
		}
		_, err := cl.Put(ctx, c.vault, svops.DockerItem(in.ServerURL, in.Username, in.Secret))
		return err
	case "erase":
		server, _ := io.ReadAll(c.stdin)
		return cl.Delete(ctx, c.vault, svops.DockerItemName(strings.TrimSpace(string(server))))
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
				u, _ := svops.Field(&full.Item, "username")
				out[s] = string(u.Value)
				svops.Wipe(&full.Item)
			}
		}
		return json.NewEncoder(c.stdout).Encode(out)
	}
	fmt.Fprintf(c.stderr, "unknown action %q\n", args[0])
	return errUsage
}

// helperName is the command a program name stands for.
func helperName(argv0 string) string { return svops.HelperName(argv0) }
