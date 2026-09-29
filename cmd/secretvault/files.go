package main

import (
	"errors"
	"fmt"
	"io"
	"mime"
	"os"
	"path/filepath"
	"text/tabwriter"

	"github.com/codemodify/secretvault/svrpc"
)

// cmdAttach is `secretvault attach ITEM FILE`.
func (c *cli) cmdAttach(args []string) error {
	fs := c.flags("attach")
	name := fs.String("name", "", "the file's name in the item (default: FILE's own)")
	typ := fs.String("type", "", "its media type (default: from the extension)")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 2, 2, "ITEM FILE|- [--name NAME] [--type TYPE]   (- reads standard input, and needs --name)")
	if err != nil {
		return err
	}
	var data []byte
	if pos[1] == "-" {
		if *name == "" {
			return errors.New("a file from standard input needs --name")
		}
		data, err = io.ReadAll(io.LimitReader(c.stdin, svrpc.MaxFileData+1))
	} else {
		if *name == "" {
			*name = filepath.Base(pos[1])
		}
		data, err = os.ReadFile(pos[1])
	}
	if err != nil {
		return err
	}
	defer clear(data)
	if len(data) > svrpc.MaxFileData {
		return fmt.Errorf("that file is larger than the %d MiB secretvault takes in one piece", svrpc.MaxFileData>>20)
	}
	if *typ == "" {
		*typ = mime.TypeByExtension(filepath.Ext(*name))
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	if _, err := cl.Attach(ctx, svrpc.FileAttachParams{Vault: c.vault, Item: pos[0], Name: *name, Type: *typ, Data: data}); err != nil {
		return err
	}
	fmt.Fprintf(c.stdout, "Attached %s (%d bytes) to %s\n", *name, len(data), pos[0])
	return nil
}

// cmdFile is `secretvault file ls|get|rm`.
func (c *cli) cmdFile(args []string) error {
	if len(args) == 0 {
		args = []string{"help"}
	}
	fs := c.flags("file " + args[0])
	var u unlockFlags
	u.register(fs)
	switch args[0] {
	case "ls", "list":
		pos, err := parse(fs, args[1:], 1, 1, "ITEM")
		if err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		e, err := cl.Get(ctx, c.vault, pos[0])
		if err != nil {
			return err
		}
		wipe(&e.Item)
		if len(e.Item.Files) == 0 {
			fmt.Fprintf(c.stdout, "%s has no files.\n", pos[0])
			return nil
		}
		tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
		fmt.Fprintln(tw, "NAME\tSIZE\tTYPE\tSHA-256")
		for _, f := range e.Item.Files {
			fmt.Fprintf(tw, "%s\t%d\t%s\t%s\n", f.Name, f.Size, f.Type, f.SHA256[:16]+"...")
		}
		return tw.Flush()

	case "get":
		out := fs.String("o", "", "write it to `PATH` (- for standard output; default: its own name, here)")
		force := fs.Bool("force", false, "overwrite PATH if it exists")
		pos, err := parse(fs, args[1:], 2, 2, "ITEM NAME [-o PATH|-] [--force]")
		if err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		fd, err := cl.File(ctx, c.vault, pos[0], pos[1])
		if err != nil {
			return err
		}
		defer clear(fd.Data)
		if *out == "-" {
			_, err := c.stdout.Write(fd.Data)
			return err
		}
		path := *out
		if path == "" {
			path = filepath.Base(fd.Name)
		}
		if *force {
			err = os.WriteFile(path, fd.Data, 0o600)
		} else if err = writeNew(path, fd.Data); errors.Is(err, os.ErrExist) {
			return fmt.Errorf("%s exists (use --force to overwrite it, or -o)", path)
		}
		if err != nil {
			return err
		}
		fmt.Fprintf(c.stdout, "Wrote %s (%d bytes)\n", path, len(fd.Data))
		return nil

	case "rm", "remove":
		pos, err := parse(fs, args[1:], 2, 2, "ITEM NAME")
		if err != nil {
			return err
		}
		cl, err := c.open(&u)
		if err != nil {
			return err
		}
		ctx, cancel := c.ctx()
		defer cancel()
		_, err = cl.Detach(ctx, c.vault, pos[0], pos[1])
		return err
	}
	fmt.Fprintln(c.stderr, "secretvault file: ls ITEM | get ITEM NAME [-o PATH] | rm ITEM NAME   (attach with 'secretvault attach ITEM FILE')")
	return errUsage
}
