package main

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/codemodify/secretvault/svcontainer"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// Encrypted containers: LUKS2 image files, mounted as disks, whose keys
// are vault items (kind "container"). The daemon does the work; the image's
// header backup is read here, since it needs no key.
//
//	container create FILE --size 1G [--fs ext4] [--label L] [--item NAME] [--passphrase]
//	container open FILE [--mount-options O]      prints the mount point
//	container close FILE|MOUNTPOINT
//	container ls
//	container header-backup FILE OUT
//	container passwd FILE [--remove]             the passphrase keyslot

func (c *cli) cmdContainer(args []string) error {
	if len(args) == 0 {
		args = []string{"ls"}
	}
	switch args[0] {
	case "create":
		return c.containerCreate(args[1:])
	case "open":
		return c.containerOpen(args[1:])
	case "close":
		return c.containerClose(args[1:])
	case "ls", "list":
		return c.containerList(args[1:])
	case "header-backup":
		return c.containerHeaderBackup(args[1:])
	case "passwd":
		return c.containerPasswd(args[1:])
	}
	fmt.Fprintf(c.stderr, "secretvault container: unknown subcommand %q (create, open, close, ls, header-backup, passwd)\n", args[0])
	return errUsage
}

func (c *cli) containerCreate(args []string) error {
	fs := c.flags("container create")
	size := fs.String("size", "", "the whole image's size: `N` bytes, or with K, M, G or T (1G)")
	fsType := fs.String("fs", svcontainer.Filesystems[0], "the filesystem: "+strings.Join(svcontainer.Filesystems, ", "))
	label := fs.String("label", "", "the filesystem's label")
	item := fs.String("item", "", "the item to keep the key in (default: containers/ and the file's name)")
	withPass := fs.Bool("passphrase", false, "also make a passphrase keyslot, asked for now, so the image opens with cryptsetup alone")
	passFile := fs.String("new-passphrase-file", "", "as --passphrase, reading the passphrase from `FILE`")
	sector := fs.Int("sector-size", 4096, "the encryption sector size, 512 or 4096")
	mountOpts := fs.String("mount-options", "", "mount options, such as noexec")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "FILE --size SIZE [--fs ext4] [--label L] [--item NAME] [--passphrase]")
	if err != nil {
		return err
	}
	if err := svops.MountsHere(); err != nil {
		return err
	}
	if *size == "" {
		return errors.New("say how big the container is, with --size (512M, 1G, ...)")
	}
	n, err := svops.ParseSize(*size)
	if err != nil {
		return err
	}
	path, err := filepath.Abs(pos[0])
	if err != nil {
		return err
	}
	if *item == "" {
		*item = svops.ContainerItemName(path)
	}
	var pass []byte
	if *withPass || *passFile != "" {
		if pass, err = c.newPassphrase(*passFile); err != nil {
			return err
		}
		defer clear(pass)
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	info, err := cl.CreateContainer(ctx, svrpc.ContainerCreateParams{Vault: c.vault, Item: *item, Path: path, Size: n,
		FS: *fsType, Label: *label, SectorSize: *sector, Passphrase: pass, MountOptions: *mountOpts})
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "Created %s (%s, %s); its key is the item %s.\n", info.Path, svops.HumanSize(n), *fsType, info.Item)
	if len(pass) > 0 {
		fmt.Fprintln(c.stderr, "The passphrase also opens it, with cryptsetup alone.")
	}
	fmt.Fprintln(c.stdout, info.MountPoint)
	return nil
}

func (c *cli) containerOpen(args []string) error {
	fs := c.flags("container open")
	item := fs.String("item", "", "the item that holds the key (default: the one made for this image)")
	mountOpts := fs.String("mount-options", "", "mount options, such as ro or noexec")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "FILE [--item NAME] [--mount-options O]")
	if err != nil {
		return err
	}
	if err := svops.MountsHere(); err != nil {
		return err
	}
	path, err := svops.ExistingImage(pos[0])
	if err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	info, err := cl.OpenContainer(ctx, svrpc.ContainerOpenParams{Vault: c.vault, Item: *item, Path: path, MountOptions: *mountOpts})
	if err != nil {
		return err
	}
	fmt.Fprintln(c.stdout, info.MountPoint)
	return nil
}

func (c *cli) containerClose(args []string) error {
	pos, err := parse(c.flags("container close"), args, 1, 1, "FILE|MOUNTPOINT")
	if err != nil {
		return err
	}
	if err := svops.MountsHere(); err != nil {
		return err
	}
	target, err := filepath.Abs(pos[0])
	if err != nil {
		return err
	}
	cl, err := c.daemon()
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	info, err := cl.CloseContainer(ctx, target)
	if err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "Closed %s.\n", info.Path)
	return nil
}

func (c *cli) containerList(args []string) error {
	fs := c.flags("container ls")
	var u unlockFlags
	u.register(fs)
	if _, err := parse(fs, args, 0, 0, ""); err != nil {
		return err
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	list, err := cl.Containers(ctx, c.vault)
	if err != nil {
		return err
	}
	if len(list) == 0 {
		fmt.Fprintln(c.stderr, "No containers in this vault; make one with 'secretvault container create'.")
		return nil
	}
	tw := tabwriter.NewWriter(c.stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "ITEM\tFILE\tSTATE")
	for _, ci := range list {
		state := ci.State
		switch ci.State {
		case "mounted":
			state = "mounted at " + ci.MountPoint
		case "unknown":
			state = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\n", ci.Item, ci.Path, state)
	}
	return tw.Flush()
}

func (c *cli) containerHeaderBackup(args []string) error {
	pos, err := parse(c.flags("container header-backup"), args, 2, 2, "FILE OUT")
	if err != nil {
		return err
	}
	if err := svcontainer.BackupHeader(pos[0], pos[1]); err != nil {
		return err
	}
	fmt.Fprintf(c.stderr, "Wrote %s's header to %s.\n", pos[0], pos[1])
	fmt.Fprintln(c.stderr, "Keep it as safe as the key: with it, any key or passphrase that opens the container today opens it later, even after that keyslot is gone.")
	return nil
}

func (c *cli) containerPasswd(args []string) error {
	fs := c.flags("container passwd")
	item := fs.String("item", "", "the item that holds the key (default: the one made for this image)")
	remove := fs.Bool("remove", false, "remove the passphrase keyslot instead")
	passFile := fs.String("new-passphrase-file", "", "read the new passphrase from `FILE` instead of asking")
	var u unlockFlags
	u.register(fs)
	pos, err := parse(fs, args, 1, 1, "FILE [--item NAME] [--remove]")
	if err != nil {
		return err
	}
	path, err := svops.ExistingImage(pos[0])
	if err != nil {
		return err
	}
	var pass []byte
	if !*remove {
		if pass, err = c.newPassphrase(*passFile); err != nil {
			return err
		}
		defer clear(pass)
	}
	cl, err := c.open(&u)
	if err != nil {
		return err
	}
	ctx, cancel := c.ctx()
	defer cancel()
	info, err := cl.ContainerPasswd(ctx, svrpc.ContainerPasswdParams{Vault: c.vault, Item: *item, Path: path, Passphrase: pass, Remove: *remove})
	if err != nil {
		return err
	}
	if *remove {
		fmt.Fprintf(c.stderr, "Removed the passphrase keyslot of %s; only the vault's key opens it now.\n", info.Path)
	} else {
		fmt.Fprintf(c.stderr, "%s opens with the new passphrase (and cryptsetup alone).\n", info.Path)
	}
	return nil
}
