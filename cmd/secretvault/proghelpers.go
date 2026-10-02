package main

import (
	"fmt"

	"github.com/codemodify/secretvault/svops"
)

// `secretvault helpers status|setup|undo`: the helpers git, docker and
// age start (git-credential-secretvault, docker-credential-secretvault,
// age-plugin-secretvault) linked beside this program, git's
// credential.helper and docker's credsStore set to secretvault, and that
// undone. What changes where, and how it is undone, is svops'
// (proghelpers.go), in its words; here are the flags and the dry runs.

func (c *cli) cmdHelpers(args []string) error {
	if len(args) == 0 {
		args = []string{"status"}
	}
	switch args[0] {
	case "status":
		return c.helpersStatus(args[1:])
	case "setup":
		return c.helpersSetup(args[1:])
	case "undo":
		return c.helpersUndo(args[1:])
	}
	fmt.Fprintf(c.stderr, "secretvault helpers: unknown subcommand %q (status, setup, undo)\n", args[0])
	return errUsage
}

// helpersPlan looks at the helpers as they are now, for this program:
// the links lead to it, by its own path, links resolved.
func (c *cli) helpersPlan() (*svops.HelpersPlan, error) {
	self := c.self
	if self == nil {
		self = svops.Executable
	}
	exe, err := self()
	if err != nil {
		return nil, err
	}
	return svops.PlanHelpers(exe)
}

func (c *cli) helpersStatus(args []string) error {
	if _, err := parse(c.flags("helpers status"), args, 0, 0, ""); err != nil {
		return err
	}
	plan, err := c.helpersPlan()
	if err != nil {
		return err
	}
	rows := plan.StatusRows()
	width := 0
	for _, r := range rows {
		width = max(width, len(r[0]))
	}
	for _, r := range rows {
		fmt.Fprintf(c.stdout, "%-*s  %s\n", width, r[0], r[1])
	}
	if plan.Undoable() {
		fmt.Fprintln(c.stdout, "\nUndo with 'secretvault helpers undo'.")
	} else {
		fmt.Fprintln(c.stdout, "\nSet them up with 'secretvault helpers setup' (--dry-run shows what would change).")
	}
	return nil
}

func (c *cli) helpersSetup(args []string) error {
	fs := c.flags("helpers setup")
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--dry-run]"); err != nil {
		return err
	}
	plan, err := c.helpersPlan()
	if err != nil {
		return err
	}
	if *dryRun {
		fmt.Fprintln(c.stdout, svops.HelpersSetupIntro(plan.CLI))
		c.printLines(plan.SetupLines())
		fmt.Fprintln(c.stdout, "\nNothing was changed. Undo a setup with 'secretvault helpers undo'.")
		return nil
	}
	done, err := plan.Apply()
	c.printLines(done)
	if err != nil {
		return fmt.Errorf("%w (undo what was done with 'secretvault helpers undo')", err)
	}
	if len(done) == 0 {
		c.printLines(plan.SetupLines())
		fmt.Fprintln(c.stdout, "\nNothing was changed.")
		return nil
	}
	fmt.Fprintln(c.stdout, "\nUndo with 'secretvault helpers undo'.")
	return nil
}

func (c *cli) helpersUndo(args []string) error {
	fs := c.flags("helpers undo")
	dryRun := fs.Bool("dry-run", false, "show what would change, and change nothing")
	if _, err := parse(fs, args, 0, 0, "[--dry-run]"); err != nil {
		return err
	}
	plan, err := c.helpersPlan()
	if err != nil {
		return err
	}
	if !plan.Undoable() {
		fmt.Fprintln(c.stdout, svops.HelpersNothingToUndo)
		return nil
	}
	if *dryRun {
		fmt.Fprintln(c.stdout, svops.HelpersUndoIntro)
		c.printLines(plan.UndoLines())
		fmt.Fprintln(c.stdout, "\nNothing was changed.")
		return nil
	}
	done, err := plan.Undo()
	c.printLines(done)
	return err
}

func (c *cli) printLines(lines []string) {
	for _, l := range lines {
		fmt.Fprintln(c.stdout, l)
	}
}
