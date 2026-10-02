package svops

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/codemodify/secretvault/svcore"
)

// Setting up the helpers other programs run: the links git, docker and
// age look for beside the secretvault CLI (as scripts/install.sh makes
// them), git's credential.helper, and docker's credsStore. A plan says
// what would change; Apply makes the changes, and Undo takes away what
// is secretvault's, leaving everything else as it is.

// HelperProgramNames are the links to set up, by the program that runs
// them.
var HelperProgramNames = []string{"git-credential-secretvault", "docker-credential-secretvault", "age-plugin-secretvault"}

// HelperLinkState is a helper's link beside the CLI, as a plan sees it
// (HelperLinks says where PATH finds each).
type HelperLinkState struct {
	Name   string // git-credential-secretvault
	Path   string // where it goes
	Ours   bool   // a link to the CLI is there already
	Other  string // something else is there (what), left alone
	Exists bool
}

// HelpersPlan is what setting the helpers up would do, or undoing it.
type HelpersPlan struct {
	CLI   string
	Links []HelperLinkState

	// Git's credential helpers now (git config --global), and whether
	// secretvault is among them; GitErr says why they could not be read.
	GitHelpers []string
	GitHas     bool
	GitErr     error

	// Docker's config file, its credsStore now, and whether it can be
	// read (DockerErr: a file that is not JSON is left alone);
	// DockerPrevious is the credsStore secretvault's replaced, put back by
	// Undo.
	DockerConfig   string
	DockerStore    string
	DockerErr      error
	DockerPrevious string
}

// helpersRecord is what Apply keeps for Undo, beside the vaults.
type helpersRecord struct {
	DockerPrevious string `json:"docker_previous,omitempty"`
}

func helpersRecordPath() (string, error) {
	h, err := svcore.Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "helpers.json"), nil
}

// helperStore is the name git and docker are given: they run
// git-credential-secretvault and docker-credential-secretvault.
const helperStore = "secretvault"

// DockerConfigPath is docker's config file: $DOCKER_CONFIG/config.json,
// else ~/.docker/config.json.
func DockerConfigPath() (string, error) {
	if d := os.Getenv("DOCKER_CONFIG"); d != "" {
		return filepath.Join(d, "config.json"), nil
	}
	h, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, ".docker", "config.json"), nil
}

// PlanHelpers looks at what is there now. cli is the secretvault CLI the
// links point at (the managers' CLIProgram()); it refuses "" (ErrNoCLI).
func PlanHelpers(cli string) (*HelpersPlan, error) {
	if cli == "" {
		return nil, ErrNoCLI
	}
	if runtime.GOOS == "windows" {
		return nil, errors.New("on Windows the helpers are copies of secretvault.exe under their names: make them by hand")
	}
	p := &HelpersPlan{CLI: cli}
	dir := filepath.Dir(cli)
	for _, name := range HelperProgramNames {
		l := HelperLinkState{Name: name, Path: filepath.Join(dir, name)}
		if st, err := os.Lstat(l.Path); err == nil {
			l.Exists = true
			target, lerr := os.Readlink(l.Path)
			switch {
			case st.Mode()&fs.ModeSymlink == 0:
				l.Other = "a file, not a link"
			case lerr == nil && (target == filepath.Base(cli) || target == cli):
				l.Ours = true
			default:
				l.Other = "a link to " + target
			}
		}
		p.Links = append(p.Links, l)
	}
	out, err := CommandRunner("git", "config", "--global", "--get-all", "credential.helper")
	switch {
	case errors.Is(err, exec.ErrNotFound):
		p.GitErr = errors.New("git is not installed")
	case err == nil:
		for _, h := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if h = strings.TrimSpace(h); h != "" {
				p.GitHelpers = append(p.GitHelpers, h)
			}
		}
	case len(bytes.TrimSpace(out)) == 0:
		// git config says nothing, and fails, when there is no such key.
	default:
		p.GitErr = fmt.Errorf("git config: %s", strings.TrimSpace(string(out)))
	}
	p.GitHas = slices.Contains(p.GitHelpers, helperStore)
	if rp, err := helpersRecordPath(); err == nil {
		if b, err := os.ReadFile(rp); err == nil {
			var rec helpersRecord
			if json.Unmarshal(b, &rec) == nil {
				p.DockerPrevious = rec.DockerPrevious
			}
		}
	}
	if p.DockerConfig, err = DockerConfigPath(); err != nil {
		p.DockerErr = err
		return p, nil
	}
	if b, err := os.ReadFile(p.DockerConfig); err == nil {
		var cfg map[string]json.RawMessage
		if err := json.Unmarshal(b, &cfg); err != nil {
			p.DockerErr = fmt.Errorf("%s is not JSON: left alone", p.DockerConfig)
		} else if raw, ok := cfg["credsStore"]; ok {
			json.Unmarshal(raw, &p.DockerStore)
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		p.DockerErr = err
	}
	return p, nil
}

// SetupLines say what Apply would do.
func (p *HelpersPlan) SetupLines() []string {
	var out []string
	for _, l := range p.Links {
		switch {
		case l.Ours:
			out = append(out, fmt.Sprintf("- %s: already a link to %s", l.Path, filepath.Base(p.CLI)))
		case l.Exists:
			out = append(out, fmt.Sprintf("- %s: %s, left alone", l.Path, l.Other))
		default:
			out = append(out, fmt.Sprintf("- link %s to %s", l.Path, filepath.Base(p.CLI)))
		}
	}
	switch {
	case p.GitErr != nil:
		out = append(out, "- git: "+p.GitErr.Error()+", left alone")
	case p.GitHas:
		out = append(out, "- git: secretvault is already among its credential helpers")
	case len(p.GitHelpers) > 0:
		out = append(out, fmt.Sprintf("- git config --global --add credential.helper secretvault (after %s, which git asks first)", strings.Join(p.GitHelpers, ", ")))
	default:
		out = append(out, "- git config --global --add credential.helper secretvault")
	}
	switch {
	case p.DockerErr != nil:
		out = append(out, "- docker: "+p.DockerErr.Error())
	case p.DockerStore == helperStore:
		out = append(out, "- docker: "+p.DockerConfig+" already has \"credsStore\": \"secretvault\"")
	case p.DockerStore != "":
		out = append(out, fmt.Sprintf("- set \"credsStore\": \"secretvault\" in %s, in place of %q", p.DockerConfig, p.DockerStore))
	default:
		out = append(out, fmt.Sprintf("- set \"credsStore\": \"secretvault\" in %s", p.DockerConfig))
	}
	return out
}

// Apply makes the links, adds secretvault to git's credential helpers,
// and makes it docker's credsStore, as the plan says; it returns what it
// did, as far as it got.
func (p *HelpersPlan) Apply() ([]string, error) {
	var done []string
	for _, l := range p.Links {
		if l.Exists {
			continue
		}
		if err := os.Symlink(filepath.Base(p.CLI), l.Path); err != nil {
			return done, err
		}
		done = append(done, "linked "+l.Path)
	}
	if p.GitErr == nil && !p.GitHas {
		if out, err := CommandRunner("git", "config", "--global", "--add", "credential.helper", helperStore); err != nil {
			return done, fmt.Errorf("git config: %v %s", err, strings.TrimSpace(string(out)))
		}
		done = append(done, "git's credential helpers include secretvault")
	}
	if p.DockerErr == nil && p.DockerStore != helperStore {
		if p.DockerStore != "" {
			rp, err := helpersRecordPath()
			if err != nil {
				return done, err
			}
			b, _ := json.Marshal(helpersRecord{DockerPrevious: p.DockerStore})
			if err := WriteReplacing(rp, b, 0o600); err != nil {
				return done, err
			}
		}
		if err := setDockerStore(p.DockerConfig, helperStore); err != nil {
			return done, err
		}
		done = append(done, "docker's credsStore is secretvault, in "+p.DockerConfig)
	}
	return done, nil
}

// UndoLines say what Undo would do.
func (p *HelpersPlan) UndoLines() []string {
	var out []string
	for _, l := range p.Links {
		if l.Ours {
			out = append(out, "- remove the link "+l.Path)
		}
	}
	if p.GitErr == nil && p.GitHas {
		out = append(out, "- git config --global --unset credential.helper '^secretvault$'")
	}
	if p.DockerErr == nil && p.DockerStore == helperStore {
		if p.DockerPrevious != "" {
			out = append(out, fmt.Sprintf("- put \"credsStore\": %q back in %s", p.DockerPrevious, p.DockerConfig))
		} else {
			out = append(out, "- take \"credsStore\": \"secretvault\" out of "+p.DockerConfig)
		}
	}
	if len(out) == 0 {
		out = append(out, "Nothing: no helper is set up for secretvault.")
	}
	return out
}

// Undo removes the links that are secretvault's, takes secretvault out of
// git's credential helpers, and out of docker's credsStore; it returns
// what it did, as far as it got.
func (p *HelpersPlan) Undo() ([]string, error) {
	var done []string
	for _, l := range p.Links {
		if !l.Ours {
			continue
		}
		if err := os.Remove(l.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return done, err
		}
		done = append(done, "removed "+l.Path)
	}
	if p.GitErr == nil && p.GitHas {
		if out, err := CommandRunner("git", "config", "--global", "--unset", "credential.helper", "^"+helperStore+"$"); err != nil {
			return done, fmt.Errorf("git config: %v %s", err, strings.TrimSpace(string(out)))
		}
		done = append(done, "git's credential helpers no longer include secretvault")
	}
	if p.DockerErr == nil && p.DockerStore == helperStore {
		if err := setDockerStore(p.DockerConfig, p.DockerPrevious); err != nil {
			return done, err
		}
		if p.DockerPrevious != "" {
			done = append(done, "docker's credsStore is "+p.DockerPrevious+" again, in "+p.DockerConfig)
		} else {
			done = append(done, "docker's credsStore is gone from "+p.DockerConfig)
		}
	}
	if rp, err := helpersRecordPath(); err == nil {
		os.Remove(rp)
	}
	return done, nil
}

// setDockerStore sets (or with "" removes) credsStore in docker's config
// file, keeping the rest of it as it is.
func setDockerStore(path, store string) error {
	cfg := map[string]json.RawMessage{}
	b, err := os.ReadFile(path)
	switch {
	case err == nil:
		if err := json.Unmarshal(b, &cfg); err != nil {
			return fmt.Errorf("%s is not JSON: left alone", path)
		}
	case errors.Is(err, fs.ErrNotExist):
		if store == "" {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return err
		}
	default:
		return err
	}
	if store == "" {
		delete(cfg, "credsStore")
	} else {
		cfg["credsStore"], _ = json.Marshal(store)
	}
	out, err := json.MarshalIndent(cfg, "", "\t")
	if err != nil {
		return err
	}
	return WriteReplacing(path, append(out, '\n'), 0o600)
}
