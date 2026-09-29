package svd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"

	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svsync"
)

// Config is secretvaultd's settings, kept in <home>/config.json (0600).
type Config struct {
	Vaults  []VaultConfig `json:"vaults"`
	Default string        `json:"default,omitempty"`
	Prompt  PromptConfig  `json:"prompt,omitempty"`

	// SecretService makes the daemon the desktop's keyring
	// (org.freedesktop.secrets). `secretvault keyring takeover` turns it on.
	SecretService bool `json:"secret_service,omitempty"`

	// NoSSHAgent turns off the SSH agent socket (on by default: it serves
	// only programs pointed at it with SSH_AUTH_SOCK).
	NoSSHAgent bool `json:"no_ssh_agent,omitempty"`

	// Directories are organisations' LDAP directories, asked for people's
	// keys (directory.go).
	Directories []svrpc.DirectoryConfig `json:"directories,omitempty"`

	// ContactsVault is the vault contacts are kept in ("" for the default
	// vault). `secretvault contact vault NAME` sets it.
	ContactsVault string `json:"contacts_vault,omitempty"`

	// CloseContainersOnLock closes a vault's open containers when the
	// vault locks. Off by default: containers stay mounted, as VeraCrypt's
	// do (containers.go).
	CloseContainersOnLock bool `json:"close_containers_on_lock,omitempty"`
}

// VaultConfig registers one vault.
type VaultConfig struct {
	Name     string         `json:"name"`
	Path     string         `json:"path"`
	AutoLock svrpc.AutoLock `json:"auto_lock"`

	// Sync is the server the vault is kept in step with, if any
	// (`secretvault sync setup` or `sync join`).
	Sync *svsync.Remote `json:"sync,omitempty"`

	// LoginUnlock opens the vault when the daemon starts at login (login.go).
	LoginUnlock bool `json:"login_unlock,omitempty"`
}

// PromptConfig says how desktop prompts are shown.
type PromptConfig struct {
	// Program is the pinentry to use for desktop prompts; "" picks one
	// (docs/architecture.md, "Prompts"), "none" disables desktop prompts.
	Program string `json:"program,omitempty"`
}

// DefaultAutoLock is how a vault unlocked by passphrase locks itself:
// after 15 idle minutes, on screen lock and on sleep.
var DefaultAutoLock = svrpc.AutoLock{IdleMinutes: 15, OnScreenLock: true, OnSleep: true}

// LoginAutoLock is how a vault opened at login locks itself: when the
// session ends, with the daemon, as a login keyring does.
var LoginAutoLock = svrpc.AutoLock{}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// checkVaultName accepts short names that are also safe directory names.
func checkVaultName(name string) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("%q is not a vault name (letters, digits, '.', '_' and '-', at most 64)", name)
	}
	return nil
}

func configPath(home string) string { return filepath.Join(home, "config.json") }

// loadConfig reads the config, and registers any vault folder found under
// <home>/vaults that it does not list yet (vaults made before the daemon
// existed, or copied in by hand), locking as autoLock says.
func loadConfig(home string, autoLock svrpc.AutoLock) (*Config, error) {
	cfg := &Config{}
	b, err := os.ReadFile(configPath(home))
	switch {
	case err == nil:
		if err := json.Unmarshal(b, cfg); err != nil {
			return nil, fmt.Errorf("%s: %w", configPath(home), err)
		}
	case !errors.Is(err, fs.ErrNotExist):
		return nil, err
	}
	known := map[string]bool{}
	for _, v := range cfg.Vaults {
		known[v.Name] = true
	}
	entries, _ := os.ReadDir(filepath.Join(home, "vaults"))
	var found []string
	for _, e := range entries {
		p := filepath.Join(home, "vaults", e.Name())
		if !e.IsDir() || known[e.Name()] || checkVaultName(e.Name()) != nil {
			continue
		}
		if _, err := os.Stat(filepath.Join(p, svformat.DescriptorName)); err == nil {
			found = append(found, e.Name())
		}
	}
	sort.Strings(found)
	for _, name := range found {
		cfg.Vaults = append(cfg.Vaults, VaultConfig{Name: name, Path: filepath.Join(home, "vaults", name), AutoLock: autoLock})
	}
	if cfg.Default == "" && len(cfg.Vaults) > 0 {
		cfg.Default = cfg.Vaults[0].Name
		for _, v := range cfg.Vaults {
			if v.Name == "default" {
				cfg.Default = "default"
			}
		}
	}
	return cfg, nil
}

// save writes the config atomically.
func (c *Config) save(home string) error {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	return writeAtomic(configPath(home), append(b, '\n'))
}

// writeAtomic replaces the file at path with b (mode 0600): readers see
// the old file or the new one, never half of either.
func writeAtomic(path string, b []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(b)
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}
