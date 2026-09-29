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
)

// Config is secretvaultd's settings, kept in <home>/config.json (0600).
type Config struct {
	Vaults  []VaultConfig `json:"vaults"`
	Default string        `json:"default,omitempty"`
	Prompt  PromptConfig  `json:"prompt,omitempty"`

	// SecretService makes the daemon the desktop's keyring
	// (org.freedesktop.secrets). `secretvault keyring takeover` turns it on.
	SecretService bool `json:"secret_service,omitempty"`
}

// VaultConfig registers one vault.
type VaultConfig struct {
	Name     string         `json:"name"`
	Path     string         `json:"path"`
	AutoLock svrpc.AutoLock `json:"auto_lock"`
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
// existed, or copied in by hand).
func loadConfig(home string) (*Config, error) {
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
		cfg.Vaults = append(cfg.Vaults, VaultConfig{Name: name, Path: filepath.Join(home, "vaults", name), AutoLock: DefaultAutoLock})
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
	if err := os.MkdirAll(home, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(home, ".config-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(append(b, '\n'))
	if err == nil {
		err = tmp.Sync()
	}
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), configPath(home))
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}
