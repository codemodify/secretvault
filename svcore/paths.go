package svcore

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/codemodify/secretvault/svformat"
)

// secretvault keeps two folders for each person: its settings, and its
// data. Settings are what a person (or `secretvault ...`) chose, and the
// records of what secretvault changed in other programs so that it can
// undo it; data is everything else it keeps: vaults, keys, logs and
// state.

const (
	// EnvHome moves the data folder. Set alone, it moves the settings
	// too: everything is then kept in that one folder, as before the two
	// were apart (tests and second installations rely on it).
	EnvHome = "SECRETVAULT_HOME"

	// EnvConfig moves the settings folder.
	EnvConfig = "SECRETVAULT_CONFIG"
)

// ConfigDir is secretvault's per-user settings folder:
//
//	$SECRETVAULT_CONFIG, if set; else $SECRETVAULT_HOME, if set
//	Linux, BSD  $XDG_CONFIG_HOME/secretvault, else ~/.config/secretvault
//	macOS       ~/Library/Preferences/secretvault
//	Windows     %APPDATA%\secretvault
func ConfigDir() (string, error) {
	if d := os.Getenv(EnvConfig); d != "" {
		return d, nil
	}
	if d := os.Getenv(EnvHome); d != "" {
		return d, nil
	}
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, "secretvault"), nil
		}
		return "", errors.New("svcore: %APPDATA% is not set")
	case "darwin":
		u, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(u, "Library", "Preferences", "secretvault"), nil
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "secretvault"), nil
	}
	u, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(u, ".config", "secretvault"), nil
}

// DataDir is secretvault's per-user data folder:
//
//	$SECRETVAULT_HOME, if set
//	Linux, BSD  ~/.data/secretvault
//	macOS       ~/Library/Application Support/secretvault
//	Windows     %LOCALAPPDATA%\secretvault (local, not roaming: vaults are
//	            synced by secretvault, not by the Windows profile)
func DataDir() (string, error) {
	if h := os.Getenv(EnvHome); h != "" {
		return h, nil
	}
	switch runtime.GOOS {
	case "windows", "darwin":
		return LegacyDir()
	}
	u, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(u, ".data", "secretvault"), nil
}

// LegacyDir is the one folder secretvault kept everything in before
// settings and data were apart: on Linux and the BSDs
// $XDG_DATA_HOME/secretvault, else ~/.local/share/secretvault; elsewhere
// the data folder, which has not moved there. It ignores
// $SECRETVAULT_HOME: what was moved by hand is not moved again.
func LegacyDir() (string, error) {
	switch runtime.GOOS {
	case "windows":
		if d := os.Getenv("LOCALAPPDATA"); d != "" {
			return filepath.Join(d, "secretvault"), nil
		}
		return "", errors.New("svcore: %LOCALAPPDATA% is not set")
	case "darwin":
		u, err := os.UserHomeDir()
		if err != nil {
			return "", err
		}
		return filepath.Join(u, "Library", "Application Support", "secretvault"), nil
	}
	if d := os.Getenv("XDG_DATA_HOME"); filepath.IsAbs(d) {
		return filepath.Join(d, "secretvault"), nil
	}
	u, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(u, ".local", "share", "secretvault"), nil
}

// VaultDir is where the named vault of this user lives: DATA/vaults/<name>.
func VaultDir(name string) (string, error) {
	h, err := DataDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "vaults", name), nil
}

type deviceFile struct {
	ID      svformat.ID `json:"id"`
	Created time.Time   `json:"created"`
}

// Device returns this installation's device ID, kept in DATA/device.json
// and created on first use. Revisions record it, so a conflict can say
// which device wrote which side.
func Device(home string) (svformat.ID, error) {
	p := filepath.Join(home, "device.json")
	b, err := os.ReadFile(p)
	if err == nil {
		var d deviceFile
		if err := json.Unmarshal(b, &d); err == nil && !d.ID.IsZero() {
			return d.ID, nil
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return svformat.ID{}, err
	}
	d := deviceFile{ID: svformat.NewID(), Created: time.Now().UTC()}
	b, _ = json.MarshalIndent(d, "", "  ")
	if err := os.MkdirAll(home, 0o700); err != nil {
		return svformat.ID{}, err
	}
	if err := os.WriteFile(p, append(b, '\n'), 0o600); err != nil {
		return svformat.ID{}, err
	}
	return d.ID, nil
}
