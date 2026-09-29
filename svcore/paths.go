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

// EnvHome overrides where secretvault keeps its per-user data.
const EnvHome = "SECRETVAULT_HOME"

// Home is secretvault's per-user data directory:
//
//	$SECRETVAULT_HOME, if set
//	Linux, BSD  $XDG_DATA_HOME/secretvault, else ~/.local/share/secretvault
//	macOS       ~/Library/Application Support/secretvault
//	Windows     %LOCALAPPDATA%\secretvault (local, not roaming: vaults are
//	            synced by secretvault, not by the Windows profile)
func Home() (string, error) {
	if h := os.Getenv(EnvHome); h != "" {
		return h, nil
	}
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

// VaultDir is where the named vault of this user lives: Home/vaults/<name>.
func VaultDir(name string) (string, error) {
	h, err := Home()
	if err != nil {
		return "", err
	}
	return filepath.Join(h, "vaults", name), nil
}

type deviceFile struct {
	ID      svformat.ID `json:"id"`
	Created time.Time   `json:"created"`
}

// Device returns this installation's device ID, kept in Home/device.json
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
