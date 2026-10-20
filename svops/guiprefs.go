package svops

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/codemodify/secretvault/svcore"
)

// The desktop manager's own settings, in the settings folder: its look,
// which its windows and the passphrase prompts are drawn in (Tools ›
// Appearance). A file that is missing or not read is the default.

// GUIFile is the desktop manager's settings file, in the settings folder.
const GUIFile = "gui.json"

// The looks the desktop manager can be in.
const (
	LookDesktop = "desktop" // dark or light as the desktop is set (the default)
	LookDark    = "dark"
	LookLight   = "light"
)

// GUIPrefs are the desktop manager's settings.
type GUIPrefs struct {
	Look string `json:"look,omitempty"` // LookDesktop, LookDark, LookLight
}

// GUIPrefsFile is where they are kept.
func GUIPrefsFile() (string, error) {
	dir, err := svcore.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, GUIFile), nil
}

// LoadGUIPrefs reads them; what is missing, or not one of the choices, is
// the default.
func LoadGUIPrefs() GUIPrefs {
	var p GUIPrefs
	if path, err := GUIPrefsFile(); err == nil {
		if b, err := os.ReadFile(path); err == nil {
			json.Unmarshal(b, &p)
		}
	}
	switch p.Look {
	case LookDark, LookLight:
	default:
		p.Look = LookDesktop
	}
	return p
}

// SaveGUIPrefs keeps them, in a file only its owner reads.
func SaveGUIPrefs(p GUIPrefs) error {
	path, err := GUIPrefsFile()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return WriteReplacing(path, append(b, '\n'), 0o600)
}
