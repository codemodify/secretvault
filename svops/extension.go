package svops

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/codemodify/secretvault/browser"
)

// secretvault's own browser extension, packaged from the copy every
// program carries (package browser), for one family of browsers:
//
//   - Firefox: a .zip with manifest.json at its root, which Firefox loads
//     as a temporary add-on and addons.mozilla.org takes to sign (or the
//     same files in a folder, whose manifest.json about:debugging takes).
//   - Chromium (Chrome, Chromium, Brave, Edge, Vivaldi): a folder, which
//     "Load unpacked" takes, or a .zip, which the Chrome Web Store takes.
//
// There is one source tree. Its manifest.json holds what both families
// need; each package's manifest is that one without what the other family
// alone reads (ExtensionManifest), so that neither browser warns about a
// key it does not know. Nothing here signs or uploads anything
// (docs/browser.md says how the person does).

// ExtensionTarget is a family of browsers the extension is packaged for.
type ExtensionTarget string

const (
	TargetFirefox  ExtensionTarget = "firefox"
	TargetChromium ExtensionTarget = "chromium" // Chrome, Chromium, Brave, Edge, Vivaldi
)

// ExtensionTargets are the targets, as --target takes them.
var ExtensionTargets = []ExtensionTarget{TargetFirefox, TargetChromium}

// ParseExtensionTarget reads a target's name; "chrome" and the other
// Chromium browsers' names are taken for chromium.
func ParseExtensionTarget(s string) (ExtensionTarget, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "firefox":
		return TargetFirefox, nil
	case "chromium", "chrome", "brave", "edge", "vivaldi":
		return TargetChromium, nil
	}
	return "", fmt.Errorf("no extension target %q (firefox or chromium)", s)
}

// Browsers names the browsers a target is for, for people.
func (t ExtensionTarget) Browsers() string {
	if t == TargetChromium {
		return "Chrome, Chromium, Brave, Edge or Vivaldi"
	}
	return "Firefox"
}

// ExtensionVersion is the extension's version, from its manifest.
func ExtensionVersion() string {
	b, err := fs.ReadFile(browser.Extension(), "manifest.json")
	if err != nil {
		return ""
	}
	var m struct {
		Version string `json:"version"`
	}
	json.Unmarshal(b, &m)
	return m.Version
}

// ExtensionFileName is the package's usual name, a .zip:
// secretvault-extension-0.1.0.zip for Firefox, and
// secretvault-extension-0.1.0-chromium.zip for Chromium.
func ExtensionFileName(t ExtensionTarget) string { return ExtensionDirName(t) + ".zip" }

// ExtensionDirName is the usual name of a folder of the extension's files.
func ExtensionDirName(t ExtensionTarget) string {
	name := "secretvault-extension-" + ExtensionVersion()
	if t == TargetChromium {
		name += "-chromium"
	}
	return name
}

// packTime is every packaged file's time, so that the same extension
// makes the same package.
var packTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

func extensionFiles() ([]string, error) {
	var files []string
	err := fs.WalkDir(browser.Extension(), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			files = append(files, p)
		}
		return nil
	})
	sort.Slice(files, func(i, j int) bool {
		// The manifest first, as stores like to find it.
		if (files[i] == "manifest.json") != (files[j] == "manifest.json") {
			return files[i] == "manifest.json"
		}
		return files[i] < files[j]
	})
	return files, err
}

// extensionFile is one packaged file's contents for target t: the
// manifest made for t (for the Chrome Web Store when store), the rest as
// they are.
func extensionFile(p string, t ExtensionTarget, store bool) ([]byte, error) {
	if p == "manifest.json" {
		return extensionManifest(t, store)
	}
	return fs.ReadFile(browser.Extension(), p)
}

// member is one member of a JSON object, kept in its order.
type member struct {
	key string
	raw json.RawMessage
}

// readObject reads a JSON object's members in order.
func readObject(b []byte) ([]member, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil, errors.New("not a JSON object")
	}
	var out []member
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			return nil, err
		}
		k, _ := t.(string)
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return nil, err
		}
		out = append(out, member{k, raw})
	}
	return out, nil
}

// writeObject writes members back as an object, in their order.
func writeObject(ms []member) []byte {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, m := range ms {
		if i > 0 {
			b.WriteByte(',')
		}
		k, _ := json.Marshal(m.key)
		b.Write(k)
		b.WriteByte(':')
		b.Write(m.raw)
	}
	b.WriteByte('}')
	return b.Bytes()
}

// without is ms without the members named.
func without(ms []member, keys ...string) []member {
	var out []member
	for _, m := range ms {
		drop := false
		for _, k := range keys {
			drop = drop || m.key == k
		}
		if !drop {
			out = append(out, m)
		}
	}
	return out
}

// ExtensionManifest is manifest.json as packaged for t. The source
// manifest serves both families; for each, what only the other reads is
// taken out:
//
//   - Firefox: the "key" that fixes the Chromium ID, minimum_chrome_version,
//     the background's service_worker (Firefox runs background.scripts),
//     and use_dynamic_url, which it does not know.
//   - Chromium: browser_specific_settings (Firefox's ID and minimum version)
//     and background.scripts (the service worker imports them itself).
//
// The Chromium zip is for the Chrome Web Store, which refuses a manifest
// with a "key" (it takes the ID's private key apart, as key.pem): its
// manifest is Chromium's without the key (ExtensionStoreManifest).
func ExtensionManifest(t ExtensionTarget) ([]byte, error) { return extensionManifest(t, false) }

// ExtensionStoreManifest is the manifest of the Chromium zip, for the
// Chrome Web Store: Chromium's, without "key".
func ExtensionStoreManifest() ([]byte, error) { return extensionManifest(TargetChromium, true) }

func extensionManifest(t ExtensionTarget, store bool) ([]byte, error) {
	src, err := fs.ReadFile(browser.Extension(), "manifest.json")
	if err != nil {
		return nil, err
	}
	top, err := readObject(src)
	if err != nil {
		return nil, fmt.Errorf("manifest.json: %w", err)
	}
	var dropTop, dropBackground []string
	switch t {
	case TargetFirefox:
		dropTop, dropBackground = []string{"key", "minimum_chrome_version"}, []string{"service_worker"}
	case TargetChromium:
		dropTop, dropBackground = []string{"browser_specific_settings"}, []string{"scripts"}
		if store {
			dropTop = append(dropTop, "key")
		}
	default:
		return nil, fmt.Errorf("no extension target %q", t)
	}
	top = without(top, dropTop...)
	for i, m := range top {
		switch m.key {
		case "background":
			bg, err := readObject(m.raw)
			if err != nil {
				return nil, fmt.Errorf("manifest.json: background: %w", err)
			}
			top[i].raw = writeObject(without(bg, dropBackground...))
		case "web_accessible_resources":
			if t != TargetFirefox {
				continue
			}
			var list []json.RawMessage
			if err := json.Unmarshal(m.raw, &list); err != nil {
				return nil, fmt.Errorf("manifest.json: web_accessible_resources: %w", err)
			}
			for j, raw := range list {
				w, err := readObject(raw)
				if err != nil {
					return nil, fmt.Errorf("manifest.json: web_accessible_resources: %w", err)
				}
				list[j] = writeObject(without(w, "use_dynamic_url"))
			}
			top[i].raw, _ = json.Marshal(list)
		}
	}
	var out bytes.Buffer
	if err := json.Indent(&out, writeObject(top), "", "  "); err != nil {
		return nil, err
	}
	out.WriteByte('\n')
	return out.Bytes(), nil
}

// PackExtension writes the extension for t as a zip: for Chromium, the
// Chrome Web Store's package, whose manifest has no "key".
func PackExtension(w io.Writer, t ExtensionTarget) error {
	files, err := extensionFiles()
	if err != nil {
		return err
	}
	z := zip.NewWriter(w)
	for _, p := range files {
		data, err := extensionFile(p, t, t == TargetChromium)
		if err != nil {
			return err
		}
		h := &zip.FileHeader{Name: p, Method: zip.Deflate, Modified: packTime}
		h.SetMode(0o644)
		f, err := z.CreateHeader(h)
		if err != nil {
			return err
		}
		if _, err := f.Write(data); err != nil {
			return err
		}
	}
	return z.Close()
}

// ErrExtensionExists is a package or folder already there, which writing
// the extension does not replace unless told to.
var ErrExtensionExists = errors.New("it is there already")

// WriteExtension writes the extension's zip for t to path, replacing a
// file there only when replace is set.
func WriteExtension(path string, t ExtensionTarget, replace bool) error {
	var buf bytes.Buffer
	if err := PackExtension(&buf, t); err != nil {
		return err
	}
	if !replace {
		if _, err := os.Lstat(path); err == nil {
			return fmt.Errorf("%s: %w", path, ErrExtensionExists)
		}
	}
	return WriteReplacing(path, buf.Bytes(), 0o644)
}

// WriteExtensionDir writes the extension's files for t into dir, which
// must be missing or empty.
func WriteExtensionDir(dir string, t ExtensionTarget) error {
	if entries, err := os.ReadDir(dir); err == nil && len(entries) > 0 {
		return fmt.Errorf("%s: %w, and is not empty", dir, ErrExtensionExists)
	}
	files, err := extensionFiles()
	if err != nil {
		return err
	}
	for _, p := range files {
		data, err := extensionFile(p, t, false)
		if err != nil {
			return err
		}
		out := filepath.Join(dir, filepath.FromSlash(p))
		if err := os.MkdirAll(filepath.Dir(out), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(out, data, 0o644); err != nil {
			return err
		}
	}
	return nil
}

// ExtensionFileCount is how many files the extension has, to say so.
func ExtensionFileCount() int {
	files, _ := extensionFiles()
	return len(files)
}
