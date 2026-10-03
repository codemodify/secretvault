package svops

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svimport"
)

// Every source is one svimport reads, called by a name no other takes,
// with steps to follow, and asks only for what its export needs.
func TestTheImportSourcesAreWhole(t *testing.T) {
	if ImportSources[0].Name != "firefox" {
		t.Errorf("the first source is %s, not Firefox", ImportSources[0].Name)
	}
	names := map[string]bool{}
	formats := map[svimport.Format]bool{}
	for _, s := range ImportSources {
		for _, n := range append([]string{s.Name}, s.Aliases...) {
			if names[n] || n != strings.ToLower(n) || n == "auto" || n == "sources" {
				t.Errorf("%s: the name %q is taken, not lower case, or a word import keeps", s.Label, n)
			}
			names[n] = true
		}
		if !slices.Contains(svimport.Formats, s.Format) {
			t.Errorf("%s: svimport does not read %q", s.Label, s.Format)
		}
		formats[s.Format] = true
		if s.Label == "" || s.Program == "" || len(s.Steps) < 2 || s.File == "" {
			t.Errorf("%s: a label, steps and the file's name, please: %+v", s.Name, s)
		}
		if strings.ContainsAny(strings.Join(s.Steps, ""), "☰⋯⋮") {
			t.Errorf("%s: a menu drawn with a glyph few fonts have", s.Name)
		}
		for i, st := range s.NumberedSteps() {
			if !strings.HasPrefix(st, fmt.Sprintf("%d. ", i+1)) || !strings.HasSuffix(st, ".") && !strings.HasSuffix(st, ")") && !strings.HasSuffix(st, "…") {
				t.Errorf("%s: step %q", s.Name, st)
			}
		}
		if s.Keyfile != (s.Format == svimport.FormatKDBX) {
			t.Errorf("%s: a key file is asked for KeePass only", s.Name)
		}
		encryptable := s.Format == svimport.FormatKDBX || s.Format == svimport.FormatBitwarden || s.Format == svimport.FormatAegis
		if (s.Passphrase != "") != encryptable || (s.Passphrase != "") != (s.PassphraseHint != "") {
			t.Errorf("%s: a passphrase is asked for encrypted exports only", s.Name)
		}
		if s.Unencrypted == (s.UnencryptedNote() == "") {
			t.Errorf("%s: the note on an unencrypted export", s.Name)
		}
	}
	for _, f := range svimport.Formats {
		if !formats[f] {
			t.Errorf("no source reads %s", f)
		}
	}
	for _, want := range []string{"firefox", "chrome", "safari", "bitwarden", "1password", "keepass", "protonpass", "aegis", "google-authenticator", "cxf", "csv"} {
		if !names[want] {
			t.Errorf("no source %s", want)
		}
	}
	if s, ok := FindImportSource(" Edge "); !ok || s.Name != "chrome" {
		t.Errorf("edge is %+v %v", s, ok)
	}
	if _, ok := FindImportSource("kdbx4"); ok {
		t.Error("an unknown source was found")
	}
	if !strings.Contains(ImportSources[0].NumberedSteps()[0], "about:logins") {
		t.Errorf("Firefox's first step: %q", ImportSources[0].NumberedSteps()[0])
	}
}

func TestASourceNamesItsFormat(t *testing.T) {
	for in, want := range map[string]svimport.Format{"firefox": "csv", "Brave": "csv", "keepassxc": "kdbx", "kdbx": "kdbx",
		"1password": "1pux", "1pux": "1pux", "csv": "csv", "aegis": "aegis"} {
		if f, guessed, err := ImportFormat(in, "x", nil); f != want || guessed || err != nil {
			t.Errorf("%s: %q %v %v", in, f, guessed, err)
		}
	}
	if f, guessed, _ := ImportFormat("auto", "logins.csv", []byte("url,username,password\n")); f != "csv" || !guessed {
		t.Errorf("auto: %q %v", f, guessed)
	}
}

func TestAnExportIsRemovedPlainly(t *testing.T) {
	p := filepath.Join(t.TempDir(), "logins.csv")
	if err := os.WriteFile(p, []byte("url,username,password\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveExport(p); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(p); !os.IsNotExist(err) {
		t.Fatalf("still there: %v", err)
	}
	note := DeleteExportNote(p, "personal")
	if !strings.Contains(note, "unencrypted") || strings.Contains(strings.ToLower(note), "secure") {
		t.Errorf("the note: %q", note)
	}
}
