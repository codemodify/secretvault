package svops

import (
	"strings"
	"testing"
)

// The managers' shared words keep docs/wording.md's rules where a test
// can hold them: no reference, path or command in the first sentence,
// and no more than three sentences.
func TestTheManagersWordsLeadPlainly(t *testing.T) {
	for _, s := range []string{
		ContainersAbout, ContainersNone, ContainerNewAbout, ContainerOpenAbout, ContainerCloseAbout,
		ContainerPassphraseAbout, HeaderBackupAbout, HeaderBackupWarning,
		SignFileAbout, CheckSignatureAbout, DecryptPGPAbout, EncryptAgeAbout, DecryptAgeAbout,
		InspectMessageAbout, ComposeMessageAbout, ResolveReferenceAbout, CheckEnvFileAbout, CheckTemplateAbout,
		DeleteItemText("web/example.com", "personal", "R"), RemoveFileText("a.pdf", "web/example.com"),
		RestoreRevisionText("web/example.com", "2026-01-02 15:04"), KeepVersionText("web/example.com"),
	} {
		first, _, _ := strings.Cut(s, ". ")
		for _, bad := range []string{"sv://", "secretvault ", "keyslot", "recipient", "LUKS", "--"} {
			if strings.Contains(first, bad) {
				t.Errorf("%q leads with %q", s, bad)
			}
		}
		if n := strings.Count(s+" ", ". "); n > 3 {
			t.Errorf("%d sentences: %q", n, s)
		}
	}
}

func TestImportedAndCheckedSayCounts(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{ImportedText(2, 0, 0, 0), "2 items were imported."},
		{ImportedText(1, 1, 0, 0), "1 item was imported, with 1 attached file."},
		{ImportedText(0, 0, 2, 1), "No items were imported. 2 items the vault had already were skipped. 1 warning: the details say what."},
		{ReferencesChecked(0, 0), "There are no references to secrets in it."},
		{ReferencesChecked(1, 1), "The reference in it can be read."},
		{ReferencesChecked(3, 3), "All 3 references in it can be read."},
		{ReferencesChecked(1, 2), "1 of 2 references in it cannot be read; each is listed with why."},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}
