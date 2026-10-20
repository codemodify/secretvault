package svops

import (
	"slices"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svcore"
)

// The managers' shared words keep docs/wording.md's rules where a test
// can hold them: no reference, path or command in the first sentence,
// and no more than three sentences.
func TestTheManagersWordsLeadPlainly(t *testing.T) {
	for _, s := range []string{
		ContainersAbout, ContainersNone, ContainerNewAbout, ContainerOpenAbout, ContainerCloseAbout,
		ContainerPassphraseAbout, HeaderBackupAbout, HeaderBackupWarning,
		SignFileAbout, CheckSignatureAbout, DecryptPGPAbout, EncryptAgeAbout, DecryptAgeAbout,
		InspectMessageAbout, ComposeMessageAbout, GeneratorAbout, ResolveReferenceAbout, CheckEnvFileAbout, CheckTemplateAbout,
		DeleteItemText("web/example.com", "personal", "R"), RemoveFileText("a.pdf", "web/example.com"),
		RestoreRevisionText("web/example.com", "2026-01-02 15:04"), KeepVersionText("web/example.com"),
		DeleteDiskTitle("/home/ada/private.img"), DeleteDiskText("/home/ada/private.img", "personal"), DeleteDiskAction,
		DiskDeleted("/home/ada/private.img", "personal"),
		BadItemName("a//b"), DisksLockedSeen + "work.", DiskVaultLocked("work"),
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

// Every kind the faces offer has a name of its own in the managers, and
// an unknown kind is shown as it is.
func TestEveryKindHasAName(t *testing.T) {
	seen := map[string]string{}
	for _, k := range append(slices.Clone(svcore.Kinds), svcore.KindPasskey) {
		s := KindText(k)
		if s == k {
			t.Errorf("kind %q has no name", k)
		}
		if other, ok := seen[s]; ok {
			t.Errorf("kinds %q and %q are both shown as %q", other, k, s)
		}
		seen[s] = k
	}
	if got := KindText("com.example.thing"); got != "com.example.thing" {
		t.Errorf("an unknown kind is shown as %q", got)
	}
	if got := KindText("identity"); got != "Personal details" {
		t.Errorf("identity is shown as %q", got)
	}
}

// Deleting a disk names its file, not its path, and says the key can be
// brought back.
func TestDeletingADiskSaysWhatGoesAndWhere(t *testing.T) {
	const path = "/home/ada/private.img"
	if got := DeleteDiskTitle(path); got != "Delete the disk private.img?" {
		t.Errorf("title %q", got)
	}
	text := DeleteDiskText(path, "personal")
	for _, want := range []string{"private.img and every file in it", "for good", "deleted items of vault personal", "copy"} {
		if !strings.Contains(text, want) {
			t.Errorf("%q does not say %q", text, want)
		}
	}
	for _, s := range []string{text, DiskDeleted(path, "personal")} {
		if strings.Contains(s, "/home") {
			t.Errorf("%q names the path", s)
		}
	}
	if got := DiskDeleted(path, ""); !strings.Contains(got, "your default vault") {
		t.Errorf("status %q", got)
	}
}

// A disk whose vault is locked is said to be, and what unlocking it does.
func TestALockedDisksVaultIsSaid(t *testing.T) {
	want := "Vault work keeps its key, and is locked: unlock it to see which item the key is in. Mounting or deleting the disk asks for the vault's passphrase first."
	if got := DiskVaultLocked("work"); got != want {
		t.Errorf("got %q, want %q", got, want)
	}
}
