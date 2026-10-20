package svops

import (
	"bytes"
	"errors"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svrpc"
)

// The operations' pure parts. What they do through the daemon is tested
// through the CLI (cmd/secretvault), against a daemon of the test's own.

func TestParseSize(t *testing.T) {
	for in, want := range map[string]int64{"1024": 1024, "40M": 40 << 20, "40MiB": 40 << 20, "40mb": 40 << 20, "1G": 1 << 30,
		"1.5G": 3 << 29, "2T": 2 << 40, "512K": 512 << 10} {
		if got, err := ParseSize(in); err != nil || got != want {
			t.Errorf("%s: %d %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "G", "-1G", "1X", "1e30G", "0"} {
		if _, err := ParseSize(bad); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestWaitsAreReadAsPeopleWriteThem(t *testing.T) {
	for in, want := range map[string]time.Duration{"7d": 7 * 24 * time.Hour, "2w": 14 * 24 * time.Hour, "48h": 48 * time.Hour, "90m": 90 * time.Minute} {
		if got, err := ParseWait(in); err != nil || got != want {
			t.Errorf("%s: %v, %v", in, got, err)
		}
	}
	for _, bad := range []string{"", "d", "7dw", "-1d", "0d", "99999999999999d", "soon", "-5h"} {
		if d, err := ParseWait(bad); err == nil {
			t.Errorf("%q read as %v", bad, d)
		}
	}
	for secs, want := range map[int64]string{86400: "a day", 7 * 86400: "7 days", 3600: "an hour", 5400: "1h30m0s"} {
		if got := WaitText(secs); got != want {
			t.Errorf("WaitText(%d) = %q", secs, got)
		}
	}
}

func TestSharesComeBackTogetherInAnyOrder(t *testing.T) {
	rk := svcrypto.RandomBytes(32)
	text := svformat.EncodeRecoveryKey(rk)
	if _, err := SplitThreshold(1, 0); err == nil {
		t.Fatal("one share was accepted")
	}
	k, err := SplitThreshold(5, 0)
	if err != nil || k != 3 {
		t.Fatalf("a majority of 5: %d %v", k, err)
	}
	shares, err := SplitRecoveryKey(text, 5, k)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := SplitRecoveryKey(svformat.EncodeRecoveryKey(svcrypto.RandomBytes(32)), 4, 2)

	var c ShareCollector
	defer c.Wipe()
	if err := c.Add([]byte("not a share")); err == nil || c.Have() != 0 {
		t.Fatalf("junk was taken: %v", err)
	}
	for _, s := range []string{shares[4], shares[1]} {
		if err := c.Add([]byte(s)); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Add([]byte(other[0])); err == nil || !strings.Contains(err.Error(), "another recovery key") {
		t.Fatalf("a share of another split: %v", err)
	}
	if c.Done() || c.Need() != 3 {
		t.Fatalf("done %v, need %d", c.Done(), c.Need())
	}
	c.Add([]byte(shares[2]))
	if !c.Done() {
		t.Fatal("three of five are not enough")
	}
	got, err := c.Key()
	if err != nil || string(got) != text {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestAnEnvironmentResolvesItsReferencesInOrder(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "app.env")
	os.WriteFile(file, []byte("# a comment\nexport API=sv://-/prod/api\nNAME='plain'\nDB=\"sv://work/db#password\"\n"), 0o600)
	env := NewEnviron([]string{"HOME=/home/ada", "API=old"})
	if err := env.LoadFiles([]string{file}); err != nil {
		t.Fatal(err)
	}
	if err := env.SetPairs([]string{"EXTRA=x"}); err != nil {
		t.Fatal(err)
	}
	if err := env.SetPairs([]string{"broken"}); err == nil {
		t.Fatal("a pair without = was taken")
	}
	if refs := env.Refs(); !slices.Equal(refs, []string{"API", "DB"}) {
		t.Fatalf("refs %v", refs)
	}
	connects := 0
	var asked []svrpc.Ref
	err := env.Resolve(svrpc.ParseRef, func() error { connects++; return nil }, func(r svrpc.Ref) ([]byte, error) {
		asked = append(asked, r)
		return []byte("value of " + r.String()), nil
	})
	if err != nil || connects != 1 || len(asked) != 2 || asked[1].Vault != "work" || asked[1].Field != "password" {
		t.Fatalf("%v: %d connects, asked %v", err, connects, asked)
	}
	want := []string{"HOME=/home/ada", "API=value of sv://-/prod/api", "NAME=plain", "DB=value of sv://work/db#password", "EXTRA=x"}
	if got := env.List(); !slices.Equal(got, want) {
		t.Fatalf("got %q", got)
	}

	// A connection that fails says so as it is; a fetch that fails is
	// named by its variable.
	env = NewEnviron([]string{"A=sv://-/x"})
	if err := env.Resolve(svrpc.ParseRef, func() error { return errors.New("no daemon") }, nil); err == nil || err.Error() != "no daemon" {
		t.Fatalf("connect: %v", err)
	}
	if err := env.Resolve(DeliveryRef, nil, nil); err == nil || !strings.HasPrefix(err.Error(), "A: ") {
		t.Fatalf("a delivery server has no default vault: %v", err)
	}
}

func TestTemplatesAreFilledAndListed(t *testing.T) {
	tmpl := []byte("user={{ sv://-/db#username }}\npass={{sv://work/db}}\nleft={ sv://-/x }\n")
	if refs := TemplateRefs(tmpl); !slices.Equal(refs, []string{"sv://-/db#username", "sv://work/db"}) {
		t.Fatalf("refs %v", refs)
	}
	out, err := Inject(tmpl, func(r svrpc.Ref) ([]byte, error) { return []byte(strings.ToUpper(r.Item + r.Field)), nil })
	if err != nil || string(out) != "user=DBUSERNAME\npass=DB\nleft={ sv://-/x }\n" {
		t.Fatalf("%q %v", out, err)
	}
	if _, err := Inject(tmpl, func(svrpc.Ref) ([]byte, error) { return nil, errors.New("denied") }); err == nil {
		t.Fatal("a failure was filled in")
	}
}

func TestCredentialHelpersNameTheirItems(t *testing.T) {
	kv := map[string]string{"protocol": "https", "host": "github.com", "path": "ada/repo", "username": "ada", "password": "pw"}
	it := GitItem(kv)
	if it.Name != "ada@github.com∕ada∕repo" || !GitMatches(&it, map[string]string{"host": "github.com"}) || GitMatches(&it, map[string]string{"host": "gitlab.com"}) {
		t.Fatalf("git: %+v", it)
	}
	if !GitSame(&it, kv) || GitSame(&it, map[string]string{"protocol": "https", "host": "github.com", "username": "ada"}) {
		t.Fatal("git: the same login is not told from another")
	}
	if f, ok := SecretField(&it); !ok || string(f.Value) != "pw" {
		t.Fatalf("its secret: %v %q", ok, f.Value)
	}
	if n := DockerItemName("https://registry.example.com/v2/"); n != "registry.example.com∕v2∕" {
		t.Fatalf("docker: %s", n)
	}
	d := DockerItem("https://registry.example.com/v2/", "ada", "pw")
	if !DockerMatches(&d, "registry.example.com/v2/") || DockerMatches(&d, "ghcr.io") {
		t.Fatalf("docker: %+v", d)
	}
	for argv0, want := range map[string]string{"/usr/bin/git-credential-secretvault": "git-credential", "age-plugin-secretvault.exe": "age-plugin", "secretvault": ""} {
		if got := HelperName(argv0); got != want {
			t.Errorf("HelperName(%q) = %q", argv0, got)
		}
	}
}

func TestNewFilesNeverReplaceOldOnes(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "f")
	if err := WriteNew(p, []byte("one")); err != nil {
		t.Fatal(err)
	}
	if err := WriteNew(p, []byte("two")); !errors.Is(err, os.ErrExist) {
		t.Fatalf("over an existing file: %v", err)
	}
	if err := CreateKeyfile(filepath.Join(dir, "key")); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "key")); len(b) != 64 {
		t.Fatalf("a keyfile of %d bytes", len(b))
	}

	// An atomic file appears only when it is committed.
	a, err := CreateAtomic(filepath.Join(dir, "out"), 0o600)
	if err != nil {
		t.Fatal(err)
	}
	a.Write([]byte("half"))
	a.Abort()
	if entries, _ := os.ReadDir(dir); len(entries) != 2 {
		t.Fatalf("an aborted file left %v", entries)
	}
	a, _ = CreateAtomic(filepath.Join(dir, "out"), 0o600)
	a.Write([]byte("whole"))
	if err := a.Commit(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, "out")); !bytes.Equal(b, []byte("whole")) {
		t.Fatalf("committed %q", b)
	}
}

func TestIdentitiesAndTheirRecipients(t *testing.T) {
	dir := t.TempDir()
	rcpt, file, err := NewIdentity("modern", "identity")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(file, []byte("# secretvault identity, created ")) {
		t.Fatalf("the file:\n%s", file)
	}
	p := filepath.Join(dir, "id")
	WriteNew(p, file)
	if got, err := IdentityRecipient(p); err != nil || got != rcpt {
		t.Fatalf("its recipient: %q %v", got, err)
	}
	for _, arg := range []string{rcpt, p} {
		if got, err := RecipientArg(arg); err != nil || got != rcpt {
			t.Errorf("RecipientArg(%q) = %q, %v", arg, got, err)
		}
	}
	if _, err := RecipientArg(filepath.Join(dir, "missing")); err == nil {
		t.Error("a missing file was a recipient")
	}
}

func TestFingerprintsAndNamesAreSaidAsPeopleReadThem(t *testing.T) {
	if g := GroupFingerprint("1A2B3C4D5E6F7A8B"); g != "1A2B 3C4D 5E6F 7A8B" {
		t.Errorf("grouped %q", g)
	}
	if g := GroupFingerprint("SHA256:abc"); g != "SHA256:abc" {
		t.Errorf("an SSH fingerprint became %q", g)
	}
	taken := map[string]bool{"a": true, "a (2)": true}
	if n := UniqueName(taken, "a"); n != "a (3)" {
		t.Errorf("unique %q", n)
	}
	if n := UniqueName(taken, "a", "git"); n != "a (git)" {
		t.Errorf("unique %q", n)
	}
	if s := PathSafe(" a/b\x00 "); s != "a∕b∕" {
		t.Errorf("path-safe %q", s)
	}
	if HumanSize(3<<29) != "1.5 GiB" || HumanSize(10) != "10 bytes" {
		t.Errorf("sizes: %s %s", HumanSize(3<<29), HumanSize(10))
	}
	if ContainerItemName("/home/ada/work.img") != "work" {
		t.Error(ContainerItemName("/home/ada/work.img"))
	}
	if !IsContactURI("OPENPGP4FPR:1A2B") || IsContactURI("alice.asc") {
		t.Error("contact URIs")
	}
}

// Lists show items by their names' last parts, without the places older
// versions filed them under; two that would show the same show whole.
func TestListsShowNamesWithoutTheirOldPrefixes(t *testing.T) {
	got := ShownNames([]string{"containers/test-disk", "git/github.com", "github.com", "Bank card", "prod/db/password"})
	want := map[string]string{"containers/test-disk": "test-disk", "git/github.com": "git/github.com", "github.com": "github.com",
		"Bank card": "Bank card", "prod/db/password": "password"}
	if !maps.Equal(got, want) {
		t.Errorf("got %q, want %q", got, want)
	}
}

// Every item is in one row of what a vault holds: its kind's, Other for
// a kind of no row of its own, or none for a key of My keys.
func TestEveryItemIsInOneRow(t *testing.T) {
	for _, c := range []struct {
		it   svrpc.Item
		want string
	}{
		{svrpc.Item{Kind: "login"}, "Logins"},
		{svrpc.Item{Kind: "otp"}, "One-time codes"},
		{svrpc.Item{Kind: "container"}, "Disk keys"},
		{svrpc.Item{Kind: "generic"}, "Other"},
		{svrpc.Item{Kind: "someone-elses"}, "Other"},
		{svrpc.Item{Kind: "key"}, "Keys"},
		{svrpc.Item{Kind: "key", Attrs: map[string]string{svrpc.PGPFingerprint: "AB"}}, ""},
	} {
		got := ""
		if i := KindRowOf(&c.it); i >= 0 {
			got = KindRows[i].Title
		}
		if got != c.want {
			t.Errorf("%+v is in %q, want %q", c.it, got, c.want)
		}
	}
}
