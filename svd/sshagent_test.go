//go:build linux

package svd

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/codemodify/secretvault/svrpc"
)

// The SSH agent face, driven by OpenSSH's own tools.

func sshHarness(t *testing.T) (*harness, string, string) {
	t.Helper()
	for _, tool := range []string{"ssh-keygen", "ssh-add"} {
		need(t, tool)
	}
	h := newHarness(t)
	h.setup() // vault "personal", the default
	sock := filepath.Join(filepath.Dir(h.sock), "agent.sock")
	ln, cleanup, err := Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(cleanup)
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	h.d.ServeSSHAgent(ctx, ln)
	t.Setenv("SSH_AUTH_SOCK", sock)
	dir := t.TempDir()
	key := filepath.Join(dir, "id_ed25519")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test@example", "-f", key).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	return h, key, dir
}

func sh(t *testing.T, stdin string, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestSSHAddStoresTheKeyAndSSHKeygenSignsThroughIt(t *testing.T) {
	h, key, dir := sshHarness(t)
	h.desk.script("choose:" + svrpc.ChoiceAlways) // ssh-add may write to the vault
	if out, err := sh(t, "", "ssh-add", key); err != nil {
		t.Fatalf("ssh-add: %v %s", err, out)
	}
	os.Remove(key) // from now on the key exists only in the vault
	if out, err := sh(t, "", "ssh-add", "-l"); err != nil || !strings.Contains(out, "test@example") || !strings.Contains(out, "ED25519") {
		t.Fatalf("ssh-add -l = %q, %v", out, err)
	}

	data := filepath.Join(dir, "data")
	os.WriteFile(data, []byte("signed by a key that lives in a vault\n"), 0o600)
	h.desk.script("choose:" + svrpc.ChoiceLock) // ssh-keygen may sign with it
	if out, err := sh(t, "", "ssh-keygen", "-Y", "sign", "-f", key+".pub", "-n", "file", data); err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v %s", err, out)
	}
	q := h.desk.asked[len(h.desk.asked)-1]
	if !strings.Contains(q.Description, "ssh-keygen") || !strings.Contains(q.Description, "sign with") {
		t.Fatalf("the consent prompt said %q", q.Description)
	}
	msg, _ := os.ReadFile(data)
	if out, err := sh(t, string(msg), "ssh-keygen", "-Y", "check-novalidate", "-n", "file", "-s", data+".sig"); err != nil {
		t.Fatalf("the signature does not verify: %v %s", err, out)
	}
	h.desk.done(t)

	// ssh-add -D removes nothing: keys live in vaults.
	sh(t, "", "ssh-add", "-D")
	if out, _ := sh(t, "", "ssh-add", "-l"); !strings.Contains(out, "test@example") {
		t.Fatalf("ssh-add -D removed the key: %q", out)
	}
}

func TestALockedVaultIsUnlockedWhenSSHLooksForKeys(t *testing.T) {
	h, key, _ := sshHarness(t)
	h.desk.script("choose:" + svrpc.ChoiceAlways)
	if out, err := sh(t, "", "ssh-add", key); err != nil {
		t.Fatalf("ssh-add: %v %s", err, out)
	}
	h.d.LockAll("test")
	h.desk.script("pass:" + string(pass))
	if out, err := sh(t, "", "ssh-add", "-l"); err != nil || !strings.Contains(out, "test@example") {
		t.Fatalf("ssh-add -l on a locked vault = %q, %v", out, err)
	}
	h.desk.done(t)
}

func TestAKeyAddedWithConfirmIsAskedAboutEveryTime(t *testing.T) {
	h, key, dir := sshHarness(t)
	h.desk.script("choose:" + svrpc.ChoiceAlways)
	if out, err := sh(t, "", "ssh-add", "-c", key); err != nil {
		t.Fatalf("ssh-add -c: %v %s", err, out)
	}
	data := filepath.Join(dir, "data")
	os.WriteFile(data, []byte("x"), 0o600)
	for i := range 2 {
		h.desk.script("choose:" + svrpc.ChoiceOnce)
		os.Remove(data + ".sig")
		if out, err := sh(t, "", "ssh-keygen", "-Y", "sign", "-f", key+".pub", "-n", "file", data); err != nil {
			t.Fatalf("sign %d: %v %s", i, err, out)
		}
		q := h.desk.asked[len(h.desk.asked)-1]
		if !onlyOnceOrDeny(q.Choices) {
			t.Fatalf("an every-use prompt offered %+v", q.Choices)
		}
	}
	h.desk.done(t)
}

// A key is named for its comment. Another key with that comment goes
// beside it, never over it, and the same key added again replaces itself.
func TestKeysWithOneCommentGoSideBySide(t *testing.T) {
	h, key, dir := sshHarness(t)
	other := filepath.Join(dir, "id_other")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "test@example", "-f", other).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v %s", err, out)
	}
	h.desk.script("choose:" + svrpc.ChoiceAlways)
	for _, k := range []string{key, other, key} {
		if out, err := sh(t, "", "ssh-add", k); err != nil {
			t.Fatalf("ssh-add %s: %v %s", k, err, out)
		}
	}
	mv, err := h.d.vault("")
	if err != nil {
		t.Fatal(err)
	}
	all, err := mv.v.List("")
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range all {
		if e.Item.Kind == "ssh-key" {
			names = append(names, e.Item.Name)
		}
		e.Item.Wipe()
	}
	if !slices.Equal(names, []string{"test@example", "test@example (2)"}) {
		t.Fatalf("the keys are %q", names)
	}
}
