package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/codemodify/secretvault/svage"
	"github.com/codemodify/secretvault/svops"
	"github.com/codemodify/secretvault/svrpc"
)

// keygen makes an age identity item and returns its recipient and its
// plugin identity line, as printed.
func (h *harness) keygen(item string, extra ...string) (rcpt, plugin string) {
	h.t.Helper()
	out := h.ok("", h.with(append([]string{"age", "keygen", "--name", item}, extra...)...)...)
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "# recipient: "):
			rcpt = strings.TrimPrefix(line, "# recipient: ")
		case strings.HasPrefix(line, "AGE-PLUGIN-SECRETVAULT-1"):
			plugin = line
		}
	}
	if rcpt == "" || plugin == "" {
		h.t.Fatalf("keygen printed:\n%s", out)
	}
	return rcpt, plugin
}

func TestAgeKeygenStoresAnIdentityAndPrintsWhatAgeNeeds(t *testing.T) {
	h := newHarness(t)
	h.init()
	rcpt, plugin := h.keygen("age/laptop")
	if _, err := svage.ParseX25519Recipient(rcpt); err != nil {
		t.Fatalf("recipient %q: %v", rcpt, err)
	}
	name, data, err := svage.ParsePluginIdentity(plugin)
	if err != nil || name != "secretvault" || string(data) != "default/age/laptop" {
		t.Fatalf("plugin identity names %q %q: %v", name, data, err)
	}
	if got := strings.TrimSpace(h.ok("", h.with("age", "recipient", "age/laptop")...)); got != rcpt {
		t.Errorf("age recipient = %q", got)
	}
	for _, arg := range []string{"age/laptop", "sv://-/age/laptop", "sv://default/age/laptop"} {
		if got := strings.TrimSpace(h.ok("", h.with("age", "identity", arg)...)); got != plugin {
			t.Errorf("age identity %s = %q", arg, got)
		}
	}
	// The item is a key, and its identity is the recipient's.
	var j jsonItem
	if err := json.Unmarshal([]byte(h.ok("", h.with("get", "--json", "age/laptop")...)), &j); err != nil {
		t.Fatal(err)
	}
	if j.Kind != "key" || j.Attrs[svops.AgeRecipientName] != rcpt {
		t.Fatalf("the item: %+v", j)
	}
	secret := strings.TrimSpace(h.ok("", h.with("get", "age/laptop", "--field", "age_identity")...))
	id, err := svage.ParseX25519Identity(secret)
	if err != nil || id.Recipient().String() != rcpt {
		t.Fatalf("the stored identity does not match its recipient: %v", err)
	}
	// Keys are never replaced.
	if _, errs, code := h.run("", h.with("age", "keygen", "--name", "age/laptop")...); code != 1 || !strings.Contains(errs, "already exists") {
		t.Fatalf("a second keygen: %d %q", code, errs)
	}
	pq, _ := h.keygen("age/pq", "--pq")
	if _, err := svage.ParseHybridRecipient(pq); err != nil {
		t.Fatalf("--pq made %.20s...: %v", pq, err)
	}
	// -o writes the identity file and prints only the recipient.
	idFile := filepath.Join(h.dir, "keys.txt")
	if got := strings.TrimSpace(h.ok("", h.with("age", "keygen", "--name", "age/other", "-o", idFile)...)); !strings.HasPrefix(got, "age1") {
		t.Fatalf("keygen -o printed %q", got)
	}
	if b, _ := os.ReadFile(idFile); !bytes.Contains(b, []byte("AGE-PLUGIN-SECRETVAULT-1")) {
		t.Fatalf("the identity file holds %q", b)
	}
}

func TestAgeEncryptAndDecryptWithVaultHeldKeys(t *testing.T) {
	h := newHarness(t)
	h.init()
	rcpt, plugin := h.keygen("age/laptop")
	pqRcpt, _ := h.keygen("age/pq", "--pq")
	plain := h.write("plain.txt", strings.Repeat("the vault keeps the key\n", 5000))
	want, _ := os.ReadFile(plain)

	for _, c := range []struct {
		name string
		enc  []string
		dec  []string
	}{
		{"X25519 by recipient", []string{"-r", rcpt}, []string{"-i", "sv://-/age/laptop"}},
		{"X25519 by item, armored", []string{"-r", "sv://default/age/laptop", "-a"}, []string{"-i", "sv://default/age/laptop"}},
		{"post-quantum", []string{"-r", pqRcpt}, []string{"-i", "sv://-/age/pq"}},
		{"through an identity file", []string{"-r", rcpt}, []string{"-i", h.write("ids.txt", "# mine\n"+plugin+"\n")}},
	} {
		t.Run(c.name, func(t *testing.T) {
			ct := filepath.Join(h.dir, "file.age")
			out := filepath.Join(h.dir, "file.out")
			os.Remove(ct)
			os.Remove(out)
			h.ok("", h.with(append(append([]string{"age", "encrypt", "-o", ct}, c.enc...), plain)...)...)
			h.ok("", h.with(append(append([]string{"age", "decrypt", "-o", out}, c.dec...), ct)...)...)
			got, _ := os.ReadFile(out)
			if !bytes.Equal(got, want) {
				t.Fatalf("decrypted %d bytes, want %d", len(got), len(want))
			}
			if st, _ := os.Stat(out); runtime.GOOS != "windows" && st.Mode().Perm() != 0o600 {
				t.Errorf("the plaintext is mode %v", st.Mode().Perm())
			}
		})
	}

	// What the CLI writes is a plain age file: the identity alone opens it.
	ct := filepath.Join(h.dir, "plain.age")
	h.ok("", h.with("age", "encrypt", "-r", "sv://-/age/laptop", "-o", ct, plain)...)
	secret := strings.TrimSpace(h.ok("", h.with("get", "age/laptop", "--field", "age_identity")...))
	id, _ := svage.ParseIdentity(secret)
	f, _ := os.Open(ct)
	defer f.Close()
	r, err := svage.Decrypt(f, id)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := io.ReadAll(r); err != nil || !bytes.Equal(got, want) {
		t.Fatalf("svage read %d bytes: %v", len(got), err)
	}

	// stdin to stdout, armored, and several recipients.
	armored := h.ok("hello\n", h.with("age", "encrypt", "-a", "-r", rcpt, "-R", h.write("rcpts.txt", "# team\n"+rcpt+"\n"))...)
	if !strings.HasPrefix(armored, "-----BEGIN AGE ENCRYPTED FILE-----") {
		t.Fatalf("-a wrote %q", armored)
	}
	if got := h.ok(armored, h.with("age", "decrypt", "-i", "sv://-/age/laptop")...); got != "hello\n" {
		t.Fatalf("decrypted %q", got)
	}
}

func TestAgeRefusesWhatWouldWeakenOrBreakAFile(t *testing.T) {
	h := newHarness(t)
	h.init()
	rcpt, _ := h.keygen("age/laptop")
	pqRcpt, _ := h.keygen("age/pq", "--pq")
	// Classical and post-quantum recipients together, unless allowed.
	if _, errs, code := h.run("x", h.with("age", "encrypt", "-a", "-r", rcpt, "-r", pqRcpt)...); code != 1 || !strings.Contains(errs, "quantum") {
		t.Fatalf("mixed recipients: %d %q", code, errs)
	}
	both := h.ok("both", h.with("age", "encrypt", "-a", "--allow-mixed-pq", "-r", rcpt, "-r", pqRcpt)...)
	for _, item := range []string{"age/laptop", "age/pq"} {
		if got := h.ok(both, h.with("age", "decrypt", "-i", "sv://-/"+item)...); got != "both" {
			t.Errorf("%s decrypted %q", item, got)
		}
	}
	// A secret key where a recipient goes is refused, not echoed.
	secret := strings.TrimSpace(h.ok("", h.with("get", "age/laptop", "--field", "age_identity")...))
	if _, errs, code := h.run("x", h.with("age", "encrypt", "-a", "-r", secret)...); code != 1 || strings.Contains(errs, secret[16:]) {
		t.Fatalf("an identity as a recipient: %d %q", code, errs)
	}
	// A missing recipient item.
	if _, errs, code := h.run("x", h.with("age", "encrypt", "-a", "-r", "sv://-/nope")...); code != 1 || !strings.Contains(errs, "not found") {
		t.Fatalf("a missing item: %d %q", code, errs)
	}
	// Binary ciphertext is fine to a pipe; no recipients is a usage error.
	if _, _, code := h.run("x", h.with("age", "encrypt")...); code != 2 {
		t.Fatalf("no recipients: exit %d", code)
	}
	// A file for someone else, and a damaged file, leave no output behind.
	other, _ := svage.GenerateX25519Identity()
	var buf bytes.Buffer
	w, _ := svage.Encrypt(&buf, other.Recipient())
	w.Write([]byte("not yours"))
	w.Close()
	notMine := h.write("notmine.age", buf.String())
	out := filepath.Join(h.dir, "out")
	if _, errs, code := h.run("", h.with("age", "decrypt", "-i", "sv://-/age/laptop", "-o", out, notMine)...); code != 1 || !strings.Contains(errs, "no identity") {
		t.Fatalf("someone else's file: %d %q", code, errs)
	}
	ct := h.ok("", h.with("age", "encrypt", "-a", "-r", rcpt, h.write("big", strings.Repeat("x", 100000)))...)
	raw, _ := io.ReadAll(svage.NewArmorReader(strings.NewReader(ct)))
	raw[len(raw)-5] ^= 1 // in the last chunk
	damaged := h.write("damaged.age", string(raw))
	if _, errs, code := h.run("", h.with("age", "decrypt", "-i", "sv://-/age/laptop", "-o", out, damaged)...); code != 1 || !strings.Contains(errs, "tampered") {
		t.Fatalf("a damaged file: %d %q", code, errs)
	}
	if _, err := os.Stat(out); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a failed decryption left %s behind", out)
	}
}

func TestAgeWorksWithPassphrasesAndSSHKeys(t *testing.T) {
	h := newHarness(t)
	h.init()
	h.answers = []string{"a passphrase for the file"}
	ct := h.ok("secret message", "age", "encrypt", "-a", "-p")
	h.answers = []string{"a passphrase for the file"}
	if got := h.ok(ct, "age", "decrypt"); got != "secret message" {
		t.Fatalf("passphrase round trip: %q", got)
	}
	h.answers = []string{"wrong"}
	if _, errs, code := h.run(ct, "age", "decrypt"); code != 1 || !strings.Contains(errs, "wrong passphrase") {
		t.Fatalf("a wrong passphrase: %d %q", code, errs)
	}
	if _, errs, code := h.run("x", h.with("age", "encrypt", "-a", "-p", "-r", "age1zvkyg2lqzraa2lnjvqej32nkuu0ues2s82hzrye869xeexvn73equnujwj")...); code != 1 || !strings.Contains(errs, "only recipient") {
		t.Fatalf("-p with -r: %d %q", code, errs)
	}

	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	blk, _ := ssh.MarshalPrivateKey(priv, "")
	keyFile := h.write("id_ed25519", string(pem.EncodeToMemory(blk)))
	sshPub, _ := ssh.NewPublicKey(pub)
	pubLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
	ct = h.ok("over ssh", "age", "encrypt", "-a", "-r", pubLine)
	if got := h.ok(ct, "age", "decrypt", "-i", keyFile); got != "over ssh" {
		t.Fatalf("ssh round trip: %q", got)
	}
}

// pluginSession is what age sends a plugin to unwrap one file, followed
// by the "ok"s it answers the plugin's replies with.
func pluginSession(identity string, stanzas []*svage.Stanza) string {
	var b strings.Builder
	b.WriteString("-> grease-1 x\n\n")
	fmt.Fprintf(&b, "-> add-identity %s\n\n", identity)
	for _, s := range stanzas {
		fmt.Fprintf(&b, "-> recipient-stanza 0 %s %s\n", s.Type, strings.Join(s.Args, " "))
		body := base64.RawStdEncoding.EncodeToString(s.Body)
		for len(body) >= 64 {
			b.WriteString(body[:64] + "\n")
			body = body[64:]
		}
		b.WriteString(body + "\n")
	}
	b.WriteString("-> done\n\n")
	b.WriteString(strings.Repeat("-> ok\n\n", 4))
	return b.String()
}

// The plugin, run in-process as age would run it, asks the daemon for the
// key; the daemon, not the plugin, asks the person.
func TestAgePluginUnwrapsWithTheKeyFromTheDaemon(t *testing.T) {
	h := newHarness(t)
	h.init()
	rcpt, plugin := h.keygen("age/laptop")
	r, _ := svage.ParseRecipient(rcpt)
	fileKey := bytes.Repeat([]byte{0x42}, 16)
	stanzas, _ := r.Wrap(fileKey)
	session := pluginSession(plugin, stanzas)

	// Locked: the desktop is asked for the passphrase, not the plugin.
	h.ok("", "lock", "--all")
	h.desk.passphrase = "correct horse battery staple"
	out, errs, code := h.run(session, "age-plugin", "--age-plugin=identity-v1")
	if code != 0 {
		t.Fatalf("exit %d: %s", code, errs)
	}
	want := "-> file-key 0\n" + base64.RawStdEncoding.EncodeToString(fileKey) + "\n-> done\n\n"
	if out != want {
		t.Fatalf("the plugin said:\n%s\nwant:\n%s", out, want)
	}
	if q := h.desk.questions(); len(q) != 1 || !strings.HasPrefix(q[0], "passphrase:") || !strings.Contains(q[0], "age/laptop") {
		t.Fatalf("the desktop was asked %q", q)
	}

	// Refused: the plugin reports it, keeps the protocol, and exits 0.
	h.ok("", "lock", "--all")
	h.desk.passphrase = ""
	out, errs, code = h.run(session, "age-plugin", "--age-plugin=identity-v1")
	if code != 0 || !strings.HasPrefix(out, "-> error identity 0\n") || !strings.HasSuffix(out, "-> done\n\n") {
		t.Fatalf("refused: exit %d, said %q (%s)", code, out, errs)
	}

	// A file with no X25519 stanza is not worth asking about.
	asked := len(h.desk.questions())
	out, _, _ = h.run(pluginSession(plugin, []*svage.Stanza{{Type: "ssh-ed25519", Args: []string{"abcd", "efgh"}, Body: []byte("x")}}), "age-plugin", "--age-plugin=identity-v1")
	if out != "-> done\n\n" || len(h.desk.questions()) != asked {
		t.Fatalf("an unrelated file: said %q, asked %d more", out, len(h.desk.questions())-asked)
	}

	// Without a state machine it explains itself.
	if _, errs, code := h.run("", "age-plugin"); code != 2 || !strings.Contains(errs, "age keygen") {
		t.Fatalf("no --age-plugin: %d %q", code, errs)
	}
}

// The real thing: the CLI built and installed as age-plugin-secretvault on
// PATH, run by svage's plugin client exactly as age runs a plugin.
func buildPlugin(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	gobin := filepath.Join(runtime.GOROOT(), "bin", "go")
	out, err := exec.Command(gobin, "build", "-o", filepath.Join(dir, "secretvault"), ".").CombinedOutput()
	if err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	if err := os.Symlink("secretvault", filepath.Join(dir, "age-plugin-secretvault")); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAgePluginBinaryServesAgeClients(t *testing.T) {
	if testing.Short() {
		t.Skip("builds the CLI")
	}
	if runtime.GOOS == "windows" {
		t.Skip("installs the plugin as a symlink")
	}
	bin := buildPlugin(t)
	h := newHarness(t)
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv(svrpc.EnvSocket, h.sock)
	h.init()
	rcpt, plugin := h.keygen("age/laptop", "--pq")
	h.ok("", "lock", "--all")
	h.desk.passphrase = "correct horse battery staple"

	// Encrypted by anyone to the plain recipient...
	r, _ := svage.ParseRecipient(rcpt)
	var buf bytes.Buffer
	w, _ := svage.Encrypt(&buf, r)
	io.WriteString(w, "for the plugin")
	w.Close()
	// ...decrypted by an age client through the plugin.
	id, err := svage.ParseIdentity(plugin)
	if err != nil {
		t.Fatal(err)
	}
	pr, err := svage.Decrypt(&buf, id)
	if err != nil {
		t.Fatalf("decrypting through age-plugin-secretvault: %v", err)
	}
	if got, _ := io.ReadAll(pr); string(got) != "for the plugin" {
		t.Fatalf("got %q", got)
	}
	if q := h.desk.questions(); len(q) != 1 {
		t.Fatalf("the desktop was asked %q", q)
	}
	// Each new plugin process is a program the person decides about.
	h.desk.choice = svrpc.ChoiceOnce

	// The identity as a recipient (age -e -i): the plugin wraps to the
	// item's recipient, as a post-quantum one.
	buf.Reset()
	w, err = svage.Encrypt(&buf, id.(*svage.PluginIdentity).Recipient())
	if err != nil {
		t.Fatalf("encrypting through the plugin: %v", err)
	}
	io.WriteString(w, "wrapped by the plugin")
	w.Close()
	if !bytes.Contains(buf.Bytes(), []byte("-> mlkem768x25519 ")) {
		t.Fatal("the plugin did not wrap to the item's post-quantum recipient")
	}
	pr, err = svage.Decrypt(bytes.NewReader(buf.Bytes()), id)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := io.ReadAll(pr); string(got) != "wrapped by the plugin" {
		t.Fatalf("got %q", got)
	}

	// An identity for an item that is not there: the plugin says so, and
	// age reports it.
	missing, _ := svops.AgePluginIdentity("default", "age/missing")
	mid, _ := svage.ParseIdentity(missing)
	buf.Reset()
	w, _ = svage.Encrypt(&buf, r)
	w.Close()
	if _, err := svage.Decrypt(&buf, mid); err == nil || !strings.Contains(err.Error(), "age/missing") {
		t.Fatalf("a missing item: %v", err)
	}
}
