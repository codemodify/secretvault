package svage

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"
)

// Plugins served in-process: the client code runs unchanged, talking over
// pipes to a goroutine instead of a child process.
func serveInProcess(t *testing.T, name string, serve func(sm string, in io.Reader, out io.Writer) error) {
	t.Helper()
	old := startPlugin
	startPlugin = func(n, sm string) (*pluginProcess, error) {
		if n != name {
			return nil, fmt.Errorf("age-plugin-%s is not installed", n)
		}
		fromPlugin, pluginOut := io.Pipe()
		pluginIn, toPlugin := io.Pipe()
		done := make(chan error, 1)
		go func() {
			err := serve(sm, pluginIn, pluginOut)
			pluginOut.CloseWithError(io.EOF)
			pluginIn.CloseWithError(io.ErrClosedPipe)
			done <- err
		}()
		return &pluginProcess{Reader: fromPlugin, Writer: toPlugin, finish: func(err error) error {
			// A process's pipes have buffers; these do not, so what the
			// plugin still has to say goes nowhere instead of blocking.
			toPlugin.Close()
			fromPlugin.Close()
			if perr := <-done; err != nil && perr != nil {
				return fmt.Errorf("%w (it said: %v)", err, perr)
			}
			return err
		}}, nil
	}
	t.Cleanup(func() { startPlugin = old })
}

// keyPlugin is a plugin whose identity data is a native identity's text.
func keyPlugin() *Plugin {
	return &Plugin{
		Name: "test",
		Identity: func(data []byte) (Identity, error) {
			return ParseIdentity(string(data))
		},
		IdentityAsRecipient: func(data []byte) (Recipient, error) {
			id, err := ParseIdentity(string(data))
			if err != nil {
				return nil, err
			}
			switch id := id.(type) {
			case *X25519Identity:
				return id.Recipient(), nil
			case *HybridIdentity:
				return id.Recipient(), nil
			}
			return nil, errors.New("not a native identity")
		},
	}
}

func pluginIdentity(t *testing.T, name string, id fmt.Stringer) string {
	t.Helper()
	s, err := EncodePluginIdentity(name, []byte(id.String()))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestPluginNamesAndEncodings(t *testing.T) {
	s, err := EncodePluginIdentity("SecretVault", []byte("default/age/laptop"))
	if err != nil || !strings.HasPrefix(s, "AGE-PLUGIN-SECRETVAULT-1") {
		t.Fatalf("%q %v", s, err)
	}
	name, data, err := ParsePluginIdentity(s)
	if err != nil || name != "secretvault" || string(data) != "default/age/laptop" {
		t.Fatalf("%q %q %v", name, data, err)
	}
	r, _ := EncodePluginRecipient("yubikey", []byte{1, 2, 3})
	if name, data, err := ParsePluginRecipient(r); err != nil || name != "yubikey" || !bytes.Equal(data, []byte{1, 2, 3}) {
		t.Fatalf("%q %v %v", name, data, err)
	}
	for _, bad := range []string{"", "a/b", `a\b`, "a b", "é"} {
		if _, err := EncodePluginIdentity(bad, nil); err == nil {
			t.Errorf("plugin name %q accepted", bad)
		}
	}
	if pr, err := ParseRecipient(r); err != nil || pr.(*PluginRecipient).Name() != "yubikey" {
		t.Errorf("ParseRecipient of a plugin recipient: %T %v", pr, err)
	}
	if pi, err := ParseIdentity(s); err != nil || pi.(*PluginIdentity).Name() != "secretvault" {
		t.Errorf("ParseIdentity of a plugin identity: %T %v", pi, err)
	}
}

func TestPluginIdentitiesDecryptThroughTheProtocol(t *testing.T) {
	serveInProcess(t, "test", keyPlugin().Serve)
	k := testKeys()
	for _, native := range []fmt.Stringer{k.x, k.pq} {
		id, err := NewPluginIdentity(pluginIdentity(t, "test", native), nil)
		if err != nil {
			t.Fatal(err)
		}
		var r Recipient = k.x.Recipient()
		if native == fmt.Stringer(k.pq) {
			r = k.pq.Recipient()
		}
		got, err := decrypt(encrypt(t, false, []byte("through the plugin"), r), false, id)
		if err != nil || string(got) != "through the plugin" {
			t.Fatalf("%T: %q %v", native, got, err)
		}
		// A file for someone else is no match, not an error.
		other, _ := GenerateX25519Identity()
		_, err = decrypt(encrypt(t, false, []byte("x"), other.Recipient()), false, id)
		var nm *NoIdentityMatchError
		if !errors.As(err, &nm) {
			t.Fatalf("a file for someone else: %v", err)
		}
	}
}

func TestPluginIdentitiesEncryptAsRecipients(t *testing.T) {
	serveInProcess(t, "test", keyPlugin().Serve)
	k := testKeys()
	id, _ := NewPluginIdentity(pluginIdentity(t, "test", k.pq), nil)
	// The plugin reports "postquantum", so it mixes with hybrids only.
	file := encrypt(t, false, []byte("pq"), id.Recipient(), k.pq.Recipient())
	if got, err := decrypt(file, false, k.pq); err != nil || string(got) != "pq" {
		t.Fatalf("%q %v", got, err)
	}
	if _, err := Encrypt(io.Discard, id.Recipient(), k.x.Recipient()); !errors.Is(err, ErrIncompatibleRecipients) {
		t.Fatalf("mixed with X25519: %v", err)
	}
	// A plugin that does not know the recipient says so.
	r, _ := EncodePluginRecipient("test", []byte("nothing"))
	pr, _ := NewPluginRecipient(r, nil)
	if _, err := Encrypt(io.Discard, pr); err == nil || !strings.Contains(err.Error(), "takes no recipients") {
		t.Fatalf("an unsupported recipient: %v", err)
	}
	// And a plugin that is not installed is an error, not a hang.
	missing, _ := NewPluginIdentity(pluginIdentity(t, "missing", k.x), nil)
	if _, err := decrypt(encrypt(t, false, nil, k.x.Recipient()), false, missing); err == nil {
		t.Fatal("a missing plugin")
	}
}

// rawSession drives a plugin by hand: commands in, responses out.
type rawSession struct {
	t    *testing.T
	c    *pluginConn // client's view
	done chan error
}

func startRaw(t *testing.T, p *Plugin, sm string) *rawSession {
	fromPlugin, pluginOut := io.Pipe()
	pluginIn, toPlugin := io.Pipe()
	s := &rawSession{t: t, c: newPluginConn(fromPlugin, toPlugin), done: make(chan error, 1)}
	go func() {
		err := p.Serve(sm, pluginIn, pluginOut)
		pluginOut.CloseWithError(io.EOF)
		pluginIn.CloseWithError(io.ErrClosedPipe)
		s.done <- err
	}()
	return s
}

func (s *rawSession) send(typ string, body []byte, args ...string) {
	s.t.Helper()
	if err := s.c.write(typ, body, args...); err != nil {
		s.t.Fatal(err)
	}
}

// expect reads one command from the plugin, checks its type and first
// arguments, and answers it.
func (s *rawSession) expect(typ string, args ...string) *Stanza {
	s.t.Helper()
	st, err := s.c.read()
	if err != nil {
		s.t.Fatalf("waiting for %s: %v", typ, err)
	}
	if st.Type != typ || len(st.Args) < len(args) {
		s.t.Fatalf("got %s %v %q, want %s %v", st.Type, st.Args, st.Body, typ, args)
	}
	for i, a := range args {
		if st.Args[i] != a {
			s.t.Fatalf("got %s %v, want %s %v", st.Type, st.Args, typ, args)
		}
	}
	if typ != "done" {
		s.send("ok", nil)
	}
	return st
}

func (s *rawSession) finish() error {
	return <-s.done
}

func TestPluginUnwrapsManyFilesInOneSessionAndIgnoresGrease(t *testing.T) {
	k := testKeys()
	fileKeys := [][]byte{bytes.Repeat([]byte{1}, 16), bytes.Repeat([]byte{2}, 16), bytes.Repeat([]byte{3}, 16)}
	other, _ := GenerateX25519Identity()
	s := startRaw(t, keyPlugin(), PluginIdentityV1)
	s.send("grease-1", []byte("junk"), "a", "b")
	s.send("add-identity", nil, pluginIdentity(t, "test", k.x))
	for i, fk := range fileKeys {
		var ss []*Stanza
		if i == 1 {
			ss, _ = other.Recipient().Wrap(fk) // file 1 is not for us
		} else {
			ss, _ = k.x.Recipient().Wrap(fk)
		}
		unknown := &Stanza{Type: "unknown-type", Args: []string{"x"}, Body: []byte("?")}
		for _, st := range append([]*Stanza{unknown}, ss...) {
			s.send("recipient-stanza", st.Body, append([]string{fmt.Sprint(i), st.Type}, st.Args...)...)
		}
		s.send("grease-2", nil)
	}
	s.send("done", nil)
	for _, i := range []int{0, 2} {
		got := s.expect("file-key", fmt.Sprint(i))
		if !bytes.Equal(got.Body, fileKeys[i]) {
			t.Fatalf("file %d: wrong key", i)
		}
	}
	s.expect("done")
	if err := s.finish(); err != nil {
		t.Fatal(err)
	}
}

func TestPluginReportsBadIdentitiesAndStanzas(t *testing.T) {
	k := testKeys()
	fk := make([]byte, 16)
	good, _ := k.x.Recipient().Wrap(fk)

	// An identity for another plugin, or with data the plugin cannot
	// use: errors, and no unwrapping at all.
	s := startRaw(t, keyPlugin(), PluginIdentityV1)
	s.send("add-identity", nil, pluginIdentity(t, "test", k.x))
	s.send("add-identity", nil, pluginIdentity(t, "other", k.x))
	bad, _ := EncodePluginIdentity("test", []byte("not a key"))
	s.send("add-identity", nil, bad)
	s.send("recipient-stanza", good[0].Body, "0", good[0].Type, good[0].Args[0])
	s.send("done", nil)
	s.expect("error", "identity", "1")
	s.expect("error", "identity", "2")
	s.expect("done")
	if err := s.finish(); err != nil {
		t.Fatal(err)
	}

	// A stanza of a known type but the wrong shape.
	s = startRaw(t, keyPlugin(), PluginIdentityV1)
	s.send("add-identity", nil, pluginIdentity(t, "test", k.x))
	s.send("recipient-stanza", []byte("short"), "0", "unrelated")
	s.send("recipient-stanza", good[0].Body, "0", "X25519", good[0].Args[0], "extra")
	s.send("done", nil)
	e := s.expect("error", "stanza", "0", "1")
	if !strings.Contains(string(e.Body), "one argument") {
		t.Errorf("error says %q", e.Body)
	}
	s.expect("done")
	s.finish()

	// Broken framing is fatal.
	for _, cmds := range [][]*Stanza{
		{{Type: "recipient-stanza", Args: []string{"1", "X25519"}}},  // file 1 before file 0
		{{Type: "recipient-stanza", Args: []string{"-1", "X25519"}}}, // a negative index
		{{Type: "recipient-stanza", Args: []string{"01", "X25519"}}}, // a leading zero
		{{Type: "add-identity", Args: []string{"a", "b"}}},           // two arguments
		{{Type: "done", Args: []string{"x"}}},                        // done with an argument
		{{Type: "done"}},                                             // nothing to use
	} {
		s := startRaw(t, keyPlugin(), PluginIdentityV1)
		for _, c := range append(cmds, &Stanza{Type: "done"}) {
			// The plugin may already have hung up.
			s.c.write(c.Type, c.Body, c.Args...)
		}
		if err := s.finish(); err == nil {
			t.Errorf("%v was accepted", cmds[0])
		}
	}
	if err := keyPlugin().Serve("identity-v2", strings.NewReader(""), io.Discard); err == nil {
		t.Error("an unknown state machine was accepted")
	}
}

func TestPluginWrapsWithLabels(t *testing.T) {
	k := testKeys()
	s := startRaw(t, keyPlugin(), PluginRecipientV1)
	s.send("add-identity", nil, pluginIdentity(t, "test", k.pq))
	s.send("grease", []byte{0})
	s.send("wrap-file-key", bytes.Repeat([]byte{7}, 16))
	s.send("wrap-file-key", bytes.Repeat([]byte{8}, 16))
	s.send("extension-labels", nil)
	s.send("done", nil)
	l := s.expect("labels")
	if len(l.Args) != 1 || l.Args[0] != "postquantum" {
		t.Fatalf("labels %v", l.Args)
	}
	for i := range 2 {
		st := s.expect("recipient-stanza", fmt.Sprint(i), "mlkem768x25519")
		fk, err := k.pq.Unwrap([]*Stanza{{Type: st.Args[1], Args: st.Args[2:], Body: st.Body}})
		if err != nil || fk[0] != byte(7+i) {
			t.Fatalf("stanza %d: %v", i, err)
		}
	}
	s.expect("done")
	if err := s.finish(); err != nil {
		t.Fatal(err)
	}
}

// A plugin that asks for everything the protocol lets it ask for.
func TestClientAnswersAPluginsRequests(t *testing.T) {
	k := testKeys()
	var seen []string
	serveInProcess(t, "chatty", func(sm string, in io.Reader, out io.Writer) error {
		c := newPluginConn(in, out)
		var stanzas []*Stanza
		for {
			s, err := c.read()
			if err != nil {
				return err
			}
			if s.Type == "done" {
				break
			}
			if s.Type == "recipient-stanza" {
				stanzas = append(stanzas, &Stanza{Type: s.Args[1], Args: s.Args[2:], Body: s.Body})
			}
		}
		ask := func(typ string, body []byte, args ...string) (*Stanza, error) {
			if err := c.write(typ, body, args...); err != nil {
				return nil, err
			}
			return c.read()
		}
		if r, err := ask("msg", []byte("touch the token\x1b[2J")); err != nil || r.Type != "ok" {
			return fmt.Errorf("msg: %v %v", r, err)
		}
		if r, err := ask("request-secret", []byte("PIN")); err != nil || r.Type != "ok" || string(r.Body) != "123456" {
			return fmt.Errorf("request-secret: %v %v", r, err)
		}
		if r, err := ask("confirm", []byte("use it?"), encodeB64([]byte("Yes")), encodeB64([]byte("No"))); err != nil || r.Type != "ok" || r.Args[0] != "yes" {
			return fmt.Errorf("confirm: %v %v", r, err)
		}
		if r, err := ask("grease-x", nil, "1"); err != nil || r.Type != "unsupported" {
			return fmt.Errorf("grease: %v %v", r, err)
		}
		fk, err := k.x.Unwrap(stanzas)
		if err != nil {
			return err
		}
		if r, err := ask("file-key", fk, "0"); err != nil || r.Type != "ok" {
			return fmt.Errorf("file-key: %v %v", r, err)
		}
		return c.write("done", nil)
	})
	ui := &PluginUI{
		DisplayMessage: func(name, msg string) error { seen = append(seen, name+": "+msg); return nil },
		RequestValue: func(name, prompt string, secret bool) ([]byte, error) {
			seen = append(seen, fmt.Sprintf("%s asks %s (secret %v)", name, prompt, secret))
			return []byte("123456"), nil
		},
		Confirm: func(name, prompt, yes, no string) (bool, error) {
			seen = append(seen, fmt.Sprintf("%s: %s [%s/%s]", name, prompt, yes, no))
			return true, nil
		},
	}
	id, err := NewPluginIdentity(pluginIdentity(t, "chatty", k.x), ui)
	if err != nil {
		t.Fatal(err)
	}
	got, err := decrypt(encrypt(t, false, []byte("ok"), k.x.Recipient()), false, id)
	if err != nil || string(got) != "ok" {
		t.Fatalf("%q %v", got, err)
	}
	want := []string{"chatty: touch the token?[2J", "chatty asks PIN (secret true)", "chatty: use it? [Yes/No]"}
	if fmt.Sprint(seen) != fmt.Sprint(want) {
		t.Errorf("the UI saw %q", seen)
	}
}
