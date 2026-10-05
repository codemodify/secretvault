package svd

import (
	"bytes"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svbroker"
	"github.com/codemodify/secretvault/svcore"
	"github.com/codemodify/secretvault/svcrypto"
	"github.com/codemodify/secretvault/svformat"
	"github.com/codemodify/secretvault/svpeer"
	"github.com/codemodify/secretvault/svrpc"
	"github.com/codemodify/secretvault/svstore"
	"github.com/codemodify/secretvault/svsync"
)

// Items going to another vault (item.move, item.copy): inside the
// daemon, one question for a program's person, every item written to the
// other vault before any leaves the first, files sealed again there.

var scanData = bytes.Repeat([]byte("a scanned card "), 4096)

// moveSetup makes vaults "personal" (the default) and "mail" from the
// CLI, with three items under pgp/ (the first with a file) and one more.
func moveSetup(t *testing.T, tweaks ...func(*Options)) (*harness, *secretvault.Client, *logLines) {
	t.Helper()
	logs := &logLines{}
	h := newHarness(t, append(tweaks, func(o *Options) { o.Log = logs.add })...)
	cli := h.connect("/usr/bin/secretvault", &scripted{})
	for _, v := range []string{"personal", "mail"} {
		if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: v, Passphrase: pass}); err != nil {
			t.Fatal(err)
		}
	}
	for _, n := range []string{"pgp/a", "pgp/b", "pgp/c", "web/site"} {
		if _, err := cli.Put(ctx(t), "personal", login(n, "hunter2-"+n)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := cli.Attach(ctx(t), svrpc.FileAttachParams{Vault: "personal", Item: "pgp/a", Name: "card.png", Type: "image/png", Data: scanData}); err != nil {
		t.Fatal(err)
	}
	return h, cli, logs
}

func names(es []svrpc.Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.Item.Name)
	}
	return out
}

func codeOf(err error) int {
	var e *svrpc.Error
	if errors.As(err, &e) {
		return e.Code
	}
	return 0
}

func TestAProgramMovesItemsWithOneQuestionAndTheyCanBeBroughtBack(t *testing.T) {
	h, cli, logs := moveSetup(t)
	mail := h.connect("/usr/bin/comms-mail", nil)

	h.desk.script("choose:" + svrpc.ChoiceOnce)
	var raw json.RawMessage
	if err := mail.Call(ctx(t), svrpc.MItemMove, svrpc.MoveParams{To: "mail", Names: []string{"pgp/a", "pgp/b"}}, &raw); err != nil {
		t.Fatal(err)
	}
	h.desk.done(t)
	var res svrpc.MoveResult
	json.Unmarshal(raw, &res)
	if res.Vault != "personal" || res.To != "mail" || !slices.Equal(res.Done, []string{"pgp/a", "pgp/b"}) || len(res.Both)+len(res.NotDone) != 0 {
		t.Fatalf("the reply: %s", raw)
	}

	// One question, naming both vaults and the items, with no "always".
	qs := h.desk.questions()
	if len(qs) != 1 {
		t.Fatalf("%d questions", len(qs))
	}
	q := qs[0]
	if q.Kind != svrpc.PromptChoose || q.Title != "comms-mail wants to move 2 items to vault mail" || ids(q.Choices) != "deny,once,deny" ||
		q.Choices[1].Label != "Move 2 items" || q.Choices[0].Label != "Don't move them" || q.Choices[2].Label != "Cancel" {
		t.Fatalf("the question: %+v", q)
	}
	for _, want := range []string{`from vault "personal" to vault "mail"`, `"pgp/a" and "pgp/b"`, "can be brought back from its deleted items",
		"comms-mail does not see what is in them", "Program: /usr/bin/comms-mail", "Process: 4242"} {
		if !strings.Contains(q.Description, want) {
			t.Errorf("the question does not say %q: %q", want, q.Description)
		}
	}
	if strings.Contains(q.Description, "not yours alone") {
		t.Errorf("a vault nobody else reads is said to be shared: %q", q.Description)
	}

	// In mail, with the file, sealed there; gone from personal, into its
	// deleted items.
	got, _ := cli.List(ctx(t), "mail", "")
	if !slices.Equal(names(got), []string{"pgp/a", "pgp/b"}) {
		t.Fatalf("mail has %v", names(got))
	}
	e, err := cli.Get(ctx(t), "mail", "pgp/a")
	if err != nil || secretOf(e) != "hunter2-pgp/a" || len(e.Item.Files) != 1 {
		t.Fatalf("the moved item: %+v, %v", e, err)
	}
	f, err := cli.File(ctx(t), "mail", "pgp/a", "card.png")
	if err != nil || !bytes.Equal(f.Data, scanData) {
		t.Fatalf("its file in mail: %v", err)
	}
	h.d.vaults["mail"].v.Lock()
	h.d.vaults["personal"].v.Lock()
	if _, err := cli.Unlock(ctx(t), "mail", &svrpc.Key{Type: svformat.SlotPassphrase, Secret: pass}); err != nil {
		t.Fatal(err)
	}
	if f, err := cli.File(ctx(t), "mail", "pgp/a", "card.png"); err != nil || !bytes.Equal(f.Data, scanData) {
		t.Fatalf("its file in mail, with personal locked: %v", err)
	}
	if _, err := cli.Unlock(ctx(t), "personal", &svrpc.Key{Type: svformat.SlotPassphrase, Secret: pass}); err != nil {
		t.Fatal(err)
	}
	left, _ := cli.List(ctx(t), "personal", "")
	if !slices.Equal(names(left), []string{"pgp/c", "web/site"}) {
		t.Fatalf("personal has %v", names(left))
	}
	del, _ := cli.Deleted(ctx(t), "personal", "")
	if len(del) != 2 {
		t.Fatalf("personal's deleted items: %+v", del)
	}
	// Brought back, file and all: a duplicate of what is in mail now,
	// as the person chose.
	if _, err := cli.Restore(ctx(t), svrpc.RestoreParams{Vault: "personal", Name: "pgp/a"}); err != nil {
		t.Fatal(err)
	}
	if f, err := cli.File(ctx(t), "personal", "pgp/a", "card.png"); err != nil || !bytes.Equal(f.Data, scanData) {
		t.Fatalf("its file after restoring: %v", err)
	}

	// Both audit logs say what went, who asked, how it ended.
	for _, v := range []string{"personal", "mail"} {
		log, _ := cli.Audit(ctx(t), v, 0)
		var lines []string
		for _, a := range log {
			if a.Program == "comms-mail (/usr/bin/comms-mail)" {
				lines = append(lines, a.Outcome+" "+a.Op+" "+a.Item+" "+a.Reason)
			}
		}
		all := strings.Join(lines, "\n")
		for _, want := range []string{`allowed`, `move 2 items from vault "personal" to vault "mail": the person said yes`, "pgp/a", "pgp/b"} {
			if !strings.Contains(all, want) {
				t.Errorf("%s's audit log does not say %q:\n%s", v, want, all)
			}
		}
	}

	// Nothing secret anywhere: the reply, the audit logs, the log.
	var audits []string
	for _, v := range []string{"personal", "mail"} {
		log, _ := cli.Audit(ctx(t), v, 0)
		b, _ := json.Marshal(log)
		audits = append(audits, string(b))
	}
	for _, where := range []string{string(raw), strings.Join(audits, "\n"), logs.all(), q.Description} {
		for _, secret := range []string{"hunter2", "a scanned card", "YSBzY2FubmVk"} {
			if strings.Contains(where, secret) {
				t.Errorf("%q is in %.200s", secret, where)
			}
		}
	}
}

func TestCopyByPrefixKeepsTheItemsAndEverythingIsAPrefixToo(t *testing.T) {
	h, cli, _ := moveSetup(t)
	mail := h.connect("/usr/bin/comms-mail", nil)
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	res, err := mail.CopyItems(ctx(t), svrpc.MoveParams{To: "mail", Prefix: svrpc.PrefixOf("pgp/")})
	if err != nil || !slices.Equal(res.Done, []string{"pgp/a", "pgp/b", "pgp/c"}) {
		t.Fatalf("copy: %+v, %v", res, err)
	}
	q := h.desk.questions()[0]
	if q.Title != "comms-mail wants to copy 3 items to vault mail" || q.Choices[1].Label != "Copy 3 items" || q.Choices[0].Label != "Don't copy them" ||
		!strings.Contains(q.Description, `Vault "personal" keeps them as they are`) || len(q.Choices) != 3 {
		t.Fatalf("the question: %+v", q)
	}
	if left, _ := cli.List(ctx(t), "personal", ""); len(left) != 4 {
		t.Fatalf("personal has %v", names(left))
	}
	if f, err := cli.File(ctx(t), "mail", "pgp/a", "card.png"); err != nil || !bytes.Equal(f.Data, scanData) {
		t.Fatalf("the copy's file: %v", err)
	}

	// Copying is asked about every time too: nothing was remembered.
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := mail.CopyItems(ctx(t), svrpc.MoveParams{Vault: "personal", To: "mail", Names: []string{"web/site"}}); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("a copy said no to: %v", err)
	}

	// "" is every item; mail now has pgp/* already: a clash. A program
	// did not name what a prefix found, so it hears which names clash
	// only once the person lets it move them; nothing is written.
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	res, err = mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Prefix: svrpc.PrefixOf("")})
	if !errors.Is(err, svrpc.ErrDenied) || len(res.Clashes) != 0 || strings.Contains(err.Error(), "pgp/") {
		t.Fatalf("everything, with a clash, refused: %+v, %v", res, err)
	}
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	res, err = mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Prefix: svrpc.PrefixOf("")})
	if !errors.Is(err, svrpc.ErrExists) || !slices.Equal(res.Clashes, []string{"pgp/a", "pgp/b", "pgp/c"}) {
		t.Fatalf("everything, with a clash: %+v, %v", res, err)
	}
	if left, _ := cli.List(ctx(t), "personal", ""); len(left) != 4 {
		t.Fatalf("personal has %v", names(left))
	}
	// And in a vault of its own, everything goes.
	if _, err := cli.CreateVault(ctx(t), svrpc.VaultCreateParams{Name: "empty", Passphrase: pass}); err != nil {
		t.Fatal(err)
	}
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	res, err = mail.MoveItems(ctx(t), svrpc.MoveParams{To: "empty", Prefix: svrpc.PrefixOf("")})
	if err != nil || len(res.Done) != 4 {
		t.Fatalf("everything: %+v, %v", res, err)
	}
	if left, _ := cli.List(ctx(t), "personal", ""); len(left) != 0 {
		t.Fatalf("personal still has %v", names(left))
	}
}

func TestAClashWritesNothingAndAsksNobody(t *testing.T) {
	h, cli, _ := moveSetup(t)
	cli.Put(ctx(t), "mail", login("pgp/b", "theirs"))
	mail := h.connect("/usr/bin/comms-mail", nil)
	res, err := mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Names: []string{"pgp/a", "pgp/b", "pgp/c"}})
	if !errors.Is(err, svrpc.ErrExists) || !slices.Equal(res.Clashes, []string{"pgp/b"}) || !strings.Contains(err.Error(), `"pgp/b"`) {
		t.Fatalf("a clash: %+v, %v", res, err)
	}
	if h.desk.count() != 0 {
		t.Fatal("somebody was asked")
	}
	if got, _ := cli.List(ctx(t), "mail", ""); !slices.Equal(names(got), []string{"pgp/b"}) {
		t.Fatalf("mail has %v", names(got))
	}
	if e, _ := cli.Get(ctx(t), "mail", "pgp/b"); secretOf(e) != "theirs" {
		t.Fatal("the item there changed")
	}
	if left, _ := cli.List(ctx(t), "personal", ""); len(left) != 4 {
		t.Fatalf("personal has %v", names(left))
	}
	// No blob was left in mail either.
	if files, _ := h.d.vaults["mail"].store.List(svformat.BlobsDir); len(files) != 0 {
		t.Fatalf("blobs in mail: %v", files)
	}
}

func TestAFailureMidwayLeavesDuplicatesNeverALoss(t *testing.T) {
	h, cli, _ := moveSetup(t)
	mail := h.connect("/usr/bin/comms-mail", nil)
	fail := func(stage, at string) {
		moveStep = func(s, name string) error {
			if s == stage && name == at {
				return errors.New("the disk is full")
			}
			return nil
		}
	}
	t.Cleanup(func() { moveStep = func(string, string) error { return nil } })

	// Writing stops at pgp/b: pgp/a is in both, pgp/b and pgp/c only in
	// personal; nothing leaves personal.
	fail("write", "pgp/b")
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	res, err := mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Prefix: svrpc.PrefixOf("pgp/")})
	if codeOf(err) != svrpc.CodeFailed || len(res.Done) != 0 || !slices.Equal(res.Both, []string{"pgp/a"}) ||
		!slices.Equal(res.NotDone, []string{"pgp/b", "pgp/c"}) {
		t.Fatalf("stopped writing: %+v, %v", res, err)
	}
	for _, want := range []string{"1 item in both vaults", "Nothing was lost", "the disk is full"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not say %q: %v", want, err)
		}
	}
	if left, _ := cli.List(ctx(t), "personal", ""); len(left) != 4 {
		t.Fatalf("personal lost something: %v", names(left))
	}
	if got, _ := cli.List(ctx(t), "mail", ""); !slices.Equal(names(got), []string{"pgp/a"}) {
		t.Fatalf("mail has %v", names(got))
	}

	// Taking out stops at pgp/c: pgp/b went, pgp/c is in both.
	cli.Delete(ctx(t), "mail", "pgp/a")
	fail("remove", "pgp/c")
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	res, err = mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Names: []string{"pgp/b", "pgp/c"}})
	if codeOf(err) != svrpc.CodeFailed || !slices.Equal(res.Done, []string{"pgp/b"}) || !slices.Equal(res.Both, []string{"pgp/c"}) || len(res.NotDone) != 0 {
		t.Fatalf("stopped taking out: %+v, %v", res, err)
	}
	if left, _ := cli.List(ctx(t), "personal", ""); !slices.Equal(names(left), []string{"pgp/a", "pgp/c", "web/site"}) {
		t.Fatalf("personal has %v", names(left))
	}
	if got, _ := cli.List(ctx(t), "mail", ""); !slices.Equal(names(got), []string{"pgp/b", "pgp/c"}) {
		t.Fatalf("mail has %v", names(got))
	}

	// An item changed after it was copied stays where it is: the newer
	// version is never the one taken out.
	moveStep = func(s, name string) error {
		if s == "remove" && name == "web/site" {
			cli.Put(ctx(t), "personal", login("web/site", "changed meanwhile"))
		}
		return nil
	}
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	res, err = mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Names: []string{"web/site", "pgp/a"}})
	if codeOf(err) != svrpc.CodeFailed || !slices.Equal(res.Both, []string{"web/site"}) || !slices.Equal(res.Done, []string{"pgp/a"}) {
		t.Fatalf("changed meanwhile: %+v, %v", res, err)
	}
	if e, _ := cli.Get(ctx(t), "personal", "web/site"); secretOf(e) != "changed meanwhile" {
		t.Fatal("the newer version was lost")
	}
}

func TestNoYesCanceledMissingAndBadParameters(t *testing.T) {
	h, cli, _ := moveSetup(t)
	mail := h.connect("/usr/bin/comms-mail", nil)
	move := func(p svrpc.MoveParams) error {
		_, err := mail.MoveItems(ctx(t), p)
		return err
	}
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if err := move(svrpc.MoveParams{To: "mail", Names: []string{"pgp/a"}}); !errors.Is(err, svrpc.ErrDenied) {
		t.Fatalf("no: %v", err)
	}
	h.desk.script("cancel")
	if err := move(svrpc.MoveParams{To: "mail", Names: []string{"pgp/a"}}); !errors.Is(err, svrpc.ErrCanceled) {
		t.Fatalf("canceled: %v", err)
	}
	for name, p := range map[string]svrpc.MoveParams{
		"a missing vault":           {Vault: "nope", To: "mail", Names: []string{"pgp/a"}},
		"a missing vault to go to":  {To: "nope", Names: []string{"pgp/a"}},
		"the default, and it is to": {To: "personal", Names: []string{"pgp/a"}},
	} {
		err := move(p)
		want := svrpc.CodeNoVault
		if name == "the default, and it is to" {
			want = svrpc.CodeInvalidParams
		}
		if codeOf(err) != want {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, p := range map[string]svrpc.MoveParams{
		"the same vault twice":   {Vault: "mail", To: "mail", Names: []string{"pgp/a"}},
		"names and a prefix":     {To: "mail", Names: []string{"pgp/a"}, Prefix: svrpc.PrefixOf("pgp/")},
		"neither":                {To: "mail"},
		"no vault to go to":      {Names: []string{"pgp/a"}},
		"a bad name":             {To: "mail", Names: []string{"../x"}},
		"too many":               {To: "mail", Names: manyNames(svrpc.MaxMoveItems + 1)},
		"plan, from a program":   {To: "mail", Names: []string{"pgp/a"}, Plan: true},
		"an empty list, on wire": {},
	} {
		var err error
		if name == "an empty list, on wire" {
			err = mail.Call(ctx(t), svrpc.MItemMove, map[string]any{"to": "mail", "names": []string{}}, nil)
		} else {
			err = move(p)
		}
		want := svrpc.CodeInvalidParams
		if name == "plan, from a program" {
			want = svrpc.CodeDenied
		}
		if codeOf(err) != want {
			t.Errorf("%s: %v", name, err)
		}
	}
	res, err := mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Names: []string{"pgp/a", "nope"}})
	if !errors.Is(err, svrpc.ErrNotFound) || !slices.Equal(res.Missing, []string{"nope"}) {
		t.Fatalf("a missing item: %+v, %v", res, err)
	}
	if _, err := mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Prefix: svrpc.PrefixOf("nothing/")}); !errors.Is(err, svrpc.ErrNotFound) {
		t.Fatalf("a prefix nothing starts with: %v", err)
	}
	if h.desk.count() != 2 {
		t.Fatalf("asked %d times", h.desk.count())
	}
	if left, _ := cli.List(ctx(t), "personal", ""); len(left) != 4 {
		t.Fatal("something moved")
	}

	// Nobody to ask.
	h.d.desktop = nil
	if err := move(svrpc.MoveParams{To: "mail", Names: []string{"pgp/a"}}); !errors.Is(err, svrpc.ErrNoPrompter) {
		t.Fatalf("nobody to ask: %v", err)
	}
}

func manyNames(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "x/" + strings.Repeat("y", i%7) + string(rune('a'+i%26)) + "/" + strings.Repeat("z", i/26+1)
	}
	return out
}

func TestARememberedNoHoldsAndNoYesStandsInForTheQuestion(t *testing.T) {
	h, _, _ := moveSetup(t)
	prog := &svpeer.Process{PID: 4242, Exe: "/usr/bin/comms-mail", SystemOwned: true}
	mail := h.connect("/usr/bin/comms-mail", nil)
	// "Always allow" for everything in both vaults is no yes to a move.
	for _, v := range []string{"personal", "mail"} {
		h.d.broker.Remember(h.d.vaults[v].v, svbroker.Grant{Identity: prog.Identity(), Program: "comms-mail", Ops: svbroker.AllOps, Decision: svbroker.AllowAlways})
	}
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	if _, err := mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Names: []string{"pgp/a"}}); !errors.Is(err, svrpc.ErrDenied) || h.desk.count() != 1 {
		t.Fatalf("always-allowed, still asked: %v, %d", err, h.desk.count())
	}
	// "Always deny" writing to mail refuses without asking.
	h.d.broker.Remember(h.d.vaults["mail"].v, svbroker.Grant{Identity: prog.Identity(), Program: "comms-mail", Ops: []svbroker.Op{svbroker.OpWrite}, Decision: svbroker.DenyAlways})
	if _, err := mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Names: []string{"pgp/a"}}); !errors.Is(err, svrpc.ErrDenied) || h.desk.count() != 1 {
		t.Fatalf("always-denied: %v, %d", err, h.desk.count())
	}
}

func TestLockedVaultsAreUnlockedThroughTheDaemonsOwnPrompt(t *testing.T) {
	h, _, _ := moveSetup(t)
	h.d.LockAll("test")
	mail := h.connect("/usr/bin/comms-mail", nil)
	h.desk.script("pass:"+string(pass), "pass:"+string(pass), "choose:"+svrpc.ChoiceOnce)
	res, err := mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Names: []string{"web/site"}})
	if err != nil || !slices.Equal(res.Done, []string{"web/site"}) {
		t.Fatalf("%+v, %v", res, err)
	}
	h.desk.done(t)
	qs := h.desk.questions()
	if len(qs) != 3 || qs[0].Title != "Unlock vault personal" || qs[1].Title != "Unlock vault mail" || qs[2].Kind != svrpc.PromptChoose {
		t.Fatalf("questions: %+v", qs)
	}
	if !strings.Contains(qs[0].Description, `wants to move items from vault "personal" to vault "mail"`) {
		t.Fatalf("the unlock does not say why: %q", qs[0].Description)
	}
	if _, err := h.d.vaults["mail"].v.Get("web/site"); err != nil {
		t.Fatal(err)
	}

	// Not unlocked: nothing is asked further, nothing moves.
	h.d.LockAll("test")
	h.desk.script("cancel")
	if _, err := mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Names: []string{"pgp/a"}}); !errors.Is(err, svrpc.ErrCanceled) {
		t.Fatalf("the unlock canceled: %v", err)
	}
	h.desk.done(t)
}

func TestMovingIntoASharedOrSyncedVaultSaysWhoElseReadsIt(t *testing.T) {
	h, cli, _ := moveSetup(t)
	id, err := svcrypto.Modern.NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cli.AddSlot(ctx(t), svrpc.SlotAddParams{Vault: "mail", Type: svformat.SlotRecipient, Label: "alice",
		Secret: []byte(svformat.EncodeRecipient(svcrypto.Modern, id.Recipient()))}); err != nil {
		t.Fatal(err)
	}
	h.d.mu.Lock()
	h.d.vaults["mail"].cfg.Sync = &svsync.Remote{URL: "https://sync.example.org:8443/sv", Vault: "x"}
	h.d.mu.Unlock()
	// Another device, which registered itself in mail's folder.
	other, _ := svcore.Open(mustDir(t, h.d.vaults["mail"].cfg.Path), svcore.Options{Device: svformat.NewID(), Signer: mustSigner(t)})
	if err := other.Unlock(svcore.Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := other.RegisterDevice("the laptop"); err != nil {
		t.Fatal(err)
	}
	h.d.vaults["mail"].v.Refresh()

	mail := h.connect("/usr/bin/comms-mail", nil)
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Names: []string{"pgp/a"}})
	q := h.desk.questions()[0].Description
	for _, want := range []string{`Vault mail is not yours alone`, `"alice" opens it with a key of their own`, `the device "the laptop" has used it`,
		"syncs through sync.example.org", "All of them will be able to read the items there."} {
		if !strings.Contains(q, want) {
			t.Errorf("the question does not say %q:\n%s", want, q)
		}
	}

	// The CLI's plan says the same, for the CLI to say in its own words.
	plan, err := cli.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Prefix: svrpc.PrefixOf("pgp/"), Plan: true})
	if err != nil || !slices.Equal(plan.Items, []string{"pgp/a", "pgp/b", "pgp/c"}) || plan.Readers == nil ||
		!slices.Equal(plan.Readers.People, []string{"alice"}) || plan.Readers.Sync != "sync.example.org" || len(plan.Done) != 0 {
		t.Fatalf("the plan: %+v, %v", plan, err)
	}
	if left, _ := cli.List(ctx(t), "personal", ""); len(left) != 4 {
		t.Fatal("a plan moved something")
	}
}

func TestAProgramThatReadsTheVaultIsToldItWillReadTheItems(t *testing.T) {
	h, _, _ := moveSetup(t)
	prog := &svpeer.Process{PID: 4242, Exe: "/usr/bin/comms-mail", SystemOwned: true}
	other := &svpeer.Process{Exe: "/usr/bin/backup", SystemOwned: true}
	mv := h.d.vaults["mail"].v
	h.d.broker.Remember(mv, svbroker.Grant{Identity: prog.Identity(), Program: prog.Display(), Ops: []svbroker.Op{svbroker.OpRead}, Decision: svbroker.AllowAlways})
	h.d.broker.Remember(mv, svbroker.Grant{Identity: other.Identity(), Program: other.Display(), Ops: []svbroker.Op{svbroker.OpDecrypt}, Decision: svbroker.AllowUntilLock})
	mail := h.connect("/usr/bin/comms-mail", nil)
	h.desk.script("choose:" + svrpc.ChoiceDeny)
	mail.MoveItems(ctx(t), svrpc.MoveParams{To: "mail", Names: []string{"pgp/a"}})
	q := h.desk.questions()[0].Description
	for _, want := range []string{`You let comms-mail read everything in vault "mail", so it will be able to read them there, private keys included.`,
		`the program "` + other.Display() + `" may read everything in it`} {
		if !strings.Contains(q, want) {
			t.Errorf("the question does not say %q:\n%s", want, q)
		}
	}
	if strings.Contains(q, "does not see what is in them") || strings.Contains(q, `"comms-mail (`) {
		t.Errorf("the question:\n%s", q)
	}
}

func mustDir(t *testing.T, path string) svstore.Backend {
	t.Helper()
	s, err := svstore.OpenDir(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustSigner(t *testing.T) *svcore.DeviceKey {
	t.Helper()
	return svcore.NewDeviceKey()
}

func TestSecretvaultsOwnProgramsConfirmItThemselves(t *testing.T) {
	h, cli, _ := moveSetup(t)
	res, err := cli.MoveItems(ctx(t), svrpc.MoveParams{Vault: "personal", To: "mail", Names: []string{"pgp/c"}})
	if err != nil || !slices.Equal(res.Done, []string{"pgp/c"}) {
		t.Fatalf("%+v, %v", res, err)
	}
	if h.desk.count() != 0 {
		t.Fatal("the desktop was asked about the CLI's own move")
	}

	// A CLI that has not proved itself for a vault is asked for its
	// passphrase on its terminal, as for any use of it.
	term := &scripted{}
	other := h.connect("/usr/bin/secretvault", term)
	term.script("pass:"+string(pass), "pass:"+string(pass))
	if _, err := other.CopyItems(ctx(t), svrpc.MoveParams{Vault: "personal", To: "mail", Names: []string{"web/site"}}); err != nil {
		t.Fatal(err)
	}
	term.done(t)
	if h.desk.count() != 0 {
		t.Fatal("the desktop was asked")
	}
}

func TestPrivateKeysMoveAndAreUsedWhereTheyAreNow(t *testing.T) {
	h, cli, _ := moveSetup(t)
	k, err := cli.GeneratePGP(ctx(t), svrpc.PGPGenerateParams{Vault: "personal", Item: "keys/me", Name: "Me", Emails: []string{"me@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	mail := h.connect("/usr/bin/comms-mail", nil)
	h.desk.script("choose:" + svrpc.ChoiceOnce)
	var raw json.RawMessage
	if err := mail.Call(ctx(t), svrpc.MItemMove, svrpc.MoveParams{To: "mail", Names: []string{k.Item}}, &raw); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "PRIVATE") || len(raw) > 200 {
		t.Fatalf("the reply: %s", raw)
	}
	if _, err := cli.SignPGP(ctx(t), svrpc.PGPSignParams{Vault: "mail", Key: k.Fingerprint, Data: []byte("hello")}); err != nil {
		t.Fatalf("signing in mail: %v", err)
	}
	if _, err := cli.SignPGP(ctx(t), svrpc.PGPSignParams{Vault: "personal", Key: k.Fingerprint, Data: []byte("hello")}); err == nil {
		t.Fatal("the key is still used in personal")
	}
}

func TestAnItemWithCompetingVersionsIsSettledFirst(t *testing.T) {
	h, cli, _ := moveSetup(t)
	// Another device's handle, writing beside the daemon's without its
	// seeing: two versions of web/site.
	other, _ := svcore.Open(mustDir(t, h.d.vaults["personal"].cfg.Path), svcore.Options{Device: svformat.NewID()})
	if err := other.Unlock(svcore.Passphrase(pass)); err != nil {
		t.Fatal(err)
	}
	cli.Put(ctx(t), "personal", login("web/site", "here"))
	other.Put(svcore.Item{Kind: "login", Name: "web/site", Fields: []svcore.Field{{Name: "password", Type: "concealed", Value: []byte("there")}}})
	h.d.vaults["personal"].v.Refresh()
	if e, _ := cli.Get(ctx(t), "personal", "web/site"); len(e.Conflicts) == 0 {
		t.Fatal("no conflict")
	}
	res, err := cli.MoveItems(ctx(t), svrpc.MoveParams{Vault: "personal", To: "mail", Names: []string{"pgp/a", "web/site"}})
	if codeOf(err) != svrpc.CodeFailed || !slices.Equal(res.Conflicts, []string{"web/site"}) || !strings.Contains(err.Error(), "settle the conflict first") {
		t.Fatalf("%+v, %v", res, err)
	}
	if got, _ := cli.List(ctx(t), "mail", ""); len(got) != 0 {
		t.Fatalf("mail has %v", names(got))
	}
}
