package svd

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/codemodify/secretvault"
	"github.com/codemodify/secretvault/svmail"
	"github.com/codemodify/secretvault/svpgp"
	"github.com/codemodify/secretvault/svrpc"
)

const plainMail = "From: Alice Example <alice@example.org>\r\nTo: Me <me@example.org>\r\nSubject: the plan\r\nMessage-ID: <1@example.org>\r\nDate: Tue, 29 Sep 2026 10:00:00 +0000\r\nMIME-Version: 1.0\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nMeet at noon.\r\n"

func inspectMail(t *testing.T, c *secretvault.Client, msg []byte, decrypt bool) (*svmail.Report, []svrpc.MailVerdict, error) {
	t.Helper()
	res, err := c.InspectMail(ctx(t), svrpc.MailInspectParams{Message: msg, Decrypt: decrypt})
	if err != nil {
		return nil, nil, err
	}
	var rep svmail.Report
	if err := json.Unmarshal(res.Report, &rep); err != nil {
		t.Fatal(err)
	}
	return &rep, res.Verdicts, nil
}

func TestAMailClientLearnsWhoSignedAndReadsWhatIsForYou(t *testing.T) {
	h := newHarness(t)
	cli := h.setup()
	alice := pgpKey(t, 6, "Alice Example <alice@example.org>")
	if _, err := cli.AddContact(ctx(t), svrpc.ContactAddParams{Keys: [][]byte{armoredPublic(t, alice)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := cli.VerifyContact(ctx(t), svrpc.ContactVerifyParams{Ref: "Alice Example", Fingerprint: fpOf(alice), Method: svrpc.VerifyFingerprint}); err != nil {
		t.Fatal(err)
	}
	me, err := cli.GeneratePGP(ctx(t), svrpc.PGPGenerateParams{Name: "Me", Emails: []string{"me@example.org"}})
	if err != nil {
		t.Fatal(err)
	}
	mine, err := svpgp.ReadKey(strings.NewReader(me.PublicKey))
	if err != nil {
		t.Fatal(err)
	}

	mail := h.connect("/usr/bin/mail-client", nil)
	// Signed by Alice: valid, and she is someone you verified in person.
	signed, err := svmail.SignPGPMIME([]byte(plainMail), alice, &svmail.ComposeOptions{ProtectHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	h.desk.script("choose:" + svrpc.ChoiceLock) // reading the contacts
	rep, verdicts, err := inspectMail(t, mail, signed, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Signed != svmail.CoverFull || len(verdicts) != 1 {
		t.Fatalf("signed: %s, verdicts %+v", rep.Signed, verdicts)
	}
	if v := verdicts[0].Verdict; !v.Trusted || v.Level != "in-person" || !strings.Contains(v.Reasons[0], "Alice Example") {
		t.Fatalf("the verdict on Alice: %+v", v)
	}

	// Changed on the way: not valid, whoever signed it.
	tampered := bytes.Replace(signed, []byte("Meet at noon."), []byte("Meet at one. "), 1)
	if _, verdicts, err = inspectMail(t, mail, tampered, false); err != nil {
		t.Fatal(err)
	}
	if len(verdicts) != 1 || verdicts[0].Verdict.Trusted || verdicts[0].Verdict.Status != "invalid" {
		t.Fatalf("a changed message: %+v", verdicts)
	}

	// Encrypted to you and signed by Alice. Without decrypt the key is
	// never touched; with it, decrypting is asked about on its own.
	sealed, err := svmail.EncryptPGPMIME([]byte(plainMail), []*svpgp.Key{mine}, alice, &svmail.ComposeOptions{ProtectHeaders: true})
	if err != nil {
		t.Fatal(err)
	}
	asked := h.desk.count()
	rep, _, err = inspectMail(t, mail, sealed, false)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Encrypted != svmail.CoverFull || h.desk.count() != asked || strings.Contains(string(mustJSON(t, rep)), "Meet at noon") {
		t.Fatalf("not asked to decrypt: encrypted %s, prompts %d, report %s", rep.Encrypted, h.desk.count()-asked, mustJSON(t, rep))
	}
	h.desk.script("choose:" + svrpc.ChoiceOnce) // decrypting with the key
	rep, verdicts, err = inspectMail(t, mail, sealed, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(mustJSON(t, rep)), "Meet at noon") {
		t.Fatalf("decrypted: %s", mustJSON(t, rep))
	}
	if len(verdicts) != 1 || !verdicts[0].Verdict.Trusted {
		t.Fatalf("the signature inside: %+v", verdicts)
	}
	if q := h.desk.asked[len(h.desk.asked)-1]; !strings.Contains(q.Description, "decrypt") {
		t.Fatalf("decrypting was asked as %q", q.Description)
	}
	h.desk.done(t)
}

func mustJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
