package fidotest

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/codemodify/secretvault/svfido"
)

type pins []string

func (p *pins) PIN(context.Context, string, int, string) ([]byte, error) {
	pin := (*p)[0]
	*p = (*p)[1:]
	return []byte(pin), nil
}

func (p *pins) Touch(context.Context, string, string, func()) func() { return func() {} }

// The hmac-secret output svfido returns is what CTAP 2.1 §12.5 defines:
// HMAC-SHA-256(CredRandom, salt), with CredRandomWithUV when the person
// was verified and CredRandomWithoutUV when not, for both protocols.
func TestHMACSecretIsTheSpecsHMAC(t *testing.T) {
	for _, o := range []Options{{PIN: "1234"}, {PIN: "1234", Protocols: []int{1}}, {PIN: "1234", CTAP20: true}} {
		a := New(o)
		defer a.Stop()
		p := &pins{"1234", "1234", "1234"}
		k := &svfido.Keys{Prompts: p, Open: func(ctx context.Context) ([]*svfido.Device, error) {
			d, err := svfido.NewDevice(ctx, a.Transport(), "soft")
			return []*svfido.Device{d}, err
		}}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		salt := bytes.Repeat([]byte{0x42}, 32)
		for _, uv := range []bool{true, false} {
			e, err := k.Enroll(ctx, "secretvault:", &uv, salt, nil)
			if err != nil {
				t.Fatal(err)
			}
			c := a.openCredential(e.ID, "secretvault:")
			if c == nil {
				t.Fatal("the credential ID does not open")
			}
			credRandom := c.noUV
			if uv {
				credRandom = c.withUV
			}
			m := hmac.New(sha256.New, credRandom)
			m.Write(salt)
			if want := m.Sum(nil); !bytes.Equal(e.Output, want) {
				t.Fatalf("%+v uv=%v: output %x, HMAC-SHA-256(CredRandom, salt) = %x", o, uv, e.Output, want)
			}
			if a.openCredential(e.ID, "other:") != nil {
				t.Fatal("a credential ID opens for another site")
			}
		}
	}
}
