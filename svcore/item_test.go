package svcore

import "testing"

// A passkey's key is used in place: it is no secret for references, the
// Secret Service or deliveries to hand out.
func TestAPasskeyHasNoSecretToHandOut(t *testing.T) {
	it := Item{Kind: KindPasskey, Name: "passkeys/example.com", Fields: []Field{
		{Name: "rp_id", Type: FieldText, Value: []byte("example.com")},
		{Name: "private_key", Type: FieldKey, Value: []byte("MIGHAgEAMBMG")},
	}}
	if f, ok := it.Secret(); ok {
		t.Fatalf("a passkey's secret is %q", f.Name)
	}
	it.Kind = "key"
	if f, ok := it.Secret(); !ok || f.Name != "private_key" {
		t.Fatalf("another kind's key field: %v %v", f.Name, ok)
	}
}
