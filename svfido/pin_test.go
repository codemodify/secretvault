package svfido

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// pyCTAP computes the PIN/UV auth protocols' pieces from their
// definitions in CTAP 2.1 §6.5.6 and §6.5.7, with Python's cryptography
// package: ECDH on P-256, SHA-256 or HKDF-SHA-256, AES-256-CBC, HMAC.
const pyCTAP = `
import json, sys, hashlib, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

a = json.load(sys.stdin)
h = bytes.fromhex
priv = ec.derive_private_key(int(a["priv"], 16), ec.SECP256R1())
peer = ec.EllipticCurvePublicNumbers(int(a["x"], 16), int(a["y"], 16), ec.SECP256R1()).public_key()
z = priv.exchange(ec.ECDH(), peer)

def hkdf(info):
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=bytes(32), info=info).derive(z)

def cbc(key, iv, pt):
    e = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return e.update(pt) + e.finalize()

k1 = hashlib.sha256(z).digest()
k2 = hkdf(b"CTAP2 HMAC key") + hkdf(b"CTAP2 AES key")
pt, msg, iv2 = h(a["pt"]), h(a["msg"]), h(a["iv2"])
print(json.dumps({
    "z": z.hex(),
    "k1": k1.hex(),
    "k2": k2.hex(),
    "ct1": cbc(k1, bytes(16), pt).hex(),
    "ct2": (iv2 + cbc(k2[32:], iv2, pt)).hex(),
    "mac1": hmac.new(k1, msg, hashlib.sha256).digest()[:16].hex(),
    "mac2": hmac.new(k2[:32], msg, hashlib.sha256).digest().hex(),
}))
`

func TestPINProtocolsAgreeWithPythonCryptography(t *testing.T) {
	if err := exec.Command("python3", "-c", "import cryptography").Run(); err != nil {
		t.Skip("python3 with the cryptography package is not installed")
	}
	for range 3 {
		ours, _ := ecdh.P256().GenerateKey(rand.Reader)
		theirs, _ := ecdh.P256().GenerateKey(rand.Reader)
		z, err := ours.ECDH(theirs.PublicKey())
		if err != nil {
			t.Fatal(err)
		}
		pt, msg := random(64), random(45)
		k1, k2 := pinProtocol(1).kdf(z), pinProtocol(2).kdf(z)
		ct1, _ := pinProtocol(1).encrypt(k1, pt)
		ct2, _ := pinProtocol(2).encrypt(k2, pt)
		pub := theirs.PublicKey().Bytes()
		in, _ := json.Marshal(map[string]string{
			"priv": hex.EncodeToString(ours.Bytes()),
			"x":    hex.EncodeToString(pub[1:33]), "y": hex.EncodeToString(pub[33:]),
			"pt": hex.EncodeToString(pt), "msg": hex.EncodeToString(msg), "iv2": hex.EncodeToString(ct2[:16]),
		})
		cmd := exec.Command("python3", "-c", pyCTAP)
		cmd.Stdin = bytes.NewReader(in)
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("python: %v", err)
		}
		var py map[string]string
		if err := json.Unmarshal(out, &py); err != nil {
			t.Fatal(err)
		}
		for name, got := range map[string][]byte{
			"z": z, "k1": k1, "k2": k2, "ct1": ct1, "ct2": ct2,
			"mac1": pinProtocol(1).authenticate(k1, msg), "mac2": pinProtocol(2).authenticate(k2, msg),
		} {
			if hex.EncodeToString(got) != py[name] {
				t.Errorf("%s: ours %x, Python's %s", name, got, py[name])
			}
		}
		for p, ct := range map[pinProtocol][]byte{1: ct1, 2: ct2} {
			k := map[pinProtocol][]byte{1: k1, 2: k2}[p]
			if back, err := p.decrypt(k, ct); err != nil || !bytes.Equal(back, pt) {
				t.Errorf("protocol %d decrypt: %v", p, err)
			}
		}
	}
}

// Protocol 1's IV is fixed at zero, so the same plaintext encrypts the
// same; protocol 2's is random. A token (32 bytes) MACs whole under
// protocol 2; a shared secret (64 bytes) MACs under its first half.
func TestPINProtocolDetails(t *testing.T) {
	z := random(32)
	k1, k2 := pinProtocol(1).kdf(z), pinProtocol(2).kdf(z)
	a, _ := pinProtocol(1).encrypt(k1, make([]byte, 16))
	b, _ := pinProtocol(1).encrypt(k1, make([]byte, 16))
	c, _ := pinProtocol(2).encrypt(k2, make([]byte, 16))
	d, _ := pinProtocol(2).encrypt(k2, make([]byte, 16))
	if !bytes.Equal(a, b) || bytes.Equal(c, d) || len(c) != 32 || len(a) != 16 {
		t.Fatal("IVs are not as the protocols define them")
	}
	token := random(32)
	if !bytes.Equal(pinProtocol(2).authenticate(k2, []byte("m")), pinProtocol(2).authenticate(k2[:32], []byte("m"))) ||
		len(pinProtocol(2).authenticate(token, []byte("m"))) != 32 || len(pinProtocol(1).authenticate(token, []byte("m"))) != 16 {
		t.Fatal("authenticate does not use the key the protocols say")
	}
	if _, err := pinProtocol(1).encrypt(k1, make([]byte, 15)); err == nil {
		t.Fatal("a partial block was encrypted")
	}
	for _, bad := range [][]byte{nil, make([]byte, 15), make([]byte, 17)} {
		if _, err := pinProtocol(2).decrypt(k2, bad); err == nil || !strings.Contains(err.Error(), "malformed") {
			t.Fatalf("decrypting %d bytes: %v", len(bad), err)
		}
	}
}
