// Package svsecret holds the Secret Service protocol pieces both sides of
// it need: the session key exchange and secret encryption, and a small
// client for reading another keyring (to import from gnome-keyring,
// KWallet's bridge, KeePassXC or oo7 before taking over the bus name).
// The provider itself is in svd (ss*.go).
package svsecret

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"math/big"
)

// Session algorithms.
//
//   - Plain: secrets as they are.
//   - DH ("dh-ietf1024-sha256-aes128-cbc-pkcs7"): each side makes an
//     ephemeral Diffie-Hellman key in the 1024-bit MODP group of RFC 2409
//     (group 2); HKDF-SHA256 of the shared secret (padded to 128 bytes, no
//     salt, no info) is a 16-byte AES key; each secret is AES-128-CBC with
//     PKCS#7 padding under a fresh IV. This is what libsecret uses.
//
// The group is small by today's standards, but the keys live for one
// session and only have to beat passive observers of the local bus, which
// is all the specification offers.
const (
	Plain = "plain"
	DH    = "dh-ietf1024-sha256-aes128-cbc-pkcs7"
)

var (
	prime, _  = new(big.Int).SetString("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16)
	generator = big.NewInt(2)

	// ErrPublicKey is a peer's public key outside the group.
	ErrPublicKey = errors.New("svsecret: the session's public key is out of range")
	// ErrSecret is a secret that does not decrypt under its session.
	ErrSecret = errors.New("svsecret: the secret does not decrypt under its session")
)

// DHKey is one side's ephemeral key.
type DHKey struct {
	x   *big.Int
	Pub []byte // 128 bytes, big-endian
}

// NewDHKey makes an ephemeral key.
func NewDHKey() *DHKey {
	xb := make([]byte, 128)
	rand.Read(xb)
	x := new(big.Int).SetBytes(xb)
	clear(xb)
	return &DHKey{x: x, Pub: new(big.Int).Exp(generator, x, prime).FillBytes(make([]byte, 128))}
}

// SessionKey combines this key with the peer's public key into the AES
// key both sides share, and forgets the private half.
func (k *DHKey) SessionKey(peerPub []byte) ([]byte, error) {
	y := new(big.Int).SetBytes(peerPub)
	pMinus1 := new(big.Int).Sub(prime, big.NewInt(1))
	if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(pMinus1) >= 0 {
		return nil, ErrPublicKey
	}
	shared := new(big.Int).Exp(y, k.x, prime)
	k.x.SetInt64(0)
	secret := shared.FillBytes(make([]byte, 128))
	shared.SetInt64(0)
	defer clear(secret)
	return hkdf.Key(sha256.New, secret, nil, "", 16)
}

// SealSecret encrypts a secret under a DH session key: (IV, ciphertext). A nil
// key is a plain session: no parameters, the secret as it is.
func SealSecret(key, secret []byte) (params, value []byte, err error) {
	if key == nil {
		return []byte{}, append([]byte(nil), secret...), nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	iv := make([]byte, aes.BlockSize)
	rand.Read(iv)
	n := aes.BlockSize - len(secret)%aes.BlockSize
	padded := append(append([]byte(nil), secret...), bytes.Repeat([]byte{byte(n)}, n)...)
	defer clear(padded)
	out := make([]byte, len(padded))
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(out, padded)
	return iv, out, nil
}

// OpenSecret reverses SealSecret.
func OpenSecret(key, params, value []byte) ([]byte, error) {
	if key == nil {
		return append([]byte(nil), value...), nil
	}
	if len(params) != aes.BlockSize || len(value) == 0 || len(value)%aes.BlockSize != 0 {
		return nil, ErrSecret
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(value))
	cipher.NewCBCDecrypter(block, params).CryptBlocks(out, value)
	n := int(out[len(out)-1])
	if n == 0 || n > aes.BlockSize || n > len(out) {
		clear(out)
		return nil, ErrSecret
	}
	for _, b := range out[len(out)-n:] {
		if int(b) != n {
			clear(out)
			return nil, ErrSecret
		}
	}
	return out[:len(out)-n], nil
}
