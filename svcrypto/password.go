package svcrypto

import (
	"crypto/rand"
	"errors"
	"math/big"
	"strings"
)

// Character classes for generated passwords.
const (
	Lower   = "abcdefghijklmnopqrstuvwxyz"
	Upper   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	Digits  = "0123456789"
	Symbols = "!#$%&()*+,-./:;<=>?@[]^_{|}~"
)

// Password returns a random password of n characters drawn uniformly from
// the union of the given classes, containing at least one character of
// each class (many sites insist). Draws that miss a class are thrown away
// and redrawn, so every acceptable password is equally likely.
func Password(n int, classes ...string) ([]byte, error) {
	if len(classes) == 0 {
		classes = []string{Lower, Upper, Digits, Symbols}
	}
	if n < len(classes) || n > 4096 {
		return nil, errors.New("svcrypto: password length out of range")
	}
	alphabet := strings.Join(classes, "")
	max := big.NewInt(int64(len(alphabet)))
	out := make([]byte, n)
	for {
		for i := range out {
			j, err := rand.Int(rand.Reader, max)
			if err != nil {
				return nil, err
			}
			out[i] = alphabet[j.Int64()]
		}
		ok := true
		for _, c := range classes {
			if !strings.ContainsAny(string(out), c) {
				ok = false
				break
			}
		}
		if ok {
			return out, nil
		}
	}
}
