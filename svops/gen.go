package svops

import "github.com/codemodify/secretvault/svcrypto"

// GeneratePassword makes a random password of n characters: letters,
// digits and, with symbols, punctuation. The caller clears it.
func GeneratePassword(n int, symbols bool) ([]byte, error) {
	classes := []string{svcrypto.Lower, svcrypto.Upper, svcrypto.Digits, svcrypto.Symbols}
	if !symbols {
		classes = classes[:3]
	}
	return svcrypto.Password(n, classes...)
}
