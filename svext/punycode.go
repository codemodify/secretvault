package svext

import (
	"strings"
	"unicode"
	"unicode/utf8"
)

// Host names reach here in two forms: browsers send them in their ASCII
// form (xn--bcher-kva.example), people store them as they read them
// (bücher.example), and the Public Suffix List has both. They are
// compared in the ASCII form: each label that is not ASCII becomes
// "xn--" and its Punycode (RFC 3492). Labels are lower-cased; the rest of
// IDNA's mapping (NFC, width) is not done, so a name stored in an odd
// Unicode form simply fits nothing.

const (
	pcBase        = 36
	pcTMin        = 1
	pcTMax        = 26
	pcSkew        = 38
	pcDamp        = 700
	pcInitialBias = 72
	pcInitialN    = 128
)

// asciiHost is host in the ASCII form, lower case and without a final
// dot; ok is false when it is not a host name (an empty label, a label
// over 63 bytes, a character no host has).
func asciiHost(host string) (string, bool) {
	host = strings.TrimSuffix(host, ".")
	if host == "" || len(host) > 253*4 {
		return "", false
	}
	labels := strings.Split(host, ".")
	for i, l := range labels {
		a, ok := asciiLabel(l)
		if !ok {
			return "", false
		}
		labels[i] = a
	}
	out := strings.Join(labels, ".")
	if len(out) > 253 {
		return "", false
	}
	return out, true
}

func asciiLabel(l string) (string, bool) {
	if l == "" || !utf8.ValidString(l) {
		return "", false
	}
	ascii := true
	for i := 0; i < len(l); i++ {
		if l[i] >= utf8.RuneSelf {
			ascii = false
			break
		}
	}
	if ascii {
		l = strings.ToLower(l)
	} else {
		enc, ok := punycode(strings.Map(unicode.ToLower, l))
		if !ok {
			return "", false
		}
		l = "xn--" + enc
	}
	if len(l) > 63 {
		return "", false
	}
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return "", false
		}
	}
	return l, true
}

// punycode encodes a label (RFC 3492, section 6.3).
func punycode(s string) (string, bool) {
	var out []byte
	runes := []rune(s)
	for _, r := range runes {
		if r < utf8.RuneSelf {
			out = append(out, byte(r))
		}
	}
	basic := len(out)
	handled := basic
	if basic > 0 {
		out = append(out, '-')
	}
	n, delta, bias := rune(pcInitialN), 0, pcInitialBias
	for handled < len(runes) {
		m := rune(unicode.MaxRune + 1)
		for _, r := range runes {
			if r >= n && r < m {
				m = r
			}
		}
		if int(m-n) > (1<<30)/(handled+1) {
			return "", false // overflow
		}
		delta += int(m-n) * (handled + 1)
		n = m
		for _, r := range runes {
			if r < n {
				delta++
			}
			if r != n {
				continue
			}
			q := delta
			for k := pcBase; ; k += pcBase {
				t := k - bias
				switch {
				case t < pcTMin:
					t = pcTMin
				case t > pcTMax:
					t = pcTMax
				}
				if q < t {
					break
				}
				out = append(out, pcDigit(t+(q-t)%(pcBase-t)))
				q = (q - t) / (pcBase - t)
			}
			out = append(out, pcDigit(q))
			bias = pcAdapt(delta, handled+1, handled == basic)
			delta = 0
			handled++
		}
		delta++
		n++
	}
	return string(out), true
}

func pcDigit(d int) byte {
	if d < 26 {
		return byte('a' + d)
	}
	return byte('0' + d - 26)
}

func pcAdapt(delta, points int, first bool) int {
	if first {
		delta /= pcDamp
	} else {
		delta /= 2
	}
	delta += delta / points
	k := 0
	for delta > ((pcBase-pcTMin)*pcTMax)/2 {
		delta /= pcBase - pcTMin
		k += pcBase
	}
	return k + (pcBase-pcTMin+1)*delta/(delta+pcSkew)
}
