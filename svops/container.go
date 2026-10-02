package svops

import (
	"fmt"
	"math"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/codemodify/secretvault/svcontainer"
)

// Encrypted containers: LUKS2 image files, mounted as disks, whose keys
// are vault items (kind "container"). The daemon creates, opens, closes
// and lists them; what is here needs no key.

// MountsHere says, with svcontainer.ErrNoMount, where containers cannot
// be mounted yet.
func MountsHere() error {
	if runtime.GOOS != "linux" {
		return svcontainer.ErrNoMount
	}
	return nil
}

// ContainerItemName is the item a new container's key goes in by default:
// containers/ and the file's name without its extension.
func ContainerItemName(path string) string {
	base := filepath.Base(path)
	if stem := strings.TrimSuffix(base, filepath.Ext(base)); stem != "" {
		base = stem
	}
	return "containers/" + base
}

// ExistingImage is an image's absolute path, once it is known to be a
// container. It is checked with the caller's own access, so a mistake is
// told exactly (the daemon tells programs no more than "not a container"
// before they have consent).
func ExistingImage(arg string) (string, error) {
	path, err := filepath.Abs(arg)
	if err != nil {
		return "", err
	}
	if _, err := svcontainer.Inspect(path); err != nil {
		return "", err
	}
	return path, nil
}

// ParseSize reads a size: bytes, or a number with K, M, G or T (powers of
// 1024; KiB, MB and the like mean the same).
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	i := strings.IndexFunc(s, func(r rune) bool { return !(r >= '0' && r <= '9' || r == '.') })
	num, unit := s, ""
	if i >= 0 {
		num, unit = s[:i], strings.ToUpper(strings.TrimSpace(s[i:]))
	}
	unit = strings.TrimSuffix(strings.TrimSuffix(unit, "B"), "I")
	mult, ok := map[string]float64{"": 1, "K": 1 << 10, "M": 1 << 20, "G": 1 << 30, "T": 1 << 40}[unit]
	n, err := strconv.ParseFloat(num, 64)
	if !ok || err != nil || n <= 0 || n*mult > math.MaxInt64/2 {
		return 0, fmt.Errorf("%q is not a size (say 512M or 1G)", s)
	}
	return int64(math.Ceil(n * mult)), nil
}

// HumanSize says a size in bytes as people do.
func HumanSize(n int64) string {
	for _, u := range []struct {
		unit string
		size int64
	}{{"TiB", 1 << 40}, {"GiB", 1 << 30}, {"MiB", 1 << 20}, {"KiB", 1 << 10}} {
		if n >= u.size {
			return strings.TrimSuffix(strconv.FormatFloat(float64(n)/float64(u.size), 'f', 1, 64), ".0") + " " + u.unit
		}
	}
	return fmt.Sprintf("%d bytes", n)
}
