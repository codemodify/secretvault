package svops

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Emergency access: a person you trust can open a vault of yours after a
// waiting period, unless you deny it first. The daemon does it all; here
// is the wait, as people write and read it.

// ParseWait reads a waiting period: a Go duration (48h, 90m), or a number
// of days (7d) or weeks (2w).
func ParseWait(s string) (time.Duration, error) {
	for suffix, unit := range map[string]time.Duration{"d": 24 * time.Hour, "w": 7 * 24 * time.Hour} {
		if digits, ok := strings.CutSuffix(s, suffix); ok {
			n, err := strconv.Atoi(digits)
			if err != nil || n <= 0 || n > 10000 { // beyond any wait allowed, and far from overflowing
				return 0, fmt.Errorf("%q is not a wait (like 48h, 7d or 2w)", s)
			}
			return time.Duration(n) * unit, nil
		}
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return 0, fmt.Errorf("%q is not a wait (like 48h, 7d or 2w)", s)
	}
	return d, nil
}

// WaitText says a wait in seconds as people do.
func WaitText(secs int64) string {
	d := time.Duration(secs) * time.Second
	switch {
	case d >= 24*time.Hour && d%(24*time.Hour) == 0:
		if n := d / (24 * time.Hour); n != 1 {
			return fmt.Sprintf("%d days", n)
		}
		return "a day"
	case d >= time.Hour && d%time.Hour == 0:
		if n := d / time.Hour; n != 1 {
			return fmt.Sprintf("%d hours", n)
		}
		return "an hour"
	}
	return d.String()
}
