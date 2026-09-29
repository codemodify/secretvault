package svserver

import (
	"crypto/rand"
	"encoding/base32"
	"strings"
	"sync"
	"time"
)

// replayCache remembers every request accepted while its timestamp is
// still inside the allowed skew, so a captured request cannot be sent
// again. A request is known by its device and nonce; the signature covers
// both, so neither can be changed to make an old request look new.
type replayCache struct {
	mu      sync.Mutex
	seen    map[string]int64 // device + nonce → Unix time after which it is too old anyway
	max     int
	nextGC  int64
	gcEvery int64
}

func newReplayCache(limit int, skew time.Duration) *replayCache {
	return &replayCache{seen: map[string]int64{}, max: limit, gcEvery: max(int64(skew/time.Second)/4, 1)}
}

// add records a request, reporting false if it was seen before. full is
// true when the cache cannot take more (the request is then refused
// rather than risk forgetting one still valid).
func (c *replayCache) add(key string, expires, now int64) (fresh, full bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now >= c.nextGC || len(c.seen) >= c.max {
		for k, exp := range c.seen {
			if exp < now {
				delete(c.seen, k)
			}
		}
		c.nextGC = now + c.gcEvery
	}
	if _, ok := c.seen[key]; ok {
		return false, false
	}
	if len(c.seen) >= c.max {
		return false, true
	}
	c.seen[key] = expires
	return true, false
}

// limiter is a token bucket per key (a device, or an IP address).
type limiter struct {
	rate, burst float64
	mu          sync.Mutex
	buckets     map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newLimiter allows rate requests a second per key, in bursts of up to
// ten seconds' worth. A rate below zero turns limiting off.
func newLimiter(rate float64) *limiter {
	if rate < 0 {
		return nil
	}
	if rate == 0 {
		rate = 100
	}
	return &limiter{rate: rate, burst: max(10*rate, 1), buckets: map[string]*bucket{}}
}

// allow takes a token for key, reporting false (and how long until one is
// free) when there is none.
func (l *limiter) allow(key string, now time.Time) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) > 10000 {
		for k, b := range l.buckets {
			if b.tokens+now.Sub(b.last).Seconds()*l.rate >= l.burst {
				delete(l.buckets, k)
			}
		}
	}
	b := l.buckets[key]
	if b == nil {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}
	if el := now.Sub(b.last).Seconds(); el > 0 {
		b.tokens = min(l.burst, b.tokens+el*l.rate)
	}
	b.last = now
	if b.tokens < 1 {
		return false, time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	}
	b.tokens--
	return true, 0
}

// Enrolment codes are 128 random bits in base32: 26 letters and digits,
// read back forgiving case, spaces and dashes.

var codeEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func newEnrolmentCode() string {
	var b [16]byte
	rand.Read(b[:])
	return codeEncoding.EncodeToString(b[:])
}

func normaliseCode(s string) string {
	s = strings.ToUpper(s)
	return strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' {
			return -1
		}
		return r
	}, s)
}
