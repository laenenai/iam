package domain

import "time"

// Clock supplies domain time. Tests use FixedClock; deployment uses SystemClock.
type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (SystemClock) Now() time.Time {
	return time.Now()
}

// FixedClock is a manually advanced clock. Its zero value is the Unix epoch,
// so a zero-value clock can still mint a valid ULID.
type FixedClock struct {
	now time.Time
}

func (c FixedClock) Now() time.Time {
	if c.now.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return c.now
}

func (c *FixedClock) Advance(d time.Duration) {
	c.now = c.Now().Add(d)
}
