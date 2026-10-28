package domain

import "time"

// Clock supplies domain time. Tests use FixedClock; deployment uses SystemClock.
type Clock interface {
	Now() time.Time
}

// SystemClock reads the wall clock.
type SystemClock struct{}

// Now returns the current wall time.
func (SystemClock) Now() time.Time {
	return time.Now()
}

// FixedClock is a manually advanced clock. Its zero value is the Unix epoch,
// so a zero-value clock can still mint a valid ULID.
type FixedClock struct {
	now time.Time
}

// Now returns the clock value, or the Unix epoch for the zero value.
func (c FixedClock) Now() time.Time {
	if c.now.IsZero() {
		return time.Unix(0, 0).UTC()
	}
	return c.now
}

// Advance moves the clock forward.
func (c *FixedClock) Advance(d time.Duration) {
	c.now = c.Now().Add(d)
}
