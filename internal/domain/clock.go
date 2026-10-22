package domain

import "time"

// Clock abstracts the current time so id generation, and anything else
// that reads "now" on a write path, can be driven deterministically in
// tests.
//
// Read paths in the registry port do not use a Clock: they take the
// deciding instant as an explicit asOf argument, so a decision and the
// freshness check that authorizes it share one instant instead of two
// reads of a wall clock. See registry.Registry's doc comment.
type Clock interface {
	Now() time.Time
}

// SystemClock is the production Clock, backed by the real wall clock.
type SystemClock struct{}

// Now returns the current wall-clock time.
func (SystemClock) Now() time.Time { return time.Now() }

var _ Clock = SystemClock{}

// FixedClock is a test Clock that returns a fixed instant until advanced.
// It is not safe for concurrent use.
type FixedClock struct {
	now time.Time
}

// NewFixedClock returns a FixedClock starting at t.
func NewFixedClock(t time.Time) *FixedClock { return &FixedClock{now: t} }

// Now returns the clock's current fixed instant.
func (c *FixedClock) Now() time.Time { return c.now }

// Advance moves the clock's fixed instant forward by d.
func (c *FixedClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

var _ Clock = (*FixedClock)(nil)
