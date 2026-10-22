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

// Now returns the current wall-clock time, canonicalized. See Canonical
// for why that is not optional.
func (SystemClock) Now() time.Time { return Canonical(time.Now()) }

var _ Clock = SystemClock{}

// FixedClock is a test Clock that returns a fixed instant until advanced.
// It is not safe for concurrent use.
type FixedClock struct {
	now time.Time
}

// NewFixedClock returns a FixedClock starting at t, canonicalized the
// same way SystemClock's instants are, so a test cannot accidentally
// produce an instant production code never could.
func NewFixedClock(t time.Time) *FixedClock { return &FixedClock{now: Canonical(t)} }

// Now returns the clock's current fixed instant.
func (c *FixedClock) Now() time.Time { return c.now }

// Advance moves the clock's fixed instant forward by d.
func (c *FixedClock) Advance(d time.Duration) { c.now = Canonical(c.now.Add(d)) }

var _ Clock = (*FixedClock)(nil)

// Canonical returns t in UTC, truncated to microsecond precision: the
// form every instant this module stores or compares must be in.
//
// Postgres timestamptz holds microseconds. A time.Time carrying
// nanoseconds round-trips *equal to itself in memory* and *unequal through
// the database*, so an in-memory adapter and a Postgres adapter disagree
// about whether two instants are the same instant — which in this module
// means a conformance suite that passes against one adapter and fails
// against the other for a reason that has nothing to do with the contract.
// CONVENTIONS records two other modules hitting this independently on the
// same day.
//
// UTC as well as truncation, because a timestamptz read back carries the
// session's time zone rather than the one it was written in: two values
// that are the same instant compare unequal under time.Time's == and
// reflect.DeepEqual if their locations differ, even though Equal says they
// match. Canonicalizing both ends removes the trap instead of asking every
// comparison to remember Equal.
//
// It is applied where instants enter the system — the clocks above, and
// domain.NewMandatoryAct's caller-supplied instant — rather than at each
// comparison, so there is no path that forgets.
func Canonical(t time.Time) time.Time {
	if t.IsZero() {
		return t
	}
	return t.UTC().Truncate(time.Microsecond)
}
