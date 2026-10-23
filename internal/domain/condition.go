package domain

import "time"

// PrincipalState is the registry's verdict on whether a principal may be
// used in an authorization decision right now. It is an enumeration and
// not a boolean on purpose: "may I use this principal" has four different
// answers that demand four different responses from the caller, and
// collapsing them into a bool forces the caller to guess.
//
//	usable           -> proceed
//	resync-required  -> re-provision from a fresh token, then retry
//	deprovisioned    -> deny, permanently; no retry will help
//	expired          -> deny; this agent run is over
//
// A caller handed `false` would have to decide between retrying forever,
// failing the request, and telling the user to log in again, with no basis
// for choosing. Design §8.1 requires a stale principal to "force a
// re-sync before use", which is an instruction, not a verdict, and only a
// typed condition can carry it.
//
// The zero value is PrincipalStateUnknown and it is not usable. That is
// fail-closed by construction: a PrincipalCondition that was never
// evaluated, or one that a future adapter forgot to fill in, denies.
type PrincipalState string

const (
	// PrincipalStateUnknown is the zero value: the condition has not been
	// evaluated. It denies, and Err reports ErrResyncRequired, because an
	// unevaluated freshness check is indistinguishable from a failed one.
	PrincipalStateUnknown PrincipalState = ""
	// PrincipalStateUsable means the principal is active and within the
	// deployment's staleness bound.
	PrincipalStateUsable PrincipalState = "usable"
	// PrincipalStateResyncRequired means the principal's claim-derived
	// state is older than the bound. It is recoverable: re-provision from
	// a fresh token and the condition clears.
	PrincipalStateResyncRequired PrincipalState = "resync-required"
	// PrincipalStateDeprovisioned means the principal has been
	// deprovisioned. It is not recoverable and not a staleness condition:
	// a fresh token for the same external subject does not revive it
	// (design §8.1, §9.3 — deprovisioning denies immediately regardless
	// of token validity).
	PrincipalStateDeprovisioned PrincipalState = "deprovisioned"
	// PrincipalStateExpired means an agent-run principal is past its
	// policy TTL. Garbage collection is a sweep, so the row may still
	// exist; the principal is unusable from the deadline itself, which is
	// why a slow collector delays cleanup and never access.
	PrincipalStateExpired PrincipalState = "expired"
)

// PrincipalCondition is the typed freshness-and-liveness verdict for one
// principal at one instant, together with the facts it was computed from
// so a caller can log or surface them without a second read.
type PrincipalCondition struct {
	// PrincipalID names the principal this verdict is about.
	PrincipalID PrincipalID
	// State is the verdict. See PrincipalState.
	State PrincipalState
	// SyncedAt is the principal's last successful sync, copied from the
	// row the verdict was computed from.
	SyncedAt time.Time
	// Age is asOf minus SyncedAt: how stale the principal was at the
	// deciding instant. It may be negative if SyncedAt is in the future
	// relative to asOf.
	Age time.Duration
	// Bound is the deployment's declared staleness bound, reported back
	// so a caller — and this module's conformance suite — can reason
	// about the margin without having to know the registry's
	// configuration.
	Bound time.Duration
	// AsOf is the instant the verdict was computed for.
	AsOf time.Time
}

// Err returns the sentinel a caller should propagate for c's state, or nil
// if the principal is usable. It is the single place the mapping from
// state to refusal lives, so no adapter and no consumer gets to invent its
// own.
func (c PrincipalCondition) Err() error {
	switch c.State {
	case PrincipalStateUsable:
		return nil
	case PrincipalStateDeprovisioned:
		return ErrPrincipalDeprovisioned
	case PrincipalStateExpired:
		return ErrAgentRunExpired
	case PrincipalStateResyncRequired:
		return ErrResyncRequired
	default:
		// PrincipalStateUnknown and anything a future version adds
		// without teaching this switch about it: deny. The one thing
		// this module must never do is permit by default.
		return ErrResyncRequired
	}
}

// Usable reports whether the principal may be used. It is a convenience
// over State and deliberately not the only way to ask: a caller that needs
// to *do* something about a refusal must read State or Err.
func (c PrincipalCondition) Usable() bool { return c.State == PrincipalStateUsable }

// EvaluateCondition computes p's condition against bound at asOf. It is a
// pure function in domain rather than adapter logic so that an in-memory
// registry and a Postgres one cannot disagree about when a principal has
// gone stale — a disagreement that would show up as one deployment
// permitting what another denies.
//
// The order of the checks is the order of severity, and it matters:
//
//   - A deprovisioned principal is deprovisioned even if it synced a
//     millisecond ago, and the verdict ignores asOf entirely. Design §8.1
//     says deprovisioning denies immediately regardless of token validity,
//     so there is no instant at which a deprovisioned principal is usable
//     and no re-sync that clears it.
//   - An expired agent run is expired even if its parent is active.
//   - **The staleness bound does not apply to an agent run**, which is the
//     one non-obvious rule here. The bound exists because claim-derived
//     state drifts from the directory that owns it: a user's group
//     membership may have changed since their token was issued, so past
//     the bound the registry refuses until a fresh token re-syncs it. An
//     agent run has no such state and no such token. It is delegated, not
//     provisioned; it holds no groups at all; and nothing
//     could re-sync it, because there is no issuer to ask. Applying the
//     bound to it would make every run longer than the bound fail halfway
//     through with a refusal no caller could clear — a staleness check
//     against an authority that does not exist. An agent run's liveness is
//     its TTL, and its parent's deprovisioning reaches it because
//     Registry.Deprovision cascades to live runs rather than because a
//     read-time check chases the parent.
//   - A bound of zero or less is a misconfiguration, and it resolves to
//     resync-required rather than to "never stale". A deployment that
//     failed to declare a bound gets the fail-closed reading; Config
//     validation refuses the value long before this, and this is the
//     backstop for the path that skipped it.
func EvaluateCondition(p Principal, bound time.Duration, asOf time.Time) PrincipalCondition {
	c := PrincipalCondition{
		PrincipalID: p.ID,
		SyncedAt:    p.SyncedAt,
		Age:         asOf.Sub(p.SyncedAt),
		Bound:       bound,
		AsOf:        asOf,
	}

	switch {
	case !p.DeprovisionedAt.IsZero():
		c.State = PrincipalStateDeprovisioned
	case p.Kind == PrincipalKindAgentRun && !p.ExpiresAt.IsZero() && !asOf.Before(p.ExpiresAt):
		c.State = PrincipalStateExpired
	case p.Kind == PrincipalKindAgentRun:
		// Inside its TTL and not deprovisioned. The staleness bound does
		// not apply: see the doc comment above.
		c.State = PrincipalStateUsable
	case bound <= 0, p.SyncedAt.IsZero(), c.Age > bound:
		c.State = PrincipalStateResyncRequired
	default:
		c.State = PrincipalStateUsable
	}
	return c
}
