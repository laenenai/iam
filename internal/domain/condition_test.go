package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/laenen-ai/iam/internal/domain"
)

func TestEvaluateCondition(t *testing.T) {
	t.Parallel()

	clock := domain.NewFixedClock(time.Date(2026, 10, 23, 12, 0, 0, 0, time.UTC))
	now := clock.Now()
	tenant := domain.NewTenantID(clock)
	parent := domain.NewPrincipalID(clock)
	const bound = time.Hour

	user := domain.Principal{
		ID:       domain.NewPrincipalID(clock),
		TenantID: tenant,
		Kind:     domain.PrincipalKindUser,
		SyncedAt: now,
	}
	agent := domain.Principal{
		ID:          domain.NewPrincipalID(clock),
		TenantID:    tenant,
		Kind:        domain.PrincipalKindAgentRun,
		DelegatedBy: parent,
		SyncedAt:    now,
		ExpiresAt:   now.Add(30 * time.Minute),
	}

	cases := []struct {
		name      string
		principal domain.Principal
		bound     time.Duration
		asOf      time.Time
		wantState domain.PrincipalState
		wantErr   error
	}{
		{"fresh user", user, bound, now.Add(time.Minute), domain.PrincipalStateUsable, nil},
		{"user exactly at the bound is still fresh", user, bound, now.Add(bound), domain.PrincipalStateUsable, nil},
		{"user one nanosecond past the bound is stale", user, bound, now.Add(bound + 1), domain.PrincipalStateResyncRequired, domain.ErrResyncRequired},
		{"never synced", func() domain.Principal { p := user; p.SyncedAt = time.Time{}; return p }(), bound, now, domain.PrincipalStateResyncRequired, domain.ErrResyncRequired},
		{"zero bound fails closed", user, 0, now, domain.PrincipalStateResyncRequired, domain.ErrResyncRequired},
		{"negative bound fails closed", user, -time.Hour, now, domain.PrincipalStateResyncRequired, domain.ErrResyncRequired},
		{
			"deprovisioned beats freshness",
			func() domain.Principal { p := user; p.DeprovisionedAt = now; return p }(),
			bound, now.Add(time.Nanosecond), domain.PrincipalStateDeprovisioned, domain.ErrPrincipalDeprovisioned,
		},
		{
			"deprovisioned beats staleness too",
			func() domain.Principal { p := user; p.DeprovisionedAt = now; return p }(),
			bound, now.Add(10 * bound), domain.PrincipalStateDeprovisioned, domain.ErrPrincipalDeprovisioned,
		},
		{"agent run inside its ttl", agent, bound, now.Add(time.Minute), domain.PrincipalStateUsable, nil},
		{"agent run exactly at its deadline is expired", agent, bound, agent.ExpiresAt, domain.PrincipalStateExpired, domain.ErrAgentRunExpired},
		{"agent run past its deadline", agent, bound, agent.ExpiresAt.Add(time.Minute), domain.PrincipalStateExpired, domain.ErrAgentRunExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := domain.EvaluateCondition(tc.principal, tc.bound, tc.asOf)
			if got.State != tc.wantState {
				t.Fatalf("State = %q, want %q", got.State, tc.wantState)
			}
			if !errors.Is(got.Err(), tc.wantErr) {
				t.Fatalf("Err() = %v, want %v", got.Err(), tc.wantErr)
			}
			if got.Usable() != (tc.wantErr == nil) {
				t.Fatalf("Usable() = %v but Err() = %v", got.Usable(), got.Err())
			}
			if got.Bound != tc.bound || !got.AsOf.Equal(tc.asOf) {
				t.Fatalf("condition did not report the facts it was computed from: %+v", got)
			}
		})
	}
}

// TestZeroConditionDenies is the fail-closed canary for the typed
// condition: the value a caller gets without evaluating anything, or that
// a future adapter forgets to fill in, must refuse rather than permit.
func TestZeroConditionDenies(t *testing.T) {
	t.Parallel()

	var c domain.PrincipalCondition
	if c.State != domain.PrincipalStateUnknown {
		t.Fatalf("the zero condition's state is %q, want the unknown state", c.State)
	}
	if c.Usable() {
		t.Fatal("the zero PrincipalCondition reports Usable; it must fail closed")
	}
	if !errors.Is(c.Err(), domain.ErrResyncRequired) {
		t.Fatalf("the zero condition's Err() = %v, want ErrResyncRequired", c.Err())
	}

	// A state this switch has never heard of must deny too, so adding a
	// state without teaching Err about it cannot turn into a permit.
	future := domain.PrincipalCondition{State: domain.PrincipalState("quarantined-pending-review")}
	if future.Usable() || future.Err() == nil {
		t.Fatal("an unrecognized PrincipalState permitted; the default branch must deny")
	}
}
