package scenario

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/laenenai/iam"
)

// APIGoldenPath is where the harness looks for the module's public surface
// when arming the pending tripwire. It is relative to the examples
// directory, which is where the corpus's test lives.
const APIGoldenPath = "../api.txt"

// RunCorpus runs the whole use-case corpus. newRegistry is called once per
// scenario with that scenario's own *testing.T, so an adapter that needs
// setup and teardown registers it with t.Cleanup inside the factory and
// every scenario gets fresh, isolated state — the same contract
// iamtest.RunRegistrySuite uses, for the same reason.
//
// It is exported, and lives in a non-test file, because the corpus has to
// be runnable from another module: CAS's alpha builds its own
// authorization "shaped as this module's port and verified by this
// module's conformance suite" (design §14), and a use-case corpus that
// only runs here would verify the shape and not the behaviour.
//
// What it does for each scenario:
//
//  1. validates the scenario — a fixture naming a principal that does not
//     exist, or an action its kind does not register, would otherwise pass
//     for the wrong reason;
//  2. materializes the identity layer against reg, which is live;
//  3. evaluates every structural claim, which is live;
//  4. evaluates every reachable expectation row against the reference
//     oracle, matching the reason as well as the verdict.
//
// And then the part that matters more than any of it: it arms the pending
// tripwire. If the module's public surface has grown a capability any
// scenario is pending on, the run fails and names those scenarios.
func RunCorpus(t *testing.T, scenarios []Scenario, newRegistry func(t *testing.T) iam.Registry) {
	t.Helper()

	if len(scenarios) == 0 {
		t.Fatal("the corpus is empty, which is not a pass")
	}

	seen := make(map[string]bool, len(scenarios))
	for _, s := range scenarios {
		if seen[s.ID] {
			t.Fatalf("two scenarios share the id %q", s.ID)
		}
		seen[s.ID] = true
	}

	for _, s := range scenarios {
		t.Run(s.ID+"_"+slug(s.Title), func(t *testing.T) {
			RunScenario(t, s, newRegistry(t))
		})
	}

	t.Run("PendingTripwire", func(t *testing.T) {
		AssertTripwire(t, scenarios, APIGoldenPath)
	})
}

// RunScenario runs one scenario against reg.
func RunScenario(t *testing.T, s Scenario, reg iam.Registry) {
	t.Helper()

	if err := s.Validate(); err != nil {
		t.Fatalf("scenario is not well formed: %v", err)
	}
	t.Logf("%s — %s\n  models: %s\n  governed by: %s\n  status: %s",
		s.ID, s.Title, collapse(s.Models), strings.Join(s.Governs, ", "), s.Status)

	clock := iam.SystemClock{}
	env, err := Materialize(context.Background(), reg, s.Fixture, clock)
	if err != nil {
		t.Fatalf("materializing the identity layer against the real registry failed: %v", err)
	}

	for i, c := range s.Claims {
		name := fmt.Sprintf("claim%d_%s", i, slug(string(c.Kind)))
		t.Run(name, func(t *testing.T) {
			var err error
			if c.needsRegistry() {
				err = evalLive(t.Context(), s.Fixture, env, c)
			} else {
				err = c.evalStatic(s.Fixture)
			}
			if err != nil {
				t.Fatalf("%s(%s): %v\n  what this claim means: %s", c.Kind, c.Subject, err, c.Why)
			}
		})
	}

	if len(s.Expect) > 0 {
		t.Run("ExpectationTable", func(t *testing.T) {
			runTable(t, s)
		})
	}
}

// runTable evaluates the reachable rows against the reference oracle. It
// is explicit in its failure messages that a match here is evidence about
// the corpus's own oracle and not yet about `iam`: the table is pinned, so
// that when the real Decide arrives the two can be run against the same
// rows and diffed.
func runTable(t *testing.T, s Scenario) {
	t.Helper()
	for i, e := range s.Expect {
		row := fmt.Sprintf("row%d_%s_%s_%s", i, slug(e.Principal), slug(e.Action), slug(e.Resource.String()))
		t.Run(row, func(t *testing.T) {
			if e.Unreachable != "" {
				t.Logf("not evaluated — the design cannot deliver this row: %s\n  the requirement is: %s %s %s -> %s (%s)\n  the gap is demonstrated by this scenario's claims.",
					e.Unreachable, e.Principal, e.Action, e.Resource, e.Want, e.Reason)
				return
			}
			got, err := Decide(s.Fixture, e.Principal, e.Action, e.Resource)
			if err != nil {
				t.Fatalf("the reference decision procedure could not answer %s %s %s: %v\n  note: %s",
					e.Principal, e.Action, e.Resource, err, e.Note)
			}
			if got.Verdict != e.Want {
				t.Fatalf("%s %s %s = %s (%s: %s), want %s because %s\n  note: %s",
					e.Principal, e.Action, e.Resource, got.Verdict, got.Reason, got.Because, e.Want, e.Because, e.Note)
			}
			if got.Reason != e.Reason {
				t.Fatalf("%s %s %s = %s for the wrong reason: got %s (%s), want %s (%s). "+
					"A scenario that passes for the wrong reason is worse than one that fails.\n  note: %s",
					e.Principal, e.Action, e.Resource, got.Verdict, got.Reason, got.Because, e.Reason, e.Because, e.Note)
			}
			if e.Because != "" && got.Because != e.Because {
				t.Fatalf("%s %s %s = %s through %q, want it through %q. The corpus names which tuple is "+
					"responsible so that a scenario cannot drift into passing through another.\n  note: %s",
					e.Principal, e.Action, e.Resource, got.Verdict, got.Because, e.Because, e.Note)
			}
		})
	}
}

// evalLive evaluates a claim that needs the real registry.
//
// There were three more cases here, and they are worth naming because
// their absence is the refactor: live-clearances read a principal's
// clearance groups back from the registry, no-clearance-from-discretion
// applied every discretionary operation the registry exposed and asserted
// the principal still held none, and any-actor-may-classify showed that
// anybody could perform a mandatory act on their own behalf. The registry
// no longer has the surface any of them called.
func evalLive(ctx context.Context, f Fixture, env *Env, c Claim) error {
	switch c.Kind {
	case ClaimLiveGroups:
		return liveGroups(ctx, env, c)
	case ClaimPrincipalUnusable:
		return principalUnusable(ctx, env, c)
	case ClaimMembershipChangeTakesEffect:
		return membershipChangeTakesEffect(ctx, f, env, c)
	default:
		return fmt.Errorf("claim %s is not a live claim", c.Kind)
	}
}

func liveGroups(ctx context.Context, env *Env, c Claim) error {
	id, ok := env.PrincipalID(c.Subject)
	if !ok {
		return fmt.Errorf("unknown principal %q", c.Subject)
	}
	groups, err := env.Registry.GroupsOf(ctx, id, env.Now)
	if err != nil {
		return fmt.Errorf("GroupsOf(%s): %w", c.Subject, err)
	}
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Name)
	}
	return compareStrings(names, c.Detail, fmt.Sprintf("the groups the registry reports for %s", c.Subject))
}

// principalUnusable asserts that the registry refuses to read a
// principal's memberships at all. Detail names the expected state, so a
// deprovisioned principal cannot pass this claim by being merely expired.
func principalUnusable(ctx context.Context, env *Env, c Claim) error {
	id, ok := env.PrincipalID(c.Subject)
	if !ok {
		return fmt.Errorf("unknown principal %q", c.Subject)
	}
	wantErr := expectedConditionError(c.Detail)
	if wantErr == nil {
		return fmt.Errorf("claim principal-unusable: detail must be one of %q, %q or %q, got %q",
			iam.PrincipalStateDeprovisioned, iam.PrincipalStateExpired, iam.PrincipalStateResyncRequired, c.Detail)
	}
	// The expected sentinel is rendered as text rather than passed as an
	// error value: it is the *description* of what should have happened,
	// not a cause of this failure, and wrapping it would make
	// errors.Is(this, sentinel) true for a message that reports the
	// sentinel's absence.
	want := wantErr.Error()
	if _, err := env.Registry.GroupsOf(ctx, id, env.Now); !errors.Is(err, wantErr) {
		return fmt.Errorf("GroupsOf(%s) error = %w, want %s — a registry that answers with a membership list lets a "+
			"caller decide with a principal it may not use", c.Subject, err, want)
	}
	condition, err := env.Registry.Condition(ctx, id, env.Now)
	if err != nil {
		return fmt.Errorf("Condition(%s): %w", c.Subject, err)
	}
	if condition.Usable() {
		return fmt.Errorf("Condition(%s) says usable, which contradicts the membership reads", c.Subject)
	}
	return nil
}

// expectedConditionError maps the state a claim names onto the sentinel a
// membership read must return for a principal in that state. It returns
// nil for anything else, so a claim naming a state that is not a refusal
// fails rather than passing vacuously.
func expectedConditionError(detail string) error {
	switch iam.PrincipalState(detail) {
	case iam.PrincipalStateDeprovisioned:
		return iam.ErrPrincipalDeprovisioned
	case iam.PrincipalStateExpired:
		return iam.ErrAgentRunExpired
	case iam.PrincipalStateResyncRequired:
		return iam.ErrResyncRequired
	default:
		return nil
	}
}

// membershipChangeTakesEffect adds a principal to a group through the
// real registry and asserts two things: that the membership
// the authorization predicate joins against actually changed, and that no
// grant was rewritten to make it happen. That second half is design
// §8.2's userset form earning its keep — the grant names the team, so
// changing the team is one row and the grant is untouched.
func membershipChangeTakesEffect(ctx context.Context, f Fixture, env *Env, c Claim) error {
	id, ok := env.PrincipalID(c.Subject)
	if !ok {
		return fmt.Errorf("unknown principal %q", c.Subject)
	}
	group, ok := env.Group(c.Detail)
	if !ok {
		return fmt.Errorf("the fixture declares no group %q", c.Detail)
	}

	before, err := env.Registry.GroupMembers(ctx, group.ID, env.Now)
	if err != nil {
		return fmt.Errorf("GroupMembers(%s) before: %w", c.Detail, err)
	}
	if slices.Contains(before, id) {
		return fmt.Errorf("%s is already a member of %s, so this claim would pass vacuously", c.Subject, c.Detail)
	}

	tuplesBefore, err := CountTuples(f)
	if err != nil {
		return err
	}
	if err := env.Registry.AddGroupMember(ctx, group.ID, id); err != nil {
		return fmt.Errorf("AddGroupMember(%s, %s): %w", c.Detail, c.Subject, err)
	}

	after, err := env.Registry.GroupMembers(ctx, group.ID, env.Now)
	if err != nil {
		return fmt.Errorf("GroupMembers(%s) after: %w", c.Detail, err)
	}
	if !slices.Contains(after, id) {
		return fmt.Errorf("after AddGroupMember(%s, %s) the registry still does not report the membership the "+
			"authorization predicate joins against", c.Detail, c.Subject)
	}
	if len(after) != len(before)+1 {
		return fmt.Errorf("the group went from %d members to %d, want %d", len(before), len(after), len(before)+1)
	}

	tuplesAfter, err := CountTuples(f)
	if err != nil {
		return err
	}
	if tuplesAfter.Tuples != tuplesBefore.Tuples {
		return fmt.Errorf("the membership change rewrote %d grant tuples; a userset grant names the team, so "+
			"changing the team must touch no grant at all (design §8.2 form 2, anti-goal A2's closure budget)",
			tuplesAfter.Tuples-tuplesBefore.Tuples)
	}
	return nil
}

// AssertTripwire fails the test if any capability a scenario is pending on
// has arrived in the module's public surface. This is the mechanism that
// stops a pending scenario from staying pending forever, and the reason it
// is a tripwire on api.txt rather than a flag in this package is that a
// flag has to be remembered: api.txt is regenerated by a test that `mise
// test` already runs, so the moment `Decide` reaches the facade, this
// fails and names the scenarios that must now be wired to it.
func AssertTripwire(t *testing.T, scenarios []Scenario, apiGoldenPath string) {
	t.Helper()

	arrived, err := Tripwire(apiGoldenPath)
	if err != nil {
		t.Fatalf("arming the pending tripwire: %v", err)
	}

	available := Available()
	for _, c := range arrived {
		if !slices.Contains(available, c) {
			available = append(available, c)
		}
	}
	if len(available) == 0 {
		return
	}

	var stuck []string
	for _, s := range scenarios {
		if s.Status != StatusPending {
			continue
		}
		var ready []string
		for _, c := range s.PendingOn {
			if slices.Contains(available, c) {
				ready = append(ready, string(c))
			}
		}
		if len(ready) > 0 {
			stuck = append(stuck, fmt.Sprintf("%s (%s) is pending on %s, which now exists", s.ID, s.Title, strings.Join(ready, ", ")))
		}
	}
	if len(stuck) == 0 {
		return
	}
	t.Fatalf("the module has grown capabilities the corpus is still waiting on, so these scenarios are no longer "+
		"honestly pending:\n  %s\n\nWire their expectation tables to the real API, change their status to live, and "+
		"regenerate examples/pending.txt. A pending scenario that silently stays pending forever is the failure mode "+
		"this corpus exists to avoid.", strings.Join(stuck, "\n  "))
}

func slug(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	return strings.Trim(b.String(), "_")
}

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }
