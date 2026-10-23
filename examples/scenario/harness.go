package scenario

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/laenen-ai/iam"
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
				t.Fatalf("%s %s %s = %s through %q, want it through %q. The corpus names which tuple or "+
					"classification is responsible so that a scenario cannot drift into passing through another.\n  note: %s",
					e.Principal, e.Action, e.Resource, got.Verdict, got.Because, e.Because, e.Note)
			}
		})
	}
}

// evalLive evaluates a claim that needs the real registry.
func evalLive(ctx context.Context, f Fixture, env *Env, c Claim) error {
	switch c.Kind {
	case ClaimLiveClearances:
		return liveClearances(ctx, env, c)
	case ClaimLiveGroups:
		return liveGroups(ctx, env, c)
	case ClaimPrincipalUnusable:
		return principalUnusable(ctx, env, c)
	case ClaimNoClearanceFromDiscretion, ClaimAbsoluteHasNoLift:
		return noClearanceFromDiscretion(ctx, f, env, c)
	case ClaimMembershipChangeTakesEffect:
		return membershipChangeTakesEffect(ctx, f, env, c)
	case ClaimAnyActorMayClassify:
		return anyActorMayClassify(ctx, f, env, c)
	default:
		return fmt.Errorf("claim %s is not a live claim", c.Kind)
	}
}

func liveClearances(ctx context.Context, env *Env, c Claim) error {
	id, ok := env.PrincipalID(c.Subject)
	if !ok {
		return fmt.Errorf("unknown principal %q", c.Subject)
	}
	groups, err := env.Registry.ClearanceGroupsOf(ctx, id, env.Now)
	if err != nil {
		return fmt.Errorf("ClearanceGroupsOf(%s): %w", c.Subject, err)
	}
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Name)
	}
	return compareStrings(names, c.Detail, fmt.Sprintf("the clearance groups the registry reports for %s", c.Subject))
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
	return compareStrings(names, c.Detail, fmt.Sprintf("the ordinary groups the registry reports for %s", c.Subject))
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
	if _, err := env.Registry.ClearanceGroupsOf(ctx, id, env.Now); !errors.Is(err, wantErr) {
		return fmt.Errorf("ClearanceGroupsOf(%s) error = %w, want %s", c.Subject, err, want)
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

// membershipChangeTakesEffect adds a principal to an ordinary group
// through the real registry and asserts two things: that the membership
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
		return fmt.Errorf("the fixture declares no ordinary group %q", c.Detail)
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

// anyActorMayClassify demonstrates the gap design §16 question 2 leaves
// open. The registry demands a MandatoryAct for every clearance write, and
// the act witnesses the *channel* — classify-permission or directory-sync
// — together with an actor, a reason and an instant. What nothing checks
// is whether that actor holds the classify permission, because the design
// has not yet decided who does.
//
// So an ordinary user can construct an act naming itself, add itself to a
// clearance group, and satisfy a mandatory gate. The type system's
// achievement is real and narrower than it looks: it makes a clearance
// write impossible to perform *accidentally*, and it does not make one
// impossible to perform.
func anyActorMayClassify(ctx context.Context, f Fixture, env *Env, c Claim) error {
	id, ok := env.PrincipalID(c.Subject)
	if !ok {
		return fmt.Errorf("unknown principal %q", c.Subject)
	}
	if c.Detail == "" {
		return errors.New("claim any-actor-may-classify: detail must name the clearance group to break into")
	}
	cg, ok := env.ClearanceGroup(c.Detail)
	if !ok {
		return fmt.Errorf("the fixture declares no clearance group %q", c.Detail)
	}
	for _, spec := range f.ClearanceGroups {
		if spec.Name == c.Detail && slices.Contains(spec.Members, c.Subject) {
			return fmt.Errorf("%s is already a member of %s, so this claim would pass vacuously", c.Subject, c.Detail)
		}
	}

	act, err := iam.NewMandatoryAct(iam.MandatoryChannelClassify, id,
		"design §16 Q2: nothing checks whether this actor may classify", env.Now)
	if err != nil {
		return fmt.Errorf("an unprivileged principal could not even construct a mandatory act, which would mean the "+
			"gap this claim records has been closed: %w", err)
	}
	if err := env.Registry.AddClearanceGroupMember(ctx, act, cg.ID, id); err != nil {
		return fmt.Errorf("the registry refused a self-issued mandatory act, which means design §16 question 2 has "+
			"been answered and this scenario should move out of UNEXPRESSIBLE.md: %w", err)
	}

	held, err := env.Registry.ClearanceGroupsOf(ctx, id, env.Now)
	if err != nil {
		return fmt.Errorf("ClearanceGroupsOf(%s): %w", c.Subject, err)
	}
	names := make([]string, 0, len(held))
	for _, g := range held {
		names = append(names, g.Name)
	}
	if !slices.Contains(names, c.Detail) {
		return fmt.Errorf("the self-issued act was accepted but %s is not in %s, so the registry is inconsistent "+
			"rather than permissive", c.Subject, c.Detail)
	}
	return nil
}

// noClearanceFromDiscretion is anti-goal A3's adversarial suite at the
// size the identity registry makes possible today: for the named
// principal, enumerate every discretionary operation the registry exposes,
// apply each one, and assert the principal still holds no clearance.
//
// It is not the full suite the design asks for — that needs the tuple
// store, so grants, shares, role assignments, ownership transfers and link
// creation cannot be attempted yet. It is the part that can be attempted,
// and it covers the attacks that are available precisely because identity
// exists before authorization does: adding the principal to every ordinary
// group, having the issuer assert the clearance group's own name as a
// claim-derived group, delegating an agent run from a cleared parent, and
// presenting an ordinary group's id where a clearance group's is expected.
func noClearanceFromDiscretion(ctx context.Context, f Fixture, env *Env, c Claim) error {
	target, ok := env.PrincipalID(c.Subject)
	if !ok {
		return fmt.Errorf("unknown principal %q", c.Subject)
	}

	var attempts []string

	// 1. Add the principal to every ordinary group in the fixture. Group
	//    membership is the everyday discretionary act and the one most
	//    likely to be mistaken for a clearance.
	for _, g := range f.Groups {
		group, known := env.Group(g.Name)
		if !known {
			return fmt.Errorf("group %s was not materialized", g.Name)
		}
		if err := env.Registry.AddGroupMember(ctx, group.ID, target); err != nil {
			return fmt.Errorf("AddGroupMember(%s, %s): %w", g.Name, c.Subject, err)
		}
		attempts = append(attempts, "added to ordinary group "+g.Name)
	}

	// 2. Have the issuer assert every clearance group's name as a
	//    claim-derived group. A claim set is the widest discretionary
	//    channel there is — an IdP administrator controls it — and the
	//    registry must upsert an *ordinary* group of that name rather
	//    than touching the clearance group it is spelled like.
	spec, known := f.Principal(c.Subject)
	if !known {
		return fmt.Errorf("fixture declares no principal %q", c.Subject)
	}
	if spec.Kind != iam.PrincipalKindAgentRun {
		claimed := slices.Clone(spec.ClaimGroups)
		for _, cg := range f.ClearanceGroups {
			claimed = append(claimed, cg.Name)
		}
		forged := spec
		forged.ClaimGroups = claimed
		issuer := f.Issuer
		if issuer == "" {
			issuer = defaultIssuer
		}
		claims, err := claimsFor(env.Tenant, forged, issuer)
		if err != nil {
			return err
		}
		if _, err := env.Registry.UpsertFromClaims(ctx, claims); err != nil {
			return fmt.Errorf("re-upsert with forged claim groups: %w", err)
		}
		attempts = append(attempts, fmt.Sprintf("issuer asserted %v as claim-derived groups", claimed))
	}

	// 3. Present an ordinary group's id where a clearance group's is
	//    expected. The type system blocks the typed path — a GroupID
	//    cannot be converted into a ClearanceGroupID — so the attack has
	//    to arrive as text, and the registry must refuse it.
	for _, g := range f.Groups {
		group, known := env.Group(g.Name)
		if !known {
			continue
		}
		forgedID, err := iam.ParseClearanceGroupID(string(group.ID))
		if err != nil {
			return fmt.Errorf("ParseClearanceGroupID(%s): %w", group.ID, err)
		}
		act, err := iam.NewMandatoryAct(iam.MandatoryChannelClassify, target,
			"A3 adversarial: present an ordinary group id as a clearance group", env.Now)
		if err != nil {
			return err
		}
		err = env.Registry.AddClearanceGroupMember(ctx, act, forgedID, target)
		if !errors.Is(err, iam.ErrGroupKindMismatch) {
			return fmt.Errorf("AddClearanceGroupMember with ordinary group %s's id error = %v, want ErrGroupKindMismatch — "+
				"a tier-1 group that can stand where a clearance group is expected breaches A3 by construction", g.Name, err)
		}
		attempts = append(attempts, "presented ordinary group "+g.Name+"'s id as a clearance group id")
	}

	// 4. Delegate an agent run from every cleared principal. A delegation
	//    is a discretionary act, and a discretionary act that conferred a
	//    clearance would be A3 breached.
	for _, cg := range f.ClearanceGroups {
		for _, member := range cg.Members {
			parent, resolved := env.PrincipalID(member)
			if !resolved {
				continue
			}
			run, err := env.Registry.DelegateAgentRun(ctx, parent, iam.AgentRunSpec{
				TTL:         time.Hour,
				DisplayName: "A3 adversarial run of " + member,
			})
			if err != nil {
				// A deprovisioned or expired parent cannot delegate,
				// which is itself correct; the attack simply is not
				// available.
				continue
			}
			held, err := env.Registry.ClearanceGroupsOf(ctx, run.ID, env.Now)
			if err != nil {
				return fmt.Errorf("ClearanceGroupsOf(agent run of %s): %w", member, err)
			}
			if len(held) != 0 {
				return fmt.Errorf("an agent run delegated from cleared principal %s inherited clearances %v: a "+
					"delegation is a discretionary act and must confer none", member, held)
			}
			attempts = append(attempts, "delegated an agent run from cleared principal "+member)
		}
	}

	// The verdict: after every discretionary operation above, the target
	// must hold exactly the clearances a mandatory act gave it.
	wantHeld := parseSet(c.Detail)
	held, err := env.Registry.ClearanceGroupsOf(ctx, target, env.Now)
	if err != nil {
		return fmt.Errorf("ClearanceGroupsOf(%s) after %d discretionary attempts: %w", c.Subject, len(attempts), err)
	}
	names := make([]string, 0, len(held))
	for _, g := range held {
		names = append(names, g.Name)
	}
	slices.Sort(names)
	if !slices.Equal(names, wantHeld) {
		return fmt.Errorf("%s holds clearances %v after %d discretionary operations, want %v. The operations "+
			"attempted were: %s", c.Subject, names, len(attempts), wantHeld, strings.Join(attempts, "; "))
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
