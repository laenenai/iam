package scenario_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/laenenai/iam/examples/scenario"
)

// The tests in this file are about the harness rather than about `iam`.
// They exist because the corpus's two safety mechanisms — the api.txt
// tripwire and the rule that an unexpressible scenario must demonstrate
// its gap — are both mechanisms that fail by being silent, and a silent
// safety mechanism is indistinguishable from none.

// TestTripwireFiresWhenACapabilityArrives is the test that keeps the
// pending bookkeeping honest. If Tripwire could not detect a capability
// landing, every pending scenario in the corpus would stay pending
// forever and nothing would say so.
func TestTripwireFiresWhenACapabilityArrives(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		surface string
		want    scenario.Capability
	}{
		{"Decide reaches the facade", "package iam // .\n\nfunc Decide(ctx context.Context) error\n", scenario.CapDecide},
		{"Predicate reaches the facade", "package iam // .\n\ntype Predicate struct {\n\tSQL string\n}\n", scenario.CapPredicate},
		{"the tuple store reaches the facade", "package iam // .\n\nfunc WriteTuple(ctx context.Context) error\n", scenario.CapTupleStore},
		{
			"an attribute-aware predicate reaches the facade",
			"package iam // .\n\nfunc PermittedAttributes(ctx context.Context) ([]string, error)\n",
			scenario.CapAttributePredicate,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "api.txt")
			if err := os.WriteFile(path, []byte(tc.surface), 0o600); err != nil {
				t.Fatalf("write fake surface: %v", err)
			}
			arrived, err := scenario.Tripwire(path)
			if err != nil {
				t.Fatalf("Tripwire: %v", err)
			}
			found := false
			for _, c := range arrived {
				if c == tc.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("Tripwire did not notice %s arriving; it reported %v. A tripwire that cannot "+
					"detect the capability landing is why pending scenarios stay pending forever", tc.want, arrived)
			}
		})
	}
}

// TestTripwireIsQuietOnAnEmptySurface is the other half: a tripwire that
// fires on everything would be turned off within a week.
func TestTripwireIsQuietOnAnEmptySurface(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "api.txt")
	surface := "package iam // .\n\nfunc NewMemoryRegistry(cfg RegistryConfig) (Registry, error)\n" +
		"\nfunc MigrateUp(ctx context.Context, pool *pgxpool.Pool) error\n"
	if err := os.WriteFile(path, []byte(surface), 0o600); err != nil {
		t.Fatalf("write fake surface: %v", err)
	}
	arrived, err := scenario.Tripwire(path)
	if err != nil {
		t.Fatalf("Tripwire: %v", err)
	}
	if len(arrived) != 0 {
		t.Fatalf("Tripwire reported %v against a surface that has none of them", arrived)
	}
}

// TestTripwireFailsLoudlyOnAMissingSurface: if api.txt moves or is renamed,
// the tripwire must break rather than quietly reporting that nothing has
// arrived.
func TestTripwireFailsLoudlyOnAMissingSurface(t *testing.T) {
	t.Parallel()

	if _, err := scenario.Tripwire(filepath.Join(t.TempDir(), "absent.txt")); err == nil {
		t.Fatal("Tripwire returned no error for a surface it could not read, which would make the " +
			"corpus silently stop watching for the decision API")
	}
}

// TestUnexpressibleScenarioNeedsADemonstration pins the rule that makes
// examples/unexpressible worth reading: a scenario that says the design
// cannot do something must carry a claim that runs and shows it. Without
// this, UNEXPRESSIBLE.md would be a document asserting things about code
// that does not check them.
func TestUnexpressibleScenarioNeedsADemonstration(t *testing.T) {
	t.Parallel()

	base := scenario.Scenario{
		ID:      "X1",
		Title:   "a claim about something the design cannot do",
		Models:  "a scenario written to check the harness, not the module.",
		Governs: []string{"§8.5"},
		Status:  scenario.StatusUnexpressible,
		Finding: "F7",
		Cost:    "a conditional form, costing the projection",
		Fixture: scenario.Fixture{
			Tenant: "test",
			Kinds: []scenario.ResourceKind{{
				Name:      "document",
				Shape:     scenario.ShapeColumnar,
				Relations: []scenario.Relation{{Name: "viewer", Direct: true}},
				Actions:   map[string]string{"read": "viewer"},
			}},
			Principals: []scenario.PrincipalSpec{{Name: "user:a"}},
		},
		Expect: []scenario.Expectation{{
			Principal: "user:a", Action: "read", Resource: scenario.R("document:x"),
			Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
			Unreachable: "the requirement has no form to be written in",
		}},
	}

	if err := base.Validate(); err == nil {
		t.Fatal("an unexpressible scenario with no gap claim validated. The rule that each one must " +
			"demonstrate its gap with code that runs is what separates this corpus from a wish-list")
	} else if !strings.Contains(err.Error(), "demonstrates the gap") {
		t.Fatalf("Validate refused it for the wrong reason: %v", err)
	}

	withDemonstration := base
	withDemonstration.Claims = []scenario.Claim{
		scenario.C(scenario.ClaimAttributeEnforceable, "document:x.salary", "false",
			"stands in for a real demonstration"),
	}
	if err := withDemonstration.Validate(); err != nil {
		t.Fatalf("the same scenario with a gap claim should validate: %v", err)
	}

	noUnreachableRow := withDemonstration
	noUnreachableRow.Expect = []scenario.Expectation{{
		Principal: "user:a", Action: "read", Resource: scenario.R("document:x"),
		Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
	}}
	if err := noUnreachableRow.Validate(); err == nil {
		t.Fatal("an unexpressible scenario must mark at least one row unreachable, so that the thing " +
			"that cannot be expressed is written down precisely rather than gestured at")
	}
}

// TestLiveScenarioCannotCarryATable keeps the status honest in the other
// direction. "Live" is the corpus's claim that every assertion in a
// scenario runs against the real module today, and an expectation table
// does not.
func TestLiveScenarioCannotCarryATable(t *testing.T) {
	t.Parallel()

	s := scenario.Scenario{
		ID: "X2", Title: "live with a table", Models: "harness test.",
		Governs: []string{"§8.1"}, Status: scenario.StatusLive,
		Fixture: scenario.Fixture{
			Tenant: "test",
			Kinds: []scenario.ResourceKind{{
				Name: "document", Relations: []scenario.Relation{{Name: "viewer", Direct: true}},
				Actions: map[string]string{"read": "viewer"},
			}},
			Principals: []scenario.PrincipalSpec{{Name: "user:a"}},
		},
		Expect: []scenario.Expectation{{
			Principal: "user:a", Action: "read", Resource: scenario.R("document:x"),
			Want: scenario.Deny, Reason: scenario.ReasonNoGrant,
		}},
	}
	if err := s.Validate(); err == nil {
		t.Fatal("a scenario with an expectation table validated as live")
	}
}

// TestSchemaLintRejectsExclusion is design §4/A3's third corollary as a
// direct test rather than through a scenario: an exclusion operator must
// be refused, and the refusal must tell the consumer what to do instead of
// merely saying no.
//
// What "instead" means has changed, which is why each case now carries its
// own expected text. The exclusion refusal used to name the
// classification mechanism; there is no classification, so it names the
// anti-goal and `escrow`. The attribute-condition refusal used to name the
// classification mechanism too, and it now has nothing to point at: it
// says so, and names the open findings, because a refusal that invents an
// alternative is worse than one that admits there is none.
func TestSchemaLintRejectsExclusion(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name         string
		rel          scenario.Relation
		mustMention  string
		wantSentinel error
	}{
		{
			name:         "exclusion",
			rel:          scenario.Relation{Name: "viewer", Direct: true, Exclude: []string{"blocked"}},
			mustMention:  "escrow",
			wantSentinel: scenario.ErrNoDenyMechanism,
		},
		{
			name:         "attribute condition",
			rel:          scenario.Relation{Name: "viewer", Direct: true, AttributeCondition: "row.kind != 'salary'"},
			mustMention:  "F7",
			wantSentinel: scenario.ErrUnexpressible,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			kind := scenario.ResourceKind{Name: "fact", Shape: scenario.ShapeRow, Actions: map[string]string{"read": "viewer"}}
			ok, why := scenario.CanExpress(kind, tc.rel)
			if ok {
				t.Fatalf("CanExpress accepted %s, which design §8.5 does not permit", tc.name)
			}
			if !strings.Contains(why, tc.mustMention) {
				t.Fatalf("the refusal of %s did not mention %q, so it does not tell the consumer where to "+
					"go next: %s", tc.name, tc.mustMention, why)
			}

			f := scenario.Fixture{Kinds: []scenario.ResourceKind{{
				Name: kind.Name, Shape: kind.Shape,
				Relations: []scenario.Relation{tc.rel}, Actions: kind.Actions,
			}}}
			if err := scenario.LintSchema(f); !errors.Is(err, tc.wantSentinel) {
				t.Fatalf("LintSchema(%s) error = %v, want it to wrap %v — a lint that flattens its reasons "+
					"into one string makes `which rule was broken` unanswerable in code", tc.name, err, tc.wantSentinel)
			}
		})
	}
}

// TestNoDenyMechanismIsTheRefusal pins the one sentence the lint exists to
// say. There used to be a test here asserting that a tuple whose subject
// was a clearance group was refused, on the grounds that a clearance
// reachable through a discretionary operation would breach anti-goal A3 by
// construction. The tier it protected is gone and the rule is simpler: no
// relation may exclude anything, at all, because there is no deny
// mechanism to express an exclusion in.
func TestNoDenyMechanismIsTheRefusal(t *testing.T) {
	t.Parallel()

	f := scenario.Fixture{
		Tenant: "test",
		Kinds: []scenario.ResourceKind{{
			Name:  "document",
			Shape: scenario.ShapeColumnar,
			Relations: []scenario.Relation{
				{Name: "viewer", Direct: true, Exclude: []string{"screened"}},
			},
			Actions: map[string]string{"read": "viewer"},
		}},
		Principals: []scenario.PrincipalSpec{{Name: "user:a"}},
	}
	err := scenario.LintSchema(f)
	if !errors.Is(err, scenario.ErrNoDenyMechanism) {
		t.Fatalf("LintSchema error = %v, want it to wrap ErrNoDenyMechanism. A `screened` relation is the "+
			"shape a consumer reaches for when it wants an absolute, and the refusal is where it finds out "+
			"that an absolute is a key the deployment does not hold rather than a policy row", err)
	}
	if !strings.Contains(err.Error(), "escrow") {
		t.Fatalf("the refusal did not name escrow, so it says no without saying what to do: %v", err)
	}
}

// TestDirectPathRefusesADAG is finding F3 at its smallest: two parents and
// the question "which is the direct path" has no answer. D7 relies on this
// function succeeding and U3 relies on it failing, so it is worth testing
// on its own.
func TestDirectPathRefusesADAG(t *testing.T) {
	t.Parallel()

	tree := scenario.Fixture{Containment: []scenario.Edge{
		scenario.E("fact:x", "episode:e"),
		scenario.E("episode:e", "graph:g"),
	}}
	path, err := scenario.DirectPath(tree, scenario.R("fact:x"))
	if err != nil {
		t.Fatalf("DirectPath over a tree: %v", err)
	}
	if len(path) != 2 {
		t.Fatalf("DirectPath over a tree returned %v, want two ancestors", path)
	}

	dag := tree
	dag.Containment = append(dag.Containment, scenario.E("fact:x", "entity-set:s"))
	if _, err := scenario.DirectPath(dag, scenario.R("fact:x")); !errors.Is(err, scenario.ErrNoDirectPath) {
		t.Fatalf("DirectPath over a DAG error = %v, want ErrNoDirectPath", err)
	}
}

// TestContainmentCycleIsAnError: a fixture with a containment cycle must
// fail rather than recurse, because an ancestry closure that does not
// terminate is an authorization decision that does not terminate.
func TestContainmentCycleIsAnError(t *testing.T) {
	t.Parallel()

	f := scenario.Fixture{Containment: []scenario.Edge{
		scenario.E("folder:a", "folder:b"),
		scenario.E("folder:b", "folder:a"),
	}}
	if _, err := scenario.Ancestors(f, scenario.R("folder:a")); err == nil {
		t.Fatal("Ancestors returned no error for a containment cycle")
	}
}
