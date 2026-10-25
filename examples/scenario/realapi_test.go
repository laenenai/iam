package scenario_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/iam"
	"github.com/laenenai/iam/examples/scenario"
)

// The tests in this file are about the translation in realapi.go rather
// than about `iam` or about the corpus. They exist because that file is
// the hinge the whole differential hangs on: a translator that writes the
// wrong grants makes `iam.Decide` and the reference oracle disagree about
// rows neither of them is wrong about, and a translator that reports the
// wrong reason makes them agree about rows they should not. Both failures
// are indistinguishable from a finding about the module, which is the one
// thing this corpus must not produce by accident.

const (
	testStalenessBound = 15 * time.Minute
	testMaxAgentRunTTL = 24 * time.Hour
)

func newAuthority(t *testing.T) (iam.Registry, iam.Authorizer) {
	t.Helper()
	reg, err := iam.NewMemoryRegistry(iam.RegistryConfig{
		StalenessBound: testStalenessBound,
		MaxAgentRunTTL: testMaxAgentRunTTL,
	})
	if err != nil {
		t.Fatalf("NewMemoryRegistry: %v", err)
	}
	authorizer, err := iam.NewMemoryAuthorizer(reg, iam.AuthorizerConfig{})
	if err != nil {
		t.Fatalf("NewMemoryAuthorizer: %v", err)
	}
	return reg, authorizer
}

// realize materializes a fixture against fresh in-memory adapters.
func realize(t *testing.T, f scenario.Fixture) *scenario.RealWorld {
	t.Helper()
	reg, authorizer := newAuthority(t)
	env, err := scenario.Materialize(context.Background(), reg, f, iam.SystemClock{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	world, err := scenario.Realize(context.Background(), authorizer, env, f)
	if err != nil {
		t.Fatalf("Realize: %v", err)
	}
	return world
}

// driveShaped is a Drive-shaped schema: a team whose membership is a
// userset, and two nestable kinds whose `viewer` inherits from their
// parent and unions with `editor` and `owner`. It is the smallest schema
// in which all four of design §8.2's composition forms can fire.
func driveShaped() []scenario.ResourceKind {
	container := func(name string) scenario.ResourceKind {
		return scenario.ResourceKind{
			Name:  name,
			Shape: scenario.ShapeColumnar,
			Relations: []scenario.Relation{
				{Name: "owner", Direct: true, Usersets: []string{"team#member", "role#assignee"}},
				{
					Name: "editor", Direct: true,
					Usersets:          []string{"team#member", "role#assignee"},
					InheritFromParent: []string{"editor"},
					Union:             []string{"owner"},
				},
				{
					Name: "viewer", Direct: true,
					Usersets:          []string{"team#member", "role#assignee"},
					InheritFromParent: []string{"viewer"},
					Union:             []string{"editor", "owner"},
				},
			},
			Actions: map[string]string{"read": "viewer", "write": "editor", "share": "owner"},
		}
	}
	return []scenario.ResourceKind{
		{
			Name:      "team",
			Relations: []scenario.Relation{{Name: "member", Direct: true}},
			Actions:   map[string]string{"read": "member"},
		},
		{
			Name:      "role",
			Relations: []scenario.Relation{{Name: "assignee", Direct: true, Usersets: []string{"team#member"}}},
			Actions:   map[string]string{"assume": "assignee"},
		},
		container("folder"),
		container("document"),
	}
}

func user(name string) scenario.PrincipalSpec {
	return scenario.PrincipalSpec{Name: name, Kind: iam.PrincipalKindUser, Role: "a principal"}
}

// TestEveryCompositionFormSurvivesTheTranslation is the test that makes
// the differential mean something. Each row below fires a different one of
// §8.2's four forms, and each is checked twice: against the reason the
// translation must report, and against the reference oracle's own answer.
//
// The second check is the differential in miniature and the first is what
// stops it passing vacuously. The reason mapping is the fiddly half —
// `iam` reports three reasons over a container closure and the corpus
// names four composition forms — and the row that pins it is `user:a write
// document:x`: no `editor` grant exists anywhere, the folder's `editor`
// unions with the `owner` grant written on it, and the answer is
// *inherited* and not *union*, because the union fired on the ancestor and
// inheritance is the outermost form. A consumer told `union` would go
// looking at the schema's relation definitions instead of at the grant on
// the folder.
func TestEveryCompositionFormSurvivesTheTranslation(t *testing.T) {
	t.Parallel()

	f := scenario.Fixture{
		Tenant:     "acme",
		Kinds:      driveShaped(),
		Principals: []scenario.PrincipalSpec{user("user:a"), user("user:b"), user("user:c"), user("user:d")},
		Groups:     []scenario.GroupSpec{{Name: "team:eng", Members: []string{"user:b"}}},
		Containment: []scenario.Edge{
			scenario.E("document:x", "folder:f"),
		},
		Tuples: []scenario.Tuple{
			scenario.T("folder:f", "owner", scenario.P("user:a")),
			scenario.T("folder:f", "viewer", scenario.US("team:eng", "member")),
			scenario.T("document:x", "viewer", scenario.P("user:c")),
		},
	}
	world := realize(t, f)
	if !world.Expressible() {
		t.Fatalf("this fixture should translate without loss, and it reported gaps: %v", world.Gaps())
	}

	cases := []struct {
		principal string
		action    string
		resource  string
		want      scenario.Decision
	}{
		{
			// Form 1, on the object itself.
			principal: "user:c", action: "read", resource: "document:x",
			want: scenario.Decision{
				Verdict: scenario.Allow, Reason: scenario.ReasonDirect,
				Because: "document:x#viewer@user:c",
			},
		},
		{
			// Form 2: the grant names a set the principal is in, and the
			// membership comes from the real registry.
			principal: "user:b", action: "read", resource: "folder:f",
			want: scenario.Decision{
				Verdict: scenario.Allow, Reason: scenario.ReasonUserset,
				Because: "folder:f#viewer@team:eng#member",
			},
		},
		{
			// Form 3: iam's own containment closure carries it down.
			principal: "user:b", action: "read", resource: "document:x",
			want: scenario.Decision{
				Verdict: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:f#viewer@team:eng#member",
			},
		},
		{
			// Form 4, on the object itself: `viewer` unions with `editor`,
			// which unions with the `owner` grant written here.
			principal: "user:a", action: "read", resource: "folder:f",
			want: scenario.Decision{
				Verdict: scenario.Allow, Reason: scenario.ReasonUnion,
				Because: "folder:f#owner@user:a",
			},
		},
		{
			// Form 3 over form 4, which is the row the reason mapping
			// turns on. See this test's doc comment.
			principal: "user:a", action: "write", resource: "document:x",
			want: scenario.Decision{
				Verdict: scenario.Allow, Reason: scenario.ReasonInherited,
				Because: "folder:f#owner@user:a",
			},
		},
		{
			// A share reaches nobody it was not written for, and a viewer
			// is not an editor.
			principal: "user:b", action: "write", resource: "document:x",
			want: scenario.Decision{Verdict: scenario.Deny, Reason: scenario.ReasonNoGrant},
		},
		{
			// A grant at the bottom does not reach upwards.
			principal: "user:c", action: "read", resource: "folder:f",
			want: scenario.Decision{Verdict: scenario.Deny, Reason: scenario.ReasonNoGrant},
		},
		{
			principal: "user:d", action: "read", resource: "document:x",
			want: scenario.Decision{Verdict: scenario.Deny, Reason: scenario.ReasonNoGrant},
		},
	}
	for _, tc := range cases {
		t.Run(tc.principal+"_"+tc.action+"_"+tc.resource, func(t *testing.T) {
			resource := scenario.R(tc.resource)
			got, err := world.Decide(t.Context(), tc.principal, tc.action, resource)
			if err != nil {
				t.Fatalf("RealWorld.Decide: %v", err)
			}
			if got != tc.want {
				t.Fatalf("the real module answered %s %s %s as %+v, want %+v. The reason is matched as well "+
					"as the verdict because the corpus's whole differential compares it",
					tc.principal, tc.action, tc.resource, got, tc.want)
			}
			oracle, err := scenario.Decide(f, tc.principal, tc.action, resource)
			if err != nil {
				t.Fatalf("the reference oracle could not answer: %v", err)
			}
			if got != oracle {
				t.Fatalf("the real module and the reference oracle disagree about %s %s %s: %+v against %+v",
					tc.principal, tc.action, tc.resource, got, oracle)
			}
		})
	}
}

// TestAKindNestedInsideItselfTranslates is an ordinary Drive hierarchy —
// a folder inside a folder, with a folder at the root — and it is here
// because it was once impossible.
//
// `iam.ContainerKind` declares one parent kind and refuses two as finding
// F3's DAG, and it refused a kind naming itself, so this shape had no
// declaration at all: design goal 4's own example, with nothing to
// register. The corpus found that by trying to run against the real
// module, and `ContainerKind.Nestable` closed it — recursion declared as
// a flag, because `Parents: ["tenant", "folder"]` on kind `folder` cannot
// be told apart from the two-parent declaration F3 refuses. D2 and D7 are
// both this shape; this test is the smallest version of them, and it
// replaces one that pinned a depth-suffixed workaround instead.
func TestAKindNestedInsideItselfTranslates(t *testing.T) {
	t.Parallel()

	f := scenario.Fixture{
		Tenant:     "acme",
		Kinds:      driveShaped(),
		Principals: []scenario.PrincipalSpec{user("user:a")},
		Containment: []scenario.Edge{
			scenario.E("folder:inner", "folder:outer"),
			scenario.E("document:deep", "folder:inner"),
		},
		Tuples: []scenario.Tuple{
			scenario.T("folder:outer", "viewer", scenario.P("user:a")),
		},
	}
	world := realize(t, f)

	got, err := world.Decide(t.Context(), "user:a", "read", scenario.R("document:deep"))
	if err != nil {
		t.Fatalf("RealWorld.Decide: %v", err)
	}
	want := scenario.Decision{
		Verdict: scenario.Allow, Reason: scenario.ReasonInherited,
		Because: "folder:outer#viewer@user:a",
	}
	if got != want {
		t.Fatalf("one grant two hops up a folder-in-folder hierarchy answered %+v, want %+v", got, want)
	}
}

// TestRealizeRefusesADAG: containment is a tree in `iam`, one parent per
// container set at creation. A fixture with two parents for one child has
// no shape here at all, and the refusal must be typed, because the harness
// distinguishes "this fixture does not reach the module" from "the module
// answered differently" and those are very different findings.
func TestRealizeRefusesADAG(t *testing.T) {
	t.Parallel()

	f := scenario.Fixture{
		Tenant:     "acme",
		Kinds:      driveShaped(),
		Principals: []scenario.PrincipalSpec{user("user:a")},
		Containment: []scenario.Edge{
			scenario.E("document:x", "folder:f"),
			scenario.E("document:x", "folder:g"),
		},
		Tuples: []scenario.Tuple{scenario.T("folder:f", "viewer", scenario.P("user:a"))},
	}
	reg, authorizer := newAuthority(t)
	env, err := scenario.Materialize(context.Background(), reg, f, iam.SystemClock{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	_, err = scenario.Realize(context.Background(), authorizer, env, f)
	if !errors.Is(err, scenario.ErrNotTranslatable) {
		t.Fatalf("Realize over a DAG error = %v, want it to wrap ErrNotTranslatable", err)
	}
	if !errors.Is(err, scenario.ErrNoDirectPath) {
		t.Fatalf("the refusal did not name the finding it is: %v", err)
	}
}

// TestANestedGroupMemberIsReportedAsAGap is D3's one unanswerable row at
// its smallest. A group's members are principals here and never other
// groups, and there is no role object with relations of its own for a
// userset to resolve through instead, so a team holding a role has no
// form.
//
// It must be reported as a Gap rather than as an error. A gap is how the
// harness decides that *this* table falls back to the oracle, and the
// distinction is load-bearing: the rest of the fixture translates
// perfectly, and a scenario silently differing on one row would be far
// worse than one that says which row and why.
func TestANestedGroupMemberIsReportedAsAGap(t *testing.T) {
	t.Parallel()

	f := scenario.Fixture{
		Tenant:     "acme",
		Kinds:      driveShaped(),
		Principals: []scenario.PrincipalSpec{user("user:a"), user("user:b")},
		Groups:     []scenario.GroupSpec{{Name: "team:eng", Members: []string{"user:b"}}},
		Containment: []scenario.Edge{
			scenario.E("role:reader", "folder:f"),
			scenario.E("document:x", "folder:f"),
		},
		Tuples: []scenario.Tuple{
			scenario.T("role:reader", "assignee", scenario.P("user:a")),
			scenario.T("role:reader", "assignee", scenario.US("team:eng", "member")),
			scenario.T("folder:f", "viewer", scenario.US("role:reader", "assignee")),
		},
	}
	world := realize(t, f)

	gaps := world.Gaps()
	if len(gaps) != 1 {
		t.Fatalf("want exactly one gap, got %v", gaps)
	}
	if gaps[0].What != "role:reader#assignee@team:eng#member" {
		t.Fatalf("the gap names %q, want the tuple that has no form", gaps[0].What)
	}
	if !strings.Contains(gaps[0].Why, "member that is itself a set") {
		t.Fatalf("the gap does not say which absence it runs into: %s", gaps[0].Why)
	}
	if world.Expressible() {
		t.Fatal("a world with a gap reported itself expressible, which would let a table run against the " +
			"real module on a fixture the real module never received in full")
	}

	// The principal assigned the role by name still works, which is why
	// the gap is one row of D3 and not the scenario.
	byName, err := world.Decide(t.Context(), "user:a", "read", scenario.R("document:x"))
	if err != nil {
		t.Fatalf("RealWorld.Decide: %v", err)
	}
	if byName.Verdict != scenario.Allow || byName.Reason != scenario.ReasonInherited {
		t.Fatalf("a role assigned to a principal by name answered %+v, want an inherited allow", byName)
	}
	throughTeam, err := world.Decide(t.Context(), "user:b", "read", scenario.R("document:x"))
	if err != nil {
		t.Fatalf("RealWorld.Decide: %v", err)
	}
	if throughTeam.Verdict != scenario.Deny {
		t.Fatalf("a team holding a role answered %+v. If this now allows, nested group membership has "+
			"arrived and D3 moves to live — see CapNestedGroupMember", throughTeam)
	}
}

// TestRealizeRefusesAPredicateDefinedEdge: a container's parent is set at
// creation, so a containment edge whose membership is a function of data a
// later write changes has nothing to be. That is U5, and the refusal is
// where the corpus and the module agree about it.
func TestRealizeRefusesAPredicateDefinedEdge(t *testing.T) {
	t.Parallel()

	f := scenario.Fixture{
		Tenant:     "acme",
		Kinds:      driveShaped(),
		Principals: []scenario.PrincipalSpec{user("user:a")},
		Containment: []scenario.Edge{{
			Child: scenario.R("document:x"), Parent: scenario.R("folder:f"),
			Kind: scenario.EdgePredicate, Predicate: "document is tagged finance",
		}},
		Tuples: []scenario.Tuple{scenario.T("folder:f", "viewer", scenario.P("user:a"))},
	}
	reg, authorizer := newAuthority(t)
	env, err := scenario.Materialize(context.Background(), reg, f, iam.SystemClock{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	_, err = scenario.Realize(context.Background(), authorizer, env, f)
	if !errors.Is(err, scenario.ErrNotTranslatable) {
		t.Fatalf("Realize over a predicate-defined edge error = %v, want it to wrap ErrNotTranslatable", err)
	}
}

// TestRealizeRefusesAKindLevelDAG: one parent kind per kind. A fixture
// where `document` sits inside a `folder` in one place and inside a `role`
// in another declares a DAG at the level of kinds even though every
// container still has exactly one parent, and that is the declaration
// `iam.ErrMultipleContainmentParents` exists to refuse.
//
// It is worth having its own test because it is the one refusal here that
// is a *refusal* rather than a limit: the closure a decision reads is
// keyed on the container, and F3's spike measured what keying it on the
// resource costs instead.
func TestRealizeRefusesAKindLevelDAG(t *testing.T) {
	t.Parallel()

	f := scenario.Fixture{
		Tenant:     "acme",
		Kinds:      driveShaped(),
		Principals: []scenario.PrincipalSpec{user("user:a")},
		Containment: []scenario.Edge{
			scenario.E("document:x", "folder:f"),
			scenario.E("document:y", "role:r"),
		},
		Tuples: []scenario.Tuple{scenario.T("folder:f", "viewer", scenario.P("user:a"))},
	}
	reg, authorizer := newAuthority(t)
	env, err := scenario.Materialize(context.Background(), reg, f, iam.SystemClock{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	_, err = scenario.Realize(context.Background(), authorizer, env, f)
	if !errors.Is(err, scenario.ErrNotTranslatable) {
		t.Fatalf("Realize over a kind-level DAG error = %v, want it to wrap ErrNotTranslatable", err)
	}
	if !strings.Contains(err.Error(), "two different kinds") {
		t.Fatalf("the refusal does not say what was wrong with the declaration: %v", err)
	}
}

// TestRealizeRefusesAKindThatIsBothRootAndContained is the one limit left
// in the kind declaration, and it is reported rather than worked around.
//
// `AllowsRoot` is "declares no parent", so a kind is either a root kind or
// a contained one. A fixture with a `document` inside a folder *and* a
// `document` at the root cannot be declared, and the containment is still
// a perfectly good tree — so this is not finding F3 and the refusal says
// so. No fixture in the corpus is this shape; if one ever is, it will fail
// here with a message that names the limit instead of surfacing as a
// confusing CreateContainer error.
func TestRealizeRefusesAKindThatIsBothRootAndContained(t *testing.T) {
	t.Parallel()

	f := scenario.Fixture{
		Tenant:     "acme",
		Kinds:      driveShaped(),
		Principals: []scenario.PrincipalSpec{user("user:a")},
		Containment: []scenario.Edge{
			scenario.E("document:x", "folder:f"),
		},
		Tuples: []scenario.Tuple{
			scenario.T("folder:f", "viewer", scenario.P("user:a")),
			// document:loose has no containment edge, so it is a root
			// document beside a contained one.
			scenario.T("document:loose", "viewer", scenario.P("user:a")),
		},
	}
	reg, authorizer := newAuthority(t)
	env, err := scenario.Materialize(context.Background(), reg, f, iam.SystemClock{})
	if err != nil {
		t.Fatalf("Materialize: %v", err)
	}
	_, err = scenario.Realize(context.Background(), authorizer, env, f)
	if !errors.Is(err, scenario.ErrNotTranslatable) {
		t.Fatalf("Realize error = %v, want it to wrap ErrNotTranslatable", err)
	}
	if !strings.Contains(err.Error(), "AllowsRoot") {
		t.Fatalf("the refusal does not name the rule it runs into: %v", err)
	}
}
