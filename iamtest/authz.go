package iamtest

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/laenenai/iam"
)

// Authority is the pair of ports an authorization decision needs, and the
// value RunAuthorizerSuite's factory returns.
//
// It is a pair rather than just the Authorizer, and that is the contract
// speaking rather than the test being convenient. The group side of a
// decision is the identity registry's membership — joined, not copied —
// so the property most worth testing is the composition: that
// deprovisioning a principal through the Registry stops the Authorizer
// matching grants written to that principal's groups *and* to the
// principal by name. A suite handed only the Authorizer could not write
// that test, and the failure it would miss is the one that leaks.
//
// Both values must be backed by the same store: the same pool, or an
// in-memory authorizer built over this very registry. A pair wired to two
// different stores will fail the first subtest that provisions a principal
// and then grants to it, which is the intended way to find that out.
type Authority struct {
	// Registry provisions principals and groups.
	Registry iam.Registry
	// Authorizer holds containers, grants and decisions.
	Authorizer iam.Authorizer
}

// suiteSchemaName is the schema the suite registers. It is this suite's
// own name rather than a consumer's, so running the suite against a
// deployment that already has CAS's or cogos's schema registered adds one
// rather than colliding with one.
const suiteSchemaName = "iamtest"

// The suite's containment tree: a three-level chain plus a second root, so
// that inheritance, non-inheritance across a sibling subtree, and a forest
// of two roots are all expressible.
const (
	kindRoot   = "iamtest-root"
	kindMiddle = "iamtest-middle"
	kindLeaf   = "iamtest-leaf"
)

// The suite's permissions. Two, because one cannot show that a grant of
// one permission does not confer the other.
const (
	permRead  iam.Permission = "iamtest.read"
	permWrite iam.Permission = "iamtest.write"
)

// suiteSchema is the declaration every subtest registers. It is a tree:
// each kind names at most one parent, which is the only shape this module
// accepts.
func suiteSchema() iam.Schema {
	return iam.Schema{
		Name:    suiteSchemaName,
		Version: 1,
		Kinds: []iam.ContainerKind{
			{Name: kindRoot},
			{Name: kindMiddle, Parents: []string{kindRoot}},
			{Name: kindLeaf, Parents: []string{kindMiddle}},
		},
		Permissions: []iam.Permission{permRead, permWrite},
	}
}

// RunAuthorizerSuite runs the contract every authz.Authorizer adapter must
// satisfy. newAuthority is called once per subtest, receiving that
// subtest's own *T, so an adapter that needs per-test setup and teardown
// (a fresh map, a scratch database, a pool to close) registers it with
// t.Cleanup inside newAuthority and gets fresh, isolated state for every
// subtest.
//
// This file is deliberately not named authz_test.go: it must be importable
// from another module's tests, because CHARTER.md makes "the suite runs
// green in the consumer's CI against the consumer's wiring" the adoption
// test. That only works for a regular, non-test-only source file.
//
// Nothing here inspects SQL, reads a table, or assumes a database. The
// properties that only exist against real Postgres — that the closure's
// size is a function of hierarchy depth, that a decision resolves on an
// index join, that an added permissive policy cannot widen the tenant
// predicate — belong in that adapter's own test file and are there.
//
// Subtests do not call t.Parallel: an adapter's factory may serialize on a
// shared resource, and a conformance suite that assumed otherwise would
// make a correct adapter look broken.
//
// Four of the subtests below are security invariants rather than
// behavioural ones, and every adapter is forced through all four:
// DeprovisioningDeniesOnBothArms, AnExpiredAgentRunDeniesOnBothArms,
// NothingIsAnExistenceOracle and CrossTenantReachIsRefused.
func RunAuthorizerSuite(t *testing.T, newAuthority func(t *testing.T) Authority) {
	t.Helper()

	// TwoContainmentParentsAreRefusedOutright is the reason this method
	// exists at all. Design §8.4 accepted a containment declaration
	// giving a resource two parents, and the consumer then silently got a
	// closure keyed on the resource rather than on the container —
	// 106,495,540 rows and 10.9 GB against 433,063 rows and 37 MB at the
	// budgeted scale, measured by finding F3's spike. Nothing enforced
	// the tree, and the tree is load-bearing.
	//
	// The assertion is on the sentinel *and* on the message, because a
	// refusal a caller cannot act on is only half of one: the caller that
	// hits this has to redesign its containment or reopen F3, and it
	// needs to be told which declaration and which parents.
	t.Run("TwoContainmentParentsAreRefusedOutright", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()

		twoParents := iam.Schema{
			Name:    "consumer-with-a-dag",
			Version: 1,
			Kinds: []iam.ContainerKind{
				{Name: "graph"},
				{Name: "episode", Parents: []string{"graph"}},
				{Name: "entity-set", Parents: []string{"graph"}},
				// The declaration F3 was about: a fact lives in an
				// episode *and* in an entity-set.
				{Name: "fact", Parents: []string{"episode", "entity-set"}},
			},
			Permissions: []iam.Permission{permRead},
		}

		err := a.Authorizer.RegisterSchema(ctx, twoParents)
		if !errors.Is(err, iam.ErrMultipleContainmentParents) {
			t.Fatalf("RegisterSchema with a two-parent kind returned %v, want ErrMultipleContainmentParents.\n"+
				"A schema that declares a DAG must be refused outright: design §9.2's closure is bounded by "+
				"hierarchy depth only under one parent per container, and accepting it silently is what finding "+
				"F3's spike found §8.4 doing", err)
		}
		msg := err.Error()
		for _, needle := range []string{"consumer-with-a-dag", "fact", "episode", "entity-set"} {
			if !strings.Contains(msg, needle) {
				t.Errorf("the refusal does not name %q: %s\n"+
					"It must name the declaration and both parents, because the caller has to change a data "+
					"model and cannot do that from a sentinel alone", needle, msg)
			}
		}

		// And the refusal must be total: nothing from the schema is
		// registered, so a container of one of its kinds still fails.
		_, err = a.Authorizer.CreateContainer(ctx, iam.ContainerSpec{
			TenantID: newTenant(),
			Kind:     "graph",
		})
		if !errors.Is(err, iam.ErrSchemaNotRegistered) {
			t.Fatalf("after a refused schema, CreateContainer(kind=graph) returned %v, want ErrSchemaNotRegistered.\n"+
				"A partially registered schema would be worse than a refused one: the kinds that happened to be "+
				"valid would work and the consumer would discover the rest later", err)
		}
	})

	// AnUnregisteredKindOrPermissionIsRefused: fail-closed on the way in.
	// A misspelled permission is a grant that silently never fires, and
	// finding it at write time costs one error where finding it at read
	// time costs an outage — or, for a revocation that never applied, a
	// disclosure.
	t.Run("AnUnregisteredKindOrPermissionIsRefused", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		if _, err := a.Authorizer.CreateContainer(ctx, iam.ContainerSpec{TenantID: tenant, Kind: "not-a-kind"}); !errors.Is(err, iam.ErrSchemaNotRegistered) {
			t.Fatalf("CreateContainer with an undeclared kind returned %v, want ErrSchemaNotRegistered", err)
		}

		root := mustContainer(t, a, tenant, kindRoot, "")
		anne := mustPrincipal(t, a, tenant, "anne")

		err := mustGrantErr(t, a, iam.GrantSpec{
			TenantID:   tenant,
			Container:  root.ID,
			Permission: "iamtest.raed",
			Subject:    iam.PrincipalSubject(anne),
		})
		if !errors.Is(err, iam.ErrSchemaNotRegistered) {
			t.Fatalf("Grant with an undeclared permission returned %v, want ErrSchemaNotRegistered.\n"+
				"A grant whose permission is misspelled is a grant that never fires, and it must fail where it "+
				"is written rather than where it is read", err)
		}
	})

	// ContainmentIsATreeAndAncestorsReadBackNearestFirst pins the closure's
	// shape: the container itself at depth 0, then outwards. The reflexive
	// row is part of the contract and not an implementation detail,
	// because it is what lets a decision be one join instead of a union of
	// two.
	t.Run("ContainmentIsATreeAndAncestorsReadBackNearestFirst", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		root := mustContainer(t, a, tenant, kindRoot, "")
		middle := mustContainer(t, a, tenant, kindMiddle, root.ID)
		leaf := mustContainer(t, a, tenant, kindLeaf, middle.ID)

		if !root.IsRoot() {
			t.Errorf("the root container reports a parent of %q", root.Parent)
		}
		if middle.Parent != root.ID || leaf.Parent != middle.ID {
			t.Fatalf("the chain did not form: middle.Parent=%q root=%q, leaf.Parent=%q middle=%q", middle.Parent, root.ID, leaf.Parent, middle.ID)
		}

		got, err := a.Authorizer.Ancestors(ctx, tenant, leaf.ID)
		if err != nil {
			t.Fatalf("Ancestors(leaf): %v", err)
		}
		want := []iam.ContainerID{leaf.ID, middle.ID, root.ID}
		if !slices.Equal(got, want) {
			t.Fatalf("Ancestors(leaf) = %v, want %v (itself at depth 0, then outwards to the root)", got, want)
		}

		rootAncestors, err := a.Authorizer.Ancestors(ctx, tenant, root.ID)
		if err != nil {
			t.Fatalf("Ancestors(root): %v", err)
		}
		if !slices.Equal(rootAncestors, []iam.ContainerID{root.ID}) {
			t.Fatalf("Ancestors(root) = %v, want just the root itself: the reflexive row is part of the closure", rootAncestors)
		}

		// A kind declared inside another cannot be a root, and a root kind
		// cannot be placed inside a container. Both are the declared tree
		// being enforced on instances rather than only on declarations.
		if _, err := a.Authorizer.CreateContainer(ctx, iam.ContainerSpec{TenantID: tenant, Kind: kindLeaf}); !errors.Is(err, iam.ErrInvalidContainer) {
			t.Errorf("creating a leaf with no parent returned %v, want ErrInvalidContainer", err)
		}
		if _, err := a.Authorizer.CreateContainer(ctx, iam.ContainerSpec{TenantID: tenant, Kind: kindRoot, Parent: root.ID}); !errors.Is(err, iam.ErrInvalidContainer) {
			t.Errorf("creating a root kind inside a container returned %v, want ErrInvalidContainer", err)
		}
		// And a leaf cannot be placed directly in the root, because the
		// declaration says it lives in a middle.
		if _, err := a.Authorizer.CreateContainer(ctx, iam.ContainerSpec{TenantID: tenant, Kind: kindLeaf, Parent: root.ID}); !errors.Is(err, iam.ErrInvalidContainer) {
			t.Errorf("creating a leaf inside a root returned %v, want ErrInvalidContainer: the declared edge is leaf-in-middle", err)
		}
	})

	// OneGrantOnAContainerReachesEverythingInside is design §8.2's third
	// composition form, and the whole economic argument for this module:
	// one row per share rather than one per resource. The sibling subtree
	// is in the same test on purpose — inheritance that also reached
	// sideways would be a disclosure, not a convenience.
	t.Run("OneGrantOnAContainerReachesEverythingInside", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		root := mustContainer(t, a, tenant, kindRoot, "")
		shared := mustContainer(t, a, tenant, kindMiddle, root.ID)
		sharedLeaf := mustContainer(t, a, tenant, kindLeaf, shared.ID)
		sibling := mustContainer(t, a, tenant, kindMiddle, root.ID)
		siblingLeaf := mustContainer(t, a, tenant, kindLeaf, sibling.ID)

		anne := mustPrincipal(t, a, tenant, "anne")
		mustGrant(t, a, iam.GrantSpec{
			TenantID:   tenant,
			Container:  shared.ID,
			Permission: permRead,
			Subject:    iam.PrincipalSubject(anne),
		})

		assertDecision(t, a, iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: shared.ID},
			true, iam.ReasonDirect, 0, "a grant on the container itself is depth 0 and reports the direct form")
		assertDecision(t, a, iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: sharedLeaf.ID},
			true, iam.ReasonInherited, 1, "one hop down, through the containment closure, with no second grant written")

		assertDenied(t, a, iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: sibling.ID},
			"a sibling subtree is not below the grant: inheritance that reached sideways would be a disclosure")
		assertDenied(t, a, iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: siblingLeaf.ID},
			"nor is anything inside that sibling")
		assertDenied(t, a, iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: root.ID},
			"nor the ancestor above the grant: containment inherits down, never up. Upward visibility is "+
				"design §8.2's visible_below and is deliberately not built")
		assertDenied(t, a, iam.Request{TenantID: tenant, Principal: anne, Permission: permWrite, Container: shared.ID},
			"a grant of read is not a grant of write: there is no union of relations here")

		// The grant is one row, and it is on the container.
		grants, err := a.Authorizer.GrantsOn(ctx, tenant, shared.ID)
		if err != nil {
			t.Fatalf("GrantsOn(shared): %v", err)
		}
		if len(grants) != 1 {
			t.Fatalf("GrantsOn(shared) returned %d grants, want 1", len(grants))
		}
		below, err := a.Authorizer.GrantsOn(ctx, tenant, sharedLeaf.ID)
		if err != nil {
			t.Fatalf("GrantsOn(sharedLeaf): %v", err)
		}
		if len(below) != 0 {
			t.Fatalf("GrantsOn(sharedLeaf) returned %d grants, want 0: sharing a container must write nothing "+
				"on what it contains, which is the whole closure budget (anti-goal A2)", len(below))
		}
	})

	// AGroupGrantFollowsMembershipWithNoGrantRewritten is design §8.2's
	// userset form earning its keep: the grant names the group, so
	// changing the group is one membership row and the grant is untouched.
	t.Run("AGroupGrantFollowsMembershipWithNoGrantRewritten", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		root := mustContainer(t, a, tenant, kindRoot, "")
		leaf := mustContainer(t, a, tenant, kindLeaf, mustContainer(t, a, tenant, kindMiddle, root.ID).ID)

		team, err := a.Registry.EnsureGroup(ctx, tenant, "iamtest-team")
		if err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
		anne := mustPrincipal(t, a, tenant, "anne")
		lena := mustPrincipal(t, a, tenant, "lena")
		if err := a.Registry.AddGroupMember(ctx, team.ID, anne); err != nil {
			t.Fatalf("AddGroupMember(anne): %v", err)
		}

		revAfterGrant := mustGrant(t, a, iam.GrantSpec{
			TenantID:   tenant,
			Container:  root.ID,
			Permission: permRead,
			Subject:    iam.GroupSubject(team.ID),
		})

		assertDecision(t, a, iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: root.ID},
			true, iam.ReasonUserset, 0, "a group grant on the container itself reports the userset form")
		assertDecision(t, a, iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: leaf.ID},
			true, iam.ReasonInherited, 2, "inheritance outranks the userset in the reason, because the row to go "+
				"and look at is two hops up")
		assertDenied(t, a, iam.Request{TenantID: tenant, Principal: lena, Permission: permRead, Container: leaf.ID},
			"lena is not in the team yet")

		if err := a.Registry.AddGroupMember(ctx, team.ID, lena); err != nil {
			t.Fatalf("AddGroupMember(lena): %v", err)
		}
		assertDecision(t, a, iam.Request{TenantID: tenant, Principal: lena, Permission: permRead, Container: leaf.ID},
			true, iam.ReasonInherited, 2, "a membership change takes effect with no grant rewritten")

		// And nothing was written on the authorization side to make it
		// happen: the revision has not moved, because adding a member is
		// not a closure-affecting write here — it is the registry's.
		rev, err := a.Authorizer.Revision(ctx, tenant)
		if err != nil {
			t.Fatalf("Revision: %v", err)
		}
		if rev != revAfterGrant {
			t.Fatalf("the revision moved from %d to %d across a membership change. A group grant names the group, "+
				"so changing the group must touch no grant at all (design §8.2 form 2, anti-goal A2's closure budget)",
				revAfterGrant, rev)
		}
		grants, err := a.Authorizer.GrantsOn(ctx, tenant, root.ID)
		if err != nil {
			t.Fatalf("GrantsOn: %v", err)
		}
		if len(grants) != 1 {
			t.Fatalf("GrantsOn(root) returned %d grants after a membership change, want 1", len(grants))
		}
	})

	// ADirectGrantOutranksAGroupGrant is about the *explanation* rather
	// than the verdict. Both would allow; a consumer debugging a decision
	// needs to be sent to the row somebody wrote deliberately.
	t.Run("ADirectGrantOutranksAGroupGrant", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		root := mustContainer(t, a, tenant, kindRoot, "")
		team, err := a.Registry.EnsureGroup(ctx, tenant, "iamtest-team")
		if err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
		anne := mustPrincipal(t, a, tenant, "anne")
		if err := a.Registry.AddGroupMember(ctx, team.ID, anne); err != nil {
			t.Fatalf("AddGroupMember: %v", err)
		}
		mustGrant(t, a, iam.GrantSpec{TenantID: tenant, Container: root.ID, Permission: permRead, Subject: iam.GroupSubject(team.ID)})
		mustGrant(t, a, iam.GrantSpec{TenantID: tenant, Container: root.ID, Permission: permRead, Subject: iam.PrincipalSubject(anne)})

		d := assertDecision(t, a, iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: root.ID},
			true, iam.ReasonDirect, 0, "a grant written to the principal by name outranks one reaching it through a group")
		if p, ok := d.Via.Subject.Principal(); !ok || p != anne {
			t.Fatalf("the allow was attributed to %s, want the direct grant to anne. An authorization answer a "+
				"consumer cannot explain is an answer it cannot audit", d.Via)
		}
	})

	// DeprovisioningDeniesOnBothArms is a security invariant, and the
	// "both arms" is the whole point. Deprovisioning that stopped group
	// grants and not grants written to the principal by name would pass a
	// careless test suite and then leak on exactly the grants somebody
	// wrote deliberately.
	t.Run("DeprovisioningDeniesOnBothArms", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		root := mustContainer(t, a, tenant, kindRoot, "")
		team, err := a.Registry.EnsureGroup(ctx, tenant, "iamtest-team")
		if err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
		viaGroup := mustPrincipal(t, a, tenant, "via-group")
		viaName := mustPrincipal(t, a, tenant, "via-name")
		if err := a.Registry.AddGroupMember(ctx, team.ID, viaGroup); err != nil {
			t.Fatalf("AddGroupMember: %v", err)
		}
		mustGrant(t, a, iam.GrantSpec{TenantID: tenant, Container: root.ID, Permission: permRead, Subject: iam.GroupSubject(team.ID)})
		mustGrant(t, a, iam.GrantSpec{TenantID: tenant, Container: root.ID, Permission: permRead, Subject: iam.PrincipalSubject(viaName)})

		assertAllowed(t, a, iam.Request{TenantID: tenant, Principal: viaGroup, Permission: permRead, Container: root.ID}, "before deprovisioning, through the group")
		assertAllowed(t, a, iam.Request{TenantID: tenant, Principal: viaName, Permission: permRead, Container: root.ID}, "before deprovisioning, by name")

		if err := a.Registry.Deprovision(ctx, viaGroup); err != nil {
			t.Fatalf("Deprovision(viaGroup): %v", err)
		}
		if err := a.Registry.Deprovision(ctx, viaName); err != nil {
			t.Fatalf("Deprovision(viaName): %v", err)
		}

		assertDenied(t, a, iam.Request{TenantID: tenant, Principal: viaGroup, Permission: permRead, Container: root.ID},
			"a deprovisioned principal must stop matching a grant written to its group, immediately and with no "+
				"membership row deleted (design §8.1, §9.3)")
		assertDenied(t, a, iam.Request{TenantID: tenant, Principal: viaName, Permission: permRead, Container: root.ID},
			"and must stop matching a grant written to it by name. An implementation that filtered only the group "+
				"arm would look correct in every group-based test and leak on every personal grant")

		// The grant rows are untouched: deprovisioning is an identity
		// fact, not a rewrite of the authorization layer, so audit can
		// still explain what the principal had access to.
		grants, err := a.Authorizer.GrantsOn(ctx, tenant, root.ID)
		if err != nil {
			t.Fatalf("GrantsOn: %v", err)
		}
		if len(grants) != 2 {
			t.Fatalf("GrantsOn(root) returned %d grants after two deprovisionings, want 2 — deprovisioning must "+
				"deny without deleting history", len(grants))
		}
	})

	// AnExpiredAgentRunDeniesOnBothArms is the same invariant for the
	// other liveness condition. An expired run is unusable from its
	// deadline, so a slow collector delays cleanup and never access.
	t.Run("AnExpiredAgentRunDeniesOnBothArms", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		root := mustContainer(t, a, tenant, kindRoot, "")
		parent := mustPrincipal(t, a, tenant, "parent")
		team, err := a.Registry.EnsureGroup(ctx, tenant, "iamtest-team")
		if err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}

		// A TTL of one nanosecond is already past by the time anything
		// reads it, and it needs no sleep and no clock injection: both
		// adapters evaluate liveness at their own instant, which is later.
		run, err := a.Registry.DelegateAgentRun(ctx, parent, iam.AgentRunSpec{TTL: time.Nanosecond, DisplayName: "expired run"})
		if err != nil {
			t.Fatalf("DelegateAgentRun: %v", err)
		}
		if err := a.Registry.AddGroupMember(ctx, team.ID, run.ID); err != nil {
			t.Fatalf("AddGroupMember(run): %v", err)
		}
		mustGrant(t, a, iam.GrantSpec{TenantID: tenant, Container: root.ID, Permission: permRead, Subject: iam.GroupSubject(team.ID)})
		mustGrant(t, a, iam.GrantSpec{TenantID: tenant, Container: root.ID, Permission: permRead, Subject: iam.PrincipalSubject(run.ID)})

		assertDenied(t, a, iam.Request{TenantID: tenant, Principal: run.ID, Permission: permRead, Container: root.ID},
			"an expired agent run must match neither a group grant nor a grant written to it by name")
	})

	// NothingIsAnExistenceOracle: an unknown container, an unknown
	// principal, an undeclared permission and a principal holding nothing
	// are one answer. A decision that distinguished them would tell a
	// caller which ids exist, over an id space it is not supposed to be
	// able to enumerate — and it would also train callers to treat a
	// refusal as an outage.
	t.Run("NothingIsAnExistenceOracle", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		root := mustContainer(t, a, tenant, kindRoot, "")
		anne := mustPrincipal(t, a, tenant, "anne")
		ghostContainer := iam.NewContainerID(iam.SystemClock{})
		ghostPrincipal := iam.NewPrincipalID(iam.SystemClock{})

		cases := []struct {
			name string
			req  iam.Request
		}{
			{"a container that does not exist", iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: ghostContainer}},
			{"a principal that does not exist", iam.Request{TenantID: tenant, Principal: ghostPrincipal, Permission: permRead, Container: root.ID}},
			{"a permission no schema declares", iam.Request{TenantID: tenant, Principal: anne, Permission: "iamtest.nonesuch", Container: root.ID}},
			{"a principal that simply holds nothing", iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: root.ID}},
		}
		for _, c := range cases {
			d, err := a.Authorizer.Decide(ctx, c.req)
			if err != nil {
				t.Fatalf("Decide for %s returned an error: %v\nAll four of these must be the same answer — a "+
					"Decision whose Allowed is false — or the error itself is the oracle", c.name, err)
			}
			if d.Allowed {
				t.Fatalf("Decide for %s allowed", c.name)
			}
			if d.Reason != iam.ReasonNoGrant {
				t.Errorf("Decide for %s denied with reason %q, want %q: there is one deny in this layer and it is "+
					"a grant nobody wrote", c.name, d.Reason, iam.ReasonNoGrant)
			}
			if !d.Via.IsZero() {
				t.Errorf("Decide for %s denied but attributed the denial to %s", c.name, d.Via)
			}
		}

		// A malformed request, by contrast, *is* an error: it is a defect
		// in the caller and not an answer about the world.
		if _, err := a.Authorizer.Decide(ctx, iam.Request{TenantID: tenant, Permission: permRead, Container: root.ID}); !errors.Is(err, iam.ErrInvalidRequest) {
			t.Errorf("Decide with no principal returned %v, want ErrInvalidRequest", err)
		}
	})

	// CrossTenantReachIsRefused. No decision reads another tenant's rules
	// (design §3), and the refusals are shaped so that "another tenant's"
	// and "does not exist" are the same answer.
	t.Run("CrossTenantReachIsRefused", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		mustRegister(t, a, suiteSchema())
		tenantA, tenantB := newTenant(), newTenant()

		rootA := mustContainer(t, a, tenantA, kindRoot, "")
		anneA := mustPrincipal(t, a, tenantA, "anne-a")
		anneB := mustPrincipal(t, a, tenantB, "anne-b")
		mustGrant(t, a, iam.GrantSpec{TenantID: tenantA, Container: rootA.ID, Permission: permRead, Subject: iam.PrincipalSubject(anneA)})

		if _, err := a.Authorizer.Container(ctx, tenantB, rootA.ID); !errors.Is(err, iam.ErrNotFound) {
			t.Errorf("Container(tenantB, rootA) returned %v, want ErrNotFound: another tenant's container is not "+
				"found, because telling the two apart is a cross-tenant existence oracle", err)
		}
		if _, err := a.Authorizer.CreateContainer(ctx, iam.ContainerSpec{TenantID: tenantB, Kind: kindMiddle, Parent: rootA.ID}); !errors.Is(err, iam.ErrNotFound) {
			t.Errorf("creating a container in tenantB inside tenantA's root returned %v, want ErrNotFound: a "+
				"containment edge that crossed a tenant would carry a grant across the isolation boundary", err)
		}
		if err := mustGrantErr(t, a, iam.GrantSpec{TenantID: tenantA, Container: rootA.ID, Permission: permRead, Subject: iam.PrincipalSubject(anneB)}); !errors.Is(err, iam.ErrNotFound) {
			t.Errorf("granting tenantA's container to tenantB's principal returned %v, want ErrNotFound", err)
		}
		assertDenied(t, a, iam.Request{TenantID: tenantB, Principal: anneA, Permission: permRead, Container: rootA.ID},
			"a decision taken in tenantB must not find tenantA's grant")
	})

	// GrantAndRevokeAreIdempotentAndOnlyRealChangesAreLogged. A log entry
	// for a write that changed nothing would make a projection do work for
	// no reason and make the log's length a function of retries — and a
	// retry is the normal case, not the exception.
	t.Run("GrantAndRevokeAreIdempotentAndOnlyRealChangesAreLogged", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		root := mustContainer(t, a, tenant, kindRoot, "")
		anne := mustPrincipal(t, a, tenant, "anne")
		spec := iam.GrantSpec{TenantID: tenant, Container: root.ID, Permission: permRead, Subject: iam.PrincipalSubject(anne)}

		first := mustGrant(t, a, spec)
		second := mustGrant(t, a, spec)
		if second != first {
			t.Fatalf("granting the same grant twice moved the revision from %d to %d; it must be idempotent and "+
				"must not append to the log", first, second)
		}

		firstRevoke, err := a.Authorizer.Revoke(ctx, spec)
		if err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		if firstRevoke <= first {
			t.Fatalf("Revoke returned revision %d, want greater than the grant's %d: a revocation is a real change", firstRevoke, first)
		}
		assertDenied(t, a, iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: root.ID}, "after revocation")

		secondRevoke, err := a.Authorizer.Revoke(ctx, spec)
		if err != nil {
			t.Fatalf("revoking an absent grant returned %v, want nil: it is not an error", err)
		}
		if secondRevoke != firstRevoke {
			t.Fatalf("revoking an absent grant moved the revision from %d to %d", firstRevoke, secondRevoke)
		}
	})

	// TheChangeLogIsGaplessAndResumable is the guarantee a projection
	// needs in order to be restartable: a reader that stores the highest
	// revision it has processed and resumes from it sees every subsequent
	// change exactly once. Everything else about the log is bookkeeping;
	// this is the contract.
	t.Run("TheChangeLogIsGaplessAndResumable", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		root := mustContainer(t, a, tenant, kindRoot, "")
		middle := mustContainer(t, a, tenant, kindMiddle, root.ID)
		anne := mustPrincipal(t, a, tenant, "anne")
		team, err := a.Registry.EnsureGroup(ctx, tenant, "iamtest-team")
		if err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}

		grantSpec := iam.GrantSpec{TenantID: tenant, Container: middle.ID, Permission: permRead, Subject: iam.PrincipalSubject(anne)}
		groupSpec := iam.GrantSpec{TenantID: tenant, Container: root.ID, Permission: permWrite, Subject: iam.GroupSubject(team.ID)}
		mustGrant(t, a, grantSpec)
		mustGrant(t, a, groupSpec)
		if _, err := a.Authorizer.Revoke(ctx, grantSpec); err != nil {
			t.Fatalf("Revoke: %v", err)
		}

		head, err := a.Authorizer.Revision(ctx, tenant)
		if err != nil {
			t.Fatalf("Revision: %v", err)
		}
		// Two containers, two grants, one revocation.
		if head != 5 {
			t.Fatalf("the tenant's revision is %d after five closure-affecting writes, want 5: the revision is "+
				"gapless, so it is exactly the number of logged changes", head)
		}

		all, err := a.Authorizer.Changes(ctx, tenant, 0, 0)
		if err != nil {
			t.Fatalf("Changes(from 0): %v", err)
		}
		if len(all) != 5 {
			t.Fatalf("Changes(from 0) returned %d entries, want 5", len(all))
		}
		for i, c := range all {
			if want := iam.Revision(i + 1); c.Revision != want {
				t.Fatalf("entry %d has revision %d, want %d: revisions must be gapless and in order, or a cursor "+
					"stored at N skips what was still in flight below it — which is a dropped revocation, and a "+
					"dropped revocation is a disclosure", i, c.Revision, want)
			}
			if c.TenantID != tenant {
				t.Errorf("entry %d belongs to tenant %q, want %q", i, c.TenantID, tenant)
			}
			if !c.Kind.Valid() {
				t.Errorf("entry %d has kind %q, which is not one of the three", i, c.Kind)
			}
		}
		if all[0].Kind != iam.ChangeContainerCreated || all[2].Kind != iam.ChangeGrantWritten || all[4].Kind != iam.ChangeGrantRevoked {
			t.Errorf("the log does not describe what happened: got kinds %q, %q, %q for the first container, the "+
				"first grant and the revocation", all[0].Kind, all[2].Kind, all[4].Kind)
		}
		// A revocation is logged as its own kind rather than as an absence,
		// because design §9.3 requires a revocation to propagate on a
		// different path from a grant: a projection that misses a grant is
		// an outage and one that misses a revocation is a disclosure.
		if all[4].Permission != permRead {
			t.Errorf("the revocation entry does not say what was revoked: permission %q", all[4].Permission)
		}

		// Resuming from every possible cursor sees each change exactly
		// once, which is the property stated as an assertion rather than
		// as a comment.
		var replayed []iam.Revision
		cursor := iam.Revision(0)
		for {
			page, err := a.Authorizer.Changes(ctx, tenant, cursor, 2)
			if err != nil {
				t.Fatalf("Changes(from %d): %v", cursor, err)
			}
			if len(page) == 0 {
				break
			}
			for _, c := range page {
				if c.Revision <= cursor {
					t.Fatalf("resuming from cursor %d returned revision %d, which the reader had already "+
						"processed: a cursor that re-delivers is a projection that double-applies", cursor, c.Revision)
				}
				replayed = append(replayed, c.Revision)
				cursor = c.Revision
			}
		}
		want := []iam.Revision{1, 2, 3, 4, 5}
		if !slices.Equal(replayed, want) {
			t.Fatalf("replaying the log two entries at a time saw %v, want %v exactly once each", replayed, want)
		}

		// The revision is per tenant: another tenant's log is its own, and
		// starts at zero.
		other := newTenant()
		otherHead, err := a.Authorizer.Revision(ctx, other)
		if err != nil {
			t.Fatalf("Revision(other tenant): %v", err)
		}
		if otherHead != 0 {
			t.Fatalf("a tenant with no authorization writes has revision %d, want 0", otherHead)
		}
	})

	// EveryDecisionCarriesTheRevisionItWasComputedAgainst. Nothing reads it
	// yet. It is in the contract now because a Decision that grew the field
	// later would be a breaking change at every call site, and the
	// deployment that needs it — `iam` as a separate store, with the
	// consumer projecting locally — cannot tell design §9.3's bounded lag
	// from §16.5's divergence without it.
	t.Run("EveryDecisionCarriesTheRevisionItWasComputedAgainst", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		root := mustContainer(t, a, tenant, kindRoot, "")
		anne := mustPrincipal(t, a, tenant, "anne")

		req := iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: root.ID}
		before, err := a.Authorizer.Decide(ctx, req)
		if err != nil {
			t.Fatalf("Decide: %v", err)
		}
		head, err := a.Authorizer.Revision(ctx, tenant)
		if err != nil {
			t.Fatalf("Revision: %v", err)
		}
		if before.Revision != head {
			t.Fatalf("a denial carries revision %d while the tenant's head is %d. A deny has to carry one too: "+
				"\"denied\" and \"cannot tell you what state that was computed against\" must not be the same result",
				before.Revision, head)
		}

		granted := mustGrant(t, a, iam.GrantSpec{TenantID: tenant, Container: root.ID, Permission: permRead, Subject: iam.PrincipalSubject(anne)})
		after, err := a.Authorizer.Decide(ctx, req)
		if err != nil {
			t.Fatalf("Decide after the grant: %v", err)
		}
		if !after.Allowed {
			t.Fatal("the grant did not take effect")
		}
		if after.Revision != granted {
			t.Fatalf("the allow carries revision %d, want the grant's %d", after.Revision, granted)
		}
		if after.Revision <= before.Revision {
			t.Fatalf("the revision did not advance across a grant: %d then %d. It has to be monotonic, or it "+
				"cannot order anything", before.Revision, after.Revision)
		}
	})

	// StoredInstantsRoundTripAtMicrosecondPrecision is a convention this
	// project hit twice independently, on the same day, in two other
	// modules: Postgres timestamptz holds microseconds, so a time.Time
	// carrying nanoseconds compares equal to itself in memory and unequal
	// through the database. In `audit` that would have reported every
	// persisted entry as tampered; in `meter` it would have made a
	// conformance suite pass for the wrong reason.
	//
	// It is asserted here rather than left to the Postgres adapter because
	// the in-memory adapter is the one that *can* get it wrong invisibly:
	// it has no database to truncate for it, so an adapter that skipped
	// canonicalization would round-trip nanoseconds happily and then
	// disagree with its Postgres sibling about whether two instants are
	// the same instant.
	t.Run("StoredInstantsRoundTripAtMicrosecondPrecision", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())

		created := mustContainer(t, a, tenant, kindRoot, "")
		readBack, err := a.Authorizer.Container(ctx, tenant, created.ID)
		if err != nil {
			t.Fatalf("Container: %v", err)
		}
		assertCanonicalInstant(t, created.CreatedAt, "the CreatedAt CreateContainer returned")
		assertCanonicalInstant(t, readBack.CreatedAt, "the CreatedAt Container read back")
		if !created.CreatedAt.Equal(readBack.CreatedAt) {
			t.Fatalf("a container's CreatedAt changed on the way through the store: %v then %v.\n"+
				"Both must be UTC at microsecond precision, or two adapters disagree about whether two instants "+
				"are the same instant", created.CreatedAt, readBack.CreatedAt)
		}

		anne := mustPrincipal(t, a, tenant, "anne")
		mustGrant(t, a, iam.GrantSpec{
			TenantID: tenant, Container: created.ID, Permission: permRead, Subject: iam.PrincipalSubject(anne),
		})
		grants, err := a.Authorizer.GrantsOn(ctx, tenant, created.ID)
		if err != nil {
			t.Fatalf("GrantsOn: %v", err)
		}
		if len(grants) != 1 {
			t.Fatalf("GrantsOn returned %d grants, want 1", len(grants))
		}
		assertCanonicalInstant(t, grants[0].GrantedAt, "the GrantedAt GrantsOn returned")

		// And the same grant reached through a decision, because Via is a
		// second path to the same row and a second chance to lose
		// precision.
		d := assertDecision(t, a, iam.Request{TenantID: tenant, Principal: anne, Permission: permRead, Container: created.ID},
			true, iam.ReasonDirect, 0, "the grant just written")
		assertCanonicalInstant(t, d.Via.GrantedAt, "the GrantedAt Decide attributed the allow to")
		if !grants[0].GrantedAt.Equal(d.Via.GrantedAt) {
			t.Fatalf("one grant has two instants depending on how it is read: %v from GrantsOn, %v from Decide",
				grants[0].GrantedAt, d.Via.GrantedAt)
		}

		// A logged change carries one too, and it is for people rather
		// than for ordering — the revision orders the log — but a
		// nanosecond in it would still disagree across adapters.
		changes, err := a.Authorizer.Changes(ctx, tenant, 0, 0)
		if err != nil {
			t.Fatalf("Changes: %v", err)
		}
		if len(changes) == 0 {
			t.Fatal("the log is empty after a container and a grant")
		}
		for i, c := range changes {
			assertCanonicalInstant(t, c.RecordedAt, fmt.Sprintf("change %d's RecordedAt", i))
		}
	})

	// TheResidualIsStructuredAndFailsClosed. The residual is the surface a
	// consumer's row-level-security policy is built from, so two things
	// about it are contractual: it is a typed expression rather than text,
	// and a request it cannot satisfy yields a node that matches nothing
	// rather than an error.
	t.Run("TheResidualIsStructuredAndFailsClosed", func(t *testing.T) {
		a := newAuthority(t)
		ctx := context.Background()
		tenant := newTenant()
		mustRegister(t, a, suiteSchema())
		anne := mustPrincipal(t, a, tenant, "anne")

		req := iam.FilterRequest{
			TenantID:   tenant,
			Principal:  iam.NamedPrincipal(anne),
			Permission: permRead,
			Key:        iam.Key{Qualifier: "q", Column: "graph_id"},
			TenantKey:  iam.Key{Qualifier: "q", Column: "tenant_id"},
		}
		residual, err := a.Authorizer.Filter(ctx, req)
		if err != nil {
			t.Fatalf("Filter: %v", err)
		}
		if err := residual.Validate(); err != nil {
			t.Fatalf("the residual this module produced is not well formed: %v", err)
		}
		if residual.DeniesEverything() {
			t.Fatal("Filter for a declared permission returned a residual that matches nothing")
		}
		and, ok := residual.Expr.(iam.And)
		if !ok {
			t.Fatalf("Filter returned a %T, want an And of the tenant term and the authorization term", residual.Expr)
		}
		if len(and.Terms) != 2 {
			t.Fatalf("the conjunction has %d terms, want 2", len(and.Terms))
		}
		if _, ok := and.Terms[0].(iam.TenantIs); !ok {
			t.Errorf("the first term is a %T, want TenantIs", and.Terms[0])
		}
		permits, ok := and.Terms[1].(iam.ContainerPermits)
		if !ok {
			t.Fatalf("the second term is a %T, want ContainerPermits", and.Terms[1])
		}
		if permits.Permission != permRead {
			t.Errorf("the authorization term names permission %q, want %q", permits.Permission, permRead)
		}
		if p, named := permits.Principal.Named(); !named || p != anne {
			t.Errorf("the authorization term names %s, want anne", permits.Principal)
		}

		// A permission no schema declares is None and not an error: the
		// failure mode a consumer's policy must have is zero rows, because
		// an error breaks the statement instead of filtering it and
		// distinguishes "may not" from "nothing there".
		undeclared, err := a.Authorizer.Filter(ctx, iam.FilterRequest{
			TenantID:   tenant,
			Principal:  iam.NamedPrincipal(anne),
			Permission: "iamtest.nonesuch",
			Key:        iam.Key{Column: "graph_id"},
		})
		if err != nil {
			t.Fatalf("Filter with an undeclared permission returned an error: %v\nIt must return a residual that "+
				"matches nothing, so a consumer's policy denies rather than raising", err)
		}
		if !undeclared.DeniesEverything() {
			t.Fatalf("Filter with an undeclared permission returned %s, want a residual that matches nothing", undeclared)
		}

		// The session form, which is what a policy needs, must be
		// buildable through the same port.
		session, err := a.Authorizer.Filter(ctx, iam.FilterRequest{
			TenantID:   tenant,
			Principal:  iam.SessionPrincipal(),
			Permission: permRead,
			Key:        iam.Key{Qualifier: "q", Column: "graph_id"},
		})
		if err != nil {
			t.Fatalf("Filter for the session principal: %v", err)
		}
		if _, ok := session.Expr.(iam.ContainerPermits); !ok {
			t.Fatalf("a filter with no tenant key returned %T, want a bare ContainerPermits", session.Expr)
		}

		// And a malformed request is an error, because it is a defect in
		// the caller rather than an answer about the world.
		if _, err := a.Authorizer.Filter(ctx, iam.FilterRequest{TenantID: tenant, Principal: iam.NamedPrincipal(anne), Permission: permRead, Key: iam.Key{Column: "graph id; drop table"}}); !errors.Is(err, iam.ErrInvalidResidual) {
			t.Errorf("Filter with a key that is not a plain column name returned %v, want ErrInvalidResidual", err)
		}
	})
}

// --- helpers ------------------------------------------------------------

// assertCanonicalInstant requires an instant to be in UTC and truncated to
// microseconds, which is the form every instant this module stores or
// compares is in. See iam.Canonical.
func assertCanonicalInstant(t *testing.T, at time.Time, what string) {
	t.Helper()
	if at.IsZero() {
		t.Errorf("%s is the zero time", what)
		return
	}
	if at.Location() != time.UTC {
		t.Errorf("%s is in %v rather than UTC: %v", what, at.Location(), at)
	}
	if at.Nanosecond()%1000 != 0 {
		t.Errorf("%s carries sub-microsecond precision (%d ns): %v.\n"+
			"Postgres timestamptz holds microseconds, so this value compares equal to itself in memory and "+
			"unequal through the database", what, at.Nanosecond(), at)
	}
	if !at.Equal(iam.Canonical(at)) {
		t.Errorf("%s is not iam.Canonical of itself: %v vs %v", what, at, iam.Canonical(at))
	}
}

func mustRegister(t *testing.T, a Authority, s iam.Schema) {
	t.Helper()
	if err := a.Authorizer.RegisterSchema(context.Background(), s); err != nil {
		t.Fatalf("RegisterSchema(%s): %v", s.Name, err)
	}
}

func mustContainer(t *testing.T, a Authority, tenant iam.TenantID, kind string, parent iam.ContainerID) iam.Container {
	t.Helper()
	c, err := a.Authorizer.CreateContainer(context.Background(), iam.ContainerSpec{
		TenantID: tenant,
		Kind:     kind,
		Parent:   parent,
		Label:    kind,
	})
	if err != nil {
		t.Fatalf("CreateContainer(kind=%s, parent=%s): %v", kind, parent, err)
	}
	return c
}

// mustPrincipal provisions one user principal through the real registry,
// which is how a decision's subject comes to exist at all: this module
// grants identity through JIT provisioning and access through nothing but
// a grant.
func mustPrincipal(t *testing.T, a Authority, tenant iam.TenantID, name string) iam.PrincipalID {
	t.Helper()
	p, err := a.Registry.UpsertFromClaims(context.Background(), userClaims(t, tenant, "https://idp.example", name))
	if err != nil {
		t.Fatalf("UpsertFromClaims(%s): %v", name, err)
	}
	return p.ID
}

func mustGrant(t *testing.T, a Authority, spec iam.GrantSpec) iam.Revision {
	t.Helper()
	rev, err := a.Authorizer.Grant(context.Background(), spec)
	if err != nil {
		t.Fatalf("Grant(%s on %s to %s): %v", spec.Permission, spec.Container, spec.Subject, err)
	}
	return rev
}

// mustGrantErr returns the error a grant produced, failing the test if it
// produced none. It exists so the negative cases read as assertions about
// a refusal rather than as inverted happy paths.
func mustGrantErr(t *testing.T, a Authority, spec iam.GrantSpec) error {
	t.Helper()
	if _, err := a.Authorizer.Grant(context.Background(), spec); err != nil {
		return err
	}
	t.Fatalf("Grant(%s on %s to %s) succeeded, want a refusal", spec.Permission, spec.Container, spec.Subject)
	return nil
}

func assertDecision(t *testing.T, a Authority, req iam.Request, allowed bool, reason iam.Reason, depth int, why string) iam.Decision {
	t.Helper()
	d, err := a.Authorizer.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide(%s on %s): %v\n  the property being asserted: %s", req.Permission, req.Container, err, why)
	}
	if d.Allowed != allowed {
		t.Fatalf("Decide(%s, %s on %s) = %s, want allowed=%v\n  the property being asserted: %s",
			req.Principal, req.Permission, req.Container, d, allowed, why)
	}
	if d.Reason != reason {
		t.Fatalf("Decide(%s, %s on %s) = %s, want reason %q\n  the reason is the explanation a consumer debugging "+
			"a decision reads first, and a decision that is right for the wrong reason has drifted\n  the property "+
			"being asserted: %s", req.Principal, req.Permission, req.Container, d, reason, why)
	}
	if d.Depth != depth {
		t.Fatalf("Decide(%s, %s on %s) = %s, want depth %d\n  the property being asserted: %s",
			req.Principal, req.Permission, req.Container, d, depth, why)
	}
	return d
}

func assertAllowed(t *testing.T, a Authority, req iam.Request, why string) {
	t.Helper()
	d, err := a.Authorizer.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide: %v\n  %s", err, why)
	}
	if !d.Allowed {
		t.Fatalf("Decide(%s, %s on %s) = %s, want allow\n  %s", req.Principal, req.Permission, req.Container, d, why)
	}
}

func assertDenied(t *testing.T, a Authority, req iam.Request, why string) {
	t.Helper()
	d, err := a.Authorizer.Decide(context.Background(), req)
	if err != nil {
		t.Fatalf("Decide: %v\n  a denial is a Decision and not an error\n  %s", err, why)
	}
	if d.Allowed {
		t.Fatalf("Decide(%s, %s on %s) = %s, want deny\n  %s", req.Principal, req.Permission, req.Container, d, why)
	}
}
