package registry

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/laenen-ai/iam/internal/domain"
)

// suiteAgentRunTTL is the TTL the suite asks for when delegating an agent
// run. Any registry handed to RunRegistrySuite must permit it; see that
// function's doc comment.
const suiteAgentRunTTL = time.Hour

// RunRegistrySuite runs the contract every registry.Registry adapter must
// satisfy. newRegistry is called once per subtest, receiving that
// subtest's own *T, so an adapter that needs per-test setup and teardown
// (a fresh map, a scratch Postgres schema, a transaction that rolls back)
// registers it with t.Cleanup inside newRegistry and gets fresh, isolated
// state for every subtest.
//
// The registry newRegistry returns must be configured with a positive
// StalenessBound — the suite discovers its value through
// domain.PrincipalCondition.Bound rather than being told — and a
// MaxAgentRunTTL of at least one hour.
//
// This file is deliberately not named suite_test.go: RunRegistrySuite must
// be importable from another package's adapter tests (the pgx adapter in
// internal/registry/pgregistry has its own *_test.go calling this same
// function), which only works for a regular, non-test-only source file.
// This mirrors the standard library's testing/fstest.TestFS, and `cas`'s
// internal/blob.RunStoreSuite.
//
// Every assertion here must hold for any registry — a map, a Postgres
// schema, or a future directory-backed adapter alike. Nothing here
// inspects SQL, reads a table, or otherwise assumes a database;
// adapter-specific mechanics (the joinable membership view's query plan,
// the schema's foreign keys) belong in that adapter's own test file.
//
// Subtests do not call t.Parallel. An adapter's factory may serialize on a
// shared resource, and a conformance suite that assumed otherwise would
// make a correct adapter look broken.
//
// Four of the subtests below are security invariants rather than
// behavioural ones, and every adapter is forced to exercise them:
// NewPrincipalHoldsNoClearances, DeprovisioningDeniesImmediately,
// StalenessPastBoundForcesResync and OrdinaryGroupCannotActAsClearanceGroup.
func RunRegistrySuite(t *testing.T, newRegistry func(t *testing.T) Registry) {
	t.Helper()

	// JITUpsertIsIdempotent: provisioning the same verified subject twice
	// returns one principal, not two, and does not churn its membership.
	// This is the property the whole JIT design rests on — every request
	// re-presents the same token, so a non-idempotent upsert would mint a
	// principal per request and orphan every grant made against the last
	// one.
	t.Run("JITUpsertIsIdempotent", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()
		claims := userClaims(t, tenant, "https://idp.example", "anne", "eng", "oncall")

		first, err := reg.UpsertFromClaims(ctx, claims)
		if err != nil {
			t.Fatalf("first UpsertFromClaims: %v", err)
		}
		if first.ID == "" || first.Kind != domain.PrincipalKindUser {
			t.Fatalf("first upsert returned %+v", first)
		}

		second, err := reg.UpsertFromClaims(ctx, claims)
		if err != nil {
			t.Fatalf("second UpsertFromClaims: %v", err)
		}
		if second.ID != first.ID {
			t.Fatalf("a second upsert of the same subject minted a new id: %q then %q", first.ID, second.ID)
		}
		if second.CreatedAt.After(first.CreatedAt.Add(time.Nanosecond)) {
			t.Fatalf("a second upsert moved created_at: %v then %v", first.CreatedAt, second.CreatedAt)
		}

		// A third upsert naming the same groups must leave membership
		// exactly as it was, not remove-then-re-add it.
		if _, err := reg.UpsertFromClaims(ctx, claims); err != nil {
			t.Fatalf("third UpsertFromClaims: %v", err)
		}
		names := groupNames(t, reg, first.ID, now())
		assertNames(t, names, []string{"eng", "oncall"}, "membership after three identical upserts")

		// And ResolveExternal must find the same id, since that is the
		// path every subsequent request actually takes.
		resolved, err := reg.ResolveExternal(ctx, tenant, claims.Subject)
		if err != nil {
			t.Fatalf("ResolveExternal: %v", err)
		}
		if resolved.ID != first.ID {
			t.Fatalf("ResolveExternal returned %q, want %q", resolved.ID, first.ID)
		}
	})

	t.Run("ResolveExternalOfUnseenSubjectIsErrPrincipalNotFound", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()
		subject := mustSubject(t, "https://idp.example", "never-seen")

		if _, err := reg.ResolveExternal(ctx, tenant, subject); !errors.Is(err, domain.ErrPrincipalNotFound) {
			t.Fatalf("ResolveExternal(unseen) error = %v, want ErrPrincipalNotFound", err)
		}

		// The same subject under a different tenant is a different
		// principal: the registry is global but every row in it is
		// tenant-scoped, so one tenant's provisioning must not resolve
		// for another.
		p, err := reg.UpsertFromClaims(ctx, userClaims(t, tenant, subject.Issuer, subject.Subject))
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}
		if _, err := reg.ResolveExternal(ctx, newTenant(), subject); !errors.Is(err, domain.ErrPrincipalNotFound) {
			t.Fatalf("ResolveExternal of the same subject in another tenant error = %v, want ErrPrincipalNotFound", err)
		}
		if _, err := reg.ResolveExternal(ctx, tenant, subject); err != nil {
			t.Fatalf("ResolveExternal in the right tenant: %v", err)
		}
		if _, err := reg.PrincipalByID(ctx, p.ID); err != nil {
			t.Fatalf("PrincipalByID: %v", err)
		}
	})

	// ShrinkingClaimSetRemovesMemberships: design §8.1's reconciliation
	// rule. A claim set is authoritative for the memberships it sources,
	// so a role the issuer has stopped asserting must stop being joinable
	// — otherwise removing someone from a directory group leaves their
	// access in place until someone notices.
	t.Run("ShrinkingClaimSetRemovesMemberships", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()

		wide := userClaims(t, tenant, "https://idp.example", "anne", "eng", "oncall", "finance-readers")
		p, err := reg.UpsertFromClaims(ctx, wide)
		if err != nil {
			t.Fatalf("UpsertFromClaims(wide): %v", err)
		}
		assertNames(t, groupNames(t, reg, p.ID, now()), []string{"eng", "finance-readers", "oncall"}, "membership from the wide claim set")

		narrow := userClaims(t, tenant, "https://idp.example", "anne", "eng")
		if _, err := reg.UpsertFromClaims(ctx, narrow); err != nil {
			t.Fatalf("UpsertFromClaims(narrow): %v", err)
		}
		assertNames(t, groupNames(t, reg, p.ID, now()), []string{"eng"}, "membership after the claim set shrank")

		// The reverse direction too: an empty claim set removes every
		// claim-sourced membership. "The token no longer asserts any
		// role" must mean no roles, not "no change".
		empty := userClaims(t, tenant, "https://idp.example", "anne")
		if _, err := reg.UpsertFromClaims(ctx, empty); err != nil {
			t.Fatalf("UpsertFromClaims(empty): %v", err)
		}
		assertNames(t, groupNames(t, reg, p.ID, now()), nil, "membership after an empty claim set")

		// And the group itself survives: other principals may still be
		// in it, and a grant may reference it. Reconciliation removes
		// memberships, never groups.
		g, err := reg.EnsureGroup(ctx, tenant, "finance-readers")
		if err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
		members, err := reg.GroupMembers(ctx, g.ID, now())
		if err != nil {
			t.Fatalf("GroupMembers: %v", err)
		}
		if len(members) != 0 {
			t.Fatalf("finance-readers still has %d members after the claim set dropped it", len(members))
		}
	})

	// LocallyAddedMembershipSurvivesClaimReconciliation: the other half
	// of the reconciliation rule. An issuer is authoritative for the
	// memberships it sources and for nothing else, so a membership an
	// operator or a consumer's sharing flow wrote must not be collateral
	// damage of a token that never mentioned it.
	t.Run("LocallyAddedMembershipSurvivesClaimReconciliation", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()

		p, err := reg.UpsertFromClaims(ctx, userClaims(t, tenant, "https://idp.example", "anne", "eng"))
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}
		local, err := reg.EnsureGroup(ctx, tenant, "project-apollo")
		if err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
		if err := reg.AddGroupMember(ctx, local.ID, p.ID); err != nil {
			t.Fatalf("AddGroupMember: %v", err)
		}
		// Idempotent.
		if err := reg.AddGroupMember(ctx, local.ID, p.ID); err != nil {
			t.Fatalf("second AddGroupMember: %v", err)
		}
		assertNames(t, groupNames(t, reg, p.ID, now()), []string{"eng", "project-apollo"}, "membership before reconciliation")

		if _, err := reg.UpsertFromClaims(ctx, userClaims(t, tenant, "https://idp.example", "anne")); err != nil {
			t.Fatalf("UpsertFromClaims(empty): %v", err)
		}
		assertNames(t, groupNames(t, reg, p.ID, now()), []string{"project-apollo"},
			"membership after reconciliation: the claim-sourced row must go and the local one must stay")

		if err := reg.RemoveGroupMember(ctx, local.ID, p.ID); err != nil {
			t.Fatalf("RemoveGroupMember: %v", err)
		}
		// Removing an absent membership is not an error.
		if err := reg.RemoveGroupMember(ctx, local.ID, p.ID); err != nil {
			t.Fatalf("RemoveGroupMember of an absent membership: %v", err)
		}
		assertNames(t, groupNames(t, reg, p.ID, now()), nil, "membership after local removal")
	})

	// ReissuedExternalIdentityKeepsInternalID: design §8.1's reason for
	// having internal ids at all. Renaming a user, changing their email,
	// or re-issuing the same subject must leave every grant, clearance
	// and audit row pointing at the same principal — and must not be
	// inferable from the id, which carries no function of the subject.
	t.Run("ReissuedExternalIdentityKeepsInternalID", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()

		before := userClaims(t, tenant, "https://idp.example", "anne", "eng")
		before.DisplayName = "Anne Example"
		p1, err := reg.UpsertFromClaims(ctx, before)
		if err != nil {
			t.Fatalf("UpsertFromClaims(before): %v", err)
		}

		after := userClaims(t, tenant, "https://idp.example", "anne", "eng")
		after.DisplayName = "Anne Changed-Surname"
		p2, err := reg.UpsertFromClaims(ctx, after)
		if err != nil {
			t.Fatalf("UpsertFromClaims(after): %v", err)
		}
		if p2.ID != p1.ID {
			t.Fatalf("re-issuing the identity changed the internal id: %q -> %q", p1.ID, p2.ID)
		}
		if p2.DisplayName != after.DisplayName {
			t.Fatalf("display name did not refresh: %q", p2.DisplayName)
		}

		// A genuinely different subject at the same issuer is a
		// different principal, and so is the same subject at a
		// different issuer: an issuer is a trust root, not a label.
		other, err := reg.UpsertFromClaims(ctx, userClaims(t, tenant, "https://idp.example", "bob"))
		if err != nil {
			t.Fatalf("UpsertFromClaims(other subject): %v", err)
		}
		if other.ID == p1.ID {
			t.Fatal("two distinct subjects collapsed onto one internal id")
		}
		elsewhere, err := reg.UpsertFromClaims(ctx, userClaims(t, tenant, "https://other-idp.example", "anne"))
		if err != nil {
			t.Fatalf("UpsertFromClaims(other issuer): %v", err)
		}
		if elsewhere.ID == p1.ID {
			t.Fatal("the same subject at two issuers collapsed onto one internal id")
		}

		// The id must not be derived from the subject string: two
		// registries, or two sightings, would otherwise agree on it by
		// construction, and an id would leak the external identity.
		for _, p := range []domain.Principal{p1, other, elsewhere} {
			if s := string(p.ID); s == p.External.Subject || s == p.External.String() {
				t.Fatalf("internal id %q is the external subject; ids must be minted, never derived", s)
			}
		}
	})

	// DeprovisioningDeniesImmediately: design §8.1 and §9.3. The denial
	// is not a staleness condition, is not clearable by a re-sync, and
	// does not wait for a token to expire.
	t.Run("DeprovisioningDeniesImmediately", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()
		claims := userClaims(t, tenant, "https://idp.example", "anne", "eng")

		p, err := reg.UpsertFromClaims(ctx, claims)
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}
		group, err := reg.EnsureGroup(ctx, tenant, "eng")
		if err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}

		cond, err := reg.Condition(ctx, p.ID, now())
		if err != nil {
			t.Fatalf("Condition: %v", err)
		}
		if !cond.Usable() {
			t.Fatalf("a freshly provisioned principal is not usable: %+v", cond)
		}

		if err := reg.Deprovision(ctx, p.ID); err != nil {
			t.Fatalf("Deprovision: %v", err)
		}

		// The deciding instant is the same one that saw it usable a
		// moment ago: the denial does not wait for a clock to move.
		cond, err = reg.Condition(ctx, p.ID, cond.AsOf)
		if err != nil {
			t.Fatalf("Condition after Deprovision: %v", err)
		}
		if cond.State != domain.PrincipalStateDeprovisioned {
			t.Fatalf("Condition after Deprovision = %q, want deprovisioned", cond.State)
		}
		if !errors.Is(cond.Err(), domain.ErrPrincipalDeprovisioned) {
			t.Fatalf("condition Err() = %v, want ErrPrincipalDeprovisioned", cond.Err())
		}

		// Membership reads refuse on the principal's side...
		if _, err := reg.GroupsOf(ctx, p.ID, now()); !errors.Is(err, domain.ErrPrincipalDeprovisioned) {
			t.Fatalf("GroupsOf after Deprovision error = %v, want ErrPrincipalDeprovisioned", err)
		}
		if _, err := reg.ClearanceGroupsOf(ctx, p.ID, now()); !errors.Is(err, domain.ErrPrincipalDeprovisioned) {
			t.Fatalf("ClearanceGroupsOf after Deprovision error = %v, want ErrPrincipalDeprovisioned", err)
		}
		// ...and the principal stops appearing on the group's side,
		// which is what a SQL predicate joining membership actually
		// reads. A deprovisioning that only set a flag the predicate
		// does not consult would pass the check above and still leak.
		members, err := reg.GroupMembers(ctx, group.ID, now())
		if err != nil {
			t.Fatalf("GroupMembers after Deprovision: %v", err)
		}
		for _, m := range members {
			if m == p.ID {
				t.Fatal("a deprovisioned principal is still a joinable member of its group")
			}
		}

		// A fresh token for the same subject is not a reinstatement.
		if _, err := reg.UpsertFromClaims(ctx, claims); !errors.Is(err, domain.ErrPrincipalDeprovisioned) {
			t.Fatalf("UpsertFromClaims of a deprovisioned subject error = %v, want ErrPrincipalDeprovisioned", err)
		}
		// Adding it to a group is refused too, so nothing can re-arm it
		// through a side door.
		if err := reg.AddGroupMember(ctx, group.ID, p.ID); !errors.Is(err, domain.ErrPrincipalDeprovisioned) {
			t.Fatalf("AddGroupMember for a deprovisioned principal error = %v, want ErrPrincipalDeprovisioned", err)
		}

		// Deprovisioning is idempotent, and the row survives so audit
		// can still attribute history to it.
		if err := reg.Deprovision(ctx, p.ID); err != nil {
			t.Fatalf("second Deprovision: %v", err)
		}
		stored, err := reg.ResolveExternal(ctx, tenant, claims.Subject)
		if err != nil {
			t.Fatalf("ResolveExternal after Deprovision: %v", err)
		}
		if stored.DeprovisionedAt.IsZero() {
			t.Fatal("the resolved principal does not report its deprovisioning")
		}

		if err := reg.Deprovision(ctx, domain.PrincipalID("01K0000000000000000000000Z")); !errors.Is(err, domain.ErrPrincipalNotFound) {
			t.Fatalf("Deprovision of an unknown principal error = %v, want ErrPrincipalNotFound", err)
		}
	})

	// NewPrincipalHoldsNoClearances: design §8.3's fail-closed rule. JIT
	// provisioning grants identity, never clearance, so a new joiner sees
	// nothing classified until a mandatory act includes them.
	t.Run("NewPrincipalHoldsNoClearances", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()

		// Provision with every claim-shaped thing that might be mistaken
		// for a clearance: group names that look exactly like
		// compartments, and a clearance group of the same name that
		// already exists in the tenant.
		act := mustAct(t, domain.MandatoryChannelClassify, "security admin seeding the compartment")
		existing, err := reg.EnsureClearanceGroup(ctx, act, tenant, "privileged")
		if err != nil {
			t.Fatalf("EnsureClearanceGroup: %v", err)
		}

		p, err := reg.UpsertFromClaims(ctx, userClaims(t, tenant,
			"https://idp.example", "anne", "privileged", "conflict-screen-acme", "all-timekeepers"))
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}

		held, err := reg.ClearanceGroupsOf(ctx, p.ID, now())
		if err != nil {
			t.Fatalf("ClearanceGroupsOf: %v", err)
		}
		if len(held) != 0 {
			t.Fatalf("a newly provisioned principal holds %d clearance groups (%v); it must hold none", len(held), held)
		}

		// A group claim named identically to a clearance group must have
		// created an ordinary group, not joined the compartment.
		assertNames(t, groupNames(t, reg, p.ID, now()),
			[]string{"all-timekeepers", "conflict-screen-acme", "privileged"},
			"claim-derived ordinary groups")
		members, err := reg.ClearanceGroupMembers(ctx, existing.ID, now())
		if err != nil {
			t.Fatalf("ClearanceGroupMembers: %v", err)
		}
		if len(members) != 0 {
			t.Fatalf("the clearance group named by a claim gained %d members", len(members))
		}

		// A delegated agent run inherits nothing either: delegation is a
		// discretionary act, and a discretionary act that conferred a
		// clearance is anti-goal A3 breached.
		if err := reg.AddClearanceGroupMember(ctx, act, existing.ID, p.ID); err != nil {
			t.Fatalf("AddClearanceGroupMember: %v", err)
		}
		run, err := reg.DelegateAgentRun(ctx, p.ID, AgentRunSpec{TTL: suiteAgentRunTTL, DisplayName: "nightly consolidation"})
		if err != nil {
			t.Fatalf("DelegateAgentRun: %v", err)
		}
		inherited, err := reg.ClearanceGroupsOf(ctx, run.ID, now())
		if err != nil {
			t.Fatalf("ClearanceGroupsOf(agent run): %v", err)
		}
		if len(inherited) != 0 {
			t.Fatalf("an agent run inherited %d clearance groups from its parent; it must inherit none", len(inherited))
		}
		inheritedGroups, err := reg.GroupsOf(ctx, run.ID, now())
		if err != nil {
			t.Fatalf("GroupsOf(agent run): %v", err)
		}
		if len(inheritedGroups) != 0 {
			t.Fatalf("an agent run inherited %d ordinary groups from its parent; it must inherit none", len(inheritedGroups))
		}
	})

	// StalenessPastBoundForcesResync: design §8.1's staleness bound,
	// enforced by the registry rather than trusted to the caller. The
	// suite does not know the deployment's bound; it reads it back from
	// the condition and steps past it.
	t.Run("StalenessPastBoundForcesResync", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()
		claims := userClaims(t, tenant, "https://idp.example", "anne", "eng")

		p, err := reg.UpsertFromClaims(ctx, claims)
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}

		fresh, err := reg.Condition(ctx, p.ID, p.SyncedAt)
		if err != nil {
			t.Fatalf("Condition: %v", err)
		}
		if fresh.Bound <= 0 {
			t.Fatalf("the registry reported a non-positive staleness bound (%v); a deployment must declare one", fresh.Bound)
		}
		if !fresh.Usable() {
			t.Fatalf("a principal synced at the deciding instant is not usable: %+v", fresh)
		}

		// Exactly at the bound is still fresh; one step past it is not.
		atBound := p.SyncedAt.Add(fresh.Bound)
		if cond, err := reg.Condition(ctx, p.ID, atBound); err != nil {
			t.Fatalf("Condition(at bound): %v", err)
		} else if !cond.Usable() {
			t.Fatalf("a principal exactly at the staleness bound is not usable: %+v", cond)
		}

		pastBound := p.SyncedAt.Add(fresh.Bound + time.Second)
		stale, err := reg.Condition(ctx, p.ID, pastBound)
		if err != nil {
			t.Fatalf("Condition(past bound): %v", err)
		}
		if stale.State != domain.PrincipalStateResyncRequired {
			t.Fatalf("Condition past the bound = %q, want resync-required", stale.State)
		}
		if !errors.Is(stale.Err(), domain.ErrResyncRequired) {
			t.Fatalf("stale condition Err() = %v, want ErrResyncRequired", stale.Err())
		}
		if stale.Age <= stale.Bound {
			t.Fatalf("a stale condition reported Age=%v within Bound=%v", stale.Age, stale.Bound)
		}

		// Forced, not advisory: the memberships a decision would need
		// are refused outright at that instant.
		if _, err := reg.GroupsOf(ctx, p.ID, pastBound); !errors.Is(err, domain.ErrResyncRequired) {
			t.Fatalf("GroupsOf past the bound error = %v, want ErrResyncRequired", err)
		}
		if _, err := reg.ClearanceGroupsOf(ctx, p.ID, pastBound); !errors.Is(err, domain.ErrResyncRequired) {
			t.Fatalf("ClearanceGroupsOf past the bound error = %v, want ErrResyncRequired", err)
		}
		// And on the joinable side, a stale principal stops matching.
		group, err := reg.EnsureGroup(ctx, tenant, "eng")
		if err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
		members, err := reg.GroupMembers(ctx, group.ID, pastBound)
		if err != nil {
			t.Fatalf("GroupMembers past the bound: %v", err)
		}
		for _, m := range members {
			if m == p.ID {
				t.Fatal("a principal past the staleness bound is still a joinable member of its group")
			}
		}

		// Re-syncing clears it: unlike deprovisioning, staleness is a
		// recoverable condition, and the re-sync must move synced_at.
		resynced, err := reg.UpsertFromClaims(ctx, claims)
		if err != nil {
			t.Fatalf("UpsertFromClaims(resync): %v", err)
		}
		if !resynced.SyncedAt.After(p.SyncedAt) && !resynced.SyncedAt.Equal(p.SyncedAt) {
			t.Fatalf("a re-sync moved synced_at backwards: %v -> %v", p.SyncedAt, resynced.SyncedAt)
		}
		if cond, err := reg.Condition(ctx, p.ID, resynced.SyncedAt); err != nil {
			t.Fatalf("Condition after resync: %v", err)
		} else if !cond.Usable() {
			t.Fatalf("a re-synced principal is still not usable: %+v", cond)
		}
	})

	// OrdinaryGroupCannotActAsClearanceGroup: the runtime half of design
	// §8.3's tier separation, for an id that arrived as text — from a
	// config file, an API request, another service — and so bypassed the
	// type system. domain.ClearanceGroupID makes the confusion
	// unwriteable in Go (see TestOrdinaryGroupIDIsNotAClearanceGroupID,
	// which requires the compiler to reject it); this requires every
	// adapter to refuse it at runtime as well, because a parser cannot
	// know what a registry stores.
	t.Run("OrdinaryGroupCannotActAsClearanceGroup", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()
		act := mustAct(t, domain.MandatoryChannelClassify, "matter 4471 conflict screen")

		p, err := reg.UpsertFromClaims(ctx, userClaims(t, tenant, "https://idp.example", "anne"))
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}
		group, err := reg.EnsureGroup(ctx, tenant, "eng")
		if err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
		clearance, err := reg.EnsureClearanceGroup(ctx, act, tenant, "privileged")
		if err != nil {
			t.Fatalf("EnsureClearanceGroup: %v", err)
		}

		// An ordinary group's id, re-parsed as a clearance group id
		// (which succeeds: both are well-formed ULIDs, and syntax
		// cannot carry kind), must be refused by every clearance write.
		asClearance, err := domain.ParseClearanceGroupID(string(group.ID))
		if err != nil {
			t.Fatalf("ParseClearanceGroupID of a well-formed ULID: %v", err)
		}
		if err := reg.AddClearanceGroupMember(ctx, act, asClearance, p.ID); !errors.Is(err, domain.ErrGroupKindMismatch) {
			t.Fatalf("AddClearanceGroupMember with an ordinary group's id error = %v, want ErrGroupKindMismatch", err)
		}
		if err := reg.RemoveClearanceGroupMember(ctx, act, asClearance, p.ID); !errors.Is(err, domain.ErrGroupKindMismatch) {
			t.Fatalf("RemoveClearanceGroupMember with an ordinary group's id error = %v, want ErrGroupKindMismatch", err)
		}
		if _, err := reg.ClearanceGroupMembers(ctx, asClearance, now()); !errors.Is(err, domain.ErrGroupKindMismatch) {
			t.Fatalf("ClearanceGroupMembers with an ordinary group's id error = %v, want ErrGroupKindMismatch", err)
		}
		if _, err := reg.ClearanceGroupChanges(ctx, asClearance); !errors.Is(err, domain.ErrGroupKindMismatch) {
			t.Fatalf("ClearanceGroupChanges with an ordinary group's id error = %v, want ErrGroupKindMismatch", err)
		}

		// And the reverse: a clearance group may never be referenced
		// where a tier-1 group is expected, because a tier-1 reference
		// is a discretionary handle on a mandatory object.
		asGroup, err := domain.ParseGroupID(clearance.ID.String())
		if err != nil {
			t.Fatalf("ParseGroupID: %v", err)
		}
		if err := reg.AddGroupMember(ctx, asGroup, p.ID); !errors.Is(err, domain.ErrGroupKindMismatch) {
			t.Fatalf("AddGroupMember with a clearance group's id error = %v, want ErrGroupKindMismatch", err)
		}
		if _, err := reg.GroupMembers(ctx, asGroup, now()); !errors.Is(err, domain.ErrGroupKindMismatch) {
			t.Fatalf("GroupMembers with a clearance group's id error = %v, want ErrGroupKindMismatch", err)
		}

		// An id naming nothing at all is simply absent, and must not be
		// reported as a kind confusion — the two refusals mean different
		// things to an operator.
		unknown, err := domain.ParseClearanceGroupID("01K0000000000000000000000Z")
		if err != nil {
			t.Fatalf("ParseClearanceGroupID: %v", err)
		}
		if err := reg.AddClearanceGroupMember(ctx, act, unknown, p.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("AddClearanceGroupMember with an unknown id error = %v, want ErrNotFound", err)
		}

		// Membership of an ordinary group named like a compartment
		// confers no clearance.
		if err := reg.AddGroupMember(ctx, group.ID, p.ID); err != nil {
			t.Fatalf("AddGroupMember: %v", err)
		}
		held, err := reg.ClearanceGroupsOf(ctx, p.ID, now())
		if err != nil {
			t.Fatalf("ClearanceGroupsOf: %v", err)
		}
		if len(held) != 0 {
			t.Fatalf("ordinary group membership produced %d clearance groups", len(held))
		}
	})

	// ClearanceMembershipRequiresAMandatoryChannel: design §8.3's
	// mandatory channel, enforced at the port. There is no discretionary
	// path into a clearance group, so a write without a witness is a
	// refusal and never a defaulted-to-ordinary write.
	t.Run("ClearanceMembershipRequiresAMandatoryChannel", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()
		act := mustAct(t, domain.MandatoryChannelClassify, "matter 4471 conflict screen")

		p, err := reg.UpsertFromClaims(ctx, userClaims(t, tenant, "https://idp.example", "anne"))
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}
		cg, err := reg.EnsureClearanceGroup(ctx, act, tenant, "privileged")
		if err != nil {
			t.Fatalf("EnsureClearanceGroup: %v", err)
		}

		var noAct domain.MandatoryAct
		if _, err := reg.EnsureClearanceGroup(ctx, noAct, tenant, "sneaked-in"); !errors.Is(err, domain.ErrMandatoryChannelRequired) {
			t.Fatalf("EnsureClearanceGroup without an act error = %v, want ErrMandatoryChannelRequired", err)
		}
		if err := reg.AddClearanceGroupMember(ctx, noAct, cg.ID, p.ID); !errors.Is(err, domain.ErrMandatoryChannelRequired) {
			t.Fatalf("AddClearanceGroupMember without an act error = %v, want ErrMandatoryChannelRequired", err)
		}
		if err := reg.RemoveClearanceGroupMember(ctx, noAct, cg.ID, p.ID); !errors.Is(err, domain.ErrMandatoryChannelRequired) {
			t.Fatalf("RemoveClearanceGroupMember without an act error = %v, want ErrMandatoryChannelRequired", err)
		}

		// A clearance group's channel is fixed at creation: a
		// directory-synced compartment cannot be edited by hand, and a
		// hand-administered one cannot be overwritten by a sync.
		synced := mustAct(t, domain.MandatoryChannelDirectorySync, "hr feed")
		if err := reg.AddClearanceGroupMember(ctx, synced, cg.ID, p.ID); !errors.Is(err, domain.ErrChannelMismatch) {
			t.Fatalf("AddClearanceGroupMember through the wrong channel error = %v, want ErrChannelMismatch", err)
		}
		if _, err := reg.EnsureClearanceGroup(ctx, synced, tenant, "privileged"); !errors.Is(err, domain.ErrChannelMismatch) {
			t.Fatalf("EnsureClearanceGroup through the wrong channel error = %v, want ErrChannelMismatch", err)
		}

		// The right channel works, and is idempotent.
		if err := reg.AddClearanceGroupMember(ctx, act, cg.ID, p.ID); err != nil {
			t.Fatalf("AddClearanceGroupMember: %v", err)
		}
		if err := reg.AddClearanceGroupMember(ctx, act, cg.ID, p.ID); err != nil {
			t.Fatalf("second AddClearanceGroupMember: %v", err)
		}
		held, err := reg.ClearanceGroupsOf(ctx, p.ID, now())
		if err != nil {
			t.Fatalf("ClearanceGroupsOf: %v", err)
		}
		if len(held) != 1 || held[0].ID != cg.ID {
			t.Fatalf("ClearanceGroupsOf = %+v, want exactly the one clearance group", held)
		}
		if held[0].Channel != domain.MandatoryChannelClassify {
			t.Fatalf("clearance group channel = %q, want %q", held[0].Channel, domain.MandatoryChannelClassify)
		}

		members, err := reg.ClearanceGroupMembers(ctx, cg.ID, now())
		if err != nil {
			t.Fatalf("ClearanceGroupMembers: %v", err)
		}
		if len(members) != 1 || members[0] != p.ID {
			t.Fatalf("ClearanceGroupMembers = %v, want exactly %q", members, p.ID)
		}

		if err := reg.RemoveClearanceGroupMember(ctx, act, cg.ID, p.ID); err != nil {
			t.Fatalf("RemoveClearanceGroupMember: %v", err)
		}
		// Removing an absent membership is not an error.
		if err := reg.RemoveClearanceGroupMember(ctx, act, cg.ID, p.ID); err != nil {
			t.Fatalf("second RemoveClearanceGroupMember: %v", err)
		}
		held, err = reg.ClearanceGroupsOf(ctx, p.ID, now())
		if err != nil {
			t.Fatalf("ClearanceGroupsOf after removal: %v", err)
		}
		if len(held) != 0 {
			t.Fatalf("ClearanceGroupsOf after removal = %+v, want none", held)
		}
	})

	// ClearanceGroupChangesAreAudited: design §8.3 requires clearance
	// membership to be audited. The trail is append-only, so a removal
	// records a removal rather than erasing the addition — a mandatory
	// control whose history can be edited is not evidence of anything.
	t.Run("ClearanceGroupChangesAreAudited", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()
		create := mustAct(t, domain.MandatoryChannelClassify, "open the acme conflict screen")
		add := mustAct(t, domain.MandatoryChannelClassify, "anne is on the acme matter")
		remove := mustAct(t, domain.MandatoryChannelClassify, "anne left the acme matter")

		p, err := reg.UpsertFromClaims(ctx, userClaims(t, tenant, "https://idp.example", "anne"))
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}
		cg, err := reg.EnsureClearanceGroup(ctx, create, tenant, "conflict-screen-acme")
		if err != nil {
			t.Fatalf("EnsureClearanceGroup: %v", err)
		}
		if err := reg.AddClearanceGroupMember(ctx, add, cg.ID, p.ID); err != nil {
			t.Fatalf("AddClearanceGroupMember: %v", err)
		}
		if err := reg.RemoveClearanceGroupMember(ctx, remove, cg.ID, p.ID); err != nil {
			t.Fatalf("RemoveClearanceGroupMember: %v", err)
		}

		changes, err := reg.ClearanceGroupChanges(ctx, cg.ID)
		if err != nil {
			t.Fatalf("ClearanceGroupChanges: %v", err)
		}
		wantKinds := []domain.ClearanceChangeKind{
			domain.ClearanceChangeCreated,
			domain.ClearanceChangeAdded,
			domain.ClearanceChangeRemoved,
		}
		if len(changes) != len(wantKinds) {
			t.Fatalf("trail has %d entries (%+v), want %d", len(changes), changes, len(wantKinds))
		}
		for i, want := range wantKinds {
			got := changes[i]
			if got.Kind != want {
				t.Fatalf("trail[%d].Kind = %q, want %q", i, got.Kind, want)
			}
			if got.ID == "" || got.ClearanceGroupID != cg.ID {
				t.Fatalf("trail[%d] = %+v, want an id and the clearance group", i, got)
			}
			if got.Reason == "" || got.Actor == "" || got.ActedAt.IsZero() || got.RecordedAt.IsZero() {
				t.Fatalf("trail[%d] = %+v, want channel, actor, reason and instants recorded", i, got)
			}
			if got.Channel != domain.MandatoryChannelClassify {
				t.Fatalf("trail[%d].Channel = %q", i, got.Channel)
			}
		}
		if changes[1].PrincipalID != p.ID || changes[2].PrincipalID != p.ID {
			t.Fatalf("the membership entries do not name the principal: %+v", changes[1:])
		}
		if changes[1].Reason != add.Reason() || changes[2].Reason != remove.Reason() {
			t.Fatalf("the recorded reasons were not the acts' own: %q, %q", changes[1].Reason, changes[2].Reason)
		}

		// A refused write leaves no entry: the trail records what
		// happened, not what was attempted and denied, because a trail
		// that mixed the two could not be read as a list of who holds
		// what.
		var noAct domain.MandatoryAct
		if err := reg.AddClearanceGroupMember(ctx, noAct, cg.ID, p.ID); err == nil {
			t.Fatal("AddClearanceGroupMember without an act succeeded")
		}
		after, err := reg.ClearanceGroupChanges(ctx, cg.ID)
		if err != nil {
			t.Fatalf("ClearanceGroupChanges: %v", err)
		}
		if len(after) != len(changes) {
			t.Fatalf("a refused write appended to the trail: %d entries, was %d", len(after), len(changes))
		}
	})

	// AgentRunIsAFirstClassPrincipalWithATTL: design §8.1. The run has
	// its own id so audit and metering attribute per run, carries a
	// policy TTL, and is unusable from its deadline rather than from
	// whenever a collector happens to sweep.
	t.Run("AgentRunIsAFirstClassPrincipalWithATTL", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()

		parent, err := reg.UpsertFromClaims(ctx, serviceClaims(t, tenant, "https://idp.example", "consolidator"))
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}

		run, err := reg.DelegateAgentRun(ctx, parent.ID, AgentRunSpec{TTL: suiteAgentRunTTL, DisplayName: "run-1"})
		if err != nil {
			t.Fatalf("DelegateAgentRun: %v", err)
		}
		if run.ID == parent.ID || run.ID == "" {
			t.Fatalf("an agent run must have its own id; got %q against parent %q", run.ID, parent.ID)
		}
		if run.Kind != domain.PrincipalKindAgentRun {
			t.Fatalf("agent run kind = %q", run.Kind)
		}
		if run.DelegatedBy != parent.ID {
			t.Fatalf("agent run DelegatedBy = %q, want %q", run.DelegatedBy, parent.ID)
		}
		if run.ExpiresAt.IsZero() {
			t.Fatal("an agent run must carry a TTL deadline")
		}
		if run.TenantID != parent.TenantID {
			t.Fatalf("agent run tenant = %q, want its parent's %q", run.TenantID, parent.TenantID)
		}

		// Two runs from one parent are two principals.
		second, err := reg.DelegateAgentRun(ctx, parent.ID, AgentRunSpec{TTL: suiteAgentRunTTL, DisplayName: "run-2"})
		if err != nil {
			t.Fatalf("second DelegateAgentRun: %v", err)
		}
		if second.ID == run.ID {
			t.Fatal("two agent runs from one parent share an id; audit could not attribute per run")
		}

		if cond, err := reg.Condition(ctx, run.ID, run.ExpiresAt.Add(-time.Minute)); err != nil {
			t.Fatalf("Condition inside the TTL: %v", err)
		} else if !cond.Usable() {
			t.Fatalf("an agent run inside its TTL is not usable: %+v", cond)
		}

		// Unusable from the deadline itself, with no collection run.
		expired, err := reg.Condition(ctx, run.ID, run.ExpiresAt)
		if err != nil {
			t.Fatalf("Condition at the deadline: %v", err)
		}
		if expired.State != domain.PrincipalStateExpired {
			t.Fatalf("Condition at the deadline = %q, want expired", expired.State)
		}
		if !errors.Is(expired.Err(), domain.ErrAgentRunExpired) {
			t.Fatalf("expired condition Err() = %v, want ErrAgentRunExpired", expired.Err())
		}
		if _, err := reg.GroupsOf(ctx, run.ID, run.ExpiresAt); !errors.Is(err, domain.ErrAgentRunExpired) {
			t.Fatalf("GroupsOf at the deadline error = %v, want ErrAgentRunExpired", err)
		}

		// An agent run cannot delegate a further agent run: a chain of
		// ephemeral principals has no attributable owner.
		if _, err := reg.DelegateAgentRun(ctx, run.ID, AgentRunSpec{TTL: suiteAgentRunTTL}); err == nil {
			t.Fatal("an agent run was allowed to delegate another agent run")
		}
		// Nor may a deprovisioned or unknown principal delegate one.
		if _, err := reg.DelegateAgentRun(ctx, domain.PrincipalID("01K0000000000000000000000Z"), AgentRunSpec{TTL: suiteAgentRunTTL}); !errors.Is(err, domain.ErrPrincipalNotFound) {
			t.Fatalf("DelegateAgentRun from an unknown parent error = %v, want ErrPrincipalNotFound", err)
		}
		// A TTL is mandatory and must be positive.
		if _, err := reg.DelegateAgentRun(ctx, parent.ID, AgentRunSpec{}); !errors.Is(err, domain.ErrInvalidPrincipal) {
			t.Fatalf("DelegateAgentRun with no TTL error = %v, want ErrInvalidPrincipal", err)
		}

		// Collection is garbage collection, not enforcement: it removes
		// what has already stopped working.
		n, err := reg.CollectExpiredAgentRuns(ctx, run.ExpiresAt.Add(-time.Minute))
		if err != nil {
			t.Fatalf("CollectExpiredAgentRuns before any deadline: %v", err)
		}
		if n != 0 {
			t.Fatalf("CollectExpiredAgentRuns collected %d runs before any had expired", n)
		}
		n, err = reg.CollectExpiredAgentRuns(ctx, run.ExpiresAt.Add(time.Minute))
		if err != nil {
			t.Fatalf("CollectExpiredAgentRuns: %v", err)
		}
		if n != 2 {
			t.Fatalf("CollectExpiredAgentRuns collected %d runs, want 2", n)
		}
		if _, err := reg.PrincipalByID(ctx, run.ID); !errors.Is(err, domain.ErrPrincipalNotFound) {
			t.Fatalf("PrincipalByID after collection error = %v, want ErrPrincipalNotFound", err)
		}
		// The parent is untouched: collecting a run is not deprovisioning
		// whoever started it.
		if _, err := reg.PrincipalByID(ctx, parent.ID); err != nil {
			t.Fatalf("PrincipalByID(parent) after collection: %v", err)
		}
	})

	t.Run("EnsureGroupIsIdempotentAndTenantScoped", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		a, b := newTenant(), newTenant()

		first, err := reg.EnsureGroup(ctx, a, "eng")
		if err != nil {
			t.Fatalf("EnsureGroup: %v", err)
		}
		second, err := reg.EnsureGroup(ctx, a, "eng")
		if err != nil {
			t.Fatalf("second EnsureGroup: %v", err)
		}
		if second.ID != first.ID {
			t.Fatalf("EnsureGroup minted a second group for the same name: %q then %q", first.ID, second.ID)
		}

		elsewhere, err := reg.EnsureGroup(ctx, b, "eng")
		if err != nil {
			t.Fatalf("EnsureGroup in another tenant: %v", err)
		}
		if elsewhere.ID == first.ID {
			t.Fatal("two tenants' groups of the same name collapsed onto one id")
		}

		if _, err := reg.EnsureGroup(ctx, a, ""); err == nil {
			t.Fatal("EnsureGroup accepted an empty name")
		}

		act := mustAct(t, domain.MandatoryChannelDirectorySync, "hr feed")
		cgFirst, err := reg.EnsureClearanceGroup(ctx, act, a, "all-timekeepers")
		if err != nil {
			t.Fatalf("EnsureClearanceGroup: %v", err)
		}
		cgSecond, err := reg.EnsureClearanceGroup(ctx, act, a, "all-timekeepers")
		if err != nil {
			t.Fatalf("second EnsureClearanceGroup: %v", err)
		}
		if cgSecond.ID != cgFirst.ID {
			t.Fatalf("EnsureClearanceGroup minted a second clearance group: %q then %q", cgFirst.ID, cgSecond.ID)
		}
		// A clearance group and an ordinary group may share a name
		// without sharing anything else: they are different kinds of
		// object in different namespaces, and conflating the namespaces
		// would make a tier-1 name a lever on a tier-2 object.
		if _, err := reg.EnsureGroup(ctx, a, "all-timekeepers"); err != nil {
			t.Fatalf("EnsureGroup of a name a clearance group already uses: %v", err)
		}
	})

	t.Run("UpsertFromClaimsRejectsUnprovisionableClaims", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()

		cases := []struct {
			name   string
			claims Claims
		}{
			{"no tenant", Claims{Subject: mustSubject(t, "https://idp.example", "anne"), Kind: domain.PrincipalKindUser}},
			{"no subject", Claims{TenantID: tenant, Kind: domain.PrincipalKindUser}},
			{"unknown kind", Claims{TenantID: tenant, Subject: mustSubject(t, "https://idp.example", "anne"), Kind: "robot"}},
			{
				"agent run from claims",
				Claims{TenantID: tenant, Subject: mustSubject(t, "https://idp.example", "anne"), Kind: domain.PrincipalKindAgentRun},
			},
			{
				"empty group name",
				Claims{TenantID: tenant, Subject: mustSubject(t, "https://idp.example", "anne"), Kind: domain.PrincipalKindUser, Groups: []string{"eng", ""}},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				if _, err := reg.UpsertFromClaims(ctx, tc.claims); !errors.Is(err, domain.ErrInvalidClaims) {
					t.Fatalf("UpsertFromClaims error = %v, want ErrInvalidClaims", err)
				}
			})
		}

		// A duplicated group name is not an error: an issuer that lists
		// a role twice must produce one membership, not two or a
		// refusal.
		dup := userClaims(t, tenant, "https://idp.example", "anne", "eng", "eng")
		p, err := reg.UpsertFromClaims(ctx, dup)
		if err != nil {
			t.Fatalf("UpsertFromClaims with a duplicated group: %v", err)
		}
		assertNames(t, groupNames(t, reg, p.ID, now()), []string{"eng"}, "membership from a claim set with a duplicate")
	})

	t.Run("UnknownPrincipalReadsAreErrPrincipalNotFound", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		unknown := domain.PrincipalID("01K0000000000000000000000Z")

		if _, err := reg.PrincipalByID(ctx, unknown); !errors.Is(err, domain.ErrPrincipalNotFound) {
			t.Fatalf("PrincipalByID error = %v, want ErrPrincipalNotFound", err)
		}
		if _, err := reg.Condition(ctx, unknown, now()); !errors.Is(err, domain.ErrPrincipalNotFound) {
			t.Fatalf("Condition error = %v, want ErrPrincipalNotFound", err)
		}
		if _, err := reg.GroupsOf(ctx, unknown, now()); !errors.Is(err, domain.ErrPrincipalNotFound) {
			t.Fatalf("GroupsOf error = %v, want ErrPrincipalNotFound", err)
		}
		if _, err := reg.ClearanceGroupsOf(ctx, unknown, now()); !errors.Is(err, domain.ErrPrincipalNotFound) {
			t.Fatalf("ClearanceGroupsOf error = %v, want ErrPrincipalNotFound", err)
		}

		// A malformed id on a lookup path is "not found" rather than
		// "malformed": the registry's answer to "do you know this
		// principal" must not depend on whether the caller's id was
		// well-formed, or the shape of the refusal becomes a syntax
		// oracle over the id space.
		if _, err := reg.PrincipalByID(ctx, domain.PrincipalID("nonsense")); !errors.Is(err, domain.ErrPrincipalNotFound) {
			t.Fatalf("PrincipalByID(malformed) error = %v, want ErrPrincipalNotFound", err)
		}

		unknownGroup, err := domain.ParseGroupID("01K0000000000000000000000Z")
		if err != nil {
			t.Fatalf("ParseGroupID: %v", err)
		}
		if _, err := reg.GroupMembers(ctx, unknownGroup, now()); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("GroupMembers of an unknown group error = %v, want ErrNotFound", err)
		}
		if err := reg.AddGroupMember(ctx, unknownGroup, unknown); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("AddGroupMember into an unknown group error = %v, want ErrNotFound", err)
		}
	})
}

// --- suite helpers -------------------------------------------------------

// now returns the instant the suite uses as "the request is happening
// now". The suite never sleeps and never depends on an adapter's clock
// matching this one for anything but liveness, which it tests through
// instants it derives from the rows themselves.
func now() time.Time { return time.Now() }

// newTenant mints a tenant id. The registry is global and every row in it
// is tenant-scoped, so each subtest's assertions are kept apart by using
// fresh tenants rather than by truncating anything.
func newTenant() domain.TenantID { return domain.NewTenantID(domain.SystemClock{}) }

// mustSubject builds an external subject or fails the test.
func mustSubject(t *testing.T, issuer, subject string) domain.ExternalSubject {
	t.Helper()
	s, err := domain.ParseExternalSubject(issuer, subject)
	if err != nil {
		t.Fatalf("ParseExternalSubject(%q, %q): %v", issuer, subject, err)
	}
	return s
}

// mustAct builds a MandatoryAct or fails the test. Its actor is a fresh
// principal id: the suite does not require the actor to be a principal the
// registry knows, because a directory sync's service identity and a
// deployment-level security admin may both live outside the tenant whose
// clearance they are administering.
func mustAct(t *testing.T, channel domain.MandatoryChannel, reason string) domain.MandatoryAct {
	t.Helper()
	act, err := domain.NewMandatoryAct(channel, domain.NewPrincipalID(domain.SystemClock{}), reason, time.Now())
	if err != nil {
		t.Fatalf("NewMandatoryAct: %v", err)
	}
	return act
}

// userClaims builds a user claim set for the given subject and claim-derived groups.
func userClaims(t *testing.T, tenant domain.TenantID, issuer, subject string, groups ...string) Claims {
	t.Helper()
	return Claims{
		TenantID:    tenant,
		Subject:     mustSubject(t, issuer, subject),
		Kind:        domain.PrincipalKindUser,
		DisplayName: subject,
		Groups:      groups,
	}
}

// serviceClaims builds a service claim set, the shape a Zitadel service
// user's token arrives in.
func serviceClaims(t *testing.T, tenant domain.TenantID, issuer, subject string, groups ...string) Claims {
	t.Helper()
	c := userClaims(t, tenant, issuer, subject, groups...)
	c.Kind = domain.PrincipalKindService
	return c
}

// groupNames reads a principal's ordinary group names, failing the test on
// an error.
func groupNames(t *testing.T, reg Registry, p domain.PrincipalID, asOf time.Time) []string {
	t.Helper()
	groups, err := reg.GroupsOf(context.Background(), p, asOf)
	if err != nil {
		t.Fatalf("GroupsOf: %v", err)
	}
	names := make([]string, 0, len(groups))
	for _, g := range groups {
		names = append(names, g.Name)
	}
	return names
}

// assertNames compares a membership name list against the expected set,
// which the port documents as ordered by name.
func assertNames(t *testing.T, got, want []string, what string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("%s = %v, want %v", what, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s = %v, want %v (ordered by name)", what, got, want)
		}
	}
}
