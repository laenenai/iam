// Package iamtest holds `iam`'s conformance suites: the executable form
// of each port's contract, runnable by this module's own adapters and by a
// consumer's, in the consumer's CI, against the consumer's wiring. The
// charter makes that the adoption test — "a consumer counts as adopted
// when the suite runs green in *its* CI against *its* wiring" — so the
// suite has to be callable from another module, which an identifier in a
// _test.go file is not.
//
// It is a sibling of the root package rather than part of it because a
// non-test file that imports `testing` puts `testing` in the import graph
// of every consumer's production binary, along with its flag
// registrations. This is the standard library's own split: fstest.TestFS
// verifies any fs.FS, and httptest is a sibling of http.
//
// The suites here, not the port interfaces, are the authoritative
// description of each contract's edge-case behaviour.
package iamtest

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/laenenai/iam"
	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/registry"
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
// Two of the subtests below are security invariants rather than
// behavioural ones, and every adapter is forced to exercise them:
// DeprovisioningDeniesImmediately and StalenessPastBoundForcesResync.
// There were four. The other two held a mandatory tier to its rules, and
// went with it: see the design document's "no deny mechanism" anti-goal.
func RunRegistrySuite(t *testing.T, newRegistry func(t *testing.T) iam.Registry) {
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
	// or re-issuing the same subject must leave every grant and every
	// audit row pointing at the same principal — and must not be
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

	// DeprovisioningCascadesToDelegatedAgentRuns: the hole the previous
	// subtest would otherwise leave. An agent run is deliberately exempt
	// from the staleness bound (it has no issuer to re-sync from — see
	// domain.EvaluateCondition), so nothing else would ever catch a run
	// delegated by a principal that has since been deprovisioned. Without
	// the cascade, deprovisioning a user leaves her agents running with
	// the authority she delegated to them, for as long as their TTLs last,
	// and "deprovisioning denies immediately" would be false of the
	// principals most likely to be holding a long-running job.
	t.Run("DeprovisioningCascadesToDelegatedAgentRuns", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()

		parent, err := reg.UpsertFromClaims(ctx, userClaims(t, tenant, "https://idp.example", "anne"))
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}
		run, err := reg.DelegateAgentRun(ctx, parent.ID, registry.AgentRunSpec{TTL: suiteAgentRunTTL, DisplayName: "long job"})
		if err != nil {
			t.Fatalf("DelegateAgentRun: %v", err)
		}
		if cond, err := reg.Condition(ctx, run.ID, now()); err != nil {
			t.Fatalf("Condition: %v", err)
		} else if !cond.Usable() {
			t.Fatalf("a fresh agent run is not usable: %+v", cond)
		}

		if err := reg.Deprovision(ctx, parent.ID); err != nil {
			t.Fatalf("Deprovision(parent): %v", err)
		}

		cond, err := reg.Condition(ctx, run.ID, now())
		if err != nil {
			t.Fatalf("Condition after the parent was deprovisioned: %v", err)
		}
		if cond.State != domain.PrincipalStateDeprovisioned {
			t.Fatalf("an agent run of a deprovisioned parent reports %q, want deprovisioned", cond.State)
		}
		if _, err := reg.GroupsOf(ctx, run.ID, now()); !errors.Is(err, domain.ErrPrincipalDeprovisioned) {
			t.Fatalf("GroupsOf for a cascaded agent run error = %v, want ErrPrincipalDeprovisioned", err)
		}
		if _, err := reg.DelegateAgentRun(ctx, parent.ID, registry.AgentRunSpec{TTL: suiteAgentRunTTL}); !errors.Is(err, domain.ErrPrincipalDeprovisioned) {
			t.Fatalf("DelegateAgentRun from a deprovisioned parent error = %v, want ErrPrincipalDeprovisioned", err)
		}
	})

	// AgentRunIsNotSubjectToTheStalenessBound: the companion to the rule
	// above, pinned so no adapter "fixes" it by applying the bound. A run
	// longer than the deployment's staleness bound must not fail halfway
	// through with a refusal no caller could clear, because there is no
	// issuer an agent run could be re-synced from.
	t.Run("AgentRunIsNotSubjectToTheStalenessBound", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()

		parent, err := reg.UpsertFromClaims(ctx, serviceClaims(t, tenant, "https://idp.example", "consolidator"))
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}
		cond, err := reg.Condition(ctx, parent.ID, parent.SyncedAt)
		if err != nil {
			t.Fatalf("Condition: %v", err)
		}
		run, err := reg.DelegateAgentRun(ctx, parent.ID, registry.AgentRunSpec{TTL: suiteAgentRunTTL})
		if err != nil {
			t.Fatalf("DelegateAgentRun: %v", err)
		}
		if suiteAgentRunTTL <= cond.Bound {
			t.Skipf("this deployment's staleness bound (%v) is not shorter than the suite's agent-run TTL (%v), so the case cannot arise here",
				cond.Bound, suiteAgentRunTTL)
		}

		// Past the bound, well inside the TTL.
		asOf := run.SyncedAt.Add(cond.Bound + time.Minute)
		late, err := reg.Condition(ctx, run.ID, asOf)
		if err != nil {
			t.Fatalf("Condition past the bound: %v", err)
		}
		if !late.Usable() {
			t.Fatalf("an agent run past the staleness bound but inside its TTL reports %q; the bound must not apply to it", late.State)
		}
		if _, err := reg.GroupsOf(ctx, run.ID, asOf); err != nil {
			t.Fatalf("GroupsOf for an agent run past the bound: %v", err)
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

		run, err := reg.DelegateAgentRun(ctx, parent.ID, registry.AgentRunSpec{TTL: suiteAgentRunTTL, DisplayName: "run-1"})
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
		second, err := reg.DelegateAgentRun(ctx, parent.ID, registry.AgentRunSpec{TTL: suiteAgentRunTTL, DisplayName: "run-2"})
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
		if _, err := reg.DelegateAgentRun(ctx, run.ID, registry.AgentRunSpec{TTL: suiteAgentRunTTL}); err == nil {
			t.Fatal("an agent run was allowed to delegate another agent run")
		}
		// Nor may a deprovisioned or unknown principal delegate one.
		if _, err := reg.DelegateAgentRun(ctx, domain.PrincipalID("01K0000000000000000000000Z"), registry.AgentRunSpec{TTL: suiteAgentRunTTL}); !errors.Is(err, domain.ErrPrincipalNotFound) {
			t.Fatalf("DelegateAgentRun from an unknown parent error = %v, want ErrPrincipalNotFound", err)
		}
		// A TTL is mandatory and must be positive.
		if _, err := reg.DelegateAgentRun(ctx, parent.ID, registry.AgentRunSpec{}); !errors.Is(err, domain.ErrInvalidPrincipal) {
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
	})

	t.Run("UpsertFromClaimsRejectsUnprovisionableClaims", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()

		cases := []struct {
			name   string
			claims registry.Claims
		}{
			{"no tenant", registry.Claims{Subject: mustSubject(t, "https://idp.example", "anne"), Kind: domain.PrincipalKindUser}},
			{"no subject", registry.Claims{TenantID: tenant, Kind: domain.PrincipalKindUser}},
			{"unknown kind", registry.Claims{TenantID: tenant, Subject: mustSubject(t, "https://idp.example", "anne"), Kind: "robot"}},
			{
				"agent run from claims",
				registry.Claims{TenantID: tenant, Subject: mustSubject(t, "https://idp.example", "anne"), Kind: domain.PrincipalKindAgentRun},
			},
			{
				"empty group name",
				registry.Claims{TenantID: tenant, Subject: mustSubject(t, "https://idp.example", "anne"), Kind: domain.PrincipalKindUser, Groups: []string{"eng", ""}},
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

	// StoredInstantsRoundTripExactly: the trap CONVENTIONS records two
	// other modules hitting on the same day. Postgres timestamptz holds
	// microseconds, so a time.Time carrying nanoseconds compares equal to
	// itself in memory and unequal through the database — and an
	// in-memory adapter and a Postgres one then disagree about whether two
	// instants are the same instant. domain.Canonical closes it at the
	// points where instants enter the system; this requires every adapter
	// to preserve that, because an adapter that re-stamps or re-locates an
	// instant breaks it again.
	t.Run("StoredInstantsRoundTripExactly", func(t *testing.T) {
		reg := newRegistry(t)
		ctx := context.Background()
		tenant := newTenant()

		p, err := reg.UpsertFromClaims(ctx, userClaims(t, tenant, "https://idp.example", "anne", "eng"))
		if err != nil {
			t.Fatalf("UpsertFromClaims: %v", err)
		}
		reread, err := reg.PrincipalByID(ctx, p.ID)
		if err != nil {
			t.Fatalf("PrincipalByID: %v", err)
		}
		if !reread.SyncedAt.Equal(p.SyncedAt) {
			t.Fatalf("synced_at did not round-trip: wrote %v (%d ns), read %v (%d ns)",
				p.SyncedAt, p.SyncedAt.Nanosecond(), reread.SyncedAt, reread.SyncedAt.Nanosecond())
		}
		if !reread.CreatedAt.Equal(p.CreatedAt) {
			t.Fatalf("created_at did not round-trip: wrote %v, read %v", p.CreatedAt, reread.CreatedAt)
		}
		for _, ts := range []struct {
			name string
			at   time.Time
		}{{"synced_at", reread.SyncedAt}, {"created_at", reread.CreatedAt}} {
			if ts.at.Truncate(time.Microsecond) != ts.at {
				t.Fatalf("%s carries sub-microsecond precision (%v); it cannot survive a timestamptz round trip", ts.name, ts.at)
			}
		}

		// There was a third assertion here, on a caller-supplied
		// instant: the witness a mandatory write carried had to survive
		// into the trail intact, because a trail whose timestamps differ
		// from the act's by a few hundred nanoseconds cannot be
		// reconciled with anything else that recorded the same act. No
		// method on this port now stores an instant the caller chose, so
		// the property has nothing left to hold and is not replaced by a
		// weaker one. It returns when something stores a caller's time.
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

// userClaims builds a user claim set for the given subject and claim-derived groups.
func userClaims(t *testing.T, tenant domain.TenantID, issuer, subject string, groups ...string) registry.Claims {
	t.Helper()
	return registry.Claims{
		TenantID:    tenant,
		Subject:     mustSubject(t, issuer, subject),
		Kind:        domain.PrincipalKindUser,
		DisplayName: subject,
		Groups:      groups,
	}
}

// serviceClaims builds a service claim set, the shape a Zitadel service
// user's token arrives in.
func serviceClaims(t *testing.T, tenant domain.TenantID, issuer, subject string, groups ...string) registry.Claims {
	t.Helper()
	c := userClaims(t, tenant, issuer, subject, groups...)
	c.Kind = domain.PrincipalKindService
	return c
}

// groupNames reads a principal's ordinary group names, failing the test on
// an error.
func groupNames(t *testing.T, reg iam.Registry, p domain.PrincipalID, asOf time.Time) []string {
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
