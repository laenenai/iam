package pgregistry_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenen-ai/iam"
	"github.com/laenen-ai/iam/iamtest"
	"github.com/laenen-ai/iam/internal/domain"
	"github.com/laenen-ai/iam/internal/migrate"
	"github.com/laenen-ai/iam/internal/registry"
	"github.com/laenen-ai/iam/internal/registry/pgregistry"
	"github.com/laenen-ai/iam/internal/testdb"
)

// The deployment policy this adapter is given for the conformance run.
// The bound is long enough that no subtest trips it by accident; the suite
// discovers its value through the condition it reads back.
const (
	suiteStalenessBound = 15 * time.Minute
	suiteMaxAgentRunTTL = 24 * time.Hour
)

// newPGRegistry is the per-subtest factory. testdb.Start gives each
// subtest its own uniquely-named, freshly migrated database and registers
// the teardown with that subtest's t.Cleanup, so every subtest in the
// conformance run gets isolated state — and skips under testing.Short()
// through the single chokepoint for that convention.
func newPGRegistry(t *testing.T) iam.Registry {
	t.Helper()
	db := testdb.Start(t)
	reg, err := pgregistry.New(db.Pool(), registry.Config{
		StalenessBound: suiteStalenessBound,
		MaxAgentRunTTL: suiteMaxAgentRunTTL,
	})
	if err != nil {
		t.Fatalf("pgregistry.New: %v", err)
	}
	return reg
}

func TestPostgres_PassesRegistrySuite(t *testing.T) {
	iamtest.RunRegistrySuite(t, newPGRegistry)
}

func TestNew_RejectsInvalidConfig(t *testing.T) {
	t.Parallel()

	if _, err := pgregistry.New(nil, registry.Config{StalenessBound: time.Hour, MaxAgentRunTTL: time.Hour}); !errors.Is(err, iam.ErrInvalidConfig) {
		t.Fatalf("New(nil pool) error = %v, want ErrInvalidConfig", err)
	}

	// A pool is not dialed by New, so this needs no database and stays in
	// the -short inner loop.
	pool := &pgxpool.Pool{}
	if _, err := pgregistry.New(pool, registry.Config{MaxAgentRunTTL: time.Hour}); !errors.Is(err, iam.ErrInvalidConfig) {
		t.Fatalf("New with no staleness bound error = %v, want ErrInvalidConfig", err)
	}
}

// ---------------------------------------------------------------------------
// What only real Postgres can prove.
//
// The in-memory adapter and this one both pass the conformance suite, so
// the suite proves the *contract*. The tests below prove the
// *enforcement*: that the invariants survive something other than this
// module's own Go code — a hand-written statement, a future task, an
// operator during an incident. CONVENTIONS requires exactly this split.
// ---------------------------------------------------------------------------

// TestMigrationsApplyForwardAndAreIdempotent is the migration test
// CONVENTIONS asks for: applied forward on a fresh database, and a second
// run is a no-op rather than an error.
func TestMigrationsApplyForwardAndAreIdempotent(t *testing.T) {
	db := testdb.Start(t)
	ctx := t.Context()

	applied, err := migrate.Status(ctx, db.Pool())
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	if len(applied) == 0 {
		t.Fatal("Status reported no migrations; the embedded set is empty")
	}
	for _, a := range applied {
		if !a.Applied {
			t.Errorf("migration %d (%s) is pending after testdb.Start migrated the database", a.Version, a.Name)
		}
	}

	if err := migrate.Up(ctx, db.Pool()); err != nil {
		t.Fatalf("second Up against an already-current database: %v", err)
	}
	again, err := migrate.Status(ctx, db.Pool())
	if err != nil {
		t.Fatalf("Status after second Up: %v", err)
	}
	if len(again) != len(applied) {
		t.Fatalf("second Up changed the migration count: %d, was %d", len(again), len(applied))
	}
	for i := range applied {
		if !again[i].AppliedAt.Equal(applied[i].AppliedAt) {
			t.Errorf("migration %d AppliedAt moved on an idempotent second Up: %v -> %v",
				applied[i].Version, applied[i].AppliedAt, again[i].AppliedAt)
		}
	}
}

// TestTierSeparationIsEnforcedBySchema is the third layer of design §8.3's
// separation, and the only one that holds against something other than
// this module's Go code.
//
// Layer one is the type system (domain.ClearanceGroupID cannot be
// converted to or from GroupID — see TestOrdinaryGroupIDIsNotAClearanceGroupID,
// which requires the compiler to reject the attempt). Layer two is the
// port (every clearance write demands a mandatory act). Neither survives a
// hand-written INSERT, and a tier confusion written directly into the
// tables would mean a discretionary group-membership change opening a
// mandatory gate — anti-goal A3. This asserts the foreign keys make it
// unrepresentable.
func TestTierSeparationIsEnforcedBySchema(t *testing.T) {
	db := testdb.Start(t)
	ctx := t.Context()
	pool := db.Pool()

	tenant := string(domain.NewTenantID(domain.SystemClock{}))
	principal := string(domain.NewPrincipalID(domain.SystemClock{}))
	group := string(domain.NewGroupID(domain.SystemClock{}))
	clearance := domain.NewClearanceGroupID(domain.SystemClock{}).String()

	if _, err := pool.Exec(ctx,
		`INSERT INTO iam.principals (id, tenant_id, kind, issuer, subject, synced_at)
		 VALUES ($1, $2, 'user', 'https://idp.example', 'anne', now())`, principal, tenant); err != nil {
		t.Fatalf("seed principal: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO iam.groups (id, tenant_id, name) VALUES ($1, $2, 'eng')`, group, tenant); err != nil {
		t.Fatalf("seed group: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO iam.clearance_groups (id, tenant_id, name, channel)
		 VALUES ($1, $2, 'privileged', 'classify-permission')`, clearance, tenant); err != nil {
		t.Fatalf("seed clearance group: %v", err)
	}

	// An ordinary group's id cannot be stored as a clearance group's.
	if _, err := pool.Exec(ctx,
		`INSERT INTO iam.clearance_group_members
			(clearance_group_id, principal_id, channel, actor_principal_id, reason, acted_at)
		 VALUES ($1, $2, 'classify-permission', $3, 'hand-written', now())`,
		group, principal, principal); err == nil {
		t.Fatal("a tier-1 group id was accepted as a clearance group id by a direct INSERT; " +
			"the foreign key that makes the tier confusion unrepresentable is missing")
	}

	// And a clearance group's id cannot be stored as a tier-1 group's.
	if _, err := pool.Exec(ctx,
		`INSERT INTO iam.group_members (group_id, principal_id, source) VALUES ($1, $2, 'local')`,
		clearance, principal); err == nil {
		t.Fatal("a clearance group id was accepted as a tier-1 group id by a direct INSERT; " +
			"a clearance group may never be referenced in a tier-1 relation")
	}
}

// TestClearanceTrailIsAppendOnlyInTheDatabase proves the audit property
// design §8.3 requires holds against a statement this module would never
// issue. An application-layer guarantee — "this package offers no method
// that edits a trail entry" — does not survive a future task, a migration
// or a hand-run UPDATE during an incident, and a mandatory control whose
// history can be edited is not evidence of anything.
func TestClearanceTrailIsAppendOnlyInTheDatabase(t *testing.T) {
	db := testdb.Start(t)
	ctx := t.Context()
	pool := db.Pool()

	reg, err := pgregistry.New(pool, registry.Config{
		StalenessBound: suiteStalenessBound,
		MaxAgentRunTTL: suiteMaxAgentRunTTL,
	})
	if err != nil {
		t.Fatalf("pgregistry.New: %v", err)
	}

	tenant := domain.NewTenantID(domain.SystemClock{})
	act, err := domain.NewMandatoryAct(domain.MandatoryChannelClassify,
		domain.NewPrincipalID(domain.SystemClock{}), "matter 4471 conflict screen", time.Now())
	if err != nil {
		t.Fatalf("NewMandatoryAct: %v", err)
	}
	cg, err := reg.EnsureClearanceGroup(ctx, act, tenant, "conflict-screen-acme")
	if err != nil {
		t.Fatalf("EnsureClearanceGroup: %v", err)
	}

	for _, stmt := range []struct {
		name string
		sql  string
	}{
		{"update a reason", `UPDATE iam.clearance_group_changes SET reason = 'rewritten' WHERE clearance_group_id = $1`},
		{"delete an entry", `DELETE FROM iam.clearance_group_changes WHERE clearance_group_id = $1`},
	} {
		t.Run(stmt.name, func(t *testing.T) {
			_, err := pool.Exec(ctx, stmt.sql, cg.ID.String())
			if err == nil {
				t.Fatal("the statement succeeded; iam.clearance_group_changes must be append-only in the database, not only in Go")
			}
			if !strings.Contains(err.Error(), "append-only") {
				t.Fatalf("the statement failed, but not on the append-only guard — this test may be passing for the wrong reason: %v", err)
			}
		})
	}

	// The entry is still readable and unchanged.
	changes, err := reg.ClearanceGroupChanges(ctx, cg.ID)
	if err != nil {
		t.Fatalf("ClearanceGroupChanges: %v", err)
	}
	if len(changes) != 1 || changes[0].Reason != act.Reason() {
		t.Fatalf("trail = %+v, want the one creation entry with its original reason", changes)
	}
}

// TestAgentRunShapeIsEnforcedBySchema pins the constraints that stop a row
// describing an impossible principal from existing at all: an agent run
// with no parent or no deadline, and a user or service principal carrying
// either. Principal.Validate refuses the same shapes in Go; this is what
// holds when the write did not come through Go.
func TestAgentRunShapeIsEnforcedBySchema(t *testing.T) {
	db := testdb.Start(t)
	ctx := t.Context()
	pool := db.Pool()

	tenant := string(domain.NewTenantID(domain.SystemClock{}))
	parent := string(domain.NewPrincipalID(domain.SystemClock{}))
	if _, err := pool.Exec(ctx,
		`INSERT INTO iam.principals (id, tenant_id, kind, issuer, subject, synced_at)
		 VALUES ($1, $2, 'user', 'https://idp.example', 'anne', now())`, parent, tenant); err != nil {
		t.Fatalf("seed parent: %v", err)
	}

	cases := []struct {
		name string
		sql  string
		args []any
	}{
		{
			"agent run with no parent",
			`INSERT INTO iam.principals (id, tenant_id, kind, expires_at, synced_at)
			 VALUES ($1, $2, 'agent-run', now() + interval '1 hour', now())`,
			[]any{string(domain.NewPrincipalID(domain.SystemClock{})), tenant},
		},
		{
			"agent run with no deadline",
			`INSERT INTO iam.principals (id, tenant_id, kind, delegated_by, synced_at)
			 VALUES ($1, $2, 'agent-run', $3, now())`,
			[]any{string(domain.NewPrincipalID(domain.SystemClock{})), tenant, parent},
		},
		{
			"user principal carrying a delegation",
			`INSERT INTO iam.principals (id, tenant_id, kind, issuer, subject, delegated_by, synced_at)
			 VALUES ($1, $2, 'user', 'https://idp.example', 'bob', $3, now())`,
			[]any{string(domain.NewPrincipalID(domain.SystemClock{})), tenant, parent},
		},
		{
			"user principal carrying a deadline",
			`INSERT INTO iam.principals (id, tenant_id, kind, issuer, subject, expires_at, synced_at)
			 VALUES ($1, $2, 'user', 'https://idp.example', 'carol', now() + interval '1 hour', now())`,
			[]any{string(domain.NewPrincipalID(domain.SystemClock{})), tenant},
		},
		{
			"user principal with no external subject",
			`INSERT INTO iam.principals (id, tenant_id, kind, synced_at) VALUES ($1, $2, 'user', now())`,
			[]any{string(domain.NewPrincipalID(domain.SystemClock{})), tenant},
		},
		{
			"half an external subject",
			`INSERT INTO iam.principals (id, tenant_id, kind, issuer, synced_at)
			 VALUES ($1, $2, 'service', 'https://idp.example', now())`,
			[]any{string(domain.NewPrincipalID(domain.SystemClock{})), tenant},
		},
		{
			"an id that is not a ULID",
			`INSERT INTO iam.principals (id, tenant_id, kind, issuer, subject, synced_at)
			 VALUES ('not-a-ulid', $1, 'user', 'https://idp.example', 'dave', now())`,
			[]any{tenant},
		},
		{
			"a principal with no synced_at, whose freshness could never be evaluated",
			`INSERT INTO iam.principals (id, tenant_id, kind, issuer, subject)
			 VALUES ($1, $2, 'user', 'https://idp.example', 'erin')`,
			[]any{string(domain.NewPrincipalID(domain.SystemClock{})), tenant},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := pool.Exec(ctx, tc.sql, tc.args...); err == nil {
				t.Fatal("the row was accepted; the schema must refuse it")
			}
		})
	}
}

// TestLiveGroupMembersViewIsTheJoinablePredicateArtifact is the point of
// the whole schema: design §9's authorization predicate joins group
// membership *inside* the consumer's own statement, so the artifact it
// joins has to exist and has to answer correctly.
//
// It also pins the view's deliberate asymmetry: it excludes deprovisioned
// principals and expired agent runs, because a stale denial is a
// disclosure (§9.3), and it does not exclude principals past the
// staleness bound, because the bound is deployment configuration enforced
// before a predicate is ever compiled rather than a property of a row.
func TestLiveGroupMembersViewIsTheJoinablePredicateArtifact(t *testing.T) {
	db := testdb.Start(t)
	ctx := t.Context()
	pool := db.Pool()

	reg, err := pgregistry.New(pool, registry.Config{
		StalenessBound: suiteStalenessBound,
		MaxAgentRunTTL: suiteMaxAgentRunTTL,
	})
	if err != nil {
		t.Fatalf("pgregistry.New: %v", err)
	}

	tenant := domain.NewTenantID(domain.SystemClock{})
	subject, err := domain.ParseExternalSubject("https://idp.example", "anne")
	if err != nil {
		t.Fatalf("ParseExternalSubject: %v", err)
	}
	claims := registry.Claims{TenantID: tenant, Subject: subject, Kind: domain.PrincipalKindUser, Groups: []string{"eng"}}
	p, err := reg.UpsertFromClaims(ctx, claims)
	if err != nil {
		t.Fatalf("UpsertFromClaims: %v", err)
	}
	group, err := reg.EnsureGroup(ctx, tenant, "eng")
	if err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}

	// The predicate, verbatim in the shape a consumer embeds it.
	const predicate = `
		SELECT EXISTS (
			SELECT 1 FROM iam.live_group_members lgm
			WHERE lgm.principal_id = $1 AND lgm.group_id = $2
		)`
	visible := func() bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, predicate, string(p.ID), string(group.ID)).Scan(&ok); err != nil {
			t.Fatalf("predicate: %v", err)
		}
		return ok
	}

	if !visible() {
		t.Fatal("the predicate does not see a fresh, live membership; nothing else in this design works without it")
	}

	// Deprovisioning must stop the predicate matching in the same instant
	// it is recorded, without the membership row being deleted.
	if err := reg.Deprovision(ctx, p.ID); err != nil {
		t.Fatalf("Deprovision: %v", err)
	}
	if visible() {
		t.Fatal("the predicate still matches a deprovisioned principal; deprovisioning does not deny immediately in SQL")
	}
	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM iam.group_members WHERE principal_id = $1 AND group_id = $2`,
		string(p.ID), string(group.ID)).Scan(&rows); err != nil {
		t.Fatalf("count membership rows: %v", err)
	}
	if rows != 1 {
		t.Fatalf("the membership row was deleted by deprovisioning (%d rows); it must survive, so audit can explain what the principal had access to", rows)
	}

	// An expired agent run likewise stops matching at its deadline,
	// without waiting for the collector.
	service, err := reg.UpsertFromClaims(ctx, registry.Claims{
		TenantID: tenant,
		Subject:  mustSubject(t, "https://idp.example", "consolidator"),
		Kind:     domain.PrincipalKindService,
	})
	if err != nil {
		t.Fatalf("UpsertFromClaims(service): %v", err)
	}
	run, err := reg.DelegateAgentRun(ctx, service.ID, registry.AgentRunSpec{TTL: time.Second})
	if err != nil {
		t.Fatalf("DelegateAgentRun: %v", err)
	}
	if err := reg.AddGroupMember(ctx, group.ID, run.ID); err != nil {
		t.Fatalf("AddGroupMember(run): %v", err)
	}
	runVisible := func() bool {
		t.Helper()
		var ok bool
		if err := pool.QueryRow(ctx, predicate, string(run.ID), string(group.ID)).Scan(&ok); err != nil {
			t.Fatalf("predicate: %v", err)
		}
		return ok
	}
	if !runVisible() {
		t.Fatal("the predicate does not see a live agent run's membership")
	}
	// The view's cutoff is the database's now(), so move the deadline
	// into the past rather than sleeping for it.
	if _, err := pool.Exec(ctx,
		`UPDATE iam.principals SET expires_at = now() - interval '1 second' WHERE id = $1`,
		string(run.ID)); err != nil {
		t.Fatalf("backdate the run's deadline: %v", err)
	}
	if runVisible() {
		t.Fatal("the predicate still matches an expired agent run; the TTL must deny from its deadline, not from the collector's next sweep")
	}
}

// TestPredicatePlanIsAnIndexProbe is the plan test CONVENTIONS requires
// for any SQL predicate whose plan matters, and anti-goal A2 is explicit
// that a budget met on a small table says nothing: "the plan must show an
// index join, never a sequential scan".
//
// It asserts the shape rather than a timing: the membership probe must
// reach iam.group_members through an index, because a sequential scan here
// is the regression that turns a 20 ms predicate into a table scan per
// decision at ten million rows.
func TestPredicatePlanIsAnIndexProbe(t *testing.T) {
	db := testdb.Start(t)
	ctx := t.Context()
	pool := db.Pool()

	reg, err := pgregistry.New(pool, registry.Config{
		StalenessBound: suiteStalenessBound,
		MaxAgentRunTTL: suiteMaxAgentRunTTL,
	})
	if err != nil {
		t.Fatalf("pgregistry.New: %v", err)
	}

	tenant := domain.NewTenantID(domain.SystemClock{})
	// Enough rows that the planner has a real choice: with a handful of
	// rows a sequential scan is correct and the assertion would be
	// vacuous.
	const principals = 400
	group, err := reg.EnsureGroup(ctx, tenant, "eng")
	if err != nil {
		t.Fatalf("EnsureGroup: %v", err)
	}
	var probe domain.PrincipalID
	for i := range principals {
		p, err := reg.UpsertFromClaims(ctx, registry.Claims{
			TenantID: tenant,
			Subject:  mustSubject(t, "https://idp.example", "user-"+itoa(i)),
			Kind:     domain.PrincipalKindUser,
			Groups:   []string{"eng", "oncall-" + itoa(i%7)},
		})
		if err != nil {
			t.Fatalf("UpsertFromClaims(%d): %v", i, err)
		}
		if i == principals/2 {
			probe = p.ID
		}
	}
	if _, err := pool.Exec(ctx, `ANALYZE iam.group_members, iam.groups, iam.principals`); err != nil {
		t.Fatalf("ANALYZE: %v", err)
	}

	const explain = `
		EXPLAIN (FORMAT TEXT)
		SELECT EXISTS (
			SELECT 1 FROM iam.live_group_members lgm
			WHERE lgm.principal_id = $1 AND lgm.group_id = $2
		)`
	rows, err := pool.Query(ctx, explain, string(probe), string(group.ID))
	if err != nil {
		t.Fatalf("EXPLAIN: %v", err)
	}
	defer rows.Close()

	var plan strings.Builder
	for rows.Next() {
		var line string
		if err := rows.Scan(&line); err != nil {
			t.Fatalf("scan plan line: %v", err)
		}
		plan.WriteString(line)
		plan.WriteString("\n")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read plan: %v", err)
	}

	text := plan.String()
	// No sequential scan anywhere in the plan, not merely none on
	// iam.group_members. A2 requires an index join, and this assertion is
	// what caught an earlier draft of iam.live_group_members that joined
	// iam.groups to expose a tenant_id the predicate never reads: the
	// probe itself was an index-only scan and the dead join was a scan on
	// every decision.
	if strings.Contains(text, "Seq Scan") {
		t.Fatalf("the predicate plan contains a sequential scan; A2 requires an index join with no scan and no materialization of the rule set.\nplan:\n%s", text)
	}
	if !strings.Contains(text, "Index Only Scan") {
		t.Fatalf("the membership probe is not an index-only scan; the (principal_id, group_id) primary key or its reverse index is not being used.\nplan:\n%s", text)
	}
	t.Logf("predicate plan:\n%s", text)
}

// TestClaimReconciliationIsOneTransaction proves the atomicity an
// in-memory map gets for free and a database does not: a principal and its
// reconciled membership land together or not at all. A principal visible
// with a half-reconciled claim set is a principal whose access is briefly
// wrong, and "briefly wrong" in this module is a disclosure window.
func TestClaimReconciliationIsOneTransaction(t *testing.T) {
	db := testdb.Start(t)
	ctx := t.Context()
	pool := db.Pool()

	reg, err := pgregistry.New(pool, registry.Config{
		StalenessBound: suiteStalenessBound,
		MaxAgentRunTTL: suiteMaxAgentRunTTL,
	})
	if err != nil {
		t.Fatalf("pgregistry.New: %v", err)
	}

	tenant := domain.NewTenantID(domain.SystemClock{})
	subject := mustSubject(t, "https://idp.example", "anne")

	// A claim set naming a group whose name violates the schema's CHECK
	// cannot be constructed through Claims (Validate refuses an empty
	// name), so the failure is injected where a real one would land: a
	// tenant id the iam.ulid domain refuses. The principal insert fails,
	// and nothing — not the groups the claim set named — may remain.
	bad := registry.Claims{
		TenantID: domain.TenantID("not-a-ulid"),
		Subject:  subject,
		Kind:     domain.PrincipalKindUser,
		Groups:   []string{"eng", "oncall"},
	}
	if _, err := reg.UpsertFromClaims(ctx, bad); err == nil {
		t.Fatal("UpsertFromClaims with a malformed tenant id succeeded")
	}

	var groups int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam.groups`).Scan(&groups); err != nil {
		t.Fatalf("count groups: %v", err)
	}
	if groups != 0 {
		t.Fatalf("a failed upsert left %d groups behind; the reconciliation must be one transaction with the principal write", groups)
	}
	var principals int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM iam.principals`).Scan(&principals); err != nil {
		t.Fatalf("count principals: %v", err)
	}
	if principals != 0 {
		t.Fatalf("a failed upsert left %d principals behind", principals)
	}

	// And the good path still works afterwards, so the rollback did not
	// poison the connection or the pool.
	if _, err := reg.UpsertFromClaims(ctx, registry.Claims{
		TenantID: tenant, Subject: subject, Kind: domain.PrincipalKindUser, Groups: []string{"eng"},
	}); err != nil {
		t.Fatalf("UpsertFromClaims after a rolled-back attempt: %v", err)
	}
}

// TestErrorsNeverLeakTheExternalSubject is this module's version of `cas`'s
// NoPayloadContentLeaksInErrors canary. Postgres fills a unique-violation's
// Detail with the offending row's column values, which here are a person's
// identity at their identity provider; mapErr keeps only the constraint
// name for exactly that reason.
func TestErrorsNeverLeakTheExternalSubject(t *testing.T) {
	db := testdb.Start(t)
	ctx := t.Context()
	pool := db.Pool()

	const sentinel = "anne-sentinel-f3a9c2@example.test"
	tenant := string(domain.NewTenantID(domain.SystemClock{}))
	first := string(domain.NewPrincipalID(domain.SystemClock{}))
	second := string(domain.NewPrincipalID(domain.SystemClock{}))

	const insert = `
		INSERT INTO iam.principals (id, tenant_id, kind, issuer, subject, synced_at)
		VALUES ($1, $2, 'user', 'https://idp.example', $3, now())`
	if _, err := pool.Exec(ctx, insert, first, tenant, sentinel); err != nil {
		t.Fatalf("seed: %v", err)
	}

	_, rawErr := pool.Exec(ctx, insert, second, tenant, sentinel)
	if rawErr == nil {
		t.Fatal("a duplicate (tenant, issuer, subject) was accepted; the external-subject key is missing")
	}
	// Confirm the leak is real at the pgx layer, so the assertion below is
	// testing mapErr rather than a Postgres version that happens not to
	// fill Detail.
	if !strings.Contains(rawErr.Error(), sentinel) {
		t.Skipf("this Postgres build does not put row values in the error detail, so mapErr's redaction cannot be demonstrated here: %v", rawErr)
	}

	mapped := pgregistry.MapErrForTest(rawErr)
	if strings.Contains(mapped.Error(), sentinel) {
		t.Fatalf("the mapped error leaked the external subject: %v", mapped)
	}
	if !errors.Is(mapped, iam.ErrConflict) {
		t.Fatalf("mapped error = %v, want ErrConflict", mapped)
	}
}

// mustSubject builds an external subject or fails the test.
func mustSubject(t *testing.T, issuer, subject string) domain.ExternalSubject {
	t.Helper()
	s, err := domain.ParseExternalSubject(issuer, subject)
	if err != nil {
		t.Fatalf("ParseExternalSubject(%q, %q): %v", issuer, subject, err)
	}
	return s
}

// itoa avoids importing strconv for one call site in a loop.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [8]byte
	n := len(b)
	for i > 0 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	return string(b[n:])
}
