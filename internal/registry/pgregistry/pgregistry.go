// Package pgregistry is the Postgres-backed registry.Registry: the
// deployment adapter, and the one that actually has to make design §8.1's
// membership joinable. It passes iamtest.RunRegistrySuite unchanged.
//
// What this adapter adds over the in-memory one is not behaviour but
// enforcement. The in-memory adapter proves the contract; only this one
// proves the schema — that the tier separation survives a statement
// written outside this module, that the clearance trail is append-only
// because the table refuses to be edited, that the agent-run shape is a
// constraint rather than a Go assertion, and that the membership probe the
// authorization predicate will embed resolves on an index. See
// db/migrations/00002_identity.sql for the schema's reasoning and
// pgregistry_test.go for the properties that only exist against real
// Postgres.
//
// # Where the SQL lives
//
// Every statement this package runs is in db/queries/*.sql and reaches Go
// through sqlc, which is CONVENTIONS' default and needs no justification.
// The statements are type-checked against db/migrations at generation
// time, so a column that does not exist or a parameter of the wrong type
// fails before a test runs, and the reasoning for each one lives beside it
// in the query file — the claim reconciliation's four steps, where the
// insert-then-delete-what-is-absent argument is readable in the order it
// executes, and the deprovisioning cascade. The statement is the artifact
// being reasoned about, and a comment in Go beside a string literal is one
// edit away from describing a different query.
//
// Two things about that mapping are worth stating here, because both have
// a wrong answer that looks reasonable.
//
// A clearance group's id is the one column deliberately not mapped to its
// domain type. domain.ClearanceGroupID is a struct with an unexported
// field so that no package outside internal/domain can forge one or
// convert a GroupID into one (design §8.3, and
// TestOrdinaryGroupIDIsNotAClearanceGroupID requires the compiler to
// reject the attempt). Mapping it through the generator would mean
// sql.Scanner and driver.Valuer on that type — both exported, so any
// package could then build a ClearanceGroupID from an arbitrary string,
// and the unforgeability the type exists for would be gone. So the column
// maps to its primitive, text, and this package converts: inbound through
// clearanceKey, outbound through domain.ParseClearanceGroupID in
// toClearanceGroup. One conversion per field, at one boundary, and the
// invariant is untouched.
//
// Every other id and enum column does map to its typed domain type, so a
// generated row hands back a domain.PrincipalID and never a bare string;
// see sqlc.yaml, where each override carries its reason.
//
// # The exception: SQL composed at runtime
//
// Design §9's authorization predicate is not generated and cannot be. It
// is a fragment the consumer embeds in its own statement, so there is no
// fixed query to type-check and no Go function to call — the shape is
//
//	EXISTS (
//	  SELECT 1 FROM iam.live_group_members lgm
//	  WHERE lgm.principal_id = $1 AND lgm.group_id = <the grant's group>
//	)
//
// and it is argued where the artifact it joins is defined: the comment on
// iam.live_group_members in db/migrations/00002_identity.sql, which is
// also where the view's deliberate omissions are justified. Its text is
// kept in one place on each side — that comment, and the predicate
// constant in pgregistry_test.go, which both
// TestLiveGroupMembersViewIsTheJoinablePredicateArtifact and
// TestPredicatePlanIsAnIndexProbe use rather than restating. When
// Predicate ships it hand-composes that fragment, and that is the only
// hand-written SQL this package will have.
//
// # Liveness is filtered in Go, not in SQL
//
// Membership reads project the whole principal row and filter it through
// domain.EvaluateCondition rather than asking Postgres. That is
// deliberate: the staleness bound is deployment configuration, and two
// adapters each expressing the rule in their own language is two chances
// to disagree about when a principal goes stale — a disagreement that
// would surface as one deployment permitting what another denies. The SQL
// views (iam.live_group_members) exist for a different caller: the
// predicate above, which runs inside the consumer's own statement where no
// Go code is available.
package pgregistry

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/registry"
	"github.com/laenenai/iam/internal/registry/pgregistry/gen"
)

// Registry is the Postgres-backed identity registry.
type Registry struct {
	pool *pgxpool.Pool
	q    *gen.Queries
	cfg  registry.Config
}

var _ registry.Registry = (*Registry)(nil)

// New returns a Registry over pool, configured by cfg. The caller owns
// pool's lifetime and must have applied this module's migrations (see
// internal/migrate).
func New(pool *pgxpool.Pool, cfg registry.Config) (*Registry, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: pgregistry: nil connection pool", domain.ErrInvalidConfig)
	}
	normalized, err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	return &Registry{pool: pool, q: gen.New(pool), cfg: normalized}, nil
}

// toPrincipal converts one generated row into the domain aggregate.
//
// The three pointers are the schema's nullable columns. The domain uses a
// zero time.Time and an empty id for "absent", so NULL becomes the zero
// value here rather than being carried any further.
func toPrincipal(row gen.IamPrincipal) domain.Principal {
	p := domain.Principal{
		ID:          row.ID,
		TenantID:    row.TenantID,
		Kind:        row.Kind,
		External:    domain.ExternalSubject{Issuer: row.Issuer, Subject: row.Subject},
		DisplayName: row.DisplayName,
		SyncedAt:    row.SyncedAt,
		CreatedAt:   row.CreatedAt,
	}
	if row.DelegatedBy != nil {
		p.DelegatedBy = *row.DelegatedBy
	}
	if row.ExpiresAt != nil {
		p.ExpiresAt = *row.ExpiresAt
	}
	if row.DeprovisionedAt != nil {
		p.DeprovisionedAt = *row.DeprovisionedAt
	}
	return p
}

// toGroup converts one generated row into the domain aggregate.
func toGroup(row gen.IamGroup) domain.Group {
	return domain.Group{
		ID:        row.ID,
		TenantID:  row.TenantID,
		Name:      row.Name,
		CreatedAt: row.CreatedAt,
	}
}

// toClearanceGroup converts one generated row into the domain aggregate,
// and is the outbound half of the clearance-group id boundary described in
// this package's doc comment: the column is text, and the only route from
// that text to a ClearanceGroupID is the validating parser.
func toClearanceGroup(row gen.IamClearanceGroup) (domain.ClearanceGroup, error) {
	id, err := domain.ParseClearanceGroupID(row.ID)
	if err != nil {
		// Only reachable if a row violating iam.ulid's CHECK exists,
		// which the schema makes impossible. Surfaced as unavailable
		// rather than silently returning a zero id.
		return domain.ClearanceGroup{}, fmt.Errorf("%w: stored clearance group id is malformed", domain.ErrUnavailable)
	}
	return domain.ClearanceGroup{
		ID:        id,
		TenantID:  row.TenantID,
		Name:      row.Name,
		Channel:   row.Channel,
		CreatedAt: row.CreatedAt,
	}, nil
}

// principalKey validates id before it reaches SQL and returns it as a
// bind value.
//
// The validation is not defensive tidiness: iam.ulid is a domain with a
// CHECK constraint, so a malformed id handed to Postgres raises a check
// violation rather than returning no rows — and the port documents a
// malformed id on a lookup path as ErrPrincipalNotFound, not as a
// different error. A caller able to distinguish "that id is well-formed
// but I don't have it" from "that id is nonsense" has a syntax oracle over
// the id space.
func principalKey(id domain.PrincipalID) (domain.PrincipalID, error) {
	parsed, err := domain.ParsePrincipalID(string(id))
	if err != nil {
		return "", fmt.Errorf("%w: %s", domain.ErrPrincipalNotFound, id)
	}
	return parsed, nil
}

// groupKey validates an ordinary group id before it reaches SQL.
func groupKey(id domain.GroupID) (domain.GroupID, error) {
	parsed, err := domain.ParseGroupID(string(id))
	if err != nil {
		return "", fmt.Errorf("%w: group %s", domain.ErrNotFound, id)
	}
	return parsed, nil
}

// clearanceKey validates a clearance group id before it reaches SQL and
// returns the text the column holds. It is the inbound half of the
// clearance-group id boundary: the one place a ClearanceGroupID becomes a
// bind value, and every row carrying one comes back through the parser.
func clearanceKey(id domain.ClearanceGroupID) (string, error) {
	if id.IsZero() {
		return "", fmt.Errorf("%w: clearance group (zero id)", domain.ErrNotFound)
	}
	if _, err := domain.ParseClearanceGroupID(id.String()); err != nil {
		return "", fmt.Errorf("%w: clearance group %s", domain.ErrNotFound, id.String())
	}
	return id.String(), nil
}

// UpsertFromClaims implements registry.Registry.
func (r *Registry) UpsertFromClaims(ctx context.Context, c registry.Claims) (domain.Principal, error) {
	if err := c.Validate(); err != nil {
		return domain.Principal{}, err
	}

	var out domain.Principal
	err := r.inTx(ctx, func(q *gen.Queries) error {
		row, err := q.UpsertPrincipalFromClaims(ctx, gen.UpsertPrincipalFromClaimsParams{
			ID:          domain.NewPrincipalID(r.cfg.Clock),
			TenantID:    c.TenantID,
			Kind:        c.Kind,
			DisplayName: c.DisplayName,
			Issuer:      c.Subject.Issuer,
			Subject:     c.Subject.Subject,
			SyncedAt:    r.cfg.Clock.Now(),
		})
		switch {
		case err == nil:
		case errors.Is(err, pgx.ErrNoRows):
			// The only way to reach here is a conflict the DO UPDATE's
			// WHERE refused, i.e. the stored principal is deprovisioned.
			return fmt.Errorf("%w: %s", domain.ErrPrincipalDeprovisioned, c.Subject)
		default:
			return mapErr(err)
		}

		p := toPrincipal(row)
		if err := r.reconcileClaimGroups(ctx, q, c.TenantID, p.ID, registry.NormalizeClaimGroups(c.Groups)); err != nil {
			return err
		}
		out = p
		return nil
	})
	if err != nil {
		return domain.Principal{}, err
	}
	return out, nil
}

// reconcileClaimGroups brings this principal's claim-sourced memberships
// to exactly want, in the four steps db/queries/groups.sql spells out and
// argues for. The ids minted here are candidates for the groups that do
// not exist yet; the stored ids are read back in step 2 because a conflict
// keeps the stored id rather than the candidate.
func (r *Registry) reconcileClaimGroups(ctx context.Context, q *gen.Queries, tenant domain.TenantID, p domain.PrincipalID, want []string) error {
	ids := make([]string, 0, len(want))
	if len(want) > 0 {
		candidates := make([]string, len(want))
		for i := range want {
			candidates[i] = string(domain.NewGroupID(r.cfg.Clock))
		}
		if err := q.EnsureClaimGroups(ctx, gen.EnsureClaimGroupsParams{
			TenantID: tenant,
			Ids:      candidates,
			Names:    want,
		}); err != nil {
			return mapErr(err)
		}

		resolved, err := q.GroupIDsByName(ctx, gen.GroupIDsByNameParams{TenantID: tenant, Names: want})
		if err != nil {
			return mapErr(err)
		}
		for _, id := range resolved {
			ids = append(ids, string(id))
		}

		if err := q.AddClaimGroupMemberships(ctx, gen.AddClaimGroupMembershipsParams{
			PrincipalID: p,
			GroupIds:    ids,
		}); err != nil {
			return mapErr(err)
		}
	}

	// Run unconditionally, including with an empty ids slice: that is what
	// makes "the token no longer asserts any role" remove every
	// claim-sourced membership.
	return mapErr(q.PruneClaimGroupMemberships(ctx, gen.PruneClaimGroupMembershipsParams{
		PrincipalID: p,
		GroupIds:    ids,
	}))
}

// ResolveExternal implements registry.Registry.
func (r *Registry) ResolveExternal(ctx context.Context, tenant domain.TenantID, s domain.ExternalSubject) (domain.Principal, error) {
	row, err := r.q.PrincipalByExternalSubject(ctx, gen.PrincipalByExternalSubjectParams{
		TenantID: tenant,
		Issuer:   s.Issuer,
		Subject:  s.Subject,
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Principal{}, fmt.Errorf("%w: %s", domain.ErrPrincipalNotFound, s)
	}
	if err != nil {
		return domain.Principal{}, mapErr(err)
	}
	return toPrincipal(row), nil
}

// PrincipalByID implements registry.Registry.
func (r *Registry) PrincipalByID(ctx context.Context, id domain.PrincipalID) (domain.Principal, error) {
	return r.principal(ctx, r.q, id)
}

func (r *Registry) principal(ctx context.Context, q *gen.Queries, id domain.PrincipalID) (domain.Principal, error) {
	key, err := principalKey(id)
	if err != nil {
		return domain.Principal{}, err
	}
	row, err := q.PrincipalByID(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.Principal{}, fmt.Errorf("%w: %s", domain.ErrPrincipalNotFound, id)
	}
	if err != nil {
		return domain.Principal{}, mapErr(err)
	}
	return toPrincipal(row), nil
}

// Condition implements registry.Registry.
func (r *Registry) Condition(ctx context.Context, id domain.PrincipalID, asOf time.Time) (domain.PrincipalCondition, error) {
	p, err := r.principal(ctx, r.q, id)
	if err != nil {
		return domain.PrincipalCondition{}, err
	}
	return domain.EvaluateCondition(p, r.cfg.StalenessBound, asOf), nil
}

// usable returns the principal if it may be used at asOf, or its
// condition's error. Every principal-side membership read passes through
// it, which is what makes the staleness bound an enforcement point rather
// than a caller's responsibility.
func (r *Registry) usable(ctx context.Context, q *gen.Queries, id domain.PrincipalID, asOf time.Time) (domain.Principal, error) {
	p, err := r.principal(ctx, q, id)
	if err != nil {
		return domain.Principal{}, err
	}
	if err := domain.EvaluateCondition(p, r.cfg.StalenessBound, asOf).Err(); err != nil {
		return domain.Principal{}, fmt.Errorf("%w: principal %s", err, id)
	}
	return p, nil
}

// EnsureGroup implements registry.Registry.
func (r *Registry) EnsureGroup(ctx context.Context, tenant domain.TenantID, name string) (domain.Group, error) {
	if tenant == "" || name == "" {
		return domain.Group{}, fmt.Errorf("%w: a group needs a tenant and a non-empty name", domain.ErrConflict)
	}
	if err := r.q.EnsureGroup(ctx, gen.EnsureGroupParams{
		ID:       domain.NewGroupID(r.cfg.Clock),
		TenantID: tenant,
		Name:     name,
	}); err != nil {
		return domain.Group{}, mapErr(err)
	}

	row, err := r.q.GroupByName(ctx, gen.GroupByNameParams{TenantID: tenant, Name: name})
	if err != nil {
		return domain.Group{}, mapErr(err)
	}
	return toGroup(row), nil
}

// requireGroup resolves an ordinary group id, distinguishing "this id
// names a clearance group" (ErrGroupKindMismatch — a tier confusion) from
// "this id names nothing" (ErrNotFound — a typo). An operator needs to be
// told which, and merging them would hide exactly the mistake design §8.3
// is about.
func (r *Registry) requireGroup(ctx context.Context, q *gen.Queries, id domain.GroupID) error {
	key, err := groupKey(id)
	if err != nil {
		return err
	}
	kind, err := r.idKind(ctx, q, string(key))
	if err != nil {
		return err
	}
	switch kind {
	case kindGroup:
		return nil
	case kindClearance:
		return fmt.Errorf("%w: %s names a clearance group, which may never be referenced as a tier-1 group", domain.ErrGroupKindMismatch, id)
	default:
		return fmt.Errorf("%w: group %s", domain.ErrNotFound, id)
	}
}

// requireClearanceGroup resolves a clearance group id, with the mirror of
// requireGroup's reasoning, and returns the group so its channel can be
// checked against the act.
func (r *Registry) requireClearanceGroup(ctx context.Context, q *gen.Queries, id domain.ClearanceGroupID) (domain.ClearanceGroup, error) {
	key, err := clearanceKey(id)
	if err != nil {
		return domain.ClearanceGroup{}, err
	}
	row, err := q.ClearanceGroupByID(ctx, key)
	switch {
	case err == nil:
		return toClearanceGroup(row)
	case !errors.Is(err, pgx.ErrNoRows):
		return domain.ClearanceGroup{}, mapErr(err)
	}

	kind, err := r.idKind(ctx, q, key)
	if err != nil {
		return domain.ClearanceGroup{}, err
	}
	if kind == kindGroup {
		return domain.ClearanceGroup{}, fmt.Errorf("%w: %s names an ordinary tier-1 group, which may never hold a clearance", domain.ErrGroupKindMismatch, key)
	}
	return domain.ClearanceGroup{}, fmt.Errorf("%w: clearance group %s", domain.ErrNotFound, key)
}

// idKind names which namespace an id belongs to.
type idKind string

const (
	kindNone      idKind = ""
	kindGroup     idKind = "group"
	kindClearance idKind = "clearance"
)

// idKind asks both namespaces in one statement; see IDKind in
// db/queries/groups.sql for why, and for why its parameter is deliberately
// neither of this module's typed group ids.
func (r *Registry) idKind(ctx context.Context, q *gen.Queries, key string) (idKind, error) {
	kind, err := q.IDKind(ctx, key)
	if errors.Is(err, pgx.ErrNoRows) {
		return kindNone, nil
	}
	if err != nil {
		return kindNone, mapErr(err)
	}
	return idKind(kind), nil
}

// AddGroupMember implements registry.Registry.
func (r *Registry) AddGroupMember(ctx context.Context, g domain.GroupID, p domain.PrincipalID) error {
	return r.inTx(ctx, func(q *gen.Queries) error {
		if err := r.requireGroup(ctx, q, g); err != nil {
			return err
		}
		principal, err := r.principal(ctx, q, p)
		if err != nil {
			return err
		}
		if !principal.DeprovisionedAt.IsZero() {
			return fmt.Errorf("%w: %s", domain.ErrPrincipalDeprovisioned, p)
		}
		return mapErr(q.AddLocalGroupMember(ctx, gen.AddLocalGroupMemberParams{
			GroupID:     g,
			PrincipalID: principal.ID,
		}))
	})
}

// RemoveGroupMember implements registry.Registry.
func (r *Registry) RemoveGroupMember(ctx context.Context, g domain.GroupID, p domain.PrincipalID) error {
	return r.inTx(ctx, func(q *gen.Queries) error {
		if err := r.requireGroup(ctx, q, g); err != nil {
			return err
		}
		key, err := principalKey(p)
		if err != nil {
			// Removing a membership for a malformed principal id is a
			// no-op, not a refusal: removal is documented idempotent,
			// and there is nothing to remove.
			return nil
		}
		return mapErr(q.RemoveGroupMember(ctx, gen.RemoveGroupMemberParams{
			GroupID:     g,
			PrincipalID: key,
		}))
	})
}

// GroupsOf implements registry.Registry.
func (r *Registry) GroupsOf(ctx context.Context, p domain.PrincipalID, asOf time.Time) ([]domain.Group, error) {
	if _, err := r.usable(ctx, r.q, p, asOf); err != nil {
		return nil, err
	}
	rows, err := r.q.GroupsOfPrincipal(ctx, p)
	if err != nil {
		return nil, mapErr(err)
	}

	var out []domain.Group
	for _, row := range rows {
		out = append(out, toGroup(row))
	}
	return out, nil
}

// GroupMembers implements registry.Registry.
func (r *Registry) GroupMembers(ctx context.Context, g domain.GroupID, asOf time.Time) ([]domain.PrincipalID, error) {
	if err := r.requireGroup(ctx, r.q, g); err != nil {
		return nil, err
	}
	rows, err := r.q.GroupMemberPrincipals(ctx, g)
	if err != nil {
		return nil, mapErr(err)
	}
	return r.usableMembers(rows, asOf), nil
}

// usableMembers filters a member projection to the principals usable at
// asOf.
//
// Filtering in Go, against domain.EvaluateCondition, is the deliberate
// choice described in the package doc comment: it is the same rule the
// in-memory adapter applies, from the same function, so the two cannot
// disagree about when a principal goes stale.
func (r *Registry) usableMembers(rows []gen.IamPrincipal, asOf time.Time) []domain.PrincipalID {
	var out []domain.PrincipalID
	for _, row := range rows {
		p := toPrincipal(row)
		if domain.EvaluateCondition(p, r.cfg.StalenessBound, asOf).Usable() {
			out = append(out, p.ID)
		}
	}
	return out
}

// EnsureClearanceGroup implements registry.Registry.
func (r *Registry) EnsureClearanceGroup(ctx context.Context, act domain.MandatoryAct, tenant domain.TenantID, name string) (domain.ClearanceGroup, error) {
	if err := registry.RequireMandatoryAct(act); err != nil {
		return domain.ClearanceGroup{}, err
	}
	if tenant == "" || name == "" {
		return domain.ClearanceGroup{}, fmt.Errorf("%w: a clearance group needs a tenant and a non-empty name", domain.ErrConflict)
	}

	var out domain.ClearanceGroup
	err := r.inTx(ctx, func(q *gen.Queries) error {
		row, err := q.ClearanceGroupByName(ctx, gen.ClearanceGroupByNameParams{TenantID: tenant, Name: name})
		switch {
		case err == nil:
			cg, err := toClearanceGroup(row)
			if err != nil {
				return err
			}
			if cg.Channel != act.Channel() {
				return registry.ChannelMismatchError(cg, act)
			}
			out = cg
			return nil
		case !errors.Is(err, pgx.ErrNoRows):
			return mapErr(err)
		}

		created, err := q.CreateClearanceGroup(ctx, gen.CreateClearanceGroupParams{
			ID:       domain.NewClearanceGroupID(r.cfg.Clock).String(),
			TenantID: tenant,
			Name:     name,
			Channel:  act.Channel(),
		})
		if err != nil {
			return mapErr(err)
		}
		cg, err := toClearanceGroup(created)
		if err != nil {
			return err
		}
		if err := r.record(ctx, q, cg.ID, "", domain.ClearanceChangeCreated, act); err != nil {
			return err
		}
		out = cg
		return nil
	})
	if err != nil {
		return domain.ClearanceGroup{}, err
	}
	return out, nil
}

// AddClearanceGroupMember implements registry.Registry.
func (r *Registry) AddClearanceGroupMember(ctx context.Context, act domain.MandatoryAct, g domain.ClearanceGroupID, p domain.PrincipalID) error {
	return r.changeClearanceMembership(ctx, act, g, p, domain.ClearanceChangeAdded)
}

// RemoveClearanceGroupMember implements registry.Registry.
func (r *Registry) RemoveClearanceGroupMember(ctx context.Context, act domain.MandatoryAct, g domain.ClearanceGroupID, p domain.PrincipalID) error {
	return r.changeClearanceMembership(ctx, act, g, p, domain.ClearanceChangeRemoved)
}

// changeClearanceMembership is the one path into a clearance group's
// membership, shared by the add and remove methods so neither can acquire
// a weaker precondition than the other. The membership write and its trail
// entry are one transaction: a clearance that is held with no record of
// who granted it is the failure design §8.3's audit requirement exists to
// prevent.
func (r *Registry) changeClearanceMembership(ctx context.Context, act domain.MandatoryAct, g domain.ClearanceGroupID, p domain.PrincipalID, kind domain.ClearanceChangeKind) error {
	if err := registry.RequireMandatoryAct(act); err != nil {
		return err
	}
	return r.inTx(ctx, func(q *gen.Queries) error {
		cg, err := r.requireClearanceGroup(ctx, q, g)
		if err != nil {
			return err
		}
		if cg.Channel != act.Channel() {
			return registry.ChannelMismatchError(cg, act)
		}
		principal, err := r.principal(ctx, q, p)
		if err != nil {
			return err
		}
		if kind == domain.ClearanceChangeAdded && !principal.DeprovisionedAt.IsZero() {
			return fmt.Errorf("%w: %s", domain.ErrPrincipalDeprovisioned, p)
		}

		switch kind {
		case domain.ClearanceChangeAdded:
			if err := q.AddClearanceGroupMember(ctx, gen.AddClearanceGroupMemberParams{
				ClearanceGroupID: cg.ID.String(),
				PrincipalID:      principal.ID,
				Channel:          act.Channel(),
				ActorPrincipalID: act.Actor(),
				Reason:           act.Reason(),
				ActedAt:          act.At(),
			}); err != nil {
				return mapErr(err)
			}
		case domain.ClearanceChangeRemoved:
			if err := q.RemoveClearanceGroupMember(ctx, gen.RemoveClearanceGroupMemberParams{
				ClearanceGroupID: cg.ID.String(),
				PrincipalID:      principal.ID,
			}); err != nil {
				return mapErr(err)
			}
		case domain.ClearanceChangeCreated:
			return fmt.Errorf("%w: creation is recorded by EnsureClearanceGroup", domain.ErrConflict)
		}

		// Recorded even when the membership did not change: "someone
		// re-asserted this clearance, and why" is itself the audit
		// record, and so is a withdrawal of a clearance not held.
		return r.record(ctx, q, cg.ID, p, kind, act)
	})
}

// record appends one entry to a clearance group's trail. Nothing in this
// package updates or deletes one, and the table refuses to be edited
// anyway (see the append-only trigger in 00002_identity.sql).
func (r *Registry) record(ctx context.Context, q *gen.Queries, g domain.ClearanceGroupID, p domain.PrincipalID, kind domain.ClearanceChangeKind, act domain.MandatoryAct) error {
	var principal *domain.PrincipalID
	if p != "" {
		principal = &p
	}
	return mapErr(q.RecordClearanceChange(ctx, gen.RecordClearanceChangeParams{
		ID:               domain.NewChangeID(r.cfg.Clock),
		ClearanceGroupID: g.String(),
		PrincipalID:      principal,
		Kind:             kind,
		Channel:          act.Channel(),
		ActorPrincipalID: act.Actor(),
		Reason:           act.Reason(),
		ActedAt:          act.At(),
		RecordedAt:       r.cfg.Clock.Now(),
	}))
}

// ClearanceGroupsOf implements registry.Registry.
func (r *Registry) ClearanceGroupsOf(ctx context.Context, p domain.PrincipalID, asOf time.Time) ([]domain.ClearanceGroup, error) {
	if _, err := r.usable(ctx, r.q, p, asOf); err != nil {
		return nil, err
	}
	rows, err := r.q.ClearanceGroupsOfPrincipal(ctx, p)
	if err != nil {
		return nil, mapErr(err)
	}

	var out []domain.ClearanceGroup
	for _, row := range rows {
		cg, err := toClearanceGroup(row)
		if err != nil {
			return nil, err
		}
		out = append(out, cg)
	}
	return out, nil
}

// ClearanceGroupMembers implements registry.Registry.
func (r *Registry) ClearanceGroupMembers(ctx context.Context, g domain.ClearanceGroupID, asOf time.Time) ([]domain.PrincipalID, error) {
	cg, err := r.requireClearanceGroup(ctx, r.q, g)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ClearanceGroupMemberPrincipals(ctx, cg.ID.String())
	if err != nil {
		return nil, mapErr(err)
	}
	return r.usableMembers(rows, asOf), nil
}

// ClearanceGroupChanges implements registry.Registry.
//
// The trail comes back in seq order, which is the query's job and not this
// method's; see ClearanceGroupChanges in db/queries/clearance.sql for why
// the ULID is not the ordering.
func (r *Registry) ClearanceGroupChanges(ctx context.Context, g domain.ClearanceGroupID) ([]domain.ClearanceChange, error) {
	cg, err := r.requireClearanceGroup(ctx, r.q, g)
	if err != nil {
		return nil, err
	}
	rows, err := r.q.ClearanceGroupChanges(ctx, cg.ID.String())
	if err != nil {
		return nil, mapErr(err)
	}

	var out []domain.ClearanceChange
	for _, row := range rows {
		c := domain.ClearanceChange{
			ID:               row.ID,
			ClearanceGroupID: cg.ID,
			Kind:             row.Kind,
			Channel:          row.Channel,
			Actor:            row.ActorPrincipalID,
			Reason:           row.Reason,
			ActedAt:          row.ActedAt,
			RecordedAt:       row.RecordedAt,
		}
		if row.PrincipalID != nil {
			c.PrincipalID = *row.PrincipalID
		}
		out = append(out, c)
	}
	return out, nil
}

// DelegateAgentRun implements registry.Registry.
func (r *Registry) DelegateAgentRun(ctx context.Context, parent domain.PrincipalID, spec registry.AgentRunSpec) (domain.Principal, error) {
	if err := registry.ValidateAgentRunSpec(spec, r.cfg.MaxAgentRunTTL); err != nil {
		return domain.Principal{}, err
	}

	var out domain.Principal
	err := r.inTx(ctx, func(q *gen.Queries) error {
		now := r.cfg.Clock.Now()
		// The parent must be usable, not merely present: a principal too
		// stale to decide with is too stale to delegate from, and a
		// deprovisioned one must not be able to leave a live agent run
		// behind it.
		p, err := r.usable(ctx, q, parent, now)
		if err != nil {
			return err
		}
		if p.Kind == domain.PrincipalKindAgentRun {
			return fmt.Errorf("%w: an agent run may not delegate a further agent run; delegation depth is captoken's object", domain.ErrInvalidPrincipal)
		}

		run, err := q.CreateAgentRun(ctx, gen.CreateAgentRunParams{
			ID:          domain.NewPrincipalID(r.cfg.Clock),
			TenantID:    p.TenantID,
			DisplayName: spec.DisplayName,
			DelegatedBy: string(p.ID),
			ExpiresAt:   now.Add(spec.TTL),
			SyncedAt:    now,
		})
		if err != nil {
			return mapErr(err)
		}
		out = toPrincipal(run)
		return nil
	})
	if err != nil {
		return domain.Principal{}, err
	}
	return out, nil
}

// CollectExpiredAgentRuns implements registry.Registry.
func (r *Registry) CollectExpiredAgentRuns(ctx context.Context, asOf time.Time) (int, error) {
	collected, err := r.q.CollectExpiredAgentRuns(ctx, asOf)
	if err != nil {
		return 0, mapErr(err)
	}
	return int(collected), nil
}

// Deprovision implements registry.Registry.
func (r *Registry) Deprovision(ctx context.Context, p domain.PrincipalID) error {
	return r.inTx(ctx, func(q *gen.Queries) error {
		principal, err := r.principal(ctx, q, p)
		if err != nil {
			return err
		}
		if !principal.DeprovisionedAt.IsZero() {
			// Idempotent, and the original instant is kept: moving it
			// would rewrite when access actually stopped.
			return nil
		}
		return mapErr(q.DeprovisionPrincipalAndAgentRuns(ctx, gen.DeprovisionPrincipalAndAgentRunsParams{
			ID:              principal.ID,
			DeprovisionedAt: r.cfg.Clock.Now(),
		}))
	})
}

// inTx runs fn inside a transaction, rolling back on any error, and hands
// it a *gen.Queries bound to that transaction so a statement reads the
// same whether it runs standalone or inside one.
//
// Every multi-statement operation in this package goes through it, because
// each one has an invariant that spans its statements: a principal and its
// reconciled membership, a clearance membership and its trail entry, a
// deprovisioning and its cascade. A partially applied write in any of the
// three is a security defect rather than an inconsistency.
func (r *Registry) inTx(ctx context.Context, fn func(q *gen.Queries) error) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return mapErr(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := fn(r.q.WithTx(tx)); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return mapErr(err)
	}
	return nil
}
