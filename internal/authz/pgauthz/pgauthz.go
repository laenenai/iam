// Package pgauthz is the Postgres-backed authz.Authorizer: the deployment
// adapter, and the one that actually has to make a decision answerable
// inside a SQL statement. It passes iamtest.RunAuthorizerSuite unchanged.
//
// What it adds over the in-memory adapter is not behaviour but
// enforcement. The in-memory adapter proves the contract; only this one
// proves the schema — that containment is a tree because there is one
// parent column and no statement that updates it, that no containment
// edge or grant can cross a tenant because each is a composite foreign
// key, that the closure's size is a function of hierarchy depth, and that
// a decision resolves on an index join rather than a scan. See
// db/migrations/00003_authorization.sql for the schema's reasoning and
// pgauthz_test.go for the properties that only exist against real
// Postgres.
//
// # Every method runs in a transaction, including the reads
//
// These tables carry `tenancy`'s restrictive row-level-security policy, so
// a statement with no tenant session context returns zero rows rather than
// failing. Establishing that context means `set_config(…, is_local =>
// true)`, and `is_local` only means anything inside a transaction: set
// non-locally on a pooled connection it would outlive the call, and the
// next borrower of that connection would inherit somebody else's tenant.
// There is no safe way to set it outside a transaction, so there is no way
// to read without one.
//
// That costs round trips — BEGIN, set_config, the statement, COMMIT — and
// the cost is stated rather than hidden. It is the same cost `tenancy`'s
// own data plane pays for every statement it runs, for the same reason,
// and the thing it buys is that the grant and closure tables cannot be
// read across a tenant boundary even by a hand-written statement that
// forgot to scope itself.
//
// Read transactions are REPEATABLE READ and READ ONLY. The isolation level
// is not caution: a decision reads the change log's head and then the
// grants, and under READ COMMITTED those are two snapshots, so the
// revision could describe a state newer than the answer it is attached to.
// One snapshot makes the revision exact.
//
// # Where the SQL lives
//
// Every statement here is in db/queries/authz/authz.sql and reaches Go
// through sqlc, type-checked against db/migrations at generation time.
// Each statement's reasoning lives beside it, because the statement is the
// artifact being reasoned about and a comment in Go next to a string
// literal is one edit away from describing a different query.
//
// The one exception is render.go, which composes the residual into SQL. It
// has no fixed shape — the column it filters on belongs to the consumer —
// so there is nothing for sqlc to generate. CONVENTIONS names exactly this
// case as the standing exception and requires the text to be kept in one
// place, which render.go does.
package pgauthz

import (
	"context"
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/laenenai/tenancy"

	"github.com/laenenai/iam/internal/authz"
	"github.com/laenenai/iam/internal/authz/pgauthz/gen"
	"github.com/laenenai/iam/internal/domain"
)

// changeLogLockKey is the first argument of the two-argument advisory lock
// every closure-affecting write takes. It is the CRC32 (IEEE) checksum of
// this adapter's own package path, truncated to int32 because
// pg_advisory_xact_lock's two-argument form takes two int4s:
//
//	crc32.ChecksumIEEE([]byte("github.com/laenenai/iam/internal/authz"))
//
// It is a fixed value and must never change. Changing it would let an old
// and a new binary assign revisions concurrently during a rolling deploy,
// which is the race the lock exists to prevent, and the symptom would be a
// duplicate-key failure rather than a silent gap — which is the one mercy
// in it.
const changeLogLockKey int32 = 1761292422

// Authorizer is the Postgres-backed authorization layer.
type Authorizer struct {
	pool *pgxpool.Pool
	q    *gen.Queries
	cfg  authz.Config

	// schemas holds the registered declarations for this process. They
	// are not persisted: see the authz package doc on what §8.4's absent
	// schema versioning costs. The mutex is separate from the database
	// because registration touches no rows.
	schemas *schemaSet
}

var _ authz.Authorizer = (*Authorizer)(nil)

// New returns an Authorizer over pool, configured by cfg. The caller owns
// pool's lifetime and must have applied this module's migrations
// (internal/migrate), which is also what asserts the row-level-security
// policy these statements depend on.
func New(pool *pgxpool.Pool, cfg authz.Config) (*Authorizer, error) {
	if pool == nil {
		return nil, fmt.Errorf("%w: pgauthz: nil connection pool", domain.ErrInvalidConfig)
	}
	normalized, err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	return &Authorizer{
		pool:    pool,
		q:       gen.New(pool),
		cfg:     normalized,
		schemas: newSchemaSet(),
	}, nil
}

// RegisterSchema implements authz.Authorizer.
func (a *Authorizer) RegisterSchema(ctx context.Context, s domain.Schema) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := s.Validate(); err != nil {
		return err
	}
	a.schemas.put(s)
	return nil
}

// read runs fn inside a repeatable-read, read-only transaction that has
// established tenant's session context.
func (a *Authorizer) read(ctx context.Context, tenant domain.TenantID, fn func(*gen.Queries) error) error {
	return a.inTenantTx(ctx, tenant, pgx.TxOptions{
		IsoLevel:   pgx.RepeatableRead,
		AccessMode: pgx.ReadOnly,
	}, fn)
}

// write runs fn inside a read-write transaction that has established
// tenant's session context. It is READ COMMITTED on purpose: the ordering
// a write needs comes from the advisory lock, not from the isolation
// level, and REPEATABLE READ would turn a concurrent grant into a
// serialization failure the caller would have to retry for no benefit.
func (a *Authorizer) write(ctx context.Context, tenant domain.TenantID, fn func(*gen.Queries) error) error {
	return a.inTenantTx(ctx, tenant, pgx.TxOptions{}, fn)
}

// inTenantTx is the one place a tenant session context is established, so
// that no method can forget to.
func (a *Authorizer) inTenantTx(ctx context.Context, tenant domain.TenantID, opts pgx.TxOptions, fn func(*gen.Queries) error) error {
	if tenant == "" {
		return fmt.Errorf("%w: empty tenant id", domain.ErrInvalidRequest)
	}
	tx, err := a.pool.BeginTx(ctx, opts)
	if err != nil {
		return mapErr(err)
	}
	// Rollback on every path that does not reach Commit. A committed
	// transaction's Rollback is a no-op, so this is unconditional rather
	// than conditional, which is one fewer branch to get wrong.
	defer func() { _ = tx.Rollback(ctx) }()

	q := a.q.WithTx(tx)
	if err := q.SetTenantContext(ctx, gen.SetTenantContextParams{
		Name:  tenancy.TenantGUC,
		Value: string(tenant),
	}); err != nil {
		return mapErr(err)
	}
	if err := fn(q); err != nil {
		return err
	}
	return mapErr(tx.Commit(ctx))
}

// CreateContainer implements authz.Authorizer.
func (a *Authorizer) CreateContainer(ctx context.Context, spec domain.ContainerSpec) (domain.Container, error) {
	if err := ctx.Err(); err != nil {
		return domain.Container{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := spec.Validate(); err != nil {
		return domain.Container{}, err
	}
	kind, ok := a.schemas.kind(spec.Kind)
	if !ok {
		return domain.Container{}, fmt.Errorf("%w: no registered schema declares container kind %q", domain.ErrSchemaNotRegistered, spec.Kind)
	}
	parentKind, declaresParent := kind.ParentKind()
	switch {
	case spec.Parent == "" && declaresParent:
		return domain.Container{}, fmt.Errorf("%w: kind %q is declared inside %q, so it cannot be a root", domain.ErrInvalidContainer, spec.Kind, parentKind)
	case spec.Parent != "" && !declaresParent:
		return domain.Container{}, fmt.Errorf("%w: kind %q is declared as a root kind, so it cannot be placed inside a container", domain.ErrInvalidContainer, spec.Kind)
	}

	now := domain.Canonical(a.cfg.Clock.Now())
	container := domain.Container{
		ID:        domain.NewContainerID(a.cfg.Clock),
		TenantID:  spec.TenantID,
		Kind:      spec.Kind,
		Parent:    spec.Parent,
		Label:     spec.Label,
		CreatedAt: now,
	}

	err := a.write(ctx, spec.TenantID, func(q *gen.Queries) error {
		if spec.Parent != "" {
			parent, err := q.ContainerByID(ctx, gen.ContainerByIDParams{ID: spec.Parent, TenantID: spec.TenantID})
			if err != nil {
				if errors.Is(mapErr(err), domain.ErrNotFound) {
					// Another tenant's container is not found, and the
					// policy has already made it unreadable, so this
					// error is the same one either way. Telling the two
					// apart would be a cross-tenant existence oracle.
					return fmt.Errorf("%w: container %s", domain.ErrNotFound, spec.Parent)
				}
				return mapErr(err)
			}
			if parent.Kind != parentKind {
				return fmt.Errorf("%w: kind %q is declared inside %q, but container %s is a %q",
					domain.ErrInvalidContainer, spec.Kind, parentKind, spec.Parent, parent.Kind)
			}
		}

		var parent *domain.ContainerID
		if spec.Parent != "" {
			p := spec.Parent
			parent = &p
		}
		if _, err := q.InsertContainer(ctx, gen.InsertContainerParams{
			ID:        container.ID,
			TenantID:  container.TenantID,
			Kind:      container.Kind,
			ParentID:  parent,
			Label:     container.Label,
			CreatedAt: container.CreatedAt,
		}); err != nil {
			return mapErr(err)
		}
		if err := q.InsertClosureSelf(ctx, gen.InsertClosureSelfParams{
			TenantID:    container.TenantID,
			ContainerID: container.ID,
		}); err != nil {
			return mapErr(err)
		}
		if spec.Parent != "" {
			if err := q.InsertClosureFromParent(ctx, gen.InsertClosureFromParentParams{
				TenantID:    container.TenantID,
				ContainerID: container.ID,
				ParentID:    spec.Parent,
			}); err != nil {
				return mapErr(err)
			}
		}
		_, err := a.appendChange(ctx, q, domain.Change{
			TenantID:   container.TenantID,
			Kind:       domain.ChangeContainerCreated,
			Container:  container.ID,
			RecordedAt: now,
		})
		return err
	})
	if err != nil {
		return domain.Container{}, err
	}
	return container, nil
}

// Container implements authz.Authorizer.
func (a *Authorizer) Container(ctx context.Context, tenant domain.TenantID, id domain.ContainerID) (domain.Container, error) {
	if id == "" {
		return domain.Container{}, fmt.Errorf("%w: container %s", domain.ErrNotFound, id)
	}
	var out domain.Container
	err := a.read(ctx, tenant, func(q *gen.Queries) error {
		row, err := q.ContainerByID(ctx, gen.ContainerByIDParams{ID: id, TenantID: tenant})
		if err != nil {
			if errors.Is(mapErr(err), domain.ErrNotFound) {
				return fmt.Errorf("%w: container %s", domain.ErrNotFound, id)
			}
			return mapErr(err)
		}
		out = toContainer(row)
		return nil
	})
	if err != nil {
		return domain.Container{}, err
	}
	return out, nil
}

// Ancestors implements authz.Authorizer.
func (a *Authorizer) Ancestors(ctx context.Context, tenant domain.TenantID, id domain.ContainerID) ([]domain.ContainerID, error) {
	var out []domain.ContainerID
	err := a.read(ctx, tenant, func(q *gen.Queries) error {
		// The closure read back. The container's own reflexive row is in
		// it, so an empty result means the container does not exist in
		// this tenant rather than that it has no ancestors — which is
		// also why this does not need a separate existence check.
		ids, err := q.Ancestors(ctx, gen.AncestorsParams{ContainerID: id, TenantID: tenant})
		if err != nil {
			return mapErr(err)
		}
		if len(ids) == 0 {
			return fmt.Errorf("%w: container %s", domain.ErrNotFound, id)
		}
		out = ids
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Grant implements authz.Authorizer.
func (a *Authorizer) Grant(ctx context.Context, spec domain.GrantSpec) (domain.Revision, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := spec.Validate(); err != nil {
		return 0, err
	}
	if !a.schemas.declaresPermission(spec.Permission) {
		return 0, fmt.Errorf("%w: no registered schema declares permission %q; a misspelled permission is a grant that silently never fires", domain.ErrSchemaNotRegistered, spec.Permission)
	}

	now := domain.Canonical(a.cfg.Clock.Now())
	principal, group := splitSubject(spec.Subject)

	var rev domain.Revision
	err := a.write(ctx, spec.TenantID, func(q *gen.Queries) error {
		if _, err := q.ContainerByID(ctx, gen.ContainerByIDParams{ID: spec.Container, TenantID: spec.TenantID}); err != nil {
			if errors.Is(mapErr(err), domain.ErrNotFound) {
				return fmt.Errorf("%w: container %s", domain.ErrNotFound, spec.Container)
			}
			return mapErr(err)
		}
		if err := a.checkSubject(ctx, q, spec); err != nil {
			return err
		}

		rows, err := q.InsertGrant(ctx, gen.InsertGrantParams{
			TenantID:    spec.TenantID,
			ContainerID: spec.Container,
			Permission:  spec.Permission,
			PrincipalID: principal,
			GroupID:     group,
			GrantedAt:   now,
		})
		if err != nil {
			return mapErr(err)
		}
		if rows == 0 {
			// The grant already existed. Idempotent, and deliberately
			// not logged: an entry for a write that changed nothing
			// makes a projection do work for no reason and makes the
			// log's length a function of retries.
			rev, err = a.headRevision(ctx, q, spec.TenantID)
			return err
		}
		rev, err = a.appendChange(ctx, q, domain.Change{
			TenantID:   spec.TenantID,
			Kind:       domain.ChangeGrantWritten,
			Container:  spec.Container,
			Permission: spec.Permission,
			Subject:    spec.Subject,
			RecordedAt: now,
		})
		return err
	})
	if err != nil {
		return 0, err
	}
	return rev, nil
}

// checkSubject refuses a grant whose subject does not exist in this
// tenant. The composite foreign keys in the schema refuse it too; those
// are the guarantee and this is the diagnosis, because a foreign-key
// violation names a constraint and not what the caller got wrong.
//
// An unknown subject and another tenant's subject are the same answer.
func (a *Authorizer) checkSubject(ctx context.Context, q *gen.Queries, spec domain.GrantSpec) error {
	if p, ok := spec.Subject.Principal(); ok {
		tenant, err := q.PrincipalTenantID(ctx, p)
		switch {
		case errors.Is(mapErr(err), domain.ErrNotFound):
			return fmt.Errorf("%w: grant names principal %s", domain.ErrNotFound, p)
		case err != nil:
			return mapErr(err)
		case tenant != spec.TenantID:
			return fmt.Errorf("%w: grant names principal %s", domain.ErrNotFound, p)
		}
		return nil
	}
	g, _ := spec.Subject.Group()
	tenant, err := q.GroupTenantID(ctx, g)
	switch {
	case errors.Is(mapErr(err), domain.ErrNotFound):
		return fmt.Errorf("%w: grant names group %s", domain.ErrNotFound, g)
	case err != nil:
		return mapErr(err)
	case tenant != spec.TenantID:
		return fmt.Errorf("%w: grant names group %s", domain.ErrNotFound, g)
	}
	return nil
}

// Revoke implements authz.Authorizer.
func (a *Authorizer) Revoke(ctx context.Context, spec domain.GrantSpec) (domain.Revision, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := spec.Validate(); err != nil {
		return 0, err
	}
	principal, group := splitSubject(spec.Subject)

	var rev domain.Revision
	err := a.write(ctx, spec.TenantID, func(q *gen.Queries) error {
		rows, err := q.DeleteGrant(ctx, gen.DeleteGrantParams{
			TenantID:    spec.TenantID,
			ContainerID: spec.Container,
			Permission:  spec.Permission,
			PrincipalID: principal,
			GroupID:     group,
		})
		if err != nil {
			return mapErr(err)
		}
		if rows == 0 {
			rev, err = a.headRevision(ctx, q, spec.TenantID)
			return err
		}
		rev, err = a.appendChange(ctx, q, domain.Change{
			TenantID:   spec.TenantID,
			Kind:       domain.ChangeGrantRevoked,
			Container:  spec.Container,
			Permission: spec.Permission,
			Subject:    spec.Subject,
			RecordedAt: domain.Canonical(a.cfg.Clock.Now()),
		})
		return err
	})
	if err != nil {
		return 0, err
	}
	return rev, nil
}

// GrantsOn implements authz.Authorizer.
func (a *Authorizer) GrantsOn(ctx context.Context, tenant domain.TenantID, container domain.ContainerID) ([]domain.Grant, error) {
	var out []domain.Grant
	err := a.read(ctx, tenant, func(q *gen.Queries) error {
		if _, err := q.ContainerByID(ctx, gen.ContainerByIDParams{ID: container, TenantID: tenant}); err != nil {
			if errors.Is(mapErr(err), domain.ErrNotFound) {
				return fmt.Errorf("%w: container %s", domain.ErrNotFound, container)
			}
			return mapErr(err)
		}
		rows, err := q.GrantsOnContainer(ctx, gen.GrantsOnContainerParams{ContainerID: container, TenantID: tenant})
		if err != nil {
			return mapErr(err)
		}
		out = make([]domain.Grant, 0, len(rows))
		for _, row := range rows {
			out = append(out, toGrant(row))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Decide implements authz.Authorizer.
//
// The revision is read before the grants, inside the same repeatable-read
// snapshot, so the value reported is exactly the state the answer was
// computed against rather than a later one.
func (a *Authorizer) Decide(ctx context.Context, req domain.Request) (domain.Decision, error) {
	if err := ctx.Err(); err != nil {
		return domain.Decision{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := req.Validate(); err != nil {
		return domain.Decision{}, err
	}

	var decision domain.Decision
	err := a.read(ctx, req.TenantID, func(q *gen.Queries) error {
		rev, err := a.headRevision(ctx, q, req.TenantID)
		if err != nil {
			return err
		}
		rows, err := q.Decide(ctx, gen.DecideParams{
			Permission:  req.Permission,
			ContainerID: req.Container,
			TenantID:    req.TenantID,
			PrincipalID: req.Principal,
		})
		if err != nil {
			return mapErr(err)
		}
		if len(rows) == 0 {
			// An unknown container, an unknown principal, an undeclared
			// permission and a principal with no grants are one answer.
			// That is what keeps this from being an existence oracle, and
			// it is why a denial is a Decision rather than an error.
			decision = domain.Deny(rev)
			return nil
		}
		row := rows[0]
		decision = domain.Allow(domain.Grant{
			TenantID:   req.TenantID,
			Container:  row.ContainerID,
			Permission: row.Permission,
			Subject:    joinSubject(row.PrincipalID, row.GroupID),
			GrantedAt:  domain.Canonical(row.GrantedAt),
		}, int(row.Depth), rev)
		return nil
	})
	if err != nil {
		return domain.Decision{}, err
	}
	return decision, nil
}

// Filter implements authz.Authorizer.
func (a *Authorizer) Filter(ctx context.Context, req authz.FilterRequest) (domain.Residual, error) {
	if err := ctx.Err(); err != nil {
		return domain.Residual{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := req.Validate(); err != nil {
		return domain.Residual{}, err
	}

	var residual domain.Residual
	err := a.read(ctx, req.TenantID, func(q *gen.Queries) error {
		rev, err := a.headRevision(ctx, q, req.TenantID)
		if err != nil {
			return err
		}
		residual, err = authz.BuildResidual(req, rev, a.schemas.declaresPermission(req.Permission))
		return err
	})
	if err != nil {
		return domain.Residual{}, err
	}
	return residual, nil
}

// Changes implements authz.Authorizer.
func (a *Authorizer) Changes(ctx context.Context, tenant domain.TenantID, after domain.Revision, limit int) ([]domain.Change, error) {
	limit = authz.NormalizeChangeLimit(limit)

	var out []domain.Change
	err := a.read(ctx, tenant, func(q *gen.Queries) error {
		if after > math.MaxInt64 {
			// Unreachable against any real log — the column is a bigint
			// and the revision is assigned as max+1 — and it is checked
			// because the conversion below is from an unsigned type,
			// where an out-of-range cursor would silently become a
			// negative one and return the whole log instead of nothing.
			return fmt.Errorf("%w: cursor %d is beyond any revision this log can hold", domain.ErrInvalidRequest, after)
		}
		rows, err := q.ChangesAfter(ctx, gen.ChangesAfterParams{
			TenantID: tenant,
			After:    int64(after), //nolint:gosec // bounded above
			PageSize: int32(limit), //nolint:gosec // bounded by NormalizeChangeLimit
		})
		if err != nil {
			return mapErr(err)
		}
		out = make([]domain.Change, 0, len(rows))
		for _, row := range rows {
			out = append(out, toChange(row))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Revision implements authz.Authorizer.
func (a *Authorizer) Revision(ctx context.Context, tenant domain.TenantID) (domain.Revision, error) {
	var rev domain.Revision
	err := a.read(ctx, tenant, func(q *gen.Queries) error {
		var err error
		rev, err = a.headRevision(ctx, q, tenant)
		return err
	})
	if err != nil {
		return 0, err
	}
	return rev, nil
}

// headRevision reads the tenant's current revision.
func (a *Authorizer) headRevision(ctx context.Context, q *gen.Queries, tenant domain.TenantID) (domain.Revision, error) {
	rev, err := q.HeadRevision(ctx, tenant)
	if err != nil {
		return 0, mapErr(err)
	}
	if rev < 0 {
		// Unreachable: the column is CHECK (revision > 0) and the
		// aggregate coalesces to 0. It is checked anyway because the
		// conversion below is to an unsigned type, where a negative value
		// would become an enormous revision rather than an error.
		return 0, fmt.Errorf("%w: change log head is negative", domain.ErrUnavailable)
	}
	return domain.Revision(rev), nil //nolint:gosec // non-negative, checked above
}

// appendChange takes the per-tenant advisory lock and appends one entry,
// returning the revision it was given.
//
// The lock is taken here rather than at the start of the transaction, so
// it is held for as short a time as possible while still being held to
// commit — which is the property that makes revision order commit order.
func (a *Authorizer) appendChange(ctx context.Context, q *gen.Queries, c domain.Change) (domain.Revision, error) {
	if err := q.LockChangeLog(ctx, gen.LockChangeLogParams{
		Key:      changeLogLockKey,
		TenantID: string(c.TenantID),
	}); err != nil {
		return 0, mapErr(err)
	}
	principal, group := splitSubject(c.Subject)
	rev, err := q.AppendChange(ctx, gen.AppendChangeParams{
		TenantID:    c.TenantID,
		Kind:        c.Kind,
		ContainerID: c.Container,
		Permission:  c.Permission,
		PrincipalID: principal,
		GroupID:     group,
		RecordedAt:  c.RecordedAt,
	})
	if err != nil {
		return 0, mapErr(err)
	}
	if rev <= 0 {
		return 0, fmt.Errorf("%w: change log assigned a non-positive revision", domain.ErrUnavailable)
	}
	return domain.Revision(rev), nil //nolint:gosec // positive, checked above
}

// splitSubject decomposes a domain.Subject into the two nullable columns
// the schema stores it as. It is the conversion CONVENTIONS prescribes for
// a deliberately opaque type: the type maps to its primitives at the
// storage boundary and the adapter converts, rather than the type growing
// an exported sql.Scanner that would let any package forge one.
func splitSubject(s domain.Subject) (*domain.PrincipalID, *domain.GroupID) {
	if p, ok := s.Principal(); ok {
		return &p, nil
	}
	if g, ok := s.Group(); ok {
		return nil, &g
	}
	return nil, nil
}

// joinSubject is splitSubject's inverse. Exactly one column is non-NULL —
// the schema's own CHECK constraint guarantees it — so a row that reaches
// here with neither becomes the zero Subject, which names nobody and
// matches nothing.
func joinSubject(principal *domain.PrincipalID, group *domain.GroupID) domain.Subject {
	switch {
	case principal != nil:
		return domain.PrincipalSubject(*principal)
	case group != nil:
		return domain.GroupSubject(*group)
	default:
		return domain.Subject{}
	}
}

func toContainer(row gen.IamContainer) domain.Container {
	c := domain.Container{
		ID:        row.ID,
		TenantID:  row.TenantID,
		Kind:      row.Kind,
		Label:     row.Label,
		CreatedAt: domain.Canonical(row.CreatedAt),
	}
	if row.ParentID != nil {
		c.Parent = *row.ParentID
	}
	return c
}

func toGrant(row gen.IamGrant) domain.Grant {
	return domain.Grant{
		TenantID:   row.TenantID,
		Container:  row.ContainerID,
		Permission: row.Permission,
		Subject:    joinSubject(row.PrincipalID, row.GroupID),
		GrantedAt:  domain.Canonical(row.GrantedAt),
	}
}

func toChange(row gen.IamAuthzChangelog) domain.Change {
	rev := row.Revision
	if rev < 0 {
		rev = 0
	}
	return domain.Change{
		Revision:   domain.Revision(rev), //nolint:gosec // non-negative, clamped above
		TenantID:   row.TenantID,
		Kind:       row.Kind,
		Container:  row.ContainerID,
		Permission: row.Permission,
		Subject:    joinSubject(row.PrincipalID, row.GroupID),
		RecordedAt: domain.Canonical(row.RecordedAt),
	}
}

// schemaSet holds the schemas registered in this process. It is a type of
// its own rather than a map and a mutex on the Authorizer, because the
// in-memory adapter needs exactly the same thing and a reader comparing
// the two should see one shape.
type schemaSet struct {
	mu sync.RWMutex
	by map[string]domain.Schema
}

func newSchemaSet() *schemaSet {
	return &schemaSet{by: make(map[string]domain.Schema)}
}

func (s *schemaSet) put(schema domain.Schema) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.by[schema.Name] = schema
}

func (s *schemaSet) kind(name string) (domain.ContainerKind, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, schema := range s.by {
		if k, ok := schema.Kind(name); ok {
			return k, true
		}
	}
	return domain.ContainerKind{}, false
}

func (s *schemaSet) declaresPermission(p domain.Permission) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, schema := range s.by {
		if schema.DeclaresPermission(p) {
			return true
		}
	}
	return false
}
