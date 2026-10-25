package authz

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/registry"
)

// Memory is the in-memory Authorizer: a real adapter rather than a mock.
// It enforces the single-parent tree, maintains the containment closure
// as a parent walk, composes the group side with a real registry, and
// passes iamtest.RunAuthorizerSuite unchanged — so a consumer's own tests
// of its authorization code can run against it with no database. Its
// state lives only for the life of the value, so it is not a deployment
// option.
//
// # Why it composes a Registry rather than holding memberships
//
// It takes the identity registry as a dependency and asks it the one
// identity question a decision has: registry.LiveGroupsOf. It does not
// keep its own copy of membership, and that is the same decision the
// Postgres adapter makes by joining iam.live_group_members instead of a
// table of its own. A second copy of membership is a copy that goes
// stale, and the way it fails is that a deprovisioned principal keeps
// reading until somebody notices — which is a disclosure, not a bug
// report.
//
// # The closure is a walk here and a table there, and both are "keyed on
// the container"
//
// This adapter has no closure table: Ancestors walks parent pointers.
// That is not a different design from the Postgres adapter's materialized
// iam.container_closure — it is the same containment relation, keyed on
// the container in both, computed on read where there is no cost to it
// and stored where the read happens inside somebody else's query plan.
// What matters for conformance is that both are bounded by hierarchy
// depth rather than by resource count, and neither one ever holds a row
// per resource.
type Memory struct {
	cfg Config
	reg registry.Registry

	mu         sync.RWMutex
	schemas    map[string]domain.Schema
	containers map[domain.ContainerID]domain.Container
	grants     map[grantKey]domain.Grant
	// log is the change log, append-only, one slice per tenant. Entry i
	// of a tenant's slice holds revision i+1, which is what makes the
	// revision gapless without a counter that can be bumped
	// independently of an append — and the revision is per tenant for
	// the reason the port's Revision method gives.
	log map[domain.TenantID][]domain.Change
}

// grantKey is a grant's identity: the container, the permission and the
// subject. domain.Subject is comparable — two unexported string fields —
// so it is a map key directly, which is the quiet payoff of making it a
// struct with exactly two states instead of a pair of optional fields.
type grantKey struct {
	container  domain.ContainerID
	permission domain.Permission
	subject    domain.Subject
}

var _ Authorizer = (*Memory)(nil)

// NewMemory returns an in-memory Authorizer over reg, configured by cfg.
func NewMemory(reg registry.Registry, cfg Config) (*Memory, error) {
	if reg == nil {
		return nil, fmt.Errorf("%w: authz: nil registry; the authorization layer composes the identity registry's membership rather than keeping its own", domain.ErrInvalidConfig)
	}
	normalized, err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	return &Memory{
		cfg:        normalized,
		reg:        reg,
		schemas:    make(map[string]domain.Schema),
		containers: make(map[domain.ContainerID]domain.Container),
		grants:     make(map[grantKey]domain.Grant),
		log:        make(map[domain.TenantID][]domain.Change),
	}, nil
}

// RegisterSchema implements Authorizer.
func (m *Memory) RegisterSchema(ctx context.Context, s domain.Schema) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := s.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.schemas[s.Name] = s
	return nil
}

// kindLocked returns the declaration of a container kind, from whichever
// registered schema declares it.
func (m *Memory) kindLocked(kind string) (domain.ContainerKind, bool) {
	for _, s := range m.schemas {
		if k, ok := s.Kind(kind); ok {
			return k, true
		}
	}
	return domain.ContainerKind{}, false
}

// permissionDeclaredLocked reports whether any registered schema declares
// the permission.
func (m *Memory) permissionDeclaredLocked(p domain.Permission) bool {
	for _, s := range m.schemas {
		if s.DeclaresPermission(p) {
			return true
		}
	}
	return false
}

// CreateContainer implements Authorizer.
func (m *Memory) CreateContainer(ctx context.Context, spec domain.ContainerSpec) (domain.Container, error) {
	if err := ctx.Err(); err != nil {
		return domain.Container{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := spec.Validate(); err != nil {
		return domain.Container{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	kind, ok := m.kindLocked(spec.Kind)
	if !ok {
		return domain.Container{}, fmt.Errorf("%w: no registered schema declares container kind %q", domain.ErrSchemaNotRegistered, spec.Kind)
	}

	parentKind, declaresParent := kind.ParentKind()
	switch {
	case spec.Parent == "" && declaresParent:
		return domain.Container{}, fmt.Errorf("%w: kind %q is declared inside %q, so it cannot be a root", domain.ErrInvalidContainer, spec.Kind, parentKind)
	case spec.Parent != "" && !declaresParent:
		return domain.Container{}, fmt.Errorf("%w: kind %q is declared as a root kind, so it cannot be placed inside a container", domain.ErrInvalidContainer, spec.Kind)
	case spec.Parent != "":
		parent, ok := m.containers[spec.Parent]
		if !ok || parent.TenantID != spec.TenantID {
			// Another tenant's container is not found. Telling the two
			// apart would be a cross-tenant existence oracle over the id
			// space.
			return domain.Container{}, fmt.Errorf("%w: container %s", domain.ErrNotFound, spec.Parent)
		}
		if parent.Kind != parentKind {
			return domain.Container{}, fmt.Errorf("%w: kind %q is declared inside %q, but container %s is a %q",
				domain.ErrInvalidContainer, spec.Kind, parentKind, spec.Parent, parent.Kind)
		}
	}

	now := domain.Canonical(m.cfg.Clock.Now())
	container := domain.Container{
		ID:        domain.NewContainerID(m.cfg.Clock),
		TenantID:  spec.TenantID,
		Kind:      spec.Kind,
		Parent:    spec.Parent,
		Label:     spec.Label,
		CreatedAt: now,
	}
	m.containers[container.ID] = container
	m.appendLocked(domain.Change{
		TenantID:   spec.TenantID,
		Kind:       domain.ChangeContainerCreated,
		Container:  container.ID,
		RecordedAt: now,
	})
	return container, nil
}

// Container implements Authorizer.
func (m *Memory) Container(ctx context.Context, tenant domain.TenantID, id domain.ContainerID) (domain.Container, error) {
	if err := ctx.Err(); err != nil {
		return domain.Container{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.containerLocked(tenant, id)
}

func (m *Memory) containerLocked(tenant domain.TenantID, id domain.ContainerID) (domain.Container, error) {
	c, ok := m.containers[id]
	if !ok || c.TenantID != tenant {
		return domain.Container{}, fmt.Errorf("%w: container %s", domain.ErrNotFound, id)
	}
	return c, nil
}

// Ancestors implements Authorizer.
func (m *Memory) Ancestors(ctx context.Context, tenant domain.TenantID, id domain.ContainerID) ([]domain.ContainerID, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.ancestorsLocked(tenant, id)
}

// ancestorsLocked returns the container itself followed by each ancestor
// outwards. The depth bound is a backstop against a corrupted tree: an
// authorization decision that never returns is worse than one that
// errors.
func (m *Memory) ancestorsLocked(tenant domain.TenantID, id domain.ContainerID) ([]domain.ContainerID, error) {
	current, err := m.containerLocked(tenant, id)
	if err != nil {
		return nil, err
	}
	out := []domain.ContainerID{current.ID}
	for current.Parent != "" {
		if len(out) > domain.MaxContainmentDepth {
			return nil, fmt.Errorf("%w: containment above %s is deeper than %d", domain.ErrContainmentCycle, id, domain.MaxContainmentDepth)
		}
		if slices.Contains(out, current.Parent) {
			return nil, fmt.Errorf("%w: containment above %s revisits %s", domain.ErrContainmentCycle, id, current.Parent)
		}
		parent, ok := m.containers[current.Parent]
		if !ok {
			return nil, fmt.Errorf("%w: container %s names a parent that does not exist", domain.ErrContainmentCycle, current.ID)
		}
		out = append(out, parent.ID)
		current = parent
	}
	return out, nil
}

// Grant implements Authorizer.
func (m *Memory) Grant(ctx context.Context, spec domain.GrantSpec) (domain.Revision, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := spec.Validate(); err != nil {
		return 0, err
	}
	if err := m.resolveSubject(ctx, spec); err != nil {
		return 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := m.containerLocked(spec.TenantID, spec.Container); err != nil {
		return 0, err
	}
	if !m.permissionDeclaredLocked(spec.Permission) {
		return 0, fmt.Errorf("%w: no registered schema declares permission %q; a misspelled permission is a grant that silently never fires", domain.ErrSchemaNotRegistered, spec.Permission)
	}

	key := grantKey{container: spec.Container, permission: spec.Permission, subject: spec.Subject}
	if _, exists := m.grants[key]; exists {
		// Idempotent, and deliberately not logged: a log entry for a
		// write that changed nothing makes a projection do work for no
		// reason and makes the log's length a function of retries.
		return m.revisionLocked(spec.TenantID), nil
	}

	now := domain.Canonical(m.cfg.Clock.Now())
	m.grants[key] = domain.Grant{
		TenantID:   spec.TenantID,
		Container:  spec.Container,
		Permission: spec.Permission,
		Subject:    spec.Subject,
		GrantedAt:  now,
	}
	return m.appendLocked(domain.Change{
		TenantID:   spec.TenantID,
		Kind:       domain.ChangeGrantWritten,
		Container:  spec.Container,
		Permission: spec.Permission,
		Subject:    spec.Subject,
		RecordedAt: now,
	}), nil
}

// resolveSubject refuses a grant whose subject does not exist in this
// tenant. It runs outside the lock because it calls the registry, and a
// lock held across another component's call is a deadlock waiting for a
// second caller.
//
// An unknown subject and another tenant's subject are the same answer,
// for the reason the container lookup gives.
func (m *Memory) resolveSubject(ctx context.Context, spec domain.GrantSpec) error {
	if p, ok := spec.Subject.Principal(); ok {
		principal, err := m.reg.PrincipalByID(ctx, p)
		switch {
		case errors.Is(err, domain.ErrPrincipalNotFound), errors.Is(err, domain.ErrNotFound):
			return fmt.Errorf("%w: grant names principal %s", domain.ErrNotFound, p)
		case err != nil:
			return err
		case principal.TenantID != spec.TenantID:
			return fmt.Errorf("%w: grant names principal %s", domain.ErrNotFound, p)
		}
		return nil
	}
	g, _ := spec.Subject.Group()
	group, err := m.reg.GroupByID(ctx, g)
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return fmt.Errorf("%w: grant names group %s", domain.ErrNotFound, g)
	case err != nil:
		return err
	case group.TenantID != spec.TenantID:
		return fmt.Errorf("%w: grant names group %s", domain.ErrNotFound, g)
	}
	return nil
}

// Revoke implements Authorizer.
func (m *Memory) Revoke(ctx context.Context, spec domain.GrantSpec) (domain.Revision, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := spec.Validate(); err != nil {
		return 0, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	key := grantKey{container: spec.Container, permission: spec.Permission, subject: spec.Subject}
	if _, exists := m.grants[key]; !exists {
		// Revoking what is not there is not an error. It is also not a
		// log entry: a projection replaying a revocation of a grant it
		// never saw would be doing work to reach the state it is already
		// in.
		return m.revisionLocked(spec.TenantID), nil
	}
	delete(m.grants, key)

	return m.appendLocked(domain.Change{
		TenantID:   spec.TenantID,
		Kind:       domain.ChangeGrantRevoked,
		Container:  spec.Container,
		Permission: spec.Permission,
		Subject:    spec.Subject,
		RecordedAt: domain.Canonical(m.cfg.Clock.Now()),
	}), nil
}

// GrantsOn implements Authorizer.
func (m *Memory) GrantsOn(ctx context.Context, tenant domain.TenantID, container domain.ContainerID) ([]domain.Grant, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, err := m.containerLocked(tenant, container); err != nil {
		return nil, err
	}
	out := make([]domain.Grant, 0, len(m.grants))
	for key, g := range m.grants {
		if key.container == container {
			out = append(out, g)
		}
	}
	sortGrants(out)
	return out, nil
}

// sortGrants puts grants in the order both adapters return them:
// permission, then subject. It is shared with the Postgres adapter's
// ORDER BY by convention rather than by code, which is exactly the kind
// of agreement the conformance suite exists to check.
func sortGrants(gs []domain.Grant) {
	slices.SortFunc(gs, func(a, b domain.Grant) int {
		if c := strings.Compare(string(a.Permission), string(b.Permission)); c != 0 {
			return c
		}
		return strings.Compare(a.Subject.String(), b.Subject.String())
	})
}

// Decide implements Authorizer.
//
// It evaluates design §7.1 as it now stands and nothing more: one term,
// default-deny. The order of the search is the order a consumer needs the
// answer explained in — the container itself before its ancestors, and a
// direct grant before a group's — so the Reason it reports is the
// outermost form that fired.
func (m *Memory) Decide(ctx context.Context, req domain.Request) (domain.Decision, error) {
	if err := ctx.Err(); err != nil {
		return domain.Decision{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := req.Validate(); err != nil {
		return domain.Decision{}, err
	}

	m.mu.RLock()
	rev := m.revisionLocked(req.TenantID)
	m.mu.RUnlock()

	now := m.cfg.Clock.Now()

	// The principal's own liveness, for the direct arm. An unknown
	// principal is not an error: it denies, exactly as a known principal
	// with no grants does.
	principal, err := m.reg.PrincipalByID(ctx, req.Principal)
	switch {
	case errors.Is(err, domain.ErrPrincipalNotFound), errors.Is(err, domain.ErrNotFound):
		return domain.Deny(rev), nil
	case err != nil:
		return domain.Decision{}, err
	}
	live := principal.TenantID == req.TenantID && registry.LiveForDecision(principal, now)
	if !live {
		// A deprovisioned principal, an expired agent run, or a principal
		// from another tenant matches nothing at all — not through a
		// group and not through a grant written to it by name. The two
		// arms have to agree about this: deprovisioning that worked on
		// group grants and not on personal ones would pass a test suite
		// and leak on exactly the grants somebody wrote deliberately.
		return domain.Deny(rev), nil
	}

	groups, err := m.reg.LiveGroupsOf(ctx, req.Principal, now)
	if err != nil {
		return domain.Decision{}, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	ancestors, err := m.ancestorsLocked(req.TenantID, req.Container)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			// An unknown container denies rather than erroring, so that
			// "no such container" and "you hold nothing on it" are one
			// answer.
			return domain.Deny(rev), nil
		}
		return domain.Decision{}, err
	}

	for depth, ancestor := range ancestors {
		// The direct arm first, so a grant written to this principal by
		// name is the reason reported when both could fire.
		key := grantKey{container: ancestor, permission: req.Permission, subject: domain.PrincipalSubject(req.Principal)}
		if g, ok := m.grants[key]; ok {
			return domain.Allow(g, depth, rev), nil
		}
		// Then the group arm, in a deterministic order, so two adapters
		// attribute the same allow to the same grant when a principal is
		// in two groups that both hold the permission.
		sorted := slices.Clone(groups)
		slices.Sort(sorted)
		for _, gid := range sorted {
			key := grantKey{container: ancestor, permission: req.Permission, subject: domain.GroupSubject(gid)}
			if g, ok := m.grants[key]; ok {
				return domain.Allow(g, depth, rev), nil
			}
		}
	}
	return domain.Deny(rev), nil
}

// Filter implements Authorizer.
func (m *Memory) Filter(ctx context.Context, req FilterRequest) (domain.Residual, error) {
	if err := ctx.Err(); err != nil {
		return domain.Residual{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := req.Validate(); err != nil {
		return domain.Residual{}, err
	}

	m.mu.RLock()
	defer m.mu.RUnlock()

	return BuildResidual(req, m.revisionLocked(req.TenantID), m.permissionDeclaredLocked(req.Permission))
}

// Changes implements Authorizer.
func (m *Memory) Changes(ctx context.Context, tenant domain.TenantID, after domain.Revision, limit int) ([]domain.Change, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if tenant == "" {
		return nil, fmt.Errorf("%w: empty tenant id", domain.ErrInvalidRequest)
	}
	limit = NormalizeChangeLimit(limit)

	m.mu.RLock()
	defer m.mu.RUnlock()

	out := make([]domain.Change, 0, limit)
	for _, c := range m.log[tenant] {
		if c.Revision <= after {
			continue
		}
		out = append(out, c)
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

// Revision implements Authorizer.
func (m *Memory) Revision(ctx context.Context, tenant domain.TenantID) (domain.Revision, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if tenant == "" {
		return 0, fmt.Errorf("%w: empty tenant id", domain.ErrInvalidRequest)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.revisionLocked(tenant), nil
}

func (m *Memory) revisionLocked(tenant domain.TenantID) domain.Revision {
	return domain.Revision(len(m.log[tenant]))
}

// appendLocked appends one entry and returns the revision it was given.
//
// The revision is the entry's position, so it is gapless by construction
// and cannot be advanced without an append — which is the property a
// resumable cursor needs and the one a counter next to a slice would
// eventually lose. The Postgres adapter reaches the same property a
// harder way, by assigning max+1 under an advisory lock held to commit,
// because a sequence there would allocate before commit and let a reader
// see revision 5 while 4 is still in flight.
func (m *Memory) appendLocked(c domain.Change) domain.Revision {
	c.Revision = domain.Revision(len(m.log[c.TenantID]) + 1)
	m.log[c.TenantID] = append(m.log[c.TenantID], c)
	return c.Revision
}
