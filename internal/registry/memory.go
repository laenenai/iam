package registry

import (
	"context"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/laenenai/iam/internal/domain"
)

// Memory is an in-memory Registry: the adapter the decision procedure's
// unit tests run against, with no database and no I/O (design §6 — "the
// core performs no I/O and the decision procedure is unit-testable with
// in-memory adapters, because that component is what A3 is about").
//
// It is a real adapter and not a mock. It passes RunRegistrySuite
// unchanged, which means it enforces the staleness bound, claim
// reconciliation and immediate deprovisioning exactly as the Postgres
// adapter does — so a test that passes here is a test of the contract
// rather than of a stub's convenience.
//
// It is safe for concurrent use. State lives only for the life of the
// value, so it is not a deployment option; a deployment with no Postgres
// has no registry.
type Memory struct {
	cfg Config

	mu         sync.RWMutex
	principals map[domain.PrincipalID]domain.Principal
	// byExternal maps a tenant-scoped (issuer, subject) to the internal
	// id minted for it at first sight. The internal id is the value, not
	// the key: nothing here derives one from the other.
	byExternal map[externalKey]domain.PrincipalID

	groups      map[domain.GroupID]domain.Group
	groupByName map[nameKey]domain.GroupID
	// members is group -> principal -> which side owns the row. The
	// source is what makes claim reconciliation surgical: see
	// domain.GroupSource.
	members map[domain.GroupID]map[domain.PrincipalID]domain.GroupSource
}

// externalKey is the tenant-scoped external-subject lookup key. Tenant is
// part of the key because the registry is global while every row in it is
// tenant-scoped: the same subject at the same issuer is a different
// principal in a different tenant.
type externalKey struct {
	tenant  domain.TenantID
	issuer  string
	subject string
}

// nameKey is the tenant-scoped name lookup key for groups.
type nameKey struct {
	tenant domain.TenantID
	name   string
}

var _ Registry = (*Memory)(nil)

// NewMemory returns an in-memory Registry configured by cfg, or an error
// wrapping domain.ErrInvalidConfig if cfg is not valid.
func NewMemory(cfg Config) (*Memory, error) {
	normalized, err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	return &Memory{
		cfg:         normalized,
		principals:  make(map[domain.PrincipalID]domain.Principal),
		byExternal:  make(map[externalKey]domain.PrincipalID),
		groups:      make(map[domain.GroupID]domain.Group),
		groupByName: make(map[nameKey]domain.GroupID),
		members:     make(map[domain.GroupID]map[domain.PrincipalID]domain.GroupSource),
	}, nil
}

// UpsertFromClaims implements Registry.
func (m *Memory) UpsertFromClaims(ctx context.Context, c Claims) (domain.Principal, error) {
	if err := ctx.Err(); err != nil {
		return domain.Principal{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := c.Validate(); err != nil {
		return domain.Principal{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.cfg.Clock.Now()
	key := externalKey{tenant: c.TenantID, issuer: c.Subject.Issuer, subject: c.Subject.Subject}

	id, seen := m.byExternal[key]
	if !seen {
		// First sight: mint an id. It is a fresh ULID and carries no
		// function of the external subject, which is the whole reason
		// grants and audit reference it (design §8.1).
		id = domain.NewPrincipalID(m.cfg.Clock)
	}

	p, exists := m.principals[id]
	if exists && !p.DeprovisionedAt.IsZero() {
		// A fresh token for a deprovisioned subject is not a
		// reinstatement. Reviving here would make deprovisioning last
		// exactly until the user's next request.
		return domain.Principal{}, fmt.Errorf("%w: %s", domain.ErrPrincipalDeprovisioned, id)
	}
	if !exists {
		p = domain.Principal{ID: id, TenantID: c.TenantID, External: c.Subject, CreatedAt: now}
	}
	p.Kind = c.Kind
	p.DisplayName = c.DisplayName
	p.SyncedAt = now

	if err := p.Validate(); err != nil {
		return domain.Principal{}, err
	}

	m.principals[id] = p
	m.byExternal[key] = id

	if err := m.reconcileClaimGroups(c.TenantID, id, NormalizeClaimGroups(c.Groups), now); err != nil {
		return domain.Principal{}, err
	}
	return p, nil
}

// reconcileClaimGroups brings this principal's claim-sourced memberships
// to exactly want. It must be called with m.mu held.
//
// It touches GroupSourceClaim rows only. A membership written through
// AddGroupMember (GroupSourceLocal) survives a claim set that does not
// name it, because the issuer is not the authority for it — see
// domain.GroupSource.
func (m *Memory) reconcileClaimGroups(tenant domain.TenantID, p domain.PrincipalID, want []string, now time.Time) error {
	wanted := make(map[domain.GroupID]struct{}, len(want))
	for _, name := range want {
		g, err := m.ensureGroupLocked(tenant, name, now)
		if err != nil {
			return err
		}
		wanted[g.ID] = struct{}{}
		if m.members[g.ID] == nil {
			m.members[g.ID] = make(map[domain.PrincipalID]domain.GroupSource)
		}
		// An existing local membership is not downgraded to a claim
		// membership by the issuer also asserting it: the stronger
		// (local) ownership wins, so a later shrinking claim set does
		// not remove what an operator wrote.
		if _, already := m.members[g.ID][p]; !already {
			m.members[g.ID][p] = domain.GroupSourceClaim
		}
	}

	for gid, members := range m.members {
		if m.groups[gid].TenantID != tenant {
			continue
		}
		if _, keep := wanted[gid]; keep {
			continue
		}
		if members[p] == domain.GroupSourceClaim {
			delete(members, p)
		}
	}
	return nil
}

// ResolveExternal implements Registry.
func (m *Memory) ResolveExternal(ctx context.Context, tenant domain.TenantID, s domain.ExternalSubject) (domain.Principal, error) {
	if err := ctx.Err(); err != nil {
		return domain.Principal{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	id, ok := m.byExternal[externalKey{tenant: tenant, issuer: s.Issuer, subject: s.Subject}]
	if !ok {
		return domain.Principal{}, fmt.Errorf("%w: %s", domain.ErrPrincipalNotFound, s)
	}
	p, ok := m.principals[id]
	if !ok {
		return domain.Principal{}, fmt.Errorf("%w: %s", domain.ErrPrincipalNotFound, s)
	}
	return p, nil
}

// PrincipalByID implements Registry.
func (m *Memory) PrincipalByID(ctx context.Context, id domain.PrincipalID) (domain.Principal, error) {
	if err := ctx.Err(); err != nil {
		return domain.Principal{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.principalLocked(id)
}

// principalLocked reads a principal or returns ErrPrincipalNotFound. It
// must be called with m.mu held (read or write).
//
// A malformed id is "not found" rather than "malformed": the shape of the
// registry's refusal must not depend on whether the caller's id was
// well-formed, or it becomes a syntax oracle over the id space.
func (m *Memory) principalLocked(id domain.PrincipalID) (domain.Principal, error) {
	p, ok := m.principals[id]
	if !ok {
		return domain.Principal{}, fmt.Errorf("%w: %s", domain.ErrPrincipalNotFound, id)
	}
	return p, nil
}

// Condition implements Registry.
func (m *Memory) Condition(ctx context.Context, id domain.PrincipalID, asOf time.Time) (domain.PrincipalCondition, error) {
	if err := ctx.Err(); err != nil {
		return domain.PrincipalCondition{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	p, err := m.principalLocked(id)
	if err != nil {
		return domain.PrincipalCondition{}, err
	}
	return domain.EvaluateCondition(p, m.cfg.StalenessBound, asOf), nil
}

// usableLocked returns the principal if it may be used at asOf, or its
// condition's error. It is the single gate in front of every
// principal-side membership read, which is what makes design §8.1's
// staleness bound an enforcement point rather than a caller's
// responsibility.
func (m *Memory) usableLocked(id domain.PrincipalID, asOf time.Time) (domain.Principal, error) {
	p, err := m.principalLocked(id)
	if err != nil {
		return domain.Principal{}, err
	}
	cond := domain.EvaluateCondition(p, m.cfg.StalenessBound, asOf)
	if err := cond.Err(); err != nil {
		return domain.Principal{}, fmt.Errorf("%w: principal %s", err, id)
	}
	return p, nil
}

// EnsureGroup implements Registry.
func (m *Memory) EnsureGroup(ctx context.Context, tenant domain.TenantID, name string) (domain.Group, error) {
	if err := ctx.Err(); err != nil {
		return domain.Group{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.ensureGroupLocked(tenant, name, m.cfg.Clock.Now())
}

func (m *Memory) ensureGroupLocked(tenant domain.TenantID, name string, now time.Time) (domain.Group, error) {
	if tenant == "" || name == "" {
		return domain.Group{}, fmt.Errorf("%w: a group needs a tenant and a non-empty name", domain.ErrConflict)
	}
	key := nameKey{tenant: tenant, name: name}
	if id, ok := m.groupByName[key]; ok {
		return m.groups[id], nil
	}
	g := domain.Group{ID: domain.NewGroupID(m.cfg.Clock), TenantID: tenant, Name: name, CreatedAt: now}
	m.groups[g.ID] = g
	m.groupByName[key] = g.ID
	m.members[g.ID] = make(map[domain.PrincipalID]domain.GroupSource)
	return g, nil
}

// groupLocked resolves a group id, or reports ErrNotFound. It once
// distinguished a clearance group from an id naming nothing, because a
// tier confusion and a typo meant different things to an operator. With
// one namespace left, existence is the whole question.
func (m *Memory) groupLocked(id domain.GroupID) (domain.Group, error) {
	if g, ok := m.groups[id]; ok {
		return g, nil
	}
	return domain.Group{}, fmt.Errorf("%w: group %s", domain.ErrNotFound, id)
}

// AddGroupMember implements Registry.
func (m *Memory) AddGroupMember(ctx context.Context, g domain.GroupID, p domain.PrincipalID) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := m.groupLocked(g); err != nil {
		return err
	}
	principal, err := m.principalLocked(p)
	if err != nil {
		return err
	}
	if !principal.DeprovisionedAt.IsZero() {
		return fmt.Errorf("%w: %s", domain.ErrPrincipalDeprovisioned, p)
	}
	if m.members[g] == nil {
		m.members[g] = make(map[domain.PrincipalID]domain.GroupSource)
	}
	m.members[g][p] = domain.GroupSourceLocal
	return nil
}

// RemoveGroupMember implements Registry.
func (m *Memory) RemoveGroupMember(ctx context.Context, g domain.GroupID, p domain.PrincipalID) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	if _, err := m.groupLocked(g); err != nil {
		return err
	}
	delete(m.members[g], p)
	return nil
}

// GroupsOf implements Registry.
func (m *Memory) GroupsOf(ctx context.Context, p domain.PrincipalID, asOf time.Time) ([]domain.Group, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, err := m.usableLocked(p, asOf); err != nil {
		return nil, err
	}
	var out []domain.Group
	for gid, members := range m.members {
		if _, ok := members[p]; ok {
			out = append(out, m.groups[gid])
		}
	}
	slices.SortFunc(out, func(a, b domain.Group) int {
		if a.Name != b.Name {
			if a.Name < b.Name {
				return -1
			}
			return 1
		}
		return compareStrings(string(a.ID), string(b.ID))
	})
	return out, nil
}

// GroupMembers implements Registry.
func (m *Memory) GroupMembers(ctx context.Context, g domain.GroupID, asOf time.Time) ([]domain.PrincipalID, error) {
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()

	if _, err := m.groupLocked(g); err != nil {
		return nil, err
	}
	return m.usableMembersLocked(keysOf(m.members[g]), asOf), nil
}

// usableMembersLocked filters a membership set down to the principals
// usable at asOf, sorted by id.
//
// This side omits rather than errors, which is what makes deprovisioning
// and expiry immediate without deleting a row: the member stops appearing
// the instant its condition turns, and the membership history stays intact
// for audit. It is also the behaviour the Postgres adapter's joinable view
// implements in SQL, so the two adapters answer the same question.
func (m *Memory) usableMembersLocked(ids []domain.PrincipalID, asOf time.Time) []domain.PrincipalID {
	out := make([]domain.PrincipalID, 0, len(ids))
	for _, id := range ids {
		p, ok := m.principals[id]
		if !ok {
			continue
		}
		if domain.EvaluateCondition(p, m.cfg.StalenessBound, asOf).Usable() {
			out = append(out, id)
		}
	}
	slices.SortFunc(out, func(a, b domain.PrincipalID) int { return compareStrings(string(a), string(b)) })
	if len(out) == 0 {
		return nil
	}
	return out
}

// DelegateAgentRun implements Registry.
func (m *Memory) DelegateAgentRun(ctx context.Context, parent domain.PrincipalID, spec AgentRunSpec) (domain.Principal, error) {
	if err := ctx.Err(); err != nil {
		return domain.Principal{}, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	if err := ValidateAgentRunSpec(spec, m.cfg.MaxAgentRunTTL); err != nil {
		return domain.Principal{}, err
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	now := m.cfg.Clock.Now()
	// The parent must be usable, not merely present: a principal too
	// stale to decide with is too stale to delegate from, and a
	// deprovisioned one must not be able to leave a live agent run
	// behind it.
	p, err := m.usableLocked(parent, now)
	if err != nil {
		return domain.Principal{}, err
	}
	if p.Kind == domain.PrincipalKindAgentRun {
		return domain.Principal{}, fmt.Errorf("%w: an agent run may not delegate a further agent run; delegation depth is captoken's object", domain.ErrInvalidPrincipal)
	}

	// The run inherits its parent's tenant and nothing else: no group
	// membership at all: a delegation grants what it names, never what
	// its parent happens to hold.
	run := domain.Principal{
		ID:          domain.NewPrincipalID(m.cfg.Clock),
		TenantID:    p.TenantID,
		Kind:        domain.PrincipalKindAgentRun,
		DisplayName: spec.DisplayName,
		SyncedAt:    now,
		DelegatedBy: p.ID,
		ExpiresAt:   now.Add(spec.TTL),
		CreatedAt:   now,
	}
	if err := run.Validate(); err != nil {
		return domain.Principal{}, err
	}
	m.principals[run.ID] = run
	return run, nil
}

// CollectExpiredAgentRuns implements Registry.
func (m *Memory) CollectExpiredAgentRuns(ctx context.Context, asOf time.Time) (int, error) {
	if err := ctx.Err(); err != nil {
		return 0, fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	collected := 0
	for id, p := range m.principals {
		if p.Kind != domain.PrincipalKindAgentRun || p.ExpiresAt.IsZero() || asOf.Before(p.ExpiresAt) {
			continue
		}
		delete(m.principals, id)
		delete(m.byExternal, externalKey{tenant: p.TenantID, issuer: p.External.Issuer, subject: p.External.Subject})
		for _, members := range m.members {
			delete(members, id)
		}
		collected++
	}
	return collected, nil
}

// Deprovision implements Registry.
func (m *Memory) Deprovision(ctx context.Context, p domain.PrincipalID) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("%w: %w", domain.ErrUnavailable, err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	principal, err := m.principalLocked(p)
	if err != nil {
		return err
	}
	if !principal.DeprovisionedAt.IsZero() {
		// Idempotent, and the original instant is kept: moving it would
		// rewrite when access actually stopped.
		return nil
	}
	now := m.cfg.Clock.Now()
	principal.DeprovisionedAt = now
	m.principals[p] = principal

	// Cascade to this principal's live agent runs, in the same write.
	// Deprovisioning a user whose agents keep running with the authority
	// she delegated to them has not denied anything, and an agent run is
	// deliberately not subject to the staleness bound (see
	// domain.EvaluateCondition), so nothing else would ever catch it. The
	// cascade is one level deep because an agent run may not delegate a
	// further agent run.
	for id, run := range m.principals {
		if run.Kind != domain.PrincipalKindAgentRun || run.DelegatedBy != p || !run.DeprovisionedAt.IsZero() {
			continue
		}
		run.DeprovisionedAt = now
		m.principals[id] = run
	}

	// Memberships are deliberately left in place. They stop matching at
	// once because every membership read filters on the principal's
	// condition, and keeping the rows is what lets audit explain what the
	// principal had access to.
	return nil
}

// keysOf returns a map's keys. It exists so the membership readers do not
// each hand-roll the same loop.
func keysOf[K comparable, V any](m map[K]V) []K {
	out := make([]K, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// compareStrings is strings.Compare's three-way result, inlined here so
// the sort comparators read the same way for every id type.
func compareStrings(a, b string) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	default:
		return 0
	}
}
