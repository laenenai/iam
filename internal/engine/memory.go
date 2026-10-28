package engine

import (
	"context"
	"fmt"
	"sort"
	"sync"

	"github.com/laenenai/iam/internal/domain"
)

// Memory is the reference Engine. Tuples are a set; every check walks the
// containment tree and the group usersets.
type Memory struct {
	mu     sync.RWMutex
	tuples map[Tuple]struct{}
}

// NewMemory returns an empty reference engine.
func NewMemory() *Memory {
	return &Memory{tuples: make(map[Tuple]struct{})}
}

// Write adds tuples; writing the same tuple twice is a no-op.
func (m *Memory) Write(ctx context.Context, tuples ...Tuple) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tuple := range tuples {
		m.tuples[tuple] = struct{}{}
	}
	return nil
}

// Delete removes tuples; deleting an absent tuple is a no-op.
func (m *Memory) Delete(ctx context.Context, tuples ...Tuple) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, tuple := range tuples {
		delete(m.tuples, tuple)
	}
	return nil
}

// Check evaluates the ladder, inheritance and group usersets.
func (m *Memory) Check(ctx context.Context, subject domain.Subject, relation domain.Relation, object domain.URN) (bool, domain.Reason, error) {
	if err := ctx.Err(); err != nil {
		return false, "", err
	}
	if err := subject.Validate(); err != nil {
		return false, "", err
	}
	if _, err := domain.ParseURN(string(object)); err != nil {
		return false, "", err
	}
	base, ok := baseRelation(relation)
	if !ok {
		return false, "", fmt.Errorf("%w: %q", domain.ErrInvalidRelation, relation)
	}

	m.mu.RLock()
	defer m.mu.RUnlock()
	allowed, reason := m.check(subject, base, object, false, make(map[visit]struct{}))
	return allowed, reason, nil
}

type visit struct {
	object   domain.URN
	relation domain.Relation
}

func (m *Memory) check(subject domain.Subject, relation domain.Relation, object domain.URN, inherited bool, seen map[visit]struct{}) (bool, domain.Reason) {
	key := visit{object: object, relation: relation}
	if _, ok := seen[key]; ok {
		return false, domain.ReasonNoGrant
	}
	seen[key] = struct{}{}

	if m.matches(subject.URN, relation, object, false) {
		return true, matchReason(inherited, false)
	}
	if m.matches(subject.URN, relation, object, true) {
		return true, matchReason(inherited, true)
	}

	switch relation {
	case domain.Viewer:
		if ok, reason := m.check(subject, domain.Commenter, object, inherited, seen); ok {
			return true, reason
		}
	case domain.Commenter:
		if ok, reason := m.check(subject, domain.Editor, object, inherited, seen); ok {
			return true, reason
		}
	case domain.Editor:
		if ok, reason := m.check(subject, domain.Owner, object, inherited, seen); ok {
			return true, reason
		}
	case domain.CanDelete:
		if ok, reason := m.check(subject, domain.Owner, object, inherited, seen); ok {
			return true, reason
		}
	}

	if relation != domain.CanDelete {
		for _, parent := range m.parents(object) {
			if ok, reason := m.check(subject, relation, parent, true, seen); ok {
				return true, reason
			}
		}
	}

	return false, domain.ReasonNoGrant
}

func (m *Memory) matches(user domain.URN, relation domain.Relation, object domain.URN, userset bool) bool {
	for tuple := range m.tuples {
		if tuple.Object != object || tuple.Relation != relation || tuple.Userset != userset {
			continue
		}
		if !userset && tuple.Subject == user {
			return true
		}
		if userset && m.isMember(tuple.Subject, user) {
			return true
		}
	}
	return false
}

func (m *Memory) isMember(group, user domain.URN) bool {
	for tuple := range m.tuples {
		if tuple.Object == group && tuple.Relation == domain.Member && !tuple.Userset && tuple.Subject == user {
			return true
		}
	}
	return false
}

func (m *Memory) parents(object domain.URN) []domain.URN {
	var parents []domain.URN
	for tuple := range m.tuples {
		if tuple.Object == object && tuple.Relation == domain.Parent && !tuple.Userset {
			parents = append(parents, tuple.Subject)
		}
	}
	sort.Slice(parents, func(i, j int) bool { return parents[i] < parents[j] })
	return parents
}

func baseRelation(relation domain.Relation) (domain.Relation, bool) {
	switch relation {
	case domain.Owner, domain.Editor, domain.Commenter, domain.Viewer, domain.CanDelete:
		return relation, true
	case domain.CanShare:
		return domain.Owner, true
	case domain.CanView:
		return domain.Viewer, true
	case domain.CanEdit:
		return domain.Editor, true
	case domain.CanComment:
		return domain.Commenter, true
	default:
		return "", false
	}
}

func matchReason(inherited, userset bool) domain.Reason {
	switch {
	case inherited:
		return domain.ReasonInherited
	case userset:
		return domain.ReasonUserset
	default:
		return domain.ReasonDirect
	}
}
