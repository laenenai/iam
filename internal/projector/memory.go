package projector

import (
	"sort"
	"sync"

	"github.com/laenenai/iam/internal/domain"
)

// MemoryStore is the reference Store. It is not durable; plan 3 supplies the
// Postgres adapter behind the same port.
type MemoryStore struct {
	mu sync.RWMutex

	nodes      map[domain.TenantID]map[domain.URN]domain.Node
	grants     map[domain.TenantID]map[domain.GrantID]domain.Grant
	groups     map[domain.TenantID]map[domain.URN]domain.Group
	members    map[domain.TenantID]map[domain.URN]map[domain.URN]memberRecord
	principals map[domain.TenantID]map[domain.URN]domain.Principal

	pending      map[string]domain.KindSpec
	kinds        map[string]domain.KindSpec
	modelVersion int
}

type memberRecord struct {
	subject domain.Subject
	live    bool
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		nodes:      make(map[domain.TenantID]map[domain.URN]domain.Node),
		grants:     make(map[domain.TenantID]map[domain.GrantID]domain.Grant),
		groups:     make(map[domain.TenantID]map[domain.URN]domain.Group),
		members:    make(map[domain.TenantID]map[domain.URN]map[domain.URN]memberRecord),
		principals: make(map[domain.TenantID]map[domain.URN]domain.Principal),
		pending:    make(map[string]domain.KindSpec),
		kinds:      make(map[string]domain.KindSpec),
	}
}

func (s *MemoryStore) SetNode(node domain.Node) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byURN := s.nodes[node.Tenant]
	if byURN == nil {
		byURN = make(map[domain.URN]domain.Node)
		s.nodes[node.Tenant] = byURN
	}
	byURN[node.URN] = node
}

func (s *MemoryStore) Node(tenant domain.TenantID, urn domain.URN) (domain.Node, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	node, ok := s.nodes[tenant][urn]
	return node, ok
}

func (s *MemoryStore) Nodes(tenant domain.TenantID) []domain.Node {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Node, 0, len(s.nodes[tenant]))
	for _, node := range s.nodes[tenant] {
		out = append(out, node)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URN < out[j].URN })
	return out
}

func (s *MemoryStore) SetGrant(grant domain.Grant) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byID := s.grants[grant.Tenant]
	if byID == nil {
		byID = make(map[domain.GrantID]domain.Grant)
		s.grants[grant.Tenant] = byID
	}
	byID[grant.ID] = grant
}

func (s *MemoryStore) Grant(tenant domain.TenantID, id domain.GrantID) (domain.Grant, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	grant, ok := s.grants[tenant][id]
	return grant, ok
}

func (s *MemoryStore) GrantsForObject(tenant domain.TenantID, object domain.URN) []domain.Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []domain.Grant
	for _, grant := range s.grants[tenant] {
		if grant.Live && grant.Object == object {
			out = append(out, grant)
		}
	}
	sortGrants(out)
	return out
}

func (s *MemoryStore) GrantsForSubject(tenant domain.TenantID, subject domain.Subject) []domain.Grant {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []domain.Grant
	for _, grant := range s.grants[tenant] {
		if grant.Live && grant.Subject == subject {
			out = append(out, grant)
		}
	}
	sortGrants(out)
	return out
}

func (s *MemoryStore) GroupsForMember(tenant domain.TenantID, member domain.Subject) []domain.Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []domain.Group
	for urn, group := range s.groups[tenant] {
		if !group.Live {
			continue
		}
		if record, ok := s.members[tenant][urn][member.URN]; ok && record.live && record.subject == member {
			out = append(out, group)
		}
	}
	sortGroups(out)
	return out
}

func (s *MemoryStore) GroupsForAdmin(tenant domain.TenantID, admin domain.Subject) []domain.Group {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []domain.Group
	for _, group := range s.groups[tenant] {
		if group.Live && group.Admin == admin {
			out = append(out, group)
		}
	}
	sortGroups(out)
	return out
}

func (s *MemoryStore) SetGroup(group domain.Group) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byURN := s.groups[group.Tenant]
	if byURN == nil {
		byURN = make(map[domain.URN]domain.Group)
		s.groups[group.Tenant] = byURN
	}
	byURN[group.URN] = group
}

func (s *MemoryStore) Group(tenant domain.TenantID, urn domain.URN) (domain.Group, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	group, ok := s.groups[tenant][urn]
	return group, ok
}

func (s *MemoryStore) SetGroupMember(tenant domain.TenantID, group domain.URN, member domain.Subject, live bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byGroup := s.members[tenant]
	if byGroup == nil {
		byGroup = make(map[domain.URN]map[domain.URN]memberRecord)
		s.members[tenant] = byGroup
	}
	members := byGroup[group]
	if members == nil {
		members = make(map[domain.URN]memberRecord)
		byGroup[group] = members
	}
	members[member.URN] = memberRecord{subject: member, live: live}
}

func (s *MemoryStore) GroupMembers(tenant domain.TenantID, group domain.URN) []domain.Subject {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []domain.Subject
	for _, record := range s.members[tenant][group] {
		if record.live {
			out = append(out, record.subject)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].URN < out[j].URN })
	return out
}

func (s *MemoryStore) SetPrincipal(principal domain.Principal) {
	s.mu.Lock()
	defer s.mu.Unlock()
	byURN := s.principals[principal.Tenant]
	if byURN == nil {
		byURN = make(map[domain.URN]domain.Principal)
		s.principals[principal.Tenant] = byURN
	}
	byURN[principal.URN] = principal
}

func (s *MemoryStore) Principal(tenant domain.TenantID, subject domain.Subject) (domain.Principal, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	principal, ok := s.principals[tenant][subject.URN]
	return principal, ok
}

func (s *MemoryStore) Live(tenant domain.TenantID, subject domain.Subject) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if subject.Kind == domain.SubjectGroup {
		group, ok := s.groups[tenant][subject.URN]
		return ok && group.Live
	}
	principal, ok := s.principals[tenant][subject.URN]
	return ok && principal.Live
}

func (s *MemoryStore) AddPendingKind(kind domain.KindSpec) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, published := s.kinds[kind.Name]; published {
		return
	}
	s.pending[kind.Name] = cloneKind(kind)
}

func (s *MemoryStore) PendingKind(name string) (domain.KindSpec, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kind, ok := s.pending[name]
	return cloneKind(kind), ok
}

func (s *MemoryStore) PublishKinds(version int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for name, kind := range s.pending {
		s.kinds[name] = kind
		delete(s.pending, name)
	}
	if version > s.modelVersion {
		s.modelVersion = version
	}
}

func (s *MemoryStore) Kind(name string) (domain.KindSpec, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	kind, ok := s.kinds[name]
	return cloneKind(kind), ok
}

func (s *MemoryStore) ModelVersion() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.modelVersion
}

func cloneKind(kind domain.KindSpec) domain.KindSpec {
	kind.Contains = append([]string(nil), kind.Contains...)
	kind.Relations = append([]domain.Relation(nil), kind.Relations...)
	return kind
}

func sortGrants(grants []domain.Grant) {
	sort.Slice(grants, func(i, j int) bool { return grants[i].ID < grants[j].ID })
}

func sortGroups(groups []domain.Group) {
	sort.Slice(groups, func(i, j int) bool { return groups[i].URN < groups[j].URN })
}
