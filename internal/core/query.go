package core

import (
	"context"
	"fmt"
	"sort"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/eventlog"
)

// ListObjectsRequest asks which live nodes of a kind a subject can reach.
type ListObjectsRequest struct {
	Tenant   domain.TenantID
	Subject  domain.Subject
	Relation domain.Relation
	Kind     string
}

// ListObjectsResult is the sorted reachable URNs and the revision used.
type ListObjectsResult struct {
	Objects  []domain.URN
	Revision domain.Revision
}

// AccessibleCountRequest asks for a count of reachable nodes.
type AccessibleCountRequest struct {
	Tenant   domain.TenantID
	Subject  domain.Subject
	Relation domain.Relation
	Kind     string
}

// AccessibleCountResult is the count and the revision used.
type AccessibleCountResult struct {
	Count    int
	Revision domain.Revision
}

// ListSubjectsRequest asks who can reach an object with provenance.
type ListSubjectsRequest struct {
	Tenant   domain.TenantID
	Object   domain.URN
	Relation domain.Relation
}

// SubjectGrant is one effective subject and its contributing grant.
type SubjectGrant struct {
	Subject   domain.Subject
	ViaGroup  domain.URN
	GrantID   domain.GrantID
	Object    domain.URN
	Relation  domain.Relation
	GrantedBy string
	Depth     int
}

// ListSubjectsResult is the provenance set and the revision used.
type ListSubjectsResult struct {
	Grants   []SubjectGrant
	Revision domain.Revision
}

// ListObjects returns the sorted live nodes a subject can reach.
func (i *IAM) ListObjects(ctx context.Context, actor domain.Actor, req ListObjectsRequest) (ListObjectsResult, error) {
	objects, revision, err := i.listObjects(ctx, actor, req.Tenant, req.Subject, req.Relation, req.Kind)
	if err != nil {
		return ListObjectsResult{}, err
	}
	return ListObjectsResult{Objects: objects, Revision: revision}, nil
}

// AccessibleCount returns the number of reachable live nodes.
func (i *IAM) AccessibleCount(ctx context.Context, actor domain.Actor, req AccessibleCountRequest) (AccessibleCountResult, error) {
	objects, revision, err := i.listObjects(ctx, actor, req.Tenant, req.Subject, req.Relation, req.Kind)
	if err != nil {
		return AccessibleCountResult{}, err
	}
	return AccessibleCountResult{Count: len(objects), Revision: revision}, nil
}

func (i *IAM) listObjects(ctx context.Context, actor domain.Actor, tenantID domain.TenantID, subject domain.Subject, relation domain.Relation, kind string) ([]domain.URN, domain.Revision, error) {
	tenant, err := i.queryRequest(actor, tenantID, subject, relation)
	if err != nil {
		return nil, 0, err
	}
	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return nil, 0, err
	}
	revision := i.projector.Applied(ws)
	var objects []domain.URN
	for _, node := range i.store.Nodes(tenant) {
		if !node.Live {
			continue
		}
		if kind != "" && node.Kind != kind {
			continue
		}
		decision, err := i.evaluateProjected(ctx, tenant, subject, relation, node.URN, revision)
		if err != nil {
			return nil, 0, err
		}
		if decision.Allowed {
			objects = append(objects, node.URN)
		}
	}
	sort.Slice(objects, func(a, b int) bool { return objects[a] < objects[b] })
	return objects, revision, nil
}

// ListSubjects returns effective subjects with every contributing grant.
func (i *IAM) ListSubjects(ctx context.Context, actor domain.Actor, req ListSubjectsRequest) (ListSubjectsResult, error) {
	tenant, err := domain.ParseTenantID(string(req.Tenant))
	if err != nil {
		return ListSubjectsResult{}, err
	}
	object, err := domain.ParseURN(string(req.Object))
	if err != nil {
		return ListSubjectsResult{}, err
	}
	if object.Tenant() != tenant {
		return ListSubjectsResult{}, fmt.Errorf("%w: object tenant mismatch", domain.ErrInvalidURN)
	}
	base, canDelete, ok := subjectQueryRelation(req.Relation)
	if !ok {
		return ListSubjectsResult{}, fmt.Errorf("%w: %q", domain.ErrInvalidRelation, req.Relation)
	}
	if err := authorize(actor, domain.RoleUser, domain.RoleTenantAdmin, domain.RoleAuditor); err != nil {
		return ListSubjectsResult{}, err
	}
	if actor.Tenant != tenant {
		return ListSubjectsResult{}, fmt.Errorf("%w: actor tenant mismatch", domain.ErrForbidden)
	}

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return ListSubjectsResult{}, err
	}
	revision := i.projector.Applied(ws)
	if actor.Role != domain.RoleAuditor {
		if !i.store.Live(tenant, actor.Subject) {
			return ListSubjectsResult{}, fmt.Errorf("%w: actor is not live", domain.ErrForbidden)
		}
		allowed, err := i.allows(ctx, actor.Subject, domain.CanShare, object)
		if err != nil {
			return ListSubjectsResult{}, err
		}
		if !allowed {
			return ListSubjectsResult{}, fmt.Errorf("%w: no can_share on %s", domain.ErrForbidden, object)
		}
	}

	var grants []SubjectGrant
	current := object
	depth := 0
	for current != "" {
		node, ok := i.store.Node(tenant, current)
		if !ok || !node.Live {
			break
		}
		for _, grant := range i.store.GrantsForObject(tenant, current) {
			if !subjectGrantIncluded(grant, base, canDelete, depth) {
				continue
			}
			if grant.Subject.Kind == domain.SubjectGroup {
				group, ok := i.store.Group(tenant, grant.Subject.URN)
				if !ok || !group.Live {
					continue
				}
				for _, member := range i.store.GroupMembers(tenant, grant.Subject.URN) {
					if !i.store.Live(tenant, member) {
						continue
					}
					grants = append(grants, SubjectGrant{
						Subject:   member,
						ViaGroup:  grant.Subject.URN,
						GrantID:   grant.ID,
						Object:    grant.Object,
						Relation:  grant.Relation,
						GrantedBy: grant.GrantedBy,
						Depth:     depth,
					})
				}
				continue
			}
			if !i.store.Live(tenant, grant.Subject) {
				continue
			}
			grants = append(grants, SubjectGrant{
				Subject:   grant.Subject,
				GrantID:   grant.ID,
				Object:    grant.Object,
				Relation:  grant.Relation,
				GrantedBy: grant.GrantedBy,
				Depth:     depth,
			})
		}
		current = node.Parent
		depth++
	}
	sort.Slice(grants, func(a, b int) bool {
		if grants[a].Subject.URN != grants[b].Subject.URN {
			return grants[a].Subject.URN < grants[b].Subject.URN
		}
		if grants[a].Object != grants[b].Object {
			return grants[a].Object < grants[b].Object
		}
		return grants[a].GrantID < grants[b].GrantID
	})
	return ListSubjectsResult{Grants: grants, Revision: revision}, nil
}

func (i *IAM) queryRequest(actor domain.Actor, tenantID domain.TenantID, subject domain.Subject, relation domain.Relation) (domain.TenantID, error) {
	if err := authorize(actor, domain.RoleUser, domain.RoleAgent, domain.RoleTenantAdmin, domain.RoleAuditor); err != nil {
		return "", err
	}
	tenant, err := domain.ParseTenantID(string(tenantID))
	if err != nil {
		return "", err
	}
	if err := subject.Validate(); err != nil {
		return "", err
	}
	if subject.URN.Tenant() != tenant {
		return "", fmt.Errorf("%w: subject tenant mismatch", domain.ErrInvalidSubject)
	}
	if actor.Tenant != tenant {
		return "", fmt.Errorf("%w: actor tenant mismatch", domain.ErrForbidden)
	}
	if actor.Role == domain.RoleUser || actor.Role == domain.RoleAgent {
		if actor.Subject != subject {
			return "", fmt.Errorf("%w: actor may only query itself", domain.ErrForbidden)
		}
	}
	if actor.Subject.Kind == domain.SubjectAgent || subject.Kind == domain.SubjectAgent {
		return "", fmt.Errorf("%w: agents are not supported in this plan", domain.ErrUnsupported)
	}
	if !checkable(relation) {
		return "", fmt.Errorf("%w: %q", domain.ErrInvalidRelation, relation)
	}
	return tenant, nil
}

func (i *IAM) evaluate(ctx context.Context, tenant domain.TenantID, subject domain.Subject, relation domain.Relation, object domain.URN) (Decision, error) {
	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return Decision{}, err
	}
	return i.evaluateProjected(ctx, tenant, subject, relation, object, i.projector.Applied(ws))
}

func (i *IAM) evaluateProjected(ctx context.Context, tenant domain.TenantID, subject domain.Subject, relation domain.Relation, object domain.URN, revision domain.Revision) (Decision, error) {
	if !checkable(relation) {
		return Decision{Allowed: false, Reason: domain.ReasonNoGrant, Revision: revision}, nil
	}
	node, ok := i.store.Node(tenant, object)
	if !ok || !node.Live {
		return Decision{Allowed: false, Reason: domain.ReasonNoGrant, Revision: revision}, nil
	}
	if !i.store.Live(tenant, subject) {
		return Decision{Allowed: false, Reason: domain.ReasonNoGrant, Revision: revision}, nil
	}
	allowed, reason, err := i.engine.Check(ctx, subject, relation, object)
	if err != nil {
		return Decision{}, err
	}
	if !allowed {
		reason = domain.ReasonNoGrant
	}
	return Decision{Allowed: allowed, Reason: reason, Revision: revision}, nil
}

func subjectQueryRelation(relation domain.Relation) (base domain.Relation, canDelete bool, ok bool) {
	switch relation {
	case domain.Owner, domain.Editor, domain.Commenter, domain.Viewer:
		return relation, false, true
	case domain.CanView:
		return domain.Viewer, false, true
	case domain.CanEdit:
		return domain.Editor, false, true
	case domain.CanComment:
		return domain.Commenter, false, true
	case domain.CanShare:
		return domain.Owner, false, true
	case domain.CanDelete:
		return domain.CanDelete, true, true
	default:
		return "", false, false
	}
}

func subjectGrantIncluded(grant domain.Grant, base domain.Relation, canDelete bool, depth int) bool {
	if canDelete {
		if grant.Relation == domain.Owner {
			return true
		}
		return depth == 0 && grant.Relation == domain.CanDelete
	}
	return grant.Relation.Rank() >= base.Rank()
}
