package core

import (
	"context"
	"fmt"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/eventlog"
)

// GrantRequest issues one relation grant.
type GrantRequest struct {
	Tenant   domain.TenantID
	Object   domain.URN
	Subject  domain.Subject
	Relation domain.Relation
	Reason   string
}

// GrantResult carries the issued grant id and its revision.
type GrantResult struct {
	GrantID  domain.GrantID
	Revision domain.Revision
}

// RevokeRequest revokes one live grant.
type RevokeRequest struct {
	Tenant  domain.TenantID
	GrantID domain.GrantID
	Reason  string
}

// CheckRequest asks one authorization question.
type CheckRequest struct {
	Tenant   domain.TenantID
	Subject  domain.Subject
	Object   domain.URN
	Relation domain.Relation
}

// Decision is the answer to a check, with its revision.
type Decision struct {
	Allowed  bool
	Reason   domain.Reason
	Revision domain.Revision
}

// Grant issues a grant after authority, liveness and uniqueness checks.
func (i *IAM) Grant(ctx context.Context, actor domain.Actor, req GrantRequest) (GrantResult, error) {
	tenant, err := domain.ParseTenantID(string(req.Tenant))
	if err != nil {
		return GrantResult{}, err
	}
	object, err := domain.ParseURN(string(req.Object))
	if err != nil {
		return GrantResult{}, err
	}
	if object.Tenant() != tenant {
		return GrantResult{}, fmt.Errorf("%w: object tenant mismatch", domain.ErrInvalidURN)
	}
	if err := req.Subject.Validate(); err != nil {
		return GrantResult{}, err
	}
	if req.Subject.URN.Tenant() != tenant {
		return GrantResult{}, fmt.Errorf("%w: subject tenant mismatch", domain.ErrInvalidSubject)
	}
	if req.Subject.Kind == domain.SubjectAgent {
		return GrantResult{}, fmt.Errorf("%w: agents are not grantable subjects in this plan", domain.ErrUnsupported)
	}
	if !req.Relation.IsGrantable() {
		return GrantResult{}, fmt.Errorf("%w: %q is not grantable", domain.ErrInvalidRelation, req.Relation)
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return GrantResult{}, err
	}
	if err := i.requireLiveUser(actor, tenant); err != nil {
		return GrantResult{}, err
	}
	node, ok := i.store.Node(tenant, object)
	if !ok || !node.Live {
		return GrantResult{}, fmt.Errorf("%w: object %s", domain.ErrNotFound, object)
	}
	kind, ok := i.store.Kind(node.Kind)
	if !ok {
		return GrantResult{}, fmt.Errorf("%w: kind %s", domain.ErrInvalidKind, node.Kind)
	}
	if req.Relation != domain.CanDelete && !declares(kind, req.Relation) {
		return GrantResult{}, fmt.Errorf("%w: %s does not declare %s", domain.ErrInvalidRelation, kind.Name, req.Relation)
	}
	if !i.store.Live(tenant, req.Subject) {
		return GrantResult{}, fmt.Errorf("%w: subject %s is not live", domain.ErrUnauthorized, req.Subject.URN)
	}
	for _, existing := range i.store.GrantsForObject(tenant, object) {
		if existing.Subject == req.Subject && existing.Relation == req.Relation {
			return GrantResult{}, fmt.Errorf("%w: grant already live", domain.ErrConflict)
		}
	}

	required := domain.CanShare
	if req.Relation == domain.CanDelete {
		required = domain.Owner
	}
	allowed, err := i.allows(ctx, actor.Subject, required, object)
	if err != nil {
		return GrantResult{}, err
	}
	if !allowed {
		return GrantResult{}, fmt.Errorf("%w: no %s on %s", domain.ErrForbidden, required, object)
	}

	grantID, err := domain.NewGrantID(i.clock)
	if err != nil {
		return GrantResult{}, err
	}
	revision, err := i.appendEvents(ctx, ws, actor, "Grant", domain.GrantIssued{
		GrantID:   grantID,
		Object:    object,
		Subject:   req.Subject,
		Relation:  req.Relation,
		GrantedBy: actor.ID,
		Reason:    req.Reason,
	})
	if err != nil {
		return GrantResult{}, err
	}
	if err := i.project(ctx, ws); err != nil {
		return GrantResult{}, err
	}
	return GrantResult{GrantID: grantID, Revision: revision}, nil
}

// Revoke revokes a live grant under can_share authority.
func (i *IAM) Revoke(ctx context.Context, actor domain.Actor, req RevokeRequest) (domain.Revision, error) {
	tenant, err := domain.ParseTenantID(string(req.Tenant))
	if err != nil {
		return 0, err
	}
	if req.GrantID == "" {
		return 0, fmt.Errorf("%w: missing grant id", domain.ErrNotFound)
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	if err := i.requireLiveUser(actor, tenant); err != nil {
		return 0, err
	}
	grant, ok := i.store.Grant(tenant, req.GrantID)
	if !ok || !grant.Live {
		return 0, fmt.Errorf("%w: grant %s", domain.ErrNotFound, req.GrantID)
	}
	allowed, err := i.allows(ctx, actor.Subject, domain.CanShare, grant.Object)
	if err != nil {
		return 0, err
	}
	if !allowed {
		return 0, fmt.Errorf("%w: no can_share on %s", domain.ErrForbidden, grant.Object)
	}
	revision, err := i.appendEvents(ctx, ws, actor, "Revoke", domain.GrantRevoked{
		GrantID:   grant.ID,
		Object:    grant.Object,
		RevokedBy: actor.ID,
		Reason:    req.Reason,
	})
	if err != nil {
		return 0, err
	}
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	return revision, nil
}

// Check answers one authorization question, filtering both live projections.
func (i *IAM) Check(ctx context.Context, actor domain.Actor, req CheckRequest) (Decision, error) {
	if err := authorize(actor, domain.RoleUser, domain.RoleAgent, domain.RoleTenantAdmin, domain.RoleAuditor); err != nil {
		return Decision{}, err
	}
	tenant, err := domain.ParseTenantID(string(req.Tenant))
	if err != nil {
		return Decision{}, err
	}
	if err := req.Subject.Validate(); err != nil {
		return Decision{}, err
	}
	object, err := domain.ParseURN(string(req.Object))
	if err != nil {
		return Decision{}, err
	}
	if req.Subject.URN.Tenant() != tenant || object.Tenant() != tenant {
		return Decision{}, fmt.Errorf("%w: tenant mismatch", domain.ErrInvalidURN)
	}
	if actor.Tenant != tenant {
		return Decision{}, fmt.Errorf("%w: actor tenant mismatch", domain.ErrForbidden)
	}
	if actor.Role == domain.RoleUser || actor.Role == domain.RoleAgent {
		if actor.Subject != req.Subject {
			return Decision{}, fmt.Errorf("%w: actor may only check itself", domain.ErrForbidden)
		}
	}
	if actor.Subject.Kind == domain.SubjectAgent || req.Subject.Kind == domain.SubjectAgent {
		return Decision{}, fmt.Errorf("%w: agents are not supported in this plan", domain.ErrUnsupported)
	}
	if req.Subject.Kind == domain.SubjectGroup {
		return Decision{}, fmt.Errorf("%w: groups are not checked subjects", domain.ErrUnsupported)
	}

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return Decision{}, err
	}
	if actor.Role == domain.RoleTenantAdmin && !i.store.Live(tenant, actor.Subject) {
		return Decision{}, fmt.Errorf("%w: tenant admin is not live", domain.ErrForbidden)
	}
	return i.evaluateProjected(ctx, tenant, req.Subject, req.Relation, object, i.projector.Applied(ws))
}

func declares(kind domain.KindSpec, relation domain.Relation) bool {
	for _, declared := range kind.Relations {
		if declared == relation {
			return true
		}
	}
	return false
}

func checkable(relation domain.Relation) bool {
	switch relation {
	case domain.Owner, domain.Editor, domain.Commenter, domain.Viewer,
		domain.CanShare, domain.CanDelete, domain.CanView, domain.CanEdit, domain.CanComment:
		return true
	default:
		return false
	}
}
