package core

import (
	"context"
	"fmt"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/eventlog"
)

type CreateTenantRequest struct {
	Tenant     domain.TenantID
	RootID     string
	FirstOwner domain.Subject
}

type Tenant struct {
	ID         domain.TenantID
	Root       domain.URN
	OwnerGrant domain.GrantID
	Revision   domain.Revision
}

func (i *IAM) CreateTenant(ctx context.Context, actor domain.Actor, req CreateTenantRequest) (Tenant, error) {
	if err := authorize(actor, domain.RoleDeploymentAdmin); err != nil {
		return Tenant{}, err
	}
	tenant, err := domain.ParseTenantID(string(req.Tenant))
	if err != nil {
		return Tenant{}, err
	}
	root, err := domain.NewNodeURN(tenant, domain.RootKind, req.RootID)
	if err != nil {
		return Tenant{}, err
	}
	if err := req.FirstOwner.Validate(); err != nil {
		return Tenant{}, err
	}
	if req.FirstOwner.Kind != domain.SubjectUser {
		return Tenant{}, fmt.Errorf("%w: first owner must be a user", domain.ErrInvalidSubject)
	}
	if req.FirstOwner.URN.Tenant() != tenant {
		return Tenant{}, fmt.Errorf("%w: first owner tenant mismatch", domain.ErrInvalidSubject)
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return Tenant{}, err
	}
	for _, node := range i.store.Nodes(tenant) {
		if node.Kind == domain.RootKind {
			return Tenant{}, fmt.Errorf("%w: tenant %s already has a root", domain.ErrConflict, tenant)
		}
	}

	grantID, err := domain.NewGrantID(i.clock)
	if err != nil {
		return Tenant{}, err
	}
	revision, err := i.appendEvents(ctx, ws, actor, "CreateTenant",
		domain.NodeRegistered{URN: root, Kind: domain.RootKind, CreatedBy: actor.ID},
		domain.GrantIssued{
			GrantID:   grantID,
			Object:    root,
			Subject:   req.FirstOwner,
			Relation:  domain.Owner,
			GrantedBy: actor.ID,
			Reason:    "tenant bootstrap",
		},
	)
	if err != nil {
		return Tenant{}, err
	}
	if err := i.project(ctx, ws); err != nil {
		return Tenant{}, err
	}
	return Tenant{ID: tenant, Root: root, OwnerGrant: grantID, Revision: revision}, nil
}
