package core

import (
	"context"
	"fmt"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/eventlog"
)

type RegisterNodeRequest struct {
	Tenant domain.TenantID
	URN    domain.URN
	Parent domain.URN
}

type NodeResult struct {
	Node     domain.Node
	Revision domain.Revision
}

type DeleteNodeRequest struct {
	Tenant domain.TenantID
	URN    domain.URN
	Reason string
}

type DeleteSubtreeRequest struct {
	Tenant domain.TenantID
	URN    domain.URN
	Reason string
}

func (i *IAM) RegisterNode(ctx context.Context, actor domain.Actor, req RegisterNodeRequest) (NodeResult, error) {
	tenant, urn, err := i.nodeRequest(req.Tenant, req.URN, req.Parent)
	if err != nil {
		return NodeResult{}, err
	}
	if urn.Kind() == domain.RootKind {
		return NodeResult{}, fmt.Errorf("%w: root is created by CreateTenant", domain.ErrForbidden)
	}
	if req.Parent == "" {
		return NodeResult{}, fmt.Errorf("%w: a non-root node needs a parent", domain.ErrInvalidURN)
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return NodeResult{}, err
	}
	if err := i.requireLiveUser(actor, tenant); err != nil {
		return NodeResult{}, err
	}
	if _, exists := i.store.Node(tenant, urn); exists {
		return NodeResult{}, fmt.Errorf("%w: urn %s is retired or registered", domain.ErrConflict, urn)
	}
	if kind, ok := i.store.Kind(urn.Kind()); !ok {
		return NodeResult{}, fmt.Errorf("%w: kind %s is not published", domain.ErrInvalidKind, urn.Kind())
	} else if err := kind.Validate(); err != nil {
		return NodeResult{}, err
	}

	parent, ok := i.store.Node(tenant, req.Parent)
	if !ok || !parent.Live {
		return NodeResult{}, fmt.Errorf("%w: parent %s", domain.ErrNotFound, req.Parent)
	}
	parentKind, ok := i.store.Kind(parent.Kind)
	if !ok {
		return NodeResult{}, fmt.Errorf("%w: parent kind %s", domain.ErrInvalidKind, parent.Kind)
	}
	if !containsKind(parentKind, urn.Kind()) {
		return NodeResult{}, fmt.Errorf("%w: %s may not contain %s", domain.ErrInvalidKind, parent.Kind, urn.Kind())
	}
	allowed, err := i.allows(ctx, actor.Subject, domain.CanShare, parent.URN)
	if err != nil {
		return NodeResult{}, err
	}
	if !allowed {
		return NodeResult{}, fmt.Errorf("%w: no can_share on %s", domain.ErrForbidden, parent.URN)
	}

	grantID, err := domain.NewGrantID(i.clock)
	if err != nil {
		return NodeResult{}, err
	}
	revision, err := i.appendEvents(ctx, ws, actor, "RegisterNode",
		domain.NodeRegistered{URN: urn, Kind: urn.Kind(), Parent: parent.URN, CreatedBy: actor.ID},
		domain.GrantIssued{
			GrantID:   grantID,
			Object:    urn,
			Subject:   actor.Subject,
			Relation:  domain.Owner,
			GrantedBy: actor.ID,
			Reason:    "node creator",
		},
	)
	if err != nil {
		return NodeResult{}, err
	}
	if err := i.project(ctx, ws); err != nil {
		return NodeResult{}, err
	}
	node, _ := i.store.Node(tenant, urn)
	return NodeResult{Node: node, Revision: revision}, nil
}

func (i *IAM) DeleteNode(ctx context.Context, actor domain.Actor, req DeleteNodeRequest) error {
	tenant, urn, err := i.nodeRequest(req.Tenant, req.URN, "")
	if err != nil {
		return err
	}
	if urn.Kind() == domain.RootKind {
		return fmt.Errorf("%w: root cannot be deleted", domain.ErrForbidden)
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return err
	}
	if err := i.requireLiveUser(actor, tenant); err != nil {
		return err
	}
	node, ok := i.store.Node(tenant, urn)
	if !ok || !node.Live {
		return fmt.Errorf("%w: node %s", domain.ErrNotFound, urn)
	}
	for _, candidate := range i.store.Nodes(tenant) {
		if candidate.Live && candidate.Parent == urn {
			return fmt.Errorf("%w: node %s has live children", domain.ErrConflict, urn)
		}
	}
	canShare, err := i.allows(ctx, actor.Subject, domain.CanShare, urn)
	if err != nil {
		return err
	}
	if !canShare {
		canDelete, err := i.allows(ctx, actor.Subject, domain.CanDelete, urn)
		if err != nil {
			return err
		}
		if !canDelete {
			return fmt.Errorf("%w: no can_share or can_delete on %s", domain.ErrForbidden, urn)
		}
	}
	if _, err := i.appendEvents(ctx, ws, actor, "DeleteNode", domain.NodeDeleted{URN: urn, Reason: req.Reason}); err != nil {
		return err
	}
	return i.project(ctx, ws)
}

func (i *IAM) DeleteSubtree(ctx context.Context, actor domain.Actor, req DeleteSubtreeRequest) error {
	tenant, urn, err := i.nodeRequest(req.Tenant, req.URN, "")
	if err != nil {
		return err
	}
	if urn.Kind() == domain.RootKind {
		return fmt.Errorf("%w: root cannot be deleted", domain.ErrForbidden)
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return err
	}
	if err := i.requireLiveUser(actor, tenant); err != nil {
		return err
	}
	node, ok := i.store.Node(tenant, urn)
	if !ok || !node.Live {
		return fmt.Errorf("%w: node %s", domain.ErrNotFound, urn)
	}
	owned, err := i.allows(ctx, actor.Subject, domain.Owner, urn)
	if err != nil {
		return err
	}
	if !owned {
		return fmt.Errorf("%w: subtree deletion requires owner", domain.ErrForbidden)
	}

	order := i.subtreePostOrder(tenant, node)
	events := make([]domain.Event, 0, len(order))
	for _, descendant := range order {
		events = append(events, domain.NodeDeleted{URN: descendant.URN, Reason: req.Reason})
	}
	if _, err := i.appendEvents(ctx, ws, actor, "DeleteSubtree", events...); err != nil {
		return err
	}
	return i.project(ctx, ws)
}

func (i *IAM) nodeRequest(tenantID domain.TenantID, rawURN, rawParent domain.URN) (domain.TenantID, domain.URN, error) {
	tenant, err := domain.ParseTenantID(string(tenantID))
	if err != nil {
		return "", "", err
	}
	urn, err := domain.ParseURN(string(rawURN))
	if err != nil {
		return "", "", err
	}
	if urn.Tenant() != tenant {
		return "", "", fmt.Errorf("%w: urn tenant mismatch", domain.ErrInvalidURN)
	}
	if rawParent != "" {
		parent, err := domain.ParseURN(string(rawParent))
		if err != nil {
			return "", "", err
		}
		if parent.Tenant() != tenant {
			return "", "", fmt.Errorf("%w: parent tenant mismatch", domain.ErrInvalidURN)
		}
	}
	return tenant, urn, nil
}

func (i *IAM) requireLiveUser(actor domain.Actor, tenant domain.TenantID) error {
	if err := authorize(actor, domain.RoleUser, domain.RoleTenantAdmin); err != nil {
		return err
	}
	if actor.Tenant != tenant {
		return fmt.Errorf("%w: actor tenant mismatch", domain.ErrForbidden)
	}
	if !i.store.Live(tenant, actor.Subject) {
		return fmt.Errorf("%w: actor is not live", domain.ErrUnauthorized)
	}
	return nil
}

func (i *IAM) allows(ctx context.Context, subject domain.Subject, relation domain.Relation, object domain.URN) (bool, error) {
	allowed, _, err := i.engine.Check(ctx, subject, relation, object)
	return allowed, err
}

func (i *IAM) subtreePostOrder(tenant domain.TenantID, root domain.Node) []domain.Node {
	children := make(map[domain.URN][]domain.Node)
	for _, node := range i.store.Nodes(tenant) {
		if node.Live && node.Parent != "" {
			children[node.Parent] = append(children[node.Parent], node)
		}
	}
	var order []domain.Node
	seen := make(map[domain.URN]struct{})
	var walk func(domain.Node)
	walk = func(node domain.Node) {
		if _, ok := seen[node.URN]; ok {
			return
		}
		seen[node.URN] = struct{}{}
		for _, child := range children[node.URN] {
			walk(child)
		}
		order = append(order, node)
	}
	walk(root)
	return order
}

func containsKind(parent domain.KindSpec, child string) bool {
	if parent.ContainsAny {
		return true
	}
	for _, name := range parent.Contains {
		if name == child {
			return true
		}
	}
	return false
}
