package core

import (
	"context"
	"fmt"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/eventlog"
)

// CreateGroupRequest creates a flat group and its first admin.
type CreateGroupRequest struct {
	Tenant  domain.TenantID
	GroupID string
	Name    string
}

// GroupResult is the created group and its revision.
type GroupResult struct {
	Group    domain.Group
	Revision domain.Revision
}

// AddGroupMemberRequest adds one user to a group.
type AddGroupMemberRequest struct {
	Tenant domain.TenantID
	Group  domain.URN
	Member domain.Subject
}

// RemoveGroupMemberRequest removes one user from a group.
type RemoveGroupMemberRequest struct {
	Tenant domain.TenantID
	Group  domain.URN
	Member domain.Subject
}

// SetGroupAdminRequest replaces the group admin.
type SetGroupAdminRequest struct {
	Tenant domain.TenantID
	Group  domain.URN
	Admin  domain.Subject
}

// DeleteGroupRequest tombstones a group and retires its URN.
type DeleteGroupRequest struct {
	Tenant domain.TenantID
	Group  domain.URN
	Reason string
}

// CreateGroup makes a live user the new group admin.
func (i *IAM) CreateGroup(ctx context.Context, actor domain.Actor, req CreateGroupRequest) (GroupResult, error) {
	tenant, err := domain.ParseTenantID(string(req.Tenant))
	if err != nil {
		return GroupResult{}, err
	}
	groupURN, err := domain.NewSubjectURN(tenant, domain.SubjectGroup, req.GroupID)
	if err != nil {
		return GroupResult{}, err
	}
	if req.Name == "" {
		return GroupResult{}, fmt.Errorf("%w: group name is required", domain.ErrInvalidSubject)
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return GroupResult{}, err
	}
	if err := i.requireLiveUser(actor, tenant); err != nil {
		return GroupResult{}, err
	}
	if _, ok := i.store.Group(tenant, groupURN); ok {
		return GroupResult{}, fmt.Errorf("%w: group %s is retired", domain.ErrConflict, groupURN)
	}
	if _, ok := i.store.Node(tenant, groupURN); ok {
		return GroupResult{}, fmt.Errorf("%w: urn %s is a node", domain.ErrConflict, groupURN)
	}
	revision, err := i.appendEvents(ctx, ws, actor, "CreateGroup", domain.GroupCreated{
		Group:     groupURN,
		Name:      req.Name,
		Admin:     actor.Subject,
		CreatedBy: actor.ID,
	})
	if err != nil {
		return GroupResult{}, err
	}
	if err := i.project(ctx, ws); err != nil {
		return GroupResult{}, err
	}
	group, _ := i.store.Group(tenant, groupURN)
	return GroupResult{Group: group, Revision: revision}, nil
}

// AddGroupMember adds a live user under group-admin authority.
func (i *IAM) AddGroupMember(ctx context.Context, actor domain.Actor, req AddGroupMemberRequest) (domain.Revision, error) {
	tenant, groupURN, err := i.groupRequest(req.Tenant, req.Group)
	if err != nil {
		return 0, err
	}
	if err := validateGroupMember(tenant, req.Member); err != nil {
		return 0, err
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	if err := i.requireGroupAdmin(actor, tenant, groupURN); err != nil {
		return 0, err
	}
	if !i.store.Live(tenant, req.Member) {
		return 0, fmt.Errorf("%w: member %s is not live", domain.ErrUnauthorized, req.Member.URN)
	}
	for _, member := range i.store.GroupMembers(tenant, groupURN) {
		if member == req.Member {
			return 0, fmt.Errorf("%w: %s is already a member", domain.ErrConflict, req.Member.URN)
		}
	}
	revision, err := i.appendEvents(ctx, ws, actor, "AddGroupMember", domain.MemberAdded{
		Group:   groupURN,
		Member:  req.Member,
		AddedBy: actor.ID,
	})
	if err != nil {
		return 0, err
	}
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	return revision, nil
}

// RemoveGroupMember removes a live member under group-admin authority.
func (i *IAM) RemoveGroupMember(ctx context.Context, actor domain.Actor, req RemoveGroupMemberRequest) (domain.Revision, error) {
	tenant, groupURN, err := i.groupRequest(req.Tenant, req.Group)
	if err != nil {
		return 0, err
	}
	if err := validateGroupMember(tenant, req.Member); err != nil {
		return 0, err
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	if err := i.requireGroupAdmin(actor, tenant, groupURN); err != nil {
		return 0, err
	}
	member := false
	for _, current := range i.store.GroupMembers(tenant, groupURN) {
		if current == req.Member {
			member = true
			break
		}
	}
	if !member {
		return 0, fmt.Errorf("%w: %s is not a member", domain.ErrNotFound, req.Member.URN)
	}
	revision, err := i.appendEvents(ctx, ws, actor, "RemoveGroupMember", domain.MemberRemoved{
		Group:     groupURN,
		Member:    req.Member,
		RemovedBy: actor.ID,
	})
	if err != nil {
		return 0, err
	}
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	return revision, nil
}

// SetGroupAdmin changes the admin under current-admin or tenant-admin authority.
func (i *IAM) SetGroupAdmin(ctx context.Context, actor domain.Actor, req SetGroupAdminRequest) (domain.Revision, error) {
	tenant, groupURN, err := i.groupRequest(req.Tenant, req.Group)
	if err != nil {
		return 0, err
	}
	if err := validateGroupMember(tenant, req.Admin); err != nil {
		return 0, err
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	if err := i.requireGroupAdmin(actor, tenant, groupURN); err != nil {
		return 0, err
	}
	group, _ := i.store.Group(tenant, groupURN)
	if group.Admin == req.Admin {
		return 0, fmt.Errorf("%w: %s is already admin", domain.ErrConflict, req.Admin.URN)
	}
	if !i.store.Live(tenant, req.Admin) {
		return 0, fmt.Errorf("%w: admin %s is not live", domain.ErrUnauthorized, req.Admin.URN)
	}
	revision, err := i.appendEvents(ctx, ws, actor, "SetGroupAdmin", domain.GroupAdminChanged{
		Group:     groupURN,
		Admin:     req.Admin,
		ChangedBy: actor.ID,
	})
	if err != nil {
		return 0, err
	}
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	return revision, nil
}

// DeleteGroup retires a group; its URN is never reusable.
func (i *IAM) DeleteGroup(ctx context.Context, actor domain.Actor, req DeleteGroupRequest) (domain.Revision, error) {
	tenant, groupURN, err := i.groupRequest(req.Tenant, req.Group)
	if err != nil {
		return 0, err
	}

	i.commandMu.Lock()
	defer i.commandMu.Unlock()

	ws := eventlog.TenantWorkspace(tenant)
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	if err := i.requireGroupAdmin(actor, tenant, groupURN); err != nil {
		return 0, err
	}
	revision, err := i.appendEvents(ctx, ws, actor, "DeleteGroup", domain.GroupDeleted{Group: groupURN, Reason: req.Reason})
	if err != nil {
		return 0, err
	}
	if err := i.project(ctx, ws); err != nil {
		return 0, err
	}
	return revision, nil
}

func (i *IAM) groupRequest(tenantID domain.TenantID, rawURN domain.URN) (domain.TenantID, domain.URN, error) {
	tenant, err := domain.ParseTenantID(string(tenantID))
	if err != nil {
		return "", "", err
	}
	urn, err := domain.ParseURN(string(rawURN))
	if err != nil {
		return "", "", err
	}
	if urn.Tenant() != tenant {
		return "", "", fmt.Errorf("%w: group tenant mismatch", domain.ErrInvalidURN)
	}
	if urn.Kind() != string(domain.SubjectGroup) {
		return "", "", fmt.Errorf("%w: %s is not a group urn", domain.ErrInvalidSubject, urn)
	}
	return tenant, urn, nil
}

func (i *IAM) requireGroupAdmin(actor domain.Actor, tenant domain.TenantID, groupURN domain.URN) error {
	if err := i.requireLiveUser(actor, tenant); err != nil {
		return err
	}
	group, ok := i.store.Group(tenant, groupURN)
	if !ok || !group.Live {
		return fmt.Errorf("%w: group %s", domain.ErrNotFound, groupURN)
	}
	if actor.Role == domain.RoleTenantAdmin {
		return nil
	}
	if group.Admin != actor.Subject {
		return fmt.Errorf("%w: %s is not the group admin", domain.ErrForbidden, actor.Subject.URN)
	}
	return nil
}

func validateGroupMember(tenant domain.TenantID, member domain.Subject) error {
	if err := member.Validate(); err != nil {
		return err
	}
	if member.Kind != domain.SubjectUser {
		return fmt.Errorf("%w: groups contain users only", domain.ErrInvalidSubject)
	}
	if member.URN.Tenant() != tenant {
		return fmt.Errorf("%w: member tenant mismatch", domain.ErrInvalidSubject)
	}
	return nil
}
