package iam

import "context"

// Reader answers authorization queries.
type Reader interface {
	Check(ctx context.Context, actor Actor, req CheckRequest) (Decision, error)
	ListObjects(ctx context.Context, actor Actor, req ListObjectsRequest) (ListObjectsResult, error)
	AccessibleCount(ctx context.Context, actor Actor, req AccessibleCountRequest) (AccessibleCountResult, error)
	ListSubjects(ctx context.Context, actor Actor, req ListSubjectsRequest) (ListSubjectsResult, error)
}

// Writer manages nodes, grants and groups.
type Writer interface {
	RegisterNode(ctx context.Context, actor Actor, req RegisterNodeRequest) (NodeResult, error)
	DeleteNode(ctx context.Context, actor Actor, req DeleteNodeRequest) error
	DeleteSubtree(ctx context.Context, actor Actor, req DeleteSubtreeRequest) error
	Grant(ctx context.Context, actor Actor, req GrantRequest) (GrantResult, error)
	Revoke(ctx context.Context, actor Actor, req RevokeRequest) (Revision, error)
	CreateGroup(ctx context.Context, actor Actor, req CreateGroupRequest) (GroupResult, error)
	AddGroupMember(ctx context.Context, actor Actor, req AddGroupMemberRequest) (Revision, error)
	RemoveGroupMember(ctx context.Context, actor Actor, req RemoveGroupMemberRequest) (Revision, error)
	SetGroupAdmin(ctx context.Context, actor Actor, req SetGroupAdminRequest) (Revision, error)
	DeleteGroup(ctx context.Context, actor Actor, req DeleteGroupRequest) (Revision, error)
}

// PrincipalResolver maps an external identity to a tenant principal.
type PrincipalResolver interface {
	ResolvePrincipal(ctx context.Context, actor Actor, req ResolvePrincipalRequest) (PrincipalResult, error)
}

// IdentityAdmin manages principal links and liveness.
type IdentityAdmin interface {
	LinkPrincipal(ctx context.Context, actor Actor, req LinkPrincipalRequest) (PrincipalResult, error)
	DeactivatePrincipal(ctx context.Context, actor Actor, req DeactivatePrincipalRequest) (Revision, error)
	ReactivatePrincipal(ctx context.Context, actor Actor, req ReactivatePrincipalRequest) (Revision, error)
	DeletePrincipal(ctx context.Context, actor Actor, req DeletePrincipalRequest) (Revision, error)
}

// TenantProvisioner manages tenants and the published IAM model.
type TenantProvisioner interface {
	CreateTenant(ctx context.Context, actor Actor, req CreateTenantRequest) (Tenant, error)
	RegisterKind(ctx context.Context, actor Actor, req RegisterKindRequest) error
	PublishModel(ctx context.Context, actor Actor, req PublishModelRequest) error
}

// Service is the transport-independent IAM contract implemented by IAM.
type Service interface {
	Reader
	Writer
	PrincipalResolver
	IdentityAdmin
	TenantProvisioner
}

var _ Service = (*IAM)(nil)
