package iam

import (
	"context"

	"github.com/laenenai/iam/internal/core"
	"github.com/laenenai/iam/internal/domain"
)

//nolint:revive // aliases inherit their documentation from the aliased type.
type (
	TenantID           = domain.TenantID
	URN                = domain.URN
	SubjectKind        = domain.SubjectKind
	Subject            = domain.Subject
	Relation           = domain.Relation
	GrantID            = domain.GrantID
	Revision           = domain.Revision
	ActorRole          = domain.ActorRole
	Actor              = domain.Actor
	Clock              = domain.Clock
	SystemClock        = domain.SystemClock
	FixedClock         = domain.FixedClock
	Node               = domain.Node
	Grant              = domain.Grant
	Group              = domain.Group
	Principal          = domain.Principal
	KindSpec           = domain.KindSpec
	Event              = domain.Event
	Reason             = domain.Reason
	DeactivationSource = domain.DeactivationSource

	NodeRegistered       = domain.NodeRegistered
	NodeDeleted          = domain.NodeDeleted
	GrantIssued          = domain.GrantIssued
	GrantRevoked         = domain.GrantRevoked
	GroupCreated         = domain.GroupCreated
	GroupAdminChanged    = domain.GroupAdminChanged
	MemberAdded          = domain.MemberAdded
	MemberRemoved        = domain.MemberRemoved
	GroupDeleted         = domain.GroupDeleted
	PrincipalLinked      = domain.PrincipalLinked
	PrincipalDeactivated = domain.PrincipalDeactivated
	PrincipalReactivated = domain.PrincipalReactivated
	PrincipalDeleted     = domain.PrincipalDeleted
	KindRegistered       = domain.KindRegistered
	ModelPublished       = domain.ModelPublished

	IAM    = core.IAM
	Config = core.Config

	CreateTenantRequest = core.CreateTenantRequest
	Tenant              = core.Tenant

	RegisterKindRequest = core.RegisterKindRequest
	PublishModelRequest = core.PublishModelRequest

	RegisterNodeRequest  = core.RegisterNodeRequest
	NodeResult           = core.NodeResult
	DeleteNodeRequest    = core.DeleteNodeRequest
	DeleteSubtreeRequest = core.DeleteSubtreeRequest

	GrantRequest  = core.GrantRequest
	GrantResult   = core.GrantResult
	RevokeRequest = core.RevokeRequest
	CheckRequest  = core.CheckRequest
	Decision      = core.Decision

	CreateGroupRequest       = core.CreateGroupRequest
	GroupResult              = core.GroupResult
	AddGroupMemberRequest    = core.AddGroupMemberRequest
	RemoveGroupMemberRequest = core.RemoveGroupMemberRequest
	SetGroupAdminRequest     = core.SetGroupAdminRequest
	DeleteGroupRequest       = core.DeleteGroupRequest

	LinkPrincipalRequest       = core.LinkPrincipalRequest
	PrincipalResult            = core.PrincipalResult
	DeactivatePrincipalRequest = core.DeactivatePrincipalRequest
	ReactivatePrincipalRequest = core.ReactivatePrincipalRequest
	DeletePrincipalRequest     = core.DeletePrincipalRequest

	ListObjectsRequest     = core.ListObjectsRequest
	ListObjectsResult      = core.ListObjectsResult
	AccessibleCountRequest = core.AccessibleCountRequest
	AccessibleCountResult  = core.AccessibleCountResult
	ListSubjectsRequest    = core.ListSubjectsRequest
	SubjectGrant           = core.SubjectGrant
	ListSubjectsResult     = core.ListSubjectsResult
)

// Subjects, relations, roles, sources, kinds and decision reasons.
const (
	SubjectUser  = domain.SubjectUser
	SubjectAgent = domain.SubjectAgent
	SubjectGroup = domain.SubjectGroup

	Parent     = domain.Parent
	Owner      = domain.Owner
	Editor     = domain.Editor
	Commenter  = domain.Commenter
	Viewer     = domain.Viewer
	CanShare   = domain.CanShare
	CanDelete  = domain.CanDelete
	CanView    = domain.CanView
	CanEdit    = domain.CanEdit
	CanComment = domain.CanComment
	Member     = domain.Member
	Admin      = domain.Admin

	RoleUser            = domain.RoleUser
	RoleAgent           = domain.RoleAgent
	RoleTenantAdmin     = domain.RoleTenantAdmin
	RoleDeploymentAdmin = domain.RoleDeploymentAdmin
	RoleIdentityAdapter = domain.RoleIdentityAdapter
	RoleAuditor         = domain.RoleAuditor

	SourceGlobal = domain.SourceGlobal
	SourceTenant = domain.SourceTenant

	RootKind = domain.RootKind

	ReasonNoGrant   = domain.ReasonNoGrant
	ReasonDirect    = domain.ReasonDirect
	ReasonUserset   = domain.ReasonUserset
	ReasonInherited = domain.ReasonInherited
)

// Typed sentinels returned by the facade.
var (
	ErrInvalidTenant     = domain.ErrInvalidTenant
	ErrInvalidURN        = domain.ErrInvalidURN
	ErrInvalidSubject    = domain.ErrInvalidSubject
	ErrInvalidRelation   = domain.ErrInvalidRelation
	ErrInvalidKind       = domain.ErrInvalidKind
	ErrInvalidActor      = domain.ErrInvalidActor
	ErrNotFound          = domain.ErrNotFound
	ErrConflict          = domain.ErrConflict
	ErrForbidden         = domain.ErrForbidden
	ErrUnauthorized      = domain.ErrUnauthorized
	ErrStale             = domain.ErrStale
	ErrModelNotProjected = domain.ErrModelNotProjected
	ErrUnknownEvent      = domain.ErrUnknownEvent
	ErrUnsupported       = domain.ErrUnsupported
	ErrIDGeneration      = domain.ErrIDGeneration
)

// NewMemory constructs the reference in-memory IAM.
func NewMemory(ctx context.Context, cfg Config) (*IAM, error) {
	return core.NewMemory(ctx, cfg)
}

// ParseTenantID validates a tenant slug.
func ParseTenantID(s string) (TenantID, error) {
	return domain.ParseTenantID(s)
}

// ParseURN validates a three-segment IAM URN.
func ParseURN(s string) (URN, error) {
	return domain.ParseURN(s)
}

// NewNodeURN builds and validates a node URN.
func NewNodeURN(tenant TenantID, kind, id string) (URN, error) {
	return domain.NewNodeURN(tenant, kind, id)
}

// NewSubjectURN builds and validates a subject URN.
func NewSubjectURN(tenant TenantID, kind SubjectKind, id string) (URN, error) {
	return domain.NewSubjectURN(tenant, kind, id)
}

// NewUserSubject builds a user subject.
func NewUserSubject(tenant TenantID, id string) (Subject, error) {
	return domain.NewUserSubject(tenant, id)
}

// NewGroupSubject builds a group subject.
func NewGroupSubject(tenant TenantID, id string) (Subject, error) {
	return domain.NewGroupSubject(tenant, id)
}

// ParseSubject parses a user, agent or group subject URN.
func ParseSubject(urn URN) (Subject, error) {
	return domain.ParseSubject(urn)
}

// NewGrantID mints a ULID grant id at the clock time.
func NewGrantID(clock Clock) (GrantID, error) {
	return domain.NewGrantID(clock)
}

// DefaultKinds returns the built-in node kinds.
func DefaultKinds() []KindSpec {
	return domain.DefaultKinds()
}
