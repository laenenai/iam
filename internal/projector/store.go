// Package projector applies the event log to the read models and the engine.
package projector

import (
	"github.com/laenenai/iam/internal/domain"
)

// Store is the disposable read model rebuilt from the log. Queries that feed
// authorization return live rows only; Grant returns a revoked grant so the
// projector can distinguish "revoked" from "never existed".
type Store interface {
	SetNode(domain.Node)
	Node(tenant domain.TenantID, urn domain.URN) (domain.Node, bool)
	Nodes(tenant domain.TenantID) []domain.Node

	SetGrant(domain.Grant)
	Grant(tenant domain.TenantID, id domain.GrantID) (domain.Grant, bool)
	GrantsForObject(tenant domain.TenantID, object domain.URN) []domain.Grant
	GrantsForSubject(tenant domain.TenantID, subject domain.Subject) []domain.Grant

	GroupsForMember(tenant domain.TenantID, member domain.Subject) []domain.Group
	GroupsForAdmin(tenant domain.TenantID, admin domain.Subject) []domain.Group
	SetGroup(domain.Group)
	Group(tenant domain.TenantID, urn domain.URN) (domain.Group, bool)
	SetGroupMember(tenant domain.TenantID, group domain.URN, member domain.Subject, live bool)
	GroupMembers(tenant domain.TenantID, group domain.URN) []domain.Subject

	SetPrincipal(domain.Principal)
	Principal(tenant domain.TenantID, subject domain.Subject) (domain.Principal, bool)
	Live(tenant domain.TenantID, subject domain.Subject) bool

	AddPendingKind(domain.KindSpec)
	PendingKind(name string) (domain.KindSpec, bool)
	PublishKinds(version int)
	Kind(name string) (domain.KindSpec, bool)
	ModelVersion() int
}
