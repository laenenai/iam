package domain

import "strconv"

// Event is one immutable fact appended to the log.
type Event interface {
	EventType() string
	Stream() string
}

// DeactivationSource says which authority deactivated a principal.
type DeactivationSource string

const (
	SourceGlobal DeactivationSource = "global"
	SourceTenant DeactivationSource = "tenant"
)

type NodeRegistered struct {
	URN       URN
	Kind      string
	Parent    URN
	CreatedBy string
}

func (NodeRegistered) EventType() string { return "node.registered" }
func (e NodeRegistered) Stream() string  { return nodeStream("node", e.URN) }

type NodeDeleted struct {
	URN    URN
	Reason string
}

func (NodeDeleted) EventType() string { return "node.deleted" }
func (e NodeDeleted) Stream() string  { return nodeStream("node", e.URN) }

type GrantIssued struct {
	GrantID   GrantID
	Object    URN
	Subject   Subject
	Relation  Relation
	GrantedBy string
	Reason    string
}

func (GrantIssued) EventType() string { return "grant.issued" }
func (e GrantIssued) Stream() string  { return nodeStream("acl", e.Object) }

type GrantRevoked struct {
	GrantID   GrantID
	Object    URN
	RevokedBy string
	Reason    string
}

func (GrantRevoked) EventType() string { return "grant.revoked" }
func (e GrantRevoked) Stream() string  { return nodeStream("acl", e.Object) }

type GroupCreated struct {
	Group     URN
	Name      string
	Admin     Subject
	CreatedBy string
}

func (GroupCreated) EventType() string { return "group.created" }
func (e GroupCreated) Stream() string  { return groupStream(e.Group) }

type GroupAdminChanged struct {
	Group     URN
	Admin     Subject
	ChangedBy string
}

func (GroupAdminChanged) EventType() string { return "group.admin_changed" }
func (e GroupAdminChanged) Stream() string  { return groupStream(e.Group) }

type MemberAdded struct {
	Group   URN
	Member  Subject
	AddedBy string
}

func (MemberAdded) EventType() string { return "member.added" }
func (e MemberAdded) Stream() string  { return groupStream(e.Group) }

type MemberRemoved struct {
	Group     URN
	Member    Subject
	RemovedBy string
}

func (MemberRemoved) EventType() string { return "member.removed" }
func (e MemberRemoved) Stream() string  { return groupStream(e.Group) }

type GroupDeleted struct {
	Group  URN
	Reason string
}

func (GroupDeleted) EventType() string { return "group.deleted" }
func (e GroupDeleted) Stream() string  { return groupStream(e.Group) }

type PrincipalLinked struct {
	Issuer     string
	ExternalID string
	Subject    Subject
}

func (PrincipalLinked) EventType() string { return "principal.linked" }
func (e PrincipalLinked) Stream() string  { return principalStream(e.Subject) }

type PrincipalDeactivated struct {
	Subject Subject
	Source  DeactivationSource
	Reason  string
}

func (PrincipalDeactivated) EventType() string { return "principal.deactivated" }
func (e PrincipalDeactivated) Stream() string  { return principalStream(e.Subject) }

type PrincipalReactivated struct {
	Subject Subject
	Source  DeactivationSource
	Reason  string
}

func (PrincipalReactivated) EventType() string { return "principal.reactivated" }
func (e PrincipalReactivated) Stream() string  { return principalStream(e.Subject) }

type PrincipalDeleted struct {
	Subject Subject
	Reason  string
}

func (PrincipalDeleted) EventType() string { return "principal.deleted" }
func (e PrincipalDeleted) Stream() string  { return principalStream(e.Subject) }

type KindRegistered struct {
	Version int
	Kind    KindSpec
}

func (KindRegistered) EventType() string { return "kind.registered" }
func (e KindRegistered) Stream() string  { return "model:" + strconv.Itoa(e.Version) }

type ModelPublished struct {
	Version int
}

func (ModelPublished) EventType() string { return "model.published" }
func (e ModelPublished) Stream() string  { return "model:" + strconv.Itoa(e.Version) }

func nodeStream(prefix string, u URN) string {
	if u == "" {
		return ""
	}
	return prefix + ":" + u.Kind() + "_" + u.ID()
}

func groupStream(u URN) string {
	if u == "" {
		return ""
	}
	return "group:" + u.ID()
}

func principalStream(s Subject) string {
	if s.URN == "" {
		return ""
	}
	return "principal:" + string(s.Kind) + "_" + s.URN.ID()
}
