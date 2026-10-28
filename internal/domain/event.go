package domain

import "strconv"

// Event is one immutable fact appended to the log.
type Event interface {
	EventType() string
	Stream() string
}

// DeactivationSource says which authority deactivated a principal.
type DeactivationSource string

// Deactivation sources.
const (
	SourceGlobal DeactivationSource = "global"
	SourceTenant DeactivationSource = "tenant"
)

// NodeRegistered records a registered node.
type NodeRegistered struct {
	URN       URN
	Kind      string
	Parent    URN
	CreatedBy string
}

// EventType reports the stable event name.
func (NodeRegistered) EventType() string { return "node.registered" }

// Stream returns the event stream identity.
func (e NodeRegistered) Stream() string { return nodeStream("node", e.URN) }

// NodeDeleted tombstones a node.
type NodeDeleted struct {
	URN    URN
	Reason string
}

// EventType reports the stable event name.
func (NodeDeleted) EventType() string { return "node.deleted" }

// Stream returns the event stream identity.
func (e NodeDeleted) Stream() string { return nodeStream("node", e.URN) }

// GrantIssued records a new grant.
type GrantIssued struct {
	GrantID   GrantID
	Object    URN
	Subject   Subject
	Relation  Relation
	GrantedBy string
	Reason    string
}

// EventType reports the stable event name.
func (GrantIssued) EventType() string { return "grant.issued" }

// Stream returns the event stream identity.
func (e GrantIssued) Stream() string { return nodeStream("acl", e.Object) }

// GrantRevoked revokes a grant.
type GrantRevoked struct {
	GrantID   GrantID
	Object    URN
	RevokedBy string
	Reason    string
}

// EventType reports the stable event name.
func (GrantRevoked) EventType() string { return "grant.revoked" }

// Stream returns the event stream identity.
func (e GrantRevoked) Stream() string { return nodeStream("acl", e.Object) }

// GroupCreated records a new group.
type GroupCreated struct {
	Group     URN
	Name      string
	Admin     Subject
	CreatedBy string
}

// EventType reports the stable event name.
func (GroupCreated) EventType() string { return "group.created" }

// Stream returns the event stream identity.
func (e GroupCreated) Stream() string { return groupStream(e.Group) }

// GroupAdminChanged replaces a group admin.
type GroupAdminChanged struct {
	Group     URN
	Admin     Subject
	ChangedBy string
}

// EventType reports the stable event name.
func (GroupAdminChanged) EventType() string { return "group.admin_changed" }

// Stream returns the event stream identity.
func (e GroupAdminChanged) Stream() string { return groupStream(e.Group) }

// MemberAdded records a group membership.
type MemberAdded struct {
	Group   URN
	Member  Subject
	AddedBy string
}

// EventType reports the stable event name.
func (MemberAdded) EventType() string { return "member.added" }

// Stream returns the event stream identity.
func (e MemberAdded) Stream() string { return groupStream(e.Group) }

// MemberRemoved removes a group membership.
type MemberRemoved struct {
	Group     URN
	Member    Subject
	RemovedBy string
}

// EventType reports the stable event name.
func (MemberRemoved) EventType() string { return "member.removed" }

// Stream returns the event stream identity.
func (e MemberRemoved) Stream() string { return groupStream(e.Group) }

// GroupDeleted tombstones a group.
type GroupDeleted struct {
	Group  URN
	Reason string
}

// EventType reports the stable event name.
func (GroupDeleted) EventType() string { return "group.deleted" }

// Stream returns the event stream identity.
func (e GroupDeleted) Stream() string { return groupStream(e.Group) }

// PrincipalLinked maps an external identity.
type PrincipalLinked struct {
	Issuer     string
	ExternalID string
	Subject    Subject
}

// EventType reports the stable event name.
func (PrincipalLinked) EventType() string { return "principal.linked" }

// Stream returns the event stream identity.
func (e PrincipalLinked) Stream() string { return principalStream(e.Subject) }

// PrincipalDeactivated changes one liveness source.
type PrincipalDeactivated struct {
	Subject Subject
	Source  DeactivationSource
	Reason  string
}

// EventType reports the stable event name.
func (PrincipalDeactivated) EventType() string { return "principal.deactivated" }

// Stream returns the event stream identity.
func (e PrincipalDeactivated) Stream() string { return principalStream(e.Subject) }

// PrincipalReactivated restores one liveness source.
type PrincipalReactivated struct {
	Subject Subject
	Source  DeactivationSource
	Reason  string
}

// EventType reports the stable event name.
func (PrincipalReactivated) EventType() string { return "principal.reactivated" }

// Stream returns the event stream identity.
func (e PrincipalReactivated) Stream() string { return principalStream(e.Subject) }

// PrincipalDeleted terminally deletes a principal.
type PrincipalDeleted struct {
	Subject Subject
	Reason  string
}

// EventType reports the stable event name.
func (PrincipalDeleted) EventType() string { return "principal.deleted" }

// Stream returns the event stream identity.
func (e PrincipalDeleted) Stream() string { return principalStream(e.Subject) }

// KindRegistered stages a kind.
type KindRegistered struct {
	Version int
	Kind    KindSpec
}

// EventType reports the stable event name.
func (KindRegistered) EventType() string { return "kind.registered" }

// Stream returns the event stream identity.
func (e KindRegistered) Stream() string { return "model:" + strconv.Itoa(e.Version) }

// ModelPublished publishes a model version.
type ModelPublished struct {
	Version int
}

// EventType reports the stable event name.
func (ModelPublished) EventType() string { return "model.published" }

// Stream returns the event stream identity.
func (e ModelPublished) Stream() string { return "model:" + strconv.Itoa(e.Version) }

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
