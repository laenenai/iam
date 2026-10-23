package domain

import "time"

// GroupSource names where an ordinary group membership came from, and it
// exists for one reason: design §8.1 requires that "a claim set that
// shrinks removes memberships", and that reconciliation must not reach
// memberships the IdP was never the authority for.
//
// Without the distinction, a JIT upsert whose token happens to omit a role
// claim would delete a membership an operator added by hand, and an
// operator's hand-added membership would survive the user's removal from
// the directory. With it, reconciliation is scoped to exactly the rows the
// issuer owns.
type GroupSource string

const (
	// GroupSourceClaim means the membership was derived from a token
	// claim and is owned by the issuer: a JIT upsert whose claim set no
	// longer names the group removes it.
	GroupSourceClaim GroupSource = "claim"
	// GroupSourceLocal means the membership was written directly through
	// the registry, by an operator or by a consumer's own sharing flow.
	// A JIT upsert never removes it.
	GroupSourceLocal GroupSource = "local"
)

// Valid reports whether s is one of the two sources the registry
// recognizes.
func (s GroupSource) Valid() bool {
	switch s {
	case GroupSourceClaim, GroupSourceLocal:
		return true
	default:
		return false
	}
}

// Group is a group: a team, a workspace, or a claim-derived role.
// Membership is discretionary — anyone who may share may change it. There
// was once a second, mandatory kind of group whose membership no
// discretionary operation could change; it went with the deny mechanism,
// and this is the only kind of group left.
//
// Groups and their membership are rows rather than token claims, and that
// is the whole reason identity lives in this module at all: design §9's
// authorization predicate has to join membership inside the consumer's own
// SQL statement, and a claim in a JWT cannot be joined. See the
// internal/registry package doc comment.
type Group struct {
	// ID is the group's stable internal id.
	ID GroupID
	// TenantID scopes the group.
	TenantID TenantID
	// Name is the group's name within its tenant, unique there. For a
	// claim-derived group it is the claim value exactly as the issuer
	// spelled it, so a second sighting of the same role upserts rather
	// than duplicating.
	Name string
	// CreatedAt is when the registry first recorded this group.
	CreatedAt time.Time
}

// Membership is one principal's membership of one ordinary group, as the
// joinable row the predicate reads.
type Membership struct {
	// GroupID names the group.
	GroupID GroupID
	// PrincipalID names the member.
	PrincipalID PrincipalID
	// Source records who owns this row: see GroupSource.
	Source GroupSource
	// AddedAt is when the membership was recorded.
	AddedAt time.Time
}
