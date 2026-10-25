package domain

import (
	"fmt"
	"strings"
	"time"
)

// Grant is the only rule shape this layer has: a subject holds a
// permission on a container, and everything the container contains
// inherits it.
//
// Design §8.2 permits four composition forms. Two of them are here — a
// direct grant and a group subject — one of them is the containment
// inheritance the closure materializes, and the fourth, union over
// relations on the same object, is absent because there are no relations
// to union. See the internal/authz package doc for why that is the whole
// language the two real consumers asked for.
//
// A grant is not a credential and holds no security-relevant material:
// every field is either a minted, opaque ULID or a permission name the
// consumer chose, so none of CONVENTIONS' four redaction interfaces
// applies. That is stated rather than left implicit, because the absence
// of a redaction method on a type in this module should be a conclusion
// somebody reached and not one nobody asked.
type Grant struct {
	// TenantID scopes the grant. No decision reads another tenant's
	// grants (design §3), and the row-level-security policy on the grant
	// table is what enforces that inside a consumer's own statement.
	TenantID TenantID
	// Container is the container the grant is written on.
	Container ContainerID
	// Permission is what the subject may do.
	Permission Permission
	// Subject is who holds it: one principal, or one group.
	Subject Subject
	// GrantedAt is when it was recorded.
	GrantedAt time.Time
}

// IsZero reports whether g names nothing.
func (g Grant) IsZero() bool {
	return g.Container == "" && g.Permission == "" && g.Subject.IsZero()
}

// String renders the grant in design §8.2's notation,
// `object#relation@subject`, with the container as the object and the
// permission in the relation's place.
func (g Grant) String() string {
	if g.IsZero() {
		return "grant:none"
	}
	return "container:" + string(g.Container) + "#" + string(g.Permission) + "@" + g.Subject.String()
}

// GrantSpec is one grant to write or to revoke.
type GrantSpec struct {
	// TenantID scopes it and must match the container's tenant.
	TenantID TenantID
	// Container is the container the permission is held on.
	Container ContainerID
	// Permission must be one the tenant's registered schema declares. A
	// permission no schema names is refused rather than stored: a grant
	// whose permission is misspelled is a grant that silently never
	// fires, and finding it at write time costs one error where finding
	// it at read time costs an outage or a disclosure.
	Permission Permission
	// Subject is who gets it.
	Subject Subject
}

// Validate reports whether the spec describes a writable grant.
func (g GrantSpec) Validate() error {
	if g.TenantID == "" {
		return fmt.Errorf("%w: empty tenant id", ErrInvalidGrant)
	}
	if g.Container == "" {
		return fmt.Errorf("%w: a grant must name a container", ErrInvalidGrant)
	}
	if strings.TrimSpace(string(g.Permission)) == "" {
		return fmt.Errorf("%w: a grant must name a permission", ErrInvalidGrant)
	}
	return g.Subject.Validate()
}

// ContainerSpec is one container to create.
type ContainerSpec struct {
	// TenantID scopes the container.
	TenantID TenantID
	// Kind must be a kind the tenant's registered schema declares.
	Kind string
	// Parent is the container this one lives in, or the zero value for a
	// root. It is one id and not a set, which is design §9.2's
	// single-path invariant as a field rather than as a hope.
	Parent ContainerID
	// Label is a human label for diagnostics and decides nothing.
	Label string
}

// Validate reports whether the spec describes a creatable container.
// Whether its kind and parent fit the registered schema is a question for
// the adapter, which is the only thing holding the schema and the parent
// row.
func (c ContainerSpec) Validate() error {
	if c.TenantID == "" {
		return fmt.Errorf("%w: empty tenant id", ErrInvalidContainer)
	}
	if strings.TrimSpace(c.Kind) == "" {
		return fmt.Errorf("%w: a container must name its kind, which its tenant's schema must declare", ErrInvalidContainer)
	}
	return nil
}

// Request is one point decision to take: design §7.1's
// `Decide(principal, action, resource, at)`, with the resource named by
// the container it lives in.
//
// # Why the resource is a container and not a resource
//
// The containment key finding F1 froze is a scalar on a consumer's row
// naming the container that row lives in, and every grant in this layer
// is written on a container. So a resource's permissions are exactly its
// container's, and a consumer asking about a resource passes the value it
// already stores on that row. Nothing is lost that this layer could have
// expressed: a per-resource grant would need a resource to grant on, and
// there is no resource table here — by design, since the closure's row
// count has to be a function of hierarchy depth rather than of resource
// cardinality.
//
// # Why there is no `at`
//
// Design §8.1 requires that a decision and the freshness check that
// authorizes it share one instant, and the sharpest way to have them
// share one is for there to be no second one to pass. The decision is one
// statement; the liveness of the principal and of its group memberships
// is evaluated inside it, at that statement's own instant. A caller
// cannot ask what would have been allowed an hour ago, which is right:
// serving a decision computed against a past instant is how a revoked
// grant keeps working.
//
// What this costs is stated in the internal/authz package doc: the
// deployment's staleness bound is *not* evaluated here, because the
// bound is configuration rather than a row and the joinable fragment runs
// where no configuration exists. The bound stays where §8.1 puts it — on
// the way in, enforced by the registry.
type Request struct {
	// TenantID scopes the decision.
	TenantID TenantID
	// Principal is who is asking.
	Principal PrincipalID
	// Permission is what they want to do.
	Permission Permission
	// Container is the container the resource lives in.
	Container ContainerID
}

// Validate reports whether the request is answerable.
func (r Request) Validate() error {
	if r.TenantID == "" {
		return fmt.Errorf("%w: empty tenant id", ErrInvalidRequest)
	}
	if r.Principal == "" {
		return fmt.Errorf("%w: a decision must name a principal", ErrInvalidRequest)
	}
	if strings.TrimSpace(string(r.Permission)) == "" {
		return fmt.Errorf("%w: a decision must name a permission", ErrInvalidRequest)
	}
	if r.Container == "" {
		return fmt.Errorf("%w: a decision must name the container the resource lives in", ErrInvalidRequest)
	}
	return nil
}

// Reason names why a decision came out the way it did. It is the
// *outermost* form that fired, which is the convention the use-case
// corpus's reference oracle already uses and the one a consumer debugging
// a decision needs first: an inherited grant to a group reports
// inheritance, because the row to go and look at is on an ancestor.
type Reason string

const (
	// ReasonUnevaluated is the zero value, and it denies. An
	// unevaluated decision must never read as an allow.
	ReasonUnevaluated Reason = ""
	// ReasonNoGrant is the only deny this layer has. There is no deny
	// mechanism (design A3): every refusal is a grant nobody wrote.
	ReasonNoGrant Reason = "no-grant"
	// ReasonDirect is a grant written to this principal on this very
	// container.
	ReasonDirect Reason = "direct"
	// ReasonUserset is a grant written to a group this principal is a
	// live member of, on this very container — design §8.2's second
	// form.
	ReasonUserset Reason = "userset"
	// ReasonInherited is a grant written on an ancestor, reached through
	// the containment closure — design §8.2's third form, one tuple per
	// hop rather than one per object.
	ReasonInherited Reason = "inherited"
)

// Decision is one answer from Decide.
type Decision struct {
	// Allowed is the verdict. The zero value is deny.
	Allowed bool
	// Reason names the outermost form that fired, or ReasonNoGrant.
	Reason Reason
	// Via is the grant that allowed it, and the zero Grant when nothing
	// did. It is returned because an authorization answer a consumer
	// cannot explain is an answer it cannot audit: Via names the row to
	// go and look at.
	Via Grant
	// Depth is how many containment hops lie between the request's
	// container and Via.Container — 0 when the grant was written on the
	// container itself, n when it was inherited from n hops up. It is a
	// separate field rather than a fifth Reason value because "inherited"
	// and "through a group" are two independent facts, and folding them
	// into one enum would be the cross product design §8.2 refuses for
	// roles.
	Depth int
}

// Deny returns the decision this layer gives when no grant reaches the
// request. It is a constructor rather than a literal so that every
// refusal in every adapter is the identical value, and so the zero
// Decision — which also denies — is never the thing a caller inspects.
func Deny() Decision { return Decision{Allowed: false, Reason: ReasonNoGrant} }

// Allow returns an allow attributed to via, reached depth hops up.
func Allow(via Grant, depth int) Decision {
	reason := ReasonDirect
	switch {
	case depth > 0:
		reason = ReasonInherited
	default:
		if _, isGroup := via.Subject.Group(); isGroup {
			reason = ReasonUserset
		}
	}
	return Decision{Allowed: true, Reason: reason, Via: via, Depth: depth}
}

// String renders the decision for a log line or a test failure.
func (d Decision) String() string {
	if !d.Allowed {
		return "deny (" + string(d.Reason) + ")"
	}
	return fmt.Sprintf("allow (%s, %d hops) via %s", d.Reason, d.Depth, d.Via)
}
