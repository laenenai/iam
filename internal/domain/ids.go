// Package domain is the single home for every identity entity and value
// object in `iam`: the typed internal ids that grants and audit chains
// reference, the principal and group aggregates, and the freshness verdict
// a caller must clear before a principal may be used in a decision.
//
// The invariant this package exists to hold is that **an internal id is
// never derived from anything external**. A PrincipalID is a freshly minted
// ULID with no function of (issuer, subject) in it, so re-issuing, renaming
// or re-homing an external identity leaves every grant and every audit row
// pointing at the same principal (design §8.1, CAS §9.1).
// A design that hashed the external subject into the id would rewrite
// history on an IdP rename, and nothing downstream could tell.
//
// Every id here is a distinct named string type. An earlier version had one
// that was not — ClearanceGroupID was a struct with an unexported field, so
// that no package outside this one could forge a mandatory object's id or
// convert a GroupID into one. It went with the mandatory tier: see the
// design document's "no deny mechanism" anti-goal. The technique is worth
// remembering for the next value that must be unforgeable.
package domain

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/oklog/ulid/v2"
)

// ErrMalformedID is returned by the Parse*ID functions when the input is
// not a syntactically valid ULID string. It is a parse/validation error
// rather than a business-rule outcome, so it is declared here and not in
// the taxonomy in errors.go.
var ErrMalformedID = errors.New("malformed id")

// TenantID identifies a tenant: the top-level unit of isolation. The
// registry itself is global, but every group and every external-subject
// mapping in it is tenant-scoped, and no decision reads another tenant's
// rows (design §3).
type TenantID string

// PrincipalID identifies a principal — a user, a service, or one agent run
// — and is the id that grants, audit chains and metering attribution
// reference. It is minted fresh and is never a function of the
// principal's external subject; see this package's doc comment.
type PrincipalID string

// GroupID identifies a group: a team, a workspace, a claim-derived role.
// Membership is discretionary — anybody who may share may change it.
type GroupID string

// newID mints a fresh id of type T from the current time of clock, using
// cryptographically random entropy for the non-timestamp bits. Values sort
// lexicographically by creation time because a ULID's 48-bit millisecond
// timestamp occupies its leading, fixed-width characters.
//
// ulid.MustNew panics if entropy fails to supply enough random bytes. That
// is inherited deliberately from `cas`, not overlooked: a crypto/rand read
// failure here means this process has lost its entropy source, so its
// identifiers and its encryption are both already broken, and there is
// nothing a returned error at this call site could do better than failing
// loudly.
func newID[T ~string](clock Clock) T {
	id := ulid.MustNew(ulid.Timestamp(clock.Now()), rand.Reader)
	return T(id.String())
}

// parseID validates that s is a syntactically well-formed ULID string and
// returns it as T, or a wrapped ErrMalformedID if it is not.
func parseID[T ~string](label, s string) (T, error) {
	if _, err := ulid.ParseStrict(s); err != nil {
		return T(""), fmt.Errorf("%w: %s %q: %w", ErrMalformedID, label, s, err)
	}
	return T(s), nil
}

// NewTenantID returns a fresh TenantID minted from clock.
func NewTenantID(clock Clock) TenantID { return newID[TenantID](clock) }

// ParseTenantID parses s as a TenantID, rejecting malformed input.
func ParseTenantID(s string) (TenantID, error) { return parseID[TenantID]("tenant id", s) }

// NewPrincipalID returns a fresh PrincipalID minted from clock. It takes
// no external subject, and that is the point: see the package doc comment.
func NewPrincipalID(clock Clock) PrincipalID { return newID[PrincipalID](clock) }

// ParsePrincipalID parses s as a PrincipalID, rejecting malformed input.
func ParsePrincipalID(s string) (PrincipalID, error) {
	return parseID[PrincipalID]("principal id", s)
}

// NewGroupID returns a fresh GroupID minted from clock.
func NewGroupID(clock Clock) GroupID { return newID[GroupID](clock) }

// ParseGroupID parses s as a GroupID, rejecting malformed input.
func ParseGroupID(s string) (GroupID, error) { return parseID[GroupID]("group id", s) }

// ContainerID identifies a container: the unit a grant is written on and
// the unit containment inherits down. It is the scalar containment key
// finding F1 froze — one column on a consumer's row, naming the container
// that row lives in — and it is a minted ULID for the same reason every
// other id here is: a container's identity must not be a function of a
// consumer's own key, or renaming a folder would rewrite every grant.
type ContainerID string

// NewContainerID returns a fresh ContainerID minted from clock.
func NewContainerID(clock Clock) ContainerID { return newID[ContainerID](clock) }

// ParseContainerID parses s as a ContainerID, rejecting malformed input.
func ParseContainerID(s string) (ContainerID, error) {
	return parseID[ContainerID]("container id", s)
}
