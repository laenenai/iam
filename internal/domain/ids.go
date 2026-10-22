// Package domain is the single home for every identity entity and value
// object in `iam`: the typed internal ids that grants, classifications and
// audit chains reference, the principal/group/clearance-group aggregates,
// the mandatory-channel witness, and the freshness verdict a caller must
// clear before a principal may be used in a decision.
//
// The invariant this package exists to hold is that **an internal id is
// never derived from anything external**. A PrincipalID is a freshly minted
// ULID with no function of (issuer, subject) in it, so re-issuing, renaming
// or re-homing an external identity leaves every grant, every clearance and
// every audit row pointing at the same principal (design §8.1, CAS §9.1).
// A design that hashed the external subject into the id would rewrite
// history on an IdP rename, and nothing downstream could tell.
//
// The second invariant is a type-system one, and it is the reason this
// package's ids are not all the same shape. GroupID is a tier-1,
// discretionary object: anybody who may share may change its membership.
// ClearanceGroupID is a tier-2, mandatory object, and design §8.3 requires
// that it can never stand where an ordinary group is expected — because if
// it could, adding a member to a team would open a mandatory gate, and
// anti-goal A3 would be breached by construction rather than by a bug. So
// ClearanceGroupID is a struct with an unexported field: not merely a
// distinct named string type (which a one-word conversion defeats) but a
// value no package outside this one can forge, convert into, or convert out
// of. See internal/domain/testdata/ordinary_group_id_is_not_a_clearance_group_id.go
// and TestOrdinaryGroupIDIsNotAClearanceGroupID, which compiles that file
// and requires the compiler to reject it.
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
// registry itself is global, but every group, every clearance group and
// every external-subject mapping in it is tenant-scoped, and no decision
// reads another tenant's rows (design §3).
type TenantID string

// PrincipalID identifies a principal — a user, a service, or one agent run
// — and is the id that grants, classifications, audit chains and metering
// attribution reference. It is minted fresh and is never a function of the
// principal's external subject; see this package's doc comment.
type PrincipalID string

// GroupID identifies an ordinary, tier-1 group: a team, a workspace, a
// claim-derived role. Membership is discretionary, so a GroupID may never
// be used to satisfy a mandatory control — which is enforced here by
// ClearanceGroupID being a different kind of value entirely, not by
// anybody remembering the rule.
type GroupID string

// ChangeID identifies one recorded change to a clearance group's
// membership, in the append-only trail design §8.3 requires that
// membership to carry.
type ChangeID string

// rawID is the unexported carrier type newID mints through on behalf of
// ClearanceGroupID, whose own representation is deliberately not a string
// type and so cannot be an instantiation of newID itself.
type rawID string

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

// NewChangeID returns a fresh ChangeID minted from clock.
func NewChangeID(clock Clock) ChangeID { return newID[ChangeID](clock) }

// ParseChangeID parses s as a ChangeID, rejecting malformed input.
func ParseChangeID(s string) (ChangeID, error) { return parseID[ChangeID]("change id", s) }

// ClearanceGroupID identifies a clearance group: a *mandatory* object whose
// membership moves only through the channel MandatoryChannel names, and
// which design §8.3 forbids from ever appearing in a tier-1 tuple.
//
// It is a struct wrapping an unexported string rather than a named string
// type, and that is load-bearing. A named string type would stop
// `AddClearanceGroupMember(g)` from accepting a GroupID — but it would let
// `ClearanceGroupID(g)` through, a single conversion that silently turns a
// team into a clearance group. Because the only field here is unexported
// and has a struct type at the boundary, no package outside domain can
// write that conversion in either direction, nor construct a value except
// through NewClearanceGroupID or ParseClearanceGroupID. The distinction is
// therefore a property of the type, not of reviewer attention.
//
// A syntactically valid id is still not proof of kind: ParseClearanceGroupID
// accepts any well-formed ULID, including one that happens to name an
// ordinary group, because a parser cannot know what a registry stores. The
// second half of the guarantee is therefore the registry's — it rejects an
// id that names a tier-1 group with ErrGroupKindMismatch — and the schema's:
// clearance groups and groups are separate tables with separate foreign
// keys, so the confusion is unrepresentable in SQL too.
type ClearanceGroupID struct {
	// s is the Crockford base32 ULID string. Unexported: see above.
	s string
}

// NewClearanceGroupID returns a fresh ClearanceGroupID minted from clock.
func NewClearanceGroupID(clock Clock) ClearanceGroupID {
	return ClearanceGroupID{s: string(newID[rawID](clock))}
}

// ParseClearanceGroupID parses s as a ClearanceGroupID, rejecting
// malformed input. It validates syntax only; whether the id names a
// clearance group rather than an ordinary group is a question only the
// registry can answer, and it answers it with ErrGroupKindMismatch.
func ParseClearanceGroupID(s string) (ClearanceGroupID, error) {
	raw, err := parseID[rawID]("clearance group id", s)
	if err != nil {
		return ClearanceGroupID{}, err
	}
	return ClearanceGroupID{s: string(raw)}, nil
}

// String returns the id's canonical ULID text, for storage and logging. It
// is safe to log: an internal id reveals nothing about the external
// identity behind it.
func (id ClearanceGroupID) String() string { return id.s }

// IsZero reports whether id is the zero ClearanceGroupID — the value a
// caller gets from `var g domain.ClearanceGroupID`, which names nothing.
// Every registry method that accepts one rejects the zero value rather
// than treating it as a wildcard.
func (id ClearanceGroupID) IsZero() bool { return id.s == "" }
