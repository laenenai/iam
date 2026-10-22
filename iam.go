// Package iam answers one question: who exists, what groups they are in,
// and what they are allowed to do — answerable inside a SQL query. See
// CHARTER.md for the boundary and
// docs/superpowers/specs/2026-10-23-iam-design.md for the design.
//
// This file is the facade. It re-exports, as type aliases, everything a
// consumer must be able to *name*: the ports it implements or receives,
// the entities those ports move, and the sentinel errors it branches on.
// Aliases rather than wrapper types, so a value `iam`'s internals produce
// and a value the consumer holds are the identical type — which is what
// lets a consumer implement a port in its own package and have `iamtest`'s
// conformance suite run against it.
//
// It declares aliases, re-exported constants and sentinels only. There is
// no behaviour here and no constructor; `Open` arrives with the decision
// API, which this increment deliberately does not build (design §14: the
// identity registry is the one workstream independent of the open
// `Predicate` questions).
//
// api.txt is this surface as a golden file, diffed in CI, so growing it is
// a reviewed diff.
package iam

import (
	"github.com/laenen-ai/iam/internal/domain"
	"github.com/laenen-ai/iam/internal/registry"
)

// The identity registry port and the values it moves. RunRegistrySuite in
// the iamtest package is the authoritative description of this contract's
// edge-case behaviour; the interface below is only its shape.
type (
	// Registry is the identity registry port: JIT provisioning from
	// verified claims, (issuer, subject) resolution, joinable group and
	// clearance-group membership, agent-run delegation, deprovisioning,
	// and the typed freshness condition.
	Registry = registry.Registry
	// Claims is the subset of a verified token the registry provisions
	// from. It is not a credential and nothing in this module verifies
	// one.
	Claims = registry.Claims
	// AgentRunSpec describes one agent run to delegate.
	AgentRunSpec = registry.AgentRunSpec
	// RegistryConfig is the deployment policy a registry adapter is
	// built with: the staleness bound and the agent-run TTL ceiling.
	RegistryConfig = registry.Config
)

// Identity entities and value objects.
type (
	// Principal is one identity: a user, a service, or one agent run.
	Principal = domain.Principal
	// PrincipalKind names the three kinds of principal.
	PrincipalKind = domain.PrincipalKind
	// ExternalSubject is an identity as an identity provider names it:
	// the token's issuer paired with its subject claim.
	ExternalSubject = domain.ExternalSubject
	// Group is an ordinary, tier-1 group whose membership is
	// discretionary.
	Group = domain.Group
	// GroupSource names whether a membership is owned by the issuer that
	// asserted it or by a local write.
	GroupSource = domain.GroupSource
	// Membership is one principal's membership of one ordinary group, as
	// the joinable row the authorization predicate reads.
	Membership = domain.Membership
	// ClearanceGroup is a mandatory object whose membership moves only
	// through a mandatory channel and which can never be referenced in a
	// tier-1 tuple.
	ClearanceGroup = domain.ClearanceGroup
	// ClearanceChange is one entry in a clearance group's append-only
	// membership trail.
	ClearanceChange = domain.ClearanceChange
	// ClearanceChangeKind names what a recorded membership change did.
	ClearanceChangeKind = domain.ClearanceChangeKind
	// MandatoryChannel names the only two ways a clearance group's
	// membership may change.
	MandatoryChannel = domain.MandatoryChannel
	// MandatoryAct witnesses that a clearance-group membership change
	// arrived through a mandatory channel.
	MandatoryAct = domain.MandatoryAct
	// PrincipalState is the registry's verdict on whether a principal may
	// be used in a decision; it is an enumeration and not a boolean
	// because its four answers demand four different caller responses.
	PrincipalState = domain.PrincipalState
	// PrincipalCondition is the typed freshness-and-liveness verdict for
	// one principal at one instant.
	PrincipalCondition = domain.PrincipalCondition
	// Clock abstracts the instant a write is stamped with.
	Clock = domain.Clock
	// SystemClock is the production Clock.
	SystemClock = domain.SystemClock
)

// Internal ids. Every one is a minted ULID, never a function of anything
// external, so re-issuing an external identity never rewrites history.
type (
	// TenantID identifies a tenant: the top-level unit of isolation.
	TenantID = domain.TenantID
	// PrincipalID is the stable internal id that grants,
	// classifications, audit chains and metering attribution reference.
	PrincipalID = domain.PrincipalID
	// GroupID identifies an ordinary, tier-1 group.
	GroupID = domain.GroupID
	// ClearanceGroupID identifies a clearance group. It is deliberately
	// not interconvertible with GroupID: see its own doc comment.
	ClearanceGroupID = domain.ClearanceGroupID
	// ChangeID identifies one entry in a clearance group's trail.
	ChangeID = domain.ChangeID
)

// Principal kinds.
const (
	PrincipalKindUser     = domain.PrincipalKindUser
	PrincipalKindService  = domain.PrincipalKindService
	PrincipalKindAgentRun = domain.PrincipalKindAgentRun
)

// Membership sources.
const (
	GroupSourceClaim = domain.GroupSourceClaim
	GroupSourceLocal = domain.GroupSourceLocal
)

// Mandatory channels. There is no third, and in particular none reachable
// from a sharing operation.
const (
	MandatoryChannelClassify      = domain.MandatoryChannelClassify
	MandatoryChannelDirectorySync = domain.MandatoryChannelDirectorySync
)

// Clearance-trail change kinds.
const (
	ClearanceChangeCreated = domain.ClearanceChangeCreated
	ClearanceChangeAdded   = domain.ClearanceChangeAdded
	ClearanceChangeRemoved = domain.ClearanceChangeRemoved
)

// Principal states. The zero value is PrincipalStateUnknown and it is not
// usable: an unevaluated condition denies.
const (
	PrincipalStateUnknown        = domain.PrincipalStateUnknown
	PrincipalStateUsable         = domain.PrincipalStateUsable
	PrincipalStateResyncRequired = domain.PrincipalStateResyncRequired
	PrincipalStateDeprovisioned  = domain.PrincipalStateDeprovisioned
	PrincipalStateExpired        = domain.PrincipalStateExpired
)

// Sentinel errors. Each is declared and documented once, in
// internal/domain, and re-exported here so a consumer compares with
// errors.Is against this module's own values rather than an adapter's.
var (
	// ErrInvalidConfig indicates a configuration value failed validation.
	ErrInvalidConfig = domain.ErrInvalidConfig
	// ErrMalformedID indicates a string is not a well-formed internal id.
	ErrMalformedID = domain.ErrMalformedID
	// ErrInvalidExternalSubject indicates an (issuer, subject) pair is
	// not well-formed.
	ErrInvalidExternalSubject = domain.ErrInvalidExternalSubject
	// ErrInvalidPrincipal indicates a principal's fields do not describe
	// a storable principal.
	ErrInvalidPrincipal = domain.ErrInvalidPrincipal
	// ErrInvalidClaims indicates a claim set is not provisionable.
	ErrInvalidClaims = domain.ErrInvalidClaims
	// ErrPrincipalNotFound indicates no principal matches the id or
	// external subject named in the call; for an external-subject lookup
	// it is the signal to JIT-provision.
	ErrPrincipalNotFound = domain.ErrPrincipalNotFound
	// ErrPrincipalDeprovisioned indicates the principal has been
	// deprovisioned and may not be used, regardless of token validity.
	ErrPrincipalDeprovisioned = domain.ErrPrincipalDeprovisioned
	// ErrResyncRequired indicates the principal is staler than the
	// deployment's bound and must be re-provisioned before use.
	ErrResyncRequired = domain.ErrResyncRequired
	// ErrAgentRunExpired indicates the agent-run principal is past its
	// policy TTL.
	ErrAgentRunExpired = domain.ErrAgentRunExpired
	// ErrGroupKindMismatch indicates an id was presented in the wrong
	// tier — an ordinary group where a clearance group was required, or
	// the reverse.
	ErrGroupKindMismatch = domain.ErrGroupKindMismatch
	// ErrMandatoryChannelRequired indicates a clearance-group write
	// arrived without a valid MandatoryAct witnessing its channel.
	ErrMandatoryChannelRequired = domain.ErrMandatoryChannelRequired
	// ErrChannelMismatch indicates a clearance group declared for one
	// mandatory channel was changed through the other.
	ErrChannelMismatch = domain.ErrChannelMismatch
	// ErrNotFound indicates a named group or clearance group does not
	// exist.
	ErrNotFound = domain.ErrNotFound
	// ErrConflict indicates an operation conflicts with existing state.
	ErrConflict = domain.ErrConflict
	// ErrUnavailable indicates a dependency is reachable in principle but
	// not right now.
	ErrUnavailable = domain.ErrUnavailable
)
