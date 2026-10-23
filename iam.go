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
// It carries aliases, re-exported constants, sentinels and the module's
// entry points — its constructors and the free functions a consumer must
// be able to call. What it does not carry is logic: every function below
// forwards to internal/ and does nothing else. The reachability rule is
// the one CONVENTIONS states: if a consumer would need to name it, it
// belongs here and therefore in api.txt. An internal/ constructor absent
// from this file is a constructor no consumer outside this module can
// call, which is a facade that hides what the module is for.
//
// There is no `Open` yet. It arrives with the decision API, which this
// increment deliberately does not build (design §14: the identity registry
// is the one workstream independent of the open `Predicate` questions).
// Until then the registry constructors below are the entry points.
//
// api.txt is this surface as a golden file, diffed in CI, so growing it is
// a reviewed diff.
package iam

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenenai/iam/internal/domain"
	"github.com/laenenai/iam/internal/idp"
	"github.com/laenenai/iam/internal/migrate"
	"github.com/laenenai/iam/internal/registry"
	"github.com/laenenai/iam/internal/registry/pgregistry"
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

// The provisioning seam (internal/idp). Design §8.1 makes provisioning a
// port with JIT from token claims as the only v1 implementation; nothing
// here verifies a credential (§3 — not an identity provider, not a token
// library).
type (
	// Provisioner turns an identity provider's view of a principal into
	// registry rows.
	Provisioner = idp.Provisioner
	// IssuerPolicy answers which OIDC issuers a tenant accepts. A token
	// from an unregistered issuer is refused before any registry lookup.
	IssuerPolicy = idp.IssuerPolicy
	// KeySource fetches and caches an issuer's verification keys. It is
	// the one network-shaped port in this module, which is why it is a
	// port: a deployment that configures none must still start and still
	// work for service principals (anti-goal A1).
	KeySource = idp.KeySource
	// KeySet is an issuer's current verification keys as the transport
	// fetched them.
	KeySet = idp.KeySet
	// StaticIssuerPolicy is an IssuerPolicy over an in-memory, per-tenant
	// issuer set — the shape a deployment's configuration file produces.
	StaticIssuerPolicy = idp.StaticIssuerPolicy
	// StubKeySource is the KeySource a deployment has when no OIDC client
	// is configured: it refuses every issuer with
	// ErrCapabilityUnconfigured, which is what anti-goal A1 requires a
	// deployment with no IdP to behave like.
	StubKeySource = idp.StubKeySource
	// JITProvisioner is the v1 Provisioner: check the issuer against
	// tenant policy, then upsert.
	JITProvisioner = idp.JITProvisioner
	// Migration describes one embedded schema migration's state.
	Migration = migrate.Applied
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
	// ErrIssuerNotRegistered indicates a token's issuer is not one the
	// tenant accepts; the refusal happens before any registry lookup.
	ErrIssuerNotRegistered = domain.ErrIssuerNotRegistered
	// ErrCapabilityUnconfigured indicates the operation needs a
	// capability this deployment has not configured, such as an OIDC key
	// source. It never silently degrades to a lesser behaviour.
	ErrCapabilityUnconfigured = domain.ErrCapabilityUnconfigured
)

// --- Entry points -------------------------------------------------------
//
// Each function below forwards to internal/ and contains no logic of its
// own. They are here because a consumer in another module cannot reach
// internal/, so without them the module has no callable surface.

// NewMemoryRegistry returns an in-memory Registry configured by cfg. It is
// a real adapter rather than a mock — it enforces the mandatory channel,
// the tier separation, the staleness bound and immediate deprovisioning
// itself, and passes iamtest.RunRegistrySuite unchanged — so a consumer's
// own tests of its authorization code can run against it with no database.
// Its state lives only for the life of the value, so it is not a
// deployment option.
func NewMemoryRegistry(cfg RegistryConfig) (Registry, error) {
	return registry.NewMemory(cfg)
}

// NewPostgresRegistry returns the deployment Registry over pool,
// configured by cfg. The caller owns pool's lifetime and must have applied
// this module's migrations (MigrateUp).
//
// This constructor, and MigrateUp below, are why the facade's import graph
// includes pgx. That cost is deliberate rather than overlooked: design
// §4/A1 makes one Postgres instance the deployment shape, every consumer
// in CHARTER.md's adoption table already runs one, and there is no
// deployment of this module without it. The alternative — a non-internal
// subpackage so a pgx-free consumer could avoid the link — would put the
// module's main entry point somewhere other than its facade for the
// benefit of a consumer that does not exist.
func NewPostgresRegistry(pool *pgxpool.Pool, cfg RegistryConfig) (Registry, error) {
	return pgregistry.New(pool, cfg)
}

// MigrateUp applies every pending `iam` migration embedded in this binary
// to pool, in order, under a Postgres advisory lock so that several
// processes starting against one database serialize rather than race.
// Calling it against an already-current database applies nothing and
// returns nil.
//
// Migrations are embedded and applied by the library, never by a separate
// tool run, because anti-goal A1 requires that adding authorization to a
// Go binary need nothing beyond a Postgres connection string and one
// constructor call.
func MigrateUp(ctx context.Context, pool *pgxpool.Pool) error {
	return migrate.Up(ctx, pool)
}

// MigrationStatus reports the state of every embedded migration: applied
// ones with the time they were applied, and pending ones not yet run.
func MigrationStatus(ctx context.Context, pool *pgxpool.Pool) ([]Migration, error) {
	return migrate.Status(ctx, pool)
}

// NewJITProvisioner returns the v1 Provisioner over policy and reg: it
// checks the claims' issuer against tenant policy and only then upserts.
//
// The order of those two steps is the security property, which is why
// this is the only exported way to provision: design §8.1 requires that a
// token from an unregistered issuer be rejected before any lookup, and a
// caller that upserts first has already created a principal for an
// untrusted trust root.
func NewJITProvisioner(policy IssuerPolicy, reg Registry) (*JITProvisioner, error) {
	return idp.NewJITProvisioner(policy, reg)
}

// NewStaticIssuerPolicy returns an IssuerPolicy accepting, for each
// tenant, the issuers listed for it. A tenant with no registered issuers
// accepts none: "unconfigured" must not mean "accept anything".
//
// Issuers are compared exactly, with no normalization. Two OIDC issuer
// identifiers differing by a trailing slash are two trust roots, and
// merging them would mean accepting a token from one as a token from the
// other.
func NewStaticIssuerPolicy(accepted map[TenantID][]string) *StaticIssuerPolicy {
	return idp.NewStaticIssuerPolicy(accepted)
}

// NewMandatoryAct returns the witness a clearance-group change requires:
// which mandatory channel it came through, which actor performed it, why,
// and when. Every clearance write on the Registry port demands one, and
// this is the only way to obtain one — which is how design §8.3's rule
// that clearance membership has no discretionary path is enforced by the
// type system rather than by convention.
//
// reason is required rather than optional: an unexplained change to a
// mandatory control is indistinguishable, after the fact, from a mistake.
func NewMandatoryAct(channel MandatoryChannel, actor PrincipalID, reason string, at time.Time) (MandatoryAct, error) {
	return domain.NewMandatoryAct(channel, actor, reason, at)
}

// ParseExternalSubject validates an (issuer, subject) pair and returns it.
// It performs no normalization beyond rejecting surrounding whitespace,
// for the reason NewStaticIssuerPolicy's comment gives.
func ParseExternalSubject(issuer, subject string) (ExternalSubject, error) {
	return domain.ParseExternalSubject(issuer, subject)
}

// EvaluateCondition computes a principal's typed usability verdict against
// a staleness bound at an instant. It is exported because a consumer
// holding a Principal — from an audit replay, a cache, or its own
// projection — must be able to ask the same question the registry does and
// get the same answer, rather than reimplementing the rule and drifting.
func EvaluateCondition(p Principal, bound time.Duration, asOf time.Time) PrincipalCondition {
	return domain.EvaluateCondition(p, bound, asOf)
}

// Canonical returns an instant in UTC truncated to microsecond precision:
// the form every instant this module stores or compares is in. Postgres
// timestamptz holds microseconds, so a time.Time carrying nanoseconds
// round-trips equal to itself in memory and unequal through the database.
// A consumer comparing its own instants against this module's must
// canonicalize them the same way.
func Canonical(t time.Time) time.Time { return domain.Canonical(t) }

// NewTenantID returns a fresh TenantID minted from clock.
func NewTenantID(clock Clock) TenantID { return domain.NewTenantID(clock) }

// ParseTenantID parses s as a TenantID, rejecting malformed input.
func ParseTenantID(s string) (TenantID, error) { return domain.ParseTenantID(s) }

// NewPrincipalID returns a fresh PrincipalID minted from clock. It takes
// no external subject, and that is the point: an internal id is never a
// function of anything a directory controls, so re-issuing an external
// identity never rewrites history.
func NewPrincipalID(clock Clock) PrincipalID { return domain.NewPrincipalID(clock) }

// ParsePrincipalID parses s as a PrincipalID, rejecting malformed input.
func ParsePrincipalID(s string) (PrincipalID, error) { return domain.ParsePrincipalID(s) }

// NewGroupID returns a fresh GroupID minted from clock.
func NewGroupID(clock Clock) GroupID { return domain.NewGroupID(clock) }

// ParseGroupID parses s as a GroupID, rejecting malformed input.
func ParseGroupID(s string) (GroupID, error) { return domain.ParseGroupID(s) }

// NewClearanceGroupID returns a fresh ClearanceGroupID minted from clock.
func NewClearanceGroupID(clock Clock) ClearanceGroupID { return domain.NewClearanceGroupID(clock) }

// ParseClearanceGroupID parses s as a ClearanceGroupID, rejecting
// malformed input. It validates syntax only; whether the id names a
// clearance group rather than an ordinary group is a question only a
// Registry can answer, and it answers it with ErrGroupKindMismatch.
func ParseClearanceGroupID(s string) (ClearanceGroupID, error) {
	return domain.ParseClearanceGroupID(s)
}

// NewChangeID returns a fresh ChangeID minted from clock.
func NewChangeID(clock Clock) ChangeID { return domain.NewChangeID(clock) }

// ParseChangeID parses s as a ChangeID, rejecting malformed input.
func ParseChangeID(s string) (ChangeID, error) { return domain.ParseChangeID(s) }
