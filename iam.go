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
// There is no `Open` yet, and that is now a smaller gap than it reads.
// `Open(ctx, Config)` would hand a consumer one value wiring the registry
// and the authorizer together over one pool; what exists instead is the
// two constructors, because a deployment that wants only identity should
// not be made to configure a staleness bound *and* an authorization layer,
// and because `Open` is the right shape only once design §11's second
// deployment shape — the service — settles what Config has to carry.
//
// api.txt is this surface as a golden file, diffed in CI, so growing it is
// a reviewed diff.
package iam

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/laenenai/iam/internal/authz"
	"github.com/laenenai/iam/internal/authz/pgauthz"
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
	// verified claims, (issuer, subject) resolution, joinable group
	// membership, agent-run delegation, deprovisioning, and the typed
	// freshness condition.
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
	// Group is a group — a team, a workspace, a claim-derived role —
	// whose membership is discretionary.
	Group = domain.Group
	// GroupSource names whether a membership is owned by the issuer that
	// asserted it or by a local write.
	GroupSource = domain.GroupSource
	// Membership is one principal's membership of one ordinary group, as
	// the joinable row the authorization predicate reads.
	Membership = domain.Membership
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
	// PrincipalID is the stable internal id that grants, audit chains and
	// metering attribution reference.
	PrincipalID = domain.PrincipalID
	// GroupID identifies a group.
	GroupID = domain.GroupID
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
	// ErrNotFound indicates a named group does not exist.
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
// a real adapter rather than a mock — it enforces the staleness bound and
// immediate deprovisioning itself, and passes iamtest.RunRegistrySuite
// unchanged — so a consumer's
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

// --- The authorization layer --------------------------------------------
//
// Membership on containers, inherited down a tree. A subject — a principal
// or a group — holds a permission on a container, and everything the
// container contains inherits it. Default-deny: every refusal is a grant
// nobody wrote.
//
// internal/authz's package doc carries the whole argument for why this is
// so much smaller than design §8.2 describes, and names each absence as a
// decision: no deny mechanism, no relation algebra, no `visible_below`, no
// attribute granularity, no persisted schema versioning, and `Predicate`'s
// filtered-read contract left unbuilt while finding F4 is open. Read it
// before concluding something is missing.

// The authorization port and the values it moves. RunAuthorizerSuite in
// the iamtest package is the authoritative description of this contract's
// edge-case behaviour; the interface below is only its shape.
type (
	// Authorizer is the authorization port: containers and containment as
	// a tree, grants as membership, the point decision, the residual a
	// consumer applies to its own rows, and the change log a separated
	// deployment resumes from.
	Authorizer = authz.Authorizer
	// AuthorizerConfig is the deployment policy an authorizer adapter is
	// built with.
	AuthorizerConfig = authz.Config
	// FilterRequest asks for the residual a consumer should apply to its
	// own rows: which of these rows may this principal <permission>.
	FilterRequest = authz.FilterRequest
	// Fragment is rendered Postgres SQL together with the parameters it
	// binds. It is the renderer's output, never the port's: SQL text does
	// not cross Authorizer, so that a second storage backend is a new
	// renderer rather than a breaking change for every consumer.
	Fragment = pgauthz.Fragment
)

// Containers, grants and schemas.
type (
	// Container is one node of a containment tree. It has exactly one
	// parent, and that single field is design §9.2's single-path
	// invariant.
	Container = domain.Container
	// ContainerSpec is one container to create.
	ContainerSpec = domain.ContainerSpec
	// ContainerKind is one node of a consumer's declared containment
	// tree. Its Parents field is a slice only so that a two-parent
	// declaration is representable and can therefore be refused.
	ContainerKind = domain.ContainerKind
	// Schema is one consumer's registered model: its container kinds and
	// its permission vocabulary.
	Schema = domain.Schema
	// Permission is one thing a subject may do, named by the consumer
	// that registered it.
	Permission = domain.Permission
	// Subject is who a grant is written to: one principal, or one group.
	// It has exactly two states because it has exactly two unexported
	// fields.
	Subject = domain.Subject
	// Grant is the only rule shape this layer has: a subject holds a
	// permission on a container.
	Grant = domain.Grant
	// GrantSpec is one grant to write or revoke.
	GrantSpec = domain.GrantSpec
)

// The decision and what it carries.
type (
	// Request is one point decision to take, with the resource named by
	// the container it lives in.
	Request = domain.Request
	// Decision is one answer from Decide: the verdict, the outermost form
	// that fired, the grant responsible, how many containment hops away
	// it was, and the revision it was computed against.
	Decision = domain.Decision
	// Reason names why a decision came out the way it did.
	Reason = domain.Reason
)

// The revision and the change log.
type (
	// Revision is the authorization state an answer was computed against:
	// gapless, monotonic, and per tenant. It is this design's zookie, and
	// it exists before anything reads it because a Decision that grew the
	// field later would be a breaking change at every call site.
	Revision = domain.Revision
	// Change is one entry of the change log: the unit a consumer on
	// another store replays to maintain its own projection.
	Change = domain.Change
	// ChangeKind names what a logged change was.
	ChangeKind = domain.ChangeKind
)

// The residual: a typed expression, not SQL. A backend-specific renderer
// turns it into that backend's query language, which is why SQL text never
// crosses the port — see internal/domain's residual documentation, and its
// note on Cassandra, where the containment key has to be part of the
// table's own key and no renderer can fix that.
type (
	// Residual is what the authority returns for a filtered read: the
	// expression to apply, and the revision it reflects.
	Residual = domain.Residual
	// Expr is one node of a residual. Its method set includes an
	// unexported method, so the node types are closed and a renderer's
	// type switch over them is exhaustive by construction.
	Expr = domain.Expr
	// Key names a consumer's own column: the scalar containment key
	// finding F1 froze, or its tenant column.
	Key = domain.Key
	// PrincipalRef names whose permissions a residual term is about: one
	// known principal, or whichever principal the evaluating session
	// names.
	PrincipalRef = domain.PrincipalRef
	// None matches no rows. It is the fail-closed residual, and it is a
	// node rather than an error because the failure mode a consumer needs
	// is zero rows and never a raised exception.
	None = domain.None
	// All matches every row. Never produced by this module's authority.
	All = domain.All
	// And is the conjunction of its terms, and the only combinator.
	And = domain.And
	// TenantIs restricts rows to one tenant by the consumer's own tenant
	// column.
	TenantIs = domain.TenantIs
	// ContainerPermits is the authorization term: this row's container
	// key names a container on which this principal holds this
	// permission, directly or through a group, here or on any ancestor.
	ContainerPermits = domain.ContainerPermits
)

// ContainerID identifies a container: the unit a grant is written on, the
// unit containment inherits down, and the one column a consumer adds to
// its own rows.
type ContainerID = domain.ContainerID

// Decision reasons. The zero value is ReasonUnevaluated and it denies.
const (
	ReasonUnevaluated = domain.ReasonUnevaluated
	ReasonNoGrant     = domain.ReasonNoGrant
	ReasonDirect      = domain.ReasonDirect
	ReasonUserset     = domain.ReasonUserset
	ReasonInherited   = domain.ReasonInherited
)

// Change kinds.
const (
	ChangeContainerCreated = domain.ChangeContainerCreated
	ChangeGrantWritten     = domain.ChangeGrantWritten
	ChangeGrantRevoked     = domain.ChangeGrantRevoked
)

// Authorization-layer constants a consumer has to be able to name.
const (
	// PrincipalGUC is the Postgres session variable a residual rendered
	// into a row-level-security policy reads the deciding principal from.
	// A consumer establishes it the way it establishes the tenant:
	// SELECT set_config('app.principal_id', $1, true) inside its
	// transaction. A statement that establishes neither matches no rows
	// and raises nothing.
	PrincipalGUC = authz.PrincipalGUC
	// DefaultChangeLimit is the page size Changes uses for a
	// non-positive limit.
	DefaultChangeLimit = authz.DefaultChangeLimit
	// MaxChangeLimit caps a page of changes, so a projection catching up
	// from an old cursor pages rather than materializing everything.
	MaxChangeLimit = authz.MaxChangeLimit
	// MaxContainmentDepth bounds a containment tree. Anti-goal A2 budgets
	// depth 6; this is far looser and exists so that a corrupted tree
	// terminates an ancestry walk with an error rather than running
	// forever inside a decision.
	MaxContainmentDepth = domain.MaxContainmentDepth
)

// Authorization-layer sentinel errors. None of them is a denial: a denial
// is a Decision whose Allowed is false, because default-deny is the
// ordinary answer and an error-shaped deny trains callers to treat a
// refusal as an outage.
var (
	// ErrInvalidSchema indicates a registered schema is not well formed.
	ErrInvalidSchema = domain.ErrInvalidSchema
	// ErrMultipleContainmentParents indicates a schema declared a
	// container kind with more than one containment parent, which this
	// module refuses outright. It has its own sentinel because the caller
	// that hits it has to redesign its containment or reopen design
	// finding F3, rather than fix a field.
	ErrMultipleContainmentParents = domain.ErrMultipleContainmentParents
	// ErrSchemaNotRegistered indicates no schema in this process declares
	// the container kind or permission the call names.
	ErrSchemaNotRegistered = domain.ErrSchemaNotRegistered
	// ErrInvalidContainer indicates a container spec does not describe a
	// creatable container.
	ErrInvalidContainer = domain.ErrInvalidContainer
	// ErrInvalidGrant indicates a grant spec does not describe a writable
	// grant.
	ErrInvalidGrant = domain.ErrInvalidGrant
	// ErrInvalidRequest indicates a decision or filter request is not
	// answerable.
	ErrInvalidRequest = domain.ErrInvalidRequest
	// ErrContainmentCycle indicates the stored containment graph does not
	// terminate. It should be unreachable, and it exists because the
	// alternative to an error is a decision that never returns.
	ErrContainmentCycle = domain.ErrContainmentCycle
	// ErrInvalidResidual indicates a residual, or a node of one, is not
	// well formed.
	ErrInvalidResidual = domain.ErrInvalidResidual
	// ErrUnrenderable indicates a backend's renderer cannot express a
	// residual in that backend's query language. It is not a defect in
	// the residual: CQL, for one, can filter only on a partition key and
	// a clustering prefix.
	ErrUnrenderable = domain.ErrUnrenderable
)

// NewMemoryAuthorizer returns an in-memory Authorizer over reg, configured
// by cfg. It is a real adapter rather than a mock — it enforces the
// single-parent tree, walks the containment closure, composes reg's own
// membership, and passes iamtest.RunAuthorizerSuite unchanged — so a
// consumer's tests of its own authorization code can run with no database.
// Its state lives only for the life of the value, so it is not a
// deployment option.
//
// It takes a Registry because the group side of a decision is the
// registry's membership rather than a copy of it. A second copy is a copy
// that goes stale, and the way it fails is that a deprovisioned principal
// keeps reading until somebody syncs.
func NewMemoryAuthorizer(reg Registry, cfg AuthorizerConfig) (Authorizer, error) {
	return authz.NewMemory(reg, cfg)
}

// NewPostgresAuthorizer returns the deployment Authorizer over pool,
// configured by cfg. The caller owns pool's lifetime and must have applied
// this module's migrations (MigrateUp), which is also what asserts the
// row-level-security policy its statements depend on.
//
// It needs no Registry: the group side of a decision is resolved inside
// the same SQL statement, through the registry's own
// iam.live_group_members view, which is what makes deprovisioning stop a
// decision in the statement that records it.
func NewPostgresAuthorizer(pool *pgxpool.Pool, cfg AuthorizerConfig) (Authorizer, error) {
	return pgauthz.New(pool, cfg)
}

// PrincipalSubject returns the subject naming one principal.
func PrincipalSubject(p PrincipalID) Subject { return domain.PrincipalSubject(p) }

// GroupSubject returns the subject naming one group — design §8.2's
// userset, and the form that makes a membership change take effect with no
// grant rewritten.
func GroupSubject(g GroupID) Subject { return domain.GroupSubject(g) }

// NamedPrincipal returns a residual reference to one known principal, for
// a residual joined into a single query.
func NamedPrincipal(p PrincipalID) PrincipalRef { return domain.NamedPrincipal(p) }

// SessionPrincipal returns a residual reference to whichever principal the
// evaluating session names — the form a row-level-security policy needs,
// because a policy is created once and evaluated for every principal.
func SessionPrincipal() PrincipalRef { return domain.SessionPrincipal() }

// NewContainerID returns a fresh ContainerID minted from clock.
func NewContainerID(clock Clock) ContainerID { return domain.NewContainerID(clock) }

// ParseContainerID parses s as a ContainerID, rejecting malformed input.
func ParseContainerID(s string) (ContainerID, error) { return domain.ParseContainerID(s) }

// ValidPermissionName reports whether p is a permission name this module
// will accept in a schema. The set is restricted — a letter, digit or
// underscore followed by up to 63 of those plus `.`, `:` and `-` — because
// a permission is written as a literal into row-level-security policy text
// when a consumer renders a residual for one.
func ValidPermissionName(p Permission) bool { return domain.ValidPermissionName(p) }

// RenderPostgres renders a residual for use inside an ordinary Postgres
// query, numbering its placeholders from firstArg. Pass
// len(existingArgs)+1: the residual is ANDed into a statement the consumer
// already wrote, which already has parameters.
//
// A residual that can match nothing renders as `false` with no arguments.
func RenderPostgres(r Residual, firstArg int) (Fragment, error) {
	return pgauthz.Render(r, firstArg)
}

// RenderPostgresPolicy renders a residual as a parameterless boolean
// expression, for the USING clause of a row-level-security policy. This is
// the mechanism a consumer enforcing privacy by placement actually wants:
//
//	CREATE POLICY graph_read ON tenant_quads AS RESTRICTIVE
//	    USING (<this expression>);
//
// AS RESTRICTIVE is not optional, and the reason is a measured one. Postgres
// OR-s permissive policies together and AND-s restrictive ones on top, so a
// permissive authorization policy is OR-ed away by any later permissive
// policy on the same table — which is how a tenant predicate written that
// way became a cross-tenant disclosure in this project on 2026-10-23. A
// restrictive policy ANDs, so it composes with `tenancy`'s restrictive
// tenant predicate on the same table and neither can be widened: both are
// in the database, and a hand-written statement cannot escape either.
//
// The residual must be built with SessionPrincipal and without a
// TenantKey. A policy is created once and evaluated for every principal and
// every tenant, so a literal for either would pin it to one; the principal
// comes from PrincipalGUC and the tenant is already `tenancy`'s half.
//
// # What the evaluating role needs, and the one thing to look at twice
//
// A policy's expression is evaluated with the privileges of the role
// running the statement, so that role needs USAGE on the `iam` schema and
// SELECT on exactly five relations — the ones the rendering reads:
//
//	GRANT USAGE ON SCHEMA iam TO <app_role>;
//	GRANT SELECT ON iam.container_closure, iam.grants,
//	                iam.live_principals, iam.live_group_members,
//	                iam.principals
//	    TO <app_role>;
//
// Those five and no more. `iam.live_group_members` and
// `iam.live_principals` are views over `iam.group_members` and
// `iam.principals`, and a view is read with the privileges of its owner
// unless it was created with `security_invoker`, so granting the views does
// not require granting their base tables — except that `iam.principals`
// *is* read directly, to confirm the deciding principal belongs to this
// tenant.
//
// **That last grant is the one to look at twice.** `iam.principals` carries
// no row-level-security policy — a stated gap, see RLSTablesExemptFromPolicy
// — so a role holding SELECT on it can read principal rows across tenants
// with an ordinary statement of its own. The policy itself leaks nothing:
// its subquery's result never reaches the caller, and the tenant comparison
// inside it is what keeps a principal from another tenant from being
// matched. What the grant exposes is the table, to a role that asks it
// directly. Three things follow, in order of preference: grant it to the
// narrowest role that evaluates the policy; do not give that role the
// ability to run arbitrary statements if that is avoidable; and treat the
// exemption as something to close rather than to live with.
func RenderPostgresPolicy(r Residual) (string, error) {
	return pgauthz.RenderPolicy(r)
}

// RLSTables names every `iam` table carrying `tenancy`'s tenant isolation
// policy. MigrateUp asserts it on each of them, idempotently, on every run.
//
// It is exported so a consumer can include this module's schema in its own
// CI sweep — tenancy.AssertRLSCoverage over the `iam` schema — without
// hardcoding the list.
func RLSTables() []string { return migrate.RLSTables() }

// RLSTablesExemptFromPolicy names the tenant-scoped `iam` tables that
// carry no policy, each with the reason.
//
// Both entries are a stated gap rather than a decision: the identity
// registry's adapter establishes no tenant session context, so a policy on
// its tables would make every registry read return zero rows. Tenant
// scoping of identity is enforced in Go on each read, so what is missing
// is the database-level backstop and not the check. It is exported because
// a consumer sweeping this schema needs to know which absences are known.
func RLSTablesExemptFromPolicy() map[string]string { return migrate.RLSTablesExemptFromPolicy() }
