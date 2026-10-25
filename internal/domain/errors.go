// This file declares the complete error taxonomy for the identity
// registry: every exported method in this module returns one of these
// across its boundary instead of a bare error.
//
// Three sentinels in this package are deliberately NOT part of the
// taxonomy below, because each is a well-formedness question asked before
// any registry state is consulted: ErrMalformedID (ids.go),
// ErrInvalidExternalSubject and ErrInvalidPrincipal (principal.go).
//
// On why this module does *not* collapse "no such principal" into a
// combined not-authorized-or-not-found sentinel the way `cas` does for
// content reads. `cas` merges them because its caller is the principal
// asking about a resource, and distinguishing the two answers hands that
// principal an existence oracle over the id space. The identity registry
// has a different caller: the deployment's own token-verification path,
// which already holds a verified token naming the subject it is asking
// about, so ErrPrincipalNotFound tells it nothing it did not supply. It is
// also the signal that drives JIT provisioning (design §8.1) — a caller
// that cannot tell "unknown subject" from "registry unavailable" must
// either provision on an outage or deny on a first login, and both are
// wrong. No registry method reveals the existence of a principal other
// than the one named in its arguments.

package domain

import "errors"

// ErrInvalidConfig indicates a configuration value failed validation —
// including a staleness bound of zero or less, which a deployment must
// declare positively rather than leave to a default (design §8.1).
var ErrInvalidConfig = errors.New("invalid config")

// ErrPrincipalNotFound indicates no principal matches the id or external
// subject named in the call. For an external-subject lookup this is the
// signal to JIT-provision; see this file's header for why it is not
// merged with an authorization outcome.
var ErrPrincipalNotFound = errors.New("principal not found")

// ErrPrincipalDeprovisioned indicates the named principal has been
// deprovisioned and may no longer be used, regardless of whether its
// tokens are still inside their validity window. Deprovisioning denies
// immediately (design §8.1, §9.3): it is not a staleness condition that a
// re-sync could clear, and the registry's joinable membership view stops
// matching a deprovisioned principal in the same statement that records
// the deprovisioning.
var ErrPrincipalDeprovisioned = errors.New("principal deprovisioned")

// ErrResyncRequired indicates the named principal's synced_at is older
// than the deployment's declared staleness bound, so the caller must
// re-provision it from a fresh token before the request proceeds (design
// §8.1). It is the fail-closed answer: a registry that cannot confirm a
// principal's freshness refuses rather than serving a stale identity, and
// it is also what an unevaluated (zero-value) condition reports.
var ErrResyncRequired = errors.New("resync required")

// ErrAgentRunExpired indicates the named agent-run principal is past its
// policy TTL. The row may still exist — garbage collection is a sweep, not
// a precondition — but the principal is unusable from the instant it
// expires, so a slow collector delays cleanup and never access.
var ErrAgentRunExpired = errors.New("agent run expired")

// There were three more sentinels here, and they went with the mandatory
// tier: ErrGroupKindMismatch (an id presented in the wrong tier),
// ErrMandatoryChannelRequired and ErrChannelMismatch. With one namespace
// of groups there is no tier to confuse, and with no deny mechanism there
// is no mandatory channel to witness. See the design document's "no deny
// mechanism" anti-goal.

// ErrNotFound indicates a named group does not exist.
var ErrNotFound = errors.New("not found")

// ErrConflict indicates an operation could not complete because it
// conflicts with existing state — a uniqueness violation, or a reference
// to a row that does not exist.
var ErrConflict = errors.New("conflict")

// ErrUnavailable indicates a dependency is reachable in principle but is
// not reachable right now. It is deliberately distinct from
// ErrInvalidConfig, which indicates the configuration itself is wrong
// rather than a dependency being temporarily down.
var ErrUnavailable = errors.New("unavailable")

// ErrInvalidClaims is returned when a claim set is not provisionable: no
// tenant, no external subject, an unknown principal kind, or an attempt to
// provision an agent run from claims rather than by delegation. Like
// ErrMalformedID it is a well-formedness error asked before any registry
// state is consulted.
var ErrInvalidClaims = errors.New("invalid claims")

// ErrIssuerNotRegistered indicates a token's issuer is not one the tenant
// accepts. The accepted issuer set is tenant policy (design §8.1), and the
// refusal happens before any registry lookup: an unregistered issuer must
// not be able to cause a principal to be created, a row to be read, or an
// external subject to be recorded, because each of those is a write or a
// signal attributable to an untrusted trust root.
var ErrIssuerNotRegistered = errors.New("issuer not registered")

// ErrCapabilityUnconfigured indicates the operation requires a capability
// this deployment has not configured — a key source for an OIDC issuer, a
// directory to pull from. It never silently degrades to a lesser
// behaviour: the caller must either configure the capability or avoid the
// operation. A deployment with no IdP configured still works for service
// principals (anti-goal A1), and this is the error it gets if something
// asks it to verify a user's token anyway.
var ErrCapabilityUnconfigured = errors.New("capability unconfigured")

// --- The authorization layer ------------------------------------------
//
// Eight sentinels, and the shape of the set is itself a statement: seven
// of them are well-formedness refusals asked before any state is
// consulted, the eighth reports a stored tree that is not one, and none of
// them is a denial. A denial is not an error here. Decide
// returns a Decision whose Allowed is false, because default-deny is the
// ordinary answer to most questions a consumer asks and an error-shaped
// deny trains callers to treat refusals as outages.

// ErrInvalidSchema indicates a registered schema is not well formed: no
// kinds, no permissions, a duplicate or empty name, a kind inside an
// undeclared kind, or a containment cycle. It is a well-formedness error
// asked before any state is consulted.
var ErrInvalidSchema = errors.New("invalid schema")

// ErrMultipleContainmentParents indicates a schema declared a container
// kind with more than one containment parent, which this module refuses
// outright.
//
// It has its own sentinel, separate from ErrInvalidSchema, because it is
// not a typo: it is a consumer whose data model is a DAG meeting a module
// whose closure is a tree, and the caller that hits it needs to branch —
// to redesign its containment, or to reopen design finding F3 — rather
// than to fix a field. Design §9.2's ancestry closure is "bounded by
// hierarchy depth" only under one parent per container; F3's spike
// measured the alternative at 106,495,540 rows and 10.9 GB where the
// container-keyed closure was 433,063 rows and 37 MB, and §8.4 used to
// accept the declaration and hand the consumer the first of those with no
// error at all.
var ErrMultipleContainmentParents = errors.New("containment declares more than one parent")

// ErrSchemaNotRegistered indicates no schema in this process declares the
// container kind or permission the call names. It is fail-closed on
// purpose: a consumer that has not registered its schema cannot create a
// container or write a grant, so a deployment that forgot the
// registration call fails at its first write rather than at its first
// decision.
var ErrSchemaNotRegistered = errors.New("schema not registered")

// ErrInvalidContainer indicates a container spec does not describe a
// creatable container: no tenant, no kind, a kind the tenant's schema
// does not declare, or a parent that is in another tenant or is of the
// wrong kind for the declared edge.
var ErrInvalidContainer = errors.New("invalid container")

// ErrInvalidGrant indicates a grant spec does not describe a writable
// grant: no tenant, no container, no permission, or a subject naming
// neither a principal nor a group.
var ErrInvalidGrant = errors.New("invalid grant")

// ErrInvalidRequest indicates a decision request is not answerable: no
// tenant, no principal, no permission, or no container. It is distinct
// from a denial, which is a Decision and not an error.
var ErrInvalidRequest = errors.New("invalid request")

// ErrContainmentCycle indicates the stored containment graph does not
// terminate: a container's parent chain either revisits a container or
// runs deeper than domain.MaxContainmentDepth. It should be unreachable —
// the tree is enforced by a single parent column and by a cycle check on
// every create — and it exists because the alternative to an error here
// is an authorization decision that never returns.
var ErrContainmentCycle = errors.New("containment cycle")

// ErrInvalidResidual indicates a residual, or a node of one, is not well
// formed: a key that is not a plain column name, a tenant term naming no
// tenant, an authorization term naming no principal or no permission, or a
// residual with no expression at all.
//
// It is a refusal and never a degraded render. The two things a renderer
// could otherwise do with a malformed term are to match nothing, which
// domain.None already says explicitly, or to match everything — and the
// second is the whole authorization layer failing open on a zero value.
var ErrInvalidResidual = errors.New("invalid residual")

// ErrUnrenderable indicates a backend's renderer cannot express a residual
// in that backend's query language. It is not a defect in the residual.
//
// The known case is CQL: Cassandra can filter only on a partition key and
// a prefix of the clustering columns, so "this row's container is one the
// principal may read" is renderable there only if the containment key is
// part of the table's key — a data-modelling constraint on the consumer
// rather than a translation problem. Every render path returns an error so
// that such a backend can refuse honestly instead of emitting something
// that filters less than it claims.
var ErrUnrenderable = errors.New("residual not renderable by this backend")
