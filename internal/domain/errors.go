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

// ErrGroupKindMismatch indicates an id was presented in the wrong tier: an
// ordinary tier-1 group's id where a clearance group was required, or a
// clearance group's id where an ordinary group was required. The type
// system makes the mistake unwriteable within one process (see
// ClearanceGroupID); this sentinel covers the boundary the type system
// cannot reach — an id that arrived as text, from a config file, an API
// request or another service — where the only authority on an id's kind is
// the registry itself. It is the runtime half of design §8.3's rule that a
// tier-1 group may never hold a clearance.
var ErrGroupKindMismatch = errors.New("group kind mismatch")

// ErrMandatoryChannelRequired indicates a clearance-group membership
// change arrived without a valid MandatoryAct witnessing the mandatory
// channel it came through. Clearance membership has no discretionary path
// (design §8.3), so the absence of a witness is a refusal and never a
// defaulted-to-ordinary write.
var ErrMandatoryChannelRequired = errors.New("mandatory channel required")

// ErrChannelMismatch indicates a clearance group declared for one
// mandatory channel was changed through the other — a directory-synced
// group edited by hand through the classify permission, or the reverse.
// Each clearance group names its authoritative channel at creation and
// keeps it, so a synced group cannot be quietly diverged from the
// directory that is supposed to own it.
var ErrChannelMismatch = errors.New("mandatory channel mismatch")

// ErrNotFound indicates a named group or clearance group does not exist.
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
