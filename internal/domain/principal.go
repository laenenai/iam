package domain

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// ErrInvalidExternalSubject is returned by ParseExternalSubject when
// issuer or subject is empty, over-long, or carries a control character.
// It is a well-formedness error, not a registry outcome.
var ErrInvalidExternalSubject = errors.New("invalid external subject")

// ErrInvalidPrincipal is returned by Principal.Validate when a principal's
// fields do not describe a principal this module can store — an unknown
// kind, an agent run with no parent or no TTL, or a non-agent-run carrying
// a delegation.
var ErrInvalidPrincipal = errors.New("invalid principal")

// maxExternalComponentLen bounds an issuer or subject string. It is
// generous next to any real OIDC issuer URL or subject claim and exists
// only to refuse a deliberately oversized claim outright rather than let
// it reach a unique index.
const maxExternalComponentLen = 1024

// PrincipalKind names the three kinds of principal the registry holds.
// There is no fourth, and in particular there is no "anonymous" kind: a
// link-sharing bearer is a capability token's subject, which is
// `captoken`'s object and not a row here (design §3, §8.2).
type PrincipalKind string

const (
	// PrincipalKindUser is a human identity, normally mirrored from an
	// OIDC issuer by JIT provisioning.
	PrincipalKindUser PrincipalKind = "user"
	// PrincipalKindService is a non-human identity belonging to a
	// deployment or an integration. A deployment with no IdP configured
	// still works for service principals (anti-goal A1), so a service
	// principal is permitted to carry no external subject at all.
	PrincipalKindService PrincipalKind = "service"
	// PrincipalKindAgentRun is one run of one agent: a first-class
	// principal with its own id so audit and metering attribute per run,
	// created by delegation from a user or service principal and
	// garbage-collected on a policy TTL (design §8.1). It is deliberately
	// not a flag on its parent.
	PrincipalKindAgentRun PrincipalKind = "agent-run"
)

// Valid reports whether k is one of the three kinds the registry
// recognizes. Every write path rejects any other value before it reaches
// Postgres; the schema's CHECK constraint is a backstop, not the primary
// guard.
func (k PrincipalKind) Valid() bool {
	switch k {
	case PrincipalKindUser, PrincipalKindService, PrincipalKindAgentRun:
		return true
	default:
		return false
	}
}

// ExternalSubject is an identity as an identity provider names it: the
// token's issuer paired with its subject claim. It is the registry's only
// external key, recorded at first sight and mapped once to an internal
// PrincipalID (design §8.1).
//
// Nothing downstream of the registry ever stores an ExternalSubject. A
// grant, an audit row and a metering record all reference the
// internal PrincipalID, so re-issuing a subject, renaming a user, or
// moving them between issuers rewrites exactly one row here and no history
// anywhere.
type ExternalSubject struct {
	// Issuer is the OIDC issuer identifier, exactly as the token's `iss`
	// claim spells it. Issuer acceptance is tenant policy, checked before
	// any registry lookup happens (design §8.1, internal/idp).
	Issuer string
	// Subject is the token's `sub` claim: opaque, stable within the
	// issuer, and never parsed for meaning here.
	Subject string
}

// ParseExternalSubject validates issuer and subject and returns the pair.
// It performs no normalization beyond rejecting surrounding whitespace:
// an issuer that differs from a registered one by a trailing slash is a
// different issuer, because treating them as the same would mean deciding
// that two distinct OIDC identifiers name one trust root.
func ParseExternalSubject(issuer, subject string) (ExternalSubject, error) {
	if err := validateExternalComponent("issuer", issuer); err != nil {
		return ExternalSubject{}, err
	}
	if err := validateExternalComponent("subject", subject); err != nil {
		return ExternalSubject{}, err
	}
	return ExternalSubject{Issuer: issuer, Subject: subject}, nil
}

// IsZero reports whether s names no external identity. A service
// principal in a deployment with no IdP has a zero ExternalSubject, which
// is legitimate; a user principal's must always be present.
func (s ExternalSubject) IsZero() bool { return s.Issuer == "" && s.Subject == "" }

// String returns a stable, greppable rendering for diagnostics. It is
// deliberately not an id format: nothing may parse it back and nothing may
// derive an internal id from it.
func (s ExternalSubject) String() string { return s.Issuer + "#" + s.Subject }

// validateExternalComponent reports whether s is usable as one half of an
// external subject key.
func validateExternalComponent(label, s string) error {
	if s == "" || len(s) > maxExternalComponentLen {
		return fmt.Errorf("%w: %s length", ErrInvalidExternalSubject, label)
	}
	if strings.TrimSpace(s) != s {
		return fmt.Errorf("%w: %s has surrounding whitespace", ErrInvalidExternalSubject, label)
	}
	if strings.ContainsFunc(s, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		return fmt.Errorf("%w: %s charset", ErrInvalidExternalSubject, label)
	}
	return nil
}

// Principal is one identity the registry holds. Grants,
// audit chains and metering attribution reference ID and nothing else.
type Principal struct {
	// ID is the stable internal id. It is minted fresh and is never a
	// function of External; see the package doc comment.
	ID PrincipalID
	// TenantID scopes this principal. The registry is global; every row
	// in it is tenant-scoped (design §3).
	TenantID TenantID
	// Kind is user, service, or agent-run.
	Kind PrincipalKind
	// External is the (issuer, subject) pair this principal was first
	// seen as, or the zero value for a principal with no external
	// identity (a service principal in a deployment with no IdP).
	External ExternalSubject
	// DisplayName is a human label carried for diagnostics and audit
	// rendering. It is claim-derived, may change on any re-sync, and is
	// never an identity: nothing resolves a principal by it.
	DisplayName string
	// SyncedAt is when this principal's claim-derived state was last
	// refreshed from its issuer. It is what the staleness bound is
	// measured against (design §8.1); see Condition.
	SyncedAt time.Time
	// DeprovisionedAt is when this principal was deprovisioned, or the
	// zero time while it is active. A non-zero value denies immediately
	// and is not clearable by a re-sync.
	DeprovisionedAt time.Time
	// DelegatedBy names the user or service principal that created this
	// agent run. It is set for PrincipalKindAgentRun and must be empty
	// for every other kind.
	DelegatedBy PrincipalID
	// ExpiresAt is an agent run's policy TTL deadline, after which the
	// principal is unusable and collectable. It is set for
	// PrincipalKindAgentRun and must be the zero time for every other
	// kind: a user or service principal does not expire, it is
	// deprovisioned.
	ExpiresAt time.Time
	// CreatedAt is when the registry first recorded this principal.
	CreatedAt time.Time
}

// Validate reports whether p describes a storable principal. It is the
// shared precondition every adapter runs before a write, so an in-memory
// registry and a Postgres one refuse the same values rather than relying
// on a CHECK constraint one of them does not have.
func (p Principal) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("%w: empty id", ErrInvalidPrincipal)
	}
	if p.TenantID == "" {
		return fmt.Errorf("%w: empty tenant id", ErrInvalidPrincipal)
	}
	if !p.Kind.Valid() {
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidPrincipal, p.Kind)
	}
	if p.Kind == PrincipalKindUser && p.External.IsZero() {
		return fmt.Errorf("%w: a user principal must carry an external subject", ErrInvalidPrincipal)
	}
	if p.SyncedAt.IsZero() {
		return fmt.Errorf("%w: synced_at must be set, so staleness is always measurable", ErrInvalidPrincipal)
	}

	if p.Kind == PrincipalKindAgentRun {
		if p.DelegatedBy == "" {
			return fmt.Errorf("%w: an agent run must name the principal that delegated it", ErrInvalidPrincipal)
		}
		if p.ExpiresAt.IsZero() {
			return fmt.Errorf("%w: an agent run must carry a TTL deadline", ErrInvalidPrincipal)
		}
		return nil
	}

	if p.DelegatedBy != "" {
		return fmt.Errorf("%w: only an agent run may carry a delegation", ErrInvalidPrincipal)
	}
	if !p.ExpiresAt.IsZero() {
		return fmt.Errorf("%w: only an agent run may carry a TTL deadline", ErrInvalidPrincipal)
	}
	return nil
}
