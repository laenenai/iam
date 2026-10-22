// Package idp holds the provisioning seam: the ports through which an
// identity provider's view of the world reaches the registry, and nothing
// else.
//
// Design §8.1 makes provisioning a port with JIT from token claims as the
// default and only v1 implementation, so a SCIM push adapter or a
// directory pull is a later increment rather than a refactor. §3 is
// equally firm about what does not belong here: this is not an identity
// provider and not a token library. Nothing in this package validates a
// signature, parses a JWT, manages a session, or decides what a credential
// permits — Zitadel does the first, `captoken` the last.
//
// What this increment builds is the *shape*, with the network stubbed. The
// ports are real and tested; the transport that would fetch an issuer's
// OIDC discovery document and JWKS is StubKeySource, which refuses with
// domain.ErrCapabilityUnconfigured. That is deliberate sequencing rather
// than a gap: the sequencing property worth testing — that a token from an
// unregistered issuer is refused *before* any registry lookup — is a
// property of the call order, not of HTTP, and a stub proves it while a
// real client would only obscure it.
//
// The one invariant this package exists to hold:
//
//	An unregistered issuer causes no registry access at all.
//
// Not "no principal is created" — no lookup either. A registry read is an
// attributable signal and, on the JIT path, a write; letting an untrusted
// trust root provoke one makes the accepted-issuer set advisory. See
// JITProvisioner and TestJITProvisioner_UnregisteredIssuerNeverReachesTheRegistry.
package idp

import (
	"context"
	"fmt"
	"sync"

	"github.com/laenen-ai/iam/internal/domain"
	"github.com/laenen-ai/iam/internal/registry"
)

// IssuerPolicy answers which OIDC issuers a tenant accepts. The set is
// tenant policy and not deployment configuration: two tenants in one
// deployment may trust different identity providers, and a token from an
// issuer a tenant has not registered is rejected before any lookup
// (design §8.1, CAS §9.1a).
type IssuerPolicy interface {
	// Accepts reports whether tenant accepts tokens from issuer, as
	// nil, or refuses with domain.ErrIssuerNotRegistered. It must not
	// consult the registry: it is what runs before the registry does.
	Accepts(ctx context.Context, tenant domain.TenantID, issuer string) error
}

// KeySet is an issuer's current verification keys, as the transport
// fetched them. It is opaque here on purpose: this package does not verify
// signatures, so it has no business knowing a key's algorithm or curve —
// only which key ids an issuer currently publishes, which is what a
// rotation-aware caller needs in order to decide whether to re-fetch.
type KeySet struct {
	// Issuer is the issuer these keys belong to.
	Issuer string
	// KeyIDs are the `kid` values the issuer currently publishes.
	KeyIDs []string
	// Raw is the JWKS document exactly as fetched, for the verifier that
	// does understand it to parse. It is never logged and never placed in
	// an error.
	Raw []byte
}

// KeySource fetches and caches an issuer's verification keys. It is the
// one network-shaped port in this module and the reason it is a port at
// all: anti-goal A1 forbids a required external service, so a deployment
// that configures no key source must still start and still work for
// service principals.
//
// Rotation is handled by re-fetch on an unknown `kid` (CAS §9.1a), which
// is why Invalidate exists: a verifier that meets a key id its cached set
// does not contain invalidates and asks again, rather than failing or
// polling on a timer.
type KeySource interface {
	// KeySet returns issuer's current keys, from cache or by fetching
	// them. It refuses with domain.ErrCapabilityUnconfigured if this
	// deployment has no transport configured, and
	// domain.ErrUnavailable if the issuer is unreachable right now.
	KeySet(ctx context.Context, issuer string) (KeySet, error)
	// Invalidate drops any cached key set for issuer, so the next KeySet
	// refetches. Invalidating an issuer that was never cached is not an
	// error.
	Invalidate(issuer string)
}

// Provisioner turns an identity provider's view of a principal into
// registry rows. JIT from token claims is the only implementation in v1;
// a SCIM push adapter and a directory pull are later ones, driven by a
// deployment that needs group membership to be correct *before* a user's
// first login (CAS §9.1a).
type Provisioner interface {
	// Provision records the principal the claims describe and reconciles
	// its claim-sourced group membership, returning the stored
	// principal. It refuses with domain.ErrIssuerNotRegistered, without
	// touching the registry, if the tenant does not accept the claims'
	// issuer.
	Provision(ctx context.Context, c registry.Claims) (domain.Principal, error)
}

// JITProvisioner is the v1 Provisioner: check the issuer against tenant
// policy, then upsert.
//
// It is two lines of logic and it is a type rather than a helper function
// because the *order* of those two lines is the security property. A
// caller that upserts first and checks after has already created a
// principal for an untrusted issuer; a caller that checks the issuer
// somewhere else entirely has a path that can forget to. Making the pair
// the only exported way to provision means the order cannot be got wrong
// at a call site.
type JITProvisioner struct {
	policy   IssuerPolicy
	registry registry.Registry
}

var _ Provisioner = (*JITProvisioner)(nil)

// NewJITProvisioner returns a JITProvisioner over policy and reg.
func NewJITProvisioner(policy IssuerPolicy, reg registry.Registry) (*JITProvisioner, error) {
	if policy == nil {
		return nil, fmt.Errorf("%w: idp: nil issuer policy; an empty policy accepts nothing, a nil one would accept everything", domain.ErrInvalidConfig)
	}
	if reg == nil {
		return nil, fmt.Errorf("%w: idp: nil registry", domain.ErrInvalidConfig)
	}
	return &JITProvisioner{policy: policy, registry: reg}, nil
}

// Provision implements Provisioner.
func (p *JITProvisioner) Provision(ctx context.Context, c registry.Claims) (domain.Principal, error) {
	// Before anything else, and before any registry access. The claims
	// are validated first only so that a malformed tenant id is not
	// handed to the policy as if it were a real tenant.
	if err := c.Validate(); err != nil {
		return domain.Principal{}, err
	}
	if err := p.policy.Accepts(ctx, c.TenantID, c.Subject.Issuer); err != nil {
		return domain.Principal{}, err
	}
	return p.registry.UpsertFromClaims(ctx, c)
}

// StaticIssuerPolicy is an IssuerPolicy over an in-memory, per-tenant
// issuer set: the shape a deployment's configuration file produces, and
// the one the tenant registry will produce once `tenancy` exists.
//
// A tenant with no registered issuers accepts none. That is the only
// defensible default — the alternative, treating "unconfigured" as
// "accept anything", makes the policy decorative — and it is why
// NewJITProvisioner refuses a nil policy rather than treating it as absent.
type StaticIssuerPolicy struct {
	mu       sync.RWMutex
	accepted map[domain.TenantID]map[string]struct{}
}

var _ IssuerPolicy = (*StaticIssuerPolicy)(nil)

// NewStaticIssuerPolicy returns a policy accepting, for each tenant, the
// issuers listed for it. Issuers are compared exactly, with no
// normalization: two OIDC issuer identifiers differing by a trailing
// slash are two trust roots, and merging them would mean accepting a
// token from one as a token from the other.
func NewStaticIssuerPolicy(accepted map[domain.TenantID][]string) *StaticIssuerPolicy {
	p := &StaticIssuerPolicy{accepted: make(map[domain.TenantID]map[string]struct{}, len(accepted))}
	for tenant, issuers := range accepted {
		set := make(map[string]struct{}, len(issuers))
		for _, issuer := range issuers {
			if issuer != "" {
				set[issuer] = struct{}{}
			}
		}
		p.accepted[tenant] = set
	}
	return p
}

// Accepts implements IssuerPolicy.
func (p *StaticIssuerPolicy) Accepts(_ context.Context, tenant domain.TenantID, issuer string) error {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if _, ok := p.accepted[tenant][issuer]; ok {
		return nil
	}
	// The error names the issuer, which the caller supplied, and not the
	// set of issuers the tenant does accept — that is another tenant's
	// configuration to someone probing with a wrong token.
	return fmt.Errorf("%w: %q is not registered for this tenant", domain.ErrIssuerNotRegistered, issuer)
}

// Register adds an issuer to a tenant's accepted set. It exists for
// configuration loading and tests; widening a tenant's trust roots at
// runtime is a reviewed, audited operation that belongs to whatever
// eventually owns tenant policy, not to this type.
func (p *StaticIssuerPolicy) Register(tenant domain.TenantID, issuer string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.accepted[tenant] == nil {
		p.accepted[tenant] = make(map[string]struct{}, 1)
	}
	p.accepted[tenant][issuer] = struct{}{}
}

// StubKeySource is the stubbed transport: the KeySource a deployment has
// when no OIDC client is configured. It refuses every issuer with
// domain.ErrCapabilityUnconfigured.
//
// It is a real, shipped implementation rather than a placeholder, because
// it is what anti-goal A1 requires a deployment with no IdP to behave
// like: starting, serving service principals, and refusing — clearly and
// in one named way — anything that would need an issuer's keys. The HTTP
// client that replaces it on the user path is a later increment, and it
// will implement this same interface; nothing above it changes.
type StubKeySource struct{}

var _ KeySource = StubKeySource{}

// KeySet implements KeySource by refusing.
func (StubKeySource) KeySet(_ context.Context, issuer string) (KeySet, error) {
	return KeySet{}, fmt.Errorf("%w: no OIDC key source is configured, so issuer %q cannot be verified", domain.ErrCapabilityUnconfigured, issuer)
}

// Invalidate implements KeySource. There is nothing cached to drop.
func (StubKeySource) Invalidate(string) {}
